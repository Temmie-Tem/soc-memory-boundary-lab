#!/usr/bin/env python3
"""Run Experiment 014's normal-RAM timing probe through the pinned A90P1 bridge.

The only device writes are fixed temporary files below ``/tmp/a90-native`` and
experiment-owned normal RAM (anonymous or non-secure ION).  No MMIO, partition,
firmware, SMC, EL2/EL3, or protected-memory operation is available through this
tool.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.a90_acm_snapshot import Command, Frame, exchange


SCHEMA = "a90_dram_timing_live_v1"
PROBE_SCHEMA = "a90_dram_timing_probe_v2"
EXPECTED_VERSION = "A90 Linux init 0.9.285"
EXPECTED_BUILD = "build=v2321-usb-clean-identity-rodata"
EXPECTED_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
EXPECTED_CMDLINE_TOKENS = {
    "androidboot.em.model=SM-A908N",
    "androidboot.bootloader=A908NKSU5EWA3",
    "androidboot.debug_level=0x4f4c",
    "androidboot.force_upload=0x0",
    "sec_debug.dump_sink=0x0",
}
REMOTE_ENVELOPE = "/tmp/a90-native/exp014-dram-probe.b64u"
REMOTE_BINARY = "/tmp/a90-native/exp014-dram-probe"
REMOTE_ION = "/tmp/a90-native/exp014-ion"
MAX_LEGACY_CHUNK = 3500
MAX_DEVICE_DIFFERENCES = 23
SHA256_RE = re.compile(rb"(?:^|\r?\n)([0-9a-f]{64})  ([^\r\n]+)")
EXIT_RE = re.compile(rb"(?:^|\r?\n)\[exit ([0-9]+)\](?:\r?\n|$)")
RUN_PREFIX_RE = re.compile(rb"^run: pid=[0-9]+, q/Ctrl-C cancels$")


class LiveError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExtendedCommand:
    """A90P1 command whose arguments need newline-safe cmdv1x encoding."""

    evidence_id: str
    argv: tuple[str, ...]

    @property
    def wire(self) -> bytes:
        encoded = []
        for argument in self.argv:
            data = argument.encode("utf-8")
            if b"\0" in data:
                raise LiveError("cmdv1x argument contains NUL")
            encoded.append(f"{len(data)}:{data.hex()}")
        wire = ("cmdv1x " + " ".join(encoded) + "\n").encode("ascii")
        if len(wire) >= 4096:
            raise LiveError(f"cmdv1x frame is not bounded: {len(wire)} bytes")
        return wire


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def call(
    host: str,
    port: int,
    evidence_id: str,
    argv: tuple[str, ...],
    timeout: float,
    *,
    extended: bool = False,
    allow_error: bool = False,
) -> Frame:
    command = (
        ExtendedCommand(evidence_id, argv)
        if extended
        else Command(evidence_id, argv)
    )
    try:
        return exchange(host, port, command, timeout, allow_error=allow_error)
    except Exception as exc:
        raise LiveError(f"A90P1 command failed at {evidence_id}: {argv!r}: {exc}") from exc


def require_child_exit_zero(payload: bytes, label: str) -> None:
    matches = list(EXIT_RE.finditer(payload))
    if not matches:
        raise LiveError(f"{label} lacks a child exit receipt")
    code = int(matches[-1].group(1), 10)
    if code != 0:
        raise LiveError(f"{label} child exited {code}")


def parse_run_value(payload: bytes, label: str) -> str:
    require_child_exit_zero(payload, label)
    values = []
    for line in payload.replace(b"\r\n", b"\n").splitlines():
        if RUN_PREFIX_RE.fullmatch(line) or EXIT_RE.fullmatch(line + b"\n"):
            continue
        values.append(line.decode("utf-8", errors="strict"))
    value = "\n".join(values).strip()
    if not value:
        raise LiveError(f"{label} returned no value")
    return value


def validate_target(version: bytes, cmdline: bytes) -> dict[str, object]:
    version_text = version.decode("utf-8", errors="strict")
    cmdline_text = cmdline.decode("utf-8", errors="strict")
    for expected in (EXPECTED_VERSION, EXPECTED_BUILD, EXPECTED_KERNEL):
        if expected not in version_text:
            raise LiveError(f"target version lacks exact token: {expected}")
    missing = sorted(
        token for token in EXPECTED_CMDLINE_TOKENS if token not in cmdline_text.split()
    )
    if missing:
        raise LiveError(f"target cmdline lacks exact token(s): {missing}")
    return {
        "model": "SM-A908N",
        "soc": "SM8150",
        "runtime_version": "0.9.285",
        "runtime_build": "v2321-usb-clean-identity-rodata",
        "kernel": EXPECTED_KERNEL,
        "bootloader": "A908NKSU5EWA3",
        "debug_level": "0x4f4c",
        "force_upload": "0x0",
        "dump_sink": "0x0",
    }


def make_envelope(binary: bytes) -> tuple[str, str, str]:
    body = base64.b64encode(binary).decode("ascii")
    return (
        "begin-base64 700 exp014-dram-probe\n",
        body,
        "\n====\n",
    )


def upload_binary(
    host: str,
    port: int,
    binary: bytes,
    timeout: float,
) -> dict[str, object]:
    header, body, footer = make_envelope(binary)
    call(
        host,
        port,
        "cleanup_before",
        ("run", "/bin/toybox", "rm", "-f", REMOTE_ENVELOPE, REMOTE_BINARY),
        timeout,
    )
    call(
        host,
        port,
        "envelope_header",
        ("appendfile", REMOTE_ENVELOPE, header),
        timeout,
        extended=True,
    )
    chunks = [body[offset : offset + MAX_LEGACY_CHUNK]
              for offset in range(0, len(body), MAX_LEGACY_CHUNK)]
    for index, chunk in enumerate(chunks):
        call(
            host,
            port,
            f"payload_{index:04d}",
            ("appendfile", REMOTE_ENVELOPE, chunk),
            timeout,
        )
        if (index + 1) % 50 == 0 or index + 1 == len(chunks):
            print(f"uploaded {index + 1}/{len(chunks)} chunks", flush=True)
    call(
        host,
        port,
        "envelope_footer",
        ("appendfile", REMOTE_ENVELOPE, footer),
        timeout,
        extended=True,
    )
    decode = call(
        host,
        port,
        "decode",
        ("run", "/bin/toybox", "uudecode", "-o", REMOTE_BINARY,
         REMOTE_ENVELOPE),
        timeout,
    )
    require_child_exit_zero(decode.payload, "uudecode")
    chmod = call(
        host,
        port,
        "chmod",
        ("run", "/bin/toybox", "chmod", "700", REMOTE_BINARY),
        timeout,
    )
    require_child_exit_zero(chmod.payload, "chmod")
    remote_hash_frame = call(
        host,
        port,
        "remote_hash",
        ("run", "/bin/toybox", "sha256sum", REMOTE_BINARY),
        timeout,
    )
    require_child_exit_zero(remote_hash_frame.payload, "remote sha256sum")
    match = SHA256_RE.search(remote_hash_frame.payload)
    if match is None:
        raise LiveError("remote sha256sum output is malformed")
    remote_hash = match.group(1).decode("ascii")
    local_hash = sha256(binary)
    if remote_hash != local_hash:
        raise LiveError(
            f"remote binary hash differs: {remote_hash} != {local_hash}"
        )
    return {
        "binary_size": len(binary),
        "binary_sha256": local_hash,
        "base64_bytes": len(body),
        "chunk_bytes": MAX_LEGACY_CHUNK,
        "chunk_count": len(chunks),
        "remote_path": REMOTE_BINARY,
        "remote_sha256_verified": True,
    }


def parse_probe_records(
    payload: bytes, *, require_stability: bool = True
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for raw_line in payload.replace(b"\r\n", b"\n").splitlines():
        if not raw_line.startswith(b"{"):
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise LiveError(f"probe emitted malformed JSON: {raw_line!r}") from exc
        if not isinstance(record, dict) or record.get("schema") != PROBE_SCHEMA:
            raise LiveError("probe emitted a foreign JSON record")
        records.append(record)
    if not records:
        raise LiveError("probe emitted no structured records")
    if require_stability and not any(
        record.get("type") == "stability" for record in records
    ):
        raise LiveError("probe lacks final pagemap stability record")
    return records


def probe_argv(args: argparse.Namespace) -> tuple[str, ...]:
    base = ("run", REMOTE_BINARY)
    mode = args.mode if args.backing == "anonymous" else f"ion-{args.mode}"
    if args.mode == "scan":
        return base + (mode, str(args.mib), args.ion_heap)
    if args.mode == "smoke":
        return base + (mode, str(args.cpu))
    if args.mode == "inventory":
        return base + (
            mode, str(args.mib), str(args.pairs), str(args.cpu)
        )
    differences = tuple(args.difference or ())
    return base + (
        mode, str(args.mib), str(args.repetitions), str(args.pairs),
        str(args.cpu), *differences,
    )


def ensure_private_output(path: Path) -> Path:
    root = (Path.cwd() / "evidence" / "private").resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise LiveError("output directory must remain below evidence/private") from exc
    if resolved.exists():
        raise LiveError(f"output directory already exists: {resolved}")
    resolved.mkdir(parents=True, mode=0o700)
    os.chmod(resolved, 0o700)
    return resolved


def run(args: argparse.Namespace) -> Path:
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    output_dir = ensure_private_output(args.output_dir)
    binary = args.binary.read_bytes()
    transcript_parts: list[bytes] = []
    cleanup_status: dict[str, object] = {"attempted": False, "succeeded": False}

    def recorded_call(
        evidence_id: str,
        argv: tuple[str, ...],
        timeout: float | None = None,
        *,
        allow_error: bool = False,
    ) -> Frame:
        frame = call(
            args.host, args.port, evidence_id, argv,
            args.timeout if timeout is None else timeout,
            allow_error=allow_error,
        )
        transcript_parts.append(
            f"\n===== {evidence_id} =====\n".encode("ascii") + frame.transcript
        )
        return frame

    try:
        recorded_call("hide", ("hide",))
        version_frame = recorded_call("version", ("version",))
        cmdline_frame = recorded_call(
            "cmdline", ("run", "/bin/toybox", "cat", "/proc/cmdline")
        )
        require_child_exit_zero(cmdline_frame.payload, "cmdline")
        target = validate_target(version_frame.payload, cmdline_frame.payload)
        runtime_paths = {
            "cpu_scaling_cur_freq":
                f"/sys/devices/system/cpu/cpu{args.cpu}/cpufreq/scaling_cur_freq",
            "cpu_scaling_governor":
                f"/sys/devices/system/cpu/cpu{args.cpu}/cpufreq/scaling_governor",
            "cpu_scaling_min_freq":
                f"/sys/devices/system/cpu/cpu{args.cpu}/cpufreq/scaling_min_freq",
            "cpu_scaling_max_freq":
                f"/sys/devices/system/cpu/cpu{args.cpu}/cpufreq/scaling_max_freq",
            "cpu_llcc_ddr_bw_cur_freq":
                "/sys/class/devfreq/soc:qcom,cpu-llcc-ddr-bw/cur_freq",
            "cpu_llcc_ddr_bw_available_frequencies":
                "/sys/class/devfreq/soc:qcom,cpu-llcc-ddr-bw/available_frequencies",
            "cpu_llcc_ddr_bw_governor":
                "/sys/class/devfreq/soc:qcom,cpu-llcc-ddr-bw/governor",
        }
        runtime_controls: dict[str, str] = {}
        for key, path in runtime_paths.items():
            frame = recorded_call(
                key, ("run", "/bin/toybox", "cat", path)
            )
            runtime_controls[key] = parse_run_value(frame.payload, key)

        if not args.skip_upload:
            upload = upload_binary(
                args.host, args.port, binary, args.timeout
            )
        else:
            remote_hash_frame = recorded_call(
                "remote_hash_existing",
                ("run", "/bin/toybox", "sha256sum", REMOTE_BINARY),
            )
            require_child_exit_zero(remote_hash_frame.payload, "existing remote hash")
            match = SHA256_RE.search(remote_hash_frame.payload)
            if match is None or match.group(1).decode("ascii") != sha256(binary):
                raise LiveError("existing remote probe hash does not match local binary")
            upload = {
                "binary_size": len(binary),
                "binary_sha256": sha256(binary),
                "remote_path": REMOTE_BINARY,
                "remote_sha256_verified": True,
                "upload_skipped": True,
            }

        ion_device: dict[str, object] | None = None
        if args.backing == "ion":
            ion_dev_frame = recorded_call(
                "ion_dev", ("run", "/bin/toybox", "cat",
                            "/sys/class/misc/ion/dev")
            )
            ion_dev = parse_run_value(ion_dev_frame.payload, "ion_dev")
            if ion_dev != "10:94":
                raise LiveError(f"unexpected live ION misc identity: {ion_dev!r}")
            remove_old = recorded_call(
                "ion_node_remove_before",
                ("run", "/bin/toybox", "rm", "-f", REMOTE_ION),
            )
            require_child_exit_zero(remove_old.payload, "ION node pre-clean")
            create_node = recorded_call(
                "ion_node_create",
                ("run", "/bin/toybox", "mknod", REMOTE_ION,
                 "c", "10", "94"),
            )
            require_child_exit_zero(create_node.payload, "ION node create")
            chmod_node = recorded_call(
                "ion_node_chmod",
                ("run", "/bin/toybox", "chmod", "600", REMOTE_ION),
            )
            require_child_exit_zero(chmod_node.payload, "ION node chmod")
            ion_device = {
                "sysfs_identity": ion_dev,
                "temporary_node": REMOTE_ION,
                "node_created": True,
            }

        run_frame = recorded_call(
            "probe", probe_argv(args), args.probe_timeout, allow_error=True
        )
        write_new(output_dir / "probe-output.bin", run_frame.payload)
        require_child_exit_zero(run_frame.payload, "probe")
        records = parse_probe_records(
            run_frame.payload, require_stability=args.mode != "scan"
        )
        if args.mode == "scan":
            if not any(record.get("type") == "scan_complete" for record in records):
                raise LiveError("ION kpage scan lacks completion record")
        else:
            stability = [
                record for record in records if record.get("type") == "stability"
            ][-1]
            if (stability.get("changed_pages") != 0 or
                    stability.get("lost_pages") != 0):
                raise LiveError(
                    f"physical page identity changed during probe: {stability}"
                )

        completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        manifest = {
            "schema": SCHEMA,
            "experiment_id": args.experiment_id,
            "started_utc": started,
            "completed_utc": completed,
            "target": target,
            "bridge": {"host": args.host, "port": args.port},
            "mode": args.mode,
            "backing": args.backing,
            "ion_device": ion_device,
            "runtime_controls": runtime_controls,
            "probe_argv": list(probe_argv(args)[2:]),
            "source": {
                "path": str(args.source),
                "sha256": sha256(args.source.read_bytes()),
            },
            "upload": upload,
            "records": records,
            "result": (
                "PASS_ION_KPAGE_SCAN" if args.mode == "scan"
                else "PASS_NORMAL_RAM_PROBE"
            ),
            "scope": {
                "normal_ram_only": True,
                "anonymous_backing": args.backing == "anonymous",
                "pagemap_read": args.mode != "scan",
                "kpageflags_read": args.mode == "scan",
                "el0_cache_maintenance": args.backing == "anonymous",
                "ion_uncached_writecombine": args.backing == "ion",
                "mmio": False,
                "partition_write": False,
                "smc": False,
                "protected_memory": False,
            },
        }
        write_new(output_dir / "manifest.json", json_bytes(manifest))
        return output_dir
    finally:
        if args.backing == "ion":
            try:
                ion_cleanup = recorded_call(
                    "ion_node_remove_after",
                    ("run", "/bin/toybox", "rm", "-f", REMOTE_ION),
                )
                require_child_exit_zero(ion_cleanup.payload, "ION node cleanup")
                cleanup_status["ion_node_removed"] = True
            except Exception as exc:
                cleanup_status["ion_node_removed"] = False
                cleanup_status["ion_node_error"] = str(exc)
        if not args.keep_remote:
            cleanup_status["attempted"] = True
            try:
                cleanup = recorded_call(
                    "cleanup_after",
                    ("run", "/bin/toybox", "rm", "-f",
                     REMOTE_ENVELOPE, REMOTE_BINARY),
                )
                require_child_exit_zero(cleanup.payload, "cleanup")
                cleanup_status["succeeded"] = True
            except Exception as exc:  # preserve evidence before propagating
                cleanup_status["error"] = str(exc)
        transcript_parts.append(
            b"\n===== cleanup_status =====\n" + json_bytes(cleanup_status)
        )
        transcript_path = output_dir / "transport-transcript.bin"
        if not transcript_path.exists():
            write_new(transcript_path, b"".join(transcript_parts))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--probe-timeout", type=float, default=300.0)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--source", type=Path, default=Path("tools/a90_dram_timing_probe.c")
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--mode", choices=("smoke", "inventory", "measure", "scan"),
                        required=True)
    parser.add_argument("--backing", choices=("anonymous", "ion"),
                        default="anonymous")
    parser.add_argument("--cpu", type=int, default=7)
    parser.add_argument("--mib", type=int, default=256)
    parser.add_argument("--pairs", type=int, default=64)
    parser.add_argument("--repetitions", type=int, default=201)
    parser.add_argument("--difference", action="append")
    parser.add_argument("--ion-heap", choices=("system", "user_contig"),
                        default="user_contig")
    parser.add_argument("--skip-upload", action="store_true")
    parser.add_argument("--keep-remote", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise LiveError("only the pinned loopback bridge is accepted")
    if not 0 < args.port < 65536:
        raise LiveError("port falls outside TCP range")
    if not 0 <= args.cpu < 1024:
        raise LiveError("cpu falls outside supported affinity range")
    if not 1 <= args.mib <= 3072:
        raise LiveError("MiB must be 1..3072")
    if not 1 <= args.pairs <= 128:
        raise LiveError("pairs must be 1..128")
    if not 3 <= args.repetitions <= 10001:
        raise LiveError("repetitions must be 3..10001")
    if args.difference and len(args.difference) > MAX_DEVICE_DIFFERENCES:
        raise LiveError(
            f"at most {MAX_DEVICE_DIFFERENCES} explicit differences fit A90P1"
        )
    if args.mode == "scan" and args.backing != "ion":
        raise LiveError("scan mode requires --backing ion")
    if not args.binary.is_file() or not args.source.is_file():
        raise LiveError("probe binary/source is missing")
    output = run(args)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
