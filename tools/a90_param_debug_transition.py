#!/usr/bin/env python3
"""Apply or restore the exact A90 ``param.debuglevel`` four-byte transition.

The tool has two fixed actions: LOW->MID and MID->LOW.  It cannot accept a
partition, offset, value, block device, or payload path from the command line.
Before the one-shot effect it binds the exact runtime and GPT identity, verifies
the complete live partition hash, verifies the retained rollback artifact, and
proves the exact Toybox ``dd`` semantics on a temporary regular file.  It then
writes four bytes once and requires the complete post-write partition hash to
equal a host-derived expected image.  It never replays an ambiguous effect and
does not reboot the device.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_param_capture import (
        PARAM_DEBUG_OFFSET,
        PARAM_PARTITION_BYTES,
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        decode_fields,
        discover_param,
        parse_cmdline,
        validate_runtime,
    )
    from tools.a90_partition_capture import (
        create_and_validate_node,
        device_sha256,
        remove_node,
        run_toybox,
        text_exchange,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new  # type: ignore
    from a90_param_capture import (  # type: ignore
        PARAM_DEBUG_OFFSET,
        PARAM_PARTITION_BYTES,
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        decode_fields,
        discover_param,
        parse_cmdline,
        validate_runtime,
    )
    from a90_partition_capture import (  # type: ignore
        create_and_validate_node,
        device_sha256,
        remove_node,
        run_toybox,
        text_exchange,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
ROLLBACK_IMAGE = (
    REPO_ROOT
    / "evidence/private/verification-006-a90-param-capture-20260825-01/param--sda10.bin"
)
ROLLBACK_SHA256 = "1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345"
MID_SHA256 = "50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256"

LOW_BYTES = b"DLOW"
MID_BYTES = b"DMID"
PAYLOAD_PATH = "/tmp/sdm855_mblab_param_debug_payload"
SMOKE_PATH = "/tmp/sdm855_mblab_param_debug_dd_smoke"
DD_BLOCK_SIZE = 4
DD_SEEK_BLOCKS = PARAM_DEBUG_OFFSET // DD_BLOCK_SIZE
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SHA_LINE_RE = re.compile(rb"(?m)^([0-9a-f]{64})  (/.+?)\r?$")


@dataclass(frozen=True)
class Transition:
    action: str
    before_bytes: bytes
    after_bytes: bytes
    before_sha256: str
    after_sha256: str
    before_label: str
    after_label: str


TRANSITIONS = {
    "apply-mid": Transition(
        "apply-mid", LOW_BYTES, MID_BYTES, ROLLBACK_SHA256, MID_SHA256, "LOW", "MID"
    ),
    "restore-low": Transition(
        "restore-low", MID_BYTES, LOW_BYTES, MID_SHA256, ROLLBACK_SHA256, "MID", "LOW"
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_images(path: Path = ROLLBACK_IMAGE) -> tuple[bytes, bytes]:
    original = path.read_bytes()
    if len(original) != PARAM_PARTITION_BYTES:
        raise ValueError("rollback image is not exactly 10 MiB")
    if sha256(original) != ROLLBACK_SHA256:
        raise ValueError("rollback image SHA-256 differs from the pinned capture")
    if original[PARAM_DEBUG_OFFSET : PARAM_DEBUG_OFFSET + 4] != LOW_BYTES:
        raise ValueError("rollback image does not contain DLOW at the exact field")
    modified = bytearray(original)
    modified[PARAM_DEBUG_OFFSET : PARAM_DEBUG_OFFSET + 4] = MID_BYTES
    modified_bytes = bytes(modified)
    if sha256(modified_bytes) != MID_SHA256:
        raise ValueError("host-derived MID image SHA-256 differs from the pin")
    differences = [
        offset
        for offset, (before, after) in enumerate(zip(original, modified_bytes))
        if before != after
    ]
    if differences != [PARAM_DEBUG_OFFSET + 1, PARAM_DEBUG_OFFSET + 2, PARAM_DEBUG_OFFSET + 3]:
        raise ValueError(f"unexpected host image delta: {differences}")
    return original, modified_bytes


def transition_images(
    transition: Transition, original: bytes, modified: bytes
) -> tuple[bytes, bytes]:
    if transition.action == "apply-mid":
        return original, modified
    if transition.action == "restore-low":
        return modified, original
    raise ValueError(f"unsupported transition: {transition.action}")


def fixed_dd_args(input_path: str, output_path: str) -> tuple[str, ...]:
    return (
        "dd",
        f"if={input_path}",
        f"of={output_path}",
        f"bs={DD_BLOCK_SIZE}",
        "count=1",
        f"seek={DD_SEEK_BLOCKS}",
        "conv=notrunc,fsync",
        "status=none",
    )


def _atomic_replace_json(path: Path, value: object, mode: int = 0o600) -> None:
    data = json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(f"journal temporary already exists: {temporary}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _remove_temp(host: str, port: int, path: str, timeout: float, evidence: str) -> None:
    run_toybox(host, port, evidence, ("rm", "-f", path), timeout)


def _write_ascii_payload(
    host: str, port: int, path: str, payload: bytes, timeout: float
) -> dict[str, object]:
    text = payload.decode("ascii", errors="strict")
    _remove_temp(host, port, path, timeout, "payload_cleanup_before")
    run_toybox(host, port, "payload_touch", ("touch", path), timeout)
    text_exchange(host, port, "payload_write", ("writefile", path, text), timeout)
    stat = text_exchange(host, port, "payload_stat", ("stat", path), timeout)
    if b"size=4" not in stat:
        raise ValueError(f"payload stat does not report exact size 4: {stat!r}")
    readback = text_exchange(host, port, "payload_readback", ("cat", path), timeout)
    if readback != payload:
        raise ValueError(f"payload readback mismatch: {readback!r}")
    hash_payload = run_toybox(
        host, port, "payload_sha256", ("sha256sum", path), timeout
    )
    matches = SHA_LINE_RE.findall(hash_payload)
    hashes = [digest.decode("ascii") for digest, item in matches if item == path.encode()]
    if hashes != [sha256(payload)]:
        raise ValueError(f"payload SHA-256 mismatch: {hashes}")
    return {
        "path": path,
        "size": len(payload),
        "sha256": hashes[0],
        "readback_base64": base64.b64encode(readback).decode("ascii"),
    }


def verify_regular_file_dd(
    host: str, port: int, payload_path: str, payload: bytes, timeout: float
) -> dict[str, object]:
    _remove_temp(host, port, SMOKE_PATH, timeout, "smoke_cleanup_before")
    run_toybox(host, port, "smoke_touch", ("touch", SMOKE_PATH), timeout)
    text_exchange(
        host,
        port,
        "smoke_seed",
        ("writefile", SMOKE_PATH, "AAAABBBBCCCC"),
        timeout,
    )
    args = (
        "dd",
        f"if={payload_path}",
        f"of={SMOKE_PATH}",
        "bs=4",
        "count=1",
        "seek=1",
        "conv=notrunc,fsync",
        "status=none",
    )
    frame = exchange(
        host,
        port,
        Command("smoke_dd", ("run", "/bin/toybox", *args)),
        timeout,
        allow_error=True,
    )
    readback = text_exchange(host, port, "smoke_readback", ("cat", SMOKE_PATH), timeout)
    expected = b"AAAA" + payload + b"CCCC"
    if int(frame.end["rc"], 0) != 0 or frame.end["status"] != "ok":
        raise ValueError(f"regular-file dd smoke failed: {frame.end}")
    if readback != expected:
        raise ValueError(f"regular-file dd semantics changed: {readback!r}")
    _remove_temp(host, port, SMOKE_PATH, timeout, "smoke_cleanup_after")
    return {
        "args": list(args),
        "a90p1_end": frame.end,
        "expected_sha256": sha256(expected),
        "readback_sha256": sha256(readback),
        "passed": True,
    }


def _preflight(args: argparse.Namespace) -> tuple[dict[str, str], str, object, int]:
    version_frame = exchange(
        args.host, args.port, Command("version", ("version",)), args.command_timeout
    )
    cmdline_frame = exchange(
        args.host,
        args.port,
        Command("proc_cmdline", ("cat", "/proc/cmdline")),
        args.command_timeout,
    )
    cmdline = parse_cmdline(cmdline_frame.payload)
    validate_runtime(version_frame.payload, cmdline)
    if cmdline.get("androidboot.force_upload") != "0x0":
        raise ValueError("force_upload changed from the required zero state")
    if cmdline.get("sec_debug.dump_sink") != "0x0":
        raise ValueError("dump_sink changed from the required USB-default state")
    dload_frame = exchange(
        args.host,
        args.port,
        Command(
            "download_mode",
            ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
        ),
        args.command_timeout,
    )
    dload = dload_frame.payload.decode("ascii", errors="strict").strip()
    if dload != "1":
        raise ValueError("download_mode is not 1")
    partition, start_sector = discover_param(args.host, args.port, args.command_timeout)
    return cmdline, dload, partition, start_sector


def execute(args: argparse.Namespace) -> tuple[Path, Path]:
    if not args.execute:
        raise ValueError("persistent transition requires explicit --execute")
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("transition only accepts a loopback bridge")
    transition = TRANSITIONS[args.action]
    original, modified = derive_images()
    before_image, after_image = transition_images(transition, original, modified)
    if sha256(before_image) != transition.before_sha256:
        raise ValueError("transition before-image pin mismatch")
    if sha256(after_image) != transition.after_sha256:
        raise ValueError("transition after-image pin mismatch")
    before_fields = decode_fields(before_image)
    after_fields = decode_fields(after_image)
    if before_fields["debuglevel"]["label"] != transition.before_label:
        raise ValueError("before debug label mismatch")
    if after_fields["debuglevel"]["label"] != transition.after_label:
        raise ValueError("after debug label mismatch")
    for name in ("force_upload_flag", "FMM_lock", "dump_sink"):
        if before_fields[name]["value"] != after_fields[name]["value"]:
            raise ValueError(f"non-debug field changed in host model: {name}")

    root = args.output_root.resolve()
    journal_path = root / "evidence/private" / f"{args.experiment_id}.journal.json"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    if journal_path.exists() or manifest_path.exists():
        raise FileExistsError("transition evidence already exists; effects are never replayed")

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    cmdline, dload, partition, start_sector = _preflight(args)
    if args.action == "apply-mid" and cmdline.get("androidboot.debug_level") != "0x4f4c":
        raise ValueError("apply preflight cmdline is not LOW")
    if args.action == "restore-low" and cmdline.get("androidboot.debug_level") not in {
        "0x4f4c",
        "0x494d",
    }:
        raise ValueError("restore preflight cmdline is neither LOW nor MID")

    journal: dict[str, object] = {
        "schema": "sdm855-a90-param-debug-transition-journal-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "action": transition.action,
        "status": "PREFLIGHT",
        "effect_dispatched": False,
        "effect_replayed": False,
        "target": {
            "model": TARGET_MODEL,
            "soc": TARGET_SOC,
            "bootloader": TARGET_BOOTLOADER,
            "runtime": TARGET_RUNTIME,
            "kernel": TARGET_KERNEL,
        },
        "partition": {**asdict(partition), "start_sector": start_sector},
        "transition": {
            "partition_offset": f"0x{PARAM_DEBUG_OFFSET:06x}",
            "size": 4,
            "before_label": transition.before_label,
            "after_label": transition.after_label,
            "before_bytes_hex": transition.before_bytes.hex(),
            "after_bytes_hex": transition.after_bytes.hex(),
            "before_sha256": transition.before_sha256,
            "after_sha256": transition.after_sha256,
        },
        "cmdline_before": cmdline,
        "download_mode_before": dload,
    }
    _atomic_replace_json(journal_path, journal)

    payload_record: dict[str, object] | None = None
    smoke_record: dict[str, object] | None = None
    before_hash: str | None = None
    after_hash: str | None = None
    effect_frame = None
    try:
        create_and_validate_node(args.host, args.port, partition, args.command_timeout)
        before_hash = device_sha256(
            args.host, args.port, partition, args.hash_timeout, "transition_before"
        )
        journal["device_sha256_before"] = before_hash
        if before_hash != transition.before_sha256:
            journal["status"] = "REFUSED_BEFORE_EFFECT_HASH_MISMATCH"
            _atomic_replace_json(journal_path, journal)
            raise ValueError(
                f"live param SHA-256 {before_hash} != required {transition.before_sha256}"
            )

        payload_record = _write_ascii_payload(
            args.host,
            args.port,
            PAYLOAD_PATH,
            transition.after_bytes,
            args.command_timeout,
        )
        smoke_record = verify_regular_file_dd(
            args.host,
            args.port,
            PAYLOAD_PATH,
            transition.after_bytes,
            args.command_timeout,
        )
        dd_args = fixed_dd_args(PAYLOAD_PATH, partition.node_path)
        journal.update(
            {
                "status": "EFFECT_DISPATCH_STARTED",
                "effect_dispatched": True,
                "payload": payload_record,
                "regular_file_dd_smoke": smoke_record,
                "effect_argv": ["run", "/bin/toybox", *dd_args],
            }
        )
        _atomic_replace_json(journal_path, journal)

        effect_frame = exchange(
            args.host,
            args.port,
            Command("param_debug_transition", ("run", "/bin/toybox", *dd_args)),
            args.effect_timeout,
            allow_error=True,
        )
        journal["effect_receipt"] = {
            "begin": effect_frame.begin,
            "end": effect_frame.end,
            "payload_base64": base64.b64encode(effect_frame.payload).decode("ascii"),
            "transcript_sha256": sha256(effect_frame.transcript),
        }
        journal["status"] = "EFFECT_RETURNED_VERIFYING_FULL_HASH"
        _atomic_replace_json(journal_path, journal)

        after_hash = device_sha256(
            args.host, args.port, partition, args.hash_timeout, "transition_after"
        )
        journal["device_sha256_after"] = after_hash
        rc_ok = int(effect_frame.end["rc"], 0) == 0 and effect_frame.end["status"] == "ok"
        hash_ok = after_hash == transition.after_sha256
        if not rc_ok or not hash_ok:
            journal["status"] = (
                "NO_EFFECT_REPLAY_FORBIDDEN"
                if after_hash == transition.before_sha256
                else "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
            )
            _atomic_replace_json(journal_path, journal)
            raise RuntimeError(
                f"transition verification failed: rc_ok={rc_ok} "
                f"after={after_hash}; effect was dispatched once and will not be replayed"
            )
        journal["status"] = "APPLIED_VERIFIED" if args.action == "apply-mid" else "RESTORED_VERIFIED"
        journal["completed_utc"] = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat()
        _atomic_replace_json(journal_path, journal)
    except BaseException as exc:
        if journal.get("effect_dispatched") and journal.get("status") in {
            "EFFECT_DISPATCH_STARTED",
            "EFFECT_RETURNED_VERIFYING_FULL_HASH",
        }:
            journal["status"] = "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
            journal["error"] = f"{type(exc).__name__}: {exc}"
            _atomic_replace_json(journal_path, journal)
        raise
    finally:
        try:
            _remove_temp(
                args.host, args.port, PAYLOAD_PATH, args.command_timeout, "payload_cleanup_after"
            )
            _remove_temp(
                args.host, args.port, SMOKE_PATH, args.command_timeout, "smoke_cleanup_final"
            )
        finally:
            remove_node(args.host, args.port, partition, args.command_timeout)

    completed = str(journal["completed_utc"])
    manifest = {
        "schema": "sdm855-a90-param-debug-transition-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "action": transition.action,
        "classification": journal["status"],
        "partition": {**asdict(partition), "start_sector": start_sector},
        "transition": journal["transition"],
        "device_sha256_before": before_hash,
        "device_sha256_after": after_hash,
        "full_hash_verified": after_hash == transition.after_sha256,
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "effect_a90p1_end": effect_frame.end if effect_frame else None,
        "payload": {
            "size": payload_record["size"],
            "sha256": payload_record["sha256"],
        },
        "regular_file_dd_smoke": smoke_record,
        "cmdline_before_reboot": {
            "androidboot.debug_level": cmdline.get("androidboot.debug_level"),
            "androidboot.force_upload": cmdline.get("androidboot.force_upload"),
            "sec_debug.dump_sink": cmdline.get("sec_debug.dump_sink"),
        },
        "download_mode_before": dload,
        "device_rebooted": False,
        "claims": {
            "PROVED": [
                "Exactly one four-byte bounded write effect was dispatched to the exact live param partition and the full post-write hash matched the host-derived expected image.",
                "force_upload_flag, FMM_lock and dump_sink are unchanged in the host-derived before/after images whose complete SHA-256 values bound the live transition.",
            ],
            "UNKNOWN": [
                "The current boot still reflects the pre-transition XBL cmdline until a separate normal reboot consumes the persistent field.",
            ],
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return journal_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--action", required=True, choices=tuple(TRANSITIONS))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=45.0)
    parser.add_argument("--hash-timeout", type=float, default=90.0)
    parser.add_argument("--effect-timeout", type=float, default=45.0)
    parser.add_argument("--output-root", type=Path, default=REPO_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    journal, manifest = execute(args)
    print(f"journal: {journal}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
