#!/usr/bin/env python3
"""Historical fixed SM8150 qhs_llcc REPL read experiment.

Live execution is disabled.  Experiment 007 observed a verified ``__ioremap``
return followed by a non-secure watchdog before ``msm_readl``.  The pure
planning helpers remain for evidence review and tests, but this file must not
be used to repeat the generic-REPL call path.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new


EXTERNAL_DRIVER = Path(
    "/home/temmie/dev/android-native-init-lab/workspace/public/src/scripts/"
    "revalidation/a90_repl.py"
)
EXTERNAL_DRIVER_SHA256 = (
    "98493464c7fb53bff122c8c3291c1a718837b8e2015ce33618dac204482f9f3b"
)
DEFAULT_PRIVATE_DIR = Path(
    "evidence/private/007-kernel-remapper-readonly-20260825-02"
)
DEFAULT_IMAGE = DEFAULT_PRIVATE_DIR / "boot_linux_tier2_repl_v1_repl.img"
DEFAULT_MAP = DEFAULT_PRIVATE_DIR / "System.map"
CANDIDATE_SHA256 = "b846ae9f74d8ceb922bbcd854d78b6795ef833d61e38465d3cc474cb6f0dfb65"
BASES = (0x09248080, 0x092C8080, 0x09348080, 0x093C8080)
WINDOW_SIZE = 0x5C
# Exact source: arm64 pgtable-prot.h with CONFIG_UNMAP_KERNEL_AT_EL0=n.
PROT_DEVICE_NGNRE = 0x0068000000000707
JOPP_MAGIC = 0x00BE7BAD
SYMBOLS = ("__ioremap", "msm_readl", "__iounmap")
EXPECTED_PREFIXES = {
    "__ioremap": (0xCA1103D0, 0xA9BF43FD, 0x910003FD, 0xAA1E03E3),
    "msm_readl": (0xCA1103D0, 0xA9BE43FD, 0xA9014FF4, 0x910003FD),
    "__iounmap": (0xCA1103D0, 0xA9BE43FD, 0xF9000BF3, 0x910003FD),
}
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
LIVE_EXECUTION_ENABLED = False
LIVE_DISABLED_REASON = (
    "known watchdog path disabled: Experiment 007 observed __ioremap return "
    "followed by Non Secure Watchdog Bark before msm_readl"
)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_driver(path: Path = EXTERNAL_DRIVER):
    if sha256_file(path) != EXTERNAL_DRIVER_SHA256:
        raise RuntimeError("external A90 REPL driver SHA-256 mismatch")
    parent = str(path.resolve().parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    return importlib.import_module("a90_repl")


def frame_record(evidence_id: str, argv: Sequence[str], frame: Any) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "argv": list(argv),
        "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
        "payload_sha256": sha256_bytes(frame.payload),
        "transcript_sha256": sha256_bytes(frame.transcript),
        "begin": frame.begin,
        "end": frame.end,
    }


def parse_single_decimal(payload: bytes) -> int:
    text = payload.decode("ascii", errors="strict").strip()
    if re.fullmatch(r"[0-9]+", text) is None:
        raise ValueError(f"expected one decimal integer, got {text!r}")
    return int(text, 10)


def symbol_links(symbols: dict[str, Any], image: Any) -> dict[str, int]:
    links: dict[str, int] = {}
    for name in SYMBOLS:
        symbol = symbols.get(name)
        if symbol is None:
            raise RuntimeError(f"required symbol missing from exact map: {name}")
        link = int(symbol.vaddr)
        if image.u32_at_vaddr(link - 4) != JOPP_MAGIC:
            raise RuntimeError(f"{name} is not a JOPP function entry")
        prefix = tuple(image.u32_words_at_vaddr(link, len(EXPECTED_PREFIXES[name])))
        if prefix != EXPECTED_PREFIXES[name]:
            raise RuntimeError(f"{name} static prefix mismatch")
        links[name] = link
    return links


def read_fixed_controls(
    session: Any,
    symbols: dict[str, Any],
    image: Any,
    *,
    public_records: list[dict[str, object]] | None = None,
    raw_measurement: dict[str, object] | None = None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    links = symbol_links(symbols, image)
    slide = int(session.slide())
    if slide & 0xFFF:
        raise RuntimeError("kernel slide is not page-aligned")

    raw = raw_measurement if raw_measurement is not None else {}
    raw.update({
        "slide": f"0x{slide:x}",
        "symbol_links": {name: f"0x{link:x}" for name, link in links.items()},
        "records": [],
    })
    public = public_records if public_records is not None else []

    for index, base in enumerate(BASES):
        mapped = 0
        raw_record: dict[str, object] = {
            "index": index,
            "physical_base": f"0x{base:08x}",
        }
        try:
            mapped = int(
                session.call_runtime(
                    links["__ioremap"] + slide,
                    (base, WINDOW_SIZE, PROT_DEVICE_NGNRE),
                )
            )
            raw_record["mapped_runtime"] = f"0x{mapped:x}"
            if mapped == 0 or mapped & 0x3:
                raise RuntimeError(f"__ioremap returned invalid pointer for window {index}")
            value = int(
                session.call_runtime(links["msm_readl"] + slide, (mapped,))
            )
            if value >> 32:
                raise RuntimeError(f"msm_readl returned non-u32 value for window {index}")
            raw_record["value"] = f"0x{value:08x}"
            public.append(
                {
                    "index": index,
                    "base": f"0x{base:08x}",
                    "offset": "0x00",
                    "width_bits": 32,
                    "value": f"0x{value:08x}",
                }
            )
        finally:
            if mapped:
                session.call_runtime(links["__iounmap"] + slide, (mapped,))
                raw_record["iounmap_completed"] = True
            cast_records = raw["records"]
            assert isinstance(cast_records, list)
            cast_records.append(raw_record)
    return public, raw


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    # Fail before parsing paths, hashing artifacts, opening the bridge, or
    # issuing any device command.  There is deliberately no CLI override.
    if not LIVE_EXECUTION_ENABLED:
        raise RuntimeError(LIVE_DISABLED_REASON)
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    if sha256_file(args.image) != CANDIDATE_SHA256:
        raise RuntimeError("live-proven REPL candidate SHA-256 mismatch")

    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    driver = load_driver(args.driver)
    symbols = driver.load_system_map(args.map)
    image = driver.load_static_image(args.image)
    links = symbol_links(symbols, image)
    session = driver.ReplSession(
        driver.ReplConfig(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            safe_op_retries=0,
            retry_delay_sec=0,
            # Match the transport mode that passed the live REPL selftest.
            # Each op already drains dmesg immediately before the write and
            # reads it back in the same shell; the optional marker mode lost
            # the op=0 A90R line on this resident kernel.
            use_kmsg_markers=False,
        )
    )

    frames: list[dict[str, object]] = []
    public_records: list[dict[str, object]] = []
    raw_measurement: dict[str, object] = {}
    outcome = "READ_FAILED"
    failed_stage: str | None = "preflight"
    error_type: str | None = None
    error_text: str | None = None
    panic_before: int | None = None
    panic_changed = False
    panic_restored = False
    health_after: dict[str, object] = {}

    try:
        # Establish the same resident-console precondition as the live-proven
        # harness before even the short preflight commands; the auto-menu can
        # otherwise race the second command and return EBUSY.
        session.hide()
        version_before = exchange(
            args.host, args.port, Command("version_before", ("version",)), args.timeout
        )
        frames.append(frame_record("version_before", ("version",), version_before))
        panic_frame = exchange(
            args.host,
            args.port,
            Command("panic_before", ("cat", "/proc/sys/kernel/panic_on_oops")),
            args.timeout,
        )
        frames.append(
            frame_record(
                "panic_before", ("cat", "/proc/sys/kernel/panic_on_oops"), panic_frame
            )
        )
        panic_before = parse_single_decimal(panic_frame.payload)
        failed_stage = "temporary-panic-on-oops-zero"
        if panic_before != 0:
            session.set_panic_on_oops(0)
            panic_changed = True
        else:
            panic_restored = True

        failed_stage = "fixed-four-window-read"
        read_fixed_controls(
            session,
            symbols,
            image,
            public_records=public_records,
            raw_measurement=raw_measurement,
        )
        outcome = "READABLE"
        failed_stage = None
    except Exception as exc:  # Evidence must survive a bounded negative result.
        error_type = type(exc).__name__
        error_text = str(exc)
    finally:
        if panic_before is not None and panic_changed:
            try:
                session.set_panic_on_oops(panic_before)
                panic_restored = True
            except Exception as exc:
                if error_type is None:
                    error_type = type(exc).__name__
                    error_text = str(exc)
                    failed_stage = "panic-on-oops-restore"
                    outcome = "READ_FAILED"
        try:
            version_after = exchange(
                args.host, args.port, Command("version_after", ("version",)), args.timeout
            )
            frames.append(frame_record("version_after", ("version",), version_after))
            health_after["version_status"] = version_after.end["status"]
            selftest_after = exchange(
                args.host,
                args.port,
                Command("selftest_after", ("selftest", "status")),
                args.timeout,
            )
            frames.append(
                frame_record("selftest_after", ("selftest", "status"), selftest_after)
            )
            health_after["selftest_status"] = selftest_after.end["status"]
            health_after["selftest_payload_sha256"] = sha256_bytes(selftest_after.payload)
        except Exception as exc:
            health_after["error_type"] = type(exc).__name__
            if error_type is None:
                error_type = type(exc).__name__
                error_text = str(exc)
                failed_stage = "post-health"
                outcome = "READ_FAILED"

    completed = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    raw = {
        "schema": "sdm855-a90-repl-mmio-readonly-raw-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "candidate_sha256": CANDIDATE_SHA256,
        "map_sha256": sha256_file(args.map),
        "driver_sha256": EXTERNAL_DRIVER_SHA256,
        "fixed_bases": [f"0x{base:08x}" for base in BASES],
        "window_size": WINDOW_SIZE,
        "prot_device_ngnre": f"0x{PROT_DEVICE_NGNRE:016x}",
        "symbol_links": {name: f"0x{link:x}" for name, link in links.items()},
        "frames": frames,
        "measurement": raw_measurement,
        "outcome": outcome,
        "failed_stage": failed_stage,
        "error_type": error_type,
        "error_text": error_text,
        "panic_on_oops_before": panic_before,
        "panic_on_oops_restored": panic_restored,
        "health_after": health_after,
        "memory_or_mmio_writes": False,
        "temporary_kernel_setting_mutation": panic_changed,
    }
    raw_bytes = json_bytes(raw)
    raw_path = args.output_root / "evidence" / "private" / f"{args.experiment_id}.json"
    public_path = (
        args.output_root
        / "evidence"
        / "manifests"
        / f"{args.experiment_id}.manifest.json"
    )
    write_new(raw_path, raw_bytes, 0o600)

    manifest = {
        "schema": "sdm855-a90-repl-mmio-readonly-manifest-v1",
        "experiment_id": args.experiment_id,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "started_utc": started,
        "completed_utc": completed,
        "outcome": outcome,
        "failed_stage": failed_stage,
        "error_type": error_type,
        "candidate_sha256": CANDIDATE_SHA256,
        "map_sha256": sha256_file(args.map),
        "driver_sha256": EXTERNAL_DRIVER_SHA256,
        "memory_or_mmio_writes": False,
        "temporary_panic_on_oops_mutation": panic_changed,
        "panic_on_oops_restored": panic_restored,
        "automatic_retries": False,
        "arbitrary_address_input": False,
        "read_success_count": len(public_records),
        "records": public_records,
        "health_after": health_after,
        "raw_snapshot_sha256": sha256_bytes(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
        "claim_boundary": (
            "READABLE proves post-boot EL1 kernel-space observation of the fixed "
            "XBL-programmed control words only; it does not prove writability, "
            "aliasing, final DRAM hashing, or protection bypass"
            if outcome == "READABLE"
            else "READ_FAILED at the recorded stage; it does not by itself prove "
            "hardware immutability, secure ownership, or post-transform protection"
        ),
    }
    write_new(public_path, json_bytes(manifest), 0o644)
    if outcome != "READABLE":
        raise RuntimeError(
            f"fixed remapper read failed at {failed_stage}: {error_type}; "
            f"evidence={public_path}"
        )
    return raw_path, public_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read four fixed XBL-programmed remapper control words via A90 REPL"
    )
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--image", type=Path, default=DEFAULT_IMAGE)
    parser.add_argument("--map", type=Path, default=DEFAULT_MAP)
    parser.add_argument("--driver", type=Path, default=EXTERNAL_DRIVER)
    parser.add_argument("--output-root", type=Path, default=Path("."))
    return parser


def main() -> int:
    args = make_parser().parse_args()
    raw_path, public_path = collect(args)
    print(f"private={raw_path}")
    print(f"public={public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
