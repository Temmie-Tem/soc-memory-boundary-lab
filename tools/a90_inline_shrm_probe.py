#!/usr/bin/env python3
"""Invoke one fixed inline SHRM control/read operation on the exact A90.

The flashed boot candidate supplies the address and complete operation. This
host tool sends only command-buffer magic plus op 4. It accepts no physical
address, call target, width, or value and never retries the operation.
"""

from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_repl_mmio_snapshot import (
        EXTERNAL_DRIVER,
        EXTERNAL_DRIVER_SHA256,
        SAFE_ID_RE,
        frame_record,
        load_driver,
        parse_single_decimal,
        sha256_bytes,
        sha256_file,
    )
    from tools.a90_inline_remapper_probe import run_fixed_inline_op
    from tools import build_a90_inline_remapper_candidate as inline
    from tools import build_a90_inline_shrm_candidate as candidate
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from a90_repl_mmio_snapshot import (
        EXTERNAL_DRIVER,
        EXTERNAL_DRIVER_SHA256,
        SAFE_ID_RE,
        frame_record,
        load_driver,
        parse_single_decimal,
        sha256_bytes,
        sha256_file,
    )
    from a90_inline_remapper_probe import run_fixed_inline_op
    import build_a90_inline_remapper_candidate as inline
    import build_a90_inline_shrm_candidate as candidate


DEFAULT_CANDIDATES = {
    mode: Path("evidence/private/013-inline-shrm-snapshot-20260825-01")
    / candidate.output_names(mode)[0]
    for mode in inline.MODES
}
EXPECTED_CANDIDATES = {
    mode: candidate.EXPECTED_HASHES[mode]["candidate"] for mode in inline.MODES
}
MAP_FAILURE_RESULT = (1 << 64) - 1


def classify_value(mode: str, value: int) -> str:
    if value == MAP_FAILURE_RESULT:
        return "MAP_FAILED"
    if mode == inline.MODE_CONTROL:
        return "CONTROL_PASS" if value == inline.CONTROL_SENTINEL else "CONTROL_UNEXPECTED"
    if mode == inline.MODE_READ:
        return "READABLE" if 0 <= value <= 0xFFFFFFFF else "READ_UNEXPECTED"
    raise ValueError(f"unsupported mode: {mode}")


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    expected_candidate_sha = EXPECTED_CANDIDATES[args.mode]
    candidate_path = DEFAULT_CANDIDATES[args.mode].resolve()
    if sha256_file(candidate_path) != expected_candidate_sha:
        raise RuntimeError(f"{args.mode} SHRM candidate SHA-256 mismatch")
    driver = load_driver(args.driver)
    session = driver.ReplSession(
        driver.ReplConfig(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            safe_op_retries=0,
            retry_delay_sec=0,
            use_kmsg_markers=False,
        )
    )

    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    frames: list[dict[str, object]] = []
    panic_before: int | None = None
    panic_changed = False
    panic_restored = False
    value: int | None = None
    outcome = "PROBE_FAILED"
    failed_stage: str | None = "preflight"
    error_type: str | None = None
    error_text: str | None = None
    health_after: dict[str, object] = {}

    try:
        session.hide()
        before = exchange(
            args.host, args.port, Command("version_before", ("version",)), args.timeout
        )
        frames.append(frame_record("version_before", ("version",), before))
        selftest_before = exchange(
            args.host,
            args.port,
            Command("selftest_before", ("selftest", "status")),
            args.timeout,
        )
        frames.append(
            frame_record(
                "selftest_before", ("selftest", "status"), selftest_before
            )
        )
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

        failed_stage = "fixed-inline-op"
        value = run_fixed_inline_op(session)
        outcome = classify_value(args.mode, value)
        failed_stage = None if outcome in {"CONTROL_PASS", "READABLE"} else "result"
    except Exception as exc:
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
                    outcome = "PROBE_FAILED"
        try:
            session.hide()
            after = exchange(
                args.host, args.port, Command("version_after", ("version",)), args.timeout
            )
            frames.append(frame_record("version_after", ("version",), after))
            health_after["version_status"] = after.end["status"]
            selftest = exchange(
                args.host,
                args.port,
                Command("selftest_after", ("selftest", "status")),
                args.timeout,
            )
            frames.append(
                frame_record("selftest_after", ("selftest", "status"), selftest)
            )
            health_after["selftest_status"] = selftest.end["status"]
            health_after["selftest_payload_sha256"] = sha256_bytes(selftest.payload)
        except Exception as exc:
            health_after["error_type"] = type(exc).__name__
            if error_type is None:
                error_type = type(exc).__name__
                error_text = str(exc)
                failed_stage = "post-health"
                outcome = "PROBE_FAILED"

    completed = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    raw = {
        "schema": "sdm855-a90-inline-shrm-probe-private-v1",
        "experiment_id": args.experiment_id,
        "mode": args.mode,
        "started_utc": started,
        "completed_utc": completed,
        "candidate_sha256": expected_candidate_sha,
        "driver_sha256": EXTERNAL_DRIVER_SHA256,
        "op": inline.OP_FIXED_READ,
        "snapshot_physical_address": f"0x{candidate.SNAPSHOT_WORD_PHYS:08x}",
        "snapshot_source_register": f"0x{candidate.SOURCE_REGISTER_PHYS:08x}",
        "value": f"0x{value:016x}" if value is not None else None,
        "outcome": outcome,
        "failed_stage": failed_stage,
        "error_type": error_type,
        "error_text": error_text,
        "panic_on_oops_before": panic_before,
        "panic_on_oops_restored": panic_restored,
        "frames": frames,
        "health_after": health_after,
        "automatic_retries": False,
        "memory_or_mmio_writes": False,
    }
    raw_bytes = json_bytes(raw)
    root = args.output_root.resolve()
    raw_path = root / "evidence/private" / f"{args.experiment_id}.json"
    public_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    write_new(raw_path, raw_bytes, 0o600)
    public = {
        "schema": "sdm855-a90-inline-shrm-probe-public-v1",
        "experiment_id": args.experiment_id,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "mode": args.mode,
        "started_utc": started,
        "completed_utc": completed,
        "candidate_sha256": expected_candidate_sha,
        "driver_sha256": EXTERNAL_DRIVER_SHA256,
        "snapshot_physical_address": f"0x{candidate.SNAPSHOT_WORD_PHYS:08x}",
        "snapshot_source_register": f"0x{candidate.SOURCE_REGISTER_PHYS:08x}",
        "outcome": outcome,
        "failed_stage": failed_stage,
        "error_type": error_type,
        "value": f"0x{value:08x}" if value is not None and value <= 0xFFFFFFFF else None,
        "automatic_retries": False,
        "arbitrary_address_input": False,
        "generic_call_target": False,
        "memory_or_mmio_writes": False,
        "panic_on_oops_restored": panic_restored,
        "health_after": health_after,
        "raw_snapshot_sha256": sha256_bytes(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
        "claim_boundary": (
            "CONTROL_PASS proves only that fixed map/unmap returned safely without a bus load"
            if outcome == "CONTROL_PASS"
            else "READABLE proves one post-boot 32-bit SHRM snapshot observation; it does not prove writability, aliasing, or a protection bypass"
            if outcome == "READABLE"
            else "The recorded result does not by itself prove runtime XPU state, immutability, aliasing, or a protection bypass"
        ),
    }
    write_new(public_path, json_bytes(public), 0o644)
    if outcome not in {"CONTROL_PASS", "READABLE"}:
        raise RuntimeError(
            f"inline SHRM {args.mode} probe ended as {outcome}; evidence={public_path}"
        )
    return raw_path, public_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--mode", choices=inline.MODES, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--driver", type=Path, default=EXTERNAL_DRIVER)
    parser.add_argument("--output-root", type=Path, default=Path("."))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    raw, public = collect(args)
    print(f"private={raw}")
    print(f"public={public}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
