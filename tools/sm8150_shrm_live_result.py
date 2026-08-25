#!/usr/bin/env python3
"""Combine Experiment 013 control/read/reset/rollback evidence host-only."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
from decimal import Decimal
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools import build_a90_inline_remapper_candidate as inline
    from tools import build_a90_inline_shrm_candidate as candidate
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    import build_a90_inline_remapper_candidate as inline
    import build_a90_inline_shrm_candidate as candidate


PINS: Mapping[str, str] = {
    "control_flash": "201ef82868bef1b0d149acca0ca3440aaa18648b9289332d094ece778de25bd9",
    "control_live": "27f278978252d37e0a9d2fbd9f2e9575376086f7b19ec243590574e7b6b0800a",
    "control_rollback": "cdbcd3d119696aed405a27e787fbd85751d5c71979f7a2aa21939fd394105ea1",
    "read_flash": "2a6ee2c54e07dc985043b141c2bbbfca226260a3d12bbbc2c9161968c5d77d44",
    "read_live": "fe32fbe256c511b361ca916996c2892264e9f685a576351cb5196601db5dbb73",
    "last_kmsg": "92af2a21292f8874e466afa4716830bf51d2098e3b68a14f7244b33043d2aeb2",
    "read_rollback": "a543159f7def2975c9d4a73ed04793be2da32dc1a5d32b3e625b102af7224d20",
    "final_health": "9add2c4d7b9218d96c8a2b919931cbfa325383ff0aeeea8c6902d7d937bc3899",
}

WATCHDOG_BARK_RE = re.compile(rb"Watchdog bark! Now = (?P<value>[0-9]+\.[0-9]+)")
WATCHDOG_LAST_PET_RE = re.compile(
    rb"Watchdog last pet at (?P<value>[0-9]+\.[0-9]+)"
)
CPU_ALIVE_RE = re.compile(rb"cpu alive mask from last pet (?P<value>[0-9a-fA-F]+)")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_pin(label: str, data: bytes) -> None:
    actual = sha256(data)
    if actual != PINS[label]:
        raise ValueError(f"{label} SHA-256 {actual} != pinned {PINS[label]}")


def parse_json(label: str, data: bytes) -> dict[str, object]:
    require_pin(label, data)
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def one_decimal_match(pattern: re.Pattern[bytes], payload: bytes, label: str) -> Decimal:
    matches = pattern.findall(payload)
    if len(matches) != 1:
        raise ValueError(f"{label} match count {len(matches)} != 1")
    return Decimal(matches[0].decode("ascii"))


def parse_watchdog(payload: bytes) -> dict[str, object]:
    bark = one_decimal_match(WATCHDOG_BARK_RE, payload, "watchdog bark")
    last_pet = one_decimal_match(WATCHDOG_LAST_PET_RE, payload, "watchdog last pet")
    alive = CPU_ALIVE_RE.findall(payload)
    if len(alive) != 1:
        raise ValueError(f"CPU alive-mask match count {len(alive)} != 1")
    if b"UploadCause[Non Secure Watchdog Bark]" not in payload:
        raise ValueError("bootloader upload cause is absent")
    if b"TZBSP_ERR_FATAL_NON_SECURE_WDT" not in payload:
        raise ValueError("TZ reset reason is absent")
    return {
        "bark_time_seconds": str(bark),
        "last_pet_time_seconds": str(last_pet),
        "bark_minus_last_pet_seconds": str(bark - last_pet),
        "cpu_alive_mask": f"0x{int(alive[0], 16):x}",
        "upload_cause": "Non Secure Watchdog Bark",
        "tz_reset_reason": "TZBSP_ERR_FATAL_NON_SECURE_WDT",
        "a90r_result_present": b"A90R" in payload,
    }


def validate_flash(
    record: Mapping[str, object],
    *,
    profile: str,
    predecessor: str,
    image: str,
) -> None:
    expected = {
        "profile": profile,
        "predecessor_sha256": predecessor,
        "image_sha256": image,
        "readback_sha256": image,
        "write_count": 1,
        "staging_removed": True,
        "reboot_dispatched": False,
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"{profile} flash {key}={record.get(key)!r} != {value!r}")


def analyze(paths: Mapping[str, Path]) -> tuple[dict[str, object], dict[str, object]]:
    raw_bytes = {
        label: paths[label].read_bytes()
        for label in PINS
    }
    control_flash = parse_json("control_flash", raw_bytes["control_flash"])
    control_live = parse_json("control_live", raw_bytes["control_live"])
    control_rollback = parse_json("control_rollback", raw_bytes["control_rollback"])
    read_flash = parse_json("read_flash", raw_bytes["read_flash"])
    read_live = parse_json("read_live", raw_bytes["read_live"])
    require_pin("last_kmsg", raw_bytes["last_kmsg"])
    read_rollback = parse_json("read_rollback", raw_bytes["read_rollback"])
    final_health = parse_json("final_health", raw_bytes["final_health"])

    control_hash = candidate.EXPECTED_HASHES[inline.MODE_CONTROL]["candidate"]
    read_hash = candidate.EXPECTED_HASHES[inline.MODE_READ]["candidate"]
    rollback_hash = inline.BASE_SHA256
    validate_flash(
        control_flash,
        profile="control",
        predecessor=rollback_hash,
        image=control_hash,
    )
    validate_flash(
        control_rollback,
        profile="rollback",
        predecessor=control_hash,
        image=rollback_hash,
    )
    validate_flash(
        read_flash,
        profile="read",
        predecessor=rollback_hash,
        image=read_hash,
    )
    validate_flash(
        read_rollback,
        profile="rollback",
        predecessor=read_hash,
        image=rollback_hash,
    )
    if control_live.get("outcome") != "CONTROL_PASS":
        raise ValueError("control outcome is not CONTROL_PASS")
    if control_live.get("value") != "0x000000000000c071":
        raise ValueError("control sentinel mismatch")
    if read_live.get("outcome") != "PROBE_FAILED":
        raise ValueError("read outcome is not the recorded PROBE_FAILED")
    if read_live.get("failed_stage") != "fixed-inline-op":
        raise ValueError("read did not fail at fixed-inline-op")
    if read_live.get("value") is not None:
        raise ValueError("read unexpectedly has a value")
    if read_live.get("automatic_retries") is not False:
        raise ValueError("read automatic-retry state is not false")

    watchdog = parse_watchdog(raw_bytes["last_kmsg"])
    if watchdog["a90r_result_present"]:
        raise ValueError("retained log unexpectedly contains an A90R result")
    selftest = final_health.get("selftest")
    version = final_health.get("version")
    if not isinstance(selftest, Mapping) or selftest.get("fail") != 0:
        raise ValueError("final health selftest is not clean")
    if not isinstance(version, Mapping) or version.get("build") != "v2321-usb-clean-identity-rodata":
        raise ValueError("final health is not V2321")

    control_body = (
        paths["candidate_dir"]
        / candidate.output_names(inline.MODE_CONTROL)[1]
    ).read_bytes()
    read_body = (
        paths["candidate_dir"]
        / candidate.output_names(inline.MODE_READ)[1]
    ).read_bytes()
    differing_offsets = [
        index for index, pair in enumerate(zip(control_body, read_body)) if pair[0] != pair[1]
    ]
    if differing_offsets != [76, 77, 78, 79]:
        raise ValueError(f"candidate body diff is not one word: {differing_offsets!r}")

    common = {
        "mode": "HOST_ONLY_EVIDENCE_RECOMBINATION",
        "device_access": False,
        "snapshot": {
            "physical_address": f"0x{candidate.SNAPSHOT_WORD_PHYS:08x}",
            "source_register": f"0x{candidate.SOURCE_REGISTER_PHYS:08x}",
            "set": 0,
            "word_index": candidate.SNAPSHOT_WORD_INDEX,
        },
        "paired_candidates": {
            "control_sha256": control_hash,
            "read_sha256": read_hash,
            "body_differing_byte_offsets": differing_offsets,
            "body_differing_instruction_count": 1,
            "control_instruction_le": control_body[76:80].hex(),
            "read_instruction_le": read_body[76:80].hex(),
        },
        "live_result": {
            "control_outcome": control_live["outcome"],
            "control_value": "0x0000c071",
            "read_outcome": "NO_VALUE_TRANSPORT_LOSS_THEN_WATCHDOG_RESET",
            "read_automatic_retries": False,
            "watchdog": watchdog,
        },
        "rollback": {
            "final_boot_prefix_sha256": rollback_hash,
            "full_prefix_verified": True,
            "final_version": dict(version),
            "final_selftest": dict(selftest),
            "final_battery_capacity_percent": final_health.get("battery_capacity_percent"),
        },
        "claims": {
            "PROVED": [
                "The fixed no-load map/unmap control returned 0xc071 with healthy post-state.",
                "The paired candidate differs in exactly one 32-bit instruction: control MOVZ versus one LDR W at the fixed SHRM snapshot address.",
                "The one-load path returned no value, disconnected the transport, and the retained log records Non Secure Watchdog Bark with TZBSP_ERR_FATAL_NON_SECURE_WDT.",
                "The read operation was not retried, V2321 was restored by full-prefix SHA-256, and final native selftest has zero failures.",
            ],
            "SUPPORTED": [
                "The fixed 32-bit SHRM snapshot load, rather than mapping alone, caused a system-wide stall ending in the watchdog reset.",
                "Active TZ/XPU policy denial or its downstream fabric response explains the stall because both exact static branches exclude HLOS access to the complete workspace.",
            ],
            "REFUTED": [
                "The purpose-built EL1 path can directly observe this staged MCCC snapshot word on the tested boot.",
                "The fixed SHRM snapshot read produced an alias or security-boundary bypass.",
            ],
            "UNKNOWN": [
                "A decoded runtime XPU syndrome and final XPU register readback; therefore XPU is not assigned as the causally proved root cause.",
                "Whether a secure diagnostic interface can export snapshot words without granting HLOS direct access.",
                "Whether any separate mutable final address transform exists behind the protected interface.",
            ],
        },
        "classification": "CLASS_A_OR_B_CANDIDATE_FIXED_EL1_SHRM_READ_BLOCKED",
        "security_state": "NO_ALIAS_OR_BOUNDARY_BYPASS_OBSERVED",
    }
    private = {
        "schema": "sdm855-shrm-live-result-private-v1",
        "inputs": {
            label: {"path": str(path.resolve()), "sha256": PINS[label]}
            for label, path in paths.items()
            if label in PINS
        },
        **copy.deepcopy(common),
    }
    public = {
        "schema": "sdm855-shrm-live-result-public-v1",
        "inputs": {label: {"sha256": value} for label, value in PINS.items()},
        **copy.deepcopy(common),
    }
    return private, public


def atomic_replace(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(temporary)
    write_new(temporary, data, mode)
    os.replace(temporary, path)


def default_paths(root: Path) -> dict[str, Path]:
    private = root / "evidence/private"
    return {
        "control_flash": private / "013-shrm-control-flash-20260825-01.json",
        "control_live": private / "013-shrm-control-live-20260825-01.json",
        "control_rollback": private / "013-shrm-control-rollback-20260825-01.json",
        "read_flash": private / "013-shrm-read-flash-20260825-01.json",
        "read_live": private / "013-shrm-read-live-20260825-01.json",
        "last_kmsg": private / "013-shrm-read-watchdog-20260825-01.last_kmsg.bin",
        "read_rollback": private / "013-shrm-read-rollback-20260825-01.json",
        "final_health": private / "013-shrm-final-v2321-health-20260825-01.json",
        "candidate_dir": private / "013-inline-shrm-snapshot-20260825-01",
    }


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-output",
        type=Path,
        default=root / "evidence/private/013-shrm-live-result-20260825-01.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=root / "evidence/manifests/013-shrm-live-result-20260825-01.manifest.json",
    )
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    private_output = args.private_output.resolve()
    manifest_output = args.manifest_output.resolve()
    if not args.replace:
        for output in (private_output, manifest_output):
            if output.exists():
                raise FileExistsError(output)
    private, public = analyze(default_paths(root))
    private_bytes = json_bytes(private)
    public["private_record"] = {
        "filename": private_output.name,
        "size": len(private_bytes),
        "sha256": sha256(private_bytes),
        "git_ignored": True,
    }
    public_bytes = json_bytes(public)
    if args.replace:
        atomic_replace(private_output, private_bytes, 0o600)
        atomic_replace(manifest_output, public_bytes, 0o644)
    else:
        write_new(private_output, private_bytes, 0o600)
        write_new(manifest_output, public_bytes, 0o644)
    print(private_output)
    print(manifest_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
