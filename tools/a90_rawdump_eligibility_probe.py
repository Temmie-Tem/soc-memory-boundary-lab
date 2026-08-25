#!/usr/bin/env python3
"""Collect fixed property-free A90 raw-dump eligibility surfaces.

The probe speaks only the existing A90P1 protocol through an operator-pinned
loopback ACM bridge.  It first binds exact V2321 with ``version`` and then reads
the five precedent surfaces plus one A90-source-backed legacy parameter.  It never invokes adb/getprop,
accepts no device path or command, retries no command, and performs no write,
reboot, MMIO access, SMC, service action, or payload transfer.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import Command, Frame, exchange, json_bytes, write_new
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, Frame, exchange, json_bytes, write_new


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENT_ID = (
    "verification-004-a90-rawdump-eligibility-sourcebacked-20260825-01"
)
EXPECTED_VERSION = "0.9.285"
EXPECTED_BUILD = "v2321-usb-clean-identity-rodata"
EXPECTED_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
EXPECTED_VERSION_LINE = f"version: {EXPECTED_VERSION} build={EXPECTED_BUILD}"
EXPECTED_KERNEL_LINE = f"kernel: {EXPECTED_KERNEL}"

SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SCALAR_RE = re.compile(r"[^\s\x00]{1,80}\Z")

SURFACE_COMMANDS: tuple[Command, ...] = (
    Command("proc_cmdline", ("cat", "/proc/cmdline")),
    Command(
        "qcom_download_mode",
        ("cat", "/sys/module/qcom_dload_mode/parameters/download_mode"),
    ),
    Command(
        "msm_poweroff_download_mode",
        ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
    ),
    Command(
        "ramoops_max_reason",
        ("cat", "/sys/module/ramoops/parameters/max_reason"),
    ),
    Command("kernel_panic", ("cat", "/sys/module/kernel/parameters/panic")),
    Command(
        "kernel_panic_on_warn",
        ("cat", "/sys/module/kernel/parameters/panic_on_warn"),
    ),
)
VERSION_COMMAND = Command("version", ("version",))
ALL_COMMANDS = (VERSION_COMMAND, *SURFACE_COMMANDS)

PUBLIC_CMDLINE_KEYS = (
    "androidboot.debug_level",
    "androidboot.force_upload",
    "androidboot.fmm",
    "androidboot.fmm_lock",
    "androidboot.download_mode",
    "androidboot.dload_mode",
    "androidboot.ramdump",
    "androidboot.sec_debug",
    "androidboot.bootreason",
    "androidboot.boot_recovery",
)

DEBUG_LEVELS = {
    0x4F4C: "LOW",
    0x494D: "MID",
    0x4948: "HIGH",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def clean_text(payload: bytes, label: str, *, allow_spaces: bool = False) -> str:
    value = payload.decode("ascii", errors="strict").strip()
    if not value or "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError(f"{label} is not one nonempty text line")
    if not allow_spaces and SCALAR_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a bounded scalar")
    return value


def validate_version(payload: bytes) -> dict[str, object]:
    text = payload.decode("ascii", errors="strict")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    version_matches = [line for line in lines if line == EXPECTED_VERSION_LINE]
    kernel_matches = [line for line in lines if line == EXPECTED_KERNEL_LINE]
    if len(version_matches) != 1 or len(kernel_matches) != 1:
        raise ValueError("version frame does not bind exact V2321/kernel identity")
    return {
        "version": EXPECTED_VERSION,
        "build": EXPECTED_BUILD,
        "kernel": EXPECTED_KERNEL,
        "identity_exact": True,
    }


def parse_cmdline(payload: bytes) -> dict[str, object]:
    text = clean_text(payload, "/proc/cmdline", allow_spaces=True)
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as exc:
        raise ValueError(f"/proc/cmdline quoting is malformed: {exc}") from exc
    values: dict[str, str] = {}
    duplicates: list[str] = []
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key not in PUBLIC_CMDLINE_KEYS:
            continue
        if key in values:
            duplicates.append(key)
            continue
        if not value or SCALAR_RE.fullmatch(value) is None:
            raise ValueError(f"interesting cmdline value for {key!r} is not bounded")
        values[key] = value
    if duplicates:
        raise ValueError(f"duplicate interesting cmdline keys: {sorted(set(duplicates))}")
    return {
        "token_count": len(tokens),
        "selected": values,
        "selected_key_count": len(values),
        "raw_sha256": sha256(payload),
        "raw_size": len(payload),
    }


def parse_integer(value: str) -> int | None:
    try:
        return int(value, 0)
    except ValueError:
        if re.fullmatch(r"[0-9]+", value):
            return int(value, 10)
        return None


def parse_boolish(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"true", "yes", "on", "enabled"}:
        return True
    if lowered in {"false", "no", "off", "disabled"}:
        return False
    number = parse_integer(value)
    if number is None:
        return None
    return number != 0


def decode_debug_level(value: str | None) -> dict[str, object]:
    if value is None:
        return {"raw": None, "numeric": None, "label": "UNKNOWN"}
    numeric = parse_integer(value)
    return {
        "raw": value,
        "numeric": numeric,
        "label": DEBUG_LEVELS.get(numeric, "UNKNOWN"),
    }


def _signal(value: bool | None) -> str:
    if value is True:
        return "POSITIVE"
    if value is False:
        return "NEGATIVE"
    return "UNKNOWN"


def derive_eligibility(
    cmdline: Mapping[str, object], scalar_values: Mapping[str, str | None]
) -> dict[str, object]:
    selected = cmdline["selected"]
    assert isinstance(selected, dict)
    debug = decode_debug_level(selected.get("androidboot.debug_level"))
    debug_positive = debug["label"] in {"MID", "HIGH"}
    debug_negative = debug["label"] == "LOW"
    debug_signal = (
        "POSITIVE" if debug_positive else "NEGATIVE" if debug_negative else "UNKNOWN"
    )
    force_upload = parse_boolish(selected.get("androidboot.force_upload"))
    qcom_download_raw = scalar_values.get("qcom_download_mode")
    legacy_download_raw = scalar_values.get("msm_poweroff_download_mode")
    download_raw = (
        qcom_download_raw
        if qcom_download_raw is not None
        else legacy_download_raw
    )
    download_source = (
        "/sys/module/qcom_dload_mode/parameters/download_mode"
        if qcom_download_raw is not None
        else "/sys/module/msm_poweroff/parameters/download_mode"
        if legacy_download_raw is not None
        else None
    )
    download_mode = parse_boolish(download_raw)
    fmm_observations = {
        key: selected[key]
        for key in ("androidboot.fmm", "androidboot.fmm_lock")
        if key in selected
    }

    signals = {
        "debug_level": debug_signal,
        "force_upload": _signal(force_upload),
        "download_mode": _signal(download_mode),
    }
    if "NEGATIVE" in signals.values():
        classification = "DUMP_ENTRY_SIGNALS_INCOMPLETE"
    elif all(value == "POSITIVE" for value in signals.values()):
        classification = "DUMP_ENTRY_SIGNALS_PRESENT_FMM_TOKEN_UNKNOWN"
    else:
        classification = "DUMP_ENTRY_SIGNALS_PARTIAL"

    return {
        "classification": classification,
        "actual_xbl_rawdump_eligibility": "UNKNOWN",
        "debug_level": debug,
        "force_upload": {
            "raw": selected.get("androidboot.force_upload"),
            "enabled": force_upload,
        },
        "download_mode": {
            "raw": download_raw,
            "enabled": download_mode,
            "source": download_source,
            "precedent_surface_raw": qcom_download_raw,
            "a90_source_backed_surface_raw": legacy_download_raw,
        },
        "fmm_cmdline_observations": fmm_observations,
        "signals": signals,
        "reason": (
            "The three observable entry signals are positive, but exact XBL also "
            "contains FMM/policy gates and token/transport eligibility is not "
            "established by these files."
            if classification == "DUMP_ENTRY_SIGNALS_PRESENT_FMM_TOKEN_UNKNOWN"
            else "At least one observable entry signal is negative; do not trigger "
            "a reset for dump collection from this state."
            if classification == "DUMP_ENTRY_SIGNALS_INCOMPLETE"
            else "One or more observable entry signals is absent or undecodable; "
            "actual XBL dump eligibility remains unresolved."
        ),
    }


def frame_record(command: Command, frame: Frame) -> dict[str, object]:
    return {
        "evidence_id": command.evidence_id,
        "argv": list(command.argv),
        "begin": frame.begin,
        "end": frame.end,
        "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
        "payload_size": len(frame.payload),
        "payload_sha256": sha256(frame.payload),
        "transcript_size": len(frame.transcript),
        "transcript_sha256": sha256(frame.transcript),
    }


def collect(args: argparse.Namespace) -> tuple[Path, Path, dict[str, object]]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("probe only accepts an operator-pinned loopback bridge")

    started = utc_now()
    version_frame = exchange(args.host, args.port, VERSION_COMMAND, args.timeout)
    identity = validate_version(version_frame.payload)
    raw_records = [frame_record(VERSION_COMMAND, version_frame)]
    public_records: list[dict[str, object]] = [
        {
            "evidence_id": "version",
            "command": "version",
            "rc": int(version_frame.end["rc"], 0),
            "status": version_frame.end["status"],
            "payload_size": len(version_frame.payload),
            "payload_sha256": sha256(version_frame.payload),
            "identity": identity,
        }
    ]

    cmdline: dict[str, object] | None = None
    scalars: dict[str, str | None] = {}
    for command in SURFACE_COMMANDS:
        frame = exchange(
            args.host,
            args.port,
            command,
            args.timeout,
            allow_error=True,
        )
        raw_records.append(frame_record(command, frame))
        rc = int(frame.end["rc"], 0)
        available = rc == 0 and frame.end["status"] == "ok"
        public: dict[str, object] = {
            "evidence_id": command.evidence_id,
            "command": " ".join(command.argv),
            "rc": rc,
            "status": frame.end["status"],
            "available": available,
            "payload_size": len(frame.payload),
            "payload_sha256": sha256(frame.payload),
        }
        if command.evidence_id == "proc_cmdline":
            if not available:
                raise RuntimeError("/proc/cmdline is required for property-free binding")
            cmdline = parse_cmdline(frame.payload)
            public["parsed"] = cmdline
        elif available:
            value = clean_text(frame.payload, command.evidence_id)
            scalars[command.evidence_id] = value
            public["value"] = value
            public["numeric"] = parse_integer(value)
        else:
            scalars[command.evidence_id] = None
        public_records.append(public)

    if cmdline is None:
        raise RuntimeError("/proc/cmdline was not collected")
    eligibility = derive_eligibility(cmdline, scalars)
    completed = utc_now()
    raw = {
        "schema": "sdm855-a90-rawdump-eligibility-private-v2",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target": {"model": "SM-A908N", "soc": "SM8150", **identity},
        "safety": {
            "transport": "operator-pinned loopback A90P1 bridge",
            "device_commands": "one fixed version plus six fixed cat reads",
            "device_writes": False,
            "reboots": False,
            "mmio_access": False,
            "smc_access": False,
            "getprop_or_property_service": False,
            "automatic_retries": False,
        },
        "records": raw_records,
        "cmdline": cmdline,
        "scalar_values": scalars,
        "eligibility": eligibility,
    }
    raw_bytes = json_bytes(raw)
    manifest = {
        "schema": "sdm855-a90-rawdump-eligibility-public-v2",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "identity": identity,
        "safety": raw["safety"],
        "records": public_records,
        "eligibility": eligibility,
        "raw_snapshot_sha256": sha256(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
        "claims": {
            "PROVED": [
                "Exact V2321 and its expected kernel were bound before the six surface reads.",
                "The probe used no Android property service; all eligibility observations came from /proc/cmdline and fixed sysfs parameters.",
                "No device write, reboot, MMIO, SMC, service action, payload, or automatic retry occurred.",
            ],
            "SUPPORTED": [
                "The observed debug-level, force-upload and qcom_dload_mode signals indicate whether a dump-entry attempt is worth designing; they do not bypass XBL policy.",
            ],
            "REFUTED": [],
            "UNKNOWN": [
                "Actual XBL raw-dump eligibility because FMM/policy/token and transport gates are not fully represented by these bounded surfaces.",
                "Whether SHRM is populated at collection time and whether a successful path emits SHRM_MEM.BIN.",
            ],
        },
        "classification": eligibility["classification"],
    }

    output_root = Path(args.output_root).resolve()
    raw_path = output_root / "evidence/private" / f"{args.experiment_id}.json"
    manifest_path = (
        output_root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    )
    write_new(raw_path, raw_bytes, 0o600)
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return raw_path, manifest_path, manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", default=DEFAULT_EXPERIMENT_ID)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--output-root", default=str(REPO_ROOT))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raw_path, manifest_path, manifest = collect(args)
    print(f"private snapshot: {raw_path}")
    print(f"redacted manifest: {manifest_path}")
    print(f"classification: {manifest['classification']}")
    print("actual_xbl_rawdump_eligibility: UNKNOWN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
