#!/usr/bin/env python3
"""Publish a strict, host-only amendment for the retained V015 bus vote files.

The amendment is deliberately separate from the repaired Verification-015
analyzer.  It binds the small retained ``msm-bus-dbg`` excerpts, proves the
66-client declaration and the ``disp_rsc_ebi`` vote sequence, and publishes
only sanitized metadata and numeric entries.  It does not infer a DDR clock,
transform mutation, or a controller write from a bus vote.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = REPO_ROOT / "evidence/private/verification-015-runtime-invariance-20260826-01"

CLIENT_LIST_NAME = "msm-bus-dbg-client-list.txt"
CLIENT_LIST_SIZE = 64
CLIENT_LIST_SHA256 = "62e38404fa83ce2f44e135744695f8c992652cf0daf775d70478b1cc80909413"
EBI_NAME = "msm-bus-dbg-disp_rsc_ebi.txt"
EBI_SIZE = 571
EBI_SHA256 = "90d5954aa11eaf064fef1737be7f742aada351ddbeaabd2d1bab2cb17f2aa1e2"

SCHEMA = "a90-v015-bus-vote-amendment-v1"
EXPERIMENT_ID = "verification-015-bus-vote-amendment"
MODE = "HOST_ONLY_READ_ONLY"
EXPECTED_CLIENT_COUNT = 66
EXPECTED_CLIENT_NAMES = (
    "clk_dispcc_debugfs",
    "disp_rsc_ebi",
    "disp_rsc_llcc",
    "disp_rsc_mnoc",
)

# The excerpts are short enough that their semantic rows are pinned in
# addition to their content hashes.  This keeps a test-side hash override
# from turning an altered 400 MB/s or restored 12.8 GB/s row into evidence.
EXPECTED_EBI_ROWS = (
    ("1.178022290", 1, 20_000, 20_512, 12_800_000_000, 12_800_000_000),
    ("12177.250682385", 2, 20_000, 20_512, 0, 400_000_000),
    ("12177.251094676", 1, 20_000, 20_512, 0, 400_000_000),
    ("12177.290264624", 2, 20_000, 20_512, 12_800_000_000, 12_800_000_000),
    ("12177.440166082", 1, 20_000, 20_512, 12_800_000_000, 12_800_000_000),
    ("12177.440268895", 2, 20_000, 20_512, 12_800_000_000, 12_800_000_000),
)

_CLIENT_TEXT_RE = re.compile(
    r"(?P<count>[0-9]+)\n\n(?P<names>[a-z0-9_]+(?:\n[a-z0-9_]+)*)\n"
)
_EBI_LINE_RES = (
    re.compile(r"(?P<timestamp>[0-9]+\.[0-9]{9})"),
    re.compile(r"curr[ ]{3}:[ ]+(?P<value>[0-9]+)"),
    re.compile(r"masters:[ ]+(?P<value>[0-9]+)"),
    re.compile(r"slaves[ ]:[ ]+(?P<value>[0-9]+)"),
    re.compile(r"ab[ ]{5}:[ ]+(?P<value>[0-9]+)"),
    re.compile(r"ib[ ]{5}:[ ]+(?P<value>[0-9]+)"),
)


class BusVoteError(ValueError):
    """Raised when an exact input or bounded semantic invariant fails."""


# Neighboring static tools use TraceError.  The alias keeps this amendment
# convenient to exercise from the same focused-test vocabulary.
TraceError = BusVoteError


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_exact(path: Path, expected_size: int, expected_sha256: str, label: str) -> bytes:
    """Read one pinned private input through a regular, no-follow descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BusVoteError(f"cannot open exact {label}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise BusVoteError(f"exact {label} size/type mismatch")
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise BusVoteError(f"exact {label} truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BusVoteError(f"exact {label} changed during read")
        payload = b"".join(chunks)
        if len(payload) != expected_size:
            raise BusVoteError(f"exact {label} size changed during read")
    finally:
        os.close(fd)
    digest = _sha256(payload)
    if digest != expected_sha256:
        raise BusVoteError(f"exact {label} SHA-256 mismatch")
    return payload


def parse_client_list(payload: bytes | str) -> dict[str, Any]:
    """Parse the exact count-plus-client-name excerpt."""

    if isinstance(payload, bytes):
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise BusVoteError("client list is not strict ASCII") from exc
    elif isinstance(payload, str):
        text = payload
    else:
        raise BusVoteError("client list must be bytes or text")
    match = _CLIENT_TEXT_RE.fullmatch(text)
    if match is None:
        raise BusVoteError("client list format changed")
    declared_count = int(match.group("count"))
    names = tuple(match.group("names").splitlines())
    if declared_count != EXPECTED_CLIENT_COUNT:
        raise BusVoteError("client count changed")
    if names != EXPECTED_CLIENT_NAMES or len(set(names)) != len(names):
        raise BusVoteError("client-name excerpt changed")
    if "disp_rsc_ebi" not in names:
        raise BusVoteError("disp_rsc_ebi client is absent")
    return {
        "declared_client_count": declared_count,
        "listed_client_count": len(names),
        "listed_client_names": list(names),
        "required_client": "disp_rsc_ebi",
        "required_client_present": True,
    }


def _parse_ebi_block(block: str) -> tuple[str, int, int, int, int, int]:
    lines = block.splitlines()
    if len(lines) != len(_EBI_LINE_RES):
        raise BusVoteError("disp_rsc_ebi entry line count changed")
    values: list[Any] = []
    for line, pattern in zip(lines, _EBI_LINE_RES):
        match = pattern.fullmatch(line)
        if match is None:
            raise BusVoteError("disp_rsc_ebi entry format changed")
        value = match.groupdict().get("timestamp") or match.group("value")
        values.append(value if len(values) == 0 else int(value))
    return tuple(values)  # type: ignore[return-value]


def parse_ebi_entries(payload: bytes | str) -> dict[str, Any]:
    """Parse and semantically classify the six exact EBI vote entries."""

    if isinstance(payload, bytes):
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise BusVoteError("disp_rsc_ebi transcript is not strict ASCII") from exc
    elif isinstance(payload, str):
        text = payload
    else:
        raise BusVoteError("disp_rsc_ebi transcript must be bytes or text")
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise BusVoteError("disp_rsc_ebi transcript newline framing changed")
    text = text[:-1]
    blocks = text.split("\n\n")
    if len(blocks) != len(EXPECTED_EBI_ROWS) or any(not block for block in blocks):
        raise BusVoteError("disp_rsc_ebi entry cardinality changed")
    parsed = tuple(_parse_ebi_block(block) for block in blocks)
    if parsed != EXPECTED_EBI_ROWS:
        raise BusVoteError("disp_rsc_ebi semantic rows changed")

    entries: list[dict[str, Any]] = []
    for index, (timestamp, current, masters, slaves, ab, ib) in enumerate(parsed):
        phase = (
            "INITIAL_STATIC_VOTE"
            if index == 0
            else "TRANSIENT_LOW_VOTE"
            if index in (1, 2)
            else "RESTORED_STATIC_VOTE"
        )
        entries.append(
            {
                "index": index,
                "timestamp_seconds": timestamp,
                "current": current,
                "masters": masters,
                "slaves": slaves,
                "ab_bytes_per_sec": ab,
                "ib_bytes_per_sec": ib,
                "phase": phase,
            }
        )
    initial = entries[0]
    transient = entries[1:3]
    restored = entries[3:]
    if any(row["ib_bytes_per_sec"] != 400_000_000 for row in transient):
        raise BusVoteError("transient EBI vote is not 400 MB/s")
    if any(
        row["ab_bytes_per_sec"] != initial["ab_bytes_per_sec"]
        or row["ib_bytes_per_sec"] != initial["ib_bytes_per_sec"]
        for row in restored
    ):
        raise BusVoteError("restored EBI vote does not match the initial vote")
    return {
        "entry_count": len(entries),
        "entries": entries,
        "phase_counts": {
            "INITIAL_STATIC_VOTE": 1,
            "TRANSIENT_LOW_VOTE": 2,
            "RESTORED_STATIC_VOTE": 3,
        },
        "initial_vote_bytes_per_sec": {
            "ab": initial["ab_bytes_per_sec"],
            "ib": initial["ib_bytes_per_sec"],
        },
        "transient_vote_bytes_per_sec": {
            "ab": transient[0]["ab_bytes_per_sec"],
            "ib": transient[0]["ib_bytes_per_sec"],
        },
        "restored_vote_bytes_per_sec": {
            "ab": restored[0]["ab_bytes_per_sec"],
            "ib": restored[0]["ib_bytes_per_sec"],
        },
        "restored_matches_initial": True,
    }


def _input_record(name: str, size: int, digest: str) -> dict[str, Any]:
    return {"basename": name, "size": size, "sha256": digest}


def build_manifest(private_root: Path = PRIVATE_ROOT) -> dict[str, Any]:
    """Build a deterministic, public-safe bus-vote amendment manifest."""

    client_path = private_root / CLIENT_LIST_NAME
    ebi_path = private_root / EBI_NAME
    client_payload = _read_exact(client_path, CLIENT_LIST_SIZE, CLIENT_LIST_SHA256, "client list")
    ebi_payload = _read_exact(ebi_path, EBI_SIZE, EBI_SHA256, "disp_rsc_ebi transcript")
    client = parse_client_list(client_payload)
    ebi = parse_ebi_entries(ebi_payload)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {
            "client_list": _input_record(CLIENT_LIST_NAME, CLIENT_LIST_SIZE, CLIENT_LIST_SHA256),
            "disp_rsc_ebi": _input_record(EBI_NAME, EBI_SIZE, EBI_SHA256),
        },
        "bus_vote": {
            **client,
            **ebi,
            "client_list_scope": "DECLARED_66_CLIENTS_WITH_RETAINED_RELEVANT_NAMES_ONLY",
            "initial_vote_description": "12.8 GB/s AB and IB",
            "transient_vote_description": "400 MB/s IB with zero AB",
            "restored_vote_description": "12.8 GB/s AB and IB",
            "interpretation": "The retained excerpt shows a static 12.8 GB/s EBI vote initially, a transient 400 MB/s IB entry, and restoration; it does not attest a DDR operating-point transition.",
        },
        "scope": {
            "model": "EXACT_RETAINED_MSM_BUS_DBG_EXCERPTS",
            "raw_transcript_bytes": "REDACTED",
            "ddr_frequency": "UNKNOWN",
            "transform_transition": "UNKNOWN",
            "runtime_execution": "UNKNOWN",
            "controller_register_identity": "UNKNOWN",
            "writer_absence": "UNKNOWN",
            "never_contact_device": True,
        },
        "claims": {
            "PROVED": [
                "The two retained excerpts are bound by regular-file, no-follow, size, stability, and SHA-256 checks.",
                "The client excerpt declares 66 clients and retains the disp_rsc_ebi name among its four listed relevant names.",
                "The disp_rsc_ebi excerpt contains one initial 12.8 GB/s vote, two transient 400 MB/s IB rows, and three restored 12.8 GB/s rows.",
            ],
            "SUPPORTED": [
                "The retained bus-vote excerpt supports treating the V015 bandwidth request axis as a stability-only supplement rather than DDR-frequency evidence."
            ],
            "HYPOTHESIS": [],
            "REFUTED": [],
            "UNKNOWN": [
                "DDR operating-point selection, clock readback, bus aggregation outside the retained excerpt, transform mutability, physical mapping, protection ordering, aliasing, and bypass."
            ],
        },
        "boundary_bypass": {
            "status": "NOT_AUTHORIZED",
            "device": "none",
            "smc": "none",
            "mmio": "none",
            "protected_memory": "none",
            "reason": "Host-only transcript amendment; no device or runtime state was accessed.",
        },
        "definition_of_done": {
            "target": {
                "binding": "PROVED_RETAINED_V015_INPUTS_ONLY",
                "marketing_name": "A90 5G",
                "model": "SM-A908N",
                "soc": "SM8150",
                "soc_name": "Snapdragon 855",
            },
            "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."},
            "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."},
            "commands": {
                "status": "REDACTED_REPRODUCTION_TEMPLATE",
                "command": "python3 tools/a90_v015_bus_vote_amendment.py --output <public-manifest-path>",
                "reason": "Private input paths are redacted; exact hashes are pinned.",
            },
            "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only transcript parse; no runtime repetitions."},
            "rollback": {"status": "NOT_APPLICABLE", "reason": "No device state."},
            "recovery": {"status": "NOT_APPLICABLE", "reason": "No device state."},
            "device_binding": {"status": "NOT_APPLICABLE", "reason": "No device contact."},
            "tool_and_build": {"tool": f"{Path(__file__).name} schema {SCHEMA}", "build": "NOT_APPLICABLE"},
        },
    }


def encode_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")


def write_no_clobber(path: Path, payload: bytes) -> dict[str, Any]:
    if not path.parent.is_dir():
        raise BusVoteError(f"manifest parent does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise BusVoteError("manifest output already exists or is unsafe") from exc
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise BusVoteError("manifest write made no progress")
            view = view[count:]
        os.fsync(fd)
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    return {"basename": path.name, "size_bytes": len(payload), "sha256": _sha256(payload), "mode": "0644"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--private-root", type=Path, default=PRIVATE_ROOT, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        publication = write_no_clobber(args.output, encode_manifest(build_manifest(args.private_root)))
    except (BusVoteError, OSError) as exc:
        print(f"V015 bus-vote amendment: {exc}", file=sys.stderr)
        return 2
    print(
        f"wrote {publication['basename']} {publication['size_bytes']} bytes "
        f"sha256={publication['sha256']} mode={publication['mode']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
