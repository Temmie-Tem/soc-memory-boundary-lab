#!/usr/bin/env python3
"""Validate and publish the host-side Verification-015 runtime comparison.

The original Verification-015 helper was intentionally small, but it treated a
glob as an input contract, accepted partly parsed JSONL, and wrote its output
with an ordinary truncating write.  This module is the repaired integration.
It keeps the six runtime conditions separate, validates the probe sections and
contexts before doing any arithmetic, binds the two auxiliary transcripts by
their level markers, and publishes only a deterministic public manifest.

The measurements are a classification result in allocation-offset/model
coordinates.  They are not evidence that a DDR clock changed.  The bandwidth
vote axis is therefore retained as a separately scoped stability transcript and
is excluded from DDR-frequency or transform-transition inference.
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Mapping, Sequence
import glob
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


# Preserve the historical public schema identifier.  The repair is expressed
# by the stricter validation/publication contract below, not by a silent schema
# fork that would strand existing consumers of the Verification-015 manifest.
SCHEMA = "a90-runtime-invariance-analysis-v1"
ANALYSIS_ONLY_SCHEMA = "a90-runtime-invariance-analysis-only-v1"
PROBE_SCHEMA = "a90_region_probe_r_v1"
LEVEL_REPEAT_SCHEMA = "a90-ddr-level-repeat-v1"
LEVEL_SWEEP_SCHEMA = "a90-ddr-level-sweep-v1"

# This ratio is intentionally within one condition.  It must not compare
# absolute gap magnitudes between runtimes whose delta scales differ.
WEAK_SEPARATION_RUNNER_UP_RATIO = 0.6
EXPECTED_DIFFERENCE_COUNT = 51
EXPECTED_REPEAT_LEVELS = (762, 7980)
EXPECTED_REPEAT_REPS = (0, 1, 2)
EXPECTED_REPEAT_DIFFERENCES = (
    0x100E000,
    0x1012000,
    0x1006000,
    0x101C000,
    0x16000,
    0x102000,
)
EXPECTED_SWEEP_LEVELS = (762, 2597, 5161, 5931, 6881, 7980)
EXPECTED_SWEEP_REPS = (0, 1)
EXPECTED_SWEEP_DIFFERENCES = (0x800, 0x2000, 0x16000)

HISTORICAL_PROBE_BINARY_SHA256 = (
    "bd41bb9c8a5f7dfe1ddcec8f069382df6e0ad85d8712da31a9823243c124d204"
)
PROBE_SOURCE_SHA256 = (
    "2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9"
)
DEPENDENCY_MANIFEST_SHA256 = (
    "5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e"
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = REPO_ROOT / "evidence" / "private" / (
    "verification-015-runtime-invariance-20260826-01"
)
PROBE_SOURCE_PATH = REPO_ROOT / "tools" / "a90_region_probe_r.c"
DEPENDENCY_MANIFEST_PATH = (
    REPO_ROOT
    / "evidence"
    / "manifests"
    / "023R-repaired-region-bank-relation-20260826-01.manifest.json"
)

CANONICAL_CONDITION_BASENAMES = {
    "twrp-pre-L7980": (
        "twrp-pre-sweep0-L7980.jsonl",
        "twrp-pre-sweep2-L7980.jsonl",
        "twrp-pre-sweep4-L7980.jsonl",
        "twrp-pre-sweep6-L7980.jsonl",
    ),
    "twrp-pre-L6881": (
        "twrp-pre-sweep1-L6881.jsonl",
        "twrp-pre-sweep3-L6881.jsonl",
        "twrp-pre-sweep5-L6881.jsonl",
        "twrp-pre-sweep7-L6881.jsonl",
    ),
    "twrp-post-L7980": (
        "twrp-post-postboot8-L7980.jsonl",
        "twrp-post-postboot9-L7980.jsonl",
    ),
    "v2321-L7980": (
        "v2321-L7980-pass0.jsonl",
        "v2321-L7980-pass1.jsonl",
    ),
    "v2321-L762": ("v2321-L762-pass0.jsonl",),
    "v2321-coldboot-L7980": (
        "v2321-coldboot-L7980-pass0.jsonl",
        "v2321-coldboot-L7980-pass1.jsonl",
    ),
}
REPEAT_BASENAME = "v2321-level-repeat.jsonl"
SWEEP_BASENAME = "v2321-level-sweep.jsonl"
JOURNAL_BASENAMES = (
    "twrp-devfreq-journal.txt",
    "v2321-devfreq-journal.txt",
)

# These are the exact bytes retained in the canonical private evidence
# directory.  The condition set is 15 probe files (4 + 4 + 2 + 2 + 1 + 2),
# plus repeat, sweep, and two journals: 19 private input artifacts total.
# Keep the pin beside the canonical names so a basename-only substitution
# cannot silently enter the public manifest.
CANONICAL_ARTIFACT_PINS: dict[str, tuple[int, str]] = {
    "twrp-devfreq-journal.txt": (
        805,
        "02f4521249050bb52b19b3b0774fbc3bdc0831de7adc6eb5b10ad9c9e8aaa124",
    ),
    "twrp-post-postboot8-L7980.jsonl": (
        88592,
        "320017c09575bed7cb8f1cdde1c4f21e964fd41c7ab00658dcf2e76609f532d4",
    ),
    "twrp-post-postboot9-L7980.jsonl": (
        88592,
        "f154b80d1e4a7a3389c502ca52321982649e0c3ea9642e6b90fd5849e601a307",
    ),
    "twrp-pre-sweep0-L7980.jsonl": (
        43331,
        "d364ff595160ec559d00320f4d7fa5e8180a8838099e49f001468a7967be8c49",
    ),
    "twrp-pre-sweep1-L6881.jsonl": (
        43331,
        "395260dff67549a75c639e8d0b688304a6597962ba3d2dac726f3e23df6a3136",
    ),
    "twrp-pre-sweep2-L7980.jsonl": (
        43330,
        "e98851cc34c8db908730b143ce7a4bfaade1c9f9807e443cad72ce68e3f9f86e",
    ),
    "twrp-pre-sweep3-L6881.jsonl": (
        43331,
        "aeefa142d93b29d494cc983c9ce62131d90f1aa8d01ae1aa49ceb9286e028666",
    ),
    "twrp-pre-sweep4-L7980.jsonl": (
        45785,
        "a054bc50813009717d0df7d9d89d9c93e7bdf49f24485f2ec4f288c77dea70cc",
    ),
    "twrp-pre-sweep5-L6881.jsonl": (
        45786,
        "082e003a60445e97f5c3b6e70de0cb16f9af3f641deade1225756d64dabe6b83",
    ),
    "twrp-pre-sweep6-L7980.jsonl": (
        45784,
        "9c26a71570306ec518ebcd8869b126a6ee49d3a7066b56a2b669a495e85488a7",
    ),
    "twrp-pre-sweep7-L6881.jsonl": (
        45786,
        "ffd7ad1a9c56d1332348b2432ebb08d4a577264f50d26d53aa4654be3c098b09",
    ),
    "v2321-L762-pass0.jsonl": (
        89584,
        "6708989d3cfdc42c9487db369c0d165a17d23d6a2e269b1255f8da3d8b4ba24c",
    ),
    "v2321-L7980-pass0.jsonl": (
        89580,
        "c09a32e88a7b60bc9a6732d71ddc301772b87aa829f74d609a563dfda50f244d",
    ),
    "v2321-L7980-pass1.jsonl": (
        89594,
        "6d0599a5707ae236622c5c943541ae72eb2405264f6eac69a600559abab68240",
    ),
    "v2321-coldboot-L7980-pass0.jsonl": (
        89563,
        "5c5e202730506822a357ab7c56e0ba6b2a40f57aad3ccc193eb8dc68d9bda1fd",
    ),
    "v2321-coldboot-L7980-pass1.jsonl": (
        89586,
        "315b6666be73975677528da8122f4b4703278784a9bf821a38baf2bc7200fb02",
    ),
    "v2321-devfreq-journal.txt": (
        895,
        "abedefc0a6dfeef64f601fb1e0b00a14df3091f40566d1ea7b6b92565d16902d",
    ),
    "v2321-level-repeat.jsonl": (
        124086,
        "051cd43fea712170a9af30b58bbcb0781395059a35d623de08e7ee5a19f5b61e",
    ),
    "v2321-level-sweep.jsonl": (
        68439,
        "63b29ff2f8875302cad33acacc1e4ea818a6b6053be72f7af80a15b26752524a",
    ),
}


class InvarianceError(RuntimeError):
    """Raised when an input or publication contract is not satisfied."""


def sha256_file(path: Path) -> str:
    """Return the SHA-256 of *path* without exposing its path in output."""

    try:
        return hashlib.sha256(_read_stable_bytes(Path(path), "hash input")).hexdigest()
    except (OSError, UnicodeError) as exc:
        raise InvarianceError(f"cannot hash {path.name!r}: {exc}") from exc


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def _validate_identifier(value: object, field: str) -> str:
    """Keep user-controlled IDs from becoming public path fragments."""

    if not isinstance(value, str) or SAFE_IDENTIFIER.fullmatch(value) is None:
        raise InvarianceError(
            f"{field} must match [A-Za-z0-9][A-Za-z0-9._-]*"
        )
    return value


def _read_stable_bytes(path: Path, label: str) -> bytes:
    """Read one regular non-symlink file and reject validate-then-swap races."""

    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InvarianceError(f"{label} {path.name!r} is not readable: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise InvarianceError(f"{label} {path.name!r} is not a regular file")
        if before.st_size <= 0:
            raise InvarianceError(f"{label} {path.name!r} is empty")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or len(data) != before.st_size
        ):
            raise InvarianceError(
                f"{label} {path.name!r} changed while being read"
            )
        # A same-size in-place mutation can evade an inode/size check.  Read a
        # second stable snapshot from the still-open descriptor and compare the
        # exact bytes before any parser consumes them.
        second = os.pread(descriptor, before.st_size, 0)
        if second != data:
            raise InvarianceError(
                f"{label} {path.name!r} changed during stable-byte verification"
            )
        final = os.fstat(descriptor)
        if (
            final.st_dev != before.st_dev
            or final.st_ino != before.st_ino
            or final.st_size != before.st_size
        ):
            raise InvarianceError(
                f"{label} {path.name!r} changed after stable-byte verification"
            )
        return data
    finally:
        os.close(descriptor)


def _parse_nonnegative_int(value: object, field: str, source: str) -> int:
    if _is_int(value):
        number = int(value)
    elif isinstance(value, str):
        try:
            number = int(value, 0)
        except ValueError as exc:
            raise InvarianceError(
                f"{source}: {field} is not an integer: {value!r}"
            ) from exc
    else:
        raise InvarianceError(f"{source}: {field} is not an integer")
    if number < 0:
        raise InvarianceError(f"{source}: {field} must be non-negative")
    return number


def _require(record: Mapping[str, object], key: str, source: str) -> object:
    if key not in record:
        raise InvarianceError(f"{source}: record {record.get('type')!r} lacks {key!r}")
    return record[key]


def _validate_context(record: Mapping[str, object], source: str, strict: bool) -> dict:
    if strict and record.get("schema") != PROBE_SCHEMA:
        raise InvarianceError(
            f"{source}: context has schema {record.get('schema')!r}, "
            f"expected {PROBE_SCHEMA!r}"
        )
    if record.get("type") != "context":
        raise InvarianceError(f"{source}: expected a context record")
    for field in ("heap", "order", "barrier", "divisor", "offset_mode"):
        value = _require(record, field, source)
        if not isinstance(value, str) or not value:
            raise InvarianceError(f"{source}: context {field!r} must be nonempty text")
    for field in ("cpu", "cntfrq", "mib", "repetitions", "pairs", "warmups"):
        raw_value = _require(record, field, source)
        # Context values participate in allocation bounds and cross-file
        # identity.  Keep the JSON representation unambiguous: accepting a
        # numeric string here would leave the returned context unnormalised
        # and can make ``mib * MiB`` fail later in the parser.
        if not _is_int(raw_value):
            raise InvarianceError(
                f"{source}: context {field!r} must be a JSON integer"
            )
        value = _parse_nonnegative_int(raw_value, field, source)
        if field in ("cntfrq", "mib", "repetitions", "pairs") and value == 0:
            raise InvarianceError(f"{source}: context {field!r} must be positive")
    # Keep every context field, including future diagnostic fields, in the
    # identity comparison.  A changed extra field must not be silently ignored.
    return dict(record)


def _validate_ion_heap(record: Mapping[str, object], source: str, strict: bool) -> dict:
    if strict and record.get("schema") != PROBE_SCHEMA:
        raise InvarianceError(f"{source}: ion_heap has an unexpected schema")
    if record.get("type") != "ion_heap":
        raise InvarianceError(f"{source}: expected an ion_heap record")
    name = _require(record, "name", source)
    if not isinstance(name, str) or not name:
        raise InvarianceError(f"{source}: ion_heap name must be nonempty text")
    for field in ("heap_type", "heap_id"):
        _parse_nonnegative_int(_require(record, field, source), field, source)
    return dict(record)


def _validate_pa_provenance(
    record: Mapping[str, object], source: str, strict: bool
) -> dict:
    if strict and record.get("schema") != PROBE_SCHEMA:
        raise InvarianceError(f"{source}: pa_provenance has an unexpected schema")
    if record.get("type") != "pa_provenance":
        raise InvarianceError(f"{source}: expected a pa_provenance record")
    source_name = _require(record, "source", source)
    status = _require(record, "status", source)
    if not isinstance(source_name, str) or not source_name:
        raise InvarianceError(f"{source}: pa_provenance source must be nonempty text")
    if not isinstance(status, str) or not status:
        raise InvarianceError(f"{source}: pa_provenance status must be nonempty text")
    for field in ("pages", "present", "nonzero_pfn"):
        _parse_nonnegative_int(_require(record, field, source), field, source)
    for field in ("first_pfn", "last_pfn"):
        value = _require(record, field, source)
        if not isinstance(value, str) or not value:
            raise InvarianceError(f"{source}: pa_provenance {field!r} must be text")
    contiguous = _require(record, "contiguous", source)
    if not isinstance(contiguous, bool):
        raise InvarianceError(f"{source}: pa_provenance contiguous must be boolean")
    return dict(record)


def _validate_pair(
    record: Mapping[str, object], source: str, strict: bool
) -> tuple[int, int, int]:
    if strict and record.get("schema") != PROBE_SCHEMA:
        raise InvarianceError(f"{source}: pair has an unexpected schema")
    if record.get("type") != "pair":
        raise InvarianceError(f"{source}: expected a pair record")
    value = _parse_nonnegative_int(_require(record, "value", source), "value", source)
    offset = _parse_nonnegative_int(_require(record, "offset", source), "offset", source)
    delta = _require(record, "delta", source)
    if not _is_int(delta):
        raise InvarianceError(f"{source}: pair delta must be an integer")
    if offset < 0:
        raise InvarianceError(f"{source}: pair offset must be non-negative")
    return value, offset, int(delta)


def _validate_difference(
    record: Mapping[str, object], source: str, strict: bool
) -> tuple[int, dict]:
    if strict and record.get("schema") != PROBE_SCHEMA:
        raise InvarianceError(f"{source}: difference has an unexpected schema")
    if record.get("type") != "difference":
        raise InvarianceError(f"{source}: expected a difference record")
    value = _parse_nonnegative_int(_require(record, "value", source), "value", source)
    pairs = _parse_nonnegative_int(_require(record, "pairs", source), "pairs", source)
    if pairs == 0:
        raise InvarianceError(f"{source}: difference pairs must be positive")
    stats: dict[str, int] = {}
    for field in ("p10", "median", "p90"):
        number = _require(record, field, source)
        if not _is_int(number):
            raise InvarianceError(f"{source}: difference {field!r} must be an integer")
        stats[field] = int(number)
    if not stats["p10"] <= stats["median"] <= stats["p90"]:
        raise InvarianceError(f"{source}: difference quantiles are not ordered")
    stats["pairs"] = pairs
    return value, stats


def _json_objects(text: str, source: str) -> list[tuple[int, dict]]:
    if not text.strip():
        raise InvarianceError(f"{source}: transcript is empty")
    objects: list[tuple[int, dict]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InvarianceError(
                f"{source}:{line_number}: invalid JSON: {exc.msg}"
            ) from exc
        if not isinstance(record, dict):
            raise InvarianceError(f"{source}:{line_number}: JSON record is not an object")
        objects.append((line_number, record))
    if not objects:
        raise InvarianceError(f"{source}: transcript has no JSON records")
    return objects


def _identity(record: Mapping[str, object]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _parse_probe_objects(
    objects: Sequence[tuple[int, Mapping[str, object]]],
    source: str,
    *,
    strict_schema: bool = True,
    require_context: bool = True,
) -> dict:
    """Parse one or more probe sections and reject duplicate summaries.

    A section starts at a context record.  V2321 files contain three sections
    because their 51 differences were acquired in three disjoint batches; the
    contexts are identical and the final difference-key set is still unique.
    """

    contexts: list[dict] = []
    heaps: list[dict] = []
    provenance: list[dict] = []
    sections: list[dict] = []
    current: dict | None = None
    medians: dict[int, int] = {}
    summaries: dict[int, dict] = {}

    def finish(section: dict | None) -> None:
        if section is None:
            return
        if not section["differences"]:
            raise InvarianceError(f"{source}: probe section has no difference records")
        if len(section["ion_heaps"]) != 1:
            raise InvarianceError(
                f"{source}: context section must contain exactly one ion_heap "
                f"record, got {len(section['ion_heaps'])}"
            )
        if len(section["pa_provenance"]) != 1:
            raise InvarianceError(
                f"{source}: context section must contain exactly one pa_provenance "
                f"record, got {len(section['pa_provenance'])}"
            )
        # A summary closes a difference.  Every pair must have appeared before
        # that summary, and the count must match exactly (including the zero
        # pair case, which is never a valid summary).
        for difference, count in section["pair_counts"].items():
            if difference not in section["differences"]:
                raise InvarianceError(
                    f"{source}: pair records for 0x{difference:x} lack a summary"
                )
            expected = section["differences"][difference]["pairs"]
            if count != expected:
                raise InvarianceError(
                    f"{source}: 0x{difference:x} has {count} pair records, "
                    f"summary says {expected}"
                )
        for difference, summary in section["differences"].items():
            count = section["pair_counts"].get(difference, 0)
            if count != summary["pairs"]:
                raise InvarianceError(
                    f"{source}: 0x{difference:x} summary has {summary['pairs']} "
                    f"pairs but only {count} preceding pair records"
                )
        # Recompute the probe's qsort-index statistics from the retained pair
        # deltas.  The indexes are deliberately the C probe's exact integer
        # expressions, not an interpolated percentile implementation.
        for difference, summary in section["differences"].items():
            deltas = sorted(
                pair["delta"] for pair in section["pair_records"][difference]
            )
            count = len(deltas)
            expected_stats = (
                deltas[count // 10],
                deltas[count // 2],
                deltas[count - 1 - count // 10],
            )
            actual_stats = (summary["p10"], summary["median"], summary["p90"])
            if actual_stats != expected_stats:
                raise InvarianceError(
                    f"{source}: 0x{difference:x} qsort statistics "
                    f"{actual_stats!r} != recomputed {expected_stats!r}"
                )
        sections.append(
            {
                "context": section["context"],
                "ion_heap": section["ion_heaps"][0],
                "pa_provenance": section["pa_provenance"][0],
                "difference_count": len(section["differences"]),
                "pair_record_count": section["pair_record_count"],
                "pair_records": {
                    difference: list(records)
                    for difference, records in sorted(section["pair_records"].items())
                },
                "differences": dict(section["differences"]),
            }
        )

    for line_number, raw in objects:
        record = dict(raw)
        kind = record.get("type")
        location = f"{source}:{line_number}"
        if kind == "context":
            finish(current)
            context = _validate_context(record, location, strict_schema)
            contexts.append(context)
            current = {
                "context": context,
                "pair_counts": Counter(),
                "pair_records": {},
                "summarized_differences": set(),
                "pair_record_count": 0,
                "ion_heaps": [],
                "pa_provenance": [],
                "differences": {},
            }
            continue
        if current is None:
            raise InvarianceError(f"{location}: record precedes the first context")
        if kind == "ion_heap":
            heap = _validate_ion_heap(record, location, strict_schema)
            current["ion_heaps"].append(heap)
            heaps.append(heap)
            continue
        if kind == "pa_provenance":
            pa_record = _validate_pa_provenance(record, location, strict_schema)
            current["pa_provenance"].append(pa_record)
            provenance.append(pa_record)
            continue
        if kind == "pair":
            difference, offset, delta = _validate_pair(record, location, strict_schema)
            if difference in current["summarized_differences"]:
                raise InvarianceError(
                    f"{location}: pair record for 0x{difference:x} appears after its summary"
                )
            limit = current["context"]["mib"] * 1024 * 1024
            if offset >= limit:
                raise InvarianceError(
                    f"{location}: pair offset 0x{offset:x} exceeds context allocation"
                )
            if (offset ^ difference) >= limit:
                raise InvarianceError(
                    f"{location}: pair offset^difference 0x{offset ^ difference:x} "
                    "exceeds context allocation"
                )
            offsets = current["pair_records"].setdefault(difference, [])
            if any(pair["offset"] == offset for pair in offsets):
                raise InvarianceError(
                    f"{location}: duplicate pair offset 0x{offset:x} "
                    f"for difference 0x{difference:x}"
                )
            offsets.append({"offset": offset, "delta": delta})
            current["pair_counts"][difference] += 1
            current["pair_record_count"] += 1
            continue
        if kind == "difference":
            difference, stats = _validate_difference(record, location, strict_schema)
            if difference in current["differences"] or difference in medians:
                raise InvarianceError(
                    f"{location}: duplicate difference record 0x{difference:x}"
                )
            if stats["pairs"] != current["context"]["pairs"]:
                raise InvarianceError(
                    f"{location}: 0x{difference:x} summary pairs {stats['pairs']} "
                    f"does not match context pairs {current['context']['pairs']}"
                )
            if current["pair_counts"].get(difference, 0) != stats["pairs"]:
                raise InvarianceError(
                    f"{location}: 0x{difference:x} has "
                    f"{current['pair_counts'].get(difference, 0)} preceding pair "
                    f"records, summary says {stats['pairs']}"
                )
            current["differences"][difference] = stats
            current["summarized_differences"].add(difference)
            medians[difference] = stats["median"]
            summaries[difference] = stats
            continue
        raise InvarianceError(f"{location}: unrecognized transcript type {kind!r}")

    finish(current)
    if require_context and not contexts:
        raise InvarianceError(f"{source}: no context record")
    if not medians:
        raise InvarianceError(f"{source}: no difference records")
    context_identities = {_identity(context) for context in contexts}
    if len(context_identities) > 1:
        raise InvarianceError(
            f"{source}: multiple context records are not identical"
        )
    heap_identities = {_identity(heap) for heap in heaps}
    if len(heap_identities) > 1:
        raise InvarianceError(f"{source}: multiple ion_heap records are not identical")
    provenance_identities = {_identity(item) for item in provenance}
    if len(provenance_identities) > 1:
        raise InvarianceError(
            f"{source}: multiple pa_provenance records are not identical"
        )
    return {
        "context": contexts[0] if contexts else None,
        "contexts": contexts,
        "ion_heap": heaps[0] if heaps else None,
        "pa_provenance": provenance[0] if provenance else None,
        "sections": sections,
        "medians": medians,
        "summaries": summaries,
        "difference_count": len(medians),
        "record_count": len(objects),
    }


def parse_probe_transcript(
    text: str, source: str = "<transcript>", *, require_context: bool = True
) -> dict:
    """Strictly parse a probe JSONL transcript.

    Every nonblank line must be valid JSON and every record must be a known
    probe record.  Multiple context records are accepted only when their full
    JSON objects are identical.  Duplicate difference values are never
    averaged or overwritten.
    """

    return _parse_probe_objects(
        _json_objects(text, source), source, strict_schema=True, require_context=require_context
    )


def load_medians(
    text: str,
    *,
    strict: bool = False,
    source: str = "<transcript>",
    allow_equal_duplicates: bool = False,
) -> dict[int, int]:
    """Compatibility helper returning median values from one transcript.

    The historical unit tests used tiny synthetic records without complete
    context/pair metadata.  ``strict=True`` routes through the repaired parser;
    the default keeps that small helper compatible while still validating JSON,
    context identity, and duplicate summaries.  ``allow_equal_duplicates`` is
    an explicit escape hatch for callers preserving the retired helper's
    behavior; canonical analysis never enables it.
    """

    if strict:
        return parse_probe_transcript(text, source)["medians"]
    objects = _json_objects(text, source)
    contexts: list[dict] = []
    medians: dict[int, int] = {}
    for line_number, raw in objects:
        record = dict(raw)
        if record.get("type") == "context":
            contexts.append(record)
            continue
        if record.get("type") != "difference" or "median" not in record:
            continue
        if "value" not in record:
            raise InvarianceError(f"{source}:{line_number}: difference lacks value")
        try:
            difference = int(record["value"], 0) if isinstance(record["value"], str) else int(record["value"])
            median = int(record["median"])
        except (TypeError, ValueError) as exc:
            raise InvarianceError(f"{source}:{line_number}: malformed difference") from exc
        if difference in medians:
            if not (allow_equal_duplicates and medians[difference] == median):
                raise InvarianceError(
                    f"difference 0x{difference:x} measured more than once in one transcript"
                )
        medians[difference] = median
    if contexts and len({_identity(context) for context in contexts}) > 1:
        raise InvarianceError(f"{source}: multiple context records are not identical")
    return medians


def parse_probe_file(path: Path) -> dict:
    """Read and strictly validate one probe file."""

    path = Path(path)
    _ensure_nonempty_regular(path, "probe input")
    data, artifact = _read_stable_artifact(path, "probe input")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvarianceError(f"cannot decode {path.name!r} as UTF-8") from exc
    result = parse_probe_transcript(text, path.name)
    result["path"] = path
    result["artifact"] = artifact
    return result


def combine_passes(
    passes: Sequence[Mapping[int, int]],
) -> tuple[dict[int, int], dict[int, dict]]:
    """Combine same-condition passes while retaining per-key dispersion."""

    if not passes:
        raise InvarianceError("a condition needs at least one transcript")
    keys: set[int] = set()
    normalised: list[dict[int, int]] = []
    for index, transcript in enumerate(passes):
        if not isinstance(transcript, Mapping):
            raise InvarianceError(f"pass {index} is not a mapping")
        values: dict[int, int] = {}
        for key, value in transcript.items():
            if not _is_int(key) or key < 0:
                raise InvarianceError(f"pass {index} has an invalid difference key")
            if not _is_int(value):
                raise InvarianceError(f"pass {index} has a non-integer median")
            values[int(key)] = int(value)
        normalised.append(values)
        keys.update(values)
    if not keys:
        raise InvarianceError("a condition's transcripts contain no difference")

    combined: dict[int, int] = {}
    dispersion: dict[int, dict] = {}
    for key in sorted(keys):
        values = sorted(transcript[key] for transcript in normalised if key in transcript)
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        combined[key] = sum(values) // len(values)
        dispersion[key] = {
            "observations": len(values),
            "values": values,
            "minimum": min(values),
            "maximum": max(values),
            "mean": mean,
            "population_stddev": round(math.sqrt(variance), 6),
            "spread": max(values) - min(values),
        }
    return combined, dispersion


def separation(medians: Mapping[int, int]) -> dict:
    """Split medians at their widest gap and report the runner-up gap."""

    if len(medians) < 2:
        raise InvarianceError("separation needs at least two differences")
    ordered = sorted(int(value) for value in medians.values())
    gaps = [high - low for low, high in zip(ordered, ordered[1:])]
    ranked = sorted(enumerate(gaps), key=lambda item: (-item[1], item[0]))
    widest_index, widest_gap = ranked[0]
    runner_up_gap = ranked[1][1] if len(ranked) > 1 else None
    low = ordered[widest_index]
    high = ordered[widest_index + 1]
    if runner_up_gap is None:
        runner_up_ratio = 0.0
    elif widest_gap:
        runner_up_ratio = runner_up_gap / widest_gap
    else:
        runner_up_ratio = 1.0
    return {
        "threshold": (low + high) // 2,
        "gap": widest_gap,
        "widest_gap": widest_gap,
        "runner_up_gap": runner_up_gap,
        "runner_up_ratio": runner_up_ratio,
        "weak_separation": runner_up_ratio >= WEAK_SEPARATION_RUNNER_UP_RATIO,
        "band_low": low,
        "band_high": high,
        "value_count": len(ordered),
        "gap_count": len(gaps),
    }


def classify(medians: Mapping[int, int], threshold: int) -> dict[int, str]:
    return {
        difference: ("CONFLICT" if median > threshold else "NEGATIVE")
        for difference, median in medians.items()
    }


def _pass_medians(pass_data: Mapping) -> Mapping[int, int]:
    if "medians" in pass_data and isinstance(pass_data["medians"], Mapping):
        return pass_data["medians"]
    return pass_data


def _hex_difference(difference: int) -> str:
    return f"0x{difference:x}"


def analyse_condition(
    name: str,
    passes: Sequence[Mapping[int, int] | Mapping[str, object]],
    *,
    input_metadata: Sequence[Mapping[str, object]] | None = None,
    context: Mapping[str, object] | None = None,
) -> dict:
    """Analyse one condition without merging it with another condition."""

    if not isinstance(name, str) or not name:
        raise InvarianceError("condition name must be nonempty")
    median_passes = [_pass_medians(pass_data) for pass_data in passes]
    medians, dispersion = combine_passes(median_passes)
    split = separation(medians)
    labels = classify(medians, split["threshold"])
    single = [d for d, info in dispersion.items() if info["observations"] < 2]
    unstable = [
        {"difference": _hex_difference(d), **info}
        for d, info in sorted(dispersion.items())
        if info["observations"] > 1 and info["spread"] > split["gap"]
    ]
    result = {
        "name": name,
        "transcript_count": len(median_passes),
        "difference_count": len(medians),
        "context": dict(context) if context is not None else None,
        "separation": split,
        "medians": {_hex_difference(d): m for d, m in sorted(medians.items())},
        "labels": {
            _hex_difference(d): value for d, value in sorted(labels.items())
        },
        "dispersion": {
            _hex_difference(d): info for d, info in sorted(dispersion.items())
        },
        "conflict_count": sum(1 for value in labels.values() if value == "CONFLICT"),
        "single_observation_differences": [
            _hex_difference(d) for d in sorted(single)
        ],
        "unstable_differences": unstable,
    }
    if input_metadata is not None:
        result["inputs"] = [dict(item) for item in input_metadata]
    return result


def _condition_key_sets(conditions: Sequence[Mapping[str, object]]) -> dict[str, set[str]]:
    key_sets: dict[str, set[str]] = {}
    names: set[str] = set()
    for condition in conditions:
        name = condition.get("name")
        if not isinstance(name, str) or not name:
            raise InvarianceError("every condition needs a nonempty name")
        if name in names:
            raise InvarianceError(f"duplicate condition name {name!r}")
        names.add(name)
        labels = condition.get("labels")
        if not isinstance(labels, Mapping):
            raise InvarianceError(f"condition {name!r} lacks labels")
        key_sets[name] = set(labels)
    if not key_sets:
        raise InvarianceError("at least one condition is required")
    first_name = next(iter(key_sets))
    first = key_sets[first_name]
    for name, keys in key_sets.items():
        if keys != first:
            missing = sorted(first - keys)
            extra = sorted(keys - first)
            raise InvarianceError(
                f"condition {name!r} has unequal final difference keys; "
                f"missing={missing}, extra={extra}"
            )
    return key_sets


def compare(
    conditions: Sequence[dict],
    baseline: str,
    *,
    forced_repeat_conditions: Sequence[str] | None = None,
) -> dict:
    """Compare labels against *baseline* with explicit weak-separation gates."""

    key_sets = _condition_key_sets(conditions)
    by_name = {condition["name"]: condition for condition in conditions}
    if baseline not in by_name:
        raise InvarianceError(f"baseline {baseline!r} is not among the conditions")

    weak = {
        condition["name"]
        for condition in conditions
        if condition["separation"].get(
            "weak_separation",
            condition["separation"].get("runner_up_ratio", 0)
            >= WEAK_SEPARATION_RUNNER_UP_RATIO,
        )
    }
    for condition in conditions:
        condition["weak_separation"] = condition["name"] in weak

    forced = set(forced_repeat_conditions or ())
    # This is an intentional canonical gate.  The separately bound repeat
    # transcript is evidence that the two excursions did not survive; it does
    # not turn the one-pass, weakly separated condition into INVARIANT.
    if "v2321-L762" in by_name:
        forced.add("v2321-L762")

    base = by_name[baseline]
    comparisons = []
    base_keys = key_sets[baseline]
    for condition in sorted(conditions, key=lambda item: item["name"]):
        if condition["name"] == baseline:
            continue
        shared = sorted(base_keys)
        disagreements = []
        for key in shared:
            if base["labels"][key] == condition["labels"][key]:
                continue
            row = {
                "difference": key,
                "baseline_label": base["labels"][key],
                "baseline_median": base["medians"][key],
                "condition_label": condition["labels"][key],
                "condition_median": condition["medians"][key],
            }
            if key in base.get("dispersion", {}):
                row["baseline_dispersion"] = base["dispersion"][key]
            if key in condition.get("dispersion", {}):
                row["condition_dispersion"] = condition["dispersion"][key]
            disagreements.append(row)
        name = condition["name"]
        if name in forced or disagreements and (name in weak or baseline in weak):
            status = "REPEAT_REQUIRED"
        elif disagreements:
            status = "DISAGREEMENT"
        else:
            status = "INVARIANT"
        comparisons.append(
            {
                "condition": name,
                "shared_differences": len(shared),
                "disagreements": disagreements,
                "status": status,
            }
        )

    return {
        "baseline": baseline,
        "shared_difference_count": len(base_keys),
        "weak_separation_conditions": sorted(weak),
        "weak_separation_runner_up_ratio": WEAK_SEPARATION_RUNNER_UP_RATIO,
        "forced_repeat_conditions": sorted(name for name in forced if name in by_name),
        "comparisons": comparisons,
        "all_invariant": all(
            comparison["status"] == "INVARIANT" for comparison in comparisons
        ) and not any(
            comparison["condition"] in forced for comparison in comparisons
        ),
    }


def analyse(
    condition_passes: Mapping[str, Sequence[Mapping[int, int]]],
    baseline: str,
    *,
    expected_difference_count: int | None = None,
    contexts: Mapping[str, Mapping[str, object]] | None = None,
    input_metadata: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
) -> dict:
    """Analyse all conditions, enforcing equal final key sets."""

    if not isinstance(condition_passes, Mapping) or not condition_passes:
        raise InvarianceError("at least one condition is required")
    if contexts is not None:
        if any(context is None for context in contexts.values()):
            raise InvarianceError("every condition must bind a probe context")
        context_identities = {
            _identity(context)
            for context in contexts.values()
        }
        if len(context_identities) > 1:
            raise InvarianceError("all conditions must bind one identical probe context")
    conditions = [
        analyse_condition(
            name,
            passes,
            context=(contexts or {}).get(name),
            input_metadata=(input_metadata or {}).get(name),
        )
        for name, passes in sorted(condition_passes.items())
    ]
    _condition_key_sets(conditions)
    if expected_difference_count is not None:
        for condition in conditions:
            if condition["difference_count"] != expected_difference_count:
                raise InvarianceError(
                    f"condition {condition['name']!r} has "
                    f"{condition['difference_count']} differences, expected "
                    f"{expected_difference_count}"
                )
    return {
        "schema": SCHEMA,
        "conditions": conditions,
        "comparison": compare(conditions, baseline),
    }


def _ensure_nonempty_regular(path: Path, label: str) -> None:
    path = Path(path)
    if path.is_symlink():
        raise InvarianceError(f"{label} {path.name!r} must not be a symlink")
    try:
        mode = path.stat().st_mode
        size = path.stat().st_size
    except OSError as exc:
        raise InvarianceError(f"{label} {path.name!r} is not readable: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise InvarianceError(f"{label} {path.name!r} is not a regular file")
    if size <= 0:
        raise InvarianceError(f"{label} {path.name!r} is empty")


def _artifact_metadata(path: Path, label: str) -> dict:
    path = Path(path)
    data, metadata = _read_stable_artifact(path, label)
    del data
    return metadata


def _read_stable_artifact(path: Path, label: str) -> tuple[bytes, dict]:
    path = Path(path)
    data = _read_stable_bytes(path, label)
    return data, {
        "basename": path.name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _check_artifact_pin(
    metadata: Mapping[str, object],
    pins: Mapping[str, tuple[int, str]] | None,
    label: str,
) -> None:
    if pins is None:
        return
    basename = metadata["basename"]
    expected = pins.get(str(basename))
    if expected is None:
        raise InvarianceError(f"{label} {basename!r} has no canonical size/hash pin")
    expected_size, expected_sha256 = expected
    if metadata["size_bytes"] != expected_size or metadata["sha256"] != expected_sha256:
        raise InvarianceError(
            f"{label} {basename!r} does not match its canonical size/SHA-256 pin"
        )


def _path_identity(path: Path) -> str:
    try:
        return str(path.resolve(strict=True))
    except OSError as exc:
        raise InvarianceError(f"cannot resolve input {path.name!r}: {exc}") from exc


def _validate_input_identity(
    condition_paths: Mapping[str, Sequence[Path]],
    extras: Sequence[Path] = (),
    *,
    pins: Mapping[str, tuple[int, str]] | None = None,
    known_metadata: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, list[dict]]:
    """Return sanitized metadata and reject path/hash aliases globally."""

    names: set[str] = set()
    paths_seen: dict[str, str] = {}
    hashes_seen: dict[str, str] = {}
    metadata: dict[str, list[dict]] = {}
    for condition in sorted(condition_paths):
        if condition in names:
            raise InvarianceError(f"duplicate condition name {condition!r}")
        names.add(condition)
        entries: list[dict] = []
        normalized_paths = [Path(path) for path in condition_paths[condition]]
        if not normalized_paths:
            raise InvarianceError(f"condition {condition!r} has no input paths")
        for path in sorted(normalized_paths, key=lambda item: str(item)):
            _ensure_nonempty_regular(path, "condition input")
            identity = _path_identity(path)
            if identity in paths_seen:
                raise InvarianceError(
                    f"input path is bound more than once: {path.name!r} "
                    f"(already in {paths_seen[identity]!r})"
                )
            paths_seen[identity] = condition
            item = _artifact_metadata(path, "condition input")
            known = (known_metadata or {}).get(identity)
            if known is not None and dict(item) != dict(known):
                raise InvarianceError(
                    f"condition input {path.name!r} changed between parse and binding"
                )
            _check_artifact_pin(item, pins, "condition input")
            if item["sha256"] in hashes_seen:
                raise InvarianceError(
                    f"input content hash is bound more than once: {path.name!r} "
                    f"(same content as {hashes_seen[item['sha256']]!r})"
                )
            hashes_seen[item["sha256"]] = path.name
            entries.append(item)
        metadata[condition] = entries
    for path in extras:
        _ensure_nonempty_regular(Path(path), "auxiliary input")
        identity = _path_identity(Path(path))
        if identity in paths_seen:
            raise InvarianceError(f"auxiliary input aliases a condition input: {Path(path).name!r}")
        paths_seen[identity] = "auxiliary"
        item = _artifact_metadata(Path(path), "auxiliary input")
        known = (known_metadata or {}).get(identity)
        if known is not None and dict(item) != dict(known):
            raise InvarianceError(
                f"auxiliary input {Path(path).name!r} changed between parse and binding"
            )
        _check_artifact_pin(item, pins, "auxiliary input")
        if item["sha256"] in hashes_seen:
            raise InvarianceError(
                f"auxiliary input content hash duplicates {hashes_seen[item['sha256']]!r}"
            )
        hashes_seen[item["sha256"]] = Path(path).name
    return metadata


def canonical_input_paths(root: Path = PRIVATE_ROOT) -> dict[str, list[Path]]:
    """Resolve the exact canonical basenames, failing on any missing/empty file."""

    root = Path(root)
    if not root.exists() or not root.is_dir():
        raise InvarianceError("canonical private input directory is unavailable")
    result: dict[str, list[Path]] = {}
    for condition, basenames in CANONICAL_CONDITION_BASENAMES.items():
        paths = [root / basename for basename in basenames]
        for path in paths:
            _ensure_nonempty_regular(path, "canonical condition input")
        result[condition] = paths
    return result


def _glob_paths(pattern: str) -> list[Path]:
    if not pattern:
        raise InvarianceError("condition glob is empty")
    matches = [Path(value) for value in glob.glob(pattern, recursive=True)]
    files = sorted((path for path in matches if path.is_file()), key=lambda item: str(item))
    if not files:
        raise InvarianceError(f"condition glob matched no nonempty file: {pattern!r}")
    return files


def _parse_condition(argument: str) -> tuple[str, list[Path]]:
    name, separator, pattern = argument.partition("=")
    if not separator or not name or not pattern:
        raise InvarianceError(f"--condition wants NAME=GLOB, got {argument!r}")
    _validate_identifier(name, "condition name")
    paths = _glob_paths(pattern)
    return name, paths


def _parse_level_groups(
    path: Path, *, kind: str, enforce_scope: bool = True
) -> dict:
    path = Path(path)
    source = path.name
    try:
        data, artifact = _read_stable_artifact(path, "level input")
        objects = _json_objects(data.decode("utf-8"), source)
    except UnicodeDecodeError as exc:
        raise InvarianceError(f"cannot decode {source!r} as UTF-8") from exc
    expected_schema = LEVEL_REPEAT_SCHEMA if kind == "repeat" else LEVEL_SWEEP_SCHEMA
    groups: list[dict] = []
    current_marker: dict | None = None
    current_objects: list[tuple[int, Mapping[str, object]]] = []
    seen_group_keys: set[tuple[int, int]] = set()

    def finish() -> None:
        nonlocal current_marker, current_objects
        if current_marker is None:
            return
        parsed = _parse_probe_objects(current_objects, source, strict_schema=True)
        if kind == "repeat":
            rep = int(current_marker["rep"])
            level = int(current_marker["level"])
            expected_count = None
        else:
            rep = int(current_marker["rep"])
            level = int(current_marker["requested"])
            expected_count = int(current_marker["record_count"])
            if expected_count != len(current_objects):
                raise InvarianceError(
                    f"{source}: sweep level {level} rep {rep} record_count "
                    f"{expected_count} != {len(current_objects)}"
                )
        groups.append(
            {
                "rep": rep,
                "level": level,
                "marker": dict(current_marker),
                "parsed": parsed,
            }
        )
        current_marker = None
        current_objects = []

    for line_number, raw in objects:
        record = dict(raw)
        location = f"{source}:{line_number}"
        if record.get("type") == "level":
            finish()
            if record.get("schema") != expected_schema:
                raise InvarianceError(
                    f"{location}: level marker has schema {record.get('schema')!r}, "
                    f"expected {expected_schema!r}"
                )
            if not _is_int(record.get("rep")) or int(record["rep"]) < 0:
                raise InvarianceError(f"{location}: level rep must be non-negative integer")
            if kind == "repeat":
                field = "level"
                if not _is_int(record.get(field)) or int(record[field]) <= 0:
                    raise InvarianceError(f"{location}: repeat level must be positive integer")
                level = int(record[field])
            else:
                for field in ("requested", "observed_cur_freq", "record_count"):
                    if not _is_int(record.get(field)):
                        raise InvarianceError(f"{location}: sweep {field} must be integer")
                if int(record["requested"]) <= 0 or int(record["record_count"]) <= 0:
                    raise InvarianceError(f"{location}: sweep requested/count must be positive")
                if int(record["observed_cur_freq"]) != int(record["requested"]):
                    raise InvarianceError(
                        f"{location}: observed_cur_freq does not match requested vote"
                    )
                level = int(record["requested"])
            key = (int(record["rep"]), level)
            if key in seen_group_keys:
                raise InvarianceError(f"{location}: duplicate level group {key!r}")
            seen_group_keys.add(key)
            current_marker = record
            continue
        if current_marker is None:
            raise InvarianceError(f"{location}: record precedes first level marker")
        current_objects.append((line_number, record))
    finish()
    if not groups:
        raise InvarianceError(f"{source}: no level groups")

    context_ids = {
        _identity(group["parsed"]["context"])
        for group in groups
        if group["parsed"].get("context") is not None
    }
    if len(context_ids) > 1:
        raise InvarianceError(f"{source}: level groups have mismatched contexts")

    if kind == "repeat":
        actual = {(group["rep"], group["level"]) for group in groups}
        expected = {(rep, level) for rep in EXPECTED_REPEAT_REPS for level in EXPECTED_REPEAT_LEVELS}
        if enforce_scope and actual != expected:
            raise InvarianceError(
                f"{source}: repeat scope must be exactly six groups {sorted(expected)!r}, "
                f"got {sorted(actual)!r}"
            )
        for group in groups:
            keys = set(group["parsed"]["medians"])
            expected_keys = set(EXPECTED_REPEAT_DIFFERENCES)
            if enforce_scope and keys != expected_keys:
                raise InvarianceError(
                    f"{source}: repeat group {(group['rep'], group['level'])!r} "
                    "does not contain the six canonical differences"
                )
    else:
        actual_levels = {group["level"] for group in groups}
        actual_reps = {group["rep"] for group in groups}
        actual = {(group["rep"], group["level"]) for group in groups}
        expected = {(rep, level) for rep in EXPECTED_SWEEP_REPS for level in EXPECTED_SWEEP_LEVELS}
        if enforce_scope and actual != expected:
            raise InvarianceError(
                f"{source}: sweep scope must be exactly twelve groups for six levels, "
                f"got {sorted(actual)!r}"
            )
        if enforce_scope and (actual_levels != set(EXPECTED_SWEEP_LEVELS) or actual_reps != set(EXPECTED_SWEEP_REPS)):
            raise InvarianceError(f"{source}: sweep requested levels/repetitions are not canonical")
        for group in groups:
            keys = set(group["parsed"]["medians"])
            if enforce_scope and keys != set(EXPECTED_SWEEP_DIFFERENCES):
                raise InvarianceError(
                    f"{source}: sweep group {(group['rep'], group['level'])!r} "
                    "does not contain the three canonical differences"
                )

    groups.sort(key=lambda group: (group["level"], group["rep"]))
    heap_identities = {
        _identity(group["parsed"]["ion_heap"]) for group in groups
    }
    provenance_identities = {
        _identity(group["parsed"]["pa_provenance"]) for group in groups
    }
    if len(heap_identities) != 1:
        raise InvarianceError(f"{source}: level groups have mismatched ion_heap records")
    if len(provenance_identities) != 1:
        raise InvarianceError(
            f"{source}: level groups have mismatched pa_provenance records"
        )
    return {
        "schema": expected_schema,
        "kind": kind,
        "groups": groups,
        "context": groups[0]["parsed"].get("context"),
        "ion_heap": groups[0]["parsed"].get("ion_heap"),
        "pa_provenance": groups[0]["parsed"].get("pa_provenance"),
        "artifact": artifact,
        "requested_levels": sorted({group["level"] for group in groups}),
        "replicates": sorted({group["rep"] for group in groups}),
    }


def parse_level_repeat(path: Path, *, enforce_scope: bool = True) -> dict:
    return _parse_level_groups(path, kind="repeat", enforce_scope=enforce_scope)


def parse_level_sweep(path: Path, *, enforce_scope: bool = True) -> dict:
    return _parse_level_groups(path, kind="sweep", enforce_scope=enforce_scope)


def bind_repeat_evidence(repeat: Mapping[str, object], baseline: Mapping[str, object]) -> dict:
    """Bind repeated groups using an independent split for every group.

    The baseline condition is retained as a provenance label only.  Its
    absolute median scale is intentionally never used: every six-difference
    repeat group derives its own widest-gap threshold before low/high labels
    are compared.  A surviving flip is any difference that flips in at least
    one repeated pair; no majority vote can erase an observed flip.
    """

    groups = repeat["groups"]
    by_key = {(int(group["rep"]), int(group["level"])): group for group in groups}
    group_analyses: list[dict] = []
    labels_by_group: dict[tuple[int, int], dict[str, str]] = {}
    for group in sorted(groups, key=lambda item: (int(item["level"]), int(item["rep"]))):
        rep = int(group["rep"])
        level = int(group["level"])
        medians = group["parsed"]["medians"]
        if set(medians) != set(EXPECTED_REPEAT_DIFFERENCES):
            raise InvarianceError(
                f"repeat group {(rep, level)!r} does not contain the six differences"
            )
        split = separation(medians)
        labels = classify(medians, split["threshold"])
        encoded_labels = {
            _hex_difference(difference): label
            for difference, label in sorted(labels.items())
        }
        labels_by_group[(rep, level)] = encoded_labels
        group_analyses.append(
            {
                "rep": rep,
                "level": level,
                "difference_count": len(medians),
                "separation": split,
                "medians": {
                    _hex_difference(difference): median
                    for difference, median in sorted(medians.items())
                },
                "labels": encoded_labels,
            }
        )

    per_difference: dict[str, dict] = {}
    surviving: list[str] = []
    for difference in EXPECTED_REPEAT_DIFFERENCES:
        key = _hex_difference(difference)
        repetitions = []
        flip_repetitions = 0
        for rep in EXPECTED_REPEAT_REPS:
            low_group = by_key[(rep, EXPECTED_REPEAT_LEVELS[0])]
            high_group = by_key[(rep, EXPECTED_REPEAT_LEVELS[1])]
            low = low_group["parsed"]["medians"][difference]
            high = high_group["parsed"]["medians"][difference]
            low_label = labels_by_group[(rep, EXPECTED_REPEAT_LEVELS[0])][key]
            high_label = labels_by_group[(rep, EXPECTED_REPEAT_LEVELS[1])][key]
            flipped = low_label != high_label
            if flipped:
                flip_repetitions += 1
            repetitions.append(
                {
                    "rep": rep,
                    "low_level": EXPECTED_REPEAT_LEVELS[0],
                    "high_level": EXPECTED_REPEAT_LEVELS[1],
                    "low_median": low,
                    "high_median": high,
                    "low_label": low_label,
                    "high_label": high_label,
                    "flip": flipped,
                }
            )
        # Any observed flip survives; a single flip cannot be voted away.
        if flip_repetitions > 0:
            surviving.append(key)
        per_difference[key] = {
            "repetitions": repetitions,
            "flip_repetitions": flip_repetitions,
            "survives_repetition": flip_repetitions > 0,
        }
    return {
        "binding": "v2321-L762_vs_v2321-L7980",
        "baseline_condition": baseline["name"],
        "label_binding": "independent_widest_gap_per_repeat_group",
        "group_analyses": group_analyses,
        "difference_count": len(per_difference),
        "per_difference": per_difference,
        "surviving_flip_count": len(surviving),
        "surviving_flips": surviving,
        "zero_surviving_repeated_flips": not surviving,
        "interpretation": (
            "Repeat evidence does not promote v2321-L762; its comparison remains "
            "REPEAT_REQUIRED."
        ),
    }


def validate_repeat_coverage(
    comparison: Mapping[str, object], repeat_summary: Mapping[str, object]
) -> dict:
    """Require repeat evidence to cover every primary L762 disagreement."""

    primary = next(
        (
            entry
            for entry in comparison["comparisons"]
            if entry.get("condition") == "v2321-L762"
        ),
        None,
    )
    if primary is None:
        raise InvarianceError("primary v2321-L762 comparison is absent")
    disagreements = sorted(
        {str(entry["difference"]) for entry in primary["disagreements"]}
    )
    measured = {
        str(key) for key in repeat_summary.get("per_difference", {})
    }
    missing = sorted(set(disagreements) - measured)
    if missing:
        raise InvarianceError(
            "repeat evidence does not cover primary disagreements: "
            + ", ".join(missing)
        )
    return {
        "primary_condition": "v2321-L762",
        "baseline_condition": comparison["baseline"],
        "original_disagreement_count": len(disagreements),
        "original_disagreements": disagreements,
        "repeat_difference_count": len(measured),
        "covered_disagreements": disagreements,
        "unmeasured_disagreements": missing,
        "coverage_complete": True,
    }


def summarize_level_sweep(sweep: Mapping[str, object]) -> dict:
    rows = []
    for group in sweep["groups"]:
        marker = group["marker"]
        parsed = group["parsed"]
        rows.append(
            {
                "rep": int(group["rep"]),
                "requested": int(group["level"]),
                "observed_cur_freq": int(marker["observed_cur_freq"]),
                "record_count": int(marker["record_count"]),
                "difference_count": parsed["difference_count"],
                "medians": {
                    _hex_difference(d): median
                    for d, median in sorted(parsed["medians"].items())
                },
            }
        )
    return {
        "schema": sweep["schema"],
        "requested_levels": list(EXPECTED_SWEEP_LEVELS),
        "requested_level_count": len(EXPECTED_SWEEP_LEVELS),
        "replicates_per_level": len(EXPECTED_SWEEP_REPS),
        "rows": rows,
        "scope": {
            "axis": "bus-vote-request",
            "measured_requested_levels_only": True,
            "six_levels_x_two_replicates": True,
            "ddr_frequency_inference": "EXCLUDED",
            "transform_transition_inference": "EXCLUDED",
        },
    }


def _metadata_for_single(path: Path, label: str) -> dict:
    return _artifact_metadata(path, label)


def _canonical_auxiliary_paths(root: Path = PRIVATE_ROOT) -> tuple[Path, Path, list[Path]]:
    repeat = root / REPEAT_BASENAME
    sweep = root / SWEEP_BASENAME
    journals = [root / basename for basename in JOURNAL_BASENAMES]
    for path in (repeat, sweep, *journals):
        _ensure_nonempty_regular(path, "canonical auxiliary input")
    return repeat, sweep, journals


def _common_acquisition_context(parsed_by_condition: Mapping[str, Sequence[Mapping]]) -> dict:
    """Validate and sanitize the common heap/physical-provenance records.

    The probe reports ``contiguous=true`` as an observation about the
    allocation request.  Because every retained pagemap record is BLIND, the
    effective physical contiguity remains UNKNOWN and is never promoted here.
    """

    heaps: list[Mapping[str, object]] = []
    provenance: list[Mapping[str, object]] = []
    for name in sorted(parsed_by_condition):
        entries = parsed_by_condition[name]
        if not entries:
            raise InvarianceError(f"condition {name!r} has no acquisition context")
        for entry in entries:
            heap = entry.get("ion_heap")
            pa_record = entry.get("pa_provenance")
            if not isinstance(heap, Mapping) or not isinstance(pa_record, Mapping):
                raise InvarianceError(
                    f"condition {name!r} lacks its ion_heap/pa_provenance context"
                )
            heaps.append(heap)
            provenance.append(pa_record)
    if len({_identity(heap) for heap in heaps}) != 1:
        raise InvarianceError("ion_heap acquisition contexts are not identical")
    if len({_identity(record) for record in provenance}) != 1:
        raise InvarianceError("pa_provenance acquisition contexts are not identical")
    heap = heaps[0]
    pa_record = provenance[0]
    return {
        "common_across_conditions": True,
        "ion_heap": {
            "name": heap["name"],
            "heap_type": int(heap["heap_type"]),
            "heap_id": int(heap["heap_id"]),
        },
        "pa_provenance": {
            "source": pa_record["source"],
            "status": pa_record["status"],
            "pagemap_status": pa_record["status"],
            "pages": int(pa_record["pages"]),
            "present": int(pa_record["present"]),
            "nonzero_pfn": int(pa_record["nonzero_pfn"]),
            "reported_contiguous": bool(pa_record["contiguous"]),
            "effective_contiguity": "UNKNOWN",
        },
    }


def _validate_auxiliary_context_binding(
    main_context: Mapping[str, object],
    repeat: Mapping[str, object],
    sweep: Mapping[str, object],
    *,
    main_records: Mapping[str, Mapping[str, object]] | None = None,
) -> None:
    """Bind auxiliary probe contexts to the main context by declared pairs.

    The level-repeat probe deliberately uses 32 pairs; the main conditions and
    level sweep use 16.  Every other context field must be byte-for-byte
    identical.  This prevents a level marker from being attached to a probe
    acquired with a different heap, barrier, or offset policy.
    """

    sweep_context = sweep.get("context")
    repeat_context = repeat.get("context")
    if not isinstance(sweep_context, Mapping) or not isinstance(repeat_context, Mapping):
        raise InvarianceError("auxiliary transcript is missing its probe context")
    if _identity(sweep_context) != _identity(main_context):
        raise InvarianceError("level-sweep context does not match the main probe context")
    expected_repeat = dict(main_context)
    expected_repeat["pairs"] = 32
    if _identity(repeat_context) != _identity(expected_repeat):
        raise InvarianceError(
            "level-repeat context differs from main context outside declared pairs=32"
        )
    if main_records is not None:
        for name, auxiliary in (("repeat", repeat), ("sweep", sweep)):
            if _identity(auxiliary["ion_heap"]) != _identity(main_records["ion_heap"]):
                raise InvarianceError(f"{name} ion_heap does not match main acquisition context")
            if _identity(auxiliary["pa_provenance"]) != _identity(
                main_records["pa_provenance"]
            ):
                raise InvarianceError(
                    f"{name} pa_provenance does not match main acquisition context"
                )


def _auxiliary_acquisition_scope(
    parsed: Mapping[str, object], main_context: Mapping[str, object], kind: str
) -> dict:
    common = _common_acquisition_context({"auxiliary": [parsed]})
    if kind == "repeat":
        binding = "MAIN_CONTEXT_EXCEPT_DECLARED_PAIRS_32"
    else:
        binding = "EXACT_MAIN_CONTEXT_PAIRS_16"
    return {
        "context_pairs": int(parsed["context"]["pairs"]),
        "main_context_binding": binding,
        "ion_heap": common["ion_heap"],
        "pa_provenance": common["pa_provenance"],
    }


def _validate_source_dependencies(
    *,
    probe_source_path: Path | None = None,
    dependency_manifest_path: Path | None = None,
) -> dict:
    probe_source_path = Path(probe_source_path or PROBE_SOURCE_PATH)
    dependency_manifest_path = Path(
        dependency_manifest_path or DEPENDENCY_MANIFEST_PATH
    )
    tool_data, tool = _read_stable_artifact(Path(__file__).resolve(), "analysis tool")
    del tool_data
    probe_data, probe = _read_stable_artifact(probe_source_path, "probe source")
    del probe_data
    dependency_data, dependency = _read_stable_artifact(
        dependency_manifest_path, "dependency manifest"
    )
    if probe["sha256"] != PROBE_SOURCE_SHA256:
        raise InvarianceError("probe source hash does not match the pinned dependency")
    if dependency["sha256"] != DEPENDENCY_MANIFEST_SHA256:
        raise InvarianceError("dependency manifest hash does not match the pinned dependency")
    try:
        dependency_object = json.loads(dependency_data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InvarianceError("dependency manifest is not valid JSON") from exc
    if not isinstance(dependency_object, dict) or dependency_object.get("schema") != "a90-region-relation-solver-v1":
        raise InvarianceError("dependency manifest schema is not the expected 023R schema")
    return {
        "analysis_tool": tool,
        "probe_source": probe,
        "dependency_manifest": dependency,
        "historical_probe_binary": {
            "sha256": HISTORICAL_PROBE_BINARY_SHA256,
            "status": "UNKNOWN_NO_RETAINED_BUILD_OR_TRANSFER_RECEIPT",
            "build_receipt": "NOT_RETAINED",
            "transfer_receipt": "NOT_RETAINED",
        },
    }


def _claims() -> dict[str, list[str]]:
    return {
        "PROVED": [
            "The exact hashed, condition-labelled probe transcript sets classify six separately retained conditions over equal 51-key sets; this does not prove six runtime identities.",
            "Contexts, probe records, and per-difference observation values were validated before comparison.",
            "The bound repeat transcript has zero surviving repeated flips under independent per-group widest-gap label binding.",
            "The bound level sweep contains exactly six requested bus-vote levels with two retained repetitions each.",
            "Each private input records a sanitized basename, byte size, and SHA-256; derived summaries and contexts are published, but raw transcript bytes are not.",
            "The invariance result is scoped to allocation-offset/model coordinates; pagemap BLIND leaves physical-page provenance unknown.",
        ],
        "SUPPORTED": [
            "Runtime identity, reboot identity, coldboot identity, and final cleanup are operator-reported and supported by retained project context only.",
            "The relation is supported as invariant across the operator-reported reboot, kernel/userspace, and coldboot contexts in allocation-offset/model coordinates; this is not live device authority.",
        ],
        "HYPOTHESIS": [
            "A transform transition outside the observed operator-reported conditions remains a hypothesis and is not inferred here.",
        ],
        "UNKNOWN": [
            "No retained two-environment probe build/transfer receipt proves the historical binary hash in both environments.",
            "DDR operating-point selection, physical-page provenance, and mutability through unreachable paths remain unknown.",
            "Device action, reboot/power-cycle, and final-state receipts are incomplete in these files.",
            "The reported contiguous allocation is not effective physical contiguity because pagemap status is BLIND.",
        ],
        "REFUTED": [
            "The separately bound repeat evidence refutes a surviving repeated flip for the two v2321-L762 excursions.",
        ],
    }


def _provenance_identity() -> dict:
    """Describe retained project identity without promoting transcript fields."""

    return {
        "target": {
            "status": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
            "model": "SM-A908N",
            "soc": "SM8150",
            "marketing_name": "A90 5G",
            "transcript_attests_identity": False,
        },
        "runtime_identities": {
            "twrp": {
                "status": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
                "kernel": "4.14.190-Grass,SD855-Perf+",
                "transcript_attests_identity": False,
            },
            "v2321": {
                "status": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
                "runtime": "0.9.285",
                "kernel": "4.14.190-25818860-abA908NKSU5EWA3",
                "transcript_attests_identity": False,
            },
        },
        "timestamp": {
            "status": "UNKNOWN_UNRETAINED",
            "value": None,
            "reason": "No exact per-file acquisition timestamp is retained in the canonical inputs.",
        },
        "commands": {
            "status": "REDACTED_REPRODUCTION_TEMPLATE",
            "template": (
                "python3 tools/a90_runtime_invariance_analysis.py "
                "--condition <condition-name>=<private-root>/<canonical-basename-glob> "
                "--baseline <baseline> --repeat <private-root>/v2321-level-repeat.jsonl "
                "--sweep <private-root>/v2321-level-sweep.jsonl --output <public-output>"
            ),
            "executed_receipt": "NOT_RETAINED",
        },
        "rollback": {
            "status": "UNKNOWN_INCOMPLETE_RECEIPT",
            "journal_inputs_exact": True,
            "final_state_receipt": "INCOMPLETE",
        },
        "recovery": {
            "status": "UNKNOWN_INCOMPLETE_RECEIPT",
            "reboot_receipt": "INCOMPLETE",
            "coldboot_receipt": "INCOMPLETE",
        },
        "final_state": {
            "status": "UNKNOWN_INCOMPLETE_RECEIPT",
            "journal_inputs_exact": True,
            "cleanup_receipt": "INCOMPLETE",
        },
    }


def _assert_public_safety(value: object) -> None:
    """Reject private/absolute path fragments in any public JSON value."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            _assert_public_safety(key)
            _assert_public_safety(item)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _assert_public_safety(item)
        return
    if isinstance(value, str):
        if (
            value.startswith(("/", "\\"))
            or "evidence/private" in value
            or "/home/" in value
            or "/root/" in value
        ):
            raise InvarianceError("public manifest contains a private absolute/path fragment")


def _public_manifest(
    *,
    analysis: dict,
    input_metadata: Mapping[str, Sequence[Mapping[str, object]]],
    repeat_metadata: Mapping[str, object],
    sweep_metadata: Mapping[str, object],
    journal_metadata: Sequence[Mapping[str, object]],
    repeat_summary: dict,
    sweep_summary: dict,
    dependencies: dict,
    acquisition_context: Mapping[str, object],
) -> dict:
    comparison = analysis["comparison"]
    return {
        "schema": SCHEMA,
        "experiment_id": "verification-015-runtime-invariance",
        "mode": "HOST_ONLY_READ_ONLY_ANALYSIS",
        "eligibility": "NOT_ELIGIBLE",
        "classification": "Class C: TRANSFORM ONLY",
        "class_c": "TRANSFORM ONLY",
        "coordinate_scope": "ALLOCATION_OFFSET_MODEL_COORDINATES",
        "conditions": analysis["conditions"],
        "comparison": comparison,
        "acquisition_context": dict(acquisition_context),
        "inputs": {
            "conditions": {
                name: [dict(item) for item in input_metadata[name]]
                for name in sorted(input_metadata)
            },
            "repeat": dict(repeat_metadata),
            "level_sweep": dict(sweep_metadata),
            "journals": [dict(item) for item in sorted(journal_metadata, key=lambda item: item["basename"])],
        },
        "repeat_evidence": repeat_summary,
        "level_sweep": sweep_summary,
        "dependencies": dependencies,
        "provenance_identity": _provenance_identity(),
        "provenance_status": {
            "exact_raw_transcripts_and_journals": "PROVED_INPUT",
            "input_basename_size_sha256_binding": "PROVED",
            "context_and_difference_validation": "PROVED",
            "analysis_tool_hash": "PROVED_HASH",
            "probe_source_hash": "PROVED_HASH",
            "dependency_manifest_hash": "PROVED_HASH",
            "historical_probe_binary_build_transfer": "UNKNOWN_NO_RETAINED_RECEIPT",
            "runtime_identity": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
            "reboot_identity": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
            "coldboot_identity": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
            "final_cleanup": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
            "historical_acquisition_actions": "SUPPORTED_BY_OPERATOR_REPORT_INCOMPLETE",
            "ddr_frequency_transition": "UNKNOWN_BANDWIDTH_AXIS_RETRACTED",
            "physical_page_provenance": "UNKNOWN_PAGEMAP_BLIND",
            "acquisition_heap_and_pagemap_context": "PROVED_RECORDS_EFFECTIVE_CONTIGUITY_UNKNOWN",
        },
        "transition_scope": {
            "operator_reported_transitions": [
                "reboot_through_xbl_ddr_initialization",
                "kernel_and_userspace_change",
                "operator_power_cycle_coldboot",
            ],
            "transition_identity_status": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
            "bus_vote_axis": "RETRACTED_AND_EXCLUDED",
            "bus_vote_comparison": "STABILITY_ONLY_NO_DDR_FREQUENCY_OR_TRANSFORM_INFERENCE",
            "unmodified_higher_voter_transcript": "NOT_RETAINED",
        },
        "dispositions": {
            "conceptual_experiments_015_and_016": "NOT_ELIGIBLE",
            "class_c": "TRANSFORM ONLY",
            "bandwidth_axis": "RETRACTED_AND_EXCLUDED",
            "alias_or_mutation_scope": "NO_ALIAS_OR_MUTATION_OBSERVED_OR_TESTED",
        },
        "alias_and_mutation": {
            "status": "NO_ALIAS_OR_MUTATION_OBSERVED_OR_TESTED",
            "analysis_access": "HOST_ONLY_READ_ONLY",
            "duplicate_path_policy": "REJECT",
            "duplicate_content_hash_policy": "REJECT",
            "device_mutation": "NONE_FOR_THIS_HOST_INTEGRATION_ACTION",
        },
        "public_private_separation": {
            "private_absolute_paths_in_manifest": False,
            "raw_transcript_bytes_in_manifest": False,
            "raw_sensitive_bytes_in_manifest": False,
            "input_paths_emitted": "BASENAMES_ONLY",
        },
        "publication": {
            "method": "ATOMIC_NO_CLOBBER_HARDLINK",
            "requested_mode": "0644",
            "mode_policy": "fchmod fresh inode to 0644, then lstat after publish; write result records observed mode",
            "mode_claim": "OBSERVED_ONLY_IN_WRITE_RESULT; NOT_GIT_CHECKOUT_MODE",
        },
        "claims": _claims(),
    }


def build_manifest(
    condition_paths: Mapping[str, Sequence[Path]] | None = None,
    *,
    repeat_path: Path | None = None,
    level_sweep_path: Path | None = None,
    journal_paths: Sequence[Path] | None = None,
    baseline: str = "v2321-L7980",
    probe_source_path: Path | None = None,
    dependency_manifest_path: Path | None = None,
) -> dict:
    """Build the canonical public manifest from validated private inputs."""

    if baseline != "v2321-L7980":
        raise InvarianceError(
            "canonical Verification-015 baseline must be v2321-L7980"
        )
    canonical = condition_paths is None
    if condition_paths is None:
        condition_paths = canonical_input_paths()
    condition_paths = {
        str(name): [Path(path) for path in paths]
        for name, paths in condition_paths.items()
    }
    if canonical or set(condition_paths) == set(CANONICAL_CONDITION_BASENAMES):
        if set(condition_paths) != set(CANONICAL_CONDITION_BASENAMES):
            raise InvarianceError("canonical build requires all six named conditions")
        for name, expected_basenames in CANONICAL_CONDITION_BASENAMES.items():
            actual_basenames = tuple(
                sorted(path.name for path in condition_paths[name])
            )
            if actual_basenames != tuple(sorted(expected_basenames)):
                raise InvarianceError(
                    f"condition {name!r} is not bound to its exact canonical basenames"
                )
        if repeat_path is None or level_sweep_path is None or journal_paths is None:
            default_repeat, default_sweep, default_journals = _canonical_auxiliary_paths()
            repeat_path = repeat_path or default_repeat
            level_sweep_path = level_sweep_path or default_sweep
            journal_paths = list(journal_paths or default_journals)
    else:
        raise InvarianceError(
            "build_manifest is reserved for the six canonical Verification-015 conditions"
        )

    assert repeat_path is not None and level_sweep_path is not None
    if journal_paths is None:
        raise InvarianceError("canonical build requires both journal inputs")
    journal_paths = [Path(path) for path in journal_paths]
    if len(journal_paths) != 2 or {path.name for path in journal_paths} != set(JOURNAL_BASENAMES):
        raise InvarianceError("canonical build requires the two named journal inputs")
    if Path(repeat_path).name != REPEAT_BASENAME:
        raise InvarianceError("canonical build requires v2321-level-repeat.jsonl")
    if Path(level_sweep_path).name != SWEEP_BASENAME:
        raise InvarianceError("canonical build requires v2321-level-sweep.jsonl")

    parsed_by_condition: dict[str, list[dict]] = {}
    contexts: dict[str, Mapping[str, object]] = {}
    known_metadata: dict[str, Mapping[str, object]] = {}
    for name in sorted(condition_paths):
        parsed = [parse_probe_file(path) for path in sorted(condition_paths[name], key=lambda item: str(item))]
        if not parsed:
            raise InvarianceError(f"condition {name!r} has no parsed transcripts")
        identities = {_identity(entry["context"]) for entry in parsed}
        if len(identities) != 1:
            raise InvarianceError(f"condition {name!r} transcripts have mismatched contexts")
        contexts[name] = parsed[0]["context"]
        parsed_by_condition[name] = parsed
        for path, entry in zip(
            sorted(condition_paths[name], key=lambda item: str(item)), parsed
        ):
            known_metadata[_path_identity(path)] = entry["artifact"]
    all_contexts = {_identity(value) for value in contexts.values()}
    if len(all_contexts) != 1:
        raise InvarianceError("canonical condition contexts are not identical")
    repeat = parse_level_repeat(Path(repeat_path), enforce_scope=True)
    sweep = parse_level_sweep(Path(level_sweep_path), enforce_scope=True)
    condition_acquisition = _common_acquisition_context(parsed_by_condition)
    _validate_auxiliary_context_binding(
        contexts["v2321-L7980"],
        repeat,
        sweep,
        main_records={
            "ion_heap": parsed_by_condition["v2321-L7980"][0]["ion_heap"],
            "pa_provenance": parsed_by_condition["v2321-L7980"][0]["pa_provenance"],
        },
    )
    all_acquisition_inputs = dict(parsed_by_condition)
    all_acquisition_inputs["level-repeat"] = [
        group["parsed"] for group in repeat["groups"]
    ]
    all_acquisition_inputs["level-sweep"] = [
        group["parsed"] for group in sweep["groups"]
    ]
    acquisition_context = _common_acquisition_context(all_acquisition_inputs)
    if acquisition_context["ion_heap"] != condition_acquisition["ion_heap"] or acquisition_context["pa_provenance"] != condition_acquisition["pa_provenance"]:
        raise InvarianceError("auxiliary acquisition contexts differ from condition context")
    repeat_metadata = repeat["artifact"]
    sweep_metadata = sweep["artifact"]
    journal_metadata = [
        _artifact_metadata(path, "journal input")
        for path in sorted(journal_paths, key=lambda item: item.name)
    ]
    known_metadata[_path_identity(Path(repeat_path))] = repeat_metadata
    known_metadata[_path_identity(Path(level_sweep_path))] = sweep_metadata
    for path, item in zip(
        sorted(journal_paths, key=lambda item: item.name), journal_metadata
    ):
        known_metadata[_path_identity(path)] = item
    extras = [Path(repeat_path), Path(level_sweep_path), *journal_paths]
    input_metadata = _validate_input_identity(
        condition_paths,
        extras,
        pins=CANONICAL_ARTIFACT_PINS,
        known_metadata=known_metadata,
    )
    pass_maps = {
        name: [entry["medians"] for entry in entries]
        for name, entries in parsed_by_condition.items()
    }
    analysis = analyse(
        pass_maps,
        baseline,
        expected_difference_count=EXPECTED_DIFFERENCE_COUNT,
        contexts=contexts,
        input_metadata=input_metadata,
    )
    repeat_summary = bind_repeat_evidence(
        repeat,
        next(condition for condition in analysis["conditions"] if condition["name"] == "v2321-L7980"),
    )
    repeat_summary["primary_comparison_coverage"] = validate_repeat_coverage(
        analysis["comparison"], repeat_summary
    )
    repeat_summary["acquisition_scope"] = _auxiliary_acquisition_scope(
        repeat, contexts["v2321-L7980"], "repeat"
    )
    sweep_summary = summarize_level_sweep(sweep)
    sweep_summary["acquisition_scope"] = _auxiliary_acquisition_scope(
        sweep, contexts["v2321-L7980"], "sweep"
    )
    dependencies = _validate_source_dependencies(
        probe_source_path=probe_source_path,
        dependency_manifest_path=dependency_manifest_path,
    )
    manifest = _public_manifest(
        analysis=analysis,
        input_metadata=input_metadata,
        repeat_metadata=repeat_metadata,
        sweep_metadata=sweep_metadata,
        journal_metadata=journal_metadata,
        repeat_summary=repeat_summary,
        sweep_summary=sweep_summary,
        dependencies=dependencies,
        acquisition_context=acquisition_context,
    )
    # Keep the public output free of accidental absolute paths even if a future
    # edit adds a field to one of the metadata objects.
    _assert_public_safety(manifest)
    return manifest


def encode_manifest(manifest: Mapping[str, object]) -> bytes:
    """Encode a manifest deterministically with one trailing newline."""

    return (
        json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def write_manifest(path: Path, manifest: Mapping[str, object], *, force: bool = False) -> dict:
    """Atomically publish a fresh 0644 file and never clobber an existing path.

    ``force`` is retained as a compatibility keyword but deliberately cannot
    enable replacement: this evidence path is no-clobber by contract.
    """

    del force
    path = Path(path)
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InvarianceError(f"cannot create manifest parent: {exc}") from exc
    if os.path.lexists(path):
        raise InvarianceError(f"refusing to clobber existing output {path.name!r}")
    data = encode_manifest(manifest)
    fd = -1
    temporary: Path | None = None
    expected_stat: os.stat_result | None = None
    published = False
    completed = False

    def same_identity(left: os.stat_result, right: os.stat_result) -> bool:
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
        )

    def same_file(left: os.stat_result, right: os.stat_result) -> bool:
        return same_identity(left, right) and left.st_size == right.st_size

    def read_fd(descriptor: int) -> bytes:
        chunks: list[bytes] = []
        offset = 0
        while offset < len(data):
            chunk = os.pread(descriptor, len(data) - offset, offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks)

    def unlink_owned_output() -> None:
        if not published or expected_stat is None:
            return
        try:
            current = os.lstat(path)
        except FileNotFoundError:
            return
        if same_identity(current, expected_stat):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def unlink_owned_temporary() -> None:
        if temporary is None or expected_stat is None:
            return
        try:
            current = os.lstat(temporary)
        except FileNotFoundError:
            return
        # A temp-path substitution may have installed another inode.  Never
        # unlink that replacement merely because our name points to it.
        if same_identity(current, expected_stat):
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=str(parent)
        )
        temporary = Path(temporary_name)
        os.fchmod(fd, 0o644)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise InvarianceError("manifest write made no progress")
            view = view[written:]
        os.fsync(fd)
        expected_stat = os.fstat(fd)
        # link() publishes the fully written inode without replacing an
        # output created by a racing process.  A symlink at the target fails.
        os.link(temporary, path, follow_symlinks=False)
        published = True
        output_stat = os.lstat(path)
        if not same_file(output_stat, expected_stat):
            unlink_owned_output()
            raise InvarianceError(
                "atomic publication race: output inode differs from the open temp inode"
            )
        if output_stat.st_mode & 0o777 != 0o644:
            unlink_owned_output()
            raise InvarianceError("fresh manifest mode is not 0644")
        expected_digest = hashlib.sha256(data).hexdigest()
        if read_fd(fd) != data:
            unlink_owned_output()
            raise InvarianceError("atomic publication source bytes changed before publish")
        output_fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            output_open_stat = os.fstat(output_fd)
            output_data = b""
            while len(output_data) < len(data):
                chunk = os.read(output_fd, len(data) - len(output_data))
                if not chunk:
                    break
                output_data += chunk
        finally:
            os.close(output_fd)
        if (
            not same_file(output_open_stat, expected_stat)
            or output_data != data
            or hashlib.sha256(output_data).hexdigest() != expected_digest
        ):
            unlink_owned_output()
            raise InvarianceError("atomic publication output bytes or inode changed")
        unlink_owned_temporary()
        temporary = None
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        # Re-open the published path after the directory durability barrier.
        # A same-size in-place mutation can preserve the inode and size, so
        # verify a fresh descriptor's bytes (twice) as well as its identity.
        final_fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            final_open_stat = os.fstat(final_fd)
            final_data = read_fd(final_fd)
            final_data_again = read_fd(final_fd)
            final_after_stat = os.fstat(final_fd)
        finally:
            os.close(final_fd)
        final_stat = os.lstat(path)
        if (
            not same_file(final_open_stat, expected_stat)
            or not same_file(final_after_stat, expected_stat)
            or not same_file(final_stat, expected_stat)
            or final_data != data
            or final_data_again != data
            or hashlib.sha256(final_data).hexdigest() != expected_digest
        ):
            unlink_owned_output()
            raise InvarianceError("atomic publication output changed after durability verification")
        mode = stat.S_IMODE(final_stat.st_mode)
        if mode != 0o644:
            unlink_owned_output()
            raise InvarianceError(f"fresh manifest mode is {mode:04o}, expected 0644")
        completed = True
        return {
            "requested_mode": "0644",
            "observed_mode": f"{mode:04o}",
            "size_bytes": len(data),
        }
    except FileExistsError as exc:
        raise InvarianceError(f"refusing to clobber existing output {path.name!r}") from exc
    except OSError as exc:
        raise InvarianceError(f"atomic manifest publication failed: {exc}") from exc
    finally:
        if fd >= 0:
            unlink_owned_temporary()
            if published and not completed:
                # If any post-link check raised, remove only our inode.  A
                # temp-path substitution or output race is left untouched.
                unlink_owned_output()
            os.close(fd)


def _generic_manifest(
    condition_paths: Mapping[str, Sequence[Path]], baseline: str
) -> dict:
    """Produce a safe analysis-only result for noncanonical CLI experiments."""

    _validate_identifier(baseline, "baseline")
    parsed: dict[str, list[dict]] = {}
    contexts: dict[str, Mapping[str, object]] = {}
    known_metadata: dict[str, Mapping[str, object]] = {}
    for name in sorted(condition_paths):
        _validate_identifier(name, "condition name")
        sorted_paths = sorted(condition_paths[name], key=lambda item: str(item))
        entries = [parse_probe_file(path) for path in sorted_paths]
        identities = {_identity(entry["context"]) for entry in entries}
        if len(identities) != 1:
            raise InvarianceError(f"condition {name!r} transcripts have mismatched contexts")
        parsed[name] = entries
        contexts[name] = entries[0]["context"]
        for path, entry in zip(sorted_paths, entries):
            known_metadata[_path_identity(path)] = entry["artifact"]
    input_metadata = _validate_input_identity(
        condition_paths, known_metadata=known_metadata
    )
    analysis = analyse(
        {name: [entry["medians"] for entry in entries] for name, entries in parsed.items()},
        baseline,
        contexts=contexts,
        input_metadata=input_metadata,
    )
    result = {
        "schema": ANALYSIS_ONLY_SCHEMA,
        "experiment_id": "verification-015-runtime-invariance-analysis-only",
        "mode": "HOST_ONLY_READ_ONLY_ANALYSIS",
        "eligibility": "NOT_ELIGIBLE",
        "conditions": analysis["conditions"],
        "comparison": analysis["comparison"],
        "inputs": {"conditions": input_metadata},
        "public_private_separation": {
            "private_absolute_paths_in_manifest": False,
            "raw_transcript_bytes_in_manifest": False,
            "input_paths_emitted": "BASENAMES_ONLY",
        },
        "publication": {
            "method": "ATOMIC_NO_CLOBBER_HARDLINK",
            "requested_mode": "0644",
            "mode_policy": "fchmod fresh inode to 0644, then lstat after publish; write result records observed mode",
        },
    }
    _assert_public_safety(result)
    return result


def _print_summary(manifest: Mapping[str, object]) -> None:
    for condition in manifest["conditions"]:
        split = condition["separation"]
        print(
            f"{condition['name']:<25} {condition['difference_count']:>3} diffs  "
            f"threshold={split['threshold']:>5}  "
            f"band {split['band_low']}..{split['band_high']} "
            f"(gap {split['gap']}, runner-up {split['runner_up_gap']})  "
            f"CONFLICT={condition['conflict_count']}"
        )
    comparison = manifest["comparison"]
    print()
    for entry in comparison["comparisons"]:
        print(
            f"{comparison['baseline']} vs {entry['condition']}: "
            f"{entry['shared_differences']} shared, "
            f"{len(entry['disagreements'])} disagreements -> {entry['status']}"
        )
    print(f"\nall_invariant: {comparison['all_invariant']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--condition",
        action="append",
        required=True,
        metavar="NAME=GLOB",
        help="one separately retained condition and its transcript glob",
    )
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help="allow a noncanonical condition set with a distinct analysis-only manifest",
    )
    parser.add_argument("--repeat", type=Path)
    parser.add_argument(
        "--level-sweep",
        "--sweep",
        dest="level_sweep",
        type=Path,
    )
    parser.add_argument("--journal", action="append", type=Path)
    parser.add_argument(
        "--dependency",
        "--dependency-manifest",
        dest="dependency",
        type=Path,
    )
    parser.add_argument(
        "--probe-source",
        "--probe",
        dest="probe_source",
        type=Path,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        condition_paths: dict[str, list[Path]] = {}
        for argument in args.condition:
            name, paths = _parse_condition(argument)
            if name in condition_paths:
                raise InvarianceError(f"duplicate condition name {name!r}")
            condition_paths[name] = paths
        canonical_names = set(CANONICAL_CONDITION_BASENAMES)
        if set(condition_paths) == canonical_names:
            manifest = build_manifest(
                condition_paths,
                repeat_path=args.repeat,
                level_sweep_path=args.level_sweep,
                journal_paths=args.journal,
                baseline=args.baseline,
                dependency_manifest_path=args.dependency,
                probe_source_path=args.probe_source,
            )
        elif not args.analysis_only:
            raise InvarianceError(
                "canonical Verification-015 requires all six exact condition names; "
                "pass --analysis-only for a distinct noncanonical analysis"
            )
        else:
            manifest = _generic_manifest(condition_paths, args.baseline)
        publication = write_manifest(args.output, manifest)
        _print_summary(manifest)
        print(
            f"wrote {args.output} ({publication['size_bytes']} bytes, "
            f"mode {publication['observed_mode']})"
        )
        return 0
    except InvarianceError as exc:
        print(f"verification-015: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
