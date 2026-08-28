#!/usr/bin/env python3
"""Bounded, source-pinned audit of the Route-2 static evidence line.

This is a host-only metadata and semantic audit.  It does not re-run a device
experiment and does not turn bounded static no-target rows into global writer
absence.  Its Q4 result intentionally remains UNKNOWN because the 029--034
public manifests do not carry a complete rank-relation row set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
from collections.abc import Mapping, Sequence

SCHEMA = "a90-route2-rank-audit-v1"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

MANIFEST_PINS: dict[str, dict[str, object]] = {
    "baseline_027": {
        "basename": "027-dcb-consumer-writer-complement-20260826-01.manifest.json",
        "size_bytes": 334847,
        "sha256": "d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277",
    },
    "frontier_029": {
        "basename": "029-dcb-unsupported-frontier-20260826-01.manifest.json",
        "size_bytes": 628525,
        "sha256": "c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634",
    },
    "low_bit_030": {
        "basename": "030-low-bit-selector-20260826-01.manifest.json",
        "size_bytes": 25831,
        "sha256": "28f167a67a8d32c56a227e01f93ea243ff9bb2eb1ba4bb1007524b9c71b0a73f",
    },
    "frontier_031": {
        "basename": "031-dcb-scalar-frontier-extension-20260826-01.manifest.json",
        "size_bytes": 1327118,
        "sha256": "51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86",
    },
    "frontier_032": {
        "basename": "032-dcb-arithmetic-frontier-20260826-01.manifest.json",
        "size_bytes": 1564295,
        "sha256": "beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31",
    },
    "frontier_033": {
        "basename": "033-dcb-residual-memory-frontier-20260826-01.manifest.json",
        "size_bytes": 2017356,
        "sha256": "606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598",
    },
    "frontier_034": {
        "basename": "034-dcb-site35-jump-table-20260826-01.manifest.json",
        "size_bytes": 2241492,
        "sha256": "75728982e1622f3e807c367baff5cc87d18cff94fa2a9135699f3f836b804b92",
    },
    "relation_023r": {
        "basename": "023R-repaired-region-bank-relation-20260826-01.manifest.json",
        "size_bytes": 18040,
        "sha256": "5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e",
    },
    "high_bit_016": {
        "basename": "verification-016-high-bit-relation-20260827-01.manifest.json",
        "size_bytes": 59504,
        "sha256": "72525cf994e52bbee1c3ed685c49a6ace4049cd7b279cb97811f6a0d3f4f773f",
    },
}


class Route2AuditError(RuntimeError):
    """Raised when an exact pinned input or bounded invariant fails."""


def _read_pinned(path: pathlib.Path, pin: Mapping[str, object], label: str) -> bytes:
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError as exc:
        raise Route2AuditError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != pin["size_bytes"]:
            raise Route2AuditError(f"{label} size/type differs from the pinned input")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise Route2AuditError(f"{label} was truncated while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or not stat.S_ISREG(after.st_mode)
    ):
        raise Route2AuditError(f"{label} changed while being read")
    payload = b"".join(chunks)
    if hashlib.sha256(payload).hexdigest() != pin["sha256"]:
        raise Route2AuditError(f"{label} SHA-256 differs from the pinned input")
    return payload


def _decode_json_object(data: bytes, label: str) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise Route2AuditError(f"{label} contains duplicate JSON key: {key}")
            out[key] = value
        return out

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except Route2AuditError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Route2AuditError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise Route2AuditError(f"{label} is not a JSON object")
    return value


def load_inputs() -> dict[str, dict[str, object]]:
    documents: dict[str, dict[str, object]] = {}
    for key, pin in MANIFEST_PINS.items():
        path = REPO_ROOT / "evidence/manifests" / str(pin["basename"])
        documents[key] = _decode_json_object(_read_pinned(path, pin, key), key)
    return documents


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Route2AuditError(message)


def _classification(document: Mapping[str, object], key: str) -> None:
    _require(document.get("classification") == "CLASS C (TRANSFORM ONLY)", f"{key} changed classification")
    _require(isinstance(document.get("claims"), Mapping), f"{key} has no claim map")


def _unknown_preserves_global_writer(document: Mapping[str, object], key: str) -> None:
    claims = document["claims"]
    assert isinstance(claims, Mapping)
    unknown = " ".join(str(item) for item in claims.get("UNKNOWN", []))
    _require("writer" in unknown.lower() and "global" in unknown.lower(), f"{key} lost global writer UNKNOWN")
    proved = " ".join(str(item) for item in claims.get("PROVED", []))
    _require("global writer absence" not in proved.lower(), f"{key} promoted global writer absence")


def _site_key(row: Mapping[str, object], key: str) -> tuple[object, ...]:
    index = row.get("site_index")
    region = row.get("range")
    store = row.get("store_va")
    _require(isinstance(index, int) and not isinstance(index, bool), f"{key} site index is malformed")
    _require(isinstance(region, Mapping), f"{key} site range is missing")
    start, end = region.get("start"), region.get("end_exclusive")
    _require(isinstance(start, str) and isinstance(end, str), f"{key} site range is malformed")
    _require(isinstance(store, str), f"{key} store address is malformed")
    return index, start, end, store


_MODEL_DISCRIMINATORS = (
    "INDIRECT_OR_UNSUPPORTED",
    "NO_TARGET_WITHIN_MODEL",
)
_QUADRANT_KEYS = tuple(
    f"{source}_TO_{target}"
    for source in _MODEL_DISCRIMINATORS
    for target in _MODEL_DISCRIMINATORS
)


def _site_rows(document: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    rows = document.get("sites")
    _require(isinstance(rows, list) and len(rows) == 71, f"{key} site rows are incomplete")
    typed_rows: list[Mapping[str, object]] = []
    keys: list[tuple[object, ...]] = []
    for row in rows:
        _require(isinstance(row, Mapping), f"{key} site row is malformed")
        typed_rows.append(row)
        keys.append(_site_key(row, key))
    _require(
        [item[0] for item in keys] == list(range(71)),
        f"{key} site identity is not sequential",
    )
    return typed_rows


def _discriminator(value: object, key: str) -> str:
    _require(
        isinstance(value, list) and value and all(isinstance(item, str) for item in value),
        f"{key} discriminator is malformed",
    )
    # The 027 baseline occasionally carries the auxiliary section-reader label
    # alongside the model's indirect blocker.  The bounded transition strings
    # canonicalize that pair to INDIRECT_OR_UNSUPPORTED; preserve that exact
    # interpretation while rejecting every other multi-label combination.
    if "INDIRECT_OR_UNSUPPORTED" in value:
        _require(
            set(value) <= {"INDIRECT_OR_UNSUPPORTED", "SECTION_READER_PROXIMITY_ONLY"},
            f"{key} discriminator has an unexpected auxiliary label",
        )
        return "INDIRECT_OR_UNSUPPORTED"
    _require(len(value) == 1, f"{key} discriminator is not a single model label")
    label = value[0]
    _require(label in _MODEL_DISCRIMINATORS, f"{key} discriminator is outside the model")
    return label


def _row_discriminator(row: Mapping[str, object], key: str) -> str:
    return _discriminator(row.get("discriminators"), f"{key} row")


def _validated_row_transitions(
    rows: Sequence[Mapping[str, object]],
    prior: str,
    current: str,
    key: str,
    transition_target_model: str | None = None,
) -> tuple[list[str], list[str]]:
    """Return source/current labels after checking each row's declared transition."""
    source_labels: list[str] = []
    target_labels: list[str] = []
    for index, row in enumerate(rows):
        delta = row.get(f"delta_vs_{prior}")
        _require(isinstance(delta, Mapping), f"{key} row {index} delta_vs_{prior} is missing")
        source = _discriminator(
            delta.get("baseline_discriminators"),
            f"{key} row {index} delta_vs_{prior} baseline",
        )
        target = _row_discriminator(row, f"{key} row {index}")
        target_model = current if transition_target_model is None else transition_target_model
        transition = f"{prior}_{source}_TO_{target_model}_{target}"
        _require(
            delta.get("transition") == transition,
            f"{key} row {index} delta_vs_{prior} transition label disagrees with row labels",
        )
        transition_model = transition_target_model or current
        transition_suffix = {"031": "v2", "032": "v3", "033": "v4"}.get(transition_model)
        _require(transition_suffix is not None, f"{key} row {index} has unknown transition model")
        transition_flag_name = f"transitioned_to_no_target_within_{transition_suffix}_model"
        _require(
            type(delta.get(transition_flag_name)) is bool,
            f"{key} row {index} delta_vs_{prior} transition flag is malformed",
        )
        _require(
            delta[transition_flag_name] == (source == "INDIRECT_OR_UNSUPPORTED" and target == "NO_TARGET_WITHIN_MODEL"),
            f"{key} row {index} delta_vs_{prior} transition flag disagrees with labels",
        )
        _require(
            type(delta.get("was_fail_closed")) is bool
            and delta.get("was_fail_closed") is (source == "INDIRECT_OR_UNSUPPORTED"),
            f"{key} row {index} delta_vs_{prior} source fail-closed flag disagrees with labels",
        )
        _require(
            type(delta.get("is_fail_closed")) is bool
            and delta.get("is_fail_closed") is (target == "INDIRECT_OR_UNSUPPORTED"),
            f"{key} row {index} delta_vs_{prior} target fail-closed flag disagrees with labels",
        )
        source_labels.append(source)
        target_labels.append(target)
    return source_labels, target_labels


def _quadrant_keys(source: str, target: str) -> tuple[str, ...]:
    return tuple(
        f"{source}_{source_label}_TO_{target}_{target_label}"
        for source_label in _MODEL_DISCRIMINATORS
        for target_label in _MODEL_DISCRIMINATORS
    )


def _strict_count_map(
    value: object, key: str, source: str = "", target: str = ""
) -> dict[str, int]:
    _require(isinstance(value, Mapping), f"{key} quadrant counts are missing")
    expected_keys = _quadrant_keys(source, target) if source and target else _QUADRANT_KEYS
    _require(set(value) == set(expected_keys), f"{key} quadrant keys changed")
    normalized: dict[str, int] = {}
    for name in expected_keys:
        count = value.get(name)
        _require(
            type(count) is int and 0 <= count <= 71,
            f"{key} quadrant count is outside the site-count bound",
        )
        normalized[name] = count
    return normalized


def _recompute_quadrants(
    source_labels: Sequence[str],
    target_labels: Sequence[str],
    source_model: str,
    target_model: str,
    key: str,
) -> dict[str, int]:
    _require(len(source_labels) == len(target_labels) == 71, f"{key} quadrant rows are incomplete")
    counts = {name: 0 for name in _quadrant_keys(source_model, target_model)}
    for index, (source_label, target_label) in enumerate(zip(source_labels, target_labels)):
        _require(source_label in _MODEL_DISCRIMINATORS, f"{key} source label {index} is outside the model")
        _require(target_label in _MODEL_DISCRIMINATORS, f"{key} target label {index} is outside the model")
        counts[f"{source_model}_{source_label}_TO_{target_model}_{target_label}"] += 1
    return counts


def _transition_label_counts(
    source_labels: Sequence[str], target_labels: Sequence[str], key: str
) -> dict[str, int]:
    _require(len(source_labels) == len(target_labels) == 71, f"{key} transition rows are incomplete")
    for index, (source, target) in enumerate(zip(source_labels, target_labels)):
        _require(source in _MODEL_DISCRIMINATORS, f"{key} source label {index} is outside the model")
        _require(target in _MODEL_DISCRIMINATORS, f"{key} target label {index} is outside the model")
    return {
        "baseline_fail_closed_sites": sum(source == "INDIRECT_OR_UNSUPPORTED" for source in source_labels),
        "sites_remaining_fail_closed": sum(target == "INDIRECT_OR_UNSUPPORTED" for target in target_labels),
        "sites_transitioned_to_no_target": sum(
            source == "INDIRECT_OR_UNSUPPORTED" and target == "NO_TARGET_WITHIN_MODEL"
            for source, target in zip(source_labels, target_labels)
        ),
        "regression_count": sum(
            source == "NO_TARGET_WITHIN_MODEL" and target == "INDIRECT_OR_UNSUPPORTED"
            for source, target in zip(source_labels, target_labels)
        ),
    }


def _validate_quadrants(
    document: Mapping[str, object],
    map_name: str,
    source_labels: Sequence[str],
    target_labels: Sequence[str],
    source: str,
    target: str,
    key: str,
    expected_optional: bool = False,
) -> None:
    analysis = document.get("analysis")
    _require(isinstance(analysis, Mapping), f"{key} analysis is missing")
    transition = analysis.get(map_name)
    _require(isinstance(transition, Mapping), f"{key} {map_name} is missing")
    _require(
        transition.get("identity_check") is True and transition.get("regression_free") is True,
        f"{key} {map_name} identity/regression check failed",
    )
    _require(
        type(transition.get("regression_count")) is int
        and transition.get("regression_count") == 0,
        f"{key} {map_name} regression count is non-zero",
    )
    recomputed = _recompute_quadrants(
        source_labels,
        target_labels,
        source,
        target,
        f"{key} {map_name}",
    )
    declared = _strict_count_map(
        transition.get("counts"), f"{key} {map_name} declared", source, target
    )
    _require(declared == recomputed, f"{key} {map_name} counts disagree with site labels")
    expected_value = transition.get("expected_counts")
    if expected_value is None and expected_optional:
        return
    expected = _strict_count_map(
        expected_value, f"{key} {map_name} expected", source, target
    )
    _require(expected == recomputed, f"{key} {map_name} expected counts disagree with site labels")


def _final_034_labels(rows: Sequence[Mapping[str, object]], key: str) -> list[str]:
    """Reconstruct the combined 034 target labels from its bounded site-35 proof."""
    _require(len(rows) == 71, f"{key} rows are incomplete")
    # The top-level 034 rows are deliberately verbatim 033 records.  The
    # combined outcome is therefore the target label source; site 35 is the
    # only row whose published baseline label is not already the final label.
    target = []
    for index, row in enumerate(rows):
        label = _row_discriminator(row, f"{key} row {index}")
        if index != 35:
            _require(label == "NO_TARGET_WITHIN_MODEL", f"{key} non-site35 row changed from 033 baseline")
        else:
            _require(label == "INDIRECT_OR_UNSUPPORTED", f"{key} site35 inherited label changed")
        target.append("NO_TARGET_WITHIN_MODEL")
    return target


def _audit_q1(documents: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    baseline = documents["baseline_027"]
    _classification(baseline, "027")
    summary = baseline.get("site_summary")
    _require(isinstance(summary, Mapping), "027 site_summary is missing")
    _require(summary.get("site_count") == 73, "027 site count changed")
    _require(summary.get("discriminator_counts") == {
        "INDIRECT_OR_UNSUPPORTED": 71,
        "NO_TARGET_WITHIN_MODEL": 2,
        "SECTION_READER_PROXIMITY_ONLY": 2,
    }, "027 discriminator counts changed")
    _require(summary.get("writer_absence") == "UNKNOWN" and summary.get("writer_absence_claim") is False,
             "027 writer boundary changed")
    _unknown_preserves_global_writer(baseline, "027")

    frontier_keys = ("frontier_031", "frontier_032", "frontier_033", "frontier_034")
    expected_counts = {
        "frontier_031": (51, 20),
        "frontier_032": (55, 16),
        "frontier_033": (70, 1),
        "frontier_034": (71, 0),
    }
    expected_fail_closed = {
        "027": 71,
        "031": 20,
        "032": 16,
        "033": 1,
    }
    site_sets: dict[str, list[tuple[object, ...]]] = {}
    site_rows: dict[str, list[Mapping[str, object]]] = {}
    transition_checks: dict[str, dict[str, object]] = {}
    summaries: list[dict[str, object]] = []
    for key in frontier_keys:
        document = documents[key]
        _classification(document, key)
        _unknown_preserves_global_writer(document, key)
        analysis = document.get("analysis")
        _require(isinstance(analysis, Mapping), f"{key} analysis is missing")
        _require(analysis.get("site_count") == 71, f"{key} site count changed")
        actual_deltas = {
            name: value
            for name, value in analysis.items()
            if name.startswith("actual_delta_vs_")
        }
        _require(actual_deltas, f"{key} transition delta is missing")
        no_target, indirect = expected_counts[key]
        for delta_name, delta in actual_deltas.items():
            _require(isinstance(delta, Mapping), f"{key} {delta_name} is malformed")
            _require(delta.get("transition_identity") is True, f"{key} {delta_name} identity failed")
            transitioned_values = [
                value for name, value in delta.items()
                if name.startswith("sites_transitioned_to_no_target_within_")
            ]
            _require(len(transitioned_values) == 1 and isinstance(transitioned_values[0], int),
                     f"{key} {delta_name} transition count is missing")
            transitioned = transitioned_values[0]
            _require(not isinstance(transitioned, bool), f"{key} {delta_name} transition count is malformed")
            remaining = delta.get("sites_remaining_fail_closed", delta.get("current_fail_closed_sites"))
            _require(isinstance(remaining, int) and not isinstance(remaining, bool),
                     f"{key} {delta_name} remaining count is missing")
            source_name = delta_name.removeprefix("actual_delta_vs_")
            _require(source_name in expected_fail_closed, f"{key} {delta_name} has an unknown predecessor")
            expected_source = expected_fail_closed[source_name]
            expected_remaining = indirect
            expected_transitioned = expected_source - expected_remaining
            _require(
                type(delta.get("baseline_fail_closed_sites")) is int
                and delta.get("baseline_fail_closed_sites") == expected_source,
                f"{key} {delta_name} baseline count disagrees with predecessor labels",
            )
            _require(0 <= transitioned <= expected_source, f"{key} {delta_name} transition count is out of bounds")
            _require(0 <= remaining <= expected_source, f"{key} {delta_name} remaining count is out of bounds")
            _require(
                delta.get("baseline_fail_closed_sites") == remaining + transitioned,
                f"{key} {delta_name} site transition counts do not balance",
            )
            if "current_fail_closed_sites" in delta:
                _require(
                    type(delta["current_fail_closed_sites"]) is int
                    and delta["current_fail_closed_sites"] == remaining,
                    f"{key} {delta_name} current fail-closed count disagrees with remaining count",
                )
            _require(
                transitioned == expected_transitioned and remaining == expected_remaining,
                f"{key} {delta_name} counts disagree with declared Q1 transition/remaining labels",
            )
            for field, value in delta.items():
                if field.endswith("_fail_closed_sites") and field not in {
                    "baseline_fail_closed_sites",
                    "sites_remaining_fail_closed",
                    "current_fail_closed_sites",
                }:
                    _require(
                        type(value) is int and value == expected_remaining,
                        f"{key} {delta_name} {field} disagrees with current labels",
                    )
            if "regression_count" in delta:
                _require(delta.get("regression_count") == 0, f"{key} {delta_name} reports a regression")
        transition_checks[key] = {
            "actual_delta_transition_identity": {
                name: True for name in sorted(actual_deltas)
            },
            "actual_delta_count_balance": {
                name: True for name in sorted(actual_deltas)
            },
        }
        counts = analysis.get("discriminator_counts")
        _require(isinstance(counts, Mapping), f"{key} discriminator map is missing")
        no_target, indirect = expected_counts[key]
        _require(counts.get("DCB_CONSUMER_PATH") == 0, f"{key} promoted a DCB consumer path")
        _require(counts.get("MC_OR_SHRM_SYMBOLIC_TARGET") == 0, f"{key} promoted an MC/SHRM path")
        _require(counts.get("NO_TARGET_WITHIN_MODEL") == no_target, f"{key} no-target count changed")
        _require(counts.get("INDIRECT_OR_UNSUPPORTED") == indirect, f"{key} indirect count changed")
        _require(analysis.get("dcb_consumer_paths") == [], f"{key} DCB path list is non-empty")
        _require(analysis.get("mc_or_shrm_target_paths") == [], f"{key} MC/SHRM path list is non-empty")
        _require(analysis.get("writer_absence") == "UNKNOWN" and analysis.get("writer_absence_claim") is False,
                 f"{key} writer boundary changed")
        rows = _site_rows(document, key)
        keys = [_site_key(row, key) for row in rows]
        site_rows[key] = rows
        site_sets[key] = keys
        summaries.append({
            "manifest": MANIFEST_PINS[key]["basename"],
            "site_count": 71,
            "no_target_within_model": no_target,
            "indirect_or_unsupported": indirect,
            "dcb_consumer_paths": 0,
            "mc_or_shrm_symbolic_target": 0,
        })

    # Validate each actual delta's row-level predecessor/current labels before
    # the aggregate counts are accepted.  034 deliberately retains 033 labels
    # in its inherited rows, hence the explicit target-model alias.
    row_transition_checks: dict[str, bool] = {}
    row_aggregate_checks: dict[str, bool] = {}
    for key, current, alias in (
        ("frontier_031", "031", None),
        ("frontier_032", "032", None),
        ("frontier_033", "033", None),
        ("frontier_034", "033", "033"),
    ):
        _validated_row_transitions(
            site_rows[key], "027", current, key, transition_target_model=alias
        )
        row_transition_checks[f"{key}/delta_vs_027"] = True

    # Independently re-count each actual_delta from those row labels.  This
    # prevents a coherent mutation of one row plus its transition metadata from
    # hiding behind unchanged aggregate counts.  The final 034 projection is
    # intentionally used for all 034 actual deltas; its inherited rows retain
    # the pre-site-35 labels needed only for the transition-string checks.
    for key, current, alias in (
        ("frontier_031", "031", None),
        ("frontier_032", "032", None),
        ("frontier_033", "033", None),
        ("frontier_034", "033", "033"),
    ):
        document = documents[key]
        analysis = document["analysis"]
        assert isinstance(analysis, Mapping)
        rows = site_rows[key]
        final_target = _final_034_labels(rows, key) if key == "frontier_034" else None
        for delta_name, delta in analysis.items():
            if not delta_name.startswith("actual_delta_vs_"):
                continue
            prior = delta_name.removeprefix("actual_delta_vs_")
            if key == "frontier_034" and prior == "033":
                source_labels = [
                    _row_discriminator(row, f"frontier_033 row {index}")
                    for index, row in enumerate(site_rows["frontier_033"])
                ]
            else:
                source_labels, inherited_target = _validated_row_transitions(
                    rows,
                    prior,
                    current,
                    key,
                    transition_target_model=alias,
                )
                if final_target is None:
                    target_labels = inherited_target
            if final_target is not None:
                target_labels = final_target
            observed = _transition_label_counts(source_labels, target_labels, f"{key} {delta_name}")
            transitioned_field = next(
                name for name in delta if name.startswith("sites_transitioned_to_no_target_within_")
            )
            expected_observed = {
                "baseline_fail_closed_sites": observed["baseline_fail_closed_sites"],
                "sites_remaining_fail_closed": observed["sites_remaining_fail_closed"],
                transitioned_field: observed["sites_transitioned_to_no_target"],
            }
            _require(
                delta.get("baseline_fail_closed_sites") == expected_observed["baseline_fail_closed_sites"]
                and delta.get("sites_remaining_fail_closed") == expected_observed["sites_remaining_fail_closed"]
                and delta.get(transitioned_field) == expected_observed[transitioned_field],
                f"{key} {delta_name} aggregate counts disagree with row labels",
            )
            if "current_fail_closed_sites" in delta:
                _require(
                    delta.get("current_fail_closed_sites") == observed["sites_remaining_fail_closed"],
                    f"{key} {delta_name} current count disagrees with row labels",
                )
            if "regression_count" in delta:
                _require(
                    delta.get("regression_count") == observed["regression_count"],
                    f"{key} {delta_name} regression count disagrees with row labels",
                )
            row_aggregate_checks[f"{key}/{delta_name}"] = True

    # Recompute every published quadrant map from row-level labels.  The 034
    # rows are carried forward from the 033 model, so their retained delta
    # strings use a 033 target prefix even though 034 publishes the composed
    # maps; that inherited prefix is checked explicitly below.  The separate
    # vs-033 map uses the final bounded site-35 resolution as its target.
    quadrant_checks: dict[str, bool] = {}
    source, target = _validated_row_transitions(
        site_rows["frontier_032"], "031", "032", "frontier_032"
    )
    _validate_quadrants(
        documents["frontier_032"],
        "transition_quadrants",
        source,
        target,
        "031",
        "032",
        "frontier_032",
    )
    quadrant_checks["frontier_032/transition_quadrants"] = True
    source, target = _validated_row_transitions(
        site_rows["frontier_033"], "032", "033", "frontier_033"
    )
    _validate_quadrants(
        documents["frontier_033"],
        "transition_quadrants",
        source,
        target,
        "032",
        "033",
        "frontier_033",
    )
    quadrant_checks["frontier_033/transition_quadrants"] = True
    source, _inherited_target = _validated_row_transitions(
        site_rows["frontier_034"],
        "032",
        "033",
        "frontier_034",
        transition_target_model="033",
    )
    target = _final_034_labels(site_rows["frontier_034"], "frontier_034")
    for map_name in ("transition_quadrants", "combined_transition_quadrants"):
        _validate_quadrants(
            documents["frontier_034"],
            map_name,
            source,
            target,
            "032",
            "034",
            "frontier_034",
        )
        quadrant_checks[f"frontier_034/{map_name}"] = True
    source = [
        _row_discriminator(row, f"frontier_033 row {index}")
        for index, row in enumerate(site_rows["frontier_033"])
    ]
    target = _final_034_labels(site_rows["frontier_034"], "frontier_034")
    _validate_quadrants(
        documents["frontier_034"],
        "transition_quadrants_vs_033",
        source,
        target,
        "033",
        "034",
        "frontier_034",
        expected_optional=True,
    )
    quadrant_checks["frontier_034/transition_quadrants_vs_033"] = True

    first = site_sets[frontier_keys[0]]
    stable = all(site_sets[key] == first for key in frontier_keys[1:])
    _require(stable, "029-derived site identity changed between 031 and 034")
    dependency_029 = documents["frontier_029"].get("dependency_027_semantics")
    _require(isinstance(dependency_029, Mapping), "029 dependency semantics are missing")
    _require(dependency_029.get("dcb_consumer_path") == 0 and dependency_029.get("mc_or_shrm_symbolic_target") == 0,
             "029 dependency promoted a target path")
    _require(dependency_029.get("writer_absence") == "UNKNOWN" and dependency_029.get("writer_absence_claim") is False,
             "029 dependency writer boundary changed")
    _unknown_preserves_global_writer(documents["frontier_029"], "029")
    return {
        "status": "SUPPORTED_BOUNDED_CLOSURE_UNKNOWN_GLOBAL",
        "baseline_027": {
            "site_count": 73,
            "discriminator_counts": summary["discriminator_counts"],
            "writer_absence": "UNKNOWN",
            "writer_absence_claim": False,
        },
        "extensions": summaries,
        "transition_checks": transition_checks,
        "row_transition_checks": row_transition_checks,
        "row_aggregate_checks": row_aggregate_checks,
        "quadrant_checks": quadrant_checks,
        "site_identity_stable_031_to_034": stable,
        "global_writer_or_consumer_absence": "UNKNOWN",
        "bounded_writer_route": "NO_PROMOTED_PATH_IN_DECLARED_MODELS",
    }


def _walk_rank_fields(value: object, path: str = "") -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}/{key}"
            lowered = str(key).lower()
            if lowered in {"relation", "relation_dependency", "relation_coordinate_scope", "relation_physical_attribution", "bank", "bank_relation", "rank"}:
                if lowered == "rank" and path.startswith("/decoder_extension_candidates"):
                    kind = "DECODER_ORDERING_METADATA"
                elif lowered == "relation_dependency":
                    kind = "INHERITED_RELATION_METADATA"
                else:
                    kind = "RANK_OR_RELATION_FIELD"
                found.append({"path": child_path, "kind": kind, "value_type": type(child).__name__})
            found.extend(_walk_rank_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_walk_rank_fields(child, f"{path}[{index}]"))
    return found


def _audit_q4(documents: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    relation = documents["relation_023r"]
    rank = relation.get("rank")
    kernel = relation.get("kernel")
    _require(isinstance(rank, Mapping) and rank.get("rank") == 3 and rank.get("resolved") is True,
             "023R rank-3 source is not resolved")
    _require(isinstance(kernel, Mapping) and kernel.get("unique") is True, "023R kernel is not unique")
    high = documents["high_bit_016"]
    _require(high.get("class_c") == "TRANSFORM ONLY", "V016 class changed")
    _require(high.get("coordinate_scope") == "ALLOCATION_OFFSET_MODEL_COORDINATES",
             "V016 coordinate scope changed")
    _require(high.get("matches") == {"PA25": [14, 21], "PA26": [19], "PA27": [13, 20]},
             "V016 high-bit matches changed")
    low = documents["low_bit_030"]
    dependency = low.get("relation_dependency")
    _require(isinstance(dependency, Mapping), "030 relation dependency is missing")
    _require(
        dependency.get("experiment_id") == "023R-repaired-region-bank-relation"
        and dependency.get("rank") == 3
        and dependency.get("contribution") == "0b110"
        and dependency.get("validated") is True
        and dependency.get("manifest") == MANIFEST_PINS["relation_023r"]["basename"]
        and dependency.get("sha256") == MANIFEST_PINS["relation_023r"]["sha256"]
        and dependency.get("coordinate_scope") == "allocation-offset/model coordinates"
        and dependency.get("physical_classification") == "SUPPORTED_WITHIN_MODEL",
        "030 relation dependency is not the pinned rank-3 inheritance",
    )
    fields: dict[str, list[dict[str, str]]] = {}
    for key in ("frontier_029", "low_bit_030", "frontier_031", "frontier_032", "frontier_033", "frontier_034"):
        fields[key] = _walk_rank_fields(documents[key])
    ordering_fields = [item for item in fields["frontier_029"] if item["kind"] == "DECODER_ORDERING_METADATA"]
    inherited = [item for item in fields["low_bit_030"] if item["kind"] == "INHERITED_RELATION_METADATA"]
    explicit_rows = sum(
        1 for key in ("frontier_029", "frontier_031", "frontier_032", "frontier_033", "frontier_034")
        if any(item["kind"] == "RANK_OR_RELATION_FIELD" for item in fields[key])
    )
    _require(len(ordering_fields) == 4, "029 decoder ranking metadata census changed")
    _require(len(inherited) == 1 and explicit_rows == 0, "unexpected explicit relation row appeared")
    return {
        "status": "UNKNOWN_NO_COMPLETE_029_034_RELATION_ROW_SET",
        "source_rank3": {"resolved": True, "unique": True, "rank": 3},
        "v016_matches": {"PA25": [14, 21], "PA26": [19], "PA27": [13, 20]},
        "030_inherited_relation": {
            "rank": 3,
            "contribution": "0b110",
            "validated": True,
            "physical_classification": "SUPPORTED_WITHIN_MODEL",
        },
        "rank_relation_field_inventory": fields,
        "decoder_ordering_metadata_count_029": len(ordering_fields),
        "inherited_relation_metadata_count_030": len(inherited),
        "explicit_relation_rows_in_029_031_034": explicit_rows,
        "contradiction_status": "UNKNOWN_NOT_AUDITED_FROM_COMPLETE_RAW_ROW_SET",
    }


def audit(documents: Mapping[str, Mapping[str, object]] | None = None) -> dict[str, object]:
    if documents is None:
        documents = load_inputs()
    for key, document in documents.items():
        _require(isinstance(document, Mapping), f"{key} is not a mapping")
    q1 = _audit_q1(documents)
    q4 = _audit_q4(documents)
    return {
        "schema": SCHEMA,
        "classification": "CLASS C (TRANSFORM ONLY)",
        "device_access": {
            "mode": "HOST_ONLY_READ_ONLY",
            "device_contact": False,
            "smc": False,
            "mmio": False,
            "writes": False,
        },
        "scope": {
            "q1": "BOUNDED_STATIC_MANIFEST_SEMANTICS",
            "q4": "DECLARED_RANK_RELATION_FIELDS_ONLY",
            "runtime_execution": "UNKNOWN",
            "global_writer_absence": "UNKNOWN",
            "physical_mapping": "UNKNOWN",
        },
        "inputs": {
            key: dict(pin) for key, pin in MANIFEST_PINS.items()
        },
        "q1_writer_route": q1,
        "q4_rank3_contradiction": q4,
        "claims": {
            "PROVED": [
                "all pinned 029-034 public manifests pass exact byte and JSON semantic validation",
                "027 and 031-034 bounded outputs contain zero promoted DCB consumer or MC/SHRM symbolic target paths",
                "031-034 preserve the same 71 site identities and regression-free transition checks",
                "030 inherits the exact validated rank-3 relation dependency from 023R",
                "029 rank fields are decoder-candidate ordering metadata rather than a bank-relation row set",
                "no explicit rank-relation rows occur in 029 or 031-034 declared fields",
            ],
            "SUPPORTED": [
                "bounded static evidence supports a no-promoted-writer-path disposition inside the declared models",
            ],
            "HYPOTHESIS": [],
            "UNKNOWN": [
                "global DCB consumer or transform-register writer presence/absence",
                "Q4 contradiction status until the complete 029-034 raw row set is independently audited",
                "runtime execution/order/current destination and indirect aliases",
                "physical DRAM coordinates, transform mutability and protected-memory reach",
            ],
            "REFUTED": [],
        },
        "reproduction": {
            "command": "python3 tools/a90_route2_rank_audit.py --output <manifest>",
            "no_device_action": True,
        },
    }


def encode_public(result: Mapping[str, object]) -> bytes:
    return (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def write_public(path: pathlib.Path, result: Mapping[str, object]) -> dict[str, object]:
    path = pathlib.Path(path)
    if not path.parent.is_dir():
        raise Route2AuditError(f"manifest parent does not exist: {path.parent}")
    payload = encode_public(result)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise Route2AuditError(f"manifest output already exists or is unsafe: {path}") from exc
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise Route2AuditError("manifest write made no progress")
            view = view[count:]
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    return {"basename": path.name, "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "mode": "0644"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = audit()
        publication = write_public(pathlib.Path(args.output), result)
    except (Route2AuditError, OSError) as exc:
        print(f"route2-audit: {exc}", file=__import__("sys").stderr)
        return 2
    print("Q1=SUPPORTED_BOUNDED_CLOSURE_UNKNOWN_GLOBAL")
    print("Q4=UNKNOWN_NO_COMPLETE_029_034_RELATION_ROW_SET")
    print(f"published {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
