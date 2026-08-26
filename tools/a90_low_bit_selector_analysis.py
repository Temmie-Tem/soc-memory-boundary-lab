#!/usr/bin/env python3
"""Experiment 030: can the reopen delta classify PA bits below the page?

Experiment 014 reported PA9 and PA10 as "two further independent selection
components consistent with channel selection", ranked `SUPPORTED`.  Its
evidence was that adding either to the kernel witness `0x16000` made the result
leave the conflict class.  Experiment 023R's allocation-offset/model rank-3
result covers model bits PA13..PA24 only, so whether the relation extends downward decides whether the two
statements describe one selector or two different windows.

Reproducing that test shows the observation holds and the inference does not.
A difference leaves the conflict class in two opposite directions, and only one
of them means what the inference assumed:

  - downward, to the non-conflict level, is what a selection component does:
    the two addresses stop landing in the same bank, so nothing interferes;
  - upward, past the conflict level, is not that at all.

PA9 and PA10 leave upward.  The control that separates the two cases is to add
the bit to a difference that is already *non*-conflicting: a selection
component leaves such a difference non-conflicting, whereas PA9 and PA10 raise
it to exactly the value they produce from the conflicting witness.  Their
effect is witness-independent, which means the bank relation is no longer
observable through the metric once they are set, so the measurement is
saturated rather than informative.

That is a statement about the instrument, not a denial that the bits do
something. The retained measurements do not isolate whether the saturation is
caused by channel, rank, bank group, or another coordinate. This module reports
the levels and the saturation; it does not assign a DRAM coordinate to either
bit.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from collections.abc import Mapping

try:
    from tools import a90_bank_relation_encoding_audit as relation_audit
except ModuleNotFoundError as error:
    if error.name != "tools":
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools import a90_bank_relation_encoding_audit as relation_audit

SCHEMA = "a90-low-bit-selector-analysis-v2"
RELATION_MANIFEST_PATH = relation_audit.RELATION_MANIFEST_PATH

#: Bits whose behaviour the analysis reports.  PA13 upward is Experiment 023R's
#: territory and is not re-derived here.
LOW_BITS = tuple(range(13))


def levels(measurements: dict[int, int], kernel_witness: int,
           negative_witness: int, same_row_control: int) -> dict:
    """The three reference levels every low bit is read against.

    Naming them explicitly matters: `leaving the conflict class` is ambiguous
    until the non-conflict level is on the page next to the conflict one.
    """
    return {
        "same_row": measurements.get(same_row_control),
        "non_conflict": measurements.get(negative_witness),
        "conflict": measurements.get(kernel_witness),
    }


def classify_bit(alone: int | None, with_kernel: int | None,
                 with_negative: int | None, reference: dict,
                 tolerance: int = 60) -> str:
    """What does adding this bit do to a conflicting and a non-conflicting pair?

    ``INERT``       both witnesses keep their level: the bit contributes nothing.
    ``SELECTOR``    the conflicting witness falls to the non-conflict level.
    ``SATURATING``  both witnesses move to the same new level, so the bank
                    relation is no longer visible through the metric.
    ``MODULATING``  the levels move but not together and not to non-conflict.
    """
    conflict = reference["conflict"]
    non_conflict = reference["non_conflict"]
    if None in (alone, with_kernel, with_negative, conflict, non_conflict):
        return "INCOMPLETE"
    if (abs(with_kernel - conflict) <= tolerance
            and abs(with_negative - non_conflict) <= tolerance):
        return "INERT"
    if (abs(with_kernel - non_conflict) <= tolerance
            and abs(with_negative - non_conflict) <= tolerance):
        return "SELECTOR"
    if abs(with_kernel - with_negative) <= tolerance:
        return "SATURATING"
    return "MODULATING"


def analyse(measurements: dict[int, int], kernel_witness: int = 0x16000,
            negative_witness: int = 0x2000, same_row_control: int = 0x800,
            tolerance: int = 60) -> dict:
    reference = levels(measurements, kernel_witness, negative_witness,
                       same_row_control)
    bits = {}
    for bit in LOW_BITS:
        value = 1 << bit
        verdict = classify_bit(
            measurements.get(value),
            measurements.get(kernel_witness ^ value),
            measurements.get(negative_witness ^ value),
            reference, tolerance)
        bits[bit] = {
            "alone": measurements.get(value),
            "with_kernel_witness": measurements.get(kernel_witness ^ value),
            "with_negative_witness": measurements.get(negative_witness ^ value),
            "verdict": verdict,
        }
    grouped: dict[str, list[int]] = {}
    for bit, record in bits.items():
        grouped.setdefault(record["verdict"], []).append(bit)
    return {
        "schema": SCHEMA,
        "reference_levels": reference,
        "tolerance": tolerance,
        "witnesses": {"kernel": f"0x{kernel_witness:x}",
                      "negative": f"0x{negative_witness:x}",
                      "same_row_control": f"0x{same_row_control:x}"},
        "bits": bits,
        "by_verdict": grouped,
        "any_selector": bool(grouped.get("SELECTOR")),
        "saturating_bits": grouped.get("SATURATING", []),
    }


def _format_measurements(measurements: Mapping[int, int]) -> dict[str, int]:
    """Represent one phase's complete median map with stable hexadecimal keys."""
    return {
        f"0x{difference:x}": measurements[difference]
        for difference in sorted(measurements)
    }


def compare_phase_verdicts(phase_results: Mapping[str, dict]) -> dict:
    """Compare only classifications supported by each phase's measurements.

    A phase that did not measure all three witnesses for a bit reports
    ``INCOMPLETE``.  Such a result is not treated as a disagreement, and it is
    not allowed to manufacture a cross-phase consensus.  If two or more
    phases measured a bit and disagree, the consensus verdict is explicitly
    ``DISAGREEMENT`` rather than whichever phase happened to be read last.
    """
    by_bit: dict[int, dict] = {}
    disagreements: list[dict] = []
    for bit in LOW_BITS:
        observed = {
            phase: result["bits"][bit]["verdict"]
            for phase, result in sorted(phase_results.items())
            if result["bits"][bit]["verdict"] != "INCOMPLETE"
        }
        verdicts = sorted(set(observed.values()))
        if not verdicts:
            verdict = "INCOMPLETE"
            status = "INSUFFICIENT_EVIDENCE"
        elif len(verdicts) == 1:
            verdict = verdicts[0]
            status = "CONSISTENT" if len(observed) > 1 else "SINGLE_PHASE"
        else:
            verdict = "DISAGREEMENT"
            status = "DISAGREEMENT"
            disagreements.append({
                "bit": bit,
                "phase_verdicts": observed,
            })
        by_bit[bit] = {
            "verdict": verdict,
            "status": status,
            "phase_verdicts": observed,
            "phase_count": len(observed),
        }

    grouped: dict[str, list[int]] = {}
    for bit, record in by_bit.items():
        if record["verdict"] not in ("INCOMPLETE", "DISAGREEMENT"):
            grouped.setdefault(record["verdict"], []).append(bit)
    return {
        "all_consistent": not disagreements,
        "disagreements": disagreements,
        "bits": by_bit,
        "by_verdict": grouped,
        "any_selector": bool(grouped.get("SELECTOR")),
        "saturating_bits": grouped.get("SATURATING", []),
    }


def analyse_phases(
    phase_measurements: Mapping[str, Mapping[int, int]],
    phase_contexts: Mapping[str, dict] | None = None,
    kernel_witness: int = 0x16000,
    negative_witness: int = 0x2000,
    same_row_control: int = 0x800,
    tolerance: int = 60,
    require_consistent: bool = False,
) -> dict:
    """Analyse each phase independently and publish an explicit comparison.

    Merging phase dictionaries would make duplicate differences (notably
    PA9/PA10 in phases C and D) depend on filename order.  This function keeps
    every phase's full median map and context, runs :func:`analyse` separately,
    and compares only the resulting verdicts.  ``require_consistent`` is an
    opt-in assertion for callers that need a hard gate; the normal CLI keeps
    disagreement in the manifest so the evidence cannot be mistaken for a
    successful aggregate.
    """
    if not phase_measurements:
        raise ValueError("at least one phase is required")
    phase_contexts = phase_contexts or {}
    phase_results: dict[str, dict] = {}
    formatted_measurements: dict[str, dict[str, int]] = {}
    contexts: dict[str, dict] = {}
    for phase in sorted(phase_measurements):
        measurements = phase_measurements[phase]
        result = analyse(measurements, kernel_witness, negative_witness,
                          same_row_control, tolerance)
        context = dict(phase_contexts.get(phase) or {})
        result["phase"] = phase
        result["mode"] = context.get("offset_mode")
        result["context"] = context
        phase_results[phase] = result
        formatted_measurements[phase] = _format_measurements(measurements)
        contexts[phase] = context

    consistency = compare_phase_verdicts(phase_results)
    if require_consistent and not consistency["all_consistent"]:
        details = "; ".join(
            f"PA{item['bit']}: {item['phase_verdicts']}"
            for item in consistency["disagreements"]
        )
        raise ValueError(f"phase verdict disagreement: {details}")

    return {
        "schema": SCHEMA,
        "phase_measurements": formatted_measurements,
        "phase_contexts": contexts,
        "phase_results": phase_results,
        "verdict_consistency": consistency,
        # These fields are consensus-only.  They deliberately do not contain
        # one phase's numeric reference levels or measurements, since those
        # differ between modes and cannot be selected without losing scope.
        "consensus": {
            "scope": (
                "only phases with a complete three-cell/non-INCOMPLETE verdict; "
                "incomplete partial measurements remain visible and do not create "
                "consensus; disagreements are not promoted"
            ),
            "by_verdict": consistency["by_verdict"],
            "any_selector": consistency["any_selector"],
            "saturating_bits": consistency["saturating_bits"],
        },
    }


def load_medians(text: str) -> dict[int, int]:
    """Difference value to median delta, from probe JSONL."""
    out: dict[int, int] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("type") == "difference" and "median" in entry:
            value = entry["value"]
            difference = int(value, 16) if isinstance(value, str) else int(value)
            median = entry["median"]
            if difference in out and out[difference] != median:
                raise ValueError(
                    f"conflicting medians for 0x{difference:x}: "
                    f"{out[difference]} and {median}"
                )
            out[difference] = median
    return out


def _normalise_pa_provenance(entry: dict) -> dict:
    """Keep BLIND producer fields separate from effective contiguity."""
    normalized = dict(entry)
    if normalized.get("status") == "BLIND":
        if "contiguous" in normalized:
            normalized["reported_contiguous"] = normalized.pop("contiguous")
        normalized["effective_contiguity"] = "UNKNOWN"
    return normalized


def load_phase(text: str) -> dict:
    """Load one probe phase, retaining its context alongside all medians."""
    context = None
    ion_heap = None
    pa_provenance = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        entry_type = entry.get("type")
        if entry_type != "context":
            if entry_type == "ion_heap":
                if ion_heap is not None and ion_heap != entry:
                    raise ValueError("multiple conflicting heap records in phase")
                ion_heap = entry
            elif entry_type == "pa_provenance":
                pa_provenance.append(_normalise_pa_provenance(entry))
            continue
        if context is not None and context != entry:
            raise ValueError("multiple conflicting context records in phase")
        context = entry
    return {
        "context": context or {},
        "ion_heap": ion_heap or {},
        "pa_provenance": pa_provenance,
        "measurements": load_medians(text),
    }


def main(argv: list[str]) -> int:
    import argparse
    import hashlib
    import pathlib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, help="directory of phase*.jsonl")
    parser.add_argument(
        "--relation-manifest", default=str(RELATION_MANIFEST_PATH),
        help="public 023R relation manifest to validate and pin",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    raw = pathlib.Path(args.raw)
    inputs = sorted(raw.glob("phase*.jsonl"))
    if not inputs:
        parser.error(f"no phase*.jsonl under {raw}")
    phases = {}
    contexts = {}
    ion_heaps = {}
    pa_provenance = {}
    for path in inputs:
        loaded = load_phase(path.read_text())
        phases[path.stem] = loaded["measurements"]
        contexts[path.stem] = loaded["context"]
        ion_heaps[path.stem] = loaded["ion_heap"]
        pa_provenance[path.stem] = loaded["pa_provenance"]

    relation_dependency = relation_audit.validate_relation_manifest(
        args.relation_manifest
    )
    result = analyse_phases(phases, contexts)
    result["relation_coordinate_scope"] = "allocation-offset/model coordinates"
    result["relation_physical_attribution"] = {
        "classification": "SUPPORTED_WITHIN_MODEL",
        "reason": (
            "The 023R consequence/comparison is inherited only under its "
            "validated contiguous-allocation/model assumptions; low-bit channel "
            "or other-coordinate identity remains UNKNOWN."
        ),
    }
    probe_source = pathlib.Path(__file__).with_name("a90_region_probe_r.c")
    result["provenance"] = {
        "mode": "HOST_ONLY_READ_ONLY",
        "device_writes": "none: allocate, map, read, free only (raw observation)",
        "analysis_sha256": hashlib.sha256(
            pathlib.Path(__file__).resolve().read_bytes()).hexdigest(),
        "probe_source_sha256": (
            hashlib.sha256(probe_source.read_bytes()).hexdigest()
            if probe_source.exists() else None
        ),
        "raw_inputs": {p.stem: hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in inputs},
    }
    result["relation_dependency"] = relation_dependency
    result["experiment_id"] = "030-low-bit-selector-scope"
    result["target"] = {
        "binding": "SUPPORTED_RETAINED_DEVICE_CONTEXT",
        "model": "SM-A908N",
        "soc": "SM8150",
        "heap": "qsecom",
        "model_assumed_region_base": "0xa6000000",
        "region_base_status": "SUPPORTED_WITHIN_MODEL_NOT_OBSERVED",
        "allocation_mib": 32,
    }
    result["build"] = {
        "status": "UNKNOWN",
        "reason": (
            "The retained raw phase files have no exact firmware/build receipt; "
            "the probe schema and source hash are retained separately."
        ),
        "probe_schema": "a90_region_probe_r_v1",
        "probe_source": "tools/a90_region_probe_r.c",
        "probe_source_sha256": result["provenance"]["probe_source_sha256"],
    }
    result["timestamp"] = "2026-08-26"
    result["commands"] = [
        "device: ./a90_region_probe_r qsecom 32 1001 64 7 spread <differences>",
        "device: ./a90_region_probe_r qsecom 32 1001 32 7 stride <differences>",
        "host: python3 tools/a90_low_bit_selector_analysis.py --raw <private raw directory> --relation-manifest <023R public manifest> --output <manifest>",
    ]
    result["command_status"] = "REDACTED_REPRODUCTION_TEMPLATE"
    result["command_reason"] = (
        "Private raw and output paths are redacted; the exact relation manifest "
        "is pinned by dependency provenance. These are reproduction templates, "
        "not executed-command receipts."
    )
    result["repetitions"] = 1001
    result["device_observation"] = {
        "mode": "DEVICE_READ_ONLY",
        "target": result["target"],
        "build": result["build"],
        "phase_contexts": contexts,
        "phase_ion_heaps": ion_heaps,
        "phase_pa_provenance": pa_provenance,
        "repetitions": 1001,
        "absolute_physical_base_observed": False,
        "pagemap_status": "BLIND",
        "physical_base_claim": "SUPPORTED_WITHIN_MODEL_NOT_OBSERVED",
        "writes": "none: allocate, map, read, free only",
    }
    result["host_analysis"] = {
        "mode": "HOST_ONLY_READ_ONLY",
        "tool": "tools/a90_low_bit_selector_analysis.py",
        "analysis_sha256": result["provenance"]["analysis_sha256"],
        "classification_scope": (
            "per phase; consensus only for complete non-INCOMPLETE verdicts; "
            "partial measurements remain visible"
        ),
    }
    result["claims"] = {
        "PROVED": [
            "The phase-specific reference levels and measured low-bit verdicts "
            "are PROVED for the retained allocation-offset observations.",
            "PA9 and PA10 saturating observations are retained per phase; Phase D "
            "PA10 remains INCOMPLETE because its two witness combinations were "
            "not measured.",
        ],
        "REFUTED": [
            "Only the Experiment 014 inference that an upward class departure "
            "proves an independent channel selector is REFUTED; PA9 and PA10 "
            "could still contribute jointly to channel or another coordinate."
        ],
        "SUPPORTED": [
            "Physical attribution of the 023R relation consequence is "
            "SUPPORTED_WITHIN_MODEL only under its validated contiguous-"
            "allocation/model assumptions.",
        ],
        "UNKNOWN": [
            "Whether PA9 or PA10 contributes to channel, rank, bank group, or "
            "another coordinate remains UNKNOWN; the low-bit metric saturates "
            "rather than assigning a DRAM coordinate.",
            "Absolute physical pages and the physical base remain UNKNOWN because "
            "pagemap is BLIND; the retained model base is not a live observation.",
        ],
        "HYPOTHESIS": [],
    }
    result["device_binding"] = {
        "status": "SUPPORTED_RETAINED_DEVICE_CONTEXT",
        "model": "SM-A908N",
        "soc": "SM8150",
        "reason": (
            "The retained experiment context/project record attributes this to "
            "the A90 qsecom observation, but raw phase records carry no exact "
            "model or live re-enumeration/bind receipt; host analysis performs "
            "no device access."
        ),
    }
    result["rollback"] = {
        "status": "NOT_APPLICABLE",
        "reason": "No persistent device state or firmware was written; the probe only allocated, mapped, read and freed memory.",
    }
    result["recovery"] = {
        "status": "UNKNOWN",
        "reason": (
            "The raw phase files retain no exact recovery-state receipt; host "
            "analysis performed no recovery transition."
        ),
    }
    result["public_private_separation"] = {
        "public": "This manifest contains hashes, medians, classifications and context metadata only.",
        "private": "Raw phase JSONL remains under evidence/private/030-low-bit-selector-20260826-01/ and is not published.",
        "raw_bytes_in_manifest": False,
    }
    output_path = pathlib.Path(args.output)
    output_path.write_text(
        json.dumps(result, indent=1, sort_keys=True) + "\n"
    )
    os.chmod(output_path, 0o644)
    print(json.dumps({
        "phases": {
            phase: {
                "mode": result["phase_results"][phase]["mode"],
                "by_verdict": result["phase_results"][phase]["by_verdict"],
            }
            for phase in sorted(result["phase_results"])
        },
        "consensus": result["consensus"],
        "verdict_consistency": result["verdict_consistency"],
    }, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
