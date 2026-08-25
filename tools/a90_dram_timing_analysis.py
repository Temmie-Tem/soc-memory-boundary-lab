#!/usr/bin/env python3
"""Reduce Experiment 014 live timing evidence to a redacted GF(2) result."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import gf2


SCHEMA = "a90_dram_timing_analysis_v1"
LIVE_SCHEMA = "a90_dram_timing_live_v1"
PROBE_SCHEMA = "a90_dram_timing_probe_v2"
EXPECTED_SOURCE_SHA256 = "f5788486f7410984bca0c7a31241c10d9a7078f6d1abcb753f6ccbc2ce62fe75"
EXPECTED_BINARY_SHA256 = "552432c1270affcdb9433f3a8aa7a7e0a28d3011abfc1f4ec57aa1f5715910a9"
EXPECTED_CMA_BASE = 0xF0400000
EXPECTED_CMA_END = 0xF1400000
OBSERVED_WIDTH = 24

REQUIRED_EXPERIMENTS = (
    "014-ion-uncached-reopen-controls-live-20260825-01",
    "014-ion-uncached-reopen-phase1-live-20260825-01",
    "014-ion-uncached-channel-equivalence-live-20260825-01",
    "014-ion-uncached-bank13-14-equivalence-live-20260825-01",
    "014-ion-uncached-bank15-witness-repeat-live-20260825-01",
    "014-ion-uncached-gf2-kernel-witness-live-20260825-01",
    "014-ion-uncached-single-row-bits-live-20260825-01",
    "014-ion-uncached-row17-18-bank-search-live-20260825-01",
    "014-ion-uncached-row21-22-bank-search-live-20260825-01",
    "014-ion-uncached-hash-holdout-live-20260825-01",
)

# Relations recovered by the unique kernel-class candidate in each bounded
# {row bit} XOR subset({PA13, PA14, PA15}) search.
ROW_TO_BANK_BASIS = {
    16: (13, 14),
    17: (14, 15),
    18: (13, 14, 15),
    19: (13, 15),
    20: (13,),
    21: (14,),
    22: (15,),
    23: (13, 14),
}

BANK_OUTPUT_BITS = (
    (13, 16, 18, 19, 20, 23),
    (14, 16, 17, 18, 21, 23),
    (15, 17, 18, 19, 22),
)
CHANNEL_OUTPUT_BITS = ((9,), (10,))

RELATION_DIFFERENCES = {
    row_bit: (1 << row_bit) ^ sum(1 << bit for bit in basis)
    for row_bit, basis in ROW_TO_BANK_BASIS.items()
}

RELATION_EXPERIMENTS = {
    16: "014-ion-uncached-hash-holdout-live-20260825-01",
    17: "014-ion-uncached-row17-18-bank-search-live-20260825-01",
    18: "014-ion-uncached-row17-18-bank-search-live-20260825-01",
    19: "014-ion-uncached-gf2-kernel-witness-live-20260825-01",
    20: "014-ion-uncached-row21-22-bank-search-live-20260825-01",
    21: "014-ion-uncached-row21-22-bank-search-live-20260825-01",
    22: "014-ion-uncached-row21-22-bank-search-live-20260825-01",
    23: "014-ion-uncached-gf2-kernel-witness-live-20260825-01",
}

HELDOUT_KERNEL_DIFFERENCES = (0x0003A000, 0x0024A000, 0x00C84000, 0x0095C000)
HELDOUT_NEGATIVE_DIFFERENCES = (0x00038000, 0x00248000, 0x00C86000, 0x0095E000)
CHANNEL_PERTURBATIONS = (0x00016200, 0x00016400)
LOW_BIT_PRESERVING = tuple(0x00016000 ^ (1 << bit) for bit in (0, 1, 2, 3, 6, 7, 8, 11, 12))
LOW_BIT_AMBIGUOUS = tuple(0x00016000 ^ (1 << bit) for bit in (4, 5))


class AnalysisError(ValueError):
    pass


def rows_from_bits(bit_sets: Iterable[Iterable[int]]) -> tuple[int, ...]:
    return tuple(sum(1 << bit for bit in bits) for bits in bit_sets)


def recovered_selection_rows() -> tuple[int, ...]:
    """Observed low-24 channel/bank selection row space."""
    return rows_from_bits(BANK_OUTPUT_BITS + CHANNEL_OUTPUT_BITS)


def diagnostic_low24_rows() -> tuple[int, ...]:
    return rows_from_bits(((13,), (14,), (15,), (9,), (10,)))


def same_row_space(left: Sequence[int], right: Sequence[int]) -> bool:
    left_rank = gf2.rank(left, OBSERVED_WIDTH)
    right_rank = gf2.rank(right, OBSERVED_WIDTH)
    return (
        left_rank == right_rank
        and gf2.rank(tuple(left) + tuple(right), OBSERVED_WIDTH) == left_rank
    )


def is_recovered_kernel(difference: int) -> bool:
    return gf2.apply(recovered_selection_rows(), difference, OBSERVED_WIDTH) == 0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AnalysisError(f"manifest is not an object: {path}")
    return value


def validate_manifest(
    value: dict[str, object], experiment_id: str
) -> list[dict[str, object]]:
    if value.get("schema") != LIVE_SCHEMA:
        raise AnalysisError(f"{experiment_id}: wrong live schema")
    if value.get("experiment_id") != experiment_id:
        raise AnalysisError(f"{experiment_id}: experiment ID mismatch")
    if value.get("result") != "PASS_NORMAL_RAM_PROBE":
        raise AnalysisError(f"{experiment_id}: live result is not PASS")
    if value.get("backing") != "ion" or value.get("mode") != "measure":
        raise AnalysisError(f"{experiment_id}: not an uncached ION measurement")
    target = value.get("target")
    if not isinstance(target, dict) or target.get("model") != "SM-A908N" or target.get("soc") != "SM8150":
        raise AnalysisError(f"{experiment_id}: target binding mismatch")
    source = value.get("source")
    upload = value.get("upload")
    if not isinstance(source, dict) or source.get("sha256") != EXPECTED_SOURCE_SHA256:
        raise AnalysisError(f"{experiment_id}: probe source hash mismatch")
    if not isinstance(upload, dict) or upload.get("binary_sha256") != EXPECTED_BINARY_SHA256:
        raise AnalysisError(f"{experiment_id}: probe binary hash mismatch")
    records = value.get("records")
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise AnalysisError(f"{experiment_id}: records are malformed")
    if any(record.get("schema") != PROBE_SCHEMA for record in records):
        raise AnalysisError(f"{experiment_id}: foreign probe record")
    bindings = [record for record in records if record.get("type") == "ion_cma_binding"]
    stability = [record for record in records if record.get("type") == "stability"]
    if len(bindings) != 1 or len(stability) != 1:
        raise AnalysisError(f"{experiment_id}: binding/stability record count mismatch")
    binding = bindings[0]
    if (
        int(str(binding.get("base")), 16) != EXPECTED_CMA_BASE
        or int(str(binding.get("end_exclusive")), 16) != EXPECTED_CMA_END
        or binding.get("pages") != 4096
        or binding.get("single_sg_contiguous_source") is not True
    ):
        raise AnalysisError(f"{experiment_id}: CMA binding mismatch")
    if (
        stability[0].get("method") != "dma_buf_contiguous_pin"
        or stability[0].get("changed_pages") != 0
        or stability[0].get("lost_pages") != 0
    ):
        raise AnalysisError(f"{experiment_id}: physical binding was not stable")
    measurements = [record for record in records if record.get("type") == "measurement"]
    if not measurements:
        raise AnalysisError(f"{experiment_id}: no measurements")
    return measurements


def index_measurements(
    manifests: dict[str, dict[str, object]]
) -> dict[int, list[dict[str, object]]]:
    indexed: dict[int, list[dict[str, object]]] = {}
    for experiment_id, manifest in manifests.items():
        for record in validate_manifest(manifest, experiment_id):
            if record.get("status") != "OK" or record.get("reopen_delta_available") is not True:
                continue
            difference = int(str(record["difference"]), 16)
            indexed.setdefault(difference, []).append(
                {"experiment_id": experiment_id, **record}
            )
    return indexed


def select_record(
    indexed: dict[int, list[dict[str, object]]],
    difference: int,
    preferred_experiment: str | None = None,
) -> dict[str, object]:
    candidates = indexed.get(difference, [])
    if preferred_experiment is not None:
        candidates = [
            record for record in candidates
            if record.get("experiment_id") == preferred_experiment
        ]
    if not candidates:
        raise AnalysisError(f"measurement missing for 0x{difference:08x}")
    return candidates[-1]


def compact_measurement(record: dict[str, object]) -> dict[str, object]:
    if record.get("pairs") != 64 or int(record.get("repetitions_per_pair", 0)) < 501:
        raise AnalysisError("selected measurement lacks 64 pairs or 501 repetitions")
    return {
        "experiment_id": record["experiment_id"],
        "difference": record["difference"],
        "pairs": record["pairs"],
        "repetitions_per_pair": record["repetitions_per_pair"],
        "delta_milli_ticks": {
            "p10": record["pair_reopen_delta_milli_p10"],
            "median": record["pair_reopen_delta_milli_median"],
            "p90": record["pair_reopen_delta_milli_p90"],
        },
    }


def analyze(manifests: dict[str, dict[str, object]]) -> dict[str, object]:
    missing = sorted(set(REQUIRED_EXPERIMENTS) - set(manifests))
    if missing:
        raise AnalysisError(f"required experiments missing: {missing}")
    indexed = index_measurements(manifests)

    relation_records = {
        str(row): compact_measurement(
            select_record(indexed, difference, RELATION_EXPERIMENTS[row])
        )
        for row, difference in RELATION_DIFFERENCES.items()
    }
    heldout_positive = [
        compact_measurement(
            select_record(
                indexed, difference,
                "014-ion-uncached-hash-holdout-live-20260825-01",
            )
        )
        for difference in HELDOUT_KERNEL_DIFFERENCES
    ]
    heldout_negative = [
        compact_measurement(
            select_record(
                indexed, difference,
                "014-ion-uncached-hash-holdout-live-20260825-01",
            )
        )
        for difference in HELDOUT_NEGATIVE_DIFFERENCES
    ]
    positive_p10_min = min(
        item["delta_milli_ticks"]["p10"] for item in heldout_positive
    )
    positive_p90_max = max(
        item["delta_milli_ticks"]["p90"] for item in heldout_positive
    )
    negative_p90_max = max(
        item["delta_milli_ticks"]["p90"] for item in heldout_negative
    )
    if positive_p10_min <= negative_p90_max:
        raise AnalysisError("held-out kernel and one-bit negatives overlap")
    if min(
        item["delta_milli_ticks"]["p10"]
        for item in relation_records.values()
    ) <= negative_p90_max:
        raise AnalysisError("fitted row relation overlaps one-bit negatives")

    channel_perturbations = [
        compact_measurement(
            select_record(
                indexed, difference,
                "014-ion-uncached-gf2-kernel-witness-live-20260825-01",
            )
        )
        for difference in CHANNEL_PERTURBATIONS
    ]
    if any(
        not (
            item["delta_milli_ticks"]["p90"] < positive_p10_min
            or item["delta_milli_ticks"]["p10"] > positive_p90_max
        )
        for item in channel_perturbations
    ):
        raise AnalysisError("channel perturbation overlaps held-out bank-kernel class")

    if not all(is_recovered_kernel(value) for value in RELATION_DIFFERENCES.values()):
        raise AnalysisError("recovered relation is outside the derived kernel")
    if not all(is_recovered_kernel(value) for value in HELDOUT_KERNEL_DIFFERENCES):
        raise AnalysisError("held-out positive is outside the derived kernel")
    if any(is_recovered_kernel(value) for value in HELDOUT_NEGATIVE_DIFFERENCES):
        raise AnalysisError("held-out one-bit negative falls inside the derived kernel")

    rowhit_records = indexed.get(0x800, [])
    if len(rowhit_records) != len(REQUIRED_EXPERIMENTS):
        raise AnalysisError("same-row control is missing")
    if any(
        record.get("pairs") != 64
        or int(record.get("repetitions_per_pair", 0)) < 501
        for record in rowhit_records
    ):
        raise AnalysisError("same-row control lacks 64 pairs or 501 repetitions")
    rowhit_medians = [record["pair_reopen_delta_milli_median"] for record in rowhit_records]
    if max(abs(value) for value in rowhit_medians) > 10:
        raise AnalysisError("same-row control does not remain centered on zero")

    low_preserving = [compact_measurement(select_record(indexed, value))
                      for value in LOW_BIT_PRESERVING]
    low_ambiguous = [compact_measurement(select_record(indexed, value))
                     for value in LOW_BIT_AMBIGUOUS]

    rows = recovered_selection_rows()
    diagnostic = diagnostic_low24_rows()
    if gf2.rank(rows, OBSERVED_WIDTH) != 5:
        raise AnalysisError("recovered selection rows are not rank five")
    if same_row_space(rows, diagnostic):
        raise AnalysisError("recovered and diagnostic row spaces unexpectedly match")

    return {
        "schema": SCHEMA,
        "generated_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "classification": "NORMAL_RAM_HIDDEN_BANK_HASH_PROVED_NO_ALIAS_OR_BYPASS",
        "status": "NO_BOUNDARY_BYPASS_OBSERVED",
        "probe": {
            "source_sha256": EXPECTED_SOURCE_SHA256,
            "binary_sha256": EXPECTED_BINARY_SHA256,
            "backing": "ION user_contig flags=0 / pgprot_writecombine",
            "cma_base": f"0x{EXPECTED_CMA_BASE:016x}",
            "cma_end_exclusive": f"0x{EXPECTED_CMA_END:016x}",
            "pages": 4096,
            "pairs_per_difference": 64,
        },
        "recovered_low24_selection": {
            "width": OBSERVED_WIDTH,
            "rank": gf2.rank(rows, OBSERVED_WIDTH),
            "bank_output_equations": [
                {"output_basis": index, "xor_pa_bits": list(bits),
                 "row_mask": f"0x{row:06x}"}
                for index, (bits, row) in enumerate(zip(BANK_OUTPUT_BITS, rows[:3]))
            ],
            "channel_output_equations": [
                {"output_basis": index, "xor_pa_bits": list(bits),
                 "row_mask": f"0x{row:06x}"}
                for index, (bits, row) in enumerate(zip(CHANNEL_OUTPUT_BITS, rows[3:]))
            ],
            "row_to_bank_basis": {
                str(bit): list(basis) for bit, basis in ROW_TO_BANK_BASIS.items()
            },
            "diagnostic_no_xor_row_space_equal": False,
            "observed_scope": "rank-relative PA bits 0..23 only",
        },
        "controls": {
            "same_row_delta_milli_tick_medians": rowhit_medians,
            "heldout_kernel": heldout_positive,
            "one_bank_bit_negatives": heldout_negative,
            "nonoverlap": {
                "kernel_min_p10": positive_p10_min,
                "kernel_max_p90": positive_p90_max,
                "negative_max_p90": negative_p90_max,
                "gap_milli_ticks": positive_p10_min - negative_p90_max,
            },
            "channel_perturbations": channel_perturbations,
            "low_bit_preserving": low_preserving,
            "low_bit_ambiguous": low_ambiguous,
        },
        "relation_evidence": relation_records,
        "claims": {
            "PROVED": [
                "The exact A90 exposes a stable 16-MiB non-secure write-combine CMA mapping whose VA offsets are bound to PA 0xf0400000..0xf13fffff by a unique kpageflags transition window and the single-SG ION CMA source path.",
                "Same-row controls stay centered on zero reopen delta, while learned kernel vectors and held-out GF(2) combinations form a non-overlapping conflict class against one-bank-bit negatives.",
                "Rank-relative PA row bits 16..23 are XOR-hashed into the three-dimensional bank-selection span generated by PA13..PA15 according to the recorded matrix.",
                "The no-XOR Experiment-011 diagnostic bank row space is not the observed low-24 bank-selection row space.",
            ],
            "SUPPORTED": [
                "PA9 and PA10 provide two additional independent selection components consistent with channel selection; perturbing a bank-kernel witness by either bit leaves the conflict class.",
                "The observations are consistent with a normal DRAM bank hash and do not establish a physical-address alias: no two distinct physical addresses were shown to reach one complete DRAM coordinate.",
            ],
            "REFUTED": [
                "The Experiment-011 diagnostic formula bank=PA[15:13] with no XOR is the complete silicon bank-selection function for observed PA bits 0..23.",
                "The cached anonymous/DC-CIVAC timing path alone is a valid DRAM classifier on this target.",
            ],
            "UNKNOWN": [
                "Hash contributions from rank-relative PA bits 24..31.",
                "The exact semantic channel-bit equations beyond the observed independence of PA9 and PA10.",
                "Which MC/MCCC/remapper register programs the hash, its post-boot writability and lock owner.",
                "Protection ordering relative to the hash, any physical-to-DRAM alias, and any protected-memory effect.",
                "Whether PA4/PA5 timing deviations are burst/byte-lane effects or another implementation detail; they are excluded from the recovered bank matrix.",
            ],
        },
        "source_manifests": [
            {
                "experiment_id": experiment_id,
                "manifest_sha256": sha256(
                    (Path("evidence/private") / experiment_id / "manifest.json").read_bytes()
                ),
            }
            for experiment_id in REQUIRED_EXPERIMENTS
        ],
    }


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o644)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path,
                        default=Path("evidence/private"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    manifests = {
        experiment_id: load_manifest(
            args.evidence_root / experiment_id / "manifest.json"
        )
        for experiment_id in REQUIRED_EXPERIMENTS
    }
    result = analyze(manifests)
    write_new(
        args.output,
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
