#!/usr/bin/env python3
"""Recover the DRAM bank-selection kernel in polynomial time from retained timing.

This is a port of the Knock-Knock (arXiv 2509.19568) formulation to this
target's retained corpus.  The project's existing method tests candidate masks
one at a time, which is exponential in the number of address bits.  The
observation that makes it polynomial is that every measurement already answers a
*linear* question:

    two addresses whose XOR difference is ``d`` collide in the row buffer
    <=> they share a bank <=> ``f(d) = 0``

so each CONFLICT observation says ``d`` lies in ``ker f``, and the span of the
observed conflicts is a lower bound on that kernel, computable by Gaussian
elimination over GF(2).  Each NEGATIVE observation says ``f(d) != 0``, which
gives a falsification test that no per-difference analysis can perform: a
negative difference that lands inside the span of the conflicts is a
contradiction, because linearity forces the span to be inside the kernel.

Scope, established by measurement in Verification 027 rather than assumed:

* Differences below ``MIN_DIFFERENCE`` are excluded.  Sub-page bits are column
  and burst bits, not bank bits, and including them corrupts the system --
  every contradiction in ``030-low-bit-selector`` phases C came from them.
* Datasets are never pooled.  Physical address provenance is ``BLIND`` on this
  target (pagemap reports no PFN for dma-buf), so a declared difference is
  ``declared_base + offset`` and is only coherent within one allocation.
  Pooling all datasets produces 42 contradictions and places the PA13 negative
  control inside the kernel; per-dataset analysis produces 0 for 32 of 35.

Host-only.  No device access, no MMIO, no firmware bytes, no allocation.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Iterable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.a90_acm_snapshot import json_bytes, write_new

SCHEMA = "dram-bank-kernel-recovery-v1"

# PA13 is the floor of this project's stated bank-selection model.  Anything
# below it is intra-page and is not in the domain of the linear map.
MIN_DIFFERENCE = 0x2000

# A dataset whose two timing clusters are not separated by at least this many
# cycles is not a usable bimodal measurement, and its threshold would be an
# arbitrary cut through noise rather than a class boundary.
MIN_SEPARATION = 100

# Below this, a widest-gap threshold is being fitted to too few distinct
# differences to mean anything.
MIN_DIFFERENCES = 6

# The widest gap is only the *candidate* cut.  A run whose medians form three
# clusters can put that gap above the conflict cluster, which classifies the
# conflict control as a negative and leaves almost nothing in the conflict set.
# Such a run then passes the linearity test vacuously -- no conflicts, so no
# span, so no contradiction possible.  The project's rule has always been
# widest gap *and* controls bracketing the candidates; these are that second
# half, and a run that fails it is refused rather than reduced.
CONFLICT_CONTROL = 0x16000
FAST_CONTROL = 0x2000


class RecoveryError(Exception):
    """A dataset cannot be reduced under the declared rules."""


def widest_gap_threshold(medians: Sequence[int]) -> tuple[int, float]:
    """Return (separation, threshold) using the project's widest-gap rule.

    The threshold sits at the midpoint of the largest gap between adjacent
    sorted medians, so it is derived from the data rather than chosen.
    """

    distinct = sorted(set(medians))
    if len(distinct) < 2:
        raise RecoveryError("a threshold needs at least two distinct medians")
    return max(
        (distinct[i + 1] - distinct[i], (distinct[i] + distinct[i + 1]) / 2)
        for i in range(len(distinct) - 1)
    )


def reduce_vector(basis: Sequence[int], value: int) -> int:
    """Reduce ``value`` against a GF(2) basis; zero means it is in the span."""

    for element in basis:
        value = min(value, value ^ element)
    return value


def span_basis(vectors: Iterable[int]) -> list[int]:
    """Gaussian elimination over GF(2).  This is the polynomial-time step."""

    basis: list[int] = []
    for vector in sorted(vectors, reverse=True):
        residue = reduce_vector(basis, vector)
        if residue:
            basis.append(residue)
            basis.sort(reverse=True)
    return basis


def in_span(basis: Sequence[int], value: int) -> bool:
    return reduce_vector(basis, value) == 0


def check_controls_bracket(
    summaries: Sequence[Mapping[str, object]], threshold: float
) -> None:
    """Refuse a run whose threshold does not put the controls on both sides.

    ``0x16000`` is the project's canonical conflict control and ``0x2000`` its
    canonical fast control.  If a run measured either and the threshold puts it
    on the wrong side, the cut is in the wrong place and every classification
    derived from it is unusable -- including a vacuous consistency pass.
    """

    observed = {int(r["value"], 16): r["median"] for r in summaries}
    conflict = observed.get(CONFLICT_CONTROL)
    if conflict is not None and conflict <= threshold:
        raise RecoveryError(
            f"conflict control 0x{CONFLICT_CONTROL:x} (median {conflict}) is not "
            f"above the threshold {threshold}; the cut is misplaced"
        )
    fast = observed.get(FAST_CONTROL)
    if fast is not None and fast > threshold:
        raise RecoveryError(
            f"fast control 0x{FAST_CONTROL:x} (median {fast}) is not below the "
            f"threshold {threshold}; the cut is misplaced"
        )


def load_dataset(path: Path) -> dict[str, object]:
    """Read one retained JSONL run into classified difference sets."""

    summaries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if record.get("type") == "difference" and "median" in record and "value" in record:
            summaries.append(record)
    if len(summaries) < MIN_DIFFERENCES:
        raise RecoveryError(
            f"{len(summaries)} difference summaries is below the {MIN_DIFFERENCES} floor"
        )
    separation, threshold = widest_gap_threshold([r["median"] for r in summaries])
    if separation < MIN_SEPARATION:
        raise RecoveryError(
            f"cluster separation {separation} is below the {MIN_SEPARATION} floor"
        )
    check_controls_bracket(summaries, threshold)
    conflicts, negatives, excluded = set(), set(), set()
    for record in summaries:
        value = int(record["value"], 16)
        if value < MIN_DIFFERENCE:
            excluded.add(value)
            continue
        (conflicts if record["median"] > threshold else negatives).add(value)
    return {
        "separation": separation,
        "threshold": threshold,
        "conflicts": conflicts,
        "negatives": negatives,
        "excluded_sub_page": excluded,
    }


def image_rank_lower_bound(
    negatives: set[int], max_k: int = 4
) -> tuple[int, tuple[int, ...]]:
    """Largest k proving ``rank f >= k`` from measured negatives alone.

    If d1..dk are differences whose every nonempty XOR combination was measured
    as a negative, then f(d1)..f(dk) are linearly independent: any dependency
    would make some combination land in the kernel and measure as a conflict.
    Unlike the kernel dimension, this is a bound on the *global* rank, because
    independence of images is not relative to the observed subspace.

    The combinations must all be present in the measured set -- an unmeasured
    combination proves nothing, so the search cannot assume it.
    """

    ordered = sorted(negatives)
    best_k, best_witness = 0, ()
    for size in range(1, max_k + 1):
        found = None
        for combo in itertools.combinations(ordered, size):
            if all(
                _xor(subset) in negatives
                for count in range(1, size + 1)
                for subset in itertools.combinations(combo, count)
            ):
                found = combo
                break
        if found is None:
            break
        best_k, best_witness = size, found
    return best_k, best_witness


def _xor(values: Iterable[int]) -> int:
    result = 0
    for value in values:
        result ^= value
    return result


def analyse(conflicts: set[int], negatives: set[int]) -> dict[str, object]:
    """Recover the kernel lower bound and run the linearity falsification."""

    kernel = span_basis(conflicts)
    observed = span_basis(conflicts | negatives)
    contradictions = sorted(v for v in negatives if in_span(kernel, v))
    rank_floor, witness = image_rank_lower_bound(negatives)
    return {
        "kernel_basis": [f"0x{b:x}" for b in kernel],
        "kernel_dimension_lower_bound": len(kernel),
        "observed_dimension": len(observed),
        # This bounds f *restricted to the differences this run observed*, not
        # the global rank.  A run that only probed a one-dimensional slice of
        # the image reports 1 without contradicting a global rank of 3.
        "restricted_rank_upper_bound": len(observed) - len(kernel),
        # This one is a genuine global lower bound: see image_rank_lower_bound.
        "global_rank_lower_bound": rank_floor,
        "rank_witness": [f"0x{v:x}" for v in witness],
        "contradictions": [f"0x{v:x}" for v in contradictions],
        "linearity_consistent": not contradictions,
    }


def predict_heldout(
    kernel: Sequence[int], conflicts: set[int], negatives: set[int]
) -> dict[str, object]:
    """Score an out-of-sample run against a kernel fitted elsewhere.

    The two error directions are not symmetric and must not be summarised into
    one accuracy number without saying so.  A *false conflict* -- predicted
    same-bank, measured different-bank -- falsifies the recovered kernel.  A
    *missed conflict* only says the fitted conflicts did not span the whole
    kernel, which is incompleteness of the fit set, not error.
    """

    predicted_conflicts = sum(1 for v in conflicts if in_span(kernel, v))
    predicted_negatives = sum(1 for v in negatives if not in_span(kernel, v))
    false_conflicts = sorted(v for v in negatives if in_span(kernel, v))
    missed_conflicts = sorted(v for v in conflicts if not in_span(kernel, v))
    return {
        "conflicts_total": len(conflicts),
        "conflicts_predicted": predicted_conflicts,
        "negatives_total": len(negatives),
        "negatives_predicted": predicted_negatives,
        "false_conflicts": [f"0x{v:x}" for v in false_conflicts],
        "missed_conflicts": [f"0x{v:x}" for v in missed_conflicts],
        "falsified": bool(false_conflicts),
    }


def survey(root: Path) -> dict[str, object]:
    """Reduce every retained run independently and report the corpus shape."""

    private = Path(root) / "evidence" / "private"
    results, skipped = {}, {}
    for path in sorted(private.glob("**/*.jsonl")):
        if "/raw/" in str(path):
            # These are duplicates of 023-second-region and would double-count.
            continue
        name = f"{path.parent.name}/{path.name}"
        try:
            dataset = load_dataset(path)
        except (RecoveryError, json.JSONDecodeError) as exc:
            skipped[name] = str(exc)
            continue
        if not dataset["conflicts"] or not dataset["negatives"]:
            skipped[name] = "one class is empty; nothing is constrained"
            continue
        entry = analyse(dataset["conflicts"], dataset["negatives"])
        entry.update(
            {
                "separation": dataset["separation"],
                "conflicts": len(dataset["conflicts"]),
                "negatives": len(dataset["negatives"]),
                "excluded_sub_page": len(dataset["excluded_sub_page"]),
            }
        )
        results[name] = entry
    consistent = [n for n, r in results.items() if r["linearity_consistent"]]
    return {
        "datasets": results,
        "skipped": skipped,
        "datasets_reduced": len(results),
        "datasets_linearity_consistent": len(consistent),
        "datasets_with_contradictions": sorted(set(results) - set(consistent)),
    }


def pooled_control(root: Path) -> dict[str, object]:
    """The negative control for pooling: it must fail, and visibly.

    If this ever comes back consistent, the per-dataset rule above is
    unnecessary and the corpus supports a single global recovery.  It does not:
    physical provenance is BLIND, so declared differences are only coherent
    inside one allocation.
    """

    private = Path(root) / "evidence" / "private"
    conflicts, negatives = set(), set()
    for path in sorted(private.glob("**/*.jsonl")):
        if "/raw/" in str(path):
            continue
        try:
            dataset = load_dataset(path)
        except (RecoveryError, json.JSONDecodeError):
            continue
        conflicts |= dataset["conflicts"]
        negatives |= dataset["negatives"]
    result = analyse(conflicts, negatives)
    result["pa13_control_wrongly_in_kernel"] = in_span(
        span_basis(conflicts), MIN_DIFFERENCE
    )
    return result


def build(root: Path | None = None) -> dict[str, object]:
    root = REPO_ROOT if root is None else Path(root)
    return {
        "schema": SCHEMA,
        "mode": "HOST_ONLY_REANALYSIS",
        "device_access": False,
        "mmio_access": False,
        "allocation_performed": False,
        "firmware_bytes_emitted": False,
        "min_difference": f"0x{MIN_DIFFERENCE:x}",
        "min_separation": MIN_SEPARATION,
        "per_dataset": survey(root),
        "pooled_negative_control": pooled_control(root),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = build(args.root)
    if args.output:
        write_new(args.output, json_bytes(result), 0o644)
        print(args.output)
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
