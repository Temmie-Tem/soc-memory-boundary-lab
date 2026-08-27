"""Tests for the f(PA28) reduction.

The claim is that exactly one of seven candidate differences conflicts, and
that which one names f(PA28).  A single conflicting candidate is only meaningful
if the same-phase controls fired and if every measured pair really isolated the
bit its difference names, so both gates get negative controls, and the resolved
value is shown not to be hardcoded.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import a90_pa28_relation_analysis as pa

RAW_DIR = REPO_ROOT / "evidence" / "private" / "verification-022-pa28-relation-20260827-01"
EXISTENCE = RAW_DIR / "pa28-existence.jsonl"
IDENTIFICATION = RAW_DIR / "pa28-identification.jsonl"
MANIFEST = (REPO_ROOT / "evidence" / "manifests"
            / "verification-022-pa28-relation-20260827-01.manifest.json")

CONFLICT_DELTA = 540
NEGATIVE_DELTA = 145


def _synthetic(winner: int | None, *, controls_fire: bool = True,
               break_isolation: bool = False, extra_winner: int | None = None) -> list[dict]:
    """Build a phase where `winner` (a candidate difference) conflicts."""
    records = [{"schema": pa.SCHEMA, "type": "context", "heap": "camera_preview",
                "mib": 320, "repetitions": 201, "pairs": 256, "cpu": 7, "warmups": 17,
                "order": "alternating", "barrier": "dsb_ld", "divisor": "kept_times_two",
                "offset_mode": "spread", "declared_base": "0xc2000000"},
               {"schema": pa.SCHEMA, "type": "pa_provenance", "source": "pagemap",
                "status": "BLIND"}]

    def emit(difference: int, delta: int, isolate: bool = True) -> None:
        for index in range(8):
            records.append({
                "schema": pa.SCHEMA, "type": "pair", "value": hex(difference),
                "offset": hex(0x1000 * (index + 1)),
                "pa_a": "0xc2001000", "pa_b": "0xd2001000",
                "pa_xor": hex(difference) if isolate else hex(difference ^ 0x40),
                "delta": delta})
        records.append({"schema": pa.SCHEMA, "type": "difference",
                        "value": hex(difference), "pairs": 8, "rejected_range": 0,
                        "rejected_carry": 0, "p10": delta, "median": delta, "p90": delta})

    emit(pa.CONTROL_CONFLICT, CONFLICT_DELTA if controls_fire else NEGATIVE_DELTA)
    emit(pa.CONTROL_NEGATIVE, NEGATIVE_DELTA)
    for mask in range(8):
        difference = pa.PA28
        for bit, value in pa.BASIS.items():
            if mask & value:
                difference ^= bit
        hot = difference in (winner, extra_winner)
        emit(difference, CONFLICT_DELTA if hot else NEGATIVE_DELTA,
             isolate=not (break_isolation and difference == pa.PA28))
    return records


class Resolution(unittest.TestCase):
    def test_the_conflicting_candidate_names_f_pa28(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000))
        self.assertEqual(result["verdict"], "RESOLVED")
        self.assertEqual(result["f_pa28"], "010")

    def test_a_different_winner_resolves_differently(self) -> None:
        """The answer is read off the data, not baked in."""
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x8000))
        self.assertEqual(result["verdict"], "RESOLVED")
        self.assertEqual(result["f_pa28"], "100")

    def test_a_compound_winner_resolves_to_a_compound_vector(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x2000 ^ 0x8000))
        self.assertEqual(result["f_pa28"], "101")

    def test_no_conflicting_candidate_is_outside_the_space_not_resolved(self) -> None:
        result = pa.analyse(_synthetic(None))
        self.assertEqual(result["verdict"], "OUTSIDE_RANK_3_SPACE")
        self.assertIsNone(result["f_pa28"])

    def test_two_conflicting_candidates_are_ambiguous_not_resolved(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000, extra_winner=pa.PA28 ^ 0x8000))
        self.assertEqual(result["verdict"], "AMBIGUOUS_MULTIPLE_CONFLICTS")
        self.assertIsNone(result["f_pa28"])


class Gates(unittest.TestCase):
    def test_a_control_that_did_not_fire_blocks_resolution(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000, controls_fire=False))
        self.assertEqual(result["verdict"], "INSTRUMENT_FAILED")
        self.assertIsNone(result["f_pa28"])

    def test_a_pair_that_did_not_isolate_its_bit_blocks_resolution(self) -> None:
        """A carried pair would be scored against a bit it does not name."""
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000, break_isolation=True))
        self.assertFalse(result["pair_verification"]["all_pairs_isolate_their_difference"])
        self.assertEqual(result["verdict"], "INSTRUMENT_FAILED")

    def test_foreign_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.jsonl"
            p.write_text(json.dumps({"schema": "other", "type": "context"}) + "\n")
            with self.assertRaises(ValueError):
                pa.load(p)

    def test_symlinked_receipt_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.jsonl"
            real.write_text(json.dumps(_synthetic(pa.PA28 ^ 0x4000)[0]) + "\n")
            link = Path(tmp) / "link.jsonl"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                pa.load(link)


class RetainedResult(unittest.TestCase):
    def setUp(self) -> None:
        if not (EXISTENCE.exists() and IDENTIFICATION.exists()):
            self.skipTest("retained PA28 receipts are absent on this host")
        merged = []
        for path in (EXISTENCE, IDENTIFICATION):
            records, _ = pa.load(path)
            merged.extend(records)
        self.result = pa.analyse(merged)

    def test_every_measured_pair_isolated_its_bit(self) -> None:
        verification = self.result["pair_verification"]
        self.assertEqual(verification["mismatched"], [])
        self.assertGreater(verification["pairs_checked"], 3000)

    def test_controls_fired(self) -> None:
        self.assertTrue(self.result["controls"]["controls_fired"])

    def test_exactly_one_candidate_conflicts(self) -> None:
        self.assertEqual(len(self.result["conflicting_candidates"]), 1)

    def test_the_split_is_not_marginal(self) -> None:
        """The gap that sets the threshold must dominate the next one."""
        split = self.result["phase_split"]
        self.assertGreater(split["gap"], 10 * split["runner_up_gap"])

    def test_f_pa28_is_f_pa14(self) -> None:
        self.assertEqual(self.result["verdict"], "RESOLVED")
        self.assertEqual(self.result["f_pa28"], "010")
        self.assertEqual(self.result["f_pa28_equals"], "f(PA14)")

    def test_pa28_alone_is_negative_as_the_resolved_value_requires(self) -> None:
        """f(2^28) = 010 is nonzero, so 2^28 on its own must not conflict."""
        self.assertNotIn(hex(pa.PA28), self.result["conflicting_candidates"])

    def test_pagemap_was_blind_so_the_base_came_from_the_device_tree(self) -> None:
        self.assertEqual(self.result["pagemap_status"], "BLIND")

    def test_manifest_matches_the_retained_receipts(self) -> None:
        if not MANIFEST.exists():
            self.skipTest("manifest absent")
        published = json.loads(MANIFEST.read_text())
        for key in ("verdict", "f_pa28", "f_pa28_equals", "conflicting_candidates"):
            self.assertEqual(published[key], self.result[key], key)


if __name__ == "__main__":
    unittest.main()
