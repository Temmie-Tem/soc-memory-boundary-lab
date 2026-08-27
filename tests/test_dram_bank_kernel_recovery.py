"""Focused tests for the polynomial-time bank-kernel recovery.

The tool makes two claims that a per-difference analysis cannot: that a set of
measurements is internally consistent with a *linear* bank function, and that a
kernel fitted on one run predicts another.  These tests hold both to the
standard the claims require -- each must be able to fail, the falsification
direction must be reachable, and the scope rules must be the ones the corpus
actually supports rather than convenient ones.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools import dram_bank_kernel_recovery as rec

REPO_ROOT = Path(__file__).resolve().parents[1]
V016 = REPO_ROOT / "evidence/private/verification-016-high-bit-relation-20260827-01"


class GF2Algebra(unittest.TestCase):
    def test_span_of_independent_vectors_keeps_all(self) -> None:
        self.assertEqual(3, len(rec.span_basis([0x2000, 0x4000, 0x8000])))

    def test_span_collapses_a_dependent_vector(self) -> None:
        # 0x6000 = 0x2000 ^ 0x4000, so it adds no dimension.
        self.assertEqual(2, len(rec.span_basis([0x2000, 0x4000, 0x6000])))

    def test_membership_follows_xor_closure(self) -> None:
        basis = rec.span_basis([0x2000, 0x4000])
        self.assertTrue(rec.in_span(basis, 0x6000))
        self.assertFalse(rec.in_span(basis, 0x8000))

    def test_zero_is_always_in_any_span(self) -> None:
        self.assertTrue(rec.in_span(rec.span_basis([0x2000]), 0))

    def test_span_is_order_independent(self) -> None:
        a = rec.span_basis([0x2000, 0x4000, 0x8000, 0xE000])
        b = rec.span_basis([0xE000, 0x8000, 0x4000, 0x2000])
        self.assertEqual(a, b)


class Thresholding(unittest.TestCase):
    def test_threshold_sits_in_the_widest_gap(self) -> None:
        separation, threshold = rec.widest_gap_threshold([140, 150, 160, 520, 530])
        self.assertEqual(360, separation)
        self.assertEqual(340.0, threshold)

    def test_a_single_cluster_is_refused(self) -> None:
        with self.assertRaises(rec.RecoveryError):
            rec.widest_gap_threshold([150, 150, 150])


class Falsification(unittest.TestCase):
    """The consistency verdict must be able to come back false."""

    def test_a_contradiction_is_detected(self) -> None:
        # 0x2000 and 0x4000 conflict, so 0x6000 must conflict too.  Measuring
        # it as a negative is exactly the contradiction the test exists for.
        result = rec.analyse({0x2000, 0x4000}, {0x6000})
        self.assertFalse(result["linearity_consistent"])
        self.assertEqual(["0x6000"], result["contradictions"])

    def test_a_consistent_set_passes(self) -> None:
        result = rec.analyse({0x2000, 0x4000}, {0x8000})
        self.assertTrue(result["linearity_consistent"])
        self.assertEqual([], result["contradictions"])

    def test_restricted_rank_is_labelled_as_restricted(self) -> None:
        """It bounds f on the observed subspace only, never the global rank."""
        result = rec.analyse({0x2000}, {0x4000, 0x8000})
        self.assertEqual(1, result["kernel_dimension_lower_bound"])
        self.assertEqual(3, result["observed_dimension"])
        self.assertEqual(2, result["restricted_rank_upper_bound"])
        self.assertNotIn("rank_upper_bound", result)


class GlobalRankFloor(unittest.TestCase):
    """The one quantity here that bounds the global rank from below."""

    def test_a_closed_pair_proves_rank_two(self) -> None:
        # 0x2000, 0x4000 and their XOR 0x6000 all measured negative.
        k, witness = rec.image_rank_lower_bound({0x2000, 0x4000, 0x6000})
        self.assertEqual(2, k)
        self.assertEqual((0x2000, 0x4000), witness)

    def test_a_missing_combination_proves_nothing_extra(self) -> None:
        """Without 0x6000 measured, the pair cannot be promoted to rank 2."""
        k, _ = rec.image_rank_lower_bound({0x2000, 0x4000})
        self.assertEqual(1, k)

    def test_a_conflicting_combination_blocks_the_pair(self) -> None:
        # 0x6000 absent from the negatives (it conflicts), so images are
        # dependent and the pair must not be counted.
        k, _ = rec.image_rank_lower_bound({0x2000, 0x4000, 0x8000})
        self.assertEqual(1, k)

    def test_no_negatives_gives_no_floor(self) -> None:
        self.assertEqual((0, ()), rec.image_rank_lower_bound(set()))


class HeldOutScoring(unittest.TestCase):
    """The two error directions carry different weight and must stay separate."""

    def test_a_false_conflict_falsifies(self) -> None:
        kernel = rec.span_basis([0x2000])
        score = rec.predict_heldout(kernel, set(), {0x2000})
        self.assertTrue(score["falsified"])
        self.assertEqual(["0x2000"], score["false_conflicts"])

    def test_a_missed_conflict_does_not_falsify(self) -> None:
        kernel = rec.span_basis([0x2000])
        score = rec.predict_heldout(kernel, {0x8000}, set())
        self.assertFalse(score["falsified"])
        self.assertEqual(["0x8000"], score["missed_conflicts"])


class ScopeRules(unittest.TestCase):
    def test_sub_page_differences_are_excluded(self) -> None:
        self.assertEqual(0x2000, rec.MIN_DIFFERENCE)

    def test_sub_page_exclusion_is_applied_when_loading(self) -> None:
        path = V016 / "pa25-27-heldout.jsonl"
        if not path.is_file():
            self.skipTest("retained V016 data is absent on this host")
        dataset = rec.load_dataset(path)
        for value in dataset["conflicts"] | dataset["negatives"]:
            self.assertGreaterEqual(value, rec.MIN_DIFFERENCE)

    def test_a_flat_dataset_is_refused_not_thresholded(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            for index in range(8):
                handle.write(
                    json.dumps(
                        {"type": "difference", "value": hex(0x2000 << index),
                         "median": 150 + index}
                    )
                    + "\n"
                )
            name = handle.name
        with self.assertRaises(rec.RecoveryError):
            rec.load_dataset(Path(name))


class LiveCorpus(unittest.TestCase):
    """The real answer, from the retained runs."""

    @classmethod
    def setUpClass(cls) -> None:
        if not V016.is_dir():
            raise unittest.SkipTest("retained timing corpus is absent on this host")
        cls.result = rec.build(REPO_ROOT)

    def test_most_runs_are_individually_consistent(self) -> None:
        per = self.result["per_dataset"]
        self.assertGreaterEqual(per["datasets_reduced"], 30)
        self.assertGreaterEqual(
            per["datasets_linearity_consistent"], per["datasets_reduced"] - 4
        )

    def test_pooling_fails_and_that_is_the_point(self) -> None:
        """If this ever passes, the per-dataset rule is unnecessary."""
        pooled = self.result["pooled_negative_control"]
        self.assertFalse(
            pooled["linearity_consistent"],
            "pooling became consistent; revisit the BLIND-provenance argument",
        )
        self.assertTrue(
            pooled["pa13_control_wrongly_in_kernel"],
            "the pooled control no longer misplaces PA13; re-derive the scope rule",
        )

    def test_corpus_floor_is_two_and_is_reported_as_a_floor(self) -> None:
        """The retained runs reach rank >= 2.  Reaching 3 needs a measurement
        the corpus does not contain: an XOR-closed triple of negatives."""
        floors = [
            r["global_rank_lower_bound"]
            for r in self.result["per_dataset"]["datasets"].values()
        ]
        self.assertEqual(2, max(floors))

    def test_v016_heldout_is_predicted_without_falsification(self) -> None:
        conflicts, negatives = set(), set()
        for name in ("pa25-27-discriminate.jsonl", "pa25-27-three-column.jsonl"):
            dataset = rec.load_dataset(V016 / name)
            conflicts |= dataset["conflicts"]
            negatives |= dataset["negatives"]
        kernel = rec.span_basis(conflicts)
        heldout = rec.load_dataset(V016 / "pa25-27-heldout.jsonl")
        score = rec.predict_heldout(kernel, heldout["conflicts"], heldout["negatives"])
        self.assertFalse(score["falsified"], score["false_conflicts"])
        self.assertEqual(score["conflicts_total"], score["conflicts_predicted"])
        self.assertEqual(score["negatives_total"], score["negatives_predicted"])

    def test_no_device_or_private_path_emission(self) -> None:
        self.assertFalse(self.result["device_access"])
        self.assertFalse(self.result["mmio_access"])
        self.assertFalse(self.result["allocation_performed"])
        blob = json.dumps(self.result)
        self.assertNotIn("/home/", blob, "a private absolute path reached the output")


if __name__ == "__main__":
    unittest.main()
