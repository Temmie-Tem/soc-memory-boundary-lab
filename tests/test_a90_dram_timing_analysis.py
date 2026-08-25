from __future__ import annotations

import unittest

from tools import a90_dram_timing_analysis as analysis
from tools import gf2


class RecoveredMatrixTests(unittest.TestCase):
    def test_recovered_rows_are_rank_five(self) -> None:
        self.assertEqual(
            gf2.rank(analysis.recovered_selection_rows(), analysis.OBSERVED_WIDTH),
            5,
        )

    def test_every_recovered_row_relation_is_in_kernel(self) -> None:
        for difference in analysis.RELATION_DIFFERENCES.values():
            self.assertTrue(analysis.is_recovered_kernel(difference))

    def test_heldout_vectors_are_predicted_without_fitting_them(self) -> None:
        for difference in analysis.HELDOUT_KERNEL_DIFFERENCES:
            self.assertTrue(analysis.is_recovered_kernel(difference))
        for difference in analysis.HELDOUT_NEGATIVE_DIFFERENCES:
            self.assertFalse(analysis.is_recovered_kernel(difference))

    def test_channel_perturbations_leave_known_bank_kernel(self) -> None:
        witness = analysis.RELATION_DIFFERENCES[16]
        self.assertTrue(analysis.is_recovered_kernel(witness))
        self.assertFalse(analysis.is_recovered_kernel(witness ^ (1 << 9)))
        self.assertFalse(analysis.is_recovered_kernel(witness ^ (1 << 10)))

    def test_diagnostic_and_observed_row_spaces_differ(self) -> None:
        self.assertFalse(
            analysis.same_row_space(
                analysis.recovered_selection_rows(),
                analysis.diagnostic_low24_rows(),
            )
        )

    def test_bank_equations_match_row_to_basis_table(self) -> None:
        rows = analysis.recovered_selection_rows()[:3]
        for row_bit, bank_basis in analysis.ROW_TO_BANK_BASIS.items():
            difference = (1 << row_bit) ^ sum(1 << bit for bit in bank_basis)
            self.assertEqual(gf2.apply(rows, difference, analysis.OBSERVED_WIDTH), 0)


class ExactEvidenceIntegrationTests(unittest.TestCase):
    def test_exact_live_manifests_cross_validate_recovered_matrix(self) -> None:
        evidence_root = analysis.REPO_ROOT / "evidence/private"
        if not evidence_root.exists():
            self.skipTest("exact private Experiment-014 evidence is unavailable")
        manifests = {
            experiment_id: analysis.load_manifest(
                evidence_root / experiment_id / "manifest.json"
            )
            for experiment_id in analysis.REQUIRED_EXPERIMENTS
        }
        result = analysis.analyze(manifests)
        self.assertEqual(
            result["classification"],
            "NORMAL_RAM_HIDDEN_BANK_HASH_PROVED_NO_ALIAS_OR_BYPASS",
        )
        self.assertEqual(result["recovered_low24_selection"]["rank"], 5)
        self.assertEqual(result["controls"]["nonoverlap"]["gap_milli_ticks"], 314)
        self.assertEqual(len(result["controls"]["channel_perturbations"]), 2)


if __name__ == "__main__":
    unittest.main()
