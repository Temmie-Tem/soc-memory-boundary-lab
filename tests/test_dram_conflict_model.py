from __future__ import annotations

import unittest

from tools import dram_conflict_model as model
from tools import gf2


class DiagnosticModelTests(unittest.TestCase):
    def test_selection_has_five_single_bit_rows(self) -> None:
        rows = model.diagnostic_selection_rows()
        self.assertEqual(len(rows), 5)
        for row in rows:
            self.assertEqual(row.bit_count(), 1, "diagnostic model contains no XOR term")

    def test_selection_bits_match_experiment_011(self) -> None:
        rows = model.diagnostic_selection_rows()
        selected = [row.bit_length() - 1 for row in rows]
        self.assertEqual(
            selected,
            list(model.DIAGNOSTIC_BANK_BITS) + list(model.DIAGNOSTIC_CHANNEL_BITS),
        )

    def test_selection_is_full_rank(self) -> None:
        rows = model.diagnostic_selection_rows()
        self.assertEqual(model.selection_rank(rows), 5)

    def test_kernel_dimension_complements_rank(self) -> None:
        rows = model.diagnostic_selection_rows()
        basis = model.kernel_basis(rows)
        self.assertEqual(len(basis), model.WIDTH - 5)

    def test_kernel_vectors_do_not_change_selection(self) -> None:
        rows = model.diagnostic_selection_rows()
        for vector in model.kernel_basis(rows):
            self.assertEqual(gf2.apply(rows, vector, model.WIDTH), 0)


class ConflictPredictionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = model.diagnostic_selection_rows()

    def test_row_bit_difference_alone_conflicts(self) -> None:
        # differs only in a row bit: same bank, same channel, different row
        self.assertTrue(model.predicts_conflict(self.rows, 1 << 20))

    def test_bank_bit_difference_does_not_conflict(self) -> None:
        difference = (1 << 20) | (1 << 13)
        self.assertFalse(model.predicts_conflict(self.rows, difference))

    def test_channel_bit_difference_does_not_conflict(self) -> None:
        difference = (1 << 20) | (1 << 9)
        self.assertFalse(model.predicts_conflict(self.rows, difference))

    def test_same_bank_same_row_is_not_a_conflict(self) -> None:
        # a column-only difference stays in the open row: a row hit, not a conflict
        difference = 1 << 4
        self.assertTrue(model.same_selection(self.rows, difference))
        self.assertFalse(model.predicts_conflict(self.rows, difference))


class XorInjectionTests(unittest.TestCase):
    """The negative control: a hidden hash the diagnostic formula cannot express."""

    def setUp(self) -> None:
        self.diagnostic = model.diagnostic_selection_rows()
        # bank[0] = PA[13] ^ PA[17]
        self.hashed = model.with_xor_term(self.diagnostic, output_bit=0, address_bit=17)

    def test_injection_changes_one_row_only(self) -> None:
        differing = [
            index
            for index, (a, b) in enumerate(zip(self.diagnostic, self.hashed))
            if a != b
        ]
        self.assertEqual(differing, [0])
        self.assertEqual(self.hashed[0].bit_count(), 2)

    def test_injected_model_is_still_full_rank(self) -> None:
        self.assertEqual(model.selection_rank(self.hashed), 5)

    def test_models_are_distinguishable_and_witness_is_the_xor_pair(self) -> None:
        candidates = model.single_and_pair_differences()
        witnesses = model.distinguishing_differences(
            self.diagnostic, self.hashed, candidates
        )
        self.assertIn((1 << 13) | (1 << 17), witnesses)

    def test_witness_conflicts_under_hash_but_not_under_diagnostic(self) -> None:
        witness = (1 << 13) | (1 << 17)
        self.assertTrue(model.predicts_conflict(self.hashed, witness))
        self.assertFalse(model.predicts_conflict(self.diagnostic, witness))

    def test_row_spaces_differ(self) -> None:
        self.assertFalse(model.same_row_space(self.diagnostic, self.hashed))


class ProtocolTests(unittest.TestCase):
    """The two-phase device protocol, exercised against known ground truth."""

    PIVOT = 20

    def run_protocol(self, truth) -> tuple:
        phase1 = model.synthesize(truth, model.pivot_probe_set(self.PIVOT))
        suspects = model.suspect_bits(phase1, self.PIVOT)
        phase2 = model.synthesize(
            truth, model.refinement_probe_set(suspects, self.PIVOT)
        )
        return phase1 + phase2, suspects

    def test_pivot_must_be_a_row_bit(self) -> None:
        with self.assertRaises(model.ModelError):
            model.pivot_probe_set(13)

    def test_phase_one_costs_one_probe_per_address_bit(self) -> None:
        self.assertEqual(len(model.pivot_probe_set(self.PIVOT)), model.WIDTH)

    def test_phase_two_always_carries_the_verified_row_pivot(self) -> None:
        probes = model.refinement_probe_set((9, 10, 13), self.PIVOT)
        self.assertEqual(len(probes), 3)
        self.assertTrue(all(probe & (1 << self.PIVOT) for probe in probes))
        self.assertTrue(all(probe & model.ROW_MASK for probe in probes))

    def test_phase_two_rejects_a_suspect_pivot(self) -> None:
        with self.assertRaises(model.ModelError):
            model.refinement_probe_set((9, self.PIVOT), self.PIVOT)

    def test_pivot_qualifies_selection_only_pair_for_timing(self) -> None:
        # A deliberately rank-deficient selector makes 13^14 a kernel vector.
        # Without the pivot it is a same-row hit; with the pivot it is a
        # measurable different-row conflict.
        rows = list(model.diagnostic_selection_rows())
        rows[0] = (1 << 13) | (1 << 14)
        rows[1] = rows[0]
        pair_only = (1 << 13) | (1 << 14)
        qualified = model.refinement_probe_set((13, 14), self.PIVOT)[0]
        self.assertTrue(model.same_selection(rows, pair_only))
        self.assertFalse(model.predicts_conflict(rows, pair_only))
        self.assertTrue(model.predicts_conflict(rows, qualified))

    def test_diagnostic_suspects_are_exactly_bank_and_channel_bits(self) -> None:
        truth = model.diagnostic_selection_rows()
        _observations, suspects = self.run_protocol(truth)
        self.assertEqual(
            suspects,
            tuple(sorted(model.DIAGNOSTIC_BANK_BITS + model.DIAGNOSTIC_CHANNEL_BITS)),
        )

    def test_recovers_the_diagnostic_model_exactly(self) -> None:
        truth = model.diagnostic_selection_rows()
        observations, _suspects = self.run_protocol(truth)
        recovery = model.recover(observations)
        self.assertTrue(recovery.consistent)
        self.assertTrue(model.protocol_complete(observations, self.PIVOT))
        self.assertEqual(recovery.selection_rank, 5)
        self.assertTrue(model.same_row_space(recovery.selection_rows, truth))

    def test_hidden_hash_adds_a_suspect_phase_one_cannot_explain(self) -> None:
        diagnostic = model.diagnostic_selection_rows()
        hashed = model.with_xor_term(diagnostic, output_bit=0, address_bit=17)
        _observations, suspects = self.run_protocol(hashed)
        self.assertIn(17, suspects, "a row bit joining the suspects is the hash signal")

    def test_recovers_an_injected_hash_and_separates_it_from_the_diagnostic(self) -> None:
        diagnostic = model.diagnostic_selection_rows()
        hashed = model.with_xor_term(diagnostic, output_bit=0, address_bit=17)
        observations, _suspects = self.run_protocol(hashed)

        recovery = model.recover(observations)
        self.assertTrue(recovery.consistent)
        self.assertTrue(model.protocol_complete(observations, self.PIVOT))
        self.assertTrue(model.same_row_space(recovery.selection_rows, hashed))
        self.assertFalse(model.same_row_space(recovery.selection_rows, diagnostic))

    def test_whole_protocol_stays_under_fifty_measurements(self) -> None:
        truth = model.diagnostic_selection_rows()
        observations, _suspects = self.run_protocol(truth)
        self.assertLessEqual(len(observations), 50)


class RecoveryTests(unittest.TestCase):
    def test_partial_probing_is_reported_as_incomplete(self) -> None:
        rows = model.diagnostic_selection_rows()
        partial = model.synthesize(rows, ((1 << 20), (1 << 20) | (1 << 4)))
        recovery = model.recover(partial)
        self.assertTrue(recovery.consistent)
        self.assertFalse(model.protocol_complete(partial, 20))
        self.assertGreater(
            recovery.selection_rank, 5, "partial probing overstates the row space"
        )

    def test_rank_nullity_alone_cannot_certify_completeness(self) -> None:
        rows = model.diagnostic_selection_rows()
        partial = model.synthesize(rows, ((1 << 20), (1 << 20) | (1 << 4)))
        recovery = model.recover(partial)
        self.assertEqual(
            recovery.kernel_dimension + recovery.selection_rank,
            model.WIDTH,
            "holds for any span, complete or not",
        )

    def test_row_hit_observations_are_ignored_not_trusted(self) -> None:
        rows = model.diagnostic_selection_rows()
        # a column-only difference reported as a conflict must not enter the kernel
        observations = (model.Observation(1 << 4, True),)
        recovery = model.recover(observations)
        self.assertEqual(recovery.kernel_basis, ())

    def test_contradictory_observations_are_reported(self) -> None:
        conflicting = model.Observation((1 << 20), True)
        contradicting = model.Observation((1 << 20), False)
        recovery = model.recover((conflicting, contradicting))
        self.assertFalse(recovery.consistent)
        self.assertIn(1 << 20, recovery.inconsistent)


class CrossValidationTests(unittest.TestCase):
    def test_correct_model_agrees_on_every_held_out_difference(self) -> None:
        rows = model.diagnostic_selection_rows()
        holdout = model.synthesize(rows, model.single_and_pair_differences(range(8, 24)))
        agreements, total, mismatched = model.cross_validate(rows, holdout)
        self.assertEqual(agreements, total)
        self.assertEqual(mismatched, ())

    def test_diagnostic_model_fails_against_hashed_ground_truth(self) -> None:
        diagnostic = model.diagnostic_selection_rows()
        hashed = model.with_xor_term(diagnostic, output_bit=0, address_bit=17)
        holdout = model.synthesize(hashed, model.single_and_pair_differences(range(8, 24)))
        agreements, total, mismatched = model.cross_validate(diagnostic, holdout)
        self.assertLess(agreements, total)
        self.assertIn((1 << 13) | (1 << 17), mismatched)


class AddressConstructionTests(unittest.TestCase):
    def test_rank_split_uses_the_experiment_011_boundary(self) -> None:
        self.assertEqual(model.rank_relative(0x80000000), (0, 0))
        self.assertEqual(model.rank_relative(0x140000000), (1, 0))
        self.assertEqual(model.rank_relative(0x140001000), (1, 0x1000))

    def test_address_below_first_rank_is_rejected(self) -> None:
        with self.assertRaises(model.ModelError):
            model.rank_relative(0x1000)

    def test_pair_realises_the_requested_difference(self) -> None:
        low, high = model.pair_for_difference(0x100000, (1 << 13) | (1 << 17))
        self.assertEqual(low ^ high, (1 << 13) | (1 << 17))


if __name__ == "__main__":
    unittest.main()
