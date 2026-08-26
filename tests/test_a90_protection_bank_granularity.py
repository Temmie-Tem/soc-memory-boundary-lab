"""Tests for the Verification 017 protection/bank granularity analysis.

The conclusion rests on region sizes, not on the relation alone, so the tests
below make that dependence explicit: a relation whose lowest contribution sits
higher, or a protected region small enough, would change the answer.  An
analysis that returned "cannot separate" no matter what it was handed would not
be evidence of anything.
"""

from __future__ import annotations

import unittest

from tools import a90_protection_bank_granularity as bg


class BankClassTests(unittest.TestCase):
    def test_zero_address_is_class_zero(self):
        self.assertEqual(bg.bank_class(0), 0)

    def test_a_single_bit_returns_its_contribution(self):
        self.assertEqual(bg.bank_class(1 << 13), 0b001)
        self.assertEqual(bg.bank_class(1 << 15), 0b100)

    def test_contributions_xor(self):
        # f(PA13 ^ PA14) = 001 ^ 010
        self.assertEqual(bg.bank_class((1 << 13) | (1 << 14)), 0b011)

    def test_bits_below_the_relation_do_not_contribute(self):
        self.assertEqual(bg.bank_class(0xFFF), 0)
        self.assertEqual(bg.bank_class(1 << 12), 0)

    def test_experiment_023r_kernel_witnesses_map_to_zero(self):
        # A kernel witness is exactly a difference whose class is zero.
        for witness in (0x16000, 0x2C000, 0x102000, 0x204000):
            self.assertEqual(bg.bank_class(witness), 0, hex(witness))

    def test_known_negatives_do_not_map_to_zero(self):
        for negative in (0x2000, 0x4000, 0x8000, 0x200000):
            self.assertNotEqual(bg.bank_class(negative), 0, hex(negative))


class ConsistencyTests(unittest.TestCase):
    def test_verification_016_agrees_with_the_solved_table(self):
        self.assertTrue(bg.check_v016_consistency()["agrees"])

    def test_a_disagreement_is_reported_not_swallowed(self):
        relation = dict(bg.RELATION)
        relation[25] = 0b111          # was 0b010, equal to PA14 and PA21
        result = bg.check_v016_consistency(relation)
        self.assertFalse(result["agrees"])
        self.assertIn((25, 14), result["disagreements"])


class GranularityTests(unittest.TestCase):
    def test_class_changes_every_eight_kilobytes(self):
        self.assertEqual(bg.class_change_granularity(), 0x2000)

    def test_sixty_four_kilobytes_covers_every_class(self):
        self.assertEqual(bg.span_to_cover_all_classes(), 0x10000)

    def test_a_relation_starting_higher_needs_a_larger_span(self):
        shifted = {bit + 4: vector for bit, vector in bg.RELATION.items()}
        self.assertEqual(bg.class_change_granularity(shifted), 0x2000 << 4)
        self.assertEqual(bg.span_to_cover_all_classes(shifted), 0x10000 << 4)

    def test_a_relation_that_never_reaches_full_rank_is_refused(self):
        with self.assertRaises(bg.GranularityError):
            bg.span_to_cover_all_classes({13: 0b001, 14: 0b001})

    def test_an_empty_relation_is_refused(self):
        with self.assertRaises(bg.GranularityError):
            bg.class_change_granularity({13: 0, 14: 0})


class RangeTests(unittest.TestCase):
    def test_a_large_range_covers_every_class(self):
        result = bg.classes_in_range(0xB0000000, 0x200000)
        self.assertEqual(result["classes_covered"], 8)

    def test_a_range_below_the_covering_span_need_not_cover_every_class(self):
        # This is what makes the conclusion contingent: an 8 KiB protected
        # region would occupy two classes, and a bank-granular check could then
        # tell it from a region occupying the other six.
        result = bg.classes_in_range(0xB0000000, 0x2000)
        self.assertLess(result["classes_covered"], 8)

    def test_a_single_page_occupies_one_class(self):
        result = bg.classes_in_range(0xB0000000, bg.PAGE_BYTES)
        self.assertEqual(result["classes_covered"], 1)

    def test_a_zero_sized_range_is_refused(self):
        with self.assertRaises(bg.GranularityError):
            bg.classes_in_range(0xB0000000, 0)

    def test_page_counting_is_capped_and_says_so(self):
        result = bg.classes_in_range(0x80000000, 1 << 32, cap_pages=1024)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["pages_counted"], 1024)


class AnalysisTests(unittest.TestCase):
    def test_every_real_region_covers_every_class(self):
        result = bg.analyse()
        self.assertTrue(result["all_protected_cover_every_class"])
        self.assertTrue(result["all_unprotected_cover_every_class"])

    def test_the_conclusion_is_that_a_bank_check_cannot_separate(self):
        self.assertFalse(bg.analyse()["bank_granular_check_can_separate"])

    def test_the_smallest_protected_region_is_still_large_enough(self):
        smallest = min(size for _, _, size in bg.PROTECTED_REGIONS)
        self.assertGreaterEqual(smallest, bg.span_to_cover_all_classes())

    def test_a_relation_confined_to_high_bits_would_change_the_answer(self):
        # Not a claim about this device -- a check that the analysis is
        # sensitive to its input rather than always returning the same verdict.
        high_only = {bit: vector for bit, vector in bg.RELATION.items()
                     if bit >= 26}
        result = bg.classes_in_range(0xB0000000, 0x200000, high_only)
        self.assertLess(result["classes_covered"], 8)


if __name__ == "__main__":
    unittest.main()
