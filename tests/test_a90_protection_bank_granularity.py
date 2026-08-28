"""Tests for the Verification 017 protection/bank granularity analysis.

The conclusion rests on region sizes, not on the relation alone, so the tests
below make that dependence explicit: a relation whose lowest contribution sits
higher, or a protected region small enough, would change the answer.  An
analysis that returned "cannot separate" no matter what it was handed would not
be evidence of anything.
"""

from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

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

    def test_exact_source_pins_are_present_and_revalidated(self):
        inputs = bg.source_descriptors()
        self.assertEqual(set(inputs), {"relation_manifest", "high_bit_manifest", "memory_map"})
        for kind, descriptor in inputs.items():
            self.assertEqual(descriptor, bg.SOURCE_PINS[kind])

    def test_source_semantics_cross_check_is_explicit(self):
        semantics = bg.source_semantics()
        self.assertEqual(semantics["relation_rank"], 3)
        self.assertTrue(semantics["relation_unique"])
        self.assertTrue(semantics["relation_kernel_basis_matches_source"])
        self.assertEqual(semantics["relation_kernel_basis_rank"], 9)
        self.assertEqual(len(semantics["relation_kernel_basis"]), 9)
        self.assertEqual(semantics["v016_matches"], {
            "PA25": [14, 21], "PA26": [19], "PA27": [13, 20]
        })
        self.assertEqual(semantics["v016_class"], "TRANSFORM ONLY")
        self.assertEqual(semantics["memory_map"]["protected_region_count"], 5)
        self.assertEqual(semantics["memory_map"]["raw_system_ram_count"], 10)

    def test_changed_relation_basis_is_rejected(self):
        original_read = bg._read_pinned

        def changed_read(path, pin, label):
            data = original_read(path, pin, label)
            if label == "relation_manifest":
                value = json.loads(data)
                value["kernel"]["example_kernel_basis"][0] = "0x100d000"
                return json.dumps(value).encode("utf-8")
            return data

        with mock.patch.object(bg, "_read_pinned", side_effect=changed_read):
            with self.assertRaises(bg.GranularityError):
                bg.source_semantics()

    def test_candidate_relation_kernel_mismatch_is_rejected(self):
        relation = dict(bg.RELATION)
        relation[13] = 0b010
        with self.assertRaises(bg.GranularityError):
            bg.source_semantics(relation)

    def test_changed_memory_map_range_is_rejected(self):
        original_read = bg._read_pinned

        def changed_read(path, pin, label):
            data = original_read(path, pin, label)
            if label == "memory_map":
                return data.replace(b"0x85700000", b"0x85800000", 1)
            return data

        with mock.patch.object(bg, "_read_pinned", side_effect=changed_read):
            with self.assertRaises(bg.GranularityError):
                bg.source_semantics()

    def test_memory_map_parser_rejects_ambiguous_fixed_section(self):
        malformed = (
            "## Fixed reserved ranges\n"
            "| Range | Size | Role | Evidence/status |\n"
            "|---|---:|---|---|\n"
            "| `0x0-0xfff` | 4 KiB | `x` | `PROVED` |\n"
            "| `0x0-0xfff` | 4 KiB | `x` | `PROVED` |\n"
            "## /proc/iomem observations\n"
        )
        with self.assertRaises(bg.GranularityError):
            bg.parse_memory_map_ranges(malformed)

    def test_duplicate_source_json_keys_are_rejected(self):
        with self.assertRaises(bg.GranularityError):
            bg._decode_json_object(b'{"rank": 3, "rank": 4}', "fixture")


class GranularityTests(unittest.TestCase):
    def test_class_changes_every_eight_kilobytes(self):
        self.assertEqual(bg.class_change_granularity(), 0x2000)

    def test_sixty_four_kilobytes_covers_every_class(self):
        self.assertEqual(bg.span_to_cover_all_classes(), 0x10000)

    def test_the_span_is_conditional_on_alignment(self):
        # A 64 KiB block is sufficient only when aligned to that block.  The
        # arbitrary-base guarantee is 128 KiB, because it must contain an
        # aligned 64 KiB sub-block.
        self.assertEqual(bg.span_to_cover_all_classes(aligned=True), 0x10000)
        self.assertEqual(bg.span_to_cover_all_classes(aligned=False), 0x20000)

    def test_every_swept_64_kib_aligned_base_covers_all_classes(self):
        aligned = bg.span_to_cover_all_classes(aligned=True)
        for index in range(512):
            base = 0x80000000 + index * aligned
            result = bg.classes_in_range(base, aligned)
            self.assertEqual(result["classes_covered"], 8, hex(base))

    def test_an_unaligned_region_at_the_aligned_span_can_miss_classes(self):
        aligned = bg.span_to_cover_all_classes(aligned=True)
        seen = {
            bg.classes_in_range(
                0x80000000 + (index << 12), aligned, cap_pages=64
            )["classes_covered"]
            for index in range(512)
        }
        self.assertEqual(seen, {4, 5, 6, 7, 8})

    def test_the_unaligned_span_never_misses_a_class(self):
        unaligned = bg.span_to_cover_all_classes(aligned=False)
        for index in range(512):
            result = bg.classes_in_range(
                0x80000000 + (index << 12), unaligned, cap_pages=64
            )
            self.assertEqual(result["classes_covered"], 8, hex(index << 12))

    def test_coverage_of_a_real_region_does_not_depend_on_its_base(self):
        # The smallest protected range is much wider than either bound; this
        # remains true even when its unknown base is swept across pages.
        smallest = min(size for _, _, size in bg.PROTECTED_REGIONS)
        for index in range(0, 4096, 7):
            result = bg.classes_in_range(
                0x80000000 + (index << 12), smallest, cap_pages=64
            )
            self.assertEqual(result["classes_covered"], 8, hex(index << 12))

    def test_low_bits_span_the_class_space(self):
        # PA13..PA15 provide a basis of GF(2)^3; this is why the covering span
        # is determined before the later, experimentally duplicated bits.
        span = {0}
        for bit in (13, 14, 15):
            span |= {value ^ bg.RELATION[bit] for value in span}
        self.assertEqual(len(span), 8)

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

    def test_unaligned_size_is_rejected_instead_of_truncated(self):
        with self.assertRaises(bg.GranularityError):
            bg.classes_in_range(0x80000000, bg.PAGE_BYTES + 1)


class CountermodelTests(unittest.TestCase):
    def test_same_bank_projection_has_injective_and_noninjective_completions(self):
        result = bg.countermodel_analysis()
        self.assertEqual(result["status"], "PROVED_ABSTRACT_UNDERDETERMINATION")
        self.assertTrue(result["same_bank_projection_different_completions"])
        models = {model["name"]: model for model in result["models"]}
        self.assertTrue(
            models["injective_complete_surrogate"]["injective_over_model_domain"]
        )
        self.assertFalse(
            models["folded_complete_surrogate"]["injective_over_model_domain"]
        )
        self.assertFalse(
            models["bank_only_projection"]["injective_over_model_domain"]
        )
        self.assertEqual(
            models["injective_complete_surrogate"]["bank_output_rows"],
            models["folded_complete_surrogate"]["bank_output_rows"],
        )
        self.assertEqual(
            models["folded_complete_surrogate"]["first_nonzero_null_address"],
            "0x8002000",
        )

    def test_bank_only_countermodel_exhibits_a_known_kernel_witness(self):
        result = bg.countermodel_analysis()
        models = {model["name"]: model for model in result["models"]}
        self.assertEqual(
            models["bank_only_projection"]["first_nonzero_null_address"],
            "0x16000",
        )
        self.assertGreater(
            models["bank_only_projection"]["collision_pair_count"], 0
        )

    def test_protection_ordering_remains_an_abstract_countermodel(self):
        result = bg.protection_ordering_countermodels()
        self.assertEqual(result["status"], "UNKNOWN_FOR_SILICON")
        outcomes = {row["result"] for row in result["models"]}
        self.assertIn("BYPASS_POSSIBLE_IN_ABSTRACT_MODEL", outcomes)
        self.assertIn("BYPASS_BLOCKED_IN_ABSTRACT_MODEL", outcomes)
        self.assertEqual(result["hardware_ordering"], "UNKNOWN")


class AnalysisTests(unittest.TestCase):
    def test_every_real_region_covers_every_class(self):
        result = bg.analyse()
        self.assertTrue(result["all_protected_cover_every_class"])
        self.assertTrue(result["all_unprotected_cover_every_class"])
        self.assertEqual(result["scope"]["range_projection_scope"], "MODEL_PROJECTED_ONLY")
        self.assertEqual(result["bank_granular_check_scope"], "MODEL_PROJECTED_ONLY")
        self.assertTrue(all(
            entry["range_projection_scope"] == "MODEL_PROJECTED_ONLY"
            for entry in result["protected_regions"] + result["unprotected_ranges"]
        ))

    def test_the_conclusion_is_that_a_bank_check_cannot_separate(self):
        self.assertFalse(bg.analyse()["bank_granular_check_can_separate"])

    def test_the_smallest_protected_region_is_still_large_enough(self):
        smallest = min(size for _, _, size in bg.PROTECTED_REGIONS)
        self.assertGreaterEqual(smallest, bg.span_to_cover_all_classes())

    def test_reserved_nested_ranges_are_subtracted_before_comparison(self):
        result = bg.analyse()
        self.assertEqual(
            result["reserved_subtractions"],
            [
                {"name": "rkp_region", "base": "0xb0200000", "size": 0x00200000},
                {"name": "uh_heap_region", "base": "0xb0400000", "size": 0x01400000},
            ],
        )
        self.assertIn(
            "System RAM 0xb1800000-0xbcbfffff",
            {entry["name"] for entry in result["unprotected_ranges"]},
        )
        self.assertNotIn(
            "System RAM 0xb0200000-0xbcbfffff",
            {entry["name"] for entry in result["unprotected_ranges"]},
        )

    def test_overlapping_system_ram_after_subtraction_is_refused(self):
        overlapping = (
            (0x80002000, 0x801FFFFF),
            (0x80100000, 0x802FFFFF),
        )
        with mock.patch.object(bg, "SYSTEM_RAM", overlapping):
            with self.assertRaises(bg.GranularityError):
                bg.analyse()

    def test_a_relation_confined_to_high_bits_would_change_the_answer(self):
        # Not a claim about this device -- a check that the analysis is
        # sensitive to its input rather than always returning the same verdict.
        high_only = {bit: vector for bit, vector in bg.RELATION.items()
                     if bit >= 26}
        result = bg.classes_in_range(0xB0000000, 0x200000, high_only)
        self.assertLess(result["classes_covered"], 8)

    def test_public_manifest_is_deterministic_and_no_clobber(self):
        result = bg.analyse()
        encoded = bg.encode_public(result)
        self.assertIn(b"ALLOCATION_OFFSET_MODEL_COORDINATES", encoded)
        self.assertNotIn(b"/home/", encoded)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            publication = bg.write_public(output, result)
            self.assertEqual(publication["mode"], "0644")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            self.assertEqual(output.read_bytes(), encoded)
            with self.assertRaises(bg.GranularityError):
                bg.write_public(output, result)
            self.assertEqual(json.loads(output.read_text())["classification"], "CLASS C (TRANSFORM ONLY)")

            sentinel = Path(directory) / "sentinel"
            sentinel.write_bytes(b"do not clobber")
            link = Path(directory) / "manifest-link.json"
            link.symlink_to(sentinel)
            with self.assertRaises(bg.GranularityError):
                bg.write_public(link, result)
            self.assertEqual(sentinel.read_bytes(), b"do not clobber")


if __name__ == "__main__":
    unittest.main()
