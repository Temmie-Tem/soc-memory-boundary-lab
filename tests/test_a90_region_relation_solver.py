"""Tests for the Experiment 023R relation solver.

Every test builds its own synthetic measurement set, so none needs device
output.  Several tests exist specifically to hold the repairs that took
Experiment 023 from `NO-GO` to evidence: that the classifier is not Experiment
014's threshold imported, that the base offset is solved rather than assumed,
that all eight contributions for a new bit are scored rather than one witness
read, and that the model order is measured rather than assumed.
"""

from __future__ import annotations

import json
import unittest

from tools import a90_region_relation_solver as solver


EXTENDED = dict(solver.BASE_RELATION)
EXTENDED[24] = 0b110


def difference_record(value: int, median: int, p10: int | None = None,
                      p90: int | None = None, phase: str = "phaseA") -> str:
    return json.dumps({
        "schema": "a90_region_probe_r_v1", "type": "difference",
        "value": f"0x{value:x}", "pairs": 64,
        "p10": median - 20 if p10 is None else p10, "median": median,
        "p90": median + 20 if p90 is None else p90,
    })


def pair_record(value: int, offset: int, delta: int) -> str:
    return json.dumps({
        "schema": "a90_region_probe_r_v1", "type": "pair",
        "value": f"0x{value:x}", "offset": f"0x{offset:x}", "delta": delta,
    })


def spread_offsets(count: int, size: int = 0x2000000) -> list[int]:
    """Page-aligned offsets that vary in their low bits, as the probe's
    `spread` mode produces.  Evenly spaced offsets cannot constrain a base
    offset smaller than their spacing."""
    offsets, state = [], 0x5da9f0e3c17b2846
    for _ in range(count):
        state = (state * 0x5851f42d4c957f2d + 0x14057b7ef767814f) & ((1 << 64) - 1)
        offsets.append(((state >> 17) % (size // 0x1000)) * 0x1000)
    return offsets


def labelled(value: int, label: str, phase: str = "phaseA") -> dict:
    return {"difference": value, "label": label, "median": 0, "p10": 0,
            "p90": 0, "phase": phase}


class VectorTest(unittest.TestCase):
    def test_single_bits_take_their_declared_contribution(self):
        for bit, contribution in solver.BASE_RELATION.items():
            self.assertEqual(solver.vector(1 << bit, solver.BASE_RELATION),
                             contribution)

    def test_xor_of_equal_contributions_is_a_conflict(self):
        # PA13 and PA20 both contribute b0, so their difference is in the kernel.
        self.assertEqual(solver.vector(0x102000, solver.BASE_RELATION), 0)

    def test_single_bit_is_never_a_conflict(self):
        for bit in solver.BASE_RELATION:
            self.assertNotEqual(solver.vector(1 << bit, solver.BASE_RELATION), 0)

    def test_covered_rejects_a_bit_outside_the_relation(self):
        self.assertTrue(solver.covered(0x102000, solver.BASE_RELATION))
        self.assertFalse(solver.covered(1 << 24, solver.BASE_RELATION))
        self.assertTrue(solver.covered(1 << 24, EXTENDED))

    def test_covered_ignores_sub_page_bits(self):
        self.assertTrue(solver.covered(0x102000, solver.BASE_RELATION))


class PhysicalDifferenceTest(unittest.TestCase):
    def test_aligned_base_preserves_the_offset_difference(self):
        for offset in (0x0, 0xa000, 0x1798000):
            self.assertEqual(
                solver.physical_difference(0xA6000000, offset, 0x102000),
                0x102000)

    def test_offset_base_can_change_the_realised_difference(self):
        # A base offset only matters when the difference names a bit at which
        # adding it carries differently for the two members of the pair.
        self.assertNotEqual(
            solver.physical_difference(0xA6200000, 0x200000, 0x204000),
            0x204000)

    def test_offset_base_is_invisible_to_a_low_difference(self):
        # This is exactly why Experiment 023's replay could not verify its own
        # base assumption: low differences reproduce the same labels either way.
        self.assertEqual(
            solver.physical_difference(0xA6200000, 0x11c2000, 0x16000),
            0x16000)


class SeparationTest(unittest.TestCase):
    def test_threshold_falls_in_the_widest_gap(self):
        result = solver.separation_threshold([170, 180, 190, 540, 550, 560])
        self.assertEqual(result["low_max"], 190)
        self.assertEqual(result["high_min"], 540)
        self.assertEqual(result["gap"], 350)
        self.assertEqual(result["threshold"], 365)

    def test_threshold_uses_no_prior_run(self):
        # Shifting every measurement shifts the threshold with it; the split is
        # a property of the data, not of Experiment 014's numbers.
        base = [170, 180, 540, 550]
        shifted = [value + 1000 for value in base]
        self.assertEqual(
            solver.separation_threshold(shifted)["threshold"],
            solver.separation_threshold(base)["threshold"] + 1000)

    def test_weak_separation_reports_a_small_gap(self):
        result = solver.separation_threshold([100, 110, 120, 130])
        self.assertLessEqual(result["gap"], 10)

    def test_degenerate_input_is_handled(self):
        self.assertIsNone(solver.separation_threshold([])["threshold"])
        self.assertIsNone(solver.separation_threshold([5])["threshold"])


class ClassifyTest(unittest.TestCase):
    def test_bounds_are_respected(self):
        self.assertEqual(solver.classify(600, 536, 222), "KERNEL")
        self.assertEqual(solver.classify(200, 536, 222), "NEGATIVE")

    def test_value_between_bounds_is_ambiguous_not_nearest(self):
        self.assertEqual(solver.classify(400, 536, 222), "AMBIGUOUS")
        self.assertEqual(solver.classify(300, 536, 222), "AMBIGUOUS")


class BaseOffsetTest(unittest.TestCase):
    def _pairs(self, base: int, differences: list[int], offsets: list[int]):
        pairs = []
        for difference in differences:
            for offset in offsets:
                realised = solver.physical_difference(base, offset, difference)
                if not solver.covered(realised, solver.BASE_RELATION):
                    continue
                label = ("KERNEL" if solver.vector(realised, solver.BASE_RELATION) == 0
                         else "NEGATIVE")
                pairs.append({"difference": difference, "offset": offset,
                              "label": label})
        return pairs

    def test_aligned_allocation_is_recovered(self):
        offsets = spread_offsets(64)
        pairs = self._pairs(solver.REGION_BASE,
                            [0x204000, 0x408000, 0x212000, 0x16000], offsets)
        result = solver.solve_base_offset(pairs, solver.BASE_RELATION)
        self.assertTrue(result["resolved"])
        self.assertEqual(result["offset"], "0x0")

    def test_shifted_allocation_is_recovered(self):
        offsets = spread_offsets(64)
        pairs = self._pairs(solver.REGION_BASE + 0x200000,
                            [0x204000, 0x408000, 0x212000, 0x16000], offsets)
        result = solver.solve_base_offset(pairs, solver.BASE_RELATION)
        self.assertTrue(result["resolved"])
        self.assertEqual(result["offset"], "0x200000")

    def test_low_differences_alone_cannot_resolve_the_offset(self):
        # The defect Experiment 023 had: differences below the bits at which a
        # candidate offset carries leave several offsets consistent, so
        # agreement with 014 was never a test of the base assumption.
        offsets = spread_offsets(64)
        pairs = self._pairs(solver.REGION_BASE, [0x16000, 0x2c000, 0x102000],
                            offsets)
        result = solver.solve_base_offset(pairs, solver.BASE_RELATION)
        self.assertGreater(result["candidate_count"], 1)
        self.assertFalse(result["resolved"])

    def test_ambiguous_pairs_do_not_constrain(self):
        pairs = [{"difference": 0x204000, "offset": 0xa000, "label": "AMBIGUOUS"}]
        result = solver.solve_base_offset(pairs, solver.BASE_RELATION)
        self.assertEqual(result["constraining_pairs"], 0)


class NewBitTest(unittest.TestCase):
    def _measurements(self, contribution: int) -> list[dict]:
        extended = dict(solver.BASE_RELATION)
        extended[24] = contribution
        probes = [1 << 24, 0x1002000, 0x1004000, 0x1010000, 0x1008000,
                  0x1080000, 0x1020000, 0x1040000]
        return [labelled(d, "KERNEL" if solver.vector(d, extended) == 0
                         else "NEGATIVE") for d in probes]

    def test_every_contribution_is_recovered(self):
        for contribution in range(8):
            result = solver.discriminate_new_bit(
                self._measurements(contribution), solver.BASE_RELATION, 24)
            self.assertTrue(result["resolved"], contribution)
            self.assertEqual(result["contribution"], f"0b{contribution:03b}")

    def test_one_witness_identifies_but_cannot_corroborate(self):
        # A single conflicting witness does pin the contribution: 0x1020000 is
        # PA24 ^ PA17, so a conflict forces PA24 to match PA17.  What it cannot
        # do is notice being wrong -- which is the defect in reading one
        # witness, rather than any inability to identify a value.
        single = [labelled(0x1020000, "KERNEL")]
        self.assertEqual(
            solver.discriminate_new_bit(single, solver.BASE_RELATION, 24)["contribution"],
            "0b110")

        mislabelled = [labelled(0x1040000, "KERNEL")]
        wrong = solver.discriminate_new_bit(mislabelled, solver.BASE_RELATION, 24)
        self.assertTrue(wrong["resolved"])
        self.assertNotEqual(wrong["contribution"], "0b110")

    def test_exhaustive_set_detects_a_mislabelled_measurement(self):
        # The same error inside the full eight-probe set leaves no survivor,
        # so it is reported instead of silently answered.
        probes = [1 << 24, 0x1002000, 0x1004000, 0x1010000, 0x1008000,
                  0x1080000, 0x1020000, 0x1040000]
        corrupted = [labelled(d, "KERNEL" if d == 0x1040000
                              else ("KERNEL" if solver.vector(d, EXTENDED) == 0
                                    else "NEGATIVE")) for d in probes]
        result = solver.discriminate_new_bit(corrupted, solver.BASE_RELATION, 24)
        self.assertEqual(result["survivor_count"], 0)
        self.assertFalse(result["resolved"])

    def test_contradictory_measurements_leave_no_survivor(self):
        both = [labelled(0x1020000, "KERNEL"), labelled(0x1040000, "KERNEL")]
        result = solver.discriminate_new_bit(both, solver.BASE_RELATION, 24)
        self.assertEqual(result["survivor_count"], 0)


class SpanTest(unittest.TestCase):
    def test_span_dimension_counts_independent_vectors(self):
        self.assertEqual(len(solver._span([0x2000, 0x4000, 0x6000])), 2)

    def test_membership_follows_the_span(self):
        basis = solver._span([0x2000, 0x4000])
        self.assertTrue(solver._in_span(0x6000, basis))
        self.assertFalse(solver._in_span(0x8000, basis))


class KernelAnalysisTest(unittest.TestCase):
    def _full_kernel(self) -> list[int]:
        return [d for d in range(0x2000, 1 << 25, 0x2000)
                if solver.covered(d, EXTENDED) and solver.vector(d, EXTENDED) == 0]

    def test_full_kernel_is_unique(self):
        bits = sorted(EXTENDED)
        kernel = self._full_kernel()
        negative = [1 << bit for bit in EXTENDED]
        measurements = ([labelled(d, "KERNEL") for d in kernel] +
                        [labelled(d, "NEGATIVE") for d in negative])
        result = solver.kernel_analysis(measurements, bits)
        self.assertEqual(result["span_dimension"], 9)
        self.assertEqual(result["consistent_kernel_count"], 1)
        self.assertTrue(result["unique"])

    def test_partial_span_is_not_unique(self):
        bits = sorted(EXTENDED)
        kernel = [d for d in self._full_kernel() if d < 0x200000]
        measurements = ([labelled(d, "KERNEL") for d in kernel] +
                        [labelled(1 << bit, "NEGATIVE") for bit in EXTENDED])
        result = solver.kernel_analysis(measurements, bits)
        self.assertLess(result["span_dimension"], 9)
        self.assertGreater(result["consistent_kernel_count"], 1)
        self.assertFalse(result["unique"])

    def test_extension_pool_is_not_restricted_to_single_bits(self):
        # No single address bit lies in the kernel, so an extension pool built
        # only from single bits finds nothing and reports a false zero.
        bits = sorted(EXTENDED)
        kernel = [d for d in self._full_kernel() if d < 0x200000]
        measurements = ([labelled(d, "KERNEL") for d in kernel] +
                        [labelled(1 << bit, "NEGATIVE") for bit in EXTENDED])
        result = solver.kernel_analysis(measurements, bits)
        self.assertGreater(result["consistent_kernel_count"], 0)

    def test_negative_inside_the_span_is_a_contradiction(self):
        bits = sorted(EXTENDED)
        measurements = [labelled(0x16000, "KERNEL"), labelled(0x2c000, "KERNEL"),
                        labelled(0x3a000, "NEGATIVE")]
        result = solver.kernel_analysis(measurements, bits)
        self.assertEqual(result["contradictions"], ["0x3a000"])
        self.assertFalse(result["unique"])


class RankAnalysisTest(unittest.TestCase):
    def test_rank_three_is_the_only_survivor(self):
        bits = sorted(EXTENDED)
        kernel = [d for d in range(0x2000, 1 << 25, 0x2000)
                  if solver.covered(d, EXTENDED) and solver.vector(d, EXTENDED) == 0]
        measurements = ([labelled(d, "KERNEL") for d in kernel] +
                        [labelled(1 << bit, "NEGATIVE") for bit in EXTENDED])
        result = solver.rank_analysis(measurements, bits)
        self.assertEqual(result["surviving_ranks"], [3])
        self.assertTrue(result["resolved"])
        self.assertEqual(result["by_rank"][4]["verdict"],
                         "REFUTED_SPAN_EXCEEDS_KERNEL")

    def test_higher_rank_is_refuted_by_span_not_by_assumption(self):
        bits = sorted(EXTENDED)
        kernel = [d for d in range(0x2000, 1 << 25, 0x2000)
                  if solver.covered(d, EXTENDED) and solver.vector(d, EXTENDED) == 0]
        measurements = [labelled(d, "KERNEL") for d in kernel]
        result = solver.rank_analysis(measurements, bits, ranks=(4,))
        self.assertEqual(result["by_rank"][4]["verdict"],
                         "REFUTED_SPAN_EXCEEDS_KERNEL")


class AnalyseTest(unittest.TestCase):
    def _phase_text(self) -> dict[str, str]:
        # A kernel set that spans the full nine dimensions; a smaller set
        # leaves the relation unpinned, which is what Experiment 023 had.
        kernel, basis = [], []
        for value in range(0x2000, 1 << 25, 0x2000):
            if not solver.covered(value, EXTENDED):
                continue
            if solver.vector(value, EXTENDED) != 0:
                continue
            if not solver._in_span(value, basis):
                kernel.append(value)
                basis = solver._span(basis + [value])
            if len(basis) == 9:
                break
        negative = [1 << bit for bit in solver.BASE_RELATION]
        lines_a = ([difference_record(d, 550) for d in kernel] +
                   [difference_record(d, 175) for d in negative])
        probes = [1 << 24, 0x1002000, 0x1004000, 0x1010000, 0x1008000,
                  0x1080000, 0x1020000, 0x1040000]
        lines_c = [difference_record(d, 550 if solver.vector(d, EXTENDED) == 0
                                    else 175) for d in probes]
        pairs = []
        for difference in (0x204000, 0x408000, 0x212000, 0x16000):
            for offset in spread_offsets(64):
                realised = solver.physical_difference(solver.REGION_BASE, offset,
                                                      difference)
                delta = 550 if solver.vector(realised, solver.BASE_RELATION) == 0 else 175
                pairs.append(pair_record(difference, offset, delta))
        return {"phaseA": "\n".join(lines_a),
                "phaseC": "\n".join(lines_c + pairs)}

    def test_end_to_end_resolves_every_gate(self):
        result = solver.analyse(self._phase_text())
        self.assertTrue(result["comparable_to_014"])
        self.assertTrue(result["pa_provenance"]["base_offset"]["resolved"])
        self.assertEqual(result["pa_provenance"]["base_offset"]["offset"], "0x0")
        self.assertTrue(result["new_bit"]["resolved"])
        self.assertEqual(result["new_bit"]["contribution"], "0b110")
        self.assertTrue(result["kernel"]["unique"])
        self.assertEqual(result["rank"]["rank"], 3)

    def test_stride_phase_pairs_do_not_constrain_the_offset(self):
        # Evenly spaced offsets are blind to the base offset by construction,
        # so counting them as constraints would overstate the evidence.
        text = self._phase_text()
        result = solver.analyse(text, stride_phases=("phaseA", "phaseC"))
        self.assertEqual(
            result["pa_provenance"]["base_offset"]["constraining_pairs"], 0)


if __name__ == "__main__":
    unittest.main()
