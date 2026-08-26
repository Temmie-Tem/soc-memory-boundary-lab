"""Tests for the Experiment 030 low-bit selector analysis.

Every test builds its own synthetic level set.  The central one is that a
difference can leave the conflict class in two opposite directions, and that
only the downward one means the bit selects anything -- which is the
distinction Experiment 014's PA9/PA10 evidence did not draw.
"""

from __future__ import annotations

import json
import unittest

from tools import a90_low_bit_selector_analysis as low


CONFLICT = 538
NON_CONFLICT = 168
SAME_ROW = 19
KERNEL = 0x16000
NEGATIVE = 0x2000
CONTROL = 0x800


def base_measurements() -> dict[int, int]:
    return {KERNEL: CONFLICT, NEGATIVE: NON_CONFLICT, CONTROL: SAME_ROW}


def with_bit(measurements: dict[int, int], bit: int, alone: int,
             with_kernel: int, with_negative: int) -> dict[int, int]:
    value = 1 << bit
    measurements = dict(measurements)
    measurements[value] = alone
    measurements[KERNEL ^ value] = with_kernel
    measurements[NEGATIVE ^ value] = with_negative
    return measurements


class LevelsTest(unittest.TestCase):
    def test_three_reference_levels_are_named(self):
        reference = low.levels(base_measurements(), KERNEL, NEGATIVE, CONTROL)
        self.assertEqual(reference["conflict"], CONFLICT)
        self.assertEqual(reference["non_conflict"], NON_CONFLICT)
        self.assertEqual(reference["same_row"], SAME_ROW)

    def test_missing_level_is_none_not_guessed(self):
        reference = low.levels({}, KERNEL, NEGATIVE, CONTROL)
        self.assertIsNone(reference["conflict"])


class ClassifyTest(unittest.TestCase):
    def setUp(self):
        self.reference = low.levels(base_measurements(), KERNEL, NEGATIVE,
                                    CONTROL)

    def test_inert_bit_leaves_both_witnesses_alone(self):
        self.assertEqual(
            low.classify_bit(20, CONFLICT - 4, NON_CONFLICT - 6, self.reference),
            "INERT")

    def test_selector_pulls_the_conflict_down_to_non_conflict(self):
        self.assertEqual(
            low.classify_bit(20, NON_CONFLICT + 5, NON_CONFLICT - 5,
                             self.reference),
            "SELECTOR")

    def test_bit_that_raises_both_witnesses_equally_is_saturating(self):
        # This is the PA9/PA10 signature: the conflicting and non-conflicting
        # witnesses arrive at the same value, so the bank relation is no
        # longer visible through the metric.
        self.assertEqual(
            low.classify_bit(717, 702, 702, self.reference), "SATURATING")

    def test_leaving_the_class_upward_is_not_a_selector(self):
        # Experiment 014 read "left the conflict class" as evidence of a
        # selection component.  Leaving it upward is a different event.
        verdict = low.classify_bit(717, 702, 702, self.reference)
        self.assertNotEqual(verdict, "SELECTOR")

    def test_uneven_movement_is_modulating(self):
        self.assertEqual(
            low.classify_bit(22, 367, -4, self.reference), "MODULATING")

    def test_missing_measurement_is_incomplete_not_assumed(self):
        self.assertEqual(
            low.classify_bit(None, 500, 170, self.reference), "INCOMPLETE")


class AnalyseTest(unittest.TestCase):
    def test_an_all_inert_sweep_reports_no_selector(self):
        measurements = base_measurements()
        for bit in low.LOW_BITS:
            measurements = with_bit(measurements, bit, 20, CONFLICT,
                                    NON_CONFLICT)
        result = low.analyse(measurements)
        self.assertFalse(result["any_selector"])
        self.assertEqual(sorted(result["by_verdict"]["INERT"]),
                         list(low.LOW_BITS))

    def test_a_planted_selector_is_reported(self):
        measurements = base_measurements()
        for bit in low.LOW_BITS:
            measurements = with_bit(measurements, bit, 20, CONFLICT,
                                    NON_CONFLICT)
        measurements = with_bit(measurements, 9, 20, NON_CONFLICT,
                                NON_CONFLICT)
        result = low.analyse(measurements)
        self.assertTrue(result["any_selector"])
        self.assertEqual(result["by_verdict"]["SELECTOR"], [9])

    def test_saturating_bits_are_listed_separately(self):
        measurements = base_measurements()
        for bit in low.LOW_BITS:
            measurements = with_bit(measurements, bit, 20, CONFLICT,
                                    NON_CONFLICT)
        measurements = with_bit(measurements, 9, 717, 702, 702)
        measurements = with_bit(measurements, 10, 453, 461, 463)
        result = low.analyse(measurements)
        self.assertEqual(result["saturating_bits"], [9, 10])
        self.assertFalse(result["any_selector"])

    def test_tolerance_is_explicit(self):
        measurements = base_measurements()
        for bit in low.LOW_BITS:
            measurements = with_bit(measurements, bit, 20, CONFLICT + 50,
                                    NON_CONFLICT + 50)
        loose = low.analyse(measurements, tolerance=60)
        tight = low.analyse(measurements, tolerance=10)
        self.assertEqual(loose["by_verdict"].get("INERT"), list(low.LOW_BITS))
        self.assertNotIn("INERT", tight["by_verdict"])


class LoadTest(unittest.TestCase):
    def test_medians_are_read_from_probe_output(self):
        lines = [json.dumps({"type": "difference", "value": "0x16000",
                             "median": 538, "p10": 517, "p90": 569}),
                 json.dumps({"type": "pair", "value": "0x16000",
                             "offset": "0x0", "delta": 540}),
                 json.dumps({"type": "context", "cpu": 7})]
        loaded = low.load_medians("\n".join(lines))
        self.assertEqual(loaded, {0x16000: 538})

    def test_blank_lines_are_ignored(self):
        self.assertEqual(low.load_medians("\n\n  \n"), {})


if __name__ == "__main__":
    unittest.main()
