"""Tests for the Experiment 030 low-bit selector analysis.

Every test builds its own synthetic level set.  The central one is that a
difference can leave the conflict class in two opposite directions, and that
only the downward one means the bit selects anything -- which is the
distinction Experiment 014's PA9/PA10 evidence did not draw.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

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

    def test_phase_loader_keeps_context_and_pa_provenance(self):
        text = "\n".join([
            json.dumps({"type": "context", "offset_mode": "stride",
                        "pairs": 32}),
            json.dumps({"type": "ion_heap", "name": "qsecom",
                        "heap_id": 27}),
            json.dumps({"type": "pa_provenance", "status": "BLIND"}),
            json.dumps({"type": "difference", "value": "0x2000",
                        "median": 168}),
        ])
        loaded = low.load_phase(text)
        self.assertEqual(loaded["context"]["offset_mode"], "stride")
        self.assertEqual(loaded["ion_heap"]["heap_id"], 27)
        self.assertEqual(loaded["pa_provenance"][0]["status"], "BLIND")
        self.assertEqual(loaded["measurements"], {0x2000: 168})

    def test_blind_pagemap_contiguity_is_not_effective(self):
        loaded = low.load_phase(json.dumps({
            "type": "pa_provenance",
            "source": "pagemap",
            "status": "BLIND",
            "contiguous": True,
        }))
        record = loaded["pa_provenance"][0]
        self.assertNotIn("contiguous", record)
        self.assertTrue(record["reported_contiguous"])
        self.assertEqual(record["effective_contiguity"], "UNKNOWN")

    def test_conflicting_duplicate_medians_in_one_phase_are_rejected(self):
        lines = [
            json.dumps({"type": "difference", "value": "0x200",
                        "median": 717}),
            json.dumps({"type": "difference", "value": "0x200",
                        "median": 762}),
        ]
        with self.assertRaises(ValueError):
            low.load_medians("\n".join(lines))


class PhaseAnalysisTest(unittest.TestCase):
    def _phase_c(self):
        measurements = {
            0x16000: 544,
            0x2000: 172,
            0x800: 21,
        }
        return with_bit(with_bit(measurements, 9, 717, 702, 702),
                        10, 453, 461, 463)

    def _phase_d(self):
        measurements = {
            0x16000: 538,
            0x2000: 168,
            0x800: 19,
        }
        return with_bit(with_bit(measurements, 9, 762, 753, 760),
                        10, 503, 461, 463)

    def test_duplicate_phase_measurements_and_modes_are_retained(self):
        result = low.analyse_phases(
            {"phaseD": self._phase_d(), "phaseC": self._phase_c()},
            {
                "phaseC": {"offset_mode": "spread", "pairs": 64},
                "phaseD": {"offset_mode": "stride", "pairs": 32},
            },
        )
        self.assertEqual(result["phase_measurements"]["phaseC"]["0x200"],
                         717)
        self.assertEqual(result["phase_measurements"]["phaseD"]["0x200"],
                         762)
        self.assertEqual(result["phase_results"]["phaseC"]["mode"],
                         "spread")
        self.assertEqual(result["phase_results"]["phaseD"]["mode"],
                         "stride")
        self.assertEqual(result["phase_results"]["phaseC"]["bits"][9]["verdict"],
                         "SATURATING")
        self.assertEqual(result["phase_results"]["phaseD"]["bits"][9]["verdict"],
                         "SATURATING")
        self.assertEqual(result["verdict_consistency"]["bits"][9]["status"],
                         "CONSISTENT")
        self.assertEqual(result["consensus"]["saturating_bits"], [9, 10])

    def test_disagreement_is_explicit_and_not_collapsed(self):
        selector = {
            0x16000: CONFLICT,
            0x2000: NON_CONFLICT,
            0x800: SAME_ROW,
        }
        selector = with_bit(selector, 9, 20, NON_CONFLICT, NON_CONFLICT)
        result = low.analyse_phases(
            {"phaseC": selector, "phaseD": self._phase_d()}
        )
        consistency = result["verdict_consistency"]
        self.assertFalse(consistency["all_consistent"])
        self.assertEqual(consistency["bits"][9]["verdict"],
                         "DISAGREEMENT")
        self.assertEqual(consistency["bits"][9]["phase_verdicts"],
                         {"phaseC": "SELECTOR", "phaseD": "SATURATING"})
        self.assertNotIn(9, result["consensus"]["saturating_bits"])
        with self.assertRaises(ValueError):
            low.analyse_phases(
                {"phaseC": selector, "phaseD": self._phase_d()},
                require_consistent=True,
            )

    def test_phase_output_is_order_independent(self):
        contexts = {
            "phaseC": {"offset_mode": "spread"},
            "phaseD": {"offset_mode": "stride"},
        }
        first = low.analyse_phases(
            {"phaseC": self._phase_c(), "phaseD": self._phase_d()}, contexts
        )
        second = low.analyse_phases(
            {"phaseD": self._phase_d(), "phaseC": self._phase_c()}, contexts
        )
        self.assertEqual(first, second)


class PublishedManifestTest(unittest.TestCase):
    def test_manifest_keeps_phase_d_pa10_incomplete_and_narrows_channel_claim(self):
        path = Path(__file__).resolve().parents[1] / (
            "evidence/manifests/030-low-bit-selector-20260826-01.manifest.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            document["phase_results"]["phaseD"]["bits"]["10"]["verdict"],
            "INCOMPLETE",
        )
        self.assertEqual(document["build"]["status"], "UNKNOWN")
        self.assertEqual(
            document["device_binding"]["status"],
            "SUPPORTED_RETAINED_DEVICE_CONTEXT",
        )
        self.assertEqual(document["recovery"]["status"], "UNKNOWN")
        self.assertEqual(
            document["relation_dependency"]["physical_classification"],
            "SUPPORTED_WITHIN_MODEL",
        )
        refuted = " ".join(document["claims"]["REFUTED"])
        self.assertIn("Only the Experiment 014 inference", refuted)
        self.assertIn("could still contribute jointly", refuted)
        self.assertNotIn("are channel-selection bits", refuted)
        for records in document["device_observation"]["phase_pa_provenance"].values():
            for record in records:
                self.assertEqual(record["effective_contiguity"], "UNKNOWN")
                self.assertNotEqual(record.get("contiguous"), True)

if __name__ == "__main__":
    unittest.main()
