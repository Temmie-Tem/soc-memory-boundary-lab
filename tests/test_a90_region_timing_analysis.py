"""Tests for the Experiment 023 second-region timing analysis.

Every test builds its own synthetic measurement set, so none needs device
output. The tests that read the retained live measurements skip without them.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools import a90_region_timing_analysis as analysis


def measurement(value: int, p10: int, median: int, p90: int) -> str:
    return json.dumps(
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "difference",
            "value": f"0x{value:x}",
            "pairs": 64,
            "p10": p10,
            "median": median,
            "p90": p90,
        }
    )


def run_file(tmp: Path, name: str, rows: list[str], heap: str = "qsecom", mib: int = 32) -> Path:
    header = [
        json.dumps({"schema": analysis.PROBE_SCHEMA, "type": "context", "cpu": 7,
                    "cntfrq": 19200000, "heap": heap, "mib": mib,
                    "repetitions": 1001, "pairs": 64}),
        json.dumps({"schema": analysis.PROBE_SCHEMA, "type": "ion_heap", "name": heap,
                    "heap_type": 4, "heap_id": 27}),
    ]
    path = tmp / name
    path.write_text("\n".join(header + rows) + "\n", encoding="utf-8")
    return path


class RelationTests(unittest.TestCase):
    def test_evaluate_is_linear_over_gf2(self):
        left, right = 0x16000, 0x3A000
        self.assertEqual(
            analysis.evaluate(analysis.BASE_RELATION, left ^ right),
            analysis.evaluate(analysis.BASE_RELATION, left)
            ^ analysis.evaluate(analysis.BASE_RELATION, right),
        )

    def test_known_kernel_witnesses_evaluate_to_zero(self):
        for witness in (0x16000, 0x3A000, 0x24A000, 0xC84000, 0x95C000):
            self.assertEqual(analysis.evaluate(analysis.BASE_RELATION, witness), 0,
                             f"0x{witness:x}")

    def test_one_bank_bit_flip_leaves_the_kernel(self):
        for witness in (0x16000, 0x3A000, 0x24A000):
            self.assertNotEqual(analysis.evaluate(analysis.BASE_RELATION, witness ^ 0x2000), 0)

    def test_a_same_bank_same_row_difference_is_a_row_hit_not_a_conflict(self):
        # bits 13 and 20 both map to b0, so they cancel; neither is a row bit
        self.assertEqual(analysis.predict(analysis.BASE_RELATION, 0x2000 | 0x100000), "KERNEL")
        self.assertEqual(analysis.predict(analysis.BASE_RELATION, 0x800), "ROW_HIT")

    def test_prediction_names_the_three_outcomes(self):
        self.assertEqual(analysis.predict(analysis.BASE_RELATION, 0x16000), "KERNEL")
        self.assertEqual(analysis.predict(analysis.BASE_RELATION, 0x38000), "NEGATIVE")


class BaseFreeValidityTests(unittest.TestCase):
    def test_an_aligned_base_admits_every_difference(self):
        self.assertTrue(analysis.base_free_valid(0xC84000, 0xA6000000, 0x2000000))

    def test_a_misaligned_base_rejects_differences_reaching_its_low_bit(self):
        # 0xf0400000 is 4 MiB aligned only, so bit 22 and above carry
        self.assertFalse(analysis.base_free_valid(0xC84000, 0xF0400000, 0x1000000))
        self.assertFalse(analysis.base_free_valid(0x400000, 0xF0400000, 0x1000000))

    def test_a_misaligned_base_still_admits_lower_differences(self):
        for difference in (0x16000, 0x3A000, 0x24A000, 0x38000, 0x248000):
            self.assertTrue(analysis.base_free_valid(difference, 0xF0400000, 0x1000000),
                            f"0x{difference:x}")

    def test_the_experiment_014_window_is_not_aligned_to_its_size(self):
        self.assertNotEqual(
            analysis.USER_CONTIG_014_BASE % analysis.USER_CONTIG_014_SIZE, 0
        )

    def test_the_qsecom_carveout_is_aligned_to_a_32_mib_allocation(self):
        self.assertEqual(analysis.QSECOM_REGION_BASE % 0x2000000, 0)


class ClassificationTests(unittest.TestCase):
    def test_separated_groups_report_their_gap(self):
        rows = [
            {"difference": 1, "pairs": 64, "p10": 350, "median": 400, "p90": 450},
            {"difference": 2, "pairs": 64, "p10": -80, "median": -40, "p90": 20},
        ]
        result = analysis.classify(rows, separation=100)
        self.assertEqual(result["non_overlap_gap"], 330)
        self.assertTrue(result["separated"])

    def test_overlapping_groups_are_not_separated(self):
        rows = [
            {"difference": 1, "pairs": 64, "p10": 50, "median": 60, "p90": 70},
            {"difference": 2, "pairs": 64, "p10": -10, "median": 5, "p90": 120},
        ]
        self.assertFalse(analysis.classify(rows, separation=100)["separated"])

    def test_a_positive_p10_with_a_negative_median_is_not_kernel(self):
        rows = [{"difference": 1, "pairs": 64, "p10": 10, "median": -50, "p90": -20}]
        self.assertEqual(analysis.classify(rows, separation=1)["kernel"], [])


class SolveTests(unittest.TestCase):
    def test_recovers_a_new_bit_from_its_single_kernel_witness(self):
        rows = [
            {"difference": (1 << 24) | 0x20000, "pairs": 64, "p10": 360, "median": 395, "p90": 447},
            {"difference": (1 << 24) | 0x100000, "pairs": 64, "p10": -90, "median": -40, "p90": 5},
            {"difference": 1 << 24, "pairs": 64, "p10": -80, "median": -35, "p90": 3},
        ]
        solution = analysis.solve_new_bit(rows, analysis.BASE_RELATION, 24)
        self.assertTrue(solution["resolved"])
        self.assertEqual(solution["contribution_basis"], "b1^b2")

    def test_refuses_when_more_than_one_candidate_is_kernel(self):
        rows = [
            {"difference": (1 << 24) | 0x20000, "pairs": 64, "p10": 360, "median": 1, "p90": 2},
            {"difference": (1 << 24) | 0x100000, "pairs": 64, "p10": 350, "median": 1, "p90": 2},
        ]
        self.assertFalse(analysis.solve_new_bit(rows, analysis.BASE_RELATION, 24)["resolved"])

    def test_refuses_when_none_is_kernel(self):
        rows = [{"difference": 1 << 24, "pairs": 64, "p10": -80, "median": -1, "p90": 1}]
        self.assertFalse(analysis.solve_new_bit(rows, analysis.BASE_RELATION, 24)["resolved"])

    def test_ignores_differences_that_do_not_carry_the_new_bit(self):
        rows = [{"difference": 0x16000, "pairs": 64, "p10": 360, "median": 400, "p90": 440}]
        self.assertFalse(analysis.solve_new_bit(rows, analysis.BASE_RELATION, 24)["resolved"])


class VerificationTests(unittest.TestCase):
    def test_a_consistent_set_agrees_everywhere(self):
        rows = [
            {"difference": 0x16000, "pairs": 64, "p10": 360, "median": 400, "p90": 440},
            {"difference": 0x38000, "pairs": 64, "p10": -80, "median": -40, "p90": 10},
        ]
        result = analysis.verify(rows, analysis.BASE_RELATION)
        self.assertTrue(result["all_agree"])

    def test_a_disagreement_is_reported_rather_than_hidden(self):
        rows = [{"difference": 0x38000, "pairs": 64, "p10": 360, "median": 400, "p90": 440}]
        result = analysis.verify(rows, analysis.BASE_RELATION)
        self.assertFalse(result["all_agree"])
        self.assertFalse(result["rows"][0]["agrees"])


class ParseTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())

    def test_reads_context_heap_and_differences(self):
        path = run_file(self.tmp, "run.jsonl", [measurement(0x16000, 360, 400, 440)])
        parsed = analysis.parse_measurements(path)
        self.assertEqual(parsed["heap"]["name"], "qsecom")
        self.assertEqual(len(parsed["differences"]), 1)

    def test_rejects_a_run_with_no_context(self):
        path = self.tmp / "bad.jsonl"
        path.write_text(measurement(1, 1, 1, 1) + "\n", encoding="utf-8")
        with self.assertRaises(analysis.AnalysisError):
            analysis.parse_measurements(path)

    def test_skips_out_of_range_records_without_percentiles(self):
        rows = [json.dumps({"schema": analysis.PROBE_SCHEMA, "type": "difference",
                            "value": "0x1", "status": "OUT_OF_RANGE"}),
                measurement(0x16000, 360, 400, 440)]
        path = run_file(self.tmp, "mixed.jsonl", rows)
        self.assertEqual(len(analysis.parse_measurements(path)["differences"]), 1)


class LiveMeasurementTests(unittest.TestCase):
    """These read the retained live measurements and skip without them."""

    RAW = Path(__file__).resolve().parent.parent / "evidence/private/023-second-region-20260826-01"

    @classmethod
    def setUpClass(cls):
        needed = ["phase1-user_contig.jsonl", "phase2-qsecom-replay.jsonl",
                  "phase3-pa24-discriminate.jsonl", "phase4-heldout.jsonl"]
        if not all((cls.RAW / name).exists() for name in needed):
            raise unittest.SkipTest("retained live measurements are not present")
        cls.manifest = analysis.build_manifest(
            {
                "validation": cls.RAW / needed[0],
                "replay": cls.RAW / needed[1],
                "discriminate": cls.RAW / needed[2],
                "heldout": cls.RAW / needed[3],
            },
            separation=100,
        )

    def test_the_misaligned_window_excludes_exactly_the_carrying_differences(self):
        excluded = set(self.manifest["base_free_method"]["validation_differences_excluded"])
        self.assertEqual(excluded, {"0x95c000", "0x95e000", "0xc84000", "0xc86000"})

    def test_every_phase_separates(self):
        for phase in ("validation_in_014_window", "replay_in_qsecom_region",
                      "pa24_discrimination", "held_out_controls"):
            self.assertTrue(self.manifest[phase]["classification"]["separated"], phase)

    def test_the_qsecom_replay_reproduces_the_014_relation_exactly(self):
        self.assertTrue(self.manifest["replay_in_qsecom_region"]["verification"]["all_agree"])

    def test_pa24_resolves_to_b1_xor_b2(self):
        solution = self.manifest["pa24_discrimination"]["solution"]
        self.assertTrue(solution["resolved"])
        self.assertEqual(solution["contribution_basis"], "b1^b2")

    def test_held_out_controls_agree_with_the_extended_relation(self):
        self.assertTrue(self.manifest["held_out_controls"]["verification"]["all_agree"])

    def test_manifest_carries_no_private_paths(self):
        blob = repr(self.manifest)
        self.assertNotIn("/home/", blob)


if __name__ == "__main__":
    unittest.main()
