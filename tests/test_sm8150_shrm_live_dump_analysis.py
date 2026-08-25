from __future__ import annotations

import unittest
from pathlib import Path

from tools import sm8150_shrm_live_dump_analysis as analysis


class SetQualificationTests(unittest.TestCase):
    def test_metrics_distinguish_zero_and_distinct_values(self) -> None:
        coherent = analysis.set_metrics({0: 0, 4: 0, 8: 1, 12: 1})
        random_like = analysis.set_metrics({0: 1, 4: 2, 8: 3, 12: 4})
        self.assertEqual(coherent["zero_words"], 2)
        self.assertFalse(coherent["all_values_distinct"])
        self.assertTrue(random_like["all_values_distinct"])

    def test_mc_symmetry_counts_exact_and_split_groups(self) -> None:
        word_map: dict[int, int] = {}
        for base in analysis.MC_BASES:
            word_map[base + 0x80] = 0x1DD
            word_map[base + 0x400] = 1 if base < 0x09300000 else 2
        result = analysis.mc_symmetry(word_map)
        self.assertEqual(result["common_offsets"], 2)
        self.assertEqual(result["exactly_equal_groups"], 1)
        self.assertEqual(result["two_value_groups"], 1)

    def test_overlap_requires_same_address_not_same_position(self) -> None:
        result = analysis.overlap_metrics({0x10: 1, 0x20: 2}, {0x20: 3, 0x30: 1})
        self.assertEqual(result["common_registers"], 1)
        self.assertEqual(result["equal_values"], 0)


class JournalTests(unittest.TestCase):
    def test_rejects_unpinned_journal(self) -> None:
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            analysis.validate_journal(b"not the exact excerpt\n")


class ExactAcquisitionTests(unittest.TestCase):
    def test_exact_dump_and_source_produce_qualified_public_result(self) -> None:
        journal = Path("/tmp/a90-upload-journal-snippet.txt")
        # The exact journal is intentionally not a repository fixture because
        # it is retained in the generated ignored private record.  Skip this
        # integration assertion when the live-session /tmp file is absent.
        if not journal.exists():
            self.skipTest("live host-journal excerpt is not present")
        private, public = analysis.analyze(
            analysis.RAW_DUMP.read_bytes(),
            analysis.SAMUPLOAD_SOURCE.read_bytes(),
            journal.read_bytes(),
        )
        self.assertEqual(
            public["classification"],
            "REAL_SHRM_DUMP_ACQUIRED_SET0_QUALIFIED_NO_BYPASS",
        )
        self.assertTrue(public["set_qualification"]["set0"]["use_for_follow_up"])
        self.assertFalse(public["set_qualification"]["set1"]["use_for_follow_up"])
        self.assertEqual(len(public["controller_candidates_top5"]), 5)
        self.assertEqual(public["dump"]["decoded_staged_entries"], 494)
        self.assertEqual(public["dump"]["distinct_source_registers"], 470)
        self.assertEqual(len(private["decoded_registers"]), 494)


if __name__ == "__main__":
    unittest.main()
