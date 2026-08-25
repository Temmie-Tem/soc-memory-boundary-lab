from __future__ import annotations

import unittest

from tools import a90_inline_shrm_probe as probe
from tools import build_a90_inline_remapper_candidate as inline
from tools import build_a90_inline_shrm_candidate as candidate


class A90InlineShrmProbeTests(unittest.TestCase):
    def test_result_classifier(self) -> None:
        self.assertEqual(
            probe.classify_value(inline.MODE_CONTROL, inline.CONTROL_SENTINEL),
            "CONTROL_PASS",
        )
        self.assertEqual(probe.classify_value(inline.MODE_READ, 0x12345678), "READABLE")
        self.assertEqual(
            probe.classify_value(inline.MODE_READ, probe.MAP_FAILURE_RESULT),
            "MAP_FAILED",
        )

    def test_profiles_bind_exact_candidates(self) -> None:
        self.assertEqual(
            probe.EXPECTED_CANDIDATES[inline.MODE_CONTROL],
            candidate.EXPECTED_HASHES[inline.MODE_CONTROL]["candidate"],
        )
        self.assertEqual(
            probe.EXPECTED_CANDIDATES[inline.MODE_READ],
            candidate.EXPECTED_HASHES[inline.MODE_READ]["candidate"],
        )

    def test_cli_has_no_address_or_candidate_override(self) -> None:
        parser = probe.make_parser()
        options = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertNotIn("--address", options)
        self.assertNotIn("--candidate", options)


if __name__ == "__main__":
    unittest.main()
