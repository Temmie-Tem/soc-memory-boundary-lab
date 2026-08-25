from __future__ import annotations

import unittest

from tools import a90_last_kmsg_capture as capture


class A90LastKmsgCaptureTests(unittest.TestCase):
    def test_marker_summary_distinguishes_result_and_watchdog(self) -> None:
        summary = capture.marker_summary(
            b"A90R0000c071\nNon Secure Watchdog Bark\nlast pet\n"
        )
        self.assertTrue(summary["non_secure_watchdog_bark_present"])
        self.assertTrue(summary["a90r_result_present"])
        self.assertEqual(summary["counts"]["last pet"], 1)

    def test_empty_log_has_no_markers(self) -> None:
        summary = capture.marker_summary(b"")
        self.assertFalse(summary["non_secure_watchdog_bark_present"])
        self.assertFalse(summary["a90r_result_present"])


if __name__ == "__main__":
    unittest.main()
