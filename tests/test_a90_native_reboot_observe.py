from __future__ import annotations

import contextlib
import io
import unittest

from tools import a90_native_reboot_observe as reboot


class A90NativeRebootObserveTests(unittest.TestCase):
    def test_cmd_no_done_transcript_requires_both_markers(self) -> None:
        transcript = (
            b"a90:/# cmdv1 reboot\r\n"
            b"A90P1 BEGIN seq=9 cmd=reboot argc=1 flags=0x5\r\n"
            b"reboot: syncing and restarting\r\n"
        )
        parsed = reboot.validate_reboot_transcript(transcript)
        self.assertTrue(parsed["a90p1_begin_observed"])
        self.assertTrue(parsed["reboot_marker_observed"])
        with self.assertRaisesRegex(ValueError, "acceptance markers"):
            reboot.validate_reboot_transcript(b"reboot: syncing and restarting")

    def test_debug_expectations_are_fixed(self) -> None:
        self.assertEqual(reboot.DEBUG_CMDLINE, {"low": "0x4f4c", "mid": "0x494d"})
        parser = reboot.build_parser()
        parsed = parser.parse_args(
            [
                "--experiment-id",
                "test",
                "--expect-debug-after",
                "mid",
                "--execute",
            ]
        )
        self.assertTrue(parsed.execute)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    ["--experiment-id", "test", "--expect-debug-after", "high"]
                )


if __name__ == "__main__":
    unittest.main()
