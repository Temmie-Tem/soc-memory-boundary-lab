from __future__ import annotations

import unittest

from tools import a90_sysrq_crash_once as crash


class A90SysrqCrashOnceTests(unittest.TestCase):
    def test_wire_is_one_fixed_sysrq_c_write(self) -> None:
        self.assertEqual(crash.WIRE, b"\ncmdv1 writefile /proc/sysrq-trigger c\n")

    def test_transcript_requires_writefile_begin(self) -> None:
        good = b"A90P1 BEGIN seq=2 cmd=writefile argc=3 flags=0x4\r\n"
        result = crash.validate_transcript(good)
        self.assertTrue(result["a90p1_writefile_begin_observed"])
        with self.assertRaisesRegex(ValueError, "writefile BEGIN"):
            crash.validate_transcript(b"A90P1 BEGIN seq=2 cmd=cat argc=2 flags=0x0\r\n")


if __name__ == "__main__":
    unittest.main()
