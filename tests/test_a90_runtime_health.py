from __future__ import annotations

import unittest

from tools import a90_runtime_health as health


class A90RuntimeHealthTests(unittest.TestCase):
    def test_parses_exact_version_and_selftest(self) -> None:
        version = health.parse_version(
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\r\n"
        )
        self.assertEqual(version["version"], "0.9.285")
        self.assertEqual(version["build"], "v2321-usb-clean-identity-rodata")
        selftest = health.parse_selftest(
            b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12\r\n"
        )
        self.assertEqual(selftest["fail"], 0)
        self.assertEqual(selftest["entries"], 12)

    def test_rejects_selftest_failure(self) -> None:
        with self.assertRaisesRegex(ValueError, "reports failures"):
            health.parse_selftest(
                b"selftest: pass=10 warn=1 fail=1 duration=43ms entries=12\n"
            )


if __name__ == "__main__":
    unittest.main()
