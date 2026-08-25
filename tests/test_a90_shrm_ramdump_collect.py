from __future__ import annotations

import unittest
from pathlib import Path

from tools import a90_shrm_ramdump_collect as collector


class A90ShrmRamdumpCollectTests(unittest.TestCase):
    def test_exact_qdl_release_binary_and_version(self) -> None:
        result = collector.validate_qdl()
        self.assertEqual(result["tag"], "v2.8")
        self.assertEqual(result["tag_commit"], collector.QDL_TAG_COMMIT)
        self.assertEqual(result["binary_sha256"], collector.QDL_SHA256)

    def test_command_has_one_fixed_segment_filter(self) -> None:
        command = collector.qdl_command(Path("/private/dump"))
        self.assertEqual(command[-1], "SHRM_MEM.BIN")
        self.assertIn("ramdump", command)
        self.assertIn("--backend=usb", command)
        self.assertNotIn("*", " ".join(command))

    def test_expected_dump_size_is_64_kib(self) -> None:
        self.assertEqual(collector.DUMP_SIZE, 0x10000)


if __name__ == "__main__":
    unittest.main()
