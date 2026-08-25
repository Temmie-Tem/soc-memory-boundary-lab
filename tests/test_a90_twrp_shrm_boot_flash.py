from __future__ import annotations

import unittest
from pathlib import Path

from tools import a90_twrp_shrm_boot_flash as flash


class A90TwrpShrmBootFlashTests(unittest.TestCase):
    def test_prefix_geometry_is_exact(self) -> None:
        self.assertEqual(flash.BOOT_PREFIX_SIZE, 60_882_944)
        self.assertEqual(
            flash.DD_BLOCK_SIZE * flash.DD_BLOCK_COUNT,
            flash.BOOT_PREFIX_SIZE,
        )
        self.assertEqual(flash.BOOT_BLOCK_RESOLVED, "/dev/block/sda24")

    def test_profile_predecessors_are_fail_closed(self) -> None:
        profiles = flash.profile_table(Path(__file__).resolve().parents[1])
        self.assertEqual(profiles["control"]["allowed_predecessors"], {flash.ROLLBACK_HASH})
        self.assertEqual(profiles["read"]["allowed_predecessors"], {flash.ROLLBACK_HASH})
        self.assertEqual(
            profiles["rollback"]["allowed_predecessors"],
            {flash.CONTROL_HASH, flash.READ_HASH},
        )

    def test_hash_and_scalar_parsers_reject_ambiguity(self) -> None:
        value = "a" * 64
        self.assertEqual(flash.parse_one_sha256(value + "  file\n"), value)
        self.assertEqual(flash.parse_one_decimal("60882944\n"), 60_882_944)
        with self.assertRaisesRegex(RuntimeError, "one SHA-256"):
            flash.parse_one_sha256(value + " x\n" + value + " y\n")
        with self.assertRaisesRegex(RuntimeError, "one decimal"):
            flash.parse_one_decimal("1\n2\n")


if __name__ == "__main__":
    unittest.main()
