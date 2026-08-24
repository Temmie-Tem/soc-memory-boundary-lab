from __future__ import annotations

import unittest

from tools import a90_soc_identity as identity


class A90SocIdentityTests(unittest.TestCase):
    def test_derive_physical_selector_candidate(self) -> None:
        result = identity.derive_selector(
            {
                "raw_id": str(0x6003),
                "raw_version": str(0x0201),
                "hw_platform": "MTP",
            }
        )
        self.assertEqual(result["hardware_id"], "0x6003")
        self.assertEqual(result["hardware_version"], "0x0200")
        self.assertEqual(result["physical_platform"], 1)
        self.assertEqual(result["hw_platform_id"], "0x8")
        self.assertEqual(result["dcb_filename_candidate"], "/6003_0200_1_dcb.bin")
        self.assertTrue(result["present_in_exact_cfgl"])
        self.assertEqual(result["status"], "SUPPORTED")

    def test_rumi_selects_zero_variant(self) -> None:
        result = identity.derive_selector(
            {"raw_id": str(0x6003), "raw_version": str(0x0100), "hw_platform": "RUMI"}
        )
        self.assertEqual(result["dcb_filename_candidate"], "/6003_0100_0_dcb.bin")

    def test_unknown_platform_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unrecognized hw_platform"):
            identity.derive_selector(
                {"raw_id": str(0x6003), "raw_version": str(0x0100), "hw_platform": "mystery"}
            )

    def test_candidate_absent_from_cfgl_remains_unknown(self) -> None:
        result = identity.derive_selector(
            {"raw_id": str(0x6004), "raw_version": str(0x0100), "hw_platform": "MTP"}
        )
        self.assertFalse(result["present_in_exact_cfgl"])
        self.assertEqual(result["status"], "UNKNOWN")

    def test_memtotal_parser_is_strict(self) -> None:
        self.assertEqual(
            identity.parse_memtotal_kib(b"MemTotal:        5700000 kB\nMemFree: 1 kB\n"),
            5_700_000,
        )
        with self.assertRaisesRegex(ValueError, "MemTotal"):
            identity.parse_memtotal_kib(b"MemFree: 1 kB\n")

    def test_text_and_decimal_parsers_reject_ambiguous_values(self) -> None:
        self.assertEqual(identity.clean_text(b"MTP\n", "platform"), "MTP")
        with self.assertRaisesRegex(ValueError, "not decimal"):
            identity.parse_decimal("0x6003", "raw_id")


if __name__ == "__main__":
    unittest.main()
