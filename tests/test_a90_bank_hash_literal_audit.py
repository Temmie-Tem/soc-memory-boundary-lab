from __future__ import annotations

import unittest

from tools import a90_bank_hash_literal_audit as audit


class LiteralAuditTests(unittest.TestCase):
    def test_row_space_has_all_seven_nonzero_combinations(self) -> None:
        self.assertEqual(len(audit.BANK_ROW_SPACE_NONZERO), 7)
        self.assertEqual(len(set(audit.BANK_ROW_SPACE_NONZERO)), 7)

    def test_aligned_literal_is_not_misclassified_as_table_hit(self) -> None:
        data = b"\x00" * 8 + audit.BANK_ROWS[0].to_bytes(4, "little") + b"\x00" * 12
        hits = audit.audit_blob("fixture.bin", data)
        matching = [hit for hit in hits if hit["mask"] == "0x009d2000"]
        self.assertEqual(len(matching), 1)
        self.assertTrue(matching[0]["aligned_u32_literal"])

    def test_misaligned_literal_inside_u64_address_table_is_explained(self) -> None:
        entries = (0x9D000000, 0x9D200000, 0x9D400000)
        data = b"".join(value.to_bytes(8, "little") for value in entries)
        hits = audit.audit_blob("fixture.bin", data)
        matching = [hit for hit in hits if hit["mask"] == "0x009d2000"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["offset_mod_4"], 1)
        progression = matching[0]["misaligned_u64_address_progression"]
        self.assertIsNotNone(progression)
        self.assertEqual(progression["step"], "0x200000")


class ExactFirmwareIntegrationTests(unittest.TestCase):
    def test_exact_capture_refutes_direct_literal_attribution(self) -> None:
        if not audit.DEFAULT_CAPTURE_ROOT.exists() or not audit.DEFAULT_SHRM_SNAPSHOT.exists():
            self.skipTest("exact private firmware capture is unavailable")
        result = audit.analyze()
        self.assertEqual(result["classification"], "DIRECT_LITERAL_ATTRIBUTION_REFUTED")
        self.assertEqual(result["summary"]["firmware_images"], 9)
        self.assertEqual(result["summary"]["shrm_snapshots"], 1)
        self.assertEqual(result["summary"]["raw_substring_hits"], 4)
        self.assertEqual(result["summary"]["aligned_u32_hits"], 0)
        self.assertEqual(result["summary"]["misaligned_u64_address_table_hits"], 4)
        self.assertEqual(result["summary"]["unexplained_hits"], 0)
        self.assertEqual(result["shrm_snapshot"]["literal_hits"], 0)


if __name__ == "__main__":
    unittest.main()
