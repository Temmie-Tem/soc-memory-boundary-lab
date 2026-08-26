"""Tests for the Experiment 021A DCB delivery-path audit.

Structural tests use synthetic fixtures. Tests that need the exact Experiment
004 artifacts skip when they are absent.
"""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

from tools import sm8150_dcb_delivery_paths_021a as delivery


def build_elf64(segments: list[tuple[int, int, bytes]]) -> bytes:
    ph_offset, ph_entry = 64, 56
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<Q", header, 32, ph_offset)
    struct.pack_into("<H", header, 54, ph_entry)
    struct.pack_into("<H", header, 56, len(segments))
    body_start = ph_offset + ph_entry * len(segments)
    table, body = bytearray(), bytearray()
    for vaddr, flags, payload in segments:
        offset = body_start + len(body)
        table += struct.pack("<IIQQQQQQ", 1, flags, offset, vaddr, vaddr, len(payload), len(payload), 0x1000)
        body += payload
    return bytes(header) + bytes(table) + bytes(body)


def bl(vaddr: int, target: int) -> int:
    return 0x94000000 | (((target - vaddr) // 4) & 0x03FFFFFF)


def ldrh(rt: int, rn: int, byte_offset: int) -> int:
    return 0x79400000 | ((byte_offset // 2) << 10) | (rn << 5) | rt


class EntropyTests(unittest.TestCase):
    def test_uniform_bytes_reach_eight_bits(self):
        self.assertAlmostEqual(delivery.shannon_entropy(bytes(range(256)) * 4), 8.0, places=6)

    def test_a_constant_run_has_zero_entropy(self):
        self.assertEqual(delivery.shannon_entropy(b"\x00" * 1024), 0.0)

    def test_empty_input_is_zero(self):
        self.assertEqual(delivery.shannon_entropy(b""), 0.0)


class Elf64Tests(unittest.TestCase):
    def test_rejects_elf32(self):
        data = bytearray(build_elf64([(0x1000, 5, bytes(8))]))
        data[4] = 1
        with self.assertRaises(delivery.DeliveryError):
            delivery.Elf64(bytes(data))

    def test_maps_a_vaddr_into_the_file(self):
        image = delivery.Elf64(build_elf64([(0x1000, 5, b"\x11\x22\x33\x44")]))
        self.assertEqual(image.word(0x1000), 0x44332211)

    def test_returns_none_outside_any_segment(self):
        image = delivery.Elf64(build_elf64([(0x1000, 5, bytes(8))]))
        self.assertIsNone(image.word(0x9999))


class CopyPathTests(unittest.TestCase):
    # A BL displacement is 26 bits, so the caller has to sit near the target or
    # the encoding truncates and the decoded destination is some other address.
    CALLER_BASE = delivery.BOUNDED_COPY_VA - 0x2000

    def _image(self, words: list[int], base: int) -> delivery.Elf64:
        payload = b"".join(struct.pack("<I", w) for w in words)
        return delivery.Elf64(
            build_elf64([(base, 5, payload), (delivery.BOUNDED_COPY_VA & ~0xFFF, 5, bytes(0x1000))])
        )

    def test_labels_a_call_with_the_section_read_before_it(self):
        base = self.CALLER_BASE
        words = [ldrh(9, 13, 0x0C), ldrh(3, 13, 0x0E), bl(base + 8, delivery.BOUNDED_COPY_VA)]
        result = delivery.bounded_copy_call_sites(self._image(words, base))
        self.assertEqual(result["call_site_count"], 1)
        self.assertEqual(result["sections_copied"], [0])

    def test_a_call_with_no_directory_read_has_a_null_section(self):
        base = self.CALLER_BASE
        words = [bl(base, delivery.BOUNDED_COPY_VA)]
        result = delivery.bounded_copy_call_sites(self._image(words, base))
        self.assertIsNone(result["call_sites"][0]["dcb_section"])
        self.assertEqual(result["sections_copied"], [])

    def test_reports_sections_with_no_copy_path(self):
        base = self.CALLER_BASE
        words = [ldrh(9, 13, 0x34), ldrh(3, 13, 0x36), bl(base + 8, delivery.BOUNDED_COPY_VA)]
        result = delivery.bounded_copy_call_sites(self._image(words, base))
        self.assertEqual(result["sections_copied"], [10])
        self.assertNotIn(10, result["sections_with_no_copy_path"])
        self.assertIn(11, result["sections_with_no_copy_path"])

    def test_a_branch_to_another_target_is_not_counted(self):
        base = self.CALLER_BASE
        words = [bl(base, delivery.BOUNDED_COPY_VA + 0x40)]
        self.assertEqual(delivery.bounded_copy_call_sites(self._image(words, base))["call_site_count"], 0)

    def test_a_directory_offset_that_is_not_a_slot_is_ignored(self):
        base = self.CALLER_BASE
        words = [ldrh(9, 13, 0x0E), ldrh(3, 13, 0x10), bl(base + 8, delivery.BOUNDED_COPY_VA)]
        result = delivery.bounded_copy_call_sites(self._image(words, base))
        self.assertEqual(result["sections_copied"], [1])   # 0x10 is slot 1; 0x0e is not a slot


class AblSearchabilityTests(unittest.TestCase):
    def test_reports_unavailable_without_the_artifact(self):
        self.assertEqual(
            delivery.abl_searchability(Path("/nonexistent-firmware-dir")), {"available": False}
        )


class ExactImageTests(unittest.TestCase):
    """These need the private Experiment 004 artifacts and skip without them."""

    @classmethod
    def setUpClass(cls):
        if not (delivery.FIRMWARE_DIR / delivery.XBL_NAME).exists():
            raise unittest.SkipTest("exact Experiment 004 firmware is not present")
        cls.manifest = delivery.build_manifest(delivery.FIRMWARE_DIR)

    def test_refuses_a_directory_without_the_exact_image(self):
        with self.assertRaises(delivery.DeliveryError):
            delivery.load_xbl(Path("/nonexistent-firmware-dir"))

    def test_copied_sections_match_the_recorded_loader_set(self):
        paths = self.manifest["dcb_copy_paths"]
        self.assertTrue(paths["matches_recorded_loader_sections"])
        self.assertEqual(paths["sections_copied"], sorted(delivery.EXPECTED_COPIED_SECTIONS))

    def test_the_base_relative_tables_have_no_copy_path(self):
        no_copy = set(self.manifest["dcb_copy_paths"]["sections_with_no_copy_path"])
        for section in (6, 7, 8, 10, 11, 12):
            self.assertIn(section, no_copy)

    def test_the_shrm_blob_matches_the_verification_001_pin(self):
        self.assertEqual(self.manifest["shrm_blob_literal_audit"]["blob_sha256"], delivery.SHRM_BLOB_SHA256)

    def test_shrm_reaches_a_ranked_instance_but_no_ranked_target(self):
        audit = self.manifest["shrm_blob_literal_audit"]
        self.assertTrue(audit["reaches_a_ranked_instance"])
        self.assertFalse(audit["reaches_a_ranked_target"])
        self.assertEqual(audit["ranked_target_literals"], {})

    def test_only_the_first_ranked_instance_is_named(self):
        blocks = self.manifest["shrm_blob_literal_audit"]["ranked_base_blocks"]
        named = [key for key, entries in blocks.items() if entries]
        self.assertEqual(named, ["0x09260000"])

    def test_abl_is_not_searchable(self):
        abl = self.manifest["abl_searchability"]
        self.assertTrue(abl["uefi_firmware_volume"])
        self.assertGreaterEqual(abl["payload_entropy_bits_per_byte"], delivery.INCOMPRESSIBLE_THRESHOLD)
        self.assertFalse(abl["searchable"])
        self.assertIn("void", abl["reason"])

    def test_manifest_carries_no_raw_bytes_or_private_paths(self):
        blob = repr(self.manifest)
        self.assertNotIn("evidence/private", blob)
        self.assertNotIn("/home/", blob)


if __name__ == "__main__":
    unittest.main()
