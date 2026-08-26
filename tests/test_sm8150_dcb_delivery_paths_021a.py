"""Tests for the Experiment 021A DCB delivery-path audit.

Structural tests use synthetic fixtures. Tests that need the exact Experiment
004 artifacts skip when they are absent.
"""

from __future__ import annotations

import struct
import shutil
import tempfile
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


def b(vaddr: int, target: int) -> int:
    return 0x14000000 | (((target - vaddr) // 4) & 0x03FFFFFF)


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
        self.assertEqual(result["locally_labelled_sections"], [0])

    def test_a_call_with_no_directory_read_has_a_null_section(self):
        base = self.CALLER_BASE
        words = [bl(base, delivery.BOUNDED_COPY_VA)]
        result = delivery.bounded_copy_call_sites(self._image(words, base))
        self.assertIsNone(result["call_sites"][0]["dcb_section"])
        self.assertEqual(result["locally_labelled_sections"], [])

    def test_direct_b_target_is_censused_but_is_not_a_copy_call(self):
        base = self.CALLER_BASE
        result = delivery.bounded_copy_call_sites(
            self._image([b(base, delivery.BOUNDED_COPY_VA)], base)
        )
        self.assertEqual(result["direct_bl_count"], 0)
        self.assertEqual(result["direct_b_count"], 1)
        self.assertEqual(result["call_site_count"], 0)

    def test_reports_sections_without_a_local_label(self):
        base = self.CALLER_BASE
        words = [ldrh(9, 13, 0x34), ldrh(3, 13, 0x36), bl(base + 8, delivery.BOUNDED_COPY_VA)]
        result = delivery.bounded_copy_call_sites(self._image(words, base))
        self.assertEqual(result["locally_labelled_sections"], [10])
        self.assertNotIn(10, result["sections_without_locally_labelled_direct_path"])
        self.assertIn(11, result["sections_without_locally_labelled_direct_path"])

    def test_a_branch_to_another_target_is_not_counted(self):
        base = self.CALLER_BASE
        words = [bl(base, delivery.BOUNDED_COPY_VA + 0x40)]
        self.assertEqual(delivery.bounded_copy_call_sites(self._image(words, base))["call_site_count"], 0)

    def test_a_directory_offset_that_is_not_a_slot_is_ignored(self):
        base = self.CALLER_BASE
        words = [ldrh(9, 13, 0x0E), ldrh(3, 13, 0x10), bl(base + 8, delivery.BOUNDED_COPY_VA)]
        result = delivery.bounded_copy_call_sites(self._image(words, base))
        self.assertEqual(result["locally_labelled_sections"], [1])   # 0x10 is slot 1; 0x0e is not a slot


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

    def test_manifest_uses_the_suffix_experiment_id_and_static_dod_fields(self):
        self.assertEqual(self.manifest["experiment_id"], delivery.EXPERIMENT_ID)
        dod = self.manifest["definition_of_done"]
        for field in ("build", "timestamp", "repetitions", "rollback",
                      "recovery", "device_binding"):
            self.assertEqual(dod[field]["status"], "NOT_APPLICABLE")
            self.assertTrue(dod[field]["reason"])
        self.assertEqual(dod["commands"]["status"], "REDACTED_REPRODUCTION_TEMPLATE")
        self.assertIn("021a", dod["commands"]["command"])

    def test_locally_labelled_sections_match_the_recorded_loader_set(self):
        paths = self.manifest["dcb_copy_paths"]
        self.assertTrue(paths["matches_recorded_locally_labelled_sections"])
        self.assertEqual(paths["locally_labelled_sections"], sorted(delivery.EXPECTED_COPIED_SECTIONS))

    def test_the_base_relative_tables_have_no_local_label(self):
        unlabelled = set(self.manifest["dcb_copy_paths"]["sections_without_locally_labelled_direct_path"])
        for section in (6, 7, 8, 10, 11, 12):
            self.assertIn(section, unlabelled)

    def test_the_shrm_blob_matches_the_verification_001_pin(self):
        self.assertEqual(self.manifest["shrm_blob_literal_audit"]["blob_sha256"], delivery.SHRM_BLOB_SHA256)

    def test_shrm_literal_presence_is_scoped_and_target_literal_is_absent(self):
        audit = self.manifest["shrm_blob_literal_audit"]
        self.assertTrue(audit["ranked_instance_block_literal_present"])
        self.assertFalse(audit["ranked_target_literal_present"])
        self.assertEqual(audit["ranked_target_literals"], {})

    def test_only_the_first_ranked_instance_is_named(self):
        blocks = self.manifest["shrm_blob_literal_audit"]["ranked_instance_block_literals"]
        named = [key for key, entries in blocks.items() if entries]
        self.assertEqual(named, ["0x09260000"])

    def test_abl_searchability_remains_unknown(self):
        abl = self.manifest["abl_searchability"]
        self.assertTrue(abl["fvh_marker_present"])
        self.assertEqual(abl["fvh_marker_offset"], "0x28")
        self.assertEqual(abl["firmware_volume_parse"], "NOT_PERFORMED")
        self.assertEqual(abl["artifact_name"], delivery.ABL_NAME)
        self.assertEqual(abl["artifact_size"], delivery.ABL_SIZE)
        self.assertEqual(abl["artifact_sha256"], delivery.ABL_SHA256)
        self.assertGreaterEqual(abl["payload_entropy_bits_per_byte"], delivery.INCOMPRESSIBLE_THRESHOLD)
        self.assertEqual(abl["entropy_sample_size"], 1 << 20)
        self.assertEqual(abl["entropy_scope"], "first 1048576 payload bytes")
        self.assertIsNone(abl["searchable"])
        self.assertIn("void", abl["reason"])
        self.assertEqual(abl["classification"], "UNPARSED_HIGH_ENTROPY_UEFI_FV")
        self.assertEqual(abl["searchability"], "UNKNOWN")
        self.assertEqual(abl["aligned_aarch64_ret_count"], 0)

    def test_direct_branch_and_literal_counts_are_exact(self):
        paths = self.manifest["dcb_copy_paths"]
        self.assertEqual(paths["direct_bl_count"], 7)
        self.assertEqual(paths["direct_b_count"], 0)
        self.assertEqual(paths["call_site_count"], 7)
        self.assertEqual(paths["unlabelled_direct_bl_count"], 2)
        self.assertEqual(
            self.manifest["direct_branch_census"],
            {"target_va": "0x1483ab24", "direct_bl_count": 7, "direct_b_count": 0},
        )
        conclusion = self.manifest["delivery_conclusion"]
        self.assertEqual(conclusion["classification"], "UNKNOWN")
        self.assertEqual(conclusion["local_label_status"], "NOT_OBSERVED")
        self.assertEqual(
            conclusion["sections_without_locally_labelled_direct_path_status"],
            "NOT_OBSERVED",
        )
        self.assertEqual(conclusion["direct_delivery"], "UNKNOWN")
        self.assertEqual(conclusion["global_delivery"], "UNKNOWN")
        self.assertEqual(conclusion["indirect_blr_br"], "UNKNOWN")
        self.assertEqual(conclusion["other_copy_routines"], "UNKNOWN")
        audit = self.manifest["shrm_blob_literal_audit"]
        self.assertEqual(audit["aperture_aligned_words"], 116)
        self.assertEqual(audit["ranked_instance_block_literal_counts"]["0x09260000"], 7)
        self.assertEqual(audit["ranked_instance_block_literal_counts"]["0x092e0000"], 0)
        self.assertEqual(len(audit["ranked_target_literal_counts"]), 12)
        self.assertEqual(audit["ranked_target_literal_total"], 0)

    def test_claim_scope_keeps_indirect_and_other_routines_unknown(self):
        claims = self.manifest["claims"]
        unknown = " ".join(claims["UNKNOWN"])
        self.assertIn("indirect BLR/BR", unknown)
        self.assertIn("other routine", unknown)
        self.assertNotIn("finite call graph", repr(self.manifest))
        self.assertIn("local directory-read label model", " ".join(claims["PROVED"]))
        self.assertIn("direct delivery", unknown)
        self.assertIn("two of the seven", " ".join(claims["REFUTED"]))
        self.assertIn("computed or received pointers", unknown)
        self.assertIn("exact aligned stored literals", " ".join(claims["PROVED"]))

    def test_dependency_hash_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in delivery.DEPENDENCY_MANIFESTS:
                shutil.copy2(delivery.MANIFEST_DIR / name, directory / name)
            target = directory / next(iter(delivery.DEPENDENCY_MANIFESTS))
            target.write_bytes(target.read_bytes() + b"mutation")
            with self.assertRaises(delivery.DeliveryError):
                delivery.dependency_manifest_hashes(directory)

    def test_output_is_no_clobber_and_nofollow(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            output = directory / "manifest.json"
            delivery.write_manifest(output, {"ok": 1})
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            with self.assertRaises(delivery.DeliveryError):
                delivery.write_manifest(output, {"ok": 2})
            link = directory / "link.json"
            link.symlink_to(output)
            with self.assertRaises(delivery.DeliveryError):
                delivery.write_manifest(link, {"ok": 3}, force=True)

    def test_manifest_carries_no_raw_bytes_or_private_paths(self):
        blob = repr(self.manifest)
        self.assertNotIn("evidence/private", blob)
        self.assertNotIn("/home/", blob)


if __name__ == "__main__":
    unittest.main()
