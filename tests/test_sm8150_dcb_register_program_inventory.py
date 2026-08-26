"""Tests for the Experiment 019 DCB candidate pair-array inventory.

Every structural test runs on synthetic fixtures, so the suite needs no private
firmware bytes.  The two tests that do need the exact images skip when they are
absent rather than failing a clean checkout.
"""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_dcb_register_program_inventory as inv


def build_elf(segments: list[tuple[int, bytes]]) -> bytes:
    """Assemble a minimal ELF64 whose PT_LOADs carry the given payloads."""
    ph_offset = 64
    ph_entry = 56
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    struct.pack_into("<Q", header, 32, ph_offset)
    struct.pack_into("<H", header, 54, ph_entry)
    struct.pack_into("<H", header, 56, len(segments))

    body_start = ph_offset + ph_entry * len(segments)
    table = bytearray()
    body = bytearray()
    for vaddr, payload in segments:
        file_offset = body_start + len(body)
        table += struct.pack("<IIQQQQQQ", 1, 5, file_offset, vaddr, vaddr, len(payload), len(payload), 0x1000)
        body += payload
    return bytes(header) + bytes(table) + bytes(body)


def build_dcb(sections: dict[int, bytes]) -> bytes:
    """Assemble one 0x3404-byte DCB block holding the given section bodies."""
    block = bytearray(inv.DCB_SIZE)
    cursor = inv.DCB_HEADER_SIZE
    for index in sorted(sections):
        body = sections[index]
        struct.pack_into("<HH", block, 0x0C + index * 4, cursor, len(body))
        block[cursor : cursor + len(body)] = body
        cursor += len(body)
    return bytes(block)


def table_bytes(pairs: list[tuple[int, int]], terminate: bool = True) -> bytes:
    out = b"".join(struct.pack("<II", key, value) for key, value in pairs)
    return out + (struct.pack("<II", 0, 0) if terminate else b"")


class ElfWalkTests(unittest.TestCase):
    def test_rejects_non_elf64_little_endian(self):
        with self.assertRaises(inv.InventoryError):
            inv.parse_pt_load(b"NOTELF" + bytes(120))

    def test_finds_the_dcb_sized_segment_only(self):
        dcb = build_dcb({5: table_bytes([(0x090C0010, 1)] * 4)})
        image = build_elf([(0x1000, bytes(64)), (0x2000, dcb), (0x3000, bytes(128))])
        blocks = inv.find_dcb_blocks(image)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(len(blocks[0][1]), inv.DCB_SIZE)

    def test_raises_when_no_dcb_segment_present(self):
        image = build_elf([(0x1000, bytes(64))])
        with self.assertRaises(inv.InventoryError):
            inv.find_dcb_blocks(image)

    def test_skips_segments_running_past_end_of_file(self):
        image = bytearray(build_elf([(0x1000, bytes(16))]))
        struct.pack_into("<Q", image, 64 + 32, 1 << 40)  # p_filesz far beyond EOF
        self.assertEqual(inv.parse_pt_load(bytes(image)), [])


class SectionDirectoryTests(unittest.TestCase):
    def test_parses_only_populated_slots(self):
        dcb = build_dcb({3: b"\x00\x00", 7: table_bytes([(0x400, 1)] * 4)})
        sections = inv.parse_sections(dcb)
        self.assertEqual(sorted(sections), [3, 7])

    def test_rejects_a_section_pointing_into_the_header(self):
        dcb = bytearray(build_dcb({5: table_bytes([(0x10, 1)] * 4)}))
        struct.pack_into("<HH", dcb, 0x0C + 5 * 4, 0x10, 8)
        with self.assertRaises(inv.InventoryError):
            inv.parse_sections(bytes(dcb))

    def test_rejects_a_section_running_past_the_block(self):
        dcb = bytearray(build_dcb({5: table_bytes([(0x10, 1)] * 4)}))
        struct.pack_into("<HH", dcb, 0x0C + 5 * 4, inv.DCB_SIZE - 4, 64)
        with self.assertRaises(inv.InventoryError):
            inv.parse_sections(bytes(dcb))


class PairReadingTests(unittest.TestCase):
    def test_stops_at_the_all_zero_terminator(self):
        pairs, tail = inv.read_pairs(table_bytes([(0x10, 0xAA), (0x14, 0xBB)]))
        self.assertEqual(pairs, [(0x10, 0xAA), (0x14, 0xBB)])
        self.assertEqual(tail, 0)

    def test_reports_trailing_bytes_after_the_terminator(self):
        body = table_bytes([(0x10, 1)]) + struct.pack("<II", 0x20, 2)
        _pairs, tail = inv.read_pairs(body)
        self.assertEqual(tail, 8)

    def test_reports_absence_of_a_terminator(self):
        _pairs, tail = inv.read_pairs(table_bytes([(0x10, 1)], terminate=False))
        self.assertEqual(tail, -1)

    def test_a_zero_key_with_a_nonzero_value_is_not_a_terminator(self):
        pairs, _tail = inv.read_pairs(struct.pack("<II", 0, 7) + table_bytes([(0x10, 1)]))
        self.assertEqual(pairs[0], (0, 7))


class ClassificationTests(unittest.TestCase):
    def test_accepts_a_base_relative_offset_table(self):
        record = inv.classify_section(table_bytes([(0x10, 1), (0x14, 2), (0x18, 3), (0x1C, 4)]))
        self.assertEqual(record["kind"], "BASE_RELATIVE_OFFSET_PAIR_ARRAY")
        self.assertEqual(record["array_semantics"], "CANDIDATE_ADDRESS_OR_OFFSET_VALUE_PAIR_ARRAY")
        self.assertEqual(record["entry_count"], 4)

    def test_accepts_an_absolute_address_table_and_reports_its_bases(self):
        keys = [0x090C0010, 0x090C0014, 0x090C0018, 0x090C001C]
        record = inv.classify_section(table_bytes([(k, 1) for k in keys]))
        self.assertEqual(record["kind"], "ABSOLUTE_ADDRESS_PAIR_ARRAY")
        self.assertEqual(record["distinct_64k_bases"], ["0x090c0000"])
        self.assertEqual(record["ranked_base_hits"], [])

    def test_flags_a_ranked_mc_base_when_one_is_actually_reached(self):
        keys = [b + 0x400 for b in inv.RANKED_BASES]
        record = inv.classify_section(table_bytes([(k, 1) for k in keys]))
        self.assertEqual(record["kind"], "ABSOLUTE_ADDRESS_PAIR_ARRAY")
        self.assertEqual(len(record["ranked_base_hits"]), 4)

    def test_reports_ranked_offset_hits_in_a_relative_table(self):
        record = inv.classify_section(
            table_bytes([(0x400, 0xAA), (0x404, 0xBB), (0x4D0, 0xCC), (0x500, 0xDD)])
        )
        self.assertEqual([hit["key"] for hit in record["ranked_offset_hits"]], ["0x400", "0x404", "0x4d0"])

    def test_rejects_descending_keys(self):
        record = inv.classify_section(table_bytes([(0x20, 1), (0x1C, 2), (0x18, 3), (0x14, 4)]))
        self.assertEqual(record["kind"], "NOT_A_CANDIDATE_PAIR_ARRAY")
        self.assertIn("KEYS_NOT_STRICTLY_ASCENDING", record["rejected_because"])

    def test_rejects_repeated_keys(self):
        record = inv.classify_section(table_bytes([(0x10, 1), (0x10, 2), (0x18, 3), (0x1C, 4)]))
        self.assertIn("KEYS_NOT_STRICTLY_ASCENDING", record["rejected_because"])

    def test_rejects_unaligned_keys(self):
        record = inv.classify_section(table_bytes([(0x11, 1), (0x15, 2), (0x19, 3), (0x1D, 4)]))
        self.assertIn("UNALIGNED_KEY", record["rejected_because"])

    def test_rejects_a_table_with_trailing_data_after_the_terminator(self):
        body = table_bytes([(0x10, 1), (0x14, 2), (0x18, 3), (0x1C, 4)]) + struct.pack("<II", 0x40, 9)
        record = inv.classify_section(body)
        self.assertIn("TERMINATOR_NOT_FINAL", record["rejected_because"])

    def test_rejects_too_few_entries(self):
        record = inv.classify_section(table_bytes([(0x10, 1), (0x14, 2)]))
        self.assertIn("FEWER_THAN_FOUR_ENTRIES", record["rejected_because"])

    def test_rejects_keys_that_mix_absolute_and_relative_domains(self):
        body = table_bytes([(0x10, 1), (0x14, 2), (0x18, 3), (0x090C0000, 4)])
        record = inv.classify_section(body)
        self.assertEqual(record["kind"], "NOT_A_CANDIDATE_PAIR_ARRAY")
        self.assertIn("MIXED_KEY_DOMAIN", record["rejected_because"])


class LogicalImmediateTests(unittest.TestCase):
    def setUp(self):
        self.encodable = inv.logical_immediates_32()

    def test_excludes_the_two_inencodable_extremes(self):
        self.assertNotIn(0, self.encodable)
        self.assertNotIn(0xFFFFFFFF, self.encodable)

    def test_known_encodable_values(self):
        # a single circular run of ones, and a repeating nibble pattern
        self.assertIn(0xC003FFFF, self.encodable)
        self.assertIn(0x11111111, self.encodable)

    def test_known_inencodable_values(self):
        # four separate runs that do not repeat across the full 32 bits
        for value in (0x00003333, 0x00111111, 0x00300014, 0x00300033, 0x00001111):
            self.assertNotIn(value, self.encodable)

    def test_every_encodable_value_replicates_its_element(self):
        for value, (n, _immr, _imms) in self.encodable.items():
            self.assertEqual(n, 0, f"32-bit logical immediates require N=0 (value 0x{value:08x})")


class MaterialisationAuditTests(unittest.TestCase):
    def _audit(self, images):
        return {record["value"]: record for record in inv.materialisation_audit(images)}

    def test_a_stored_word_is_counted(self):
        blob = bytes(16) + (0x00003333).to_bytes(4, "little") + bytes(16)
        record = self._audit({"synthetic.bin": blob})["0x00003333"]
        self.assertEqual(record["stored_word_total"], 1)
        self.assertFalse(record["modeled_direct_materialisation_paths_all_absent"])

    def test_all_paths_absent_on_an_empty_image(self):
        record = self._audit({"synthetic.bin": bytes(4096)})["0x00003333"]
        self.assertTrue(record["modeled_direct_materialisation_paths_all_absent"])

    def test_movz_low_is_counted_as_an_exact_single_instruction_path(self):
        # MOVZ W0,#0x3333 directly produces the 32-bit target; no high-halfword
        # MOVK is required because W-register writes zero-extend.
        movz = struct.pack("<I", 0x52800000 | (0x3333 << 5))
        record = self._audit({"synthetic.bin": movz * 4})["0x00003333"]
        self.assertEqual(record["wide_move_single_instruction_sites"]["movz_w"], 4)
        self.assertEqual(sum(record["wide_move_two_instruction_sequence_sites"].values()), 0)
        self.assertFalse(record["modeled_direct_materialisation_paths_all_absent"])

    def test_adjacent_movz_movk_sequence_is_counted_only_when_exact(self):
        movz = struct.pack("<I", 0x52800000 | (0x0014 << 5))
        movk = struct.pack("<I", 0x72A00000 | (0x0030 << 5))
        record = self._audit({"synthetic.bin": movz + movk})["0x00300014"]
        self.assertEqual(record["wide_move_two_instruction_sequence_sites"]["movz_then_movk_w"], 1)
        self.assertFalse(record["modeled_direct_materialisation_paths_all_absent"])

    def test_movn_is_counted_as_an_exact_single_instruction_path(self):
        # MOVN W0,#0x3ffc,LSL#16 produces 0xc003ffff.
        movn = struct.pack("<I", 0x12800000 | (1 << 21) | (0x3FFC << 5))
        record = self._audit({"synthetic.bin": movn})["0xc003ffff"]
        self.assertEqual(record["wide_move_single_instruction_sites"]["movn_w"], 1)

    def test_orr_immediate_site_is_found_for_an_encodable_value(self):
        _n, immr, imms = inv.logical_immediates_32()[0xC003FFFF]
        word = 0x32000000 | (immr << 16) | (imms << 10) | (31 << 5)
        record = self._audit({"synthetic.bin": struct.pack("<I", word)})["0xc003ffff"]
        self.assertEqual(record["logical_immediate"]["orr_sites"], 1)

    def test_the_64_bit_orr_form_is_not_counted(self):
        # Regression: a fixed-field mask that ignores sf and N matches ORR (64-bit)
        # and the N=1 form, inflating the site count.
        _n, immr, imms = inv.logical_immediates_32()[0xC003FFFF]
        sixty_four = 0xB2000000 | (immr << 16) | (imms << 10) | (31 << 5)
        n_set = 0x32400000 | (immr << 16) | (imms << 10) | (31 << 5)
        blob = struct.pack("<II", sixty_four, n_set)
        record = self._audit({"synthetic.bin": blob})["0xc003ffff"]
        self.assertEqual(record["logical_immediate"]["orr_sites"], 0)


class ExactImageTests(unittest.TestCase):
    """These need the private Experiment 004 artifacts and skip without them."""

    @classmethod
    def setUpClass(cls):
        if not (inv.FIRMWARE_DIR / inv.DCB_IMAGE).exists():
            raise unittest.SkipTest("exact Experiment 004 firmware is not present")
        cls.manifest = inv.build_manifest(inv.FIRMWARE_DIR)

    def test_refuses_an_image_that_is_not_the_exact_artifact(self):
        with self.assertRaises(inv.InventoryError):
            inv.load_exact_images(Path("/nonexistent-firmware-dir"))

    def test_four_dcb_blocks_are_present(self):
        self.assertEqual(len(self.manifest["dcb"]["blocks"]), 4)

    def test_candidate_pair_array_count_has_no_register_semantic_name(self):
        self.assertEqual(self.manifest["candidate_pair_array_count"], 28)
        self.assertNotIn("register_table_count", self.manifest)

    def test_no_absolute_table_reaches_a_ranked_mc_base(self):
        self.assertEqual(self.manifest["ranked_absolute_base_reached"], [])

    def test_the_only_absolute_table_base_is_0x090c0000(self):
        self.assertEqual(self.manifest["absolute_table_64k_bases"], ["0x090c0000"])

    def test_ranked_offset_hits_occur_only_in_section_7(self):
        self.assertTrue(self.manifest["ranked_offset_hits"])
        self.assertEqual({hit["section"] for hit in self.manifest["ranked_offset_hits"]}, {7})

    def test_section_7_ranked_values_do_not_match_the_live_readings(self):
        values = {
            entry["value"]
            for hit in self.manifest["ranked_offset_hits"]
            for entry in hit["hits"]
        }
        self.assertNotIn("0xc003ffff", values)
        self.assertNotIn("0x00003333", values)

    def test_qhs_mc_0x404_value_is_absent_from_every_modeled_direct_path(self):
        record = next(
            r for r in self.manifest["ranked_value_materialisation"] if r["value"] == "0x00003333"
        )
        self.assertEqual(record["stored_word_total"], 0)
        self.assertEqual(sum(record["wide_move_single_instruction_sites"].values()), 0)
        self.assertEqual(sum(record["wide_move_two_instruction_sequence_sites"].values()), 0)
        self.assertEqual(record["logical_immediate"]["orr_sites"], 0)
        self.assertTrue(record["modeled_direct_materialisation_paths_all_absent"])
        self.assertNotIn("single_instruction_paths_all_absent", record)
        self.assertNotIn("wide_move_pair_not_excluded", record)

    def test_materialisation_summary_is_derived_and_does_not_overclaim_target_reach(self):
        rows = {row["value"]: row for row in self.manifest["ranked_value_materialisation"]}
        summary = self.manifest["ranked_value_materialisation_summary"]
        self.assertEqual(summary["derivation"], "DERIVED_FROM_EXACT_RANKED_VALUE_MATERIALISATION_ROWS")
        self.assertEqual(summary["zero_stored_modeled_direct_paths"], ["0x00003333", "0x00300014"])
        self.assertEqual(summary["stored_word_totals"]["0xc003ffff"], 24)
        self.assertEqual(summary["stored_word_totals"]["0x00111111"], 3)
        self.assertEqual(summary["exact_single_wide_move_site_totals"]["0x00003333"], 0)
        self.assertEqual(summary["exact_two_instruction_wide_move_site_totals"]["0x00003333"], 0)
        self.assertEqual(self.manifest["ranked_target_reach"], "UNKNOWN")
        self.assertEqual(
            rows["0x00003333"]["materialisation_conclusion"],
            "NO_STORED_WORD_OR_EXACT_MODELED_WIDE_MOVE_OR_ORR_SITE_OBSERVED",
        )
        claims = self.manifest["claims"]
        self.assertFalse(any("programs the twelve" in claim.lower() for claim in claims.get("REFUTED", [])))
        self.assertTrue(any("boot-time write" in claim for claim in claims["UNKNOWN"]))

    def test_manifest_carries_no_raw_firmware_bytes_or_private_paths(self):
        blob = repr(self.manifest)
        self.assertNotIn("evidence/private", blob)
        self.assertNotIn("/home/", blob)


class PublicationTests(unittest.TestCase):
    def test_write_no_clobber(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            inv.write_no_clobber(path, b"{}\n")
            self.assertEqual(path.read_bytes(), b"{}\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                inv.write_no_clobber(path, b"changed\n")


if __name__ == "__main__":
    unittest.main()
