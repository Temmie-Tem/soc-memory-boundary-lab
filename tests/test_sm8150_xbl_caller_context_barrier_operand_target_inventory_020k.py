"""Focused tests for the bounded 020K operand/target inventory."""

from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_caller_context_barrier_operand_target_inventory_020k as inventory


def build_elf(segments: list[tuple[int, int, bytes]]) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4:6] = b"\x02\x01"
    header[6] = 1
    phoff, phentsize = 64, 56
    struct.pack_into("<Q", header, 0x20, phoff)
    struct.pack_into("<H", header, 0x36, phentsize)
    struct.pack_into("<H", header, 0x38, len(segments))
    table = bytearray()
    body = bytearray()
    body_start = phoff + phentsize * len(segments)
    for vaddr, flags, payload in segments:
        file_offset = body_start + len(body)
        table += struct.pack("<IIQQQQQQ", 1, flags, file_offset, vaddr, vaddr, len(payload), len(payload), 0x1000)
        body += payload
    return bytes(header) + bytes(table) + bytes(body)


def image_for(values: list[int], code_va: int = 0x1000) -> inventory.Image:
    payload = b"".join(struct.pack("<I", value) for value in values)
    return inventory.Image(build_elf([(code_va, 5, payload)]))


class DecoderTests(unittest.TestCase):
    def test_b_cond_decodes_signed_imm19_and_condition(self) -> None:
        result = inventory.decode_b_cond(0x54000040 | 0xB, 0x1000)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["condition"], 0xB)
        self.assertEqual(result["imm19"], 2)
        self.assertEqual(result["target_va"], 0x1008)

    def test_cbz_and_cbnz_decode_sf_op_rt_and_target(self) -> None:
        cbz = inventory.decode_cbz_cbnz(0x34000040, 0x1000)
        cbnz = inventory.decode_cbz_cbnz(0xB5000041, 0x1000)
        self.assertEqual((cbz["sf"], cbz["op"], cbz["rt"], cbz["operation"], cbz["target_va"]), (0, 0, 0, "CBZ", 0x1008))
        self.assertEqual((cbnz["sf"], cbnz["op"], cbnz["rt"], cbnz["operation"], cbnz["target_va"]), (1, 1, 1, "CBNZ", 0x1008))

    def test_pair_decodes_offset_and_preindex_ldp_stp(self) -> None:
        stp_offset = inventory.decode_pair_memory(0xA9047BFD)
        stp_pre = inventory.decode_pair_memory(0xA9BF7BFD)
        ldp_offset = inventory.decode_pair_memory(0xA9447BFD)
        ldp_pre = inventory.decode_pair_memory(0xA9FF7BFD)
        self.assertEqual((stp_offset["operation"], stp_offset["addressing_mode"], stp_offset["offset_bytes"], stp_offset["opc"], stp_offset["L"], stp_offset["S"]), ("STP", "OFFSET", 64, 2, 0, 0))
        self.assertEqual((stp_pre["operation"], stp_pre["addressing_mode"], stp_pre["offset_bytes"], stp_pre["opc"], stp_pre["L"], stp_pre["S"]), ("STP", "PRE_INDEX", -16, 2, 0, 1))
        self.assertEqual((ldp_offset["operation"], ldp_offset["addressing_mode"], ldp_offset["offset_bytes"], ldp_offset["opc"], ldp_offset["L"]), ("LDP", "OFFSET", 64, 2, 1))
        self.assertEqual((ldp_pre["operation"], ldp_pre["addressing_mode"], ldp_pre["offset_bytes"], ldp_pre["L"]), ("LDP", "PRE_INDEX", -16, 1))

    def test_pair_reserved_vector_opcode_and_width_forms_fail_closed(self) -> None:
        self.assertIsNone(inventory.decode_pair_memory(0xAD047BFD))
        self.assertIsNone(inventory.decode_pair_memory(0x69047BFD))
        self.assertIsNone(inventory.decode_pair_memory(0xA8007BFD))
        self.assertEqual(inventory.decode_pair_memory(0x29047BFD)["width_bits"], 32)

    def test_logical_immediate_and_bitfield_fields(self) -> None:
        logical = inventory.decode_logical_immediate(0x321F03E0)
        bitfield = inventory.decode_bitfield(0x33005E22)
        self.assertEqual((logical["sf"], logical["op"], logical["S"], logical["N"], logical["immr"], logical["imms"], logical["rn"], logical["rd"]), (0, 0, 1, 0, 31, 0, 31, 0))
        self.assertEqual((bitfield["sf"], bitfield["opc"], bitfield["N"], bitfield["immr"], bitfield["imms"], bitfield["rn"], bitfield["rd"], bitfield["alias"]), (0, 1, 0, 0, 23, 17, 2, "BFXIL"))

    def test_logical_and_bitfield_reserved_widths_fail_closed(self) -> None:
        self.assertIsNone(inventory.decode_logical_immediate(0xB21F03E0))
        self.assertIsNone(inventory.decode_logical_immediate(0x321FFFE0))
        self.assertIsNone(inventory.decode_bitfield(0xB3005E22))
        self.assertIsNone(inventory.decode_bitfield(0x73005E22))
        self.assertIsNone(inventory.decode_bitfield(0x3B005E22))

    def test_branch_target_must_stay_in_same_executable_segment(self) -> None:
        image = image_for([0x54001FE0], 0x1000)
        decoded = inventory.decode_b_cond(image.word(0x1000), 0x1000)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        with self.assertRaises(inventory.TraceError):
            inventory._target_in_segment(image, 0x1000, decoded["target_va"])

    def test_branch_alignment_is_checked(self) -> None:
        image = image_for([0x54000000], 0x1000)
        with self.assertRaises(inventory.TraceError):
            inventory._target_in_segment(image, 0x1000, 0x1002)
        with self.assertRaises(inventory.TraceError):
            inventory.decode_stop(image, 0x1002, "B_COND")


class InventoryTests(unittest.TestCase):
    def test_exact_manifest_cardinality_family_counts_and_redaction(self) -> None:
        manifest = inventory.build_manifest(inventory.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["census"]["stop_count"], 12)
        self.assertEqual(manifest["census"]["unique_stop_va_count"], 12)
        self.assertEqual(manifest["census"]["family_counts"], inventory.EXPECTED_FAMILY_COUNTS)
        self.assertEqual(len(manifest["census"]["stops"]), 12)
        encoded = json.dumps(manifest)
        self.assertNotIn("evidence/private", encoded)
        self.assertNotIn('"word":', encoded)
        self.assertTrue(all("operands" in row and "word_sha256" in row for row in manifest["census"]["stops"]))

    def test_dependency_tool_and_manifest_hash_drift_fail_closed(self) -> None:
        with mock.patch.object(inventory, "XBL_SHA256", "0" * 64):
            with self.assertRaises(inventory.TraceError):
                inventory.build_manifest(inventory.FIRMWARE_DIR)
        with mock.patch.object(inventory, "DEPENDENCY_020J_TOOL_SHA256", "0" * 64):
            with self.assertRaises(inventory.TraceError):
                inventory.build_manifest(inventory.FIRMWARE_DIR)
        with mock.patch.object(inventory, "DEPENDENCY_020J_MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(inventory.TraceError):
                inventory.build_manifest(inventory.FIRMWARE_DIR)

    def test_stop_cardinality_and_stop_va_mutation_fail_closed(self) -> None:
        image = inventory.Image(inventory.load_exact(inventory.FIRMWARE_DIR / inventory.XBL_NAME))
        dependency = inventory._load_dependency()
        stops = inventory._rederive_stops(image, dependency, inventory.FIRMWARE_DIR)
        with mock.patch.object(inventory, "_rederive_stops", return_value=stops[:-1]):
            with self.assertRaises(inventory.TraceError):
                inventory.build_manifest(inventory.FIRMWARE_DIR)
        altered = copy.deepcopy(stops)
        altered[0]["stop_va"] = altered[1]["stop_va"]
        with mock.patch.object(inventory, "_rederive_stops", return_value=altered):
            with self.assertRaises(inventory.TraceError):
                inventory.build_manifest(inventory.FIRMWARE_DIR)

    def test_stop_word_hash_mutation_fails_closed(self) -> None:
        image = inventory.Image(inventory.load_exact(inventory.FIRMWARE_DIR / inventory.XBL_NAME))
        dependency = inventory._load_dependency()
        stops = copy.deepcopy(dependency["manifest"]["census"]["stops"])
        stops[0]["word_sha256"] = "0" * 64
        dependency["manifest"]["census"]["stops"] = stops
        with self.assertRaises(inventory.TraceError):
            inventory._rederive_stops(image, dependency, inventory.FIRMWARE_DIR)

    def test_no_clobber_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            payload = inventory.encode_manifest(inventory.build_manifest(inventory.FIRMWARE_DIR))
            publication = inventory.write_no_clobber(path, payload)
            self.assertEqual(publication["size_bytes"], len(payload))
            with self.assertRaises(inventory.TraceError):
                inventory.write_no_clobber(path, payload)


if __name__ == "__main__":
    unittest.main()
