"""Focused tests for the bounded 020J barrier-opcode inventory."""

from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_caller_context_barrier_opcode_inventory_020j as trace


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


def words(values: list[int]) -> bytes:
    return b"".join(struct.pack("<I", value) for value in values)


def image_for(values: list[int], code_va: int = 0x1000) -> trace.Image:
    return trace.Image(build_elf([(code_va, 5, words(values))]))


class DecoderTests(unittest.TestCase):
    def test_control_compare_and_memory_families(self):
        self.assertEqual(trace.decode_opcode_family(0x54000000, 0x1000)["family"], "B_COND")
        self.assertEqual(trace.decode_opcode_family(0x34000000, 0x1000)["family"], "CBZ_CBNZ")
        self.assertEqual(trace.decode_opcode_family(0x36000000, 0x1000)["family"], "TBZ_TBNZ")
        self.assertEqual(trace.decode_opcode_family(0xEB00001F, 0x1000)["family"], "CMP_SUBS")
        self.assertEqual(trace.decode_opcode_family(0xF100001F, 0x1000)["family"], "CMP_SUBS")
        self.assertEqual(trace.decode_opcode_family(0xA9047BFD, 0x1000)["family"], "LDP_STP_PAIR")
        self.assertEqual(trace.decode_opcode_family(0xA9BF7BFD, 0x1000)["family"], "LDP_STP_PAIR")
        self.assertEqual(trace.decode_opcode_family(0x33005E22, 0x1000)["family"], "BITFIELD")
        self.assertEqual(trace.decode_opcode_family(0x321F03E0, 0x1000)["family"], "LOGICAL_OR_BITMASK_IMMEDIATE")

    def test_branch_families_do_not_collide(self):
        self.assertEqual(trace.decode_opcode_family(0x14000002, 0x1000)["family"], "DIRECT_B")
        self.assertEqual(trace.decode_opcode_family(0x94000002, 0x1000)["family"], "DIRECT_BL")
        self.assertEqual(trace.decode_opcode_family(0xD65F03C0, 0x1000)["family"], "RET_X30")

    def test_wrong_vector_pair_and_unknown_are_fail_closed(self):
        self.assertEqual(trace.decode_opcode_family(0xAD000000, 0x1000)["family"], "UNKNOWN_OPCODE")
        self.assertEqual(trace.decode_opcode_family(0x33400000, 0x1000)["family"], "UNKNOWN_OPCODE")
        self.assertEqual(trace.decode_opcode_family(0xB21F03E0, 0x1000)["family"], "UNKNOWN_OPCODE")
        self.assertEqual(trace.decode_opcode_family(0xFFFFFFFF, 0x1000)["family"], "UNKNOWN_OPCODE")


class InventoryTests(unittest.TestCase):
    def test_exact_manifest_is_class_c_and_family_counts_are_bounded(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["census"]["unsupported_stop_count"], 12)
        self.assertEqual(manifest["census"]["unique_stop_va_count"], 12)
        self.assertEqual(manifest["census"]["family_counts"], trace.EXPECTED_FAMILY_COUNTS)
        self.assertEqual(len(manifest["census"]["stops"]), 12)
        self.assertNotIn("evidence/private", json.dumps(manifest))
        self.assertNotIn('"word":', json.dumps(manifest))

    def test_dependency_hash_and_no_clobber(self):
        with mock.patch.object(trace, "DEPENDENCY_020I_MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace.write_no_clobber(path, b"{}\n")
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(path, b"{}\n")

    def test_stop_cardinality_and_family_drift_fail_closed(self):
        image = trace.Image(trace.load_exact(trace.FIRMWARE_DIR / trace.XBL_NAME))
        dependency = trace._load_public_dependency()
        stops = trace._rederive_stops(image, dependency, trace.FIRMWARE_DIR)
        with mock.patch.object(trace, "_rederive_stops", return_value=stops[:-1]):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)
        altered = copy.deepcopy(stops)
        altered[0]["stop_va"] = altered[1]["stop_va"]
        with mock.patch.object(trace, "_rederive_stops", return_value=altered):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)

    def test_public_dependency_redecode_is_not_replaceable(self):
        image = image_for([0xFFFFFFFF, 0x94000000])
        dependency = trace._load_public_dependency()
        with mock.patch.object(trace, "build_020i_manifest", return_value={"census": {"callsites": []}}):
            with self.assertRaises(trace.TraceError):
                trace._rederive_stops(image, dependency, trace.FIRMWARE_DIR)


if __name__ == "__main__":
    unittest.main()
