"""Focused tests for the bounded 020F slot-load use trace."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_static_slot_load_use_020f as trace


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


def ldr_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def str_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def mov_x(rd: int, rm: int) -> int:
    return 0xAA0003E0 | (rm << 16) | rd


def image_for(code_words: list[int], code_va: int = 0x1000) -> trace.Image:
    return trace.Image(build_elf([(code_va, 5, words(code_words))]))


def row(seed_va: int, register: int = 0, width: int = 64, offset: int = 0x138) -> dict[str, object]:
    return {
        "va": f"0x{seed_va:08x}",
        "kind": "LDR",
        "width_bits": width,
        "register": f"{'W' if width == 32 else 'X'}{register}",
        "slot_offset": f"0x{offset:08x}",
        "slot_va": f"0x{trace.STATIC_SLOT_PAGE + offset:08x}",
    }


class DecoderTests(unittest.TestCase):
    def test_supported_decoders(self):
        self.assertEqual(trace.decode_add_sub_immediate(0x9100052A), ("ADD", 10, 9, 1, 64))
        self.assertEqual(trace.decode_add_sub_register(0x8B00002A), ("ADD", 10, 1, 0, 64))
        self.assertEqual(trace.decode_madd(0x9B00212A), (64, 10, 9, 0, 8))
        self.assertEqual(trace.decode_mov_register(mov_x(1, 0)), (64, 0, 1))
        self.assertEqual(trace.decode_bl_target(bl(0x1000, 0x1100), 0x1000), 0x1100)
        self.assertEqual(trace.decode_conditional_b(0x54FFFF81, 0x1000), 0xFF0)
        self.assertEqual(trace.decode_cbz(0xB5000000), (64, 0))
        self.assertEqual(trace.decode_tbz(0x37000000), 0)
        self.assertEqual(trace.decode_register_offset_memory(0xB86B6940), ("LDR", 32, 0, 10, 11))

    def test_wrong_forms_fail_closed(self):
        self.assertIsNone(trace.decode_add_sub_immediate(0xB9400000))
        self.assertIsNone(trace.decode_add_sub_register(0x8B000020 | (1 << 10)))
        self.assertIsNone(trace.decode_madd(0x9B200000))
        self.assertIsNone(trace.decode_mov_register(0xAA000020))
        self.assertIsNone(trace.decode_register_offset_memory((0xB86B6940 & ~(0x7 << 13)) | (0x2 << 13)))


class TraceTests(unittest.TestCase):
    def test_arithmetic_copy_and_tainted_store_are_recorded(self):
        image = image_for([
            0xD503201F,
            mov_x(1, 0),
            0x91000422,
            str_x(2, 2, 0x20),
            0xD65F03C0,
        ], code_va=0x1000)
        result = trace.trace_load(image, row(0x1000, register=0))
        kinds = [event["kind"] for event in result["events"]]
        self.assertIn("REGISTER_COPY", kinds)
        self.assertIn("ARITHMETIC_USE", kinds)
        self.assertIn("DIRECT_TAINTED_STORE", kinds)

    def test_register_offset_address_use_and_unknown_barrier(self):
        image = image_for([
            0xD503201F,
            0xB86B6940,
            0xD503201F,
        ], code_va=0x1000)
        result = trace.trace_load(image, row(0x1000, register=10))
        self.assertEqual(result["events"][0]["kind"], "REGISTER_OFFSET_ADDRESS_USE")
        image_unknown = image_for([0xD503201F, 0xD503201F], code_va=0x1000)
        unknown = trace.trace_load(image_unknown, row(0x1000, register=0))
        self.assertEqual(unknown["events"][0]["kind"], "UNKNOWN_BARRIER")

    def test_caller_saved_bl_barrier_and_callee_saved_conditional(self):
        caller_saved = image_for([0xD503201F, bl(0x1004, 0x1100), str_x(8, 2, 0x20)], code_va=0x1000)
        result = trace.trace_load(caller_saved, row(0x1000, register=8))
        self.assertEqual(result["events"][0]["kind"], "CALLER_SAVED_BL_BARRIER")
        callee_saved = image_for([0xD503201F, bl(0x1004, 0x1100), str_x(20, 2, 0x20)], code_va=0x1000)
        result = trace.trace_load(callee_saved, row(0x1000, register=20))
        self.assertEqual(result["events"][0]["kind"], "CALLEE_SAVED_BL_CONDITIONAL")
        self.assertIn("DIRECT_TAINTED_STORE", [event["kind"] for event in result["events"]])

    def test_x30_is_caller_saved_and_movk_stops_without_bit_lattice(self):
        image = image_for([0xD503201F, mov_x(30, 0), bl(0x1008, 0x1100), str_x(30, 2, 0x20)], code_va=0x1000)
        result = trace.trace_load(image, row(0x1000, register=0))
        self.assertEqual(result["events"][1]["kind"], "CALLER_SAVED_BL_BARRIER")
        image_movk = image_for([0xD503201F, 0xF2800020, str_x(0, 2, 0x20)], code_va=0x1000)
        result = trace.trace_load(image_movk, row(0x1000, register=0))
        self.assertEqual(result["events"][0]["kind"], "PARTIAL_KILL")
        self.assertNotIn("DIRECT_TAINTED_STORE", [event["kind"] for event in result["events"]])

    def test_exact_manifest_is_class_c_and_seed_set_is_pinned(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["summary"]["seed_load_count"], 12)
        self.assertEqual(manifest["summary"]["event_counts"], {
            "ADDRESS_BASE_USE": 10,
            "ARITHMETIC_USE": 2,
            "CALLER_SAVED_BL_BARRIER": 4,
            "CONTROL_BARRIER": 5,
            "REGISTER_COPY": 1,
            "REGISTER_OFFSET_ADDRESS_USE": 2,
            "RETURN_USE": 1,
            "UNKNOWN_BARRIER": 2,
        })
        self.assertNotIn("DIRECT_TAINTED_STORE", manifest["summary"]["event_counts"])
        self.assertEqual(manifest["inputs"]["dependency_020e"]["manifest_sha256"], trace.DEPENDENCY_020E_MANIFEST_SHA256)
        self.assertNotIn("evidence/private", json.dumps(manifest))

    def test_020e_dependency_hash_mismatch_fails_closed(self):
        with mock.patch.object(trace, "DEPENDENCY_020E_MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)

    def test_public_write_is_no_clobber_and_nofollow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace.write_no_clobber(path, b"{}\n")
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(path, b"{}\n")
            target = Path(directory) / "target"
            target.write_bytes(b"keep")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(link, b"replace")
            self.assertEqual(target.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
