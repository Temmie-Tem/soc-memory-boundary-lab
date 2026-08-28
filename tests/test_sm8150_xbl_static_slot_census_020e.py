"""Focused tests for the bounded 020E static-slot census."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_static_slot_census_020e as trace


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


def adrp(rd: int, va: int, page: int) -> int:
    delta = ((page - (va & ~0xFFF)) >> 12) & 0x1FFFFF
    return 0x90000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | rd


def ldr_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def str_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def words(values: list[int]) -> bytes:
    return b"".join(struct.pack("<I", value) for value in values)


class DecoderTests(unittest.TestCase):
    def test_scalar_decoders_and_kill_forms(self):
        self.assertEqual(trace.decode_adrp(0x900000C8, 0x9FC26E34), (8, trace.STATIC_SLOT_PAGE))
        self.assertEqual(trace.decode_ldr_unsigned(ldr_x(0, 8, 0x148)), (64, 0, 8, 0x148))
        self.assertEqual(trace.decode_str_unsigned(str_x(9, 8, 0x138)), (64, 9, 8, 0x138))
        self.assertEqual(trace.decode_bl_target(bl(0x1000, 0x1100), 0x1000), 0x1100)
        self.assertIn(11, trace._written_register(0x5280400B))

    def test_wrong_forms_fail_closed(self):
        self.assertIsNone(trace.decode_adrp(0x910000C8, 0x1000))
        self.assertIsNone(trace.decode_ldr_unsigned(0xD503201F))
        self.assertIsNone(trace.decode_str_unsigned(0xD503201F))
        self.assertIsNone(trace.decode_bl_target(0xD503201F, 0x1000))


class CensusTests(unittest.TestCase):
    @staticmethod
    def _synthetic_image() -> trace.Image:
        code_va = 0x1000
        code_words = [
            adrp(8, code_va, trace.STATIC_SLOT_PAGE),
            0x5280400B,  # MOVZ W11,#0x200, recognized non-clobber
            ldr_x(0, 8, 0x138),
            adrp(9, code_va + 12, trace.STATIC_SLOT_PAGE),
            str_x(1, 9, 0x140),
        ]
        helper = words([0x90000100, 0x910B0000, 0xD65F03C0])
        caller = bytes(trace.CALLER_SIZE)
        obj = bytes(trace.OBJECT_SIZE)
        return trace.Image(build_elf([
            (trace.HELPER_START, 5, helper),
            (trace.CALLER_START, 5, caller),
            (trace.OBJECT_START, 4, obj),
            (code_va, 5, words(code_words)),
        ]))

    def test_synthetic_accesses_are_bounded(self):
        image = self._synthetic_image()
        with mock.patch.multiple(
            trace,
            HELPER_SHA256=hashlib.sha256(image.read(trace.HELPER_START, trace.HELPER_END - trace.HELPER_START)).hexdigest(),
            CALLER_SHA256=hashlib.sha256(image.read(trace.CALLER_START, trace.CALLER_SIZE)).hexdigest(),
            OBJECT_SHA256=hashlib.sha256(image.read(trace.OBJECT_START, trace.OBJECT_SIZE)).hexdigest(),
        ):
            result = trace.census_slots(image)
        self.assertEqual(result["access_count"], 2)
        self.assertEqual(result["store_count"], 1)
        self.assertEqual(result["load_count"], 1)
        self.assertEqual({row["slot_va"] for row in result["accesses"]}, {"0x9fc3e138", "0x9fc3e140"})

    def test_caller_saved_bl_is_a_fail_closed_barrier(self):
        code_va = 0x1000
        image = trace.Image(build_elf([
            (code_va, 5, words([
                adrp(8, code_va, trace.STATIC_SLOT_PAGE),
                bl(code_va + 4, 0x2000),
                ldr_x(0, 8, 0x138),
            ])),
        ]))
        result = trace.census_slots(image)
        self.assertEqual(result["access_count"], 0)
        self.assertEqual(result["caller_saved_call_barrier_count"], 1)
        self.assertEqual(result["barriers"][0]["kind"], "CALLER_SAVED_BL")
        self.assertEqual(result["unknown_barrier_count"], 0)

    def test_callee_saved_bl_is_explicitly_conditional(self):
        code_va = 0x1000
        image = trace.Image(build_elf([
            (code_va, 5, words([
                adrp(20, code_va, trace.STATIC_SLOT_PAGE),
                bl(code_va + 4, 0x2000),
                ldr_x(0, 20, 0x138),
            ])),
        ]))
        result = trace.census_slots(image)
        self.assertEqual(result["access_count"], 1)
        self.assertEqual(result["callee_saved_calls"][0]["page_register"], "X20")

    def test_exact_manifest_has_expected_bounded_split(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["device_access"], "none")
        self.assertEqual(manifest["census"]["access_count"], 18)
        self.assertEqual(manifest["census"]["store_count"], 6)
        self.assertEqual(manifest["census"]["load_count"], 12)
        self.assertNotIn("evidence/private", __import__("json").dumps(manifest))

    def test_dependency_hash_and_no_clobber_gates(self):
        image = self._synthetic_image()
        with mock.patch.object(trace, "CALLER_SHA256", "0" * 64):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace.write_no_clobber(path, b"{}\n")
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(path, b"{}\n")


if __name__ == "__main__":
    unittest.main()
