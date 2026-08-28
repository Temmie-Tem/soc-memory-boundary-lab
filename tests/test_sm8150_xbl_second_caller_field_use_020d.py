"""Focused tests for the bounded 020D second-caller field-use trace."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_second_caller_field_use_020d as trace


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


def ldr_w(rt: int, rn: int, offset: int) -> int:
    return 0xB9400000 | ((offset // 4) << 10) | (rn << 5) | rt


def ldr_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def str_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def ldp_x(rt1: int, rt2: int, rn: int, offset: int) -> int:
    return 0xA9400000 | ((offset // 8) << 15) | (rt2 << 10) | (rn << 5) | rt1


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def words(values: list[int]) -> bytes:
    return b"".join(struct.pack("<I", value) for value in values)


class DecoderTests(unittest.TestCase):
    def test_pinned_decoders(self):
        self.assertEqual(trace.decode_adrp(0x900000C8, trace.CALLER_START + 0x10), (8, trace.STATIC_SLOT_PAGE))
        self.assertEqual(trace.decode_add_sub_imm(0x910003FD), ("ADD", 29, 31, 0, 0, 64))
        self.assertEqual(trace.decode_ldr_unsigned(ldr_w(12, 0, 0x0C)), (32, 12, 0, 0x0C))
        self.assertEqual(trace.decode_str_unsigned(str_x(15, 11, 0x158)), (64, 15, 11, 0x158))
        self.assertEqual(trace.decode_ldp_unsigned(ldp_x(8, 15, 0, 0x18)), (64, 8, 15, 0, 0x18))

    def test_wrong_forms_fail_closed(self):
        self.assertIsNone(trace.decode_adrp(0x910000C8, trace.CALLER_START + 0x10))
        self.assertIsNone(trace.decode_add_sub_imm(0x918003FD))
        self.assertIsNone(trace.decode_ldr_unsigned(0xD503201F))
        self.assertIsNone(trace.decode_str_unsigned(0xD503201F))
        self.assertIsNone(trace.decode_ldp_unsigned(0xA8C10400))


class ExactTraceTests(unittest.TestCase):
    @staticmethod
    def _image(extra: bool = False) -> trace.Image:
        # Build the exact bounded second caller with synthetic object bytes.
        start = trace.CALLER_START
        words_list = [0xD503201F] * ((trace.CALLER_END - start) // 4)
        exact = {
            0x00: 0xA9BF7BFD, 0x04: 0x910003FD, 0x08: bl(start + 0x08, trace.HELPER_START),
            0x0C: ldp_x(10, 9, 0, 0x28), 0x10: adrp(8, start + 0x10, trace.STATIC_SLOT_PAGE),
            0x14: ldr_x(11, 0, 0x38), 0x18: adrp(13, start + 0x18, trace.STATIC_SLOT_PAGE),
            0x1C: ldr_w(12, 0, 0x0C), 0x20: adrp(14, start + 0x20, trace.STATIC_SLOT_PAGE),
            0x24: str_x(9, 8, 0x138), 0x28: adrp(9, start + 0x28, trace.STATIC_SLOT_PAGE),
            0x2C: ldp_x(8, 15, 0, 0x18), 0x30: str_x(11, 13, 0x140),
            0x34: adrp(11, start + 0x34, trace.STATIC_SLOT_PAGE), 0x38: str_x(12, 9, 0x148),
            0x3C: adrp(12, start + 0x3C, trace.STATIC_SLOT_PAGE), 0x40: str_x(8, 14, 0x150),
            0x44: str_x(15, 11, 0x158), 0x48: str_x(10, 12, 0x160),
            0x4C: 0xA8C17BFD, 0x50: 0xD65F03C0,
        }
        for offset, word in exact.items():
            words_list[offset // 4] = word
        helper = words([0x90000100, 0x910B0000, 0xD65F03C0])
        object_bytes = bytes(range(trace.OBJECT_SIZE))
        segments = [
            (trace.HELPER_START, 5, helper),
            (trace.OBJECT_START, 4, object_bytes),
            (trace.CALLER_VAS[0], 5, words([bl(trace.CALLER_VAS[0], trace.HELPER_START)])),
            (start, 5, words(words_list)),
        ]
        if extra:
            extra_va = 0x9FC27000
            segments.append((extra_va, 5, words([bl(extra_va, trace.HELPER_START)])))
        return trace.Image(build_elf(segments))

    def _synthetic_constants(self, image: trace.Image):
        return mock.patch.multiple(
            trace,
            HELPER_SHA256=hashlib.sha256(image.read(trace.HELPER_START, trace.HELPER_END - trace.HELPER_START)).hexdigest(),
            CALLER_SHA256=hashlib.sha256(image.read(trace.CALLER_START, trace.CALLER_SIZE)).hexdigest(),
            OBJECT_SHA256=hashlib.sha256(image.read(trace.OBJECT_START, trace.OBJECT_SIZE)).hexdigest(),
        )

    def test_symbolic_object_fields_reach_static_slots(self):
        image = self._image()
        with self._synthetic_constants(image):
            result = trace.trace_second_caller(image)
        self.assertEqual(result["status"], "SUPPORTED_BOUNDED_SECOND_CALLER_FIELD_USE_TRACE")
        self.assertEqual(result["direct_callers"]["count"], 2)
        self.assertEqual([row["destination"]["va"] for row in result["static_slot_stores"]], [
            "0x9fc3e138", "0x9fc3e140", "0x9fc3e148", "0x9fc3e150", "0x9fc3e158", "0x9fc3e160"
        ])
        self.assertTrue(all(row["source_value"]["origin"] == "UNKNOWN" for row in result["static_slot_stores"]))

    def test_hash_and_extra_caller_gates_fail_closed(self):
        image = self._image()
        with self._synthetic_constants(image):
            with self.assertRaises(trace.TraceError):
                trace.trace_second_caller(self._image(extra=True))

    def test_exact_manifest_is_class_c_and_no_device(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["device_access"], "none")
        self.assertNotIn("evidence/private", __import__("json").dumps(manifest))

    def test_public_write_is_no_clobber_and_no_follow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            trace.write_no_clobber(path, b"{}\n")
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(path, b"{}\n")
            target = root / "target"
            target.write_bytes(b"keep")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(link, b"replace")
            self.assertEqual(target.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
