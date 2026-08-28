"""Focused tests for the bounded 020B caller-object origin trace."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_caller_object_origin_020b as trace


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
        table += struct.pack(
            "<IIQQQQQQ", 1, flags, file_offset, vaddr, vaddr, len(payload), len(payload), 0x1000
        )
        body += payload
    return bytes(header) + bytes(table) + bytes(body)


def ldr_w(rt: int, rn: int, offset: int) -> int:
    return 0xB9400000 | ((offset // 4) << 10) | (rn << 5) | rt


def ldr_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def str_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def str_w(rt: int, rn: int, offset: int) -> int:
    return 0xB9000000 | ((offset // 4) << 10) | (rn << 5) | rt


def ldp_x(rt1: int, rt2: int, rn: int, offset: int) -> int:
    return 0xA9400000 | ((offset // 8) << 15) | (rt2 << 10) | (rn << 5) | rt1


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def words_payload(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


class DecoderTests(unittest.TestCase):
    def test_decoders_accept_pinned_forms(self):
        self.assertEqual(trace.decode_add_sp_imm(0x910083E0), (0, 0x20))
        self.assertEqual(trace.decode_ldr_unsigned(ldr_w(14, 0, 0x10)), (32, 14, 0, 0x10))
        self.assertEqual(trace.decode_ldr_unsigned(ldr_x(12, 0, 0x28)), (64, 12, 0, 0x28))
        self.assertEqual(trace.decode_str_unsigned(str_x(9, 31, 0x08)), (64, 9, 31, 0x08))
        self.assertEqual(trace.decode_str_unsigned(str_w(14, 31, 0x34)), (32, 14, 31, 0x34))
        self.assertEqual(trace.decode_ldp_unsigned(ldp_x(11, 10, 31, 0x10)), (64, 11, 10, 31, 0x10))
        self.assertEqual(trace.decode_q_sp(0x3DC003E0), ("LDR_Q", 0, 0))
        self.assertEqual(trace.decode_q_sp(0x3D8007E0), ("STR_Q", 0, 0x10))

    def test_decoders_reject_unrecognized_forms(self):
        self.assertIsNone(trace.decode_add_sp_imm(0x8B0003E0))
        self.assertIsNone(trace.decode_add_sub_imm(0xD18183FF))
        self.assertIsNone(trace.decode_orr_wzr_imm(0xB20003E8))
        self.assertIsNone(trace.decode_ldr_unsigned(0xD503201F))
        self.assertIsNone(trace.decode_str_unsigned(0xD503201F))
        self.assertIsNone(trace.decode_ldp_unsigned(0xA8C10400))
        self.assertIsNone(trace.decode_q_sp(0xD503201F))


class ExactTraceTests(unittest.TestCase):
    @staticmethod
    def _caller_image() -> trace.Image:
        start = trace.CALLER_START
        words = [0xD503201F] * (((trace.CALLER_END - start) // 4) + 1)
        exact = {
            0x00: 0xD10183FF,
            0x04: 0xA9057BFD,
            0x08: 0x910143FD,
            0x0C: bl(start + 0x0C, trace.QUERY_CALL_TARGET),
            0x10: 0x320003E8,
            0x14: ldr_x(9, 0, 0x20),
            0x18: str_w(8, 31, 0x20),
            0x1C: ldr_w(10, 0, 0x00),
            0x20: str_w(10, 31, 0x24),
            0x24: ldr_w(11, 0, 0x04),
            0x28: str_w(11, 31, 0x28),
            0x2C: ldr_w(12, 0, 0x08),
            0x30: str_w(12, 31, 0x2C),
            0x34: ldr_w(13, 0, 0x0C),
            0x38: str_w(13, 31, 0x30),
            0x3C: ldr_w(14, 0, 0x10),
            0x40: str_x(9, 31, 0x08),
            0x44: str_w(14, 31, 0x34),
            0x48: ldr_x(8, 0, 0x18),
            0x4C: str_x(8, 31, 0x00),
            0x50: 0x3DC003E0,
            0x54: 0x3D8007E0,
            0x58: ldp_x(11, 10, 31, 0x10),
            0x5C: str_x(10, 31, 0x40),
            0x60: ldr_x(12, 0, 0x28),
            0x64: 0x910083E0,
            0x68: str_x(11, 31, 0x38),
            0x6C: str_x(12, 31, 0x48),
            0x70: bl(start + 0x70, trace.CONSUMER_START),
            0x74: 0xA9457BFD,
            0x78: 0x910183FF,
            0x7C: 0xD65F03C0,
        }
        for offset, word in exact.items():
            words[offset // 4] = word
        payload = words_payload(words)
        consumer = words_payload([0xB9400001, 0x7100043F, 0x54000301])
        image = trace.Image(build_elf([(trace.CONSUMER_START, 5, consumer), (start, 5, payload)]))
        return image

    def test_exact_trace_resolves_setter_fields_from_opaque_return(self):
        image = self._caller_image()
        with mock.patch.multiple(
            trace,
            CALLER_SHA256=hashlib.sha256(image.read(trace.CALLER_START, trace.CALLER_SIZE)).hexdigest(),
            CALLER_TRACE_SHA256=hashlib.sha256(image.read(trace.CALLER_TRACE_START, trace.CALLER_TRACE_SIZE)).hexdigest(),
            CONSUMER_ENTRY_SHA256=hashlib.sha256(image.read(trace.CONSUMER_START, trace.CONSUMER_ENTRY_SIZE)).hexdigest(),
        ):
            result = trace.trace_object(image)
        self.assertEqual(result["status"], "SUPPORTED_BOUNDED_SYMBOLIC_CALLER_OBJECT_TRACE")
        self.assertEqual(result["consumer_call"]["object_argument"]["origin"], "STACK[SP+0x20]")
        self.assertEqual(result["object_fields"]["W3"]["origin"], "UNKNOWN")
        self.assertEqual(result["object_fields"]["W3"]["field_offset"], "0x0000000c")
        self.assertEqual(result["object_fields"]["X0"]["field_offset"], "0x00000018")
        self.assertEqual(result["object_fields"]["X1"]["field_offset"], "0x00000020")
        self.assertEqual(result["object_fields"]["X2"]["field_offset"], "0x00000028")
        self.assertEqual(result["current_values"], "UNKNOWN")

    def test_trace_rejects_caller_hash_change(self):
        image = self._caller_image()
        with mock.patch.object(trace, "CALLER_SHA256", "0" * 64):
            with self.assertRaises(trace.OriginError):
                trace.trace_object(image)

    def test_trace_rejects_another_direct_consumer_caller(self):
        base = self._caller_image()
        extra_va = trace.CALLER_END + 0x1000
        extra = words_payload([bl(extra_va, trace.CONSUMER_START)])
        image = trace.Image(build_elf([
            (trace.CONSUMER_START, 5, words_payload([0xB9400001, 0x7100043F, 0x54000301])),
            (trace.CALLER_START, 5, base.read(trace.CALLER_START, trace.CALLER_END - trace.CALLER_START + 4)),
            (extra_va, 5, extra),
        ]))
        with mock.patch.multiple(
            trace,
            CALLER_SHA256=hashlib.sha256(image.read(trace.CALLER_START, trace.CALLER_SIZE)).hexdigest(),
            CALLER_TRACE_SHA256=hashlib.sha256(image.read(trace.CALLER_TRACE_START, trace.CALLER_TRACE_SIZE)).hexdigest(),
            QUERY_CALL_SHA256=hashlib.sha256(image.read(trace.QUERY_CALL_VA, 4)).hexdigest(),
            CONSUMER_CALL_SHA256=hashlib.sha256(image.read(trace.CONSUMER_CALLER_VA, 4)).hexdigest(),
            CONSUMER_ENTRY_SHA256=hashlib.sha256(image.read(trace.CONSUMER_START, trace.CONSUMER_ENTRY_SIZE)).hexdigest(),
        ):
            with self.assertRaises(trace.OriginError):
                trace.trace_object(image)

    def test_exact_manifest_is_class_c_and_no_device(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["device_access"], "none")
        self.assertEqual(manifest["trace"]["object_base"]["opaque"], True)

    def test_public_write_is_no_clobber_and_no_symlink(self):
        payload = b"{}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            trace.write_no_clobber(path, payload)
            with self.assertRaises((OSError, trace.OriginError)):
                trace.write_no_clobber(path, payload)
            target = root / "target"
            target.write_bytes(b"keep")
            link = root / "symlink.json"
            link.symlink_to(target)
            with self.assertRaises((OSError, trace.OriginError)):
                trace.write_no_clobber(link, payload)
            self.assertEqual(target.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
