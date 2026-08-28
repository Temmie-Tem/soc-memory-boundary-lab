"""Focused tests for the bounded 020C return-helper trace."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_return_helper_trace_020c as trace


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


def add_x(rd: int, rn: int, immediate: int) -> int:
    return 0x91000000 | ((immediate // 1) << 10) | (rn << 5) | rd


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def words(*values: int) -> bytes:
    return b"".join(struct.pack("<I", value) for value in values)


class DecoderTests(unittest.TestCase):
    def test_pinned_decoder_forms(self):
        self.assertEqual(trace.decode_adrp(0x90000100, trace.HELPER_START), (0, 0x9FC36000))
        self.assertEqual(trace.decode_add_sub_imm(0x910B0000), ("ADD", 0, 0, 0x2C0, 0, 64))
        self.assertEqual(trace.decode_bl_target(bl(0x1000, 0x1100), 0x1000), 0x1100)

    def test_decoders_reject_undefined_or_wrong_forms(self):
        self.assertIsNone(trace.decode_adrp(0x91000100, trace.HELPER_START))
        self.assertIsNone(trace.decode_add_sub_imm(0xD18B0000))
        self.assertIsNone(trace.decode_add_sub_imm(0x918B0000))
        self.assertIsNone(trace.decode_bl_target(0xD503201F, 0x1000))


class ExactTraceTests(unittest.TestCase):
    @staticmethod
    def _synthetic_image(extra: bool = False) -> trace.Image:
        helper = words(adrp(0, trace.HELPER_START, 0x9FC36000), add_x(0, 0, 0x2C0), 0xD65F03C0)
        payload = bytes(range(trace.OBJECT_SIZE))
        segments = [
            (trace.HELPER_START, 5, helper),
            (trace.OBJECT_START, 4, payload),
            (trace.CALLER_VAS[0], 5, words(bl(trace.CALLER_VAS[0], trace.HELPER_START))),
            (trace.CALLER_VAS[1], 5, words(bl(trace.CALLER_VAS[1], trace.HELPER_START))),
        ]
        if extra:
            extra_va = trace.CALLER_VAS[1] + 0x100
            segments.append((extra_va, 5, words(bl(extra_va, trace.HELPER_START))))
        return trace.Image(build_elf(segments))

    def test_exact_trace_resolves_static_address_without_runtime_promotion(self):
        image = self._synthetic_image()
        with mock.patch.object(trace, "OBJECT_SHA256", hashlib.sha256(bytes(range(trace.OBJECT_SIZE))).hexdigest()):
            result = trace.trace_helper(image)
        self.assertEqual(result["status"], "SUPPORTED_BOUNDED_STATIC_RETURN_HELPER_TRACE")
        self.assertEqual(result["direct_callers"]["count"], 2)
        self.assertEqual(result["return"]["va"], "0x9fc362c0")
        self.assertEqual(result["return"]["runtime_value"], "UNKNOWN")
        self.assertEqual(result["return"]["runtime_physical_mapping"], "UNKNOWN")

    def test_exact_manifest_is_class_c_and_publicly_redacted(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["device_access"], "none")
        self.assertNotIn("evidence/private", __import__("json").dumps(manifest))

    def test_hash_and_caller_cardinality_gates_fail_closed(self):
        image = self._synthetic_image()
        with mock.patch.multiple(
            trace,
            HELPER_SHA256=hashlib.sha256(image.read(trace.HELPER_START, trace.HELPER_END - trace.HELPER_START)).hexdigest(),
            OBJECT_SHA256=hashlib.sha256(image.read(trace.OBJECT_START, trace.OBJECT_SIZE)).hexdigest(),
        ):
            with self.assertRaises(trace.TraceError):
                trace.trace_helper(self._synthetic_image(extra=True))

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
