"""Focused tests for the bounded 020A setter/base trace."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_setter_base_trace_020a as trace


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


def mov_x(rd: int, rn: int) -> int:
    return 0xAA0003E0 | (rn << 16) | rd


def ldr_w(rt: int, rn: int, offset: int) -> int:
    return 0xB9400000 | ((offset // 4) << 10) | (rn << 5) | rt


def ldr_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def ldp_x(rt1: int, rt2: int, rn: int, offset: int) -> int:
    return 0xA9400000 | ((offset // 8) << 15) | (rt2 << 10) | (rn << 5) | rt1


def str_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def str_w(rt: int, rn: int, offset: int) -> int:
    return 0xB9000000 | ((offset // 4) << 10) | (rn << 5) | rt


def adrp(rd: int, va: int, page: int) -> int:
    delta = ((page - (va & ~0xFFF)) >> 12) & 0x1FFFFF
    return 0x90000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | rd


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def words_payload(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


class DecoderTests(unittest.TestCase):
    def test_register_and_memory_decoders(self):
        self.assertEqual(trace.decode_mov_register(mov_x(19, 0)), (0, 19))
        self.assertEqual(trace.decode_ldr_unsigned(ldr_w(3, 0, 0x10)), (32, 3, 0, 0x10))
        self.assertEqual(trace.decode_ldr_unsigned(ldr_x(2, 19, 0x28)), (64, 2, 19, 0x28))
        self.assertEqual(trace.decode_ldp_unsigned(ldp_x(0, 1, 0, 0x18)), (64, 0, 1, 0, 0x18))
        self.assertEqual(trace.decode_str_unsigned(str_x(0, 7, 0x360)), (64, 0, 7, 0x360))
        self.assertEqual(trace.decode_str_unsigned(str_w(3, 4, 0x350)), (32, 3, 4, 0x350))

    def test_decoders_reject_non_matching_forms(self):
        self.assertIsNone(trace.decode_mov_register(mov_x(19, 0) | (1 << 10)))
        self.assertIsNone(trace.decode_ldr_unsigned(0xD503201F))
        self.assertIsNone(trace.decode_ldp_unsigned(0xA8C10400))
        self.assertIsNone(trace.decode_str_unsigned(0xD503201F))

    def test_bl_target_and_symbolic_field(self):
        self.assertEqual(trace.decode_bl_target(bl(0x1000, 0x1100), 0x1000), 0x1100)
        origin = trace.Origin("ENTRY_ARGUMENT", base="incoming X0", width_bits=64)
        field = trace._field(origin, 0x28, 64)
        self.assertEqual(field.describe(), "MEMORY[incoming X0+0x28]")
        with self.assertRaises(trace.TraceError):
            trace._field(trace.UNKNOWN, 0x10, 32)


class ExactTraceTests(unittest.TestCase):
    def _setter_image(self) -> trace.Image:
        page = 0x9FC38000
        words = [
            adrp(8, trace.SETTER_START, page),
            adrp(7, trace.SETTER_START + 4, page),
            adrp(6, trace.SETTER_START + 8, page),
            adrp(5, trace.SETTER_START + 12, page),
            adrp(4, trace.SETTER_START + 16, page),
            str_x(31, 8, 0x368),
            str_x(0, 7, 0x360),
            str_x(1, 6, 0x370),
            str_x(2, 5, 0x378),
            str_w(3, 4, 0x350),
            0xD65F03C0,
        ]
        return trace.Image(build_elf([(trace.SETTER_START, 5, words_payload(words))]))

    def test_setter_requires_exact_five_static_stores(self):
        image = self._setter_image()
        payload = image.read(trace.SETTER_START, trace.SETTER_SIZE)
        with mock.patch.object(trace, "SETTER_SHA256", hashlib.sha256(payload).hexdigest()):
            result = trace.validate_setter(image)
        self.assertEqual(result["store_count"], 5)
        self.assertEqual({row["global"] for row in result["stores"]}, {
            "0x9fc38368", "0x9fc38360", "0x9fc38370", "0x9fc38378", "0x9fc38350"
        })

    def test_caller_trace_resolves_fields_without_values(self):
        start, end = trace.CALLER_CONTEXT_START, trace.CALLER_CONTEXT_END
        words = [0xD503201F] * ((end - start) // 4)
        def put(va: int, word: int) -> None:
            words[(va - start) // 4] = word
        put(trace.CALLER_TRACE_START, mov_x(19, 0))
        put(trace.CALLER_TRACE_START + 4, ldr_w(3, 0, 0x10))
        put(trace.CALLER_TRACE_START + 8, ldp_x(0, 1, 0, 0x18))
        put(trace.CALLER_TRACE_START + 12, ldr_x(2, 19, 0x28))
        put(trace.CALLER_VA, bl(trace.CALLER_VA, trace.SETTER_START))
        payload = words_payload(words)
        image = trace.Image(build_elf([(start, 5, payload)]))
        with mock.patch.object(trace, "CALLER_TRACE_SHA256", hashlib.sha256(
            image.read(trace.CALLER_TRACE_START, trace.CALLER_TRACE_SIZE)
        ).hexdigest()), mock.patch.object(trace, "CALLER_CONTEXT_SHA256", hashlib.sha256(payload).hexdigest()):
            result = trace.trace_caller_arguments(image)
        self.assertEqual(result["status"], "SUPPORTED_BOUNDED_SYMBOLIC_ARGUMENT_TRACE")
        self.assertEqual(result["argument_origins"]["W3"]["origin"], "MEMORY[incoming X0+0x10]")
        self.assertEqual(result["argument_origins"]["X0"]["origin"], "MEMORY[incoming X0+0x18]")
        self.assertEqual(result["argument_origins"]["X1"]["origin"], "MEMORY[incoming X0+0x20]")
        self.assertEqual(result["argument_origins"]["X2"]["origin"], "MEMORY[incoming X0+0x28]")

    def test_exact_input_manifest_is_available_and_class_c(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["setter"]["store_count"], 5)
        self.assertEqual(manifest["direct_callers"]["count"], 1)
        self.assertEqual(manifest["caller_trace"]["current_values"], "UNKNOWN")

    def test_public_write_is_no_clobber(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        payload = (trace.json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace.write_no_clobber(path, payload)
            self.assertEqual(path.read_bytes(), payload)
            with self.assertRaises(FileExistsError):
                trace.write_no_clobber(path, payload)

    def test_exact_reader_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.bin"
            path.write_bytes(b"known")
            with self.assertRaises(trace.TraceError):
                trace.load_exact(path, 5, hashlib.sha256(b"other").hexdigest(), "fixture")

    def test_public_write_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_bytes(b"keep")
            link = Path(directory) / "manifest.json"
            link.symlink_to(target)
            with self.assertRaises((OSError, trace.TraceError)):
                trace.write_no_clobber(link, b"replace")
            self.assertEqual(target.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
