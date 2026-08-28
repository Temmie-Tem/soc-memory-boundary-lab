"""Focused tests for the bounded 020I caller-context census."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_static_slot_caller_context_entry_role_020i as trace


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


def adrp(rd: int, target_page: int, va: int) -> int:
    delta = (target_page - (va & ~0xFFF)) >> 12
    immediate = delta & ((1 << 21) - 1)
    return 0x90000000 | ((immediate & 0x3) << 29) | (((immediate >> 2) & 0x7FFFF) << 5) | rd


def ldr_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def bl(source_va: int, target_va: int) -> int:
    return 0x94000000 | (((target_va - source_va) // 4) & 0x03FFFFFF)


class DecoderTests(unittest.TestCase):
    def test_b_and_bl_are_distinct(self):
        self.assertEqual(trace.decode_direct_branch(0x14000002, 0x1000), 0x1008)
        self.assertIsNone(trace.decode_direct_branch(bl(0x1000, 0x1008), 0x1000))
        self.assertEqual(trace.decode_bl_target(bl(0x1000, 0x1008), 0x1000), 0x1008)

    def test_direct_bl_source_target_is_checked(self):
        image = image_for([bl(0x1000, 0x1008), 0xD503201F, 0xD503201F])
        with self.assertRaises(trace.TraceError):
            trace.trace_callsite(image, 0x1000, 0x100C)


class TraceTests(unittest.TestCase):
    def test_unsupported_instruction_stops_fail_closed(self):
        image = image_for([0xFFFFFFFF, bl(0x1004, 0x100C), 0xD503201F, 0xD503201F])
        result = trace.trace_callsite(image, 0x1004, 0x100C)
        self.assertEqual(result["classification"], "CALLER_CONTEXT_UNSUPPORTED")
        self.assertEqual(result["stop_reason"], "UNSUPPORTED")

    def test_ret_stops_without_promoting_context(self):
        image = image_for([0xD65F03C0, bl(0x1004, 0x100C), 0xD503201F, 0xD503201F])
        result = trace.trace_callsite(image, 0x1004, 0x100C)
        self.assertEqual(result["classification"], "ARGUMENT_OR_UNKNOWN")
        self.assertEqual(result["stop_reason"], "RET")

    def test_static_slot_origin_is_tracked_forward(self):
        image = image_for([adrp(0, trace.STATIC_SLOT_PAGE, 0x1000), ldr_x(0, 0, 0), bl(0x1008, 0x1010)])
        result = trace.trace_callsite(image, 0x1008, 0x1010)
        self.assertEqual(result["classification"], "STATIC_SLOT_ORIGIN")

    def test_classification_split_and_static_register_kill_are_fail_closed(self):
        image = trace.Image(trace.load_exact(trace.FIRMWARE_DIR / trace.XBL_NAME))
        dependency = trace._load_public_dependency()
        source_rows = trace._rederive_sources(image, dependency, trace.FIRMWARE_DIR)

        def all_unsupported(_image: trace.Image, source_va: int, target_va: int) -> dict[str, object]:
            return {"source_va": trace._fmt(source_va), "target_va": trace._fmt(target_va), "window_start": trace._fmt(source_va), "window_end_exclusive": trace._fmt(source_va), "window_instructions": trace.CALLER_WINDOW_INSTRUCTIONS, "stop_reason": "UNSUPPORTED", "stop_va": trace._fmt(source_va), "classification": "CALLER_CONTEXT_UNSUPPORTED", "definitions": []}

        with mock.patch.object(trace, "_rederive_sources", return_value=source_rows), mock.patch.object(trace, "trace_callsite", side_effect=all_unsupported):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)

        image = image_for([adrp(0, trace.STATIC_SLOT_PAGE, 0x1000), ldr_x(0, 1, 0), 0xB9000000 | (0 << 5) | 0, bl(0x100C, 0x1010)])
        result = trace.trace_callsite(image, 0x100C, 0x1010)
        self.assertEqual(result["classification"], "ARGUMENT_COPY_OR_CONSTANT")

    def test_window_limit_is_explicit(self):
        image = image_for([0x91000000] * 17 + [bl(0x1044, 0x1050)])
        result = trace.trace_callsite(image, 0x1044, 0x1050)
        self.assertEqual(result["stop_reason"], "WINDOW_LIMIT")


class CensusTests(unittest.TestCase):
    def test_exact_manifest_is_class_c_and_cardinality_bounded(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["census"]["callsite_count"], 20)
        self.assertEqual(manifest["census"]["unique_callsite_va_count"], 20)
        self.assertEqual(manifest["census"]["classification_counts"], {"ARGUMENT_COPY_OR_CONSTANT": 2, "ARGUMENT_OR_UNKNOWN": 6, "CALLER_CONTEXT_UNSUPPORTED": 12})
        self.assertEqual(len(manifest["census"]["callsites"]), 20)
        self.assertNotIn("evidence/private", json.dumps(manifest))

    def test_dependency_hash_and_no_clobber(self):
        with mock.patch.object(trace, "DEPENDENCY_020H_MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace.write_no_clobber(path, b"{}\n")
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(path, b"{}\n")

    def test_dependency_role_drift_fails_closed(self):
        dependency = trace._load_public_dependency()
        image = trace.Image(trace.load_exact(trace.FIRMWARE_DIR / trace.XBL_NAME))
        altered = trace.build_020h_manifest(trace.FIRMWARE_DIR)
        altered["census"]["roles"] = altered["census"]["roles"][:-1]
        with mock.patch.object(trace, "build_020h_manifest", return_value=altered):
            with self.assertRaises(trace.TraceError):
                trace._rederive_sources(image, dependency, trace.FIRMWARE_DIR)

    def test_role_entry_mutation_fails_closed(self):
        image = image_for([0xD503201F, bl(0x1004, 0x1008)])
        with self.assertRaises(trace.TraceError):
            trace.trace_callsite(image, 0x1004, 0x100C)


if __name__ == "__main__":
    unittest.main()
