"""Focused tests for the bounded 020H role/base-origin census."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_static_slot_function_role_base_origin_020h as trace


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


def image_for(values: list[int], code_va: int = 0x1000) -> trace.Image:
    return trace.Image(build_elf([(code_va, 5, words(values))]))


class DecoderTests(unittest.TestCase):
    def test_ret_and_direct_branch_decoders(self):
        self.assertEqual(trace.decode_ret(0xD65F03C0), 30)
        self.assertEqual(trace.decode_direct_branch(0x14000002, 0x1000), 0x1008)
        self.assertIsNone(trace.decode_direct_branch(0x94000002, 0x1000))

    def test_wrong_ret_link_register_fails_closed(self):
        self.assertIsNone(trace.decode_ret(0xD65F03A0))

    def test_direct_caller_census_is_exact_for_synthetic_image(self):
        image = image_for([0x94000002, 0xD503201F, 0xD65F03C0])
        self.assertEqual(trace.direct_callers(image, 0x1008), ["0x00001000"])


class RoleTests(unittest.TestCase):
    def test_static_seed_and_argument_base_classifications(self):
        image = image_for([ldr_x(8, 9, 0x20), 0xD503201F])
        block = trace.Block(0x1000, 0x1008, "REGION_END")
        seeded = trace.trace_base_origin(image, block, 0x1004, "X8", "0x00001000", "0x9fc3e138")
        self.assertEqual(seeded["classification"], "STATIC_SLOT_SEED")
        unresolved = trace.trace_base_origin(image, block, 0x1004, "X7", "0x00001000", "0x9fc3e138")
        self.assertEqual(unresolved["classification"], "ARGUMENT_OR_UNKNOWN")

    def test_store_does_not_define_base_register(self):
        image = image_for([str_x(8, 9, 0x20), 0xD503201F])
        block = trace.Block(0x1000, 0x1008, "REGION_END")
        result = trace.trace_base_origin(image, block, 0x1004, "X8", "0x00001000", "0x9fc3e138")
        self.assertEqual(result["classification"], "ARGUMENT_OR_UNKNOWN")

    def test_unknown_instruction_is_an_explicit_boundary(self):
        image = image_for([0xFFFFFFFF, 0xD503201F])
        block = trace.Block(0x1000, 0x1008, "REGION_END")
        result = trace.trace_base_origin(image, block, 0x1004, "X8", "0x00001000", "0x9fc3e138")
        self.assertEqual(result["classification"], "UNSUPPORTED_BOUNDARY")

    def test_return_delimited_partition_and_unknown_role(self):
        image = image_for([0xD503201F, 0xD65F03C0, 0xD503201F, 0xD65F03C0])
        with mock.patch.object(trace, "ROLE_REGION_START", 0x1000), mock.patch.object(trace, "ROLE_REGION_END", 0x1010):
            blocks = trace.recover_blocks(image, {va: image.word(va) for va in range(0x1000, 0x1010, 4)})
        self.assertEqual([(block.start, block.end, block.terminator) for block in blocks], [(0x1000, 0x1008, "RET"), (0x1008, 0x1010, "RET")])
        role = trace._block_role(image, blocks[0])
        self.assertEqual(role["role"], "UNKNOWN_ROLE_UNSUPPORTED_FORM")


class CensusTests(unittest.TestCase):
    def test_exact_manifest_is_class_c_and_bounded(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["census"]["access_witness_count"], 12)
        self.assertEqual(manifest["census"]["unique_access_va_count"], 11)
        self.assertEqual(manifest["census"]["role_row_count"], 11)
        self.assertEqual(manifest["census"]["block_count"], 7)
        self.assertEqual(len(manifest["census"]["roles"]), 11)
        self.assertNotIn("evidence/private", json.dumps(manifest))

    def test_dependency_hash_and_no_clobber(self):
        with mock.patch.object(trace, "DEPENDENCY_020G_MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace.write_no_clobber(path, b"{}\n")
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(path, b"{}\n")

    def test_role_region_hash_drift_fails_closed(self):
        with mock.patch.object(trace, "ROLE_REGION_SHA256", "0" * 64):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)

    def test_rederived_access_set_drift_fails_closed(self):
        dependency = trace._load_public_dependency()
        image = trace.Image(trace.load_exact(trace.FIRMWARE_DIR / trace.XBL_NAME))
        altered = trace.build_020g_manifest(trace.FIRMWARE_DIR)
        altered["census"]["accesses"] = altered["census"]["accesses"][:-1]
        with mock.patch.object(trace, "build_020g_manifest", return_value=altered):
            with self.assertRaises(trace.TraceError):
                trace._rederive_accesses(image, dependency, trace.FIRMWARE_DIR)


if __name__ == "__main__":
    unittest.main()
