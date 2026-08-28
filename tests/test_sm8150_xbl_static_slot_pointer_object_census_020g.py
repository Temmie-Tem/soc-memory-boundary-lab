"""Focused tests for the bounded 020G pointer/object census."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_static_slot_pointer_object_census_020g as trace


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


def str_w(rt: int, rn: int, offset: int) -> int:
    return 0xB9000000 | ((offset // 4) << 10) | (rn << 5) | rt


def image_for(values: list[int], code_va: int = 0x1000) -> trace.Image:
    return trace.Image(build_elf([(code_va, 5, words(values))]))


def event(seed: str, slot: str, va: str, **details: object) -> dict[str, object]:
    result = {"seed_va": seed, "seed_slot_va": slot, "va": va}
    result.update(details)
    return result


class DecoderTests(unittest.TestCase):
    def test_immediate_and_register_offset_forms(self):
        self.assertEqual(trace.decode_register_offset_memory(0xB86B6940), ("LDR", 32, 0, 10, 11))
        self.assertEqual(trace.decode_ldr_unsigned(ldr_x(9, 8, 0x208)), (64, 9, 8, 0x208))
        self.assertEqual(trace.decode_str_unsigned(str_w(9, 8, 0x24)), (32, 9, 8, 0x24))

    def test_wrong_register_offset_option_fails_closed(self):
        wrong = (0xB86B6940 & ~(0x7 << 13)) | (0x2 << 13)
        self.assertIsNone(trace.decode_register_offset_memory(wrong))


class CensusTests(unittest.TestCase):
    @staticmethod
    def _synthetic_rows(*, register_operation: str = "LDR", duplicate: bool = True, same_seed: bool = False) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for index in range(10):
            operation = "LDR" if index < 7 else "STR"
            rows.append({"shape": "IMMEDIATE_OBJECT_FIELD", "kind": operation, "access_va": f"0x{0x2000 + index * 4:08x}", "seed_slot_va": f"0x{0x9fc3e138 + index * 8:08x}"})
        register_vas = [0x3000, 0x3000] if duplicate else [0x3000, 0x3004]
        for index, access_va in enumerate(register_vas):
            seed_slot_va = 0x9FC3E158 if same_seed else 0x9FC3E158 + index * 8
            rows.append({"shape": "REGISTER_OFFSET_ARRAY_ELEMENT", "kind": register_operation, "access_va": f"0x{access_va:08x}", "seed_slot_va": f"0x{seed_slot_va:08x}"})
        return rows

    def _run_synthetic_census(self, rows: list[dict[str, object]]) -> dict[str, object]:
        source = trace.build_020f_manifest(trace.FIRMWARE_DIR)
        dependency = trace._load_public_manifest_pin()
        with mock.patch.object(trace, "_event_from_word", side_effect=rows):
            return trace.census_pointer_object(image_for([0]), dependency, source)

    def test_redecodes_immediate_and_register_offset_events(self):
        image = image_for([ldr_x(9, 8, 0x208), 0xB86B6940, str_w(9, 8, 0x24)])
        seed = {"va": "0x00001000", "slot_va": "0x9fc3e150"}
        rows = [
            event(seed["va"], seed["slot_va"], "0x00001000", kind="ADDRESS_BASE_USE", operation="LDR", width_bits=64, base="X8", offset="0x00000208", destination="X9"),
            event("0x00001000", "0x9fc3e158", "0x00001004", kind="REGISTER_OFFSET_ADDRESS_USE", operation="LDR", width_bits=32, registers=["X10"], destination_or_source="W0"),
            event("0x00001000", "0x9fc3e150", "0x00001008", kind="ADDRESS_BASE_USE", operation="STR", width_bits=32, base="X8", offset="0x00000024", source="W9"),
        ]
        self.assertEqual(trace._event_from_word(image, seed, rows[0])["shape"], "IMMEDIATE_OBJECT_FIELD")
        seed_register_offset = {"va": "0x00001000", "slot_va": "0x9fc3e158"}
        self.assertEqual(trace._event_from_word(image, seed_register_offset, rows[1])["shape"], "REGISTER_OFFSET_ARRAY_ELEMENT")
        self.assertEqual(trace._event_from_word(image, seed, rows[2])["shape"], "IMMEDIATE_OBJECT_FIELD")

    def test_wrong_event_or_instruction_fails_closed(self):
        image = image_for([0xD503201F])
        seed = {"va": "0x00001000", "slot_va": "0x9fc3e150"}
        with self.assertRaises(trace.TraceError):
            trace._event_from_word(image, seed, event(seed["va"], seed["slot_va"], "0x00001000", kind="ADDRESS_BASE_USE", operation="LDR", width_bits=64, base="X8", offset="0x208"))

    def test_operation_and_register_mutations_fail_closed(self):
        image = image_for([ldr_x(9, 8, 0x208)])
        seed = {"va": "0x00001000", "slot_va": "0x9fc3e150"}
        forged_operation = event(seed["va"], seed["slot_va"], "0x00001000", kind="ADDRESS_BASE_USE", operation="STR", width_bits=64, base="X8", offset="0x00000208", source="X9")
        forged_register = event(seed["va"], seed["slot_va"], "0x00001000", kind="ADDRESS_BASE_USE", operation="LDR", width_bits=64, base="X8", offset="0x00000208", destination="X7")
        with self.assertRaises(trace.TraceError):
            trace._event_from_word(image, seed, forged_operation)
        with self.assertRaises(trace.TraceError):
            trace._event_from_word(image, seed, forged_register)

    def test_aggregate_shape_and_operation_guards_fail_closed(self):
        rows = self._synthetic_rows(register_operation="STR")
        with self.assertRaises(trace.TraceError):
            self._run_synthetic_census(rows)

    def test_unique_and_duplicate_structure_guard_fail_closed(self):
        rows = self._synthetic_rows(duplicate=False)
        with self.assertRaises(trace.TraceError):
            self._run_synthetic_census(rows)

    def test_duplicate_witness_requires_distinct_seeds(self):
        rows = self._synthetic_rows(same_seed=True)
        with self.assertRaises(trace.TraceError):
            self._run_synthetic_census(rows)

    def test_exact_manifest_is_class_c_and_counts_are_bounded(self):
        manifest = trace.build_manifest(trace.FIRMWARE_DIR)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["census"]["event_count"], 12)
        self.assertEqual(manifest["census"]["immediate_object_field_count"], 10)
        self.assertEqual(manifest["census"]["register_offset_array_element_count"], 2)
        self.assertEqual(manifest["census"]["unique_access_va_count"], 11)
        self.assertEqual(manifest["census"]["duplicate_witness_count"], 1)
        self.assertNotIn("evidence/private", json.dumps(manifest))

    def test_dependency_hash_and_no_clobber(self):
        with mock.patch.object(trace, "DEPENDENCY_020F_MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(trace.TraceError):
                trace.build_manifest(trace.FIRMWARE_DIR)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace.write_no_clobber(path, b"{}\n")
            with self.assertRaises(trace.TraceError):
                trace.write_no_clobber(path, b"{}\n")


if __name__ == "__main__":
    unittest.main()
