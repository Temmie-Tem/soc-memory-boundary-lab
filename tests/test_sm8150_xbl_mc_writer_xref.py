from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_mc_writer_xref as xref


def synthetic_elf(
    *,
    segments: list[tuple[int, int, int, bytes]],
) -> bytes:
    """Build a minimal ELF64 image: (file offset, VA, flags, bytes)."""

    phoff = 0x40
    phentsize = 56
    end = phoff + phentsize * len(segments)
    for offset, _vaddr, _flags, body in segments:
        end = max(end, offset + len(body))
    data = bytearray(end)
    data[:8] = b"\x7fELF\x02\x01\x01\x00"
    struct.pack_into("<Q", data, 0x20, phoff)
    struct.pack_into("<H", data, 0x34, 64)
    struct.pack_into("<H", data, 0x36, phentsize)
    struct.pack_into("<H", data, 0x38, len(segments))
    for index, (offset, vaddr, flags, body) in enumerate(segments):
        base = phoff + index * phentsize
        struct.pack_into("<II", data, base, 1, flags)
        struct.pack_into(
            "<QQQQQ", data, base + 8, offset, vaddr, vaddr, len(body), len(body)
        )
        data[offset : offset + len(body)] = body
    return bytes(data)


class DecoderTests(unittest.TestCase):
    def test_str_unsigned_immediate_w_and_x(self) -> None:
        # str w0, [x1, #4] and str x0, [x1, #8].
        self.assertEqual(
            xref._decode_str_unsigned_immediate(0xB9000420),
            {
                "form": "STR_UNSIGNED_IMMEDIATE",
                "width_bytes": 4,
                "byte_offset": 4,
                "base_register": 1,
                "source_register": 0,
                "base_is_sp": False,
            },
        )
        decoded = xref._decode_str_unsigned_immediate(0xF9000420)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["width_bytes"], 8)
        self.assertEqual(decoded["byte_offset"], 8)

    def test_decoder_rejects_loads_byte_half_and_non_instruction_values(self) -> None:
        # LDR W0,[X1,#4] differs only in the load/store bit.
        for word in (
            0xB9400420,
            0x39000420,
            0x79000420,
            0xB9800000,
            0xF9800000,
            0x3D000000,
            0xD65F03C0,
        ):
            self.assertIsNone(xref._decode_str_unsigned_immediate(word))


class LiteralAndCensusTests(unittest.TestCase):
    def test_literal_inventory_reports_u32_u64_alignment_mapping_and_table_scope(self) -> None:
        target = xref.TARGETS[0]
        body = bytearray(0x40)
        struct.pack_into("<I", body, 0x04, xref.TARGET_BASES[0])
        struct.pack_into("<Q", body, 0x10, target)
        image = xref.ElfImage(
            synthetic_elf(segments=[(0x100, 0x1000, 5, bytes(body))])
        )
        result = xref.literal_inventory(image)
        entries = {entry["value"]: entry for entry in result["values"]}
        base = entries["0x09260000"]
        target_entry = entries["0x09260400"]
        self.assertEqual(base["u32"]["count"], 1)
        self.assertEqual(base["u32"]["aligned_count"], 1)
        self.assertEqual(base["u32"]["occurrences"][0]["file_offset"], "0x104")
        self.assertEqual(base["u32"]["occurrences"][0]["virtual_address"], "0x1004")
        self.assertEqual(base["u32"]["occurrences"][0]["segment_class"], "RX")
        self.assertEqual(base["u32"]["occurrences"][0]["source"], "other_file_literal")
        self.assertEqual(target_entry["u64"]["count"], 1)
        self.assertEqual(target_entry["u64"]["aligned_count"], 1)
        self.assertEqual(target_entry["u64"]["occurrences"][0]["file_offset"], "0x110")
        self.assertEqual(target_entry["u64"]["occurrences"][0]["virtual_address"], "0x1010")

    def test_known_experiment_017_table_membership_is_file_range_scoped(self) -> None:
        body = bytearray(xref.EXP017_TABLE_BYTE_LENGTH)
        struct.pack_into("<Q", body, 0, xref.TARGETS[0])
        image = xref.ElfImage(
            synthetic_elf(
                segments=[
                    (
                        xref.EXP017_TABLE_FILE_OFFSET,
                        xref.EXP017_TABLE_VADDR,
                        6,
                        bytes(body),
                    )
                ]
            )
        )
        result = xref.literal_inventory(image)
        target_entry = next(
            entry for entry in result["values"] if entry["value"] == "0x09260400"
        )
        occurrence = target_entry["u64"]["occurrences"][0]
        self.assertEqual(occurrence["source"], "experiment_017_table")
        self.assertEqual(occurrence["file_offset"], "0x630b8")
        self.assertEqual(occurrence["virtual_address"], "0x146b1218")
        self.assertEqual(occurrence["segment_class"], "RW")

    def test_store_offset_census_separates_rx_and_rwe(self) -> None:
        rx = struct.pack("<III", 0xB9040020, 0xB9040440, 0xB904D120)
        rwe = struct.pack("<I", 0xF9020020)
        image = xref.ElfImage(
            synthetic_elf(
                segments=[
                    (0x100, 0x1000, 5, rx),
                    (0x200, 0x2000, 7, rwe),
                ]
            )
        )
        census = xref._census(image)
        self.assertEqual(census["segment_counts"], {"RX": 1, "RWE": 1, "RW": 0, "OTHER": 0})
        self.assertEqual(census["recognized_str_wx_counts"], {"RX": 3, "RWE": 1})
        self.assertEqual(census["matching_offset_candidate_count"], 4)
        self.assertEqual(census["matching_offsets_by_segment"]["RX"], {"0x400": 1, "0x404": 1, "0x4d0": 1})
        self.assertEqual(census["matching_offsets_by_segment"]["RWE"], {"0x400": 1, "0x404": 0, "0x4d0": 0})
        self.assertTrue(census["rwe_decodes_are_ambiguous"])
        self.assertEqual(
            {name: sum(item["segment_class"] == name for item in census["candidates"])
             for name in ("RX", "RWE")},
            {"RX": 3, "RWE": 1},
        )
        self.assertTrue(all(item["exact_target_resolution"] is None for item in census["candidates"]))
        self.assertTrue(all(item["status"] == "OFFSET_MATCH_ONLY_UNRESOLVED_BASE" for item in census["candidates"]))
        self.assertTrue(all("word" not in item and "instruction" not in item for item in census["candidates"]))


class ExactIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.result = xref.analyze_path(xref.DEFAULT_XBL)

    def test_exact_pins_literals_offsets_and_stage1a_classification(self) -> None:
        result = self.result
        self.assertEqual(result["input"], {
            "filename": "xbl--sdb1.bin",
            "size": xref.XBL_SIZE,
            "sha256": xref.XBL_SHA256,
            "pin_verified": True,
        })
        self.assertEqual(result["target_set"]["base_count"], 4)
        self.assertEqual(result["target_set"]["target_count"], 12)
        self.assertEqual(result["target_set"]["offsets"], ["0x400", "0x404", "0x4d0"])
        census = result["pt_load_census"]
        self.assertEqual(census["matching_offset_candidate_count"], 14)
        self.assertEqual(census["segment_counts"], {"RX": 4, "RWE": 2, "RW": 3, "OTHER": 0})
        self.assertEqual(census["recognized_str_wx_counts"], {"RX": 6945, "RWE": 5169})
        self.assertEqual(
            census["matching_offsets_by_segment"],
            {
                "RX": {"0x400": 7, "0x404": 2, "0x4d0": 2},
                "RWE": {"0x400": 1, "0x404": 1, "0x4d0": 1},
            },
        )
        self.assertEqual(census["matching_offset_candidate_count_by_segment"], {"RX": 11, "RWE": 3})
        self.assertTrue(all(item["exact_target_resolution"] is None for item in census["candidates"]))
        self.assertTrue(all(item["status"] == "OFFSET_MATCH_ONLY_UNRESOLVED_BASE" for item in census["candidates"]))
        self.assertEqual(sum(item["base_register"] == "SP" for item in census["candidates"]), 7)
        self.assertTrue(all(item["base_register"] != "X31" for item in census["candidates"]))
        self.assertEqual(result["classification"], "STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN")
        self.assertIsNone(result["model"]["resolved_target_hit_count"])
        self.assertEqual(result["model"]["base_resolution"], "NOT_ATTEMPTED_STAGE1A")
        self.assertEqual(result["model"]["effective_address_resolution"], "NOT_ATTEMPTED_STAGE1A")
        self.assertFalse(result["device_access"])
        self.assertFalse(result["smc_access"])
        self.assertFalse(result["mmio_access"])

        entries = {entry["value"]: entry for entry in result["literal_inventory"]["values"]}
        for target in xref.TARGETS:
            entry = entries[f"0x{target:08x}"]
            self.assertEqual(entry["u32"]["count"], 1)
            self.assertEqual(entry["u32"]["aligned_count"], 1)
            self.assertEqual(entry["u32"]["occurrences"][0]["source"], "experiment_017_table")
            self.assertEqual(entry["u32"]["occurrences"][0]["segment_class"], "RW")
            self.assertEqual(entry["u64"]["count"], 1)
            self.assertEqual(entry["u64"]["aligned_count"], 1)
            self.assertEqual(entry["u64"]["occurrences"][0]["source"], "experiment_017_table")
            self.assertEqual(entry["u64"]["occurrences"][0]["segment_class"], "RW")
        for base in xref.TARGET_BASES:
            entry = entries[f"0x{base:08x}"]
            expected_aligned_u32 = 1 if base == 0x09260000 else 0
            self.assertEqual(entry["u32"]["aligned_count"], expected_aligned_u32)
            self.assertEqual(entry["u64"]["aligned_count"], 0)
        base_occurrences = entries["0x09260000"]["u32"]["occurrences"]
        self.assertEqual(len(base_occurrences), 1)
        self.assertEqual(base_occurrences[0]["file_offset"], "0x80154")
        self.assertEqual(base_occurrences[0]["virtual_address"], "0x148bc254")
        self.assertEqual(base_occurrences[0]["segment_class"], "RWE")
        self.assertEqual(base_occurrences[0]["source"], "other_file_literal")

    def test_exact_public_output_has_no_private_path_or_raw_word(self) -> None:
        encoded = json.dumps(self.result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn("instruction_word", encoded)
        self.assertNotIn('"word"', encoded)


class PublicationTests(unittest.TestCase):
    def test_no_clobber_and_public_safe_cli_output(self) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            self.assertEqual(xref.main(["--output", str(output)]), 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            self.assertRaises(FileExistsError, xref.main, ["--output", str(output)])
            parsed = json.loads(output.read_text())
            self.assertEqual(parsed["classification"], "STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN")
            serialized = output.read_text()
            self.assertNotIn("/home/", serialized)
            self.assertNotIn('"word"', serialized)


if __name__ == "__main__":
    unittest.main()
