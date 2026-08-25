from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_mc_snapshot_xref as xref


def synthetic_elf(
    *,
    segment_offset: int = 0x100,
    segment_vaddr: int = 0x1000,
    segment_data: bytes = b"hello",
    flags: int = 5,
) -> bytes:
    phoff = 0x40
    end = max(phoff + 56, segment_offset + len(segment_data))
    data = bytearray(end)
    data[:8] = b"\x7fELF\x02\x01\x01\x00"
    struct.pack_into("<Q", data, 0x20, phoff)
    struct.pack_into("<H", data, 0x34, 64)
    struct.pack_into("<H", data, 0x36, 56)
    struct.pack_into("<H", data, 0x38, 1)
    struct.pack_into("<II", data, phoff, 1, flags)
    struct.pack_into(
        "<QQQQQ",
        data,
        phoff + 8,
        segment_offset,
        segment_vaddr,
        segment_vaddr,
        len(segment_data),
        len(segment_data),
    )
    data[segment_offset : segment_offset + len(segment_data)] = segment_data
    return bytes(data)


class ElfImageTests(unittest.TestCase):
    def test_minimal_mapping_round_trip(self) -> None:
        image = xref.ElfImage(synthetic_elf(segment_data=b"abcdef"))
        self.assertEqual(image.vaddr_to_offset(0x1000, 6), 0x100)
        self.assertEqual(image.offset_to_vaddr(0x103, 2), 0x1003)
        self.assertEqual(image.read_vaddr(0x1001, 3), b"bcd")

    def test_executable_words_align_by_mapped_va_with_misaligned_file_offset(self) -> None:
        body = struct.pack("<II", 0xD65F03C0, 0xD65F03C0)
        image = xref.ElfImage(
            synthetic_elf(segment_offset=0x101, segment_vaddr=0x1000, segment_data=body)
        )
        self.assertEqual(
            list(image.executable_words()),
            [(0x1000, 0x101, 0xD65F03C0), (0x1004, 0x105, 0xD65F03C0)],
        )
        self.assertTrue(all(virtual_address % 4 == 0 for virtual_address, _, _ in image.executable_words()))

    def test_rejects_truncated_bad_class_and_bad_program_headers(self) -> None:
        with self.assertRaisesRegex(ValueError, "header is truncated"):
            xref.ElfImage(b"\x7fELF")
        bad_class = bytearray(64)
        bad_class[:8] = b"\x7fELF\x01\x01\x01\x00"
        with self.assertRaisesRegex(ValueError, "ELF64"):
            xref.ElfImage(bytes(bad_class))
        bad_entry = bytearray(synthetic_elf())
        struct.pack_into("<H", bad_entry, 0x36, 32)
        with self.assertRaisesRegex(ValueError, "entry is too short"):
            xref.ElfImage(bytes(bad_entry))
        bad_offset = bytearray(synthetic_elf())
        struct.pack_into("<Q", bad_offset, 0x20, len(bad_offset) - 1)
        with self.assertRaisesRegex(ValueError, "program-header table is truncated"):
            xref.ElfImage(bytes(bad_offset))

    def test_rejects_file_backed_pt_load_overlap(self) -> None:
        data = bytearray(synthetic_elf(segment_offset=0x100, segment_data=b"12345678"))
        second_phdr = 0x78
        data.extend(b"\0" * (second_phdr + 56 - len(data)))
        struct.pack_into("<H", data, 0x38, 2)
        struct.pack_into("<II", data, second_phdr, 1, 5)
        struct.pack_into(
            "<QQQQQ", data, second_phdr + 8, 0x200, 0x1004, 0x1004, 4, 4
        )
        data.extend(b"\0" * (0x204 - len(data)))
        with self.assertRaisesRegex(ValueError, "overlapping"):
            xref.ElfImage(bytes(data))

    def test_rejects_unbacked_mapping(self) -> None:
        image = xref.ElfImage(synthetic_elf(segment_data=b"1234"))
        with self.assertRaisesRegex(ValueError, "not file-backed"):
            image.vaddr_to_offset(0x1004, 1)


class TableTests(unittest.TestCase):
    def _table_image(self, values: list[int]) -> xref.ElfImage:
        data = struct.pack("<123Q", *values)
        return xref.ElfImage(
            synthetic_elf(
                segment_offset=xref.TABLE_FILE_OFFSET,
                segment_vaddr=xref.TABLE_VADDR,
                segment_data=data,
            )
        )

    def test_table_mapping_is_checked_before_content(self) -> None:
        image = xref.ElfImage(
            synthetic_elf(
                segment_offset=xref.TABLE_FILE_OFFSET + 8,
                segment_vaddr=xref.TABLE_VADDR,
                segment_data=b"\0" * xref.TABLE_BYTE_LENGTH,
            )
        )
        with self.assertRaisesRegex(ValueError, "expected 0x630b8"):
            xref.parse_u64_table(image)

    def test_rejects_early_terminator_unaligned_entry_and_missing_terminator(self) -> None:
        early = [0x09000000] * 123
        early[5] = 0
        with self.assertRaisesRegex(ValueError, "terminator index"):
            xref.parse_u64_table(self._table_image(early))

        unaligned = [0x09000000] * 123
        unaligned[5] = 0x09000001
        with self.assertRaisesRegex(ValueError, "aligned MMIO"):
            xref.parse_u64_table(self._table_image(unaligned))

        no_terminator = [0x09000000 + index * 4 for index in range(123)]
        with self.assertRaisesRegex(ValueError, "no u64 zero terminator"):
            xref.parse_u64_table(self._table_image(no_terminator))

    def test_candidate_coverage_has_twelve_mc_and_five_excluded_candidates(self) -> None:
        table: set[int] = set()
        for candidate in xref.TOP_CANDIDATES:
            if candidate["key"] in {"mc_plus_0x400", "mc_plus_0x404", "mc_plus_0x4d0"}:
                table.update(candidate["addresses"])
        result = xref.candidate_coverage(table)
        entries = {entry["key"]: entry for entry in result["candidates"]}
        self.assertEqual(result["mc_candidate_count"], 12)
        self.assertTrue(result["mc_candidates_all_covered"])
        self.assertEqual(result["excluded_candidate_count"], 5)
        self.assertEqual(result["excluded_candidates_covered_count"], 0)
        self.assertEqual(entries["mc_plus_0x400"]["covered_count"], 4)
        self.assertEqual(entries["mc_plus_0x404"]["covered_count"], 4)
        self.assertEqual(entries["mc_plus_0x4d0"]["covered_count"], 4)
        self.assertEqual(entries["mccc_plus_0x118"]["covered_count"], 0)
        self.assertEqual(entries["mccc_master_plus_0x294"]["covered_count"], 0)
        self.assertIn("table exclusion only", result["absence_scope"])


class DecoderTests(unittest.TestCase):
    def test_branch_and_address_decoders(self) -> None:
        self.assertEqual(
            xref._decode_aarch64_bl(0x97FFFFB3, 0x146AE26C), 0x146AE138
        )
        self.assertEqual(
            xref._decode_aarch64_b(0x14000003, 0x146AE158), 0x146AE164
        )
        self.assertEqual(
            xref._decode_aarch64_cbnz(0xB5FFFFAD, 0x146AE168),
            (64, 13, 0x146AE15C),
        )
        self.assertEqual(
            xref._decode_aarch64_adrp(0xF0000009, 0x146AE144),
            (9, 0x146B1000),
        )
        self.assertEqual(
            xref._decode_aarch64_add_immediate(0x91086129), (9, 9, 0x218)
        )
        self.assertEqual(
            xref._decode_aarch64_add_w_immediate(0x1100054A), (10, 10, 1)
        )

    def test_mov_and_memory_decoders(self) -> None:
        self.assertEqual(
            xref._decode_aarch64_mov_wide(0x529E6008),
            ("MOVZ", 32, 8, 0xF300, 0),
        )
        self.assertEqual(
            xref._decode_aarch64_mov_wide(0x72BBDBCB),
            ("MOVK", 32, 11, 0xDEDE, 16),
        )
        self.assertEqual(xref._decode_aarch64_mov_register(0xAA0803EC), (12, 8))
        self.assertEqual(
            xref._decode_aarch64_ldr_register_offset(0xF86A592D)["base_register"],
            9,
        )
        self.assertEqual(
            xref._decode_aarch64_ldr_unsigned_immediate(0xB940014A),
            {
                "kind": "LDR",
                "width_bits": 32,
                "target_register": 10,
                "base_register": 10,
                "immediate": 0,
            },
        )
        self.assertEqual(
            xref._decode_aarch64_str_post_index(0xB800450A),
            {
                "kind": "STR",
                "width_bits": 32,
                "source_register": 10,
                "base_register": 8,
                "immediate": 4,
            },
        )

    def test_decoders_fail_closed_on_wrong_encodings(self) -> None:
        with self.assertRaises(ValueError):
            xref._decode_aarch64_bl(0xD65F03C0, 0x1000)
        with self.assertRaises(ValueError):
            xref._decode_aarch64_ldr_unsigned_immediate(0xB800450A)
        with self.assertRaises(ValueError):
            xref._decode_aarch64_str_post_index(0xB940014A)
        with self.assertRaisesRegex(ValueError, "exactly X12 and X8"):
            xref._validate_store_bases([10, 8], {9, 10, 13})


class ExactIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.result = xref.analyze_path(xref.DEFAULT_XBL)

    def test_exact_pins_and_structural_grouping(self) -> None:
        result = self.result
        self.assertEqual(result["input"]["size"], xref.XBL_SIZE)
        self.assertEqual(result["input"]["sha256"], xref.XBL_SHA256)
        table = result["table"]
        self.assertEqual(table["virtual_address"], "0x146b1218")
        self.assertEqual(table["file_offset"], "0x630b8")
        self.assertEqual(table["entry_count"], 122)
        self.assertEqual(table["terminator_index"], 122)
        self.assertEqual(table["sha256"], xref.TABLE_SHA256)
        self.assertTrue(table["source_pt_load_pf_w"])
        self.assertNotIn("source_segment_writable", table)
        grouping = table["grouping"]
        self.assertEqual(grouping["mc_group_count"], 30)
        self.assertEqual(grouping["mc_group_instance_count"], 4)
        self.assertEqual(grouping["mc_address_count"], 120)
        self.assertEqual(grouping["global_address_count"], 2)
        self.assertEqual(grouping["total_nonzero_count"], 122)
        self.assertEqual(len(grouping["mc_groups"]), 30)
        self.assertTrue(all(group["instance_count"] == 4 for group in grouping["mc_groups"]))

    def test_exact_helper_direction_and_buffer_safety(self) -> None:
        helper = self.result["helper"]
        self.assertEqual(helper["virtual_address"], "0x146ae138")
        self.assertEqual(helper["end_exclusive"], "0x146ae18c")
        self.assertEqual(helper["file_offset"], "0x62318")
        self.assertEqual(helper["sha256"], xref.HELPER_SHA256)
        self.assertEqual(
            helper["static_direction"],
            "TABLE_U64_POINTERS_READ_MMIO_VALUES_TO_SEPARATE_BUFFER",
        )
        self.assertNotIn("bounded_direction", helper)
        self.assertTrue(helper["analysis_range_bounded"])
        self.assertEqual(helper["traversal_bound"], "ZERO_SENTINEL_ONLY")
        self.assertFalse(helper["hard_iteration_limit"])
        self.assertEqual(helper["static_pinned_entry_count"], 122)
        self.assertEqual(helper["destination_buffer"]["virtual_address"], "0x146bf300")
        self.assertEqual(helper["destination_buffer"]["fill_value"], "0xdededede")
        self.assertFalse(helper["destination_buffer"]["file_backed"])
        self.assertTrue(helper["destination_buffer"]["separate_from_table"])
        self.assertEqual(helper["table_pointer"]["resolved_virtual_address"], "0x146b1218")
        self.assertEqual(helper["first_loop"]["static_pinned_entry_count"], 122)
        self.assertEqual(helper["second_loop"]["static_pinned_entry_count"], 122)
        self.assertFalse(helper["first_loop"]["hard_iteration_limit"])
        self.assertFalse(helper["second_loop"]["hard_iteration_limit"])
        self.assertEqual(helper["second_loop"]["mmio_read"], "LDR W10,[X10]")
        self.assertEqual(helper["second_loop"]["result_store"], "STR W10,[X8],#4")
        self.assertEqual(helper["store_base_registers"], ["X12", "X8"])
        self.assertEqual(helper["table_pointer_store_bases"], [])
        self.assertTrue(helper["table_pointer_never_used_as_store_base"])

    def test_exact_direct_caller_cardinality_and_pins(self) -> None:
        image = xref.ElfImage(xref.DEFAULT_XBL.read_bytes())
        callers = xref.find_direct_bl_callers(image)
        self.assertEqual(len(callers), 2)
        self.assertEqual(
            [(item["virtual_address"], item["file_offset"], item["instruction_word"]) for item in callers],
            [
                ("0x146ae26c", "0x6244c", "0x97ffffb3"),
                ("0x14839f44", "0x20f44", "0x97f9d07d"),
            ],
        )
        helper = self.result["helper"]
        self.assertEqual(helper["direct_caller_cardinality"], 2)
        self.assertTrue(all("instruction_word" not in caller for caller in helper["direct_callers"]))

    def test_direct_caller_mismatch_and_helper_hash_mismatch_fail_closed(self) -> None:
        mutated = bytearray(xref.DEFAULT_XBL.read_bytes())
        struct.pack_into("<I", mutated, 0x6244C, 0xD65F03C0)
        with self.assertRaisesRegex(ValueError, "cardinality"):
            xref.validate_direct_bl_callers(xref.ElfImage(bytes(mutated)))

        helper_mutated = bytearray(xref.DEFAULT_XBL.read_bytes())
        helper_mutated[0x62318] ^= 0x01
        image = xref.ElfImage(bytes(helper_mutated))
        table = xref.parse_u64_table(image)
        with self.assertRaisesRegex(ValueError, "helper SHA-256 mismatch"):
            xref.validate_helper(image, table["values"])

    def test_exact_candidate_coverage_and_absence_scope(self) -> None:
        coverage = self.result["table"]["candidate_coverage"]
        entries = {entry["key"]: entry for entry in coverage["candidates"]}
        self.assertTrue(coverage["mc_candidates_all_covered"])
        self.assertEqual(coverage["mc_candidate_count"], 12)
        for key in ("mc_plus_0x400", "mc_plus_0x404", "mc_plus_0x4d0"):
            self.assertEqual(entries[key]["covered_count"], 4)
            self.assertTrue(entries[key]["all_expected_covered"])
        self.assertEqual(entries["mccc_plus_0x118"]["covered_count"], 0)
        self.assertEqual(entries["mccc_master_plus_0x294"]["covered_count"], 0)
        self.assertTrue(self.result["claims"]["REFUTED"])
        self.assertTrue(any("current boot" in claim for claim in self.result["claims"]["UNKNOWN"]))
        self.assertTrue(any("partial/sentinel" in claim for claim in self.result["claims"]["UNKNOWN"]))
        self.assertTrue(any("indirect BLR" in claim for claim in self.result["claims"]["UNKNOWN"]))
        self.assertEqual(
            self.result["classification"],
            "TABLE_DRIVEN_REGISTER_READ_COPY_PATH_WRITER_AND_TRANSFORM_RELATION_UNKNOWN",
        )

    def test_exact_claim_language_is_conditional_and_bound_aware(self) -> None:
        proved = " ".join(self.result["claims"]["PROVED"])
        refuted = " ".join(self.result["claims"]["REFUTED"])
        self.assertIn("if that load returns", proved)
        self.assertIn("does not prove successful runtime completion", proved)
        self.assertIn("does not prove", proved)
        self.assertIn("independently enforces a maximum of 122", refuted)
        self.assertIn("zero-sentinel-only", refuted)

    def test_exact_shrm_plan_crosscheck(self) -> None:
        crosscheck = self.result["shrm_plan_crosscheck"]
        self.assertEqual(
            [(item["distinct_addresses"], item["table_intersection_count"]) for item in crosscheck["sets"]],
            [(430, 100), (64, 4)],
        )
        self.assertEqual(
            crosscheck["union"],
            {
                "distinct_addresses": 470,
                "table_intersection_count": 100,
                "table_only_count": 22,
                "shrm_union_only_count": 370,
            },
        )

    def test_cli_requires_output_writes_public_json_and_no_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "xref.json"
            self.assertEqual(
                xref.main(["--xbl", str(xref.DEFAULT_XBL), "--output", str(output)]),
                0,
            )
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["stage"], "STAGE_2_HELPER_DIRECTION_PROVED")
            self.assertFalse(parsed["device_access"])
            self.assertFalse(parsed["firmware_bytes_emitted"])
            self.assertNotIn("path", parsed["input"])
            self.assertNotIn('"instruction_word"', output.read_text(encoding="utf-8"))
            with self.assertRaises(FileExistsError):
                xref.main(["--xbl", str(xref.DEFAULT_XBL), "--output", str(output)])

            if hasattr(os, "O_NOFOLLOW"):
                target = Path(directory) / "target.json"
                target.write_text("keep", encoding="utf-8")
                link = Path(directory) / "link.json"
                link.symlink_to(target)
                with self.assertRaises(OSError):
                    xref.write_no_clobber(link, b"replace")
                self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_analyze_rejects_wrong_pins(self) -> None:
        with self.assertRaisesRegex(ValueError, "size"):
            xref.analyze(b"not an exact XBL")


if __name__ == "__main__":
    unittest.main()
