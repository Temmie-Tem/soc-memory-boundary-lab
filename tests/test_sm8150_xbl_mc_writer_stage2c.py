from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_mc_writer_stage2c as xref


def synthetic_elf(*, segments: list[tuple[int, int, int, bytes]]) -> bytes:
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


def synthetic_table(
    rows: list[tuple[int, int]], *, table_va: int = 0x1000, table_offset: int = 0x100
) -> xref.ElfImage:
    body = b"".join(struct.pack("<IIQ", entry_id, 0, pointer) for entry_id, pointer in rows)
    body += struct.pack("<I", len(rows))
    return xref.ElfImage(
        synthetic_elf(segments=[(table_offset, table_va, 6, body)])
    )


class DecoderAndSyntheticTests(unittest.TestCase):
    def test_direct_bl_and_success_path_decoders_are_strict(self) -> None:
        self.assertEqual(
            xref._decode_bl(0x94000240, 0x146A67A4),
            {"kind": "BL", "target": xref.WRITER_VA},
        )
        self.assertIsNone(xref._decode_bl(0x14000000, 0x1000))
        self.assertEqual(
            xref._decode_cbz(0x34000140, 0x146A6778),
            {
                "kind": "CBZ",
                "width_bits": 32,
                "register": 0,
                "target": 0x146A67A0,
            },
        )
        self.assertIsNone(xref._decode_ldr_unsigned(0xB9800000))
        self.assertIsNone(xref._decode_ldr_unsigned(0xF9800000))
        self.assertIsNone(xref._decode_str_unsigned(0x3D000000))
        self.assertIsNone(xref._decode_add_w_immediate(0x1140054A))

    def test_synthetic_table_positive_target_hit(self) -> None:
        image = synthetic_table([(1, 0x09260000)])
        raw = image.read_vaddr(0x1000, 16)
        result = xref.parse_retained_table(
            image,
            table_va=0x1000,
            table_file_offset=0x100,
            entry_count=1,
            expected_hash=hashlib.sha256(raw).hexdigest(),
            count_va=0x1010,
        )
        self.assertEqual(result["entry_count"], 1)
        self.assertEqual(result["possible_effective_numeric_target_match_count"], 1)
        self.assertTrue(result["rows"][0]["numeric_target_match"])

    def test_duplicate_zero_and_bounds_fail_closed(self) -> None:
        duplicate_id = synthetic_table([(1, 0x1000), (1, 0x2000)])
        raw = duplicate_id.read_vaddr(0x1000, 32)
        with self.assertRaisesRegex(ValueError, "duplicate ID"):
            xref.parse_retained_table(
                duplicate_id,
                table_va=0x1000,
                table_file_offset=0x100,
                entry_count=2,
                expected_hash=hashlib.sha256(raw).hexdigest(),
                count_va=0x1020,
            )

        zero_pointer = synthetic_table([(1, 0)])
        raw = zero_pointer.read_vaddr(0x1000, 16)
        with self.assertRaisesRegex(ValueError, "pointer .* zero"):
            xref.parse_retained_table(
                zero_pointer,
                table_va=0x1000,
                table_file_offset=0x100,
                entry_count=1,
                expected_hash=hashlib.sha256(raw).hexdigest(),
                count_va=0x1010,
            )

        bounded = synthetic_table([(1, 0x1000)])
        with self.assertRaises(ValueError):
            xref.parse_retained_table(
                bounded,
                table_va=0x1000,
                table_file_offset=0x100,
                entry_count=2,
                expected_hash=None,
                count_va=0x1020,
            )

    def test_duplicate_pointer_and_count_fail_closed(self) -> None:
        duplicate_pointer = synthetic_table([(1, 0x1000), (2, 0x1000)])
        raw = duplicate_pointer.read_vaddr(0x1000, 32)
        with self.assertRaisesRegex(ValueError, "duplicate pointer"):
            xref.parse_retained_table(
                duplicate_pointer,
                table_va=0x1000,
                table_file_offset=0x100,
                entry_count=2,
                expected_hash=hashlib.sha256(raw).hexdigest(),
                count_va=0x1020,
            )

        wrong_count = bytearray(synthetic_table([(1, 0x1000)]).data)
        struct.pack_into("<I", wrong_count, 0x110, 2)
        image = xref.ElfImage(bytes(wrong_count))
        raw = image.read_vaddr(0x1000, 16)
        with self.assertRaisesRegex(ValueError, "expected 1"):
            xref.parse_retained_table(
                image,
                table_va=0x1000,
                table_file_offset=0x100,
                entry_count=1,
                expected_hash=hashlib.sha256(raw).hexdigest(),
                count_va=0x1010,
            )


class ExactIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.result = xref.analyze_path(xref.DEFAULT_XBL)

    def test_exact_pins_callers_code_flow_table_and_rows(self) -> None:
        result = self.result
        self.assertEqual(result["input"]["size"], xref.XBL_SIZE)
        self.assertEqual(result["input"]["sha256"], xref.XBL_SHA256)
        self.assertEqual(result["direct_callers"]["count"], 1)
        self.assertEqual(
            result["direct_callers"]["callers"],
            [{
                "virtual_address": "0x146a67a4",
                "file_offset": "0x2d5774",
                "target": "0x146a70a4",
                "segment_class": "RX",
            }],
        )
        ranges = result["code_ranges"]
        self.assertEqual(
            (ranges["writer"]["virtual_address"], ranges["writer"]["file_offset"], ranges["writer"]["byte_length"], ranges["writer"]["sha256"]),
            ("0x146a70a4", "0x2d6074", 56, xref.WRITER_SHA256),
        )
        self.assertEqual(
            (ranges["wrapper"]["virtual_address"], ranges["wrapper"]["file_offset"], ranges["wrapper"]["byte_length"], ranges["wrapper"]["sha256"]),
            ("0x146a6744", "0x2d5714", 108, xref.WRAPPER_SHA256),
        )
        self.assertEqual(
            (ranges["lookup"]["virtual_address"], ranges["lookup"]["file_offset"], ranges["lookup"]["byte_length"], ranges["lookup"]["sha256"]),
            ("0x146a7a08", "0x2d69d8", 272, xref.LOOKUP_SHA256),
        )
        flow = result["success_path"]
        self.assertTrue(flow["critical_instruction_pins_verified"])
        self.assertEqual(flow["wrapper"]["x1_source"], "SP")
        self.assertEqual(flow["wrapper"]["x0_source"], "SP")
        self.assertEqual(flow["lookup"]["pointer_entry_offset"], 8)
        self.assertEqual(flow["lookup"]["pointer_output"], "[X19]")
        self.assertEqual(flow["lookup"]["input_id_source"], "W0")
        self.assertEqual(flow["lookup"]["index_register"], "W10")
        self.assertEqual(flow["lookup"]["entry_index_register"], "X11")
        self.assertEqual(flow["lookup"]["index_initial_value"], 0)
        self.assertEqual(flow["lookup"]["index_increment"], 1)
        self.assertEqual(flow["lookup"]["loop_bound_register"], "W8")
        self.assertEqual(flow["lookup"]["loop_back_target"], "0x146a7a4c")
        self.assertEqual(flow["lookup"]["success_return"], 0)
        self.assertEqual(
            flow["lookup"]["success_epilogue_branch_target"], "0x146a7a78"
        )
        self.assertEqual(flow["wrapper"]["lookup_call_site"], "0x146a6774")
        self.assertEqual(flow["wrapper"]["writer_call_site"], "0x146a67a4")
        self.assertEqual(flow["lookup"]["id_match_branch_site"], "0x146a7a5c")
        self.assertEqual(flow["lookup"]["pointer_load_site"], "0x146a7a88")
        self.assertEqual(flow["writer"]["store_site"], "0x146a70c0")
        self.assertEqual(flow["writer"]["descriptor_pointer_load"], "X8=[X0]")
        self.assertEqual(flow["writer"]["store_offset"], "0x400")

        table = result["retained_table"]
        self.assertEqual(table["virtual_address"], "0x146aa4d0")
        self.assertEqual(table["file_offset"], "0x2d94a0")
        self.assertEqual(table["byte_length"], 768)
        self.assertEqual(table["entry_count"], 48)
        self.assertEqual(table["entry_size"], 16)
        self.assertEqual(table["sha256"], xref.TABLE_SHA256)
        self.assertEqual(table["count_u32_virtual_address"], "0x146aa7d0")
        self.assertEqual(table["count_u32_file_offset"], "0x2d97a0")
        self.assertEqual(table["count_u32"], 48)
        self.assertEqual(table["reserved_u32_zero_count"], 48)
        self.assertEqual(table["unique_id_count"], 48)
        self.assertEqual(table["unique_nonzero_pointer_count"], 48)
        self.assertEqual(table["exact_target_base_pointer_match_count"], 0)
        self.assertEqual(table["possible_effective_numeric_target_match_count"], 0)
        self.assertEqual(table["value_domain"], "XBL_VIRTUAL_ADDRESS_VALUE")
        self.assertEqual(table["va_to_pa_translation"], "UNKNOWN")
        self.assertIsNone(table["physical_destination"])
        self.assertEqual(len(table["rows"]), 48)
        self.assertEqual(
            result["scope"]["table_derived_possible_effective_values_count"], 48
        )
        self.assertTrue(all(not row["numeric_target_match"] for row in table["rows"]))

    def test_stage2a_and_stage2b_baselines_unchanged(self) -> None:
        root = Path(__file__).resolve().parents[1]
        paths = {
            "stage2a_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2a.py",
            "stage2a_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2a.py",
            "stage2a_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json",
            "stage2b_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2b.py",
            "stage2b_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2b.py",
            "stage2b_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json",
        }
        for key, path in paths.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), xref.__dict__[key.upper()])
        self.assertEqual(self.result["baseline"]["stage2b_resolved_base_count"], 2)
        self.assertEqual(self.result["baseline"]["stage2b_resolved_numeric_target_hit_count"], 0)
        self.assertEqual(self.result["scope"]["remaining_non_sp_rx_static_candidate_count"], 1)
        self.assertEqual(self.result["scope"]["remaining_non_sp_rx_static_candidate"]["base_register"], "X19")

    def test_public_safety_and_claim_boundary(self) -> None:
        encoded = json.dumps(self.result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn('"word"', encoded)
        self.assertNotIn("instruction_word", encoded)
        self.assertIn("descriptor +0x20 eligibility", encoded.lower())
        self.assertIn("physical destination/ownership", encoded)
        self.assertNotIn("physical RAM", " ".join(self.result["claims"]["PROVED"]))
        self.assertNotIn("writer identity", " ".join(self.result["claims"]["REFUTED"]))

    def test_malformed_image_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "size"):
            xref.analyze(b"not an exact XBL")


class PublicationTests(unittest.TestCase):
    def test_cli_no_clobber_and_deterministic_regeneration(self) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            self.assertEqual(xref.main(["--output", str(first)]), 0)
            self.assertEqual(xref.main(["--output", str(second)]), 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.stat().st_mode & 0o777, 0o644)
            self.assertRaises(FileExistsError, xref.main, ["--output", str(first)])
            parsed = json.loads(first.read_text())
            self.assertEqual(parsed["classification"], xref.STAGE2C_CLASSIFICATION)


if __name__ == "__main__":
    unittest.main()
