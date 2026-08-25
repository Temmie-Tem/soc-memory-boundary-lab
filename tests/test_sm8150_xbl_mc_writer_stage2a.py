from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_mc_writer_stage2a as xref


def synthetic_elf(
    *,
    segments: list[tuple[int, int, int, bytes]],
) -> bytes:
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


def movz_x(register: int, immediate: int, shift: int = 0) -> int:
    return 0xD2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movk_x(register: int, immediate: int, shift: int = 0) -> int:
    return 0xF2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movz_w(register: int, immediate: int, shift: int = 0) -> int:
    return 0x52800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movk_w(register: int, immediate: int, shift: int = 0) -> int:
    return 0x72800000 | ((shift // 16) << 21) | (immediate << 5) | register


def adrp(register: int, pc: int, target: int) -> int:
    delta_pages = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    immediate = delta_pages & ((1 << 21) - 1)
    return 0x90000000 | ((immediate & 0x3) << 29) | ((immediate >> 2) << 5) | register


def add_x(destination: int, source: int, immediate: int) -> int:
    return 0x91000000 | (immediate << 10) | (source << 5) | destination


def str_w(source: int, base: int, byte_offset: int) -> int:
    return 0xB9000000 | ((byte_offset // 4) << 10) | (base << 5) | source


def code_image(words: list[int], flags: int = 5) -> xref.ElfImage:
    body = struct.pack(f"<{len(words)}I", *words)
    return xref.ElfImage(synthetic_elf(segments=[(0x100, 0x1000, flags, body)]))


def candidate(virtual_address: int, base_register: str, byte_offset: int) -> dict[str, object]:
    return {
        "virtual_address": f"0x{virtual_address:x}",
        "file_offset": f"0x{0x100 + virtual_address - 0x1000:x}",
        "segment_class": "RX",
        "base_register": base_register,
        "byte_offset": f"0x{byte_offset:x}",
        "width_bytes": 4,
    }


def slice_image(image: xref.ElfImage, row: dict[str, object]) -> dict[str, object]:
    words, boundaries = xref._rx_word_map(image)
    return xref._slice_candidate(image, words, boundaries, row)


class DecoderTests(unittest.TestCase):
    def test_supported_and_fail_closed_decoders(self) -> None:
        self.assertEqual(xref._decode_mov_wide(movz_x(8, 0x0926, 16))["kind"], "MOVZ")
        self.assertEqual(xref._decode_mov_wide(movk_x(8, 0x0926, 16))["kind"], "MOVK")
        self.assertEqual(xref._decode_mov_wide(0x92800008)["kind"], "MOVN")
        self.assertEqual(xref._decode_adr_or_adrp(adrp(8, 0x1000, 0x09260000), 0x1000)["value"], 0x09260000)
        self.assertEqual(xref._decode_add_immediate_64(add_x(8, 8, 0x218))["source"], 8)
        self.assertEqual(xref._decode_madd(0x9B0D62F3)["destination"], 19)
        self.assertEqual(xref._decode_scalar_load(0xF9400008)["destination"], 8)
        self.assertEqual(xref._decode_pair_load(0xA9400008)["destination"], 8)
        self.assertEqual(xref._decode_pair_load(0xA9402000)["second_destination"], 8)
        self.assertIsNone(xref._decode_pair_load(0xA9000008))
        self.assertIsNone(xref._decode_add_immediate_64(0xD1000000))


class SyntheticSliceTests(unittest.TestCase):
    def test_movz_movk_exact_target(self) -> None:
        image = code_image([
            movz_x(8, 0),
            movk_x(8, 0x0926, 16),
            str_w(0, 8, 0x400),
        ])
        result = slice_image(image, candidate(0x1008, "X8", 0x400))
        self.assertTrue(result["resolved"])
        self.assertEqual(result["reason"], "RESOLVED_MOVZ_MOVK_CHAIN")
        self.assertEqual(result["base_value"], "0x09260000")
        self.assertEqual(result["effective_address"], "0x09260400")
        self.assertTrue(result["target_match"])
        self.assertEqual([item["kind"] for item in result["slice"]], ["MOVZ", "MOVK"])

    def test_adrp_add_exact_target(self) -> None:
        image = code_image([
            adrp(8, 0x1000, 0x09260000),
            add_x(8, 8, 0),
            str_w(0, 8, 0x404),
        ])
        result = slice_image(image, candidate(0x1008, "X8", 0x404))
        self.assertTrue(result["resolved"])
        self.assertEqual(result["reason"], "RESOLVED_ADRP_ADD_CHAIN")
        self.assertEqual(result["base_value"], "0x09260000")
        self.assertEqual(result["effective_address"], "0x09260404")
        self.assertTrue(result["target_match"])
        self.assertEqual([item["kind"] for item in result["slice"]], ["ADRP", "ADD_IMMEDIATE_64"])

    def test_near_miss_resolves_but_is_not_target(self) -> None:
        image = code_image([
            movz_x(8, 0),
            movk_x(8, 0x0926, 16),
            str_w(0, 8, 0x408),
        ])
        result = slice_image(image, candidate(0x1008, "X8", 0x408))
        self.assertTrue(result["resolved"])
        self.assertEqual(result["effective_address"], "0x09260408")
        self.assertFalse(result["target_match"])

    def test_direct_branch_and_inbound_target_cut_off_slice(self) -> None:
        branch_before_store = code_image([
            movz_x(8, 0x0926, 16),
            0x14000003,
            0xD503201F,
            str_w(0, 8, 0x400),
        ])
        result = slice_image(branch_before_store, candidate(0x100C, "X8", 0x400))
        self.assertFalse(result["resolved"])
        self.assertEqual(result["reason"], "NO_DIRECT_CONSTANT_DEFINITION")
        self.assertEqual(result["stop_reason"], "CONTROL_TRANSFER")

        inbound_target = code_image([
            0x14000003,
            0xD503201F,
            0xD503201F,
            str_w(0, 8, 0x400),
        ])
        result = slice_image(inbound_target, candidate(0x100C, "X8", 0x400))
        self.assertEqual(result["status"], "UNRESOLVED_INBOUND_BLOCK_ENTRY")
        self.assertEqual(result["reason"], "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY")

        call_before_store = code_image([
            movz_x(8, 0x0926, 16),
            0x94000004,
            0xD503201F,
            0xD503201F,
            str_w(0, 8, 0x400),
        ])
        result = slice_image(call_before_store, candidate(0x1010, "X8", 0x400))
        self.assertEqual(result["reason"], "NO_DIRECT_CONSTANT_DEFINITION")
        self.assertEqual(result["stop_reason"], "CONTROL_TRANSFER")

    def test_unsupported_load_and_madd_definitions_fail_closed(self) -> None:
        load_image = code_image([0xF9400008, str_w(0, 8, 0x400)])
        load_result = slice_image(load_image, candidate(0x1004, "X8", 0x400))
        self.assertEqual(load_result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(load_result["slice"][0]["kind"], "LDR_UNSIGNED_IMMEDIATE")
        self.assertEqual(load_result["slice"][0]["virtual_address"], "0x1000")

        madd_image = code_image([0x9B0D62F3, str_w(0, 19, 0x400)])
        madd_result = slice_image(madd_image, candidate(0x1004, "X19", 0x400))
        self.assertEqual(madd_result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(madd_result["slice"][0]["kind"], "MADD_OR_MSUB")

        ldp_rt2 = code_image([0xA9402000, str_w(0, 8, 0x400)])
        ldp_result = slice_image(ldp_rt2, candidate(0x1004, "X8", 0x400))
        self.assertEqual(ldp_result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(ldp_result["slice"][0]["kind"], "LDP_UNSUPPORTED")

    def test_wrong_source_movk_movn_and_mov_alias_fail_closed(self) -> None:
        wrong_source = code_image([
            adrp(8, 0x1000, 0x09260000),
            add_x(8, 9, 0),
            str_w(0, 8, 0x400),
        ])
        result = slice_image(wrong_source, candidate(0x1008, "X8", 0x400))
        self.assertEqual(result["status"], "UNSUPPORTED_REGISTER_DEFINITION")

        movk_only = code_image([movk_x(8, 0x0926, 16), str_w(0, 8, 0x400)])
        result = slice_image(movk_only, candidate(0x1004, "X8", 0x400))
        self.assertEqual(result["reason"], "NO_DIRECT_CONSTANT_DEFINITION")

        movn = code_image([0x92800008, str_w(0, 8, 0x400)])
        result = slice_image(movn, candidate(0x1004, "X8", 0x400))
        self.assertEqual(result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(result["slice"][0]["kind"], "MOVN")

        mov_alias = code_image([0xAA0903E8, str_w(0, 8, 0x400)])
        result = slice_image(mov_alias, candidate(0x1004, "X8", 0x400))
        self.assertEqual(result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(result["slice"][0]["kind"], "MOV_ALIAS")

        movz_w_image = code_image([movz_w(8, 0x0926, 16), str_w(0, 8, 0x400)])
        result = slice_image(movz_w_image, candidate(0x1004, "X8", 0x400))
        self.assertEqual(result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(result["slice"][0]["kind"], "MOVZ_32_UNSUPPORTED")

        movk_w_image = code_image([movk_w(8, 0x0926, 16), str_w(0, 8, 0x400)])
        result = slice_image(movk_w_image, candidate(0x1004, "X8", 0x400))
        self.assertEqual(result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(result["slice"][0]["kind"], "MOVK_32_UNSUPPORTED")

    def test_supported_entry_definition_does_not_cross_inbound_block(self) -> None:
        image = code_image([
            0x14000002,
            0xD503201F,
            movk_x(8, 0x0926, 16),
            str_w(0, 8, 0x400),
        ])
        result = slice_image(image, candidate(0x100C, "X8", 0x400))
        self.assertEqual(result["reason"], "NO_DIRECT_CONSTANT_DEFINITION")
        self.assertEqual(result["stop_reason"], "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY")

    def test_backward_window_is_exactly_128_instructions(self) -> None:
        words = [0xD503201F, movz_x(8, 0x0926, 16)] + [0xD503201F] * 127 + [str_w(0, 8, 0x400)]
        image = code_image(words)
        result = slice_image(image, candidate(0x1000 + 129 * 4, "X8", 0x400))
        self.assertTrue(result["resolved"])
        self.assertEqual(result["stop_reason"], "SUPPORTED_DIRECT_DEFINITION")

        words = [0xD503201F, movz_x(8, 0x0926, 16)] + [0xD503201F] * 128 + [str_w(0, 8, 0x400)]
        image = code_image(words)
        result = slice_image(image, candidate(0x1000 + 130 * 4, "X8", 0x400))
        self.assertEqual(result["reason"], "NO_DIRECT_CONSTANT_DEFINITION")
        self.assertEqual(result["stop_reason"], "WINDOW_LIMIT")

        words = [movz_x(8, 0x0926, 16)] + [movk_x(8, 0) for _ in range(129)] + [str_w(0, 8, 0x400)]
        image = code_image(words)
        result = slice_image(image, candidate(0x1000 + 130 * 4, "X8", 0x400))
        self.assertEqual(result["reason"], "NO_DIRECT_CONSTANT_DEFINITION")
        self.assertEqual(result["stop_reason"], "WINDOW_LIMIT")
        self.assertFalse(result["resolved"])

    def test_sp_is_runtime_unresolved(self) -> None:
        image = code_image([str_w(0, 31, 0x400)])
        result = slice_image(image, candidate(0x1000, "SP", 0x400))
        self.assertEqual(result["status"], "UNRESOLVED_RUNTIME_SP")
        self.assertIsNone(result["base_value"])


class ExactIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.result = xref.analyze_path(xref.DEFAULT_XBL)

    def test_exact_pins_scope_outcome_and_reasons(self) -> None:
        result = self.result
        self.assertEqual(result["input"]["size"], xref.XBL_SIZE)
        self.assertEqual(result["input"]["sha256"], xref.XBL_SHA256)
        model = result["stage2a_model"]
        self.assertEqual(model["scope"], "FOUR_NON_SP_RX_CANDIDATES_ONLY")
        self.assertEqual(model["window_max_instructions"], 128)
        self.assertEqual(model["rx_candidate_count"], 11)
        self.assertEqual(model["analyzed_rx_candidate_count"], 4)
        self.assertEqual(model["excluded_rx_sp_candidate_count"], 7)
        self.assertEqual(model["excluded_rwe_candidate_count"], 3)
        self.assertEqual(model["resolved_target_hit_count"], 0)
        self.assertEqual(model["resolved_base_count"], 0)
        self.assertEqual(model["reason_counts"], {
            "NO_DIRECT_CONSTANT_DEFINITION": 3,
            "UNSUPPORTED_REGISTER_DEFINITION": 1,
        })
        expected = {
            "0x14844b20": ("NO_DIRECT_CONSTANT_DEFINITION", "WINDOW_LIMIT"),
            "0x14844c78": ("NO_DIRECT_CONSTANT_DEFINITION", "WINDOW_LIMIT"),
            "0x146a70c0": ("UNSUPPORTED_REGISTER_DEFINITION", "UNSUPPORTED_REGISTER_DEFINITION"),
            "0x14935bf4": ("NO_DIRECT_CONSTANT_DEFINITION", "CONTROL_TRANSFER"),
        }
        for item in model["candidates"]:
            self.assertIn(item["virtual_address"], expected)
            self.assertEqual((item["reason"], item["stop_reason"]), expected[item["virtual_address"]])
        exact_non_sp = {
            (
                int(item["virtual_address"], 16),
                int(item["file_offset"], 16),
                int(item["base_register"][1:]),
                int(item["byte_offset"], 16),
                item["width_bytes"],
            )
            for item in result["pt_load_census"]["candidates"]
            if item["segment_class"] == "RX" and item["base_register"] != "SP"
        }
        self.assertEqual(
            exact_non_sp,
            {
                (
                    int(pin["virtual_address"]),
                    int(pin["file_offset"]),
                    int(pin["base_register"]),
                    int(pin["byte_offset"]),
                    int(pin["width_bytes"]),
                )
                for pin in xref.EXACT_RX_CANDIDATES
            },
        )
        self.assertEqual(result["classification"], xref.STAGE2A_CLASSIFICATION)
        self.assertEqual(result["stage"], "STAGE2A_DIRECT_DEFINITION_RX_MODEL")
        self.assertEqual(result["model"], model)
        self.assertEqual(result["stage1a_summary"]["classification"], "STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN")
        self.assertEqual(result["stage1a_summary"]["matching_offset_candidate_count"], 14)
        self.assertIsNone(result["stage1a_summary"]["resolved_target_hit_count"])

    def test_exact_public_output_is_safe_and_no_raw_words(self) -> None:
        encoded = json.dumps(self.result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn('"word"', encoded)
        self.assertNotIn("instruction_word", encoded)
        for item in self.result["stage2a_model"]["candidates"]:
            for instruction in item["slice"]:
                self.assertIn("virtual_address", instruction)
                self.assertIn("kind", instruction)
                self.assertIn("provenance", instruction)

    def test_malformed_pin_rejection(self) -> None:
        with self.assertRaisesRegex(ValueError, "size"):
            xref.analyze(b"not an exact image")


class PublicationTests(unittest.TestCase):
    def test_cli_no_clobber_and_deterministic_output(self) -> None:
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
            self.assertEqual(parsed["classification"], xref.STAGE2A_CLASSIFICATION)


if __name__ == "__main__":
    unittest.main()
