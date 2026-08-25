from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_mc_writer_stage2b as xref


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


def movz_w(register: int, immediate: int, shift: int = 0) -> int:
    return 0x52800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movk_w(register: int, immediate: int, shift: int = 0) -> int:
    return 0x72800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movz_x(register: int, immediate: int, shift: int = 0) -> int:
    return 0xD2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movk_x(register: int, immediate: int, shift: int = 0) -> int:
    return 0xF2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def str_w(source: int, base: int, byte_offset: int) -> int:
    return 0xB9000000 | ((byte_offset // 4) << 10) | (base << 5) | source


def code_image(words: list[int]) -> xref.ElfImage:
    body = struct.pack(f"<{len(words)}I", *words)
    return xref.ElfImage(synthetic_elf(segments=[(0x100, 0x1000, 5, body)]))


def candidate(virtual_address: int, byte_offset: int = 0x400) -> dict[str, object]:
    return {
        "virtual_address": f"0x{virtual_address:x}",
        "file_offset": f"0x{0x100 + virtual_address - 0x1000:x}",
        "segment_class": "RX",
        "base_register": "X8",
        "byte_offset": f"0x{byte_offset:x}",
        "width_bytes": 4,
    }


def resolve(image: xref.ElfImage, row: dict[str, object]) -> dict[str, object]:
    words, boundaries = xref.stage2a._rx_word_map(image)
    return xref._resolve_w_chain(image, words, boundaries, row)


class SyntheticWWideMoveTests(unittest.TestCase):
    def test_w_zero_extension_can_hit_exact_numeric_target(self) -> None:
        image = code_image([
            movz_w(8, 0),
            movk_w(8, 0x0926, 16),
            str_w(0, 8, 0x400),
        ])
        result = resolve(image, candidate(0x1008))
        self.assertTrue(result["resolved"])
        self.assertEqual(result["base_value"], "0x09260000")
        self.assertEqual(result["effective_address"], "0x09260400")
        self.assertTrue(result["target_match"])
        self.assertEqual(result["base_value_domain"], "XBL_VIRTUAL_ADDRESS_VALUE")

    def test_exact_512_and_513_predecessor_boundaries(self) -> None:
        exact = code_image([movz_w(8, 0x0926, 16)] + [0xD503201F] * 511 + [str_w(0, 8, 0x400)])
        result = resolve(exact, candidate(0x1000 + 512 * 4))
        self.assertTrue(result["resolved"])
        self.assertEqual(result["instruction_pins"][0]["distance_instructions"], 512)

        beyond = code_image([movz_w(8, 0x0926, 16)] + [0xD503201F] * 512 + [str_w(0, 8, 0x400)])
        result = resolve(beyond, candidate(0x1000 + 513 * 4))
        self.assertEqual(result["stop_reason"], "WINDOW_LIMIT")
        self.assertFalse(result["resolved"])

    def test_repeated_movk_consumes_window_slots(self) -> None:
        image = code_image(
            [movz_w(8, 0x0926, 16)]
            + [movk_w(8, 0) for _ in range(513)]
            + [str_w(0, 8, 0x400)]
        )
        result = resolve(image, candidate(0x1000 + 514 * 4))
        self.assertEqual(result["stop_reason"], "WINDOW_LIMIT")
        self.assertFalse(result["resolved"])

    def test_mixed_width_chains_fail_closed(self) -> None:
        w_then_x = code_image([movz_w(8, 0), movk_x(8, 0x0926, 16), str_w(0, 8, 0x400)])
        result = resolve(w_then_x, candidate(0x1008))
        self.assertEqual(result["status"], "UNSUPPORTED_REGISTER_DEFINITION")
        self.assertEqual(result["slice"][0]["kind"], "MIXED_WIDTH_WIDE_MOVE")

        x_then_w = code_image([movz_x(8, 0), movk_w(8, 0x0926, 16), str_w(0, 8, 0x400)])
        result = resolve(x_then_w, candidate(0x1008))
        self.assertEqual(result["status"], "UNSUPPORTED_REGISTER_DEFINITION")

    def test_branch_call_and_inbound_entry_cutoff(self) -> None:
        branch = code_image([movz_w(8, 0x0926, 16), 0x14000003, 0xD503201F, str_w(0, 8, 0x400)])
        result = resolve(branch, candidate(0x100C))
        self.assertEqual(result["stop_reason"], "CONTROL_TRANSFER")

        call = code_image([movz_w(8, 0x0926, 16), 0x94000004, 0xD503201F, 0xD503201F, str_w(0, 8, 0x400)])
        result = resolve(call, candidate(0x1010))
        self.assertEqual(result["stop_reason"], "CONTROL_TRANSFER")

        inbound = code_image([0x14000003, 0xD503201F, 0xD503201F, str_w(0, 8, 0x400)])
        result = resolve(inbound, candidate(0x100C))
        self.assertEqual(result["stop_reason"], "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY")


class ExactIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.result = xref.analyze_path(xref.DEFAULT_XBL)

    def test_exact_pins_results_distances_domain_and_baseline(self) -> None:
        result = self.result
        self.assertEqual(result["input"]["size"], xref.XBL_SIZE)
        self.assertEqual(result["input"]["sha256"], xref.XBL_SHA256)
        model = result["model"]
        self.assertEqual(model["window_max_instructions"], 512)
        self.assertEqual(model["analyzed_candidate_count"], 2)
        self.assertEqual(model["resolved_base_count"], 2)
        self.assertEqual(model["resolved_numeric_target_hit_count"], 0)
        self.assertEqual(model["remaining_stage2a_unresolved_count"], 2)
        expected = {
            "0x14844b20": ("0x1489f000", "0x1489f400", 360, 357),
            "0x14844c78": ("0x1489f000", "0x1489f4d0", 446, 443),
        }
        for item in model["candidates"]:
            self.assertIn(item["virtual_address"], expected)
            base, effective, movz_distance, movk_distance = expected[item["virtual_address"]]
            self.assertEqual(item["base_value"], base)
            self.assertEqual(item["effective_address"], effective)
            self.assertFalse(item["target_match"])
            self.assertEqual(item["base_value_domain"], "XBL_VIRTUAL_ADDRESS_VALUE")
            self.assertEqual(item["effective_address_domain"], "XBL_VIRTUAL_ADDRESS_VALUE")
            self.assertFalse(item["inside_file_backed_pt_load"])
            self.assertEqual(item["va_to_pa_translation"], "UNKNOWN")
            self.assertIsNone(item["physical_destination"])
            self.assertEqual(item["instruction_pins"][0]["virtual_address"], "0x14844580")
            self.assertEqual(item["instruction_pins"][1]["virtual_address"], "0x1484458c")
            self.assertEqual(item["instruction_pins"][0]["distance_instructions"], movz_distance)
            self.assertEqual(item["instruction_pins"][1]["distance_instructions"], movk_distance)
        self.assertEqual(
            result["classification"],
            xref.STAGE2B_CLASSIFICATION,
        )

    def test_stage2a_baseline_hashes_and_candidate_scope_are_unchanged(self) -> None:
        root = Path(__file__).resolve().parents[1]
        baseline_paths = {
            "tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2a.py",
            "test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2a.py",
            "manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json",
        }
        for key, path in baseline_paths.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), xref.__dict__["STAGE2A_" + key.upper()])
        baseline = self.result["stage2a_baseline"]
        self.assertEqual(baseline["remaining_unresolved_count"], 2)
        self.assertEqual(baseline["remaining_virtual_addresses"], ["0x146a70c0", "0x14935bf4"])

    def test_exact_public_safety_and_no_raw_words(self) -> None:
        encoded = json.dumps(self.result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn('"word"', encoded)
        self.assertNotIn("instruction_word", encoded)
        self.assertIn("physical RAM/MC ownership is UNKNOWN", encoded)
        self.assertTrue(
            all(item["physical_destination"] is None for item in self.result["model"]["candidates"])
        )
        self.assertTrue(
            all(
                item["va_to_pa_translation"] == "UNKNOWN"
                for item in self.result["model"]["candidates"]
            )
        )
        self.assertNotIn("physical RAM", " ".join(self.result["claims"]["PROVED"]))
        self.assertNotIn("physical RAM", " ".join(self.result["claims"]["REFUTED"]))

    def test_exact_size_hash_rejection(self) -> None:
        with self.assertRaisesRegex(ValueError, "size"):
            xref.analyze(b"not exact")


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
            self.assertEqual(parsed["classification"], xref.STAGE2B_CLASSIFICATION)


if __name__ == "__main__":
    unittest.main()
