from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_mc_writer_stage2d as xref


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


class DecoderAndConditionalModelTests(unittest.TestCase):
    def test_strict_decoders_and_numeric_controls(self) -> None:
        self.assertEqual(
            xref._decode_bl(xref.CALLER_WORD, xref.CALLER_VA),
            {"kind": "BL", "target": xref.FUNCTION_VA},
        )
        self.assertEqual(
            xref._decode_b(0x14000000, 0x1000),
            {"kind": "B", "target": 0x1000},
        )
        self.assertIsNone(xref._decode_bl(0x14000000, 0x1000))
        self.assertIsNone(xref._decode_str_unsigned(0xB9800000))
        self.assertIsNone(xref._decode_str_unsigned(0x3D000000))
        self.assertEqual(
            xref._decode_str_post_index(0xF8008409),
            {
                "kind": "STR_POST_INDEX", "width_bits": 64,
                "source_register": 9, "base_register": 0,
                "byte_offset": 8, "base_writeback_register": 0,
            },
        )
        self.assertEqual(
            xref._decode_str_post_index(0x38001501)["base_writeback_register"], 8,
        )
        self.assertIsNone(xref._decode_str_post_index(0xB8400400))
        self.assertEqual(
            xref._decode_ldp_signed_offset(0x2943C206),
            {
                "kind": "LDP_SIGNED_OFFSET", "width_bits": 32,
                "first_destination": 6, "second_destination": 16,
                "base_register": 16, "byte_offset": 28,
            },
        )
        self.assertIsNone(xref._decode_ldp_signed_offset(0x2903C206))
        self.assertEqual(
            xref._decode_madd_x(0x9B0D62F3),
            {"kind": "MADD_X", "destination": 19, "left": 23, "right": 13, "accumulator": 24},
        )

    def test_positive_and_negative_numeric_target_fixtures(self) -> None:
        bases, effective = xref._compute_effective_values(0x09260000, (0,))
        self.assertEqual(bases, [0x09260000])
        self.assertEqual(effective, [0x09260400])
        self.assertIn(effective[0], xref.TARGETS)
        _bases, negative = xref._compute_effective_values(0x85E9E570, (0, 1))
        self.assertEqual(negative, [0x85E9E970, 0x85E9EF70])
        self.assertTrue(all(value not in xref.TARGETS for value in negative))

    def test_mutation_of_callee_critical_word_fails_closed(self) -> None:
        if not xref.DEFAULT_XBL.exists():
            self.skipTest("exact private XBL is unavailable")
        data = bytearray(xref.DEFAULT_XBL.read_bytes())
        image = xref.ElfImage(bytes(data))
        offset = image.vaddr_to_offset(0x14935B60, 4)
        data[offset] ^= 1
        with self.assertRaises(ValueError):
            xref._decode_callee_path(xref.ElfImage(bytes(data)))

    def test_exact_target_audit_rejects_saved_destination_and_indirect_transfer(self) -> None:
        words = {va: spec["word"] for va, spec in xref._TARGET_CALLEE_AUDIT.items()}
        first = next(iter(words))
        words[first] = 0xAA0003F3  # MOV X19,X0
        with self.assertRaisesRegex(ValueError, "saved-register"):
            xref._audit_target_callee_words(words)
        words[first] = xref._TARGET_CALLEE_AUDIT[first]["word"]
        words[first] = 0xD61F0060  # BR X3
        with self.assertRaisesRegex(ValueError, "indirect control"):
            xref._audit_target_callee_words(words)
        words[first] = 0xD63F0060  # BLR X3
        with self.assertRaisesRegex(ValueError, "indirect control"):
            xref._audit_target_callee_words(words)
        words[first] = xref._TARGET_CALLEE_AUDIT[first]["word"]
        post_va = 0x1483C94C
        words[post_va] = (words[post_va] & ~(0x1F << 5)) | (19 << 5)
        with self.assertRaisesRegex(ValueError, "saved-register writeback"):
            xref._audit_target_callee_words(words)

        for va, spec in xref._TARGET_CALLEE_AUDIT.items():
            if spec["kind"] == "STORE_POST_INDEX":
                decoded = xref._decode_str_post_index(spec["word"])
                self.assertEqual(set(spec["writes_gpr"]), {decoded["base_writeback_register"]})
        self.assertEqual(xref._TARGET_CALLEE_AUDIT[0x1483C950]["writes_gpr"], frozenset({10}))
        self.assertEqual(xref._TARGET_CALLEE_AUDIT[0x1483C9C8]["writes_gpr"], frozenset({11}))

    def test_post_call_x9_audit_rejects_x9_definition_and_control_transfer(self) -> None:
        words = {va: spec["word"] for va, spec in xref._POST_CALL_X9_AUDIT.items()}
        first = next(iter(words))
        words[first] = 0xAA0003E9  # MOV X9,X0
        with self.assertRaisesRegex(ValueError, "X9 redefinition"):
            xref._audit_post_call_x9_words(words)
        words[first] = 0x94000000  # BL to the current PC
        with self.assertRaisesRegex(ValueError, "control transfer"):
            xref._audit_post_call_x9_words(words)
        words[first] = xref._POST_CALL_X9_AUDIT[first]["word"]
        ldp_va = 0x14935BC4
        words[ldp_va] = (words[ldp_va] & ~(0x1F << 10)) | (9 << 10)
        with self.assertRaisesRegex(ValueError, "LDP redefinition"):
            xref._audit_post_call_x9_words(words)

    def test_initializer_control_audit_rejects_indirect_forms_and_b_callers(self) -> None:
        if not xref.DEFAULT_XBL.exists():
            self.skipTest("exact private XBL is unavailable")
        image = xref.ElfImage(xref.DEFAULT_XBL.read_bytes())
        words = {va: image.u32(va) for va in range(xref.INITIALIZER_VA, xref.INITIALIZER_END_VA, 4)}
        words[xref.INITIALIZER_VA] = 0xD61F0060  # BR X3
        with self.assertRaisesRegex(ValueError, "control transfer"):
            xref._audit_initializer_control_words(words)
        words[xref.INITIALIZER_VA] = image.u32(xref.INITIALIZER_VA)
        words[xref.INITIALIZER_VA + 4] = 0xD63F0060  # BLR X3
        with self.assertRaisesRegex(ValueError, "control transfer"):
            xref._audit_initializer_control_words(words)


class ExactIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.data = xref.DEFAULT_XBL.read_bytes()
        cls.result = xref.analyze(cls.data)

    def test_exact_function_candidate_direct_bl_and_b_pins(self) -> None:
        result = self.result
        self.assertEqual(result["input"]["size"], xref.XBL_SIZE)
        self.assertEqual(result["input"]["sha256"], xref.XBL_SHA256)
        self.assertEqual(result["function"]["virtual_address"], "0x14935960")
        self.assertEqual(result["function"]["file_offset"], "0x312930")
        self.assertEqual(result["function"]["byte_length"], 1404)
        self.assertEqual(result["function"]["sha256"], xref.FUNCTION_SHA256)
        self.assertEqual(result["candidate"]["virtual_address"], "0x14935bf4")
        self.assertEqual(result["candidate"]["file_offset"], "0x312bc4")
        self.assertEqual(result["candidate"]["form"], "STR X9,[X19,#0x400]")
        self.assertEqual(result["direct_callers"]["direct_bl_count"], 1)
        self.assertEqual(result["direct_callers"]["direct_b_count"], 0)
        self.assertEqual(
            result["direct_callers"]["direct_bl_callers"],
            [{
                "virtual_address": "0x14949eec",
                "file_offset": "0x326ebc",
                "target": "0x14935960",
                "segment_class": "RX",
            }],
        )

    def test_caller_callee_and_conditional_values(self) -> None:
        caller = self.result["caller_success_path"]
        self.assertEqual(caller["lookup_call_target"], "0x14935868")
        self.assertEqual(caller["lookup_result_branch_target"], "0x14949ee4")
        self.assertEqual(caller["x1_source"], "SP")
        self.assertEqual(caller["x1_immediate"], "0xe0")
        self.assertEqual(caller["writer_call_target"], "0x14935960")
        self.assertEqual(caller["writer_call_w0_domain"], ["0x0"])
        callee = self.result["callee_path"]
        self.assertEqual(callee["intrinsic_w0_domain"], ["0x0", "0x1"])
        self.assertEqual(callee["intrinsic_pre_call_x19_base_values"], ["0x85e9e570", "0x85e9eb70"])
        self.assertEqual(callee["w20_dispatch"]["branch_target"], "0x14935aac")
        self.assertTrue(callee["pre_madd_result_gate"]["requires_w0_zero_to_reach_madd"])
        values = self.result["conditional_values"]
        self.assertEqual(values["conditional_effective_values"], ["0x85e9e970"])
        self.assertEqual(values["intrinsic_possible_effective_values"], ["0x85e9e970", "0x85e9ef70"])
        self.assertEqual(values["numeric_target_match_count"], 0)
        self.assertEqual(self.result["post_call_x9"]["source_register"], "X19")
        self.assertEqual(self.result["post_call_x9"]["offset"], "0x428")
        self.assertTrue(self.result["post_call_x9"]["no_intervening_direct_bl"])
        self.assertEqual(self.result["post_call_x9"]["range"]["sha256"], xref.POST_CALL_X9_RANGE_SHA256)
        self.assertEqual(self.result["classification"], xref.STAGE2D_CLASSIFICATION)
        self.assertEqual(
            self.result["stage"],
            "STAGE2D_UNIQUE_DIRECT_CALLER_CONDITIONAL_CALLEE_SAVED_PRESERVATION_MODEL",
        )

    def test_wrapper_thunk_import_and_memory_tail_facts(self) -> None:
        initializer = self.result["initializer"]
        self.assertEqual(initializer["x8_value"], "0x1489f000")
        self.assertEqual(initializer["x5_value"], "0x1483c904")
        self.assertEqual(initializer["resolved_import_slot"], "0x1489f3b0")
        self.assertEqual(initializer["direct_bl_caller_count"], 1)
        self.assertEqual(initializer["direct_b_caller_count"], 0)
        self.assertEqual(initializer["runtime_execution"], "UNKNOWN")
        self.assertEqual(initializer["later_slot_mutation"], "UNKNOWN")
        target = self.result["target_callee"]
        self.assertEqual(target["direct_bl_count"], 0)
        self.assertEqual(target["callee_saved_write_count"], 0)
        self.assertTrue(target["exact_instruction_class_manifest"])
        pre = self.result["pre_madd_direct_callee"]
        self.assertEqual(pre["range"]["sha256"], xref.PRE_MADD_DIRECT_CALLEE_SHA256)
        self.assertTrue(pre["normal_return_preserves_x23_x24"])
        self.assertEqual(pre["unique_ret_count"], 1)
        self.assertEqual(target["semantic_name"], "UNKNOWN")
        wrapper = self.result["wrapper_thunk"]
        self.assertEqual(wrapper["wrapper_range"]["sha256"], xref.WRAPPER_SHA256)
        self.assertEqual(wrapper["thunk_range"]["sha256"], xref.THUNK_SHA256)
        self.assertEqual(wrapper["tail_target"], "0x14900254")
        self.assertFalse(wrapper["x19_defined_by_wrapper_or_thunk"])
        self.assertEqual(wrapper["direct_bl_link_register"], "X30")
        self.assertEqual(wrapper["thunk_runtime_target"], "UNKNOWN")
        self.assertEqual(wrapper["wrapper_range"]["segment_class"], "RX")
        self.assertEqual(wrapper["thunk_range"]["segment_class"], "RX")
        memory = self.result["elf_memory_facts"]
        self.assertEqual(memory["import_slot"]["filesz"], 0)
        self.assertEqual(memory["import_slot"]["memory_only_rw_pt_load_start"], "0x14882800")
        self.assertEqual(memory["import_slot"]["memory_only_rw_pt_load_end"], "0x1489f400")
        effective = memory["effective_value_segment"]
        self.assertTrue(effective["p_vaddr_equals_p_paddr"])
        self.assertTrue(all(not value for value in effective["values_inside_file_backed_range"].values()))
        self.assertTrue(all(effective["values_inside_pt_load_memory_range"].values()))

    def test_intervening_call_sites_and_prior_hashes(self) -> None:
        calls = self.result["intervening_calls"]
        self.assertEqual(
            [(call["call_site"], call["target"], call["phase"]) for call in calls],
            [
                ("0x14935abc", "0x1493641c", "PRE_MADD"),
                ("0x14935b48", "0x149396f4", "PRE_MADD"),
                ("0x14935b54", "0x149396f4", "PRE_MADD"),
                ("0x14935b68", "0x149396f4", "POST_MADD_X19"),
            ],
        )
        root = Path(__file__).resolve().parents[1]
        paths = {
            "stage2a_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2a.py",
            "stage2a_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2a.py",
            "stage2a_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json",
            "stage2b_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2b.py",
            "stage2b_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2b.py",
            "stage2b_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json",
            "stage2c_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2c.py",
            "stage2c_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2c.py",
            "stage2c_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2c-20260825-01.manifest.json",
        }
        for key, path in paths.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), xref.__dict__[key.upper()])

    def test_mutation_of_ranges_caller_wrapper_and_import_segment_fails_closed(self) -> None:
        data = bytearray(self.data)
        image = xref.ElfImage(bytes(data))
        function_offset = image.vaddr_to_offset(xref.FUNCTION_VA, 4)
        data[function_offset] ^= 1
        with self.assertRaises(ValueError):
            xref._read_code_range(
                xref.ElfImage(bytes(data)), xref.FUNCTION_VA, xref.FUNCTION_END_VA,
                xref.FUNCTION_FILE_OFFSET, xref.FUNCTION_SIZE, xref.FUNCTION_SHA256,
            )

        data = bytearray(self.data)
        caller_offset = image.vaddr_to_offset(xref.CALLER_ZERO_SITE, 4)
        data[caller_offset] ^= 1
        with self.assertRaises(ValueError):
            xref._decode_direct_caller_path(xref.ElfImage(bytes(data)))

        data = bytearray(self.data)
        wrapper_offset = image.vaddr_to_offset(xref.WRAPPER_VA + 12, 4)
        data[wrapper_offset] ^= 1
        with self.assertRaises(ValueError):
            xref._validate_wrapper_thunk(xref.ElfImage(bytes(data)))

        data = bytearray(self.data)
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        # The exact zero-file-size import PT_LOAD is program-header index 5.
        struct.pack_into("<I", data, phoff + 5 * 56 + 4, 4)
        with self.assertRaises(ValueError):
            xref._validate_memory_segments(xref.ElfImage(bytes(data)), {0x85E9E970})

        data = bytearray(self.data)
        init_offset = image.vaddr_to_offset(xref.INITIALIZER_VA, 4)
        data[init_offset] ^= 1
        with self.assertRaises(ValueError):
            xref._validate_initializer(xref.ElfImage(bytes(data)))

        data = bytearray(self.data)
        target_offset = image.vaddr_to_offset(xref.TARGET_CALLEE_VA, 4)
        data[target_offset] ^= 1
        with self.assertRaises(ValueError):
            xref._target_callee_register_census(xref.ElfImage(bytes(data)))

        data = bytearray(self.data)
        pre_offset = image.vaddr_to_offset(xref.PRE_MADD_SAVE_SITE, 4)
        data[pre_offset] ^= 1
        with self.assertRaises(ValueError):
            xref._validate_pre_madd_direct_callee(xref.ElfImage(bytes(data)))

    def test_public_safety_and_claim_taxonomy(self) -> None:
        encoded = json.dumps(self.result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn('"word"', encoded)
        self.assertNotIn("instruction_word", encoded)
        for key in ("PROVED", "SUPPORTED", "HYPOTHESIS", "UNKNOWN", "REFUTED"):
            self.assertTrue(self.result["claims"][key])
        self.assertIn("preservation", " ".join(self.result["claims"]["REFUTED"]).lower())
        self.assertIn("UNKNOWN", encoded)
        self.assertNotIn("requires_unresolved_pre_madd_call_preservation", encoded)
        self.assertIn("current runtime import-slot target/currentness", encoded)

    def test_malformed_exact_input_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "size"):
            xref.analyze(b"not exact")


class PublicationTests(unittest.TestCase):
    def test_cli_no_clobber_and_deterministic_output(self) -> None:
        if not xref.DEFAULT_XBL.exists():
            self.skipTest("exact private XBL is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            self.assertEqual(xref.main(["--output", str(first)]), 0)
            self.assertEqual(xref.main(["--output", str(second)]), 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.stat().st_mode & 0o777, 0o644)
            self.assertRaises(FileExistsError, xref.main, ["--output", str(first)])
            self.assertEqual(json.loads(first.read_text())["classification"], xref.STAGE2D_CLASSIFICATION)


if __name__ == "__main__":
    unittest.main()
