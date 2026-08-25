from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_mc_writer_stage2e as xref


class DecoderAndBoundsTests(unittest.TestCase):
    def test_candidate_str_decoder_and_negative_controls(self) -> None:
        for candidate in xref.CANDIDATES:
            self.assertEqual(
                xref._decode_str_unsigned(candidate["word"]),
                {
                    "kind": "STR_UNSIGNED_IMMEDIATE",
                    "width_bits": candidate["width_bits"],
                    "source_register": candidate["source_register"],
                    "base_register": 31,
                    "byte_offset": candidate["byte_offset"],
                },
            )
        self.assertIsNone(xref._decode_str_unsigned(0xB9400000))
        self.assertEqual(xref._decode_str_unsigned(0xB9000000)["base_register"], 0)
        self.assertNotEqual(xref._decode_str_unsigned(0xB9000000)["base_register"], 31)
        self.assertIsNone(xref._decode_str_unsigned(0x3D000000))

    def test_sp_write_decoders_cover_immediate_register_and_writeback_forms(self) -> None:
        self.assertEqual(
            xref._decode_add_sub_immediate_sp(0xD11683FF),
            {
                "kind": "SUB_IMMEDIATE_SP", "width_bits": 64,
                "source_register": 31, "destination_register": 31,
                "immediate": 0x5A0, "shift": 0,
            },
        )
        self.assertEqual(
            xref._decode_add_sub_immediate_sp(0x911683FF)["kind"], "ADD_IMMEDIATE_SP",
        )
        self.assertEqual(
            xref._decode_add_sub_register_sp(0x0B21401F),
            {
                "kind": "ADD_REGISTER_SP", "width_bits": 32,
                "source_register": 0, "operand_register": 1,
                "destination_register": 31, "shift": 0, "extension": 2,
            },
        )
        self.assertEqual(
            xref._decode_add_sub_register_sp(0x4B24D3FF),
            {
                "kind": "SUB_REGISTER_SP", "width_bits": 32,
                "source_register": 31, "operand_register": 4,
                "destination_register": 31, "shift": 4, "extension": 6,
            },
        )
        self.assertEqual(
            xref._decode_add_sub_register_sp(0x8B21601F),
            {
                "kind": "ADD_REGISTER_SP", "width_bits": 64,
                "source_register": 0, "operand_register": 1,
                "destination_register": 31, "shift": 0, "extension": 3,
            },
        )
        self.assertEqual(
            xref._decode_add_sub_register_sp(0xCB21E3FF),
            {
                "kind": "SUB_REGISTER_SP", "width_bits": 64,
                "source_register": 31, "operand_register": 1,
                "destination_register": 31, "shift": 0, "extension": 7,
            },
        )
        self.assertEqual(xref._decode_add_sub_register_sp(0x8B21501F)["shift"], 4)
        self.assertIsNone(xref._decode_add_sub_register_sp(0x8B21741F))  # reserved imm3=5
        self.assertIsNone(xref._decode_add_sub_register_sp(0x0B010C1F))  # shifted-register class, Rd=SP
        self.assertIsNone(xref._decode_add_sub_register_sp(0x8B214802))  # non-SP destination
        self.assertIsNone(xref._decode_add_sub_register_sp(0xAB21601F))  # S=1 alias
        self.assertIsNone(xref._decode_add_sub_immediate_sp(0xB100001F))  # SUBS XZR alias
        self.assertIsNone(xref._decode_add_sub_immediate_sp(0x91000400))  # non-SP destination
        self.assertEqual(xref._decode_pair_writeback(0x6DB923E9)["kind"], "PAIR_VECTOR_PRE_INDEX_STORE")
        self.assertEqual(xref._decode_pair_writeback(0x6CC723E9)["kind"], "PAIR_VECTOR_POST_INDEX_LOAD")
        self.assertEqual(xref._decode_pair_writeback(0x6DB923E9)["element_class"], "D")
        self.assertEqual(xref._decode_pair_writeback(0x6DB923E9)["scale"], 8)
        self.assertEqual(xref._decode_pair_writeback(0x2DB923E9)["element_class"], "S")
        self.assertEqual(xref._decode_pair_writeback(0x2DB923E9)["scale"], 4)
        self.assertEqual(xref._decode_pair_writeback(0xADB923E9)["element_class"], "Q")
        self.assertEqual(xref._decode_pair_writeback(0xADB923E9)["scale"], 16)
        self.assertEqual(xref._decode_pair_writeback(0x68C107E0)["element_class"], "LDPSW")
        self.assertEqual(xref._decode_pair_writeback(0x68C107E0)["scale"], 4)
        self.assertEqual(xref._decode_pair_writeback(0x29BE0BE1)["element_class"], "W")
        self.assertEqual(xref._decode_pair_writeback(0x29BE0BE1)["scale"], 4)
        self.assertEqual(xref._decode_pair_writeback(0x28C20BE1)["element_class"], "W")
        self.assertEqual(xref._decode_pair_writeback(0x28C20BE1)["scale"], 4)
        self.assertEqual(xref._decode_pair_writeback(0xA9BF0BE1)["element_class"], "X")
        self.assertEqual(xref._decode_pair_writeback(0xA9BF0BE1)["scale"], 8)
        self.assertEqual(xref._decode_pair_writeback(0xA8C10BE1)["element_class"], "X")
        self.assertEqual(xref._decode_pair_writeback(0xA8C10BE1)["scale"], 8)
        self.assertIsNone(xref._decode_pair_writeback(0x69800000))  # reserved scalar STP width code
        self.assertIsNone(xref._decode_pair_writeback(0xEDB923E9))  # reserved width code 3
        self.assertEqual(xref._decode_single_writeback(0xF8008409)["base_register"], 0)
        self.assertIsNone(xref._decode_single_writeback(0xF9400000))  # no writeback
        self.assertIsNone(xref._decode_sp_write(0xF8008409))  # non-SP base
        self.assertIsNotNone(xref._decode_sp_write(0x6DB923E9))

    def test_synthetic_frame_bounds(self) -> None:
        self.assertEqual(
            xref._frame_bounds(0x400, 64, 0x490)["access_end_offset_exclusive"], "0x408",
        )
        self.assertTrue(xref._frame_bounds(0x4D0, 32, 0x5A0)["within_allocation"])
        with self.assertRaises(ValueError):
            xref._frame_bounds(0x48D, 32, 0x490)
        with self.assertRaises(ValueError):
            xref._frame_bounds(-1, 32, 0x490)


class ExactIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not xref.DEFAULT_XBL.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.data = xref.DEFAULT_XBL.read_bytes()
        cls.result = xref.analyze(cls.data)

    def test_exact_input_candidates_functions_and_callers(self) -> None:
        self.assertEqual(self.result["input"]["size"], xref.XBL_SIZE)
        self.assertEqual(self.result["input"]["sha256"], xref.XBL_SHA256)
        self.assertEqual(len(self.result["candidates"]), 7)
        self.assertEqual(
            [(row["virtual_address"], row["form"]) for row in self.result["candidates"]],
            [
                ("0x1492e3e0", "STR W8,[SP,#0x4d0]"),
                ("0x1492e4ec", "STR X12,[SP,#0x400]"),
                ("0x14936ec0", "STR W17,[SP,#0x404]"),
                ("0x14936ec8", "STR W4,[SP,#0x400]"),
                ("0x14936ef8", "STR W4,[SP,#0x400]"),
                ("0x14936efc", "STR W17,[SP,#0x404]"),
                ("0x149377c0", "STR X7,[SP,#0x400]"),
            ],
        )
        self.assertEqual(self.result["functions"]["F1"]["range"]["sha256"], xref.F1["sha256"])
        self.assertEqual(self.result["functions"]["F2"]["range"]["sha256"], xref.F2["sha256"])
        self.assertEqual(self.result["functions"]["F1"]["direct_bl_callers"][0]["virtual_address"], "0x1492ed64")
        self.assertEqual(self.result["functions"]["F2"]["direct_bl_callers"][0]["virtual_address"], "0x14936050")
        self.assertEqual(self.result["functions"]["F1"]["direct_b_count"], 0)
        self.assertEqual(self.result["functions"]["F2"]["direct_b_count"], 0)
        for name in ("F1", "F2"):
            function = self.result["functions"][name]
            self.assertEqual(function["indirect_branch_census"]["count"], 0)
            self.assertEqual(function["indirect_branch_census"]["recognized_count"], 0)
            self.assertEqual(function["external_direct_entry_census"]["external_direct_entry_count"], 1)
            self.assertEqual(function["external_direct_entry_census"]["external_direct_entry_to_interior_count"], 0)
            self.assertEqual(function["external_direct_entry_census"]["external_direct_entry_count"], len(function["external_direct_entry_census"]["external_direct_entries"]))
            self.assertEqual(function["external_direct_entry_census"]["external_direct_entries"][0]["kind"], "BL")

    def test_exact_frames_and_sp_write_census(self) -> None:
        for name, expected_sites in {
            "F1": [0x1492DF68, 0x1492DF88, 0x1492E6F4, 0x1492E710],
            "F2": [0x14936AE0, 0x14936B08, 0x14936BAC, 0x14936BD0],
        }.items():
            function = self.result["functions"][name]
            self.assertTrue(function["frame_pins"]["pins_verified"])
            self.assertEqual(function["sp_write_census"]["count"], 4)
            self.assertEqual(
                [int(site["virtual_address"], 0) for site in function["sp_write_census"]["sites"]],
                expected_sites,
            )
            self.assertTrue(function["sp_write_census"]["range_hash_bound"])
            writeback = function["sp_write_census"]["explicit_memory_writeback_audit"]
            self.assertEqual(writeback["recognized_count"], 4)
            self.assertEqual(writeback["count"], 4)
            self.assertEqual(writeback["expected_count"], 4)
            self.assertTrue(writeback["all_recognized_sites_accounted"])
            self.assertEqual(writeback["unexpected_count"], 0)
            self.assertEqual(writeback["missing_count"], 0)
        self.assertEqual(self.result["functions"]["F1"]["instruction_count"], 492)
        self.assertEqual(self.result["functions"]["F2"]["instruction_count"], 1102)
        for name, expected_count in (("F1", 134), ("F2", 168)):
            self.assertEqual(
                self.result["functions"][name]["sp_base_memory_access_census"],
                {
                    "count": expected_count,
                    "source": "INDEPENDENT_GNU_OBJDUMP_2.46_DISASSEMBLY_CENSUS",
                    "range_hash_pinned": True,
                    "recomputed_by_this_tool": False,
                },
            )
        for candidate in self.result["candidates"]:
            self.assertEqual(candidate["base_register"], "SP")
            self.assertTrue(candidate["local_frame_bounds"]["within_allocation"])
            self.assertEqual(candidate["recognized_sp_write_sites_on_same_function_immediate_control_cfg_path"], 0)
            self.assertEqual(candidate["sp_write_cfg_model"]["scope"], "SAME_FUNCTION_IMMEDIATE_CONTROL_CFG")
            self.assertEqual(candidate["sp_write_cfg_model"]["direct_call_handling"], "BL_FALLTHROUGH")

    def test_mutation_unexpected_sp_write_and_extra_direct_caller_fail_closed(self) -> None:
        image = xref.ElfImage(self.data)
        words = xref._function_words(image, xref.F1)
        words[0x1492DF90] = 0x910043FF  # ADD SP,SP,#0x10 in the body
        with self.assertRaisesRegex(ValueError, "unexpected SP write"):
            xref._audit_sp_write_words(xref.F1, words)

        mutated = bytearray(self.data)
        offset = image.vaddr_to_offset(xref.F1["virtual_address"], 4)
        struct.pack_into("<I", mutated, offset, 0x94000000)  # BL to F1 from F1
        mutated_image = xref.ElfImage(bytes(mutated))
        callers, _branches = xref._scan_transfers(mutated_image, xref.F1["virtual_address"])
        self.assertEqual(len(callers), 2)

    def test_candidate_wrong_base_width_and_source_fail_closed(self) -> None:
        image = xref.ElfImage(self.data)
        function = xref.F1
        candidate = xref.CANDIDATES[0]
        words = xref._function_words(image, function)
        audit = xref._audit_sp_write_words(function, words)
        original = words[candidate["virtual_address"]]
        mutations = {
            "base": (original & ~(0x1F << 5)) | (0 << 5),
            "width": original | (1 << 30),
            "source": (original & ~0x1F) | 9,
        }
        for label, mutated_word in mutations.items():
            with self.subTest(label=label):
                mutated_words = dict(words)
                mutated_words[candidate["virtual_address"]] = mutated_word
                with self.assertRaisesRegex(ValueError, "candidate pin mismatch"):
                    xref._candidate_record(image, candidate, function, mutated_words, audit)

    def test_explicit_writeback_audit_rejects_new_and_changed_sites(self) -> None:
        image = xref.ElfImage(self.data)
        original = xref._function_words(image, xref.F1)

        new_site = dict(original)
        new_site[0x1492DF90] = 0xF8428769  # recognized LDR post-index at an unpinned site
        with self.assertRaisesRegex(ValueError, "unexpected explicit memory writeback"):
            xref._audit_sp_write_words(xref.F1, new_site)

        changed_base = dict(original)
        changed_base[0x1492DFE8] = (original[0x1492DFE8] & ~(0x1F << 5)) | (21 << 5)
        with self.assertRaisesRegex(ValueError, "explicit memory writeback base mismatch"):
            xref._audit_sp_write_words(xref.F1, changed_base)

        changed_sp_base = dict(original)
        changed_sp_base[0x1492DF68] = (original[0x1492DF68] & ~(0x1F << 5)) | 0
        with self.assertRaisesRegex(ValueError, "explicit memory writeback base mismatch"):
            xref._audit_sp_write_words(xref.F1, changed_sp_base)

    def test_indirect_branch_census_and_cfg_fail_closed(self) -> None:
        image = xref.ElfImage(self.data)
        words = xref._function_words(image, xref.F1)
        mutated = dict(words)
        mutated[xref.F1["allocation_sub_site"] + 4] = 0xD61F0060  # BR X0
        with self.assertRaisesRegex(ValueError, "recognized indirect branch"):
            xref._audit_indirect_branch_census(xref.F1, mutated)
        mutated[xref.F1["allocation_sub_site"] + 4] = 0xD63F0060  # BLR X0
        with self.assertRaisesRegex(ValueError, "recognized indirect branch"):
            xref._audit_indirect_branch_census(xref.F1, mutated)
        with self.assertRaisesRegex(ValueError, "indirect branch prevents static CFG"):
            xref._path_sp_write_status(
                xref.F1,
                mutated,
                xref.CANDIDATES[0]["virtual_address"],
                set(),
            )

    def test_external_direct_entry_to_interior_fails_closed(self) -> None:
        image = xref.ElfImage(self.data)
        mutated = bytearray(self.data)
        pc = xref.F1["caller_va"]
        target = xref.F1["virtual_address"] + 4
        branch = 0x14000000 | (((target - pc) // 4) & 0x03FFFFFF)
        struct.pack_into("<I", mutated, image.vaddr_to_offset(pc, 4), branch)
        with self.assertRaisesRegex(ValueError, "external direct-entry census mismatch"):
            xref._audit_external_direct_entries(xref.ElfImage(bytes(mutated)), xref.F1)

    def test_public_safety_claims_and_prior_hashes(self) -> None:
        encoded = json.dumps(self.result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn('"word"', encoded)
        self.assertNotIn("instruction_word", encoded)
        for key in ("PROVED", "SUPPORTED", "HYPOTHESIS", "UNKNOWN", "REFUTED"):
            self.assertTrue(self.result["claims"][key])
        self.assertEqual(self.result["baseline"]["stage2d_tool_sha256"], xref.STAGE2D_TOOL_SHA256)
        self.assertEqual(self.result["classification"], xref.STAGE2E_CLASSIFICATION)
        self.assertEqual(self.result["accounting"]["rwe_candidate_count_outside_scope_unknown"], 3)
        root = Path(__file__).resolve().parents[1]
        prior_paths = {
            "stage2a_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2a.py",
            "stage2a_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2a.py",
            "stage2a_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json",
            "stage2b_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2b.py",
            "stage2b_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2b.py",
            "stage2b_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json",
            "stage2c_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2c.py",
            "stage2c_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2c.py",
            "stage2c_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2c-20260825-01.manifest.json",
            "stage2d_tool_sha256": root / "tools/sm8150_xbl_mc_writer_stage2d.py",
            "stage2d_test_sha256": root / "tests/test_sm8150_xbl_mc_writer_stage2d.py",
            "stage2d_manifest_sha256": root / "evidence/manifests/018-xbl-mc-writer-xref-stage2d-20260826-01.manifest.json",
        }
        for key, path in prior_paths.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), self.result["baseline"][key])

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


if __name__ == "__main__":
    unittest.main()
