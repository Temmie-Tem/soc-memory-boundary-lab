"""Focused tests for the bounded Experiment 024 six-byte walker proof."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_six_byte_walker as walker


def build_elf(segments: list[tuple[int, int, bytes]]) -> bytes:
    """Build a minimal ELF64 with the supplied (VA, flags, payload) loads."""
    ph_offset, ph_entry = 64, 56
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6] = 2, 1, 1
    struct.pack_into("<Q", header, 32, ph_offset)
    struct.pack_into("<H", header, 54, ph_entry)
    struct.pack_into("<H", header, 56, len(segments))
    body_start = ph_offset + ph_entry * len(segments)
    phdrs, body = bytearray(), bytearray()
    for vaddr, flags, payload in segments:
        offset = body_start + len(body)
        phdrs += struct.pack(
            "<IIQQQQQQ", 1, flags, offset, vaddr, vaddr, len(payload), len(payload), 0x1000
        )
        body += payload
    return bytes(header) + bytes(phdrs) + bytes(body)


def assemble(base: int, words: list[int], flags: int = 5) -> walker.Image:
    payload = b"".join(struct.pack("<I", word) for word in words)
    return walker.Image(build_elf([(base, flags, payload)]))


def b_cond(vaddr: int, target: int, condition: int = 3) -> int:
    displacement = (target - vaddr) // 4
    return 0x54000000 | ((displacement & 0x7FFFF) << 5) | condition


class DecoderTests(unittest.TestCase):
    def test_umaddl_decodes_operands(self):
        self.assertEqual(walker.is_umaddl(0x9BAA052E), (14, 9, 10, 1))

    def test_umaddl_rejects_signed_long_madd(self):
        self.assertIsNone(walker.is_umaddl(0x9B2A052E))

    def test_umaddl_rejects_umsubl(self):
        self.assertIsNone(walker.is_umaddl(0x9BAA852E))

    def test_movz_w_rejects_unsupported_hw(self):
        self.assertIsNone(walker.decode_movz_w(0x52C00000))

    def test_ldrh_and_ldrb_preserve_byte_offsets(self):
        self.assertEqual(walker.is_ldrh(0x794005CD), (2, 14, 13))
        self.assertEqual(walker.is_ldrb(0x394011CE), (4, 14, 14))

    def test_register_offset_store_rejects_wide_store(self):
        self.assertEqual(walker.is_str_w_register_offset(0xB82D69EE), (14, 15, 13))
        self.assertIsNone(walker.is_str_w_register_offset(0xF82D69EE))

    def test_direct_bl_and_conditional_branch_targets(self):
        self.assertEqual(walker.decode_bl_target(0x94000002, 0x1000), 0x1008)
        self.assertEqual(walker.decode_b_target(b_cond(0x1000, 0x0FE0), 0x1000), 0x0FE0)


class ImageTests(unittest.TestCase):
    def test_rejects_malformed_program_header_extent(self):
        data = bytearray(build_elf([(0x1000, 5, bytes(8))]))
        struct.pack_into("<H", data, 56, 2)
        with self.assertRaises(walker.WalkerError):
            walker.Image(bytes(data))

    def test_keeps_memory_only_load_for_selector_proof(self):
        data = bytearray(build_elf([(0x1000, 5, bytes(8)), (0x2000, 6, b"")]))
        # The second PT_LOAD is deliberately zero-file-size but nonzero-memory.
        struct.pack_into("<Q", data, 64 + 56 + 40, 0x100)
        image = walker.Image(bytes(data))
        memory_segment = image.segment_for(0x2000, file_backed=False)
        self.assertIsNotNone(memory_segment)
        self.assertEqual(memory_segment.file_size, 0)
        self.assertIsNone(image.file_offset(0x2000))


class WalkerShapeTests(unittest.TestCase):
    def synthetic(self) -> walker.Image:
        base = 0x1000
        words = [
            0xF9400408,  # LDR X8,[X0,#8]
            0x2A1F03E9,  # MOV W9,WZR
            0x321F07EA,  # ORR W10,WZR,#6
            0x9BAA052E,  # UMADDL X14,W9,W10,X1
            0x794005CD,  # LDRH W13,[X14,#2]
            0x794001CF,  # LDRH W15,[X14]
            0x394011CE,  # LDRB W14,[X14,#4]
            0x714021FF,  # CMP W15,#0x8000
            b_cond(base + 32, base + 56, 0),  # B.EQ return
            0xF940040F,  # LDR X15,[X0,#8]
            0xB82D69EE,  # STR W14,[X15,X13]
            0x11000529,  # ADD W9,W9,#1
            0x6B02013F,  # CMP W9,W2
            b_cond(base + 52, base + 12),
            0xD65F03C0,  # RET
        ]
        return assemble(base, words)

    def test_positive_shape_is_decoded(self):
        image = self.synthetic()
        result = walker.decode_six_byte_walker(image, 0x1000, 0x1000 + 15 * 4)
        self.assertEqual(result["record_stride"], 6)
        self.assertEqual(result["fields"]["offset"]["offset"], 2)
        self.assertTrue(result["fields"]["value"]["zero_extended"])
        self.assertEqual(result["back_edge"], "0x00001034")

    def test_mutating_ldrb_to_ldrh_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1018)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0x794011CE)
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_stride_literal_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1008)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0x321F0BEA)
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_base_load_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1024)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0xF940000F)
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_terminator_branch_target_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1020)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, b_cond(0x1020, 0x1040, 0))
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_umaddl_stride_register_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x100C)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0x9BAB052E)  # W11, not W10
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_store_to_scaled_form_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1028)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0xB82D79EE)
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_increment_shift_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x102C)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0x11400529)
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_count_compare_register_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1030)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0x6B03013F)  # CMP W9,W3
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_backedge_condition_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1034)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, b_cond(0x1034, 0x100C, 1))  # B.NE
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)

    def test_mutating_flags_load_register_fails_closed(self):
        image = self.synthetic()
        data = bytearray(image.data)
        offset = image.file_offset(0x1014)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", data, offset, 0x7940018F)  # LDRH W15,[X12]
        with self.assertRaises(walker.WalkerError):
            walker.decode_six_byte_walker(walker.Image(bytes(data)), 0x1000, 0x103c)


class ExactImageTests(unittest.TestCase):
    @staticmethod
    def source_paths() -> tuple[Path, Path]:
        public = os.environ.get("EXP024_PUBLIC_KERNEL_DTSI")
        osrc = os.environ.get("EXP024_OSRC_KERNEL_DTSI")
        if public and osrc:
            return Path(public), Path(osrc)
        root = Path(os.environ.get("ANDROID_NATIVE_INIT_LAB", str(walker.REPO_ROOT.parent / "android-native-init-lab")))
        return (
            root / "workspace" / "private" / "work" / "public_a90_r3q" / "kernel_samsung_r3q-e1d271581eff" / "arch" / "arm64" / "boot" / "dts" / "qcom" / "sm8150.dtsi",
            root / "workspace" / "private" / "work" / "a90-stock-mpgen27-20260822" / "source" / "arch" / "arm64" / "boot" / "dts" / "qcom" / "sm8150.dtsi",
        )

    @classmethod
    def setUpClass(cls):
        if not (walker.FIRMWARE_DIR / walker.XBL_NAME).exists():
            raise unittest.SkipTest("exact Experiment 004 XBL is not present")
        kernel, osrc = cls.source_paths()
        try:
            cls.result = walker.build_manifest(walker.FIRMWARE_DIR, kernel, osrc)
        except walker.WalkerError as exc:
            raise unittest.SkipTest(str(exc))

    def test_exact_artifact_pins(self):
        self.assertEqual(self.result["inputs"]["firmware"]["size"], walker.XBL_SIZE)
        self.assertEqual(self.result["inputs"]["firmware"]["sha256"], walker.XBL_SHA256)
        self.assertEqual(self.result["inputs"]["public_kernel_dtsi"]["size"], walker.PUBLIC_KERNEL_DTSI_SIZE)
        self.assertEqual(self.result["inputs"]["public_kernel_dtsi"]["sha256"], walker.PUBLIC_KERNEL_DTSI_SHA256)
        self.assertEqual(self.result["inputs"]["osrc_kernel_dtsi"]["size"], walker.OSRC_KERNEL_DTSI_SIZE)
        self.assertEqual(self.result["inputs"]["osrc_kernel_dtsi"]["sha256"], walker.OSRC_KERNEL_DTSI_SHA256)
        self.assertEqual(self.result["inputs"]["ufs_design_block"]["sha256"], walker.UFS_BLOCK_SHA256)

    def test_walker_range_and_direct_callers(self):
        self.assertEqual(self.result["walker"]["range"]["size"], 196)
        self.assertEqual(self.result["walker"]["range"]["sha256"], walker.WALKER_SHA256)
        self.assertEqual(self.result["walker"]["flag_gate_range"]["size"], 84)
        self.assertEqual(self.result["walker"]["flag_gate_range"]["sha256"], walker.WALKER_FLAG_GATE_SHA256)
        self.assertEqual(self.result["walker"]["terminator"]["comparison_va"], "0x148689f0")
        self.assertEqual(self.result["walker"]["terminator"]["branch_target"], "0x14868a60")
        self.assertEqual(self.result["walker"]["zero_count_control"]["count_register"], "W2")
        self.assertEqual(self.result["direct_callers"]["direct_bl_caller_count"], 3)
        self.assertEqual(self.result["direct_callers"]["direct_bl_callers"], ["0x14868640", "0x1486867c", "0x14868698"])

    def test_five_tables_and_offset_union(self):
        tables = self.result["tables"]
        self.assertEqual([row["count"] for row in tables["tables"]], [16, 13, 43, 64, 90])
        self.assertEqual(tables["nonterminator_offset_union_count"], 170)
        self.assertEqual(tables["scenario_offset_unions"]["selector_eq_0xf"]["unique_offset_count"], 53)
        self.assertEqual(tables["scenario_offset_unions"]["selector_ne_0xf"]["unique_offset_count"], 127)
        self.assertEqual(tables["nonterminator_offset_min"], "0x00007000")
        self.assertEqual(tables["nonterminator_offset_max"], "0x00007de0")
        self.assertEqual(tables["excluded_offsets_absent"], ["0x00000400", "0x00000404", "0x000004d0"])

    def test_provider_and_base_boundaries_are_explicit(self):
        self.assertEqual(len(self.result["providers"]["five_table_alternatives"]), 5)
        self.assertEqual(self.result["providers"]["runtime_selector"]["current_value"], "UNKNOWN")
        exception = self.result["providers"]["selector_eq_0xf_provider3"]
        self.assertEqual(exception["status"], "NO_TABLE_POINTER_STORE")
        self.assertEqual(exception["caller_w2"], "0")
        self.assertEqual(exception["walker_zero_count_control"], "CONDITIONALLY_RETURNS_BEFORE_ANY_TABLE_DEREFERENCE")
        audit = self.result["initializer_and_base_audit"]
        self.assertEqual(audit["base_currentness"], "UNKNOWN")
        self.assertTrue(audit["mapping"]["conditional"])
        self.assertEqual(self.result["conditional_ufs_destinations"]["outside_standalone_ufsphy_mem_offsets"], ["0x00007dc4", "0x00007dd8", "0x00007de0"])
        self.assertEqual(self.result["conditional_ufs_destinations"]["actual_reached_store_subset"], "UNKNOWN")
        self.assertEqual(audit["unresolved_success_path"]["unresolved_blr"]["va"], "0x1486ac1c")

    def test_experiment_019_dependency_is_pinned(self):
        dependency = self.result["dependencies"]["experiment_019"]
        self.assertEqual(dependency["sha256"], walker.DEPENDENCY_019_SHA256)
        self.assertEqual(dependency["candidate_pair_array_count"], 28)
        self.assertEqual(dependency["representation"], "EIGHT_BYTE_XBL_CONFIG_CANDIDATE_PAIR_ARRAYS")

    def test_dependency_hash_mutation_fails_closed(self):
        source, osrc_source = self.source_paths()
        if not source.exists():
            self.skipTest("OSRC source is not available")
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "sm8150.dtsi"
            mutated.write_bytes(source.read_bytes() + b"\n")
            with self.assertRaises(walker.WalkerError):
                walker.dts_analysis(mutated, osrc_source)

    def test_experiment_019_dependency_mutation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / walker.DEPENDENCY_019_NAME
            mutated.write_bytes(walker.DEPENDENCY_019_PATH.read_bytes() + b"\n")
            with self.assertRaises(walker.WalkerError):
                walker.load_019_dependency(mutated)

    def test_public_manifest_safety_and_claim_vocab(self):
        encoded = json.dumps(self.result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn("workspace/private", encoded)
        self.assertNotIn("evidence/private", encoded)
        self.assertEqual(set(self.result["claims"]), {"PROVED", "SUPPORTED", "HYPOTHESIS", "UNKNOWN", "REFUTED"})
        self.assertEqual(self.result["eligibility"]["experiments_015_016"], "NOT_ELIGIBLE")


class PublicationTests(unittest.TestCase):
    def test_write_no_clobber_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            previous_umask = os.umask(0o077)
            try:
                walker.write_no_clobber(path, b"{}\n")
            finally:
                os.umask(previous_umask)
            self.assertEqual(path.read_bytes(), b"{}\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                walker.write_no_clobber(path, b"changed\n")

    def test_json_regeneration_is_byte_identical(self):
        if not (walker.FIRMWARE_DIR / walker.XBL_NAME).exists():
            self.skipTest("exact XBL is not present")
        public, osrc = ExactImageTests.source_paths()
        try:
            first = json.dumps(walker.build_manifest(public_kernel_dtsi=public, osrc_kernel_dtsi=osrc), indent=1, sort_keys=True) + "\n"
            second = json.dumps(walker.build_manifest(public_kernel_dtsi=public, osrc_kernel_dtsi=osrc), indent=1, sort_keys=True) + "\n"
        except walker.WalkerError as exc:
            self.skipTest(str(exc))
        self.assertEqual(first.encode(), second.encode())
        self.assertEqual(hashlib.sha256(first.encode()).hexdigest(), hashlib.sha256(second.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
