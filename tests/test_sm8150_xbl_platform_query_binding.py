"""Focused tests for the bounded Experiment 025 binding proof.

The decoder and census tests use synthetic ELF64 images.  Exact-image tests
skip when the pinned Experiment 004 XBL is absent, while the checked-in public
manifest is still generated separately by the tool's CLI.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_xbl_platform_query_binding as binding


def build_elf(segments: list[tuple[int, int, bytes, int | None]]) -> bytes:
    """Build a minimal ELF64 with explicit PT_LOAD memory sizes."""
    ph_offset, ph_entry = 64, 56
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4], header[5], header[6] = 2, 1, 1
    struct.pack_into("<Q", header, 32, ph_offset)
    struct.pack_into("<H", header, 54, ph_entry)
    struct.pack_into("<H", header, 56, len(segments))
    body_start = ph_offset + ph_entry * len(segments)
    phdrs, body = bytearray(), bytearray()
    for vaddr, flags, payload, mem_size in segments:
        file_offset = body_start + len(body)
        memory_size = len(payload) if mem_size is None else mem_size
        phdrs += struct.pack(
            "<IIQQQQQQ",
            1,
            flags,
            file_offset,
            vaddr,
            vaddr,
            len(payload),
            memory_size,
            0x1000,
        )
        body += payload
    return bytes(header) + bytes(phdrs) + bytes(body)


def assemble(base: int, words: list[int], flags: int = 5) -> binding.Image:
    payload = b"".join(struct.pack("<I", word) for word in words)
    return binding.Image(build_elf([(base, flags, payload, None)]))


def adrp(vaddr: int, rd: int, page: int) -> int:
    delta = (page - (vaddr & ~0xFFF)) >> 12
    delta &= 0x1FFFFF
    return 0x90000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | rd


def add_x(rd: int, rn: int, immediate: int, shift: int = 0) -> int:
    return 0x91000000 | ((shift & 1) << 22) | ((immediate & 0xFFF) << 10) | (rn << 5) | rd


def ldr_x(rt: int, rn: int, byte_offset: int) -> int:
    return 0xF9400000 | ((byte_offset // 8) << 10) | (rn << 5) | rt


def str_w(rt: int, rn: int, byte_offset: int = 0) -> int:
    return 0xB9000000 | ((byte_offset // 4) << 10) | (rn << 5) | rt


def str_x(rt: int, rn: int, byte_offset: int = 0) -> int:
    return 0xF9000000 | ((byte_offset // 8) << 10) | (rn << 5) | rt


def bl(vaddr: int, target: int) -> int:
    return 0x94000000 | (((target - vaddr) // 4) & 0x03FFFFFF)


def b(vaddr: int, target: int) -> int:
    return 0x14000000 | (((target - vaddr) // 4) & 0x03FFFFFF)


class DecoderTests(unittest.TestCase):
    def test_bl_and_blr_decode(self):
        self.assertEqual(binding.decode_bl_target(bl(0x1000, 0x0F00), 0x1000), 0x0F00)
        self.assertIsNone(binding.decode_b_target(bl(0x1000, 0x0F00), 0x1000))
        self.assertEqual(binding.decode_b_target(b(0x1000, 0x0F00), 0x1000), 0x0F00)
        self.assertEqual(binding.is_blr(0xD63F0120), 9)
        self.assertIsNone(binding.is_blr(0xD61F0000))
        self.assertEqual(binding.is_br(0xD61F0020), 1)

    def test_adrp_add_pair_resolves_with_intervening_unrelated_move(self):
        base = 0x1000
        image = assemble(base, [adrp(base, 1, 0x9000), 0x52800000, add_x(1, 1, 0x590)])
        self.assertEqual(binding._direct_target(image, base + 8), 0x9590)

    def test_adrp_add_pair_rejects_redefined_input(self):
        base = 0x1000
        image = assemble(base, [adrp(base, 1, 0x9000), add_x(1, 0, 1), add_x(1, 1, 0x590)])
        self.assertIsNone(binding._direct_target(image, base + 8))

    def test_adrp_add_pair_rejects_movz_clobber(self):
        base = 0x1000
        image = assemble(base, [adrp(base, 1, 0x9000), 0x52800021, add_x(1, 1, 0x590)])
        self.assertIsNone(binding._direct_target(image, base + 8))

    def test_census_kills_address_definition_across_direct_call(self):
        base = 0x1000
        image = assemble(base, [adrp(base, 1, 0x9000), bl(base + 4, base + 0x20), str_x(0, 1)])
        scan = binding.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_accesses"], [])

    def test_census_kills_address_definition_across_indirect_branch(self):
        base = 0x1000
        image = assemble(base, [adrp(base, 1, 0x9000), 0xD61F0020, str_x(0, 1)])
        scan = binding.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_accesses"], [])

    def test_memory_decoders_distinguish_width_and_store(self):
        self.assertEqual(binding.is_ldr_str_unsigned(ldr_x(8, 20, 0x590)), ("LDR", "X", 0x590, 20, 8))
        self.assertEqual(binding.is_ldr_str_unsigned(str_w(8, 19)), ("STR", "W", 0, 19, 8))
        self.assertIsNone(binding.is_ldr_str_unsigned(0xD65F03C0))

    def test_postindex_and_unscaled_forms_decode(self):
        self.assertEqual(
            binding.is_ldr_postindex(0xF840854B),
            ("LDR", "X", 8, 10, 11),
        )
        self.assertEqual(
            binding.is_ldr_str_unscaled(0xF81F8140),
            ("STR", "X", -8, 10, 0),
        )

    def test_unsupported_computed_address_stays_unrecognized(self):
        # ADD X1,X2,X3 is not ADD-immediate and must not be treated as a fixed
        # BSS address by the bounded resolver.
        self.assertIsNone(binding.is_add_x_imm(0x8B030041))


class ImageTests(unittest.TestCase):
    def test_keeps_memory_only_pt_load(self):
        image = binding.Image(build_elf([(0x1000, 5, bytes(8), None), (0x2000, 6, b"", 0x100)]))
        segment = image.segment_for(0x2000, file_backed=False)
        self.assertIsNotNone(segment)
        self.assertEqual(segment.file_size, 0)
        self.assertEqual(segment.mem_size, 0x100)
        self.assertIsNone(image.file_offset(0x2000))

    def test_rejects_malformed_program_headers(self):
        data = bytearray(build_elf([(0x1000, 5, bytes(8), None)]))
        struct.pack_into("<H", data, 56, 2)
        with self.assertRaises(binding.BindingError):
            binding.Image(bytes(data))


class SyntheticCensusTests(unittest.TestCase):
    def test_census_resolves_direct_slot_load_and_registry_write(self):
        # The synthetic image uses the same idioms as the exact helper and
        # registry insertion, but has no private bytes or fixed addresses in
        # its output contract.
        base = 0x1000
        words = [
            adrp(base, 20, 0x9000),
            ldr_x(8, 20, 0x590),
            0xF840854B,  # LDR X11,[X10],#8 (unreachable until the second block)
        ]
        image = assemble(base, words)
        scan = binding.decode_materialised_addresses(image)
        self.assertEqual(scan["word_count"], len(words))
        self.assertEqual(scan["scan_scope"], "ALL_FILE_BACKED_EXECUTABLE_PT_LOAD_WORDS")
        self.assertEqual(scan["recognized_direct_accesses"][0]["target"], "0x00009590")
        self.assertEqual(scan["arbitrary_write_absence"], "UNKNOWN")

    def test_census_does_not_claim_absence_for_unknown_store_forms(self):
        image = assemble(0x1000, [adrp(0x1000, 1, 0x9000), 0x8B030041, 0xF9000020])
        scan = binding.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_accesses"], [])
        self.assertFalse(scan["unsupported_forms"] == [])


@unittest.skipUnless((binding.FIRMWARE_DIR / binding.XBL_NAME).exists(), "exact XBL is not present")
class ExactImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = binding.Image(binding.load_xbl(binding.FIRMWARE_DIR))

    def test_exact_platform_query_argument_flow(self):
        result = binding.analyze_platform_query(self.image)
        self.assertEqual(result["direct_caller"]["input"], "X0=SP+0x10")
        self.assertFalse(result["direct_caller"]["context_register_forwarded"])
        self.assertEqual(result["runtime_slot"]["address"], "0x14890590")
        self.assertEqual(result["helper_arguments"]["callback_output_argument"], "X1=SP+0xc")

    def test_exact_service_id_movz_movk_pair_and_mutation(self):
        self.assertEqual(binding.decode_service_id(self.image), binding.SERVICE_ID)
        mutated = bytearray(self.image.data)
        offset = self.image.file_offset(0x1486AC3C)
        self.assertIsNotNone(offset)
        struct.pack_into("<I", mutated, offset, 0x72A04020)
        with self.assertRaises(binding.BindingError):
            binding.decode_service_id(binding.Image(bytes(mutated)))

    def test_exact_record_id_descriptor_factory_and_vtable(self):
        result = binding.analyze_registry(self.image)
        self.assertEqual(result["record"]["count"], 5)
        self.assertEqual(result["record"]["service_id"], "0x02000139")
        self.assertEqual(result["descriptor"]["factory_pointer"], "0x1484a880")
        self.assertEqual(result["descriptor"]["callback_pointer"], "0x1484a9d4")
        self.assertEqual(result["factory"]["constructed_object_candidate"], "0x1488f418")

    def test_exact_callback_direct_write_is_output_only(self):
        result = binding.analyze_callback(self.image)
        self.assertEqual(result["lazy_init"]["range"]["end_exclusive"], "0x1484a854")
        self.assertEqual(result["lazy_init"]["bootstrap"]["range"]["end_exclusive"], "0x1484aa74")
        self.assertEqual(result["lazy_init"]["bootstrap"]["range"]["size"], 68)
        self.assertEqual(result["lazy_init"]["bootstrap"]["range"]["sha256"], "1fb73c03710d2acc52a1330804dcb6605d34f16bf8a84dd49902470b4edd8bf8")
        self.assertEqual(result["lazy_init"]["bootstrap"]["ret"]["word"], "0xd65f03c0")
        self.assertEqual(result["lazy_init"]["status_bss"]["writes"][0]["target"], "0x14890ba0")
        self.assertEqual(result["lazy_init"]["range"]["size"], 48)
        self.assertEqual(result["lazy_init"]["status_helper"]["range"]["size"], 44)
        self.assertEqual(result["lazy_init"]["call_graph"][0]["to"], "0x1484aa30")
        self.assertEqual(result["lazy_init"]["status_bss"]["end_exclusive"], "0x14890ba4")
        self.assertEqual([row["va"] for row in result["callback"]["direct_writes"]], ["0x1484a9f4"])
        self.assertEqual(result["callback_callee"]["direct_writes"], [])
        self.assertEqual(result["lazy_init"]["status_bss"]["writes"][0]["target"], "0x14890ba0")
        self.assertEqual(result["lazy_init"]["flag"]["address"], "0x1488f3f9")
        self.assertEqual(result["lazy_init"]["status_helper"]["mmio_read"]["address"], "0x01fc8004")
        self.assertEqual(result["write_classification"]["recognized_direct_mmio_writes"], 0)
        self.assertEqual(result["write_classification"]["arbitrary_or_nested_writes"], "UNKNOWN_BEYOND_PINNED_LAZY_INIT_AND_STATUS_HELPER")

    def test_exact_census_pins_both_slot_loads_and_registry_insert(self):
        scan = binding.decode_materialised_addresses(self.image)
        result = binding.analyze_census(self.image, scan)
        self.assertEqual(
            [row["va"] for row in result["runtime_slot"]["recognized_direct_accesses"]],
            ["0x1486ac04", "0x1486aca4"],
        )
        self.assertIn("0x1482d814", [row["va"] for row in result["registry_bss"]["recognized_direct_writes"]])
        self.assertFalse(result["complete_arbitrary_write_absence"])

    def test_dependency_key_claims_are_validated(self):
        original = binding.DEPENDENCY_PATH.read_bytes()
        mutated = bytearray(original)
        marker = b'"base_currentness": "UNKNOWN"'
        self.assertIn(marker, mutated)
        mutated[mutated.index(marker) + len(marker) - 9] = ord("X")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / binding.DEPENDENCY_NAME
            path.write_bytes(bytes(mutated))
            with mock.patch.object(binding, "DEPENDENCY_SHA256", hashlib.sha256(mutated).hexdigest()):
                with self.assertRaises(binding.BindingError):
                    binding.dependency_audit(path)


class PublicationTests(unittest.TestCase):
    @unittest.skipUnless((binding.FIRMWARE_DIR / binding.XBL_NAME).exists(), "exact XBL is not present")
    def test_manifest_is_public_and_deterministic(self):
        first = json.dumps(binding.build_manifest(), indent=1, sort_keys=True) + "\n"
        second = json.dumps(binding.build_manifest(), indent=1, sort_keys=True) + "\n"
        self.assertEqual(first, second)
        self.assertNotIn("evidence/private", first)
        self.assertNotIn("/home/", first)
        self.assertNotIn("device_id", first)
        manifest = json.loads(first)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"]["experiments_015_016"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["base_audit"]["full_base_preservation"], "UNKNOWN")
        dod = manifest["definition_of_done"]
        self.assertEqual(dod["date"], "2026-08-26")
        self.assertEqual(dod["timestamp"]["value"], "NOT_APPLICABLE")
        self.assertEqual(dod["target"], {"model": "SM-A908N", "marketing_name": "A90 5G", "soc": "SM8150", "soc_name": "Snapdragon 855", "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH"})
        self.assertEqual(dod["firmware"]["sha256"], binding.XBL_SHA256)
        self.assertEqual(dod["firmware"]["build"], "UNKNOWN")
        for artifact in ("kernel", "boot", "dtb", "research_kernel"):
            self.assertEqual(dod["non_applicable_artifacts"][artifact]["sha256"], "NOT_APPLICABLE")
            self.assertIn("host-only static", dod["non_applicable_artifacts"][artifact]["reason"])
        self.assertEqual(dod["dmesg"]["status"], "NOT_APPLICABLE")
        self.assertEqual(dod["log"]["status"], "NOT_APPLICABLE")
        self.assertEqual(dod["rollback"]["status"], "NOT_APPLICABLE")
        self.assertEqual(dod["recovery"]["status"], "NOT_APPLICABLE")
        self.assertEqual(dod["deterministic_repetition_validation"]["repetition_count"], 2)
        self.assertEqual(dod["deterministic_repetition_validation"]["validation_count"], 5)
        self.assertEqual(dod["deterministic_repetition_validation"]["repetition_result"], "BYTE_IDENTICAL")

    def test_no_clobber_and_umask_exact_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            original_umask = os.umask(0o077)
            try:
                binding.write_no_clobber(path, b"{}\n")
            finally:
                os.umask(original_umask)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                binding.write_no_clobber(path, b"clobber\n")
            self.assertEqual(path.read_bytes(), b"{}\n")

    def test_cli_regeneration_is_byte_identical(self):
        if not (binding.FIRMWARE_DIR / binding.XBL_NAME).exists():
            self.skipTest("exact XBL is not present")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            self.assertEqual(binding.main(["--firmware-dir", str(binding.FIRMWARE_DIR), "--output", str(output)]), 0)
            expected = (json.dumps(binding.build_manifest(), indent=1, sort_keys=True) + "\n").encode()
            self.assertEqual(output.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
