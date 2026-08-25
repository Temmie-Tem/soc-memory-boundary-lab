"""Tests for the Experiment 020 DCB consumer / DDR base cross-reference.

Decoder and analysis tests run on synthetic fixtures and need no private bytes.
The exact-image tests skip when the Experiment 004 artifacts are absent.
"""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

from tools import sm8150_xbl_dcb_consumer_xref as xref


def build_elf(segments: list[tuple[int, int, bytes]]) -> bytes:
    """Assemble a minimal ELF64. Each segment is (vaddr, p_flags, payload)."""
    ph_offset, ph_entry = 64, 56
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<Q", header, 32, ph_offset)
    struct.pack_into("<H", header, 54, ph_entry)
    struct.pack_into("<H", header, 56, len(segments))
    body_start = ph_offset + ph_entry * len(segments)
    table, body = bytearray(), bytearray()
    for vaddr, flags, payload in segments:
        offset = body_start + len(body)
        table += struct.pack("<IIQQQQQQ", 1, flags, offset, vaddr, vaddr, len(payload), len(payload), 0x1000)
        body += payload
    return bytes(header) + bytes(table) + bytes(body)


def movz_w(rd: int, imm16: int) -> int:
    return 0x52800000 | (imm16 << 5) | rd


def ldrh(rt: int, rn: int, byte_offset: int) -> int:
    return 0x79400000 | ((byte_offset // 2) << 10) | (rn << 5) | rt


def str_reg_offset(rt: int, rn: int, rm: int, *, wide: bool = False, scaled: bool = False) -> int:
    base = 0xF8200800 if wide else 0xB8200800
    return base | (rm << 16) | (0b011 << 13) | ((1 if scaled else 0) << 12) | (rn << 5) | rt


def str_x_imm(rt: int, rn: int, byte_offset: int) -> int:
    return 0xF9000000 | ((byte_offset // 8) << 10) | (rn << 5) | rt


def adrp(rd: int, vaddr: int, page: int) -> int:
    delta = (page - (vaddr & ~0xFFF)) >> 12
    delta &= 0x1FFFFF
    return 0x90000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | rd


def branch(vaddr: int, target: int) -> int:
    return 0x14000000 | (((target - vaddr) // 4) & 0x03FFFFFF)


def ldr_x_imm(rt: int, rn: int, byte_offset: int) -> int:
    return 0xF9400000 | ((byte_offset // 8) << 10) | (rn << 5) | rt


def ldr_x_postindex(rt: int, rn: int, imm9: int) -> int:
    return 0xF8400400 | ((imm9 & 0x1FF) << 12) | (rn << 5) | rt


def add_imm(rd: int, rn: int, imm: int) -> int:
    return 0x91000000 | (imm << 10) | (rn << 5) | rd


def add_reg(rd: int, rn: int, rm: int) -> int:
    return 0x8B000000 | (rm << 16) | (rn << 5) | rd


def str_w_imm0(rt: int, rn: int) -> int:
    return 0xB9000000 | (rn << 5) | rt


def assemble(base: int, words: list[int]) -> xref.Image:
    return xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))


class DecoderTests(unittest.TestCase):
    def test_ldrh_immediate_round_trips_its_byte_offset(self):
        self.assertEqual(xref.is_ldrh_immediate(ldrh(3, 19, 0x34)), (0x34, 19, 3))

    def test_ldrh_rejects_other_encodings(self):
        self.assertIsNone(xref.is_ldrh_immediate(movz_w(0, 1)))

    def test_movz_w_requires_a_zero_shift(self):
        self.assertEqual(xref.is_movz_w(movz_w(1, 0x77C)), (0x77C, 1))
        self.assertIsNone(xref.is_movz_w(0x52800000 | (1 << 21)))

    def test_register_offset_store_reports_scaling(self):
        unscaled = xref.is_register_offset_store(str_reg_offset(9, 11, 8))
        scaled = xref.is_register_offset_store(str_reg_offset(9, 11, 8, scaled=True))
        self.assertFalse(unscaled["scaled"])
        self.assertTrue(scaled["scaled"])
        self.assertEqual((unscaled["rt"], unscaled["rn"], unscaled["rm"]), (9, 11, 8))

    def test_register_offset_store_distinguishes_width(self):
        self.assertEqual(xref.is_register_offset_store(str_reg_offset(1, 2, 3))["width"], "W")
        self.assertEqual(xref.is_register_offset_store(str_reg_offset(1, 2, 3, wide=True))["width"], "X")

    def test_immediate_offset_store_is_not_counted(self):
        self.assertIsNone(xref.is_register_offset_store(str_x_imm(1, 2, 0x400)))

    def test_branch_target_decodes_a_backward_branch(self):
        self.assertEqual(xref.branch_target(branch(0x1000, 0xF80), 0x1000), 0xF80)

    def test_branch_target_decodes_cbz(self):
        word = 0x34000000 | ((((0x1040 - 0x1000) // 4) & 0x7FFFF) << 5) | 3
        self.assertEqual(xref.branch_target(word, 0x1000), 0x1040)

    def test_branch_target_ignores_non_branches(self):
        self.assertIsNone(xref.branch_target(movz_w(0, 1), 0x1000))

    def test_adrp_resolves_a_page_above_and_below(self):
        self.assertEqual(xref.adrp_page(adrp(8, 0x1000, 0x9000), 0x1000), (0x9000, 8))
        self.assertEqual(xref.adrp_page(adrp(8, 0x9000, 0x1000), 0x9000), (0x1000, 8))

    def test_sign_extend(self):
        self.assertEqual(xref.sign_extend(0b111, 3), -1)
        self.assertEqual(xref.sign_extend(0b011, 3), 3)


class ImageTests(unittest.TestCase):
    def test_rejects_non_elf64(self):
        with self.assertRaises(xref.XrefError):
            xref.Image(b"nope" + bytes(120))

    def test_executable_segments_are_selected_by_flags(self):
        image = xref.Image(build_elf([(0x1000, 5, bytes(8)), (0x2000, 6, bytes(8)), (0x3000, 7, bytes(8))]))
        self.assertEqual(sorted(s.kind for s in image.executable()), ["RWE", "RX"])

    def test_word_returns_none_outside_any_segment(self):
        image = xref.Image(build_elf([(0x1000, 5, bytes(8))]))
        self.assertIsNone(image.word(0x9999))


class LoaderTests(unittest.TestCase):
    def _loader_image(self) -> xref.Image:
        base = 0x1000
        words = [movz_w(1, 0x3404), movz_w(1, 0x77C), movz_w(1, 0x3DC), movz_w(1, 0x108)]
        return xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))

    def test_locates_a_window_holding_four_size_constants(self):
        result = xref.find_dcb_loader(self._loader_image())
        self.assertTrue(result["found"])
        self.assertIn("0x3404", result["constants"])

    def test_reports_not_found_when_the_cluster_is_absent(self):
        image = xref.Image(build_elf([(0x1000, 5, struct.pack("<I", movz_w(1, 0x3404)))]))
        self.assertFalse(xref.find_dcb_loader(image)["found"])

    def test_derives_a_section_index_from_a_directory_read_pair(self):
        base = 0x1000
        words = [movz_w(1, 0x77C), ldrh(9, 13, 0x0C), ldrh(3, 13, 0x0E)]
        image = xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))
        derived = xref.decode_loader_sections(image, base, base + len(words) * 4)
        self.assertEqual([d["section"] for d in derived], [0])
        self.assertEqual(derived[0]["nearest_preceding_limit"], "0x77c")

    def test_an_unpaired_directory_read_is_not_derived(self):
        base = 0x1000
        words = [ldrh(9, 13, 0x0C), ldrh(3, 7, 0x0E)]      # different base register
        image = xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))
        self.assertEqual(xref.decode_loader_sections(image, base, base + 8), [])

    def test_a_misaligned_directory_offset_is_rejected(self):
        base = 0x1000
        words = [ldrh(9, 13, 0x0E), ldrh(3, 13, 0x10)]     # 0x0e is not 0x0c + 4k
        image = xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))
        self.assertEqual([d["section"] for d in xref.decode_loader_sections(image, base, base + 8)], [])

    def test_section_directory_readers_maps_offset_to_index(self):
        base = 0x1000
        words = [ldrh(1, 19, 0x34), ldrh(2, 19, 0x36)]     # 0x34 -> section 10
        image = xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))
        self.assertEqual([r["section"] for r in xref.section_directory_readers(image)], [10])


class CensusTests(unittest.TestCase):
    def test_counts_scaled_and_unscaled_separately(self):
        words = [str_reg_offset(1, 2, 3), str_reg_offset(1, 2, 3, scaled=True)]
        image = xref.Image(build_elf([(0x1000, 5, b"".join(struct.pack("<I", w) for w in words))]))
        census = xref.register_offset_store_census(image)
        self.assertEqual(census["total_by_segment"]["RX"], 2)
        self.assertEqual(census["unscaled_total"], 1)

    def test_a_store_with_no_backward_branch_is_not_in_a_loop(self):
        image = xref.Image(build_elf([(0x1000, 5, struct.pack("<I", str_reg_offset(1, 2, 3)) + bytes(64))]))
        self.assertEqual(xref.register_offset_store_census(image)["inside_backward_branch_loop"], 0)

    def test_a_store_wrapped_by_a_backward_branch_is_in_a_loop(self):
        base = 0x1000
        words = [str_reg_offset(1, 2, 3), branch(base + 4, base)]
        image = xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))
        self.assertEqual(xref.register_offset_store_census(image)["inside_backward_branch_loop"], 1)

    def test_a_forward_branch_does_not_make_a_loop(self):
        base = 0x1000
        words = [str_reg_offset(1, 2, 3), branch(base + 4, base + 0x40)] + [0xD503201F] * 20
        image = xref.Image(build_elf([(base, 5, b"".join(struct.pack("<I", w) for w in words))]))
        self.assertEqual(xref.register_offset_store_census(image)["inside_backward_branch_loop"], 0)


class TableWalkerTests(unittest.TestCase):
    """The discriminator: does the store offset change on every pass?"""

    def _analyse(self, image):
        census = xref.register_offset_store_census(image)
        return xref.table_walker_analysis(image, census["loop_sites"])

    def test_an_offset_read_through_an_advancing_pointer_is_a_walker(self):
        base = 0x1000
        words = [
            ldr_x_postindex(13, 9, 8),        # key = *table++, writes X9 back
            str_reg_offset(10, 11, 13),       # STR W10,[X11,X13]
            branch(base + 8, base),
        ]
        result = self._analyse(assemble(base, words))
        self.assertEqual(result["table_walker_count"], 1)
        self.assertEqual(result["offset_definition_classes"], {"LOADED_VARYING": 1})

    def test_a_loop_invariant_load_is_not_a_walker(self):
        base = 0x1000
        words = [
            ldr_x_imm(13, 9, 0xEE8),          # same displacement every pass
            str_reg_offset(10, 11, 13),
            branch(base + 8, base),
        ]
        result = self._analyse(assemble(base, words))
        self.assertEqual(result["table_walker_count"], 0)
        self.assertEqual(result["offset_definition_classes"], {"LOADED_LOOP_INVARIANT": 1})

    def test_a_load_whose_base_advances_in_the_body_is_a_walker(self):
        base = 0x1000
        words = [
            ldr_x_imm(13, 9, 0x0),
            str_reg_offset(10, 11, 13),
            add_imm(9, 9, 8),                 # the address base advances
            branch(base + 12, base),
        ]
        self.assertEqual(self._analyse(assemble(base, words))["table_walker_count"], 1)

    def test_an_induction_variable_offset_is_not_a_walker(self):
        base = 0x1000
        words = [
            add_imm(13, 13, 4),
            str_reg_offset(10, 11, 13),
            branch(base + 8, base),
        ]
        result = self._analyse(assemble(base, words))
        self.assertEqual(result["offset_definition_classes"], {"INDUCTION_OR_COMPUTED": 1})

    def test_a_body_containing_ret_is_excluded_as_an_epilogue(self):
        base = 0x1000
        words = [
            ldr_x_postindex(13, 9, 8),
            xref.RET_WORD,
            str_reg_offset(10, 11, 13),
            branch(base + 12, base),
        ]
        result = self._analyse(assemble(base, words))
        self.assertEqual(result["epilogues_excluded"], 1)
        self.assertEqual(result["table_walker_count"], 0)

    def test_a_definition_after_the_store_still_counts_for_the_next_pass(self):
        base = 0x1000
        words = [
            str_reg_offset(10, 11, 13),
            ldr_x_postindex(13, 9, 8),        # defined after the store
            branch(base + 8, base),
        ]
        result = self._analyse(assemble(base, words))
        self.assertEqual(result["table_walker_count"], 1)

    def test_an_offset_defined_outside_the_loop_is_reported_as_such(self):
        base = 0x1000
        words = [str_reg_offset(10, 11, 13), branch(base + 4, base)]
        result = self._analyse(assemble(base, words))
        self.assertEqual(result["offset_definition_classes"], {"DEFINED_OUTSIDE_THE_LOOP": 1})


class ComputedAddressTests(unittest.TestCase):
    """ADD Xd,Xn,Xm feeding STR Wt,[Xd] -- in neither existing census."""

    def test_finds_the_idiom(self):
        image = assemble(0x1000, [add_reg(1, 2, 3), str_w_imm0(4, 1)])
        self.assertEqual(xref.computed_address_store_census(image)["idiom_sites"], 1)

    def test_records_the_adds_operands_not_the_stores(self):
        image = assemble(0x1000, [add_reg(1, 2, 3), str_w_imm0(4, 1), branch(0x1008, 0x1000)])
        loop = xref.computed_address_store_census(image)["loop_sites"][0]
        self.assertEqual(loop["offset_register"], 3)
        self.assertEqual(loop["base_register"], 2)

    def test_a_store_through_a_different_register_is_not_the_idiom(self):
        image = assemble(0x1000, [add_reg(1, 2, 3), str_w_imm0(4, 5)])
        self.assertEqual(xref.computed_address_store_census(image)["idiom_sites"], 0)

    def test_an_overwritten_destination_breaks_the_pair(self):
        image = assemble(0x1000, [add_reg(1, 2, 3), movz_w(1, 0), str_w_imm0(4, 1)])
        self.assertEqual(xref.computed_address_store_census(image)["idiom_sites"], 0)

    def test_a_nonzero_immediate_store_is_not_the_idiom(self):
        image = assemble(0x1000, [add_reg(1, 2, 3), 0xB9000000 | (1 << 10) | (1 << 5) | 4])
        self.assertEqual(xref.computed_address_store_census(image)["idiom_sites"], 0)

    def test_the_walker_test_uses_the_supplied_offset_register(self):
        # X3 is loaded through an advancing pointer; the store's bits 16..20 are
        # part of its immediate field and must not be read as a register.
        base = 0x1000
        words = [
            ldr_x_postindex(3, 9, 8),
            add_reg(1, 2, 3),
            str_w_imm0(4, 1),
            branch(base + 12, base),
        ]
        image = assemble(base, words)
        census = xref.computed_address_store_census(image)
        result = xref.table_walker_analysis(image, census["loop_sites"])
        self.assertEqual(result["table_walker_count"], 1)


class AopAuditTests(unittest.TestCase):
    def test_reports_unavailable_without_the_artifact(self):
        self.assertEqual(
            xref.aop_controller_reference_audit(Path("/nonexistent-firmware-dir")),
            {"available": False},
        )


class DdrSegmentTests(unittest.TestCase):
    def test_selects_the_largest_rwe_segment(self):
        image = xref.Image(build_elf([(0x1000, 7, bytes(16)), (0x2000, 7, bytes(64)), (0x3000, 5, bytes(128))]))
        self.assertEqual(xref.ddr_driver_segment(image)["vaddr"], "0x00002000")

    def test_counts_aperture_and_ranked_values(self):
        payload = struct.pack("<QQQ", 0x09260000, 0x09123456, 0x00001234)
        image = xref.Image(build_elf([(0x2000, 7, payload)]))
        result = xref.ddr_driver_segment(image)
        self.assertEqual(result["file_backed_aperture_u64"], 2)
        self.assertEqual(result["ranked_base_u64"], 1)

    def test_reports_not_found_without_an_rwe_segment(self):
        image = xref.Image(build_elf([(0x1000, 5, bytes(8))]))
        self.assertFalse(xref.ddr_driver_segment(image)["found"])


class GlobalStoreTests(unittest.TestCase):
    def test_splits_xzr_stores_from_register_stores(self):
        base = 0x9FC00000
        page = 0x9FC38000
        words = [adrp(8, base, page), str_x_imm(31, 8, 0x360), str_x_imm(0, 8, 0x368)]
        image = xref.Image(build_elf([(base, 7, b"".join(struct.pack("<I", w) for w in words))]))
        census = xref.global_store_census(image, base)
        self.assertEqual(census, {"stores_from_xzr": 1, "stores_from_register": 1})

    def test_a_store_outside_the_segment_window_is_ignored(self):
        base = 0x9FC00000
        words = [adrp(8, base, 0x10000), str_x_imm(0, 8, 0x8)]
        image = xref.Image(build_elf([(base, 7, b"".join(struct.pack("<I", w) for w in words))]))
        self.assertEqual(xref.global_store_census(image, base)["stores_from_register"], 0)


class ExactImageTests(unittest.TestCase):
    """These need the private Experiment 004 XBL and skip without it."""

    @classmethod
    def setUpClass(cls):
        if not (xref.FIRMWARE_DIR / xref.XBL_NAME).exists():
            raise unittest.SkipTest("exact Experiment 004 firmware is not present")
        cls.manifest = xref.build_manifest(xref.FIRMWARE_DIR)

    def test_refuses_a_directory_without_the_exact_image(self):
        with self.assertRaises(xref.XrefError):
            xref.load_xbl(Path("/nonexistent-firmware-dir"))

    def test_the_dcb_loader_is_located(self):
        self.assertTrue(self.manifest["dcb_loader"]["found"])

    def test_code_derived_loader_sections_match_the_recorded_constant(self):
        self.assertTrue(self.manifest["loader_matches_recorded_constant"])
        derived = {entry["section"] for entry in self.manifest["loader_consumed_sections_derived_from_code"]}
        self.assertEqual(derived, set(xref.EXPECTED_LOADER_SECTIONS))

    def test_register_offset_stores_exist_in_executable_segments(self):
        census = self.manifest["register_offset_store_census"]
        self.assertGreater(census["unscaled_total"], 0)
        self.assertGreater(census["inside_backward_branch_loop"], 0)

    def test_no_register_offset_store_walks_a_key_value_table(self):
        walkers = self.manifest["table_walker_analysis"]
        self.assertEqual(walkers["table_walker_count"], 0)
        self.assertEqual(walkers["table_walkers"], [])
        self.assertGreater(walkers["loop_sites_examined"], 0)

    def test_every_loop_site_is_classified(self):
        walkers = self.manifest["table_walker_analysis"]
        self.assertEqual(sum(walkers["offset_definition_classes"].values()), walkers["loop_sites_examined"])

    def test_the_computed_address_idiom_has_no_walker_either(self):
        self.assertEqual(self.manifest["computed_address_walker_analysis"]["table_walker_count"], 0)

    def test_aop_is_elf32_arm_and_names_no_ranked_base(self):
        aop = self.manifest["aop_controller_reference_audit"]
        self.assertTrue(aop["available"])
        self.assertEqual(aop["elf_class"], 32)
        self.assertEqual(aop["machine"], 40)          # EM_ARM
        self.assertEqual(set(aop["ranked_base_literals"].values()), {0})

    def test_aop_has_no_consecutive_run_of_directory_readers(self):
        sections = sorted(entry["section"] for entry in
                          self.manifest["aop_controller_reference_audit"]["dcb_directory_read_pairs"])
        consecutive = any(b - a == 1 for a, b in zip(sections, sections[1:]))
        self.assertFalse(consecutive)

    def test_the_ddr_segment_holds_no_aperture_constant(self):
        ddr = self.manifest["ddr_driver_segment"]
        self.assertEqual(ddr["file_backed_aperture_u64"], 0)
        self.assertEqual(ddr["ranked_base_u64"], 0)

    def test_every_non_zero_setter_store_is_argument_sourced(self):
        setter = self.manifest["pinned_base_setter"]
        self.assertTrue(setter["found"])
        self.assertTrue(setter["every_non_zero_store_is_argument_sourced"])
        self.assertEqual(setter["constant_sourced_store_count"], 0)

    def test_the_pinned_setter_has_exactly_one_direct_caller(self):
        self.assertEqual(len(self.manifest["pinned_setter_direct_callers"]), 1)

    def test_manifest_carries_no_raw_bytes_or_private_paths(self):
        blob = repr(self.manifest)
        self.assertNotIn("evidence/private", blob)
        self.assertNotIn("/home/", blob)


if __name__ == "__main__":
    unittest.main()
