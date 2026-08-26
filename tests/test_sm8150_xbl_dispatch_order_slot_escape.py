"""Focused synthetic and exact-image tests for Experiment 026.

Synthetic tests deliberately exercise the decoder's negative boundary: a
clobber, branch, unknown computed address, or unsupported memory form must not
be promoted to a target write.  Exact-image tests are skipped when the private
pinned XBL is unavailable.
"""

from __future__ import annotations

import json
import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_xbl_dispatch_order_slot_escape as dispatch


def build_elf(segments: list[tuple[int, int, bytes, int | None]]) -> bytes:
    phoff, phentsize = 64, 56
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:7] = bytes((2, 1, 1))
    struct.pack_into("<Q", header, 32, phoff)
    struct.pack_into("<H", header, 54, phentsize)
    struct.pack_into("<H", header, 56, len(segments))
    body_start = phoff + phentsize * len(segments)
    phdrs, body = bytearray(), bytearray()
    for va, flags, payload, mem_size in segments:
        off = body_start + len(body)
        mem = len(payload) if mem_size is None else mem_size
        phdrs += struct.pack("<IIQQQQQQ", 1, flags, off, va, va, len(payload), mem, 0x1000)
        body += payload
    return bytes(header) + bytes(phdrs) + bytes(body)


def assemble(base: int, words: list[int], flags: int = 5) -> dispatch.Image:
    payload = b"".join(struct.pack("<I", word) for word in words)
    return dispatch.Image(build_elf([(base, flags, payload, None)]))


def adrp(va: int, rd: int, target: int) -> int:
    delta = ((target & ~0xFFF) - (va & ~0xFFF)) >> 12
    encoded = delta & 0x1FFFFF
    return 0x90000000 | ((encoded & 3) << 29) | ((encoded >> 2) << 5) | rd


def adr(va: int, rd: int, target: int) -> int:
    delta = (target - va) & 0x1FFFFF
    return 0x10000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | rd


def add_x(rd: int, rn: int, imm: int, *, sub: bool = False) -> int:
    return (0xD1000000 if sub else 0x91000000) | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def add_reg(rd: int, rn: int, rm: int, amount: int = 0, shift_type: int = 0, *, sub: bool = False) -> int:
    return (0xCB000000 if sub else 0x8B000000) | ((shift_type & 3) << 22) | ((amount & 0x3F) << 10) | (rm << 16) | (rn << 5) | rd


def movz_x(rd: int, imm: int, hw: int = 0) -> int:
    return 0xD2800000 | ((hw & 3) << 21) | ((imm & 0xFFFF) << 5) | rd


def movk_x(rd: int, imm: int, hw: int = 0) -> int:
    return 0xF2800000 | ((hw & 3) << 21) | ((imm & 0xFFFF) << 5) | rd


def movn_w(rd: int, imm: int, hw: int = 0) -> int:
    return 0x12800000 | ((hw & 3) << 21) | ((imm & 0xFFFF) << 5) | rd


def orr_copy(rd: int, rn: int, *, shift: int = 0, shift_type: int = 0) -> int:
    return 0xAA000000 | ((shift_type & 3) << 22) | ((shift & 0x3F) << 10) | (31 << 5) | (rn << 16) | rd


def str_x(rt: int, rn: int, offset: int = 0) -> int:
    return 0xF9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def str_w(rt: int, rn: int, offset: int = 0) -> int:
    return 0xB9000000 | ((offset // 4) << 10) | (rn << 5) | rt


def str_x_reg(rt: int, rn: int, rm: int) -> int:
    # STR X<t>,[X<n>,X<m>] (register offset, LSL #0).
    return 0xF8206800 | (rm << 16) | (rn << 5) | rt


def str_x_post(rt: int, rn: int, offset: int) -> int:
    return 0xF8000400 | ((offset & 0x1FF) << 12) | (rn << 5) | rt


def ldr_x_post(rt: int, rn: int, offset: int) -> int:
    return 0xF8400400 | ((offset & 0x1FF) << 12) | (rn << 5) | rt


def ldr_x_literal(va: int, rt: int, literal_va: int) -> int:
    return 0x58000000 | ((((literal_va - va) // 4) & 0x7FFFF) << 5) | rt


def ldp_x(rt: int, rt2: int, rn: int, offset: int = 0) -> int:
    return 0xA9400000 | (((offset // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def b(va: int, target: int) -> int:
    return 0x14000000 | (((target - va) // 4) & 0x03FFFFFF)


class DecoderTests(unittest.TestCase):
    def test_adr_and_adrp_decode(self):
        self.assertEqual(dispatch.adr_target(adr(0x1000, 3, 0x1200), 0x1000), (0x1200, 3))
        self.assertEqual(dispatch.adrp_target(adrp(0x1000, 4, 0x9000), 0x1000), (0x9000, 4))

    def test_movz_movk_movn_decode(self):
        self.assertEqual(dispatch.is_movz(movz_x(2, 0x1234)), ("X", 0x1234, 0, 2))
        self.assertEqual(dispatch.is_movk(movk_x(2, 0x5678, 1)), ("X", 0x5678, 1, 2))
        self.assertEqual(dispatch.is_movn(movn_w(2, 0x12)), ("W", 0x12, 0, 2))

    def test_register_copy_shift_and_add_sub(self):
        self.assertEqual(dispatch.is_orr_reg(orr_copy(8, 9, shift=3)), ("X", 8, 31, 9, 0, 3))
        self.assertIsNotNone(dispatch.is_add_sub_reg(0x8B020041))
        self.assertIsNotNone(dispatch.is_add_sub_ext_reg(0x8B226020))
        self.assertIsNone(dispatch.is_add_sub_ext_reg(0x0B226020))  # W UXTX rejected
        self.assertEqual(dispatch.is_sub_x_imm(0xD1000421), (1, 1, 1, 0))

    def test_shift_semantics_and_opcode_boundaries(self):
        self.assertEqual(dispatch._shift_value(0x100, "X", 0, 3), 0x800)
        self.assertEqual(dispatch._shift_value(0x800, "X", 1, 3), 0x100)
        self.assertEqual(dispatch._shift_value(0xFFFFFFFFFFFFFFFF, "X", 2, 2), 0xFFFFFFFFFFFFFFFF)
        self.assertIsNone(dispatch._shift_value(1, "X", 3, 0))
        # AND (0x0a/0x8a) is not ORR and must not seed address taint.
        self.assertIsNone(dispatch.is_orr_reg(0x8A020041))
        # Unsupported UBFM/SBFM aliases are intentionally UNKNOWN.
        self.assertIsNone(dispatch.is_extend(0xD3400000))
        self.assertEqual(dispatch.is_orr_reg(orr_copy(8, 9, shift=3, shift_type=1)), ("X", 8, 31, 9, 1, 3))
        self.assertEqual(dispatch.is_orr_reg(orr_copy(8, 9, shift=3, shift_type=2)), ("X", 8, 31, 9, 2, 3))
        self.assertIsNone(dispatch.is_orr_reg(orr_copy(8, 9, shift_type=3)))
        self.assertIsNone(dispatch._is_add_sub_imm(0xB1000000))  # ADDS
        self.assertIsNone(dispatch._is_add_sub_imm(0x910003FF))  # ADD XZR
        self.assertIsNone(dispatch._is_add_sub_imm(0x91800000))  # ADDG/MTE
        self.assertIsNone(dispatch._is_add_sub_imm(0xD1800000))  # SUBG/MTE
        self.assertIsNone(dispatch.is_add_sub_reg(0xAB020041))  # ADDS shifted
        self.assertIsNone(dispatch.is_add_sub_ext_reg(0x8B626020))  # reserved bits23:22=01
        self.assertIsNone(dispatch.is_add_sub_ext_reg(0x8BA26020))  # reserved bits23:22=10

    def test_memory_forms_are_separated(self):
        self.assertEqual(dispatch.is_mem_unsigned(0xF9400008), ("LDR", "X", 0, 0, 8))
        self.assertEqual(dispatch.is_mem_unscaled(0xF81F8140), ("STR", "X", -8, 10, 0))
        self.assertEqual(dispatch.is_mem_index(0xF840854B), ("LDR", "X", 8, 10, 11, "POSTINDEX"))
        self.assertEqual(dispatch.is_mem_pair(0xA9417BFD), ("LDP", "X", 16, 31, 29, 30, "OFFSET"))
        self.assertEqual(dispatch.is_mem_pair(0xA9BF7BFD)[-1], "PREINDEX")
        self.assertEqual(dispatch.is_mem_pair(0xA8C24FF4)[-1], "POSTINDEX")
        self.assertEqual(dispatch.is_mem_literal(0x18000000, 0x1000)[:2], ("LDR", "W"))
        self.assertEqual(dispatch.is_mem_literal(0x58000000, 0x1000)[:2], ("LDR", "X"))
        self.assertIsNone(dispatch.is_mem_literal(0x98000000, 0x1000))  # LDRSW
        self.assertIsNone(dispatch.is_mem_literal(0xD8000000, 0x1000))  # PRFM
        self.assertEqual(dispatch.is_mem_reg_offset(0xF8626820)[-3:], (3, 0, 0))
        self.assertEqual(dispatch.is_mem_reg_offset(0xF8627820)[-3:], (3, 3, 0))  # S scales X index by 3
        self.assertIsNone(dispatch.is_mem_reg_offset(0xF8620820))  # invalid option
        self.assertIsNone(dispatch.is_mem_exclusive_atomic(0xC85F7C00))
        self.assertIsNone(dispatch.is_mem_unscaled(0xF89F8140))  # unprivileged/sign variant
        self.assertIsNone(dispatch.is_mem_index(0xF8C0854B))  # unprivileged/index variant
        self.assertIsNone(dispatch.is_mem_pair(0x2D000000))  # SIMD/FP pair
        self.assertIsNone(dispatch.is_mem_reg_offset(0xF8A26820))  # sign-ext variant
        self.assertIsNone(dispatch.is_mem_reg_offset(0xFC626820))  # SIMD/V variant
        self.assertIsNotNone(dispatch.is_mem_reg_offset(0xF8626820))

    def test_branch_decoders_keep_call_and_branch_distinct(self):
        self.assertEqual(dispatch.decode_bl_target(bl(0x1000, 0x1200), 0x1000), 0x1200)
        self.assertIsNone(dispatch.decode_b_target(bl(0x1000, 0x1200), 0x1000))
        self.assertEqual(dispatch.decode_b_target(b(0x1000, 0x0F00), 0x1000), 0x0F00)
        self.assertTrue(dispatch.is_ret(0xD65F03C0))


class ImageTests(unittest.TestCase):
    def test_keeps_memory_only_load(self):
        image = dispatch.Image(build_elf([(0x1000, 5, bytes(8), None), (0x2000, 6, b"", 0x100)]))
        seg = image.segment_for(0x2000, file_backed=False)
        self.assertIsNotNone(seg)
        self.assertEqual(seg.file_size, 0)
        self.assertIsNone(image.file_offset(0x2000))

    def test_rejects_program_header_extent(self):
        raw = bytearray(build_elf([(0x1000, 5, bytes(8), None)]))
        struct.pack_into("<H", raw, 56, 2)
        with self.assertRaises(dispatch.DispatchError):
            dispatch.Image(bytes(raw))


class SyntheticCensusTests(unittest.TestCase):
    def test_slot_store_and_direct_argument_escape(self):
        base = 0x10000000
        target = dispatch.RUNTIME_SLOT
        words = [adrp(base, 0, target), add_x(0, 0, target & 0xFFF), str_x(1, 0)]
        scan = dispatch.decode_materialised_addresses(assemble(base, words))
        self.assertEqual(len(scan["recognized_direct_writes"]), 1)
        self.assertEqual(scan["recognized_direct_writes"][0]["target"], dispatch.fmt(target))
        self.assertEqual(scan["recognized_pointer_escapes"], [])

        words = [adrp(base, 0, target), add_x(0, 0, target & 0xFFF), bl(base + 8, base + 0x100)]
        scan = dispatch.decode_materialised_addresses(assemble(base, words))
        self.assertEqual(scan["recognized_pointer_escapes"][0]["argument"], "X0")

    def test_movk_and_orr_copy_materialize_global(self):
        target = dispatch.REGISTRATION_HEAD
        base = 0x10000000
        low, high = target & 0xFFFF, (target >> 16) & 0xFFFF
        image = assemble(base, [movz_x(0, low), movk_x(0, high, 1), orr_copy(1, 0), str_x(2, 1)])
        scan = dispatch.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_writes"][0]["target"], dispatch.fmt(target))
        shifted = target << 3
        shifted_image = assemble(base, [movz_x(0, shifted & 0xFFFF), movk_x(0, (shifted >> 16) & 0xFFFF, 1), orr_copy(1, 0, shift=3, shift_type=1), str_x(2, 1)])
        shifted_scan = dispatch.decode_materialised_addresses(shifted_image)
        self.assertEqual(shifted_scan["recognized_direct_writes"][0]["target"], dispatch.fmt(target))

    def test_shifted_add_uses_imm6_not_shift_type(self):
        target = dispatch.REGISTRATION_HEAD
        base = 0x10000000
        # Start 0x100 below the target, then add X1<<8.  A decoder that uses
        # the shift-type code (0 for LSL) would miss the target.
        image = assemble(
            base,
            [adrp(base, 0, target), add_x(0, 0, (target & 0xFFF) - 0x100), movz_x(1, 1), add_reg(0, 0, 1, amount=8), str_x(2, 0)],
        )
        scan = dispatch.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_writes"][0]["target"], dispatch.fmt(target))

    def test_clobber_and_control_flow_fail_closed(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        clobbered = assemble(base, [adrp(base, 0, target), movz_x(0, 1), add_x(0, 0, target & 0xFFF), str_x(1, 0)])
        self.assertEqual(dispatch.decode_materialised_addresses(clobbered)["recognized_direct_accesses"], [])
        branched = assemble(base, [adrp(base, 0, target), b(base + 4, base + 12), add_x(0, 0, target & 0xFFF), str_x(1, 0)])
        self.assertEqual(dispatch.decode_materialised_addresses(branched)["recognized_direct_accesses"], [])

    def test_postindex_uses_old_effective_base(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        image = assemble(base, [adrp(base, 0, target), add_x(0, 0, target & 0xFFF), str_x_post(1, 0, 8)])
        scan = dispatch.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_writes"][0]["target"], dispatch.fmt(target))

    def test_slot_interval_overlap_catches_partial_pointer_stores(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        # W at slot+4 overlaps the upper half of the pointer-sized slot.
        upper = assemble(base, [adrp(base, 0, target + 4), add_x(0, 0, (target + 4) & 0xFFF), str_w(1, 0)])
        upper_scan = dispatch.decode_materialised_addresses(upper)
        self.assertEqual(upper_scan["recognized_direct_writes"][0]["target_class"], "RUNTIME_SLOT_0x14890590")
        # X at slot-4 overlaps the lower four bytes of the slot.
        lower = assemble(base, [adrp(base, 0, target - 4), add_x(0, 0, (target - 4) & 0xFFF), str_x(1, 0)])
        lower_scan = dispatch.decode_materialised_addresses(lower)
        self.assertEqual(lower_scan["recognized_direct_writes"][0]["target_class"], "RUNTIME_SLOT_0x14890590")
        self.assertEqual(dispatch._target_class(target + 4), "RUNTIME_SLOT_0x14890590")
        self.assertIsNone(dispatch._target_class(target - 4))

    def test_writeback_load_base_destination_overlap_clears_taint(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        image = assemble(base, [adrp(base, 0, target), add_x(0, 0, target & 0xFFF), ldr_x_post(0, 0, 8), str_x(1, 0)])
        scan = dispatch.decode_materialised_addresses(image)
        self.assertEqual(len(scan["recognized_direct_reads"]), 1)
        self.assertEqual(scan["recognized_direct_writes"], [])

    def test_xzr_alias_does_not_hold_address_taint(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        image = assemble(base, [adrp(base, 31, target), add_x(0, 31, target & 0xFFF), str_x(1, 0)])
        self.assertEqual(dispatch.decode_materialised_addresses(image)["recognized_direct_accesses"], [])

    def test_unavailable_literal_load_kills_stale_destination(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        # The LDR literal target is outside the synthetic file-backed segment.
        # It overwrites X0 with an unknown value; stale target taint must not
        # reach the following store.
        image = assemble(base, [adrp(base, 0, target), add_x(0, 0, target & 0xFFF), ldr_x_literal(base + 8, 0, 0x2000), str_x(1, 0)])
        scan = dispatch.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_accesses"], [])
        self.assertIn("LITERAL_VALUE_NOT_FILE_BACKED", scan["unsupported_forms"])

    def test_unknown_register_offset_never_becomes_fixed_target(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        image = assemble(base, [adrp(base, 0, target), add_x(0, 0, target & 0xFFF), str_x_reg(1, 0, 2)])
        scan = dispatch.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_accesses"], [])
        self.assertIn("COMPUTED_RUNTIME_INDEXES_AND_POINTERS", scan["unsupported_forms"])

    def test_pair_load_kills_both_destinations(self):
        target = dispatch.RUNTIME_SLOT
        base = 0x10000000
        # X1 is first materialized as the target, then overwritten as Rt2 by
        # LDP.  A stale single-destination model would falsely recognize the
        # following store through X1.
        image = assemble(base, [adrp(base, 1, target), add_x(1, 1, target & 0xFFF), ldp_x(0, 1, 2), str_x(3, 1)])
        scan = dispatch.decode_materialised_addresses(image)
        self.assertEqual(scan["recognized_direct_accesses"], [])


class TaxonomyTests(unittest.TestCase):
    def test_order_open_is_derived_from_unresolved_inputs(self):
        unresolved = {"runtime_status": "UNKNOWN"}
        result = dispatch.derive_order_taxonomy(unresolved, unresolved, unresolved, unresolved, unresolved)
        self.assertEqual(result["status"], "ORDER_OPEN")
        self.assertFalse(result["closure"])
        self.assertEqual(len(result["reasons"]), 5)
        closed = {"runtime_status": "PROVED_RUNTIME_ORDER"}
        result = dispatch.derive_order_taxonomy(closed, closed, closed, closed, closed)
        self.assertEqual(result["status"], "ORDER_CLOSED_STATIC")
        self.assertTrue(result["closure"])


class PublicationTests(unittest.TestCase):
    def test_no_clobber_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            dispatch.write_no_clobber(path, b"{}\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(dispatch.DispatchError):
                dispatch.write_no_clobber(path, b"changed\n")


@unittest.skipUnless((dispatch.FIRMWARE_DIR / dispatch.XBL_NAME).exists(), "exact pinned XBL is not present")
class ExactImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = dispatch.Image(dispatch.load_xbl(dispatch.FIRMWARE_DIR))

    def test_exact_range_and_dependency_pins(self):
        dependency = dispatch.analyze_dependency(dispatch.DEPENDENCY_PATH)
        self.assertEqual(dependency["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(dependency["runtime_order"], "UNKNOWN")
        self.assertEqual(dependency["runtime_slot"], dispatch.fmt(dispatch.RUNTIME_SLOT))
        self.assertEqual(dependency["blr"]["target"], "UNKNOWN_UNTIL_RUNTIME_OBJECT_BINDING")
        self.assertEqual(dependency["base_currentness"], "UNKNOWN")
        table = dispatch.analyze_table_header(self.image)
        self.assertEqual(table["header"]["count"], 2)
        self.assertEqual(table["header"]["row_stride"], 0x18)
        self.assertEqual(table["rows"][0]["kind"], 2)

    def test_exact_local_dispatch_and_registration(self):
        table = dispatch.analyze_table_header(self.image)
        registration = dispatch.analyze_registration_helpers(self.image)
        initializer = dispatch.analyze_initializer_loop(self.image, table)
        dispatcher = dispatch.analyze_dispatcher(self.image, dispatch.analyze_pool(self.image))
        self.assertEqual(registration["ranges"]["function_enclosure_including_ret"]["end_exclusive"], "0x1482edac")
        self.assertIn("tail_node+0x10", registration["global_writes"][1]["target_semantics"])
        self.assertEqual(initializer["bootstrap_state"]["address"], "0x1488af58")
        self.assertEqual(dispatcher["pool"]["stride"], 0x3F8)
        self.assertEqual(dispatcher["initializer_call"]["target"], "0x14868418")
        self.assertEqual(dispatcher["local_data_edges"][0]["target"], "0x146b30c0 + X8*0x000003f8")

    def test_exact_census_is_bounded_and_does_not_claim_slot_writer_absence(self):
        scan = dispatch.decode_materialised_addresses(self.image)
        self.assertEqual(scan["arbitrary_write_absence"], "UNKNOWN")
        self.assertFalse(scan["writer_absence_claim"])
        classes = {row["target_class"] for row in scan["recognized_direct_accesses"]}
        self.assertIn("REGISTRATION_GLOBALS_0x14890f50_0x14890f68", classes)
        self.assertIn("FACTORY_OBJECT_0x1488f400_0x1488f440", classes)
        self.assertEqual([row for row in scan["recognized_direct_writes"] if row["target_class"] == "RUNTIME_SLOT_0x14890590"], [])

    def test_manifest_is_deterministic_and_order_open(self):
        first = dispatch.build_manifest()
        second = dispatch.build_manifest()
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(first["order_and_authority"]["taxonomy"], "ORDER_OPEN")
        self.assertEqual(first["slot_escape"]["taxonomy"], "PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION")


if __name__ == "__main__":
    unittest.main()
