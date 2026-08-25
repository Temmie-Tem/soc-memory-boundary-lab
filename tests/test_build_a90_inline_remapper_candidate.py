from __future__ import annotations

import unittest
from types import SimpleNamespace

from tools import build_a90_inline_remapper_candidate as candidate


class FakeStage:
    U32_EOR_PROLOGUE = 0xCA1103D0
    U32_EOR_EPILOGUE = 0xCA11021E
    U32_RET = 0xD65F03C0
    U32_NOP = 0xD503201F

    @staticmethod
    def kernel_vaddr(offset: int) -> int:
        return 0xFFFFFF800807FFEC + offset

    @staticmethod
    def encode_bl(site: int, target: int) -> int:
        delta = target - site
        return 0x94000000 | ((delta // 4) & 0x03FFFFFF)

    @staticmethod
    def put_u32(value: int) -> bytes:
        return value.to_bytes(4, "little")


class FakeLegacy:
    stage_c = FakeStage()

    @staticmethod
    def encode_stp_pre_x(rt: int, rt2: int, rn: int, imm: int) -> int:
        return 0xA9800000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt

    @staticmethod
    def encode_str_x_imm(rt: int, rn: int, imm: int) -> int:
        return 0xF9000000 | ((imm // 8) << 10) | (rn << 5) | rt

    @staticmethod
    def encode_ldr_literal_x(rt: int, site: int, target: int) -> int:
        return 0x58000000 | ((((target - site) // 4) & 0x7FFFF) << 5) | rt

    @staticmethod
    def encode_ldr_x_imm(rt: int, rn: int, imm: int) -> int:
        return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt

    @staticmethod
    def encode_b_cond_index(site: int, target: int, cond: int) -> int:
        return 0x54000000 | (((target - site) & 0x7FFFF) << 5) | cond

    @staticmethod
    def encode_ldrb_w_imm(rt: int, rn: int, imm: int) -> int:
        return 0x39400000 | (imm << 10) | (rn << 5) | rt

    @staticmethod
    def encode_cmp_w_imm(rn: int, imm: int) -> int:
        return 0x7100001F | (imm << 10) | (rn << 5)

    @staticmethod
    def encode_mov_x(rd: int, rn: int) -> int:
        return 0xAA0003E0 | (rn << 16) | rd

    @staticmethod
    def encode_b_index(site: int, target: int) -> int:
        return 0x14000000 | ((target - site) & 0x03FFFFFF)

    @staticmethod
    def encode_adr(rd: int, site: int, target: int) -> int:
        delta = target - site
        imm = delta & 0x1FFFFF
        return 0x10000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd

    @staticmethod
    def encode_ldp_x_imm(rt: int, rt2: int, rn: int, imm: int) -> int:
        return 0xA9400000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt

    @staticmethod
    def encode_ldp_post_x(rt: int, rt2: int, rn: int, imm: int) -> int:
        return 0xA8C00000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


class InlineCandidateTests(unittest.TestCase):
    def test_payload_is_fixed_size_and_contains_one_mmio_load(self) -> None:
        legacy = FakeLegacy()
        words = candidate.build_inline_words(legacy, candidate.MODE_READ)
        payload = candidate.build_inline_payload(legacy, candidate.MODE_READ)
        self.assertEqual(len(payload), candidate.PATCH_ROOM)
        self.assertEqual(words[19], candidate.encode_ldr_w_imm(20, 19, 0))
        self.assertEqual(words.count(candidate.encode_ldr_w_imm(20, 19, 0)), 1)
        self.assertNotIn(0xD63F0000, words)  # blr x0; no generic indirect call

    def test_fixed_physical_address_and_protection_are_materialized(self) -> None:
        words = candidate.build_inline_words(FakeLegacy(), candidate.MODE_READ)
        self.assertEqual(words[11], candidate.encode_movz_x(0, 0x8080))
        self.assertEqual(words[12], candidate.encode_movk_x(0, 0x0924, 16))
        self.assertEqual(words[13], candidate.encode_movz_x(1, 0x5C))
        self.assertEqual(words[14], candidate.encode_movz_x(2, 0x0707))
        self.assertEqual(words[15], candidate.encode_movk_x(2, 0x0068, 48))

    def test_alternate_fixed_profile_is_materialized_without_runtime_input(self) -> None:
        words = candidate.build_inline_words(
            FakeLegacy(),
            candidate.MODE_READ,
            fixed_phys=0x09065100,
            fixed_size=0xF00,
        )
        self.assertEqual(words[11], candidate.encode_movz_x(0, 0x5100))
        self.assertEqual(words[12], candidate.encode_movk_x(0, 0x0906, 16))
        self.assertEqual(words[13], candidate.encode_movz_x(1, 0xF00))

    def test_fixed_sequence_unmaps_before_printing(self) -> None:
        words = candidate.build_inline_words(FakeLegacy(), candidate.MODE_READ)
        self.assertEqual(words[22], 0xD5033D9F)
        self.assertEqual(words[23], FakeLegacy.encode_mov_x(0, 19))
        self.assertEqual(words[25], candidate.encode_mov_w(1, 20))
        self.assertEqual(words[26], FakeLegacy.encode_b_index(26, 28))
        self.assertEqual(len(words), 35)

    def test_control_has_map_unmap_but_no_mmio_load(self) -> None:
        words = candidate.build_inline_words(FakeLegacy(), candidate.MODE_CONTROL)
        self.assertEqual(words[19], candidate.encode_movz_x(20, candidate.CONTROL_SENTINEL))
        self.assertNotIn(candidate.encode_ldr_w_imm(20, 19, 0), words)
        self.assertEqual(words[23], FakeLegacy.encode_mov_x(0, 19))

    def test_builder_cli_has_no_address_or_call_target(self) -> None:
        parser = candidate.make_parser()
        option_strings = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertNotIn("--address", option_strings)
        self.assertNotIn("--call-target", option_strings)

    def test_both_candidate_and_body_hashes_are_pinned(self) -> None:
        self.assertEqual(set(candidate.EXPECTED_HASHES), set(candidate.MODES))
        for hashes in candidate.EXPECTED_HASHES.values():
            self.assertRegex(hashes["candidate"], r"^[0-9a-f]{64}$")
            self.assertRegex(hashes["body"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
