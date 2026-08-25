from __future__ import annotations

import unittest

from tools import build_a90_inline_remapper_candidate as inline
from tools import build_a90_inline_shrm_candidate as shrm
from tests.test_build_a90_inline_remapper_candidate import FakeLegacy


class InlineShrmCandidateTests(unittest.TestCase):
    def test_snapshot_destination_binds_exact_mccc_source(self) -> None:
        self.assertEqual(shrm.SNAPSHOT_WORD_OFFSET, 0x56C)
        self.assertEqual(shrm.SNAPSHOT_WORD_PHYS, 0x0906566C)
        self.assertEqual(shrm.SOURCE_REGISTER_PHYS, 0x09250118)

    def test_read_profile_materializes_one_fixed_word(self) -> None:
        words = inline.build_inline_words(
            FakeLegacy(),
            inline.MODE_READ,
            fixed_phys=shrm.SNAPSHOT_WORD_PHYS,
            fixed_size=shrm.FIXED_SIZE,
        )
        self.assertEqual(words[11], inline.encode_movz_x(0, 0x566C))
        self.assertEqual(words[12], inline.encode_movk_x(0, 0x0906, 16))
        self.assertEqual(words[13], inline.encode_movz_x(1, 4))
        self.assertEqual(words.count(inline.encode_ldr_w_imm(20, 19, 0)), 1)

    def test_control_profile_has_no_load(self) -> None:
        words = inline.build_inline_words(
            FakeLegacy(),
            inline.MODE_CONTROL,
            fixed_phys=shrm.SNAPSHOT_WORD_PHYS,
            fixed_size=shrm.FIXED_SIZE,
        )
        self.assertNotIn(inline.encode_ldr_w_imm(20, 19, 0), words)
        self.assertEqual(words[19], inline.encode_movz_x(20, inline.CONTROL_SENTINEL))

    def test_hashes_are_pinned_and_cli_has_no_runtime_address(self) -> None:
        for hashes in shrm.EXPECTED_HASHES.values():
            self.assertRegex(hashes["candidate"], r"^[0-9a-f]{64}$")
            self.assertRegex(hashes["body"], r"^[0-9a-f]{64}$")
        parser = shrm.make_parser()
        options = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertNotIn("--address", options)
        self.assertNotIn("--mode", options)


if __name__ == "__main__":
    unittest.main()
