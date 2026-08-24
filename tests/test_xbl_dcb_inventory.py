from __future__ import annotations

import struct
import unittest

from tools import xbl_dcb_inventory as dcb


class XblDcbInventoryTests(unittest.TestCase):
    def test_parse_dcb(self) -> None:
        block = bytearray(dcb.DCB_SIZE)
        struct.pack_into("<III", block, 0, 0x12345678, 0x200, 0x00650000)
        struct.pack_into("<HH", block, 0x0C, 0x64, 4)
        block[0x64:0x68] = b"test"
        parsed = dcb.parse_dcb(bytes(block))
        self.assertEqual(parsed["dsf_version"], "0x00650000")
        self.assertEqual(parsed["sections"][0]["index"], 0)
        self.assertEqual(parsed["sections"][0]["size"], 4)

    def test_loader_maximum_is_enforced(self) -> None:
        block = bytearray(dcb.DCB_SIZE)
        struct.pack_into("<III", block, 0, 0, 0x1000, 0x00650000)
        struct.pack_into("<HH", block, 0x0C, 0x64, 0x77D)
        with self.assertRaisesRegex(ValueError, "loader maximum"):
            dcb.parse_dcb(bytes(block))

    def test_required_dsf_version_and_used_size_are_enforced(self) -> None:
        block = bytearray(dcb.DCB_SIZE)
        struct.pack_into("<III", block, 0, 0, 0x100, 0x00640000)
        with self.assertRaisesRegex(ValueError, "DSF version"):
            dcb.parse_dcb(bytes(block))

        struct.pack_into("<III", block, 0, 0, 0x100, 0x00650000)
        struct.pack_into("<HH", block, 0x0C, 0xF0, 0x20)
        with self.assertRaisesRegex(ValueError, "section 0 range"):
            dcb.parse_dcb(bytes(block))

    def test_parse_minimal_elf64_load(self) -> None:
        data = bytearray(0x200)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 54, 56)
        struct.pack_into("<H", data, 56, 1)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x100, 0x2000, 0x2000, 4, 4, 4)
        data[0x100:0x104] = b"code"
        segments = dcb.parse_elf64_load_segments(bytes(data))
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0].virtual_address, 0x2000)


if __name__ == "__main__":
    unittest.main()
