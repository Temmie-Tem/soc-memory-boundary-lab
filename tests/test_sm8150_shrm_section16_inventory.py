from __future__ import annotations

import struct
import unittest

from tools import sm8150_shrm_section16_inventory as shrm


def record(bases: tuple[int, ...], offsets: tuple[int, ...]) -> bytes:
    return (
        struct.pack("<BB", len(bases), len(offsets))
        + struct.pack(f"<{len(bases)}H", *bases)
        + struct.pack(f"<{len(offsets)}H", *offsets)
    )


def synthetic_workspace() -> bytes:
    workspace = bytearray(0xF00)
    # list0: one four-channel record, then a zero terminator
    list0 = record((0x9250, 0x92D0, 0x9350, 0x93D0), (0x46, 0x47)) + b"\0\0"
    # list1: one master record, then a zero terminator
    list1 = record((0x90B0,), (0xA0, 0xA5)) + b"\0\0"
    struct.pack_into("<4H", workspace, 0, 8, len(list0) + 8, 8 + len(list0), 0x8E8)
    workspace[8 : 8 + len(list0)] = list0
    workspace[8 + len(list0) : 8 + len(list0) + len(list1)] = list1
    section_end = 8 + len(list0) + len(list1)
    # The exact selected format places destination 0 at header[1].
    struct.pack_into("<H", workspace, 2, section_end)
    return bytes(workspace[:section_end])


class Sm8150ShrmSection16Tests(unittest.TestCase):
    def test_exact_address_formula_and_read_direction(self) -> None:
        decoded = shrm.decode_section16_interpreter(synthetic_workspace())
        self.assertEqual(decoded["address_formula"], "(base_page << 12) + (offset_token << 2)")
        self.assertEqual(decoded["offset_token_scaling_bytes"], 4)
        self.assertTrue(decoded["direction_argument_zero_is_read"])
        self.assertEqual(decoded["write_callsite_count"], 0)
        first = decoded["sets"][0]
        self.assertEqual(first["register_word_count"], 8)
        self.assertEqual(
            first["register_addresses"][:2], ["0x09250118", "0x0925011c"]
        )
        second = decoded["sets"][1]
        self.assertEqual(second["register_addresses"], ["0x090b0280", "0x090b0294"])

    def test_list_boundaries_and_capacity_are_enforced(self) -> None:
        workspace = bytearray(synthetic_workspace())
        # Keep the list format valid but make the first destination too small.
        header = list(struct.unpack_from("<4H", workspace, 0))
        header[3] = header[1] + 4
        struct.pack_into("<4H", workspace, 0, *header)
        with self.assertRaisesRegex(ValueError, "destination capacity"):
            shrm.decode_section16_interpreter(bytes(workspace))

        workspace = bytearray(synthetic_workspace())
        # A record that crosses list1's boundary must be rejected.
        header = struct.unpack_from("<4H", workspace, 0)
        workspace[header[2] - 2 : header[2]] = b"\x01\x01"
        with self.assertRaisesRegex(ValueError, "list boundary"):
            shrm.decode_section16_interpreter(bytes(workspace))

    def test_nonzero_direction_is_defined_as_write_for_helper_model(self) -> None:
        workspace = synthetic_workspace()
        decoded = shrm._parse_list(
            workspace + bytes(0xF00 - len(workspace)),
            list_offset=8,
            list_end=struct.unpack_from("<4H", workspace, 0)[2],
            destination_offset=struct.unpack_from("<4H", workspace, 0)[1],
            capacity_bytes=0x6B8,
            direction=1,
        )
        self.assertEqual(decoded["direction_argument"], 1)
        self.assertIn("write SHRM snapshot buffer word", decoded["direction_semantics"])
