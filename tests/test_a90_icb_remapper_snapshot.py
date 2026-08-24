from __future__ import annotations

import contextlib
import io
import unittest
from unittest import mock

from tools import a90_icb_remapper_snapshot as snapshot


class A90IcbRemapperSnapshotTests(unittest.TestCase):
    def test_default_commands_are_four_fixed_control_reads(self) -> None:
        commands = snapshot.read_commands(False)
        self.assertEqual(len(commands), 4)
        self.assertEqual(
            [command.argv[-2] for command in commands],
            ["0x09248080", "0x092c8080", "0x09348080", "0x093c8080"],
        )
        self.assertTrue(all(command.argv[-1] == "4" for command in commands))
        self.assertTrue(
            all(
                command.argv[3:5] == ("-f", snapshot.DEVICE_NODE)
                for command in commands
            )
        )
        self.assertTrue(all(len(command.argv) == 7 for command in commands))

    def test_full_commands_cover_only_proved_layout(self) -> None:
        commands = snapshot.read_commands(True)
        self.assertEqual(len(commands), 4 * 23)
        addresses = [int(command.argv[-2], 16) for command in commands]
        for base in snapshot.REGISTER_BASES:
            self.assertEqual(
                [value - base for value in addresses if base <= value <= base + 0x58],
                list(snapshot.FULL_OFFSETS),
            )

    def test_parse_u32_accepts_hex_and_rejects_extra_output(self) -> None:
        self.assertEqual(snapshot.parse_u32(b"0x000003f1\n"), 0x3F1)
        self.assertEqual(snapshot.parse_u32(b"ABCD\r\n"), 0xABCD)
        with self.assertRaisesRegex(ValueError, "not one 32-bit"):
            snapshot.parse_u32(b"0x1 0x2\n")
        with self.assertRaisesRegex(ValueError, "not one 32-bit"):
            snapshot.parse_u32(b"0x100000000\n")

    def test_cli_has_no_address_argument(self) -> None:
        parser = snapshot.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--experiment-id", "test", "--address", "0x0"])

    def test_error_frame_mode_is_available_to_collector(self) -> None:
        signature = mock.create_autospec(snapshot.exchange)
        signature(
            "127.0.0.1",
            54321,
            snapshot.Command("read", ("run",)),
            12.0,
            allow_error=True,
        )


if __name__ == "__main__":
    unittest.main()
