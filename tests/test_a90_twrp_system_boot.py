from __future__ import annotations

import hashlib
import unittest

from tools import a90_twrp_system_boot as boot


class TwrpSystemBootTests(unittest.TestCase):
    def test_device_parser_and_exact_hash_selection(self) -> None:
        serial = "a90-test-serial"
        expected_hash = hashlib.sha256(serial.encode()).hexdigest()
        calls: list[tuple[str, ...]] = []

        def fake_run(argv):
            call = tuple(argv)
            calls.append(call)
            if call == ("adb", "devices"):
                return (
                    "List of devices attached\n"
                    f"{serial}\trecovery\n"
                    "unrelated\tdevice\n"
                )
            if call[-1] == "getprop ro.product.model":
                return "SM-A908N\n"
            if call[-1] == "getprop ro.product.device":
                return "r3q\n"
            raise AssertionError(call)

        endpoint = boot.select_exact_recovery(
            "adb", fake_run, expected_serial_sha256=expected_hash
        )
        self.assertEqual(endpoint.serial_sha256, expected_hash)
        self.assertFalse(any("unrelated" in part for call in calls[1:] for part in call))

    def test_assignment_parser_is_strict(self) -> None:
        self.assertEqual(
            boot.parse_assignment("tw_reboot_arg = system\n", "tw_reboot_arg"),
            "system",
        )
        with self.assertRaisesRegex(boot.BootError, "expected one"):
            boot.parse_assignment("noise\n", "tw_reboot_arg")

    def test_dispatch_uses_gui_mainloop_exit_not_twrp_reboot(self) -> None:
        commands: list[str] = []

        def fake_run(argv):
            command = tuple(argv)[-1]
            commands.append(command)
            if command == "twrp --help 2>&1":
                return (
                    "TWRP openrecoveryscript command line tool, "
                    f"TWRP version {boot.TWRP_VERSION}\n"
                )
            if command == "twrp get tw_gui_done":
                return "tw_gui_done = 0\n"
            if command == "twrp get tw_reboot_arg":
                return "tw_reboot_arg = system\n"
            return ""

        boot.dispatch_system_boot("adb", "serial", fake_run)
        self.assertEqual(commands.count("sync; twrp set tw_gui_done 1"), 1)
        self.assertIn("twrp set tw_reboot_arg system", commands)
        self.assertNotIn("twrp reboot", commands)

    def test_nonzero_gui_done_fails_before_effect(self) -> None:
        commands: list[str] = []

        def fake_run(argv):
            command = tuple(argv)[-1]
            commands.append(command)
            if command == "twrp --help 2>&1":
                return (
                    "TWRP openrecoveryscript command line tool, "
                    f"TWRP version {boot.TWRP_VERSION}\n"
                )
            if command == "twrp get tw_gui_done":
                return "tw_gui_done = 1\n"
            raise AssertionError(command)

        with self.assertRaisesRegex(boot.BootError, "pre-effect"):
            boot.dispatch_system_boot("adb", "serial", fake_run)
        self.assertNotIn("sync; twrp set tw_gui_done 1", commands)


if __name__ == "__main__":
    unittest.main()
