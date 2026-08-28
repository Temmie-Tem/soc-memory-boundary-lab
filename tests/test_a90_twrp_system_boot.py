from __future__ import annotations

import hashlib
import contextlib
import io
import subprocess
import unittest
from unittest import mock

from tools import a90_twrp_system_boot as boot


class TwrpSystemBootTests(unittest.TestCase):
    def test_run_text_uses_fixed_timeout_and_maps_timeout_to_boot_error(self) -> None:
        with mock.patch.object(
            boot.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(("adb", "devices"), 1.0),
        ) as run:
            with self.assertRaisesRegex(boot.BootError, "timed out"):
                boot.run_text(("adb", "devices"))
        self.assertEqual(run.call_args.kwargs["timeout"], boot.SUBPROCESS_TIMEOUT_SEC)

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

    def test_legacy_dispatch_is_disabled_before_runner(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_run(argv):
            calls.append(tuple(argv))
            raise AssertionError("legacy runner must not be called")

        with self.assertRaisesRegex(boot.BootError, "disabled"):
            boot.dispatch_system_boot("adb", "serial", fake_run)
        self.assertEqual(calls, [])

    def test_legacy_shell_rejects_mutation_before_runner(self) -> None:
        runner = mock.Mock()
        with self.assertRaisesRegex(boot.BootError, "mutation is disabled"):
            boot.adb_shell("adb", "serial", "twrp set tw_gui_done 1", runner)
        runner.assert_not_called()
        self.assertNotIn("dispatch_system_boot", boot.__all__)

    def test_legacy_main_is_disabled_before_selection_or_runner(self) -> None:
        with mock.patch.object(boot, "select_exact_recovery") as select, mock.patch.object(
            boot, "run_text"
        ) as run:
            with self.assertRaisesRegex(boot.BootError, "disabled"):
                boot.main([])
        select.assert_not_called()
        run.assert_not_called()

    def test_legacy_cli_has_no_caller_selected_transport_or_timeout(self) -> None:
        parser = boot.make_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            for option in ("--adb", "--disconnect-timeout"):
                with self.assertRaises(SystemExit):
                    parser.parse_args([option, "x"])


if __name__ == "__main__":
    unittest.main()
