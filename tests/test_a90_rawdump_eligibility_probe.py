from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import a90_rawdump_eligibility_probe as probe
from tools.a90_acm_snapshot import Frame


def fake_frame(command: str, payload: bytes, *, rc: int = 0, status: str = "ok") -> Frame:
    fields = {"seq": "1", "cmd": command}
    end = {**fields, "rc": str(rc), "errno": "0", "status": status}
    return Frame(fields, end, payload, b"bounded transcript")


class AllowlistTests(unittest.TestCase):
    def test_exact_property_free_command_surface(self) -> None:
        self.assertEqual(probe.ALL_COMMANDS[0].argv, ("version",))
        self.assertEqual(
            [command.argv for command in probe.SURFACE_COMMANDS],
            [
                ("cat", "/proc/cmdline"),
                ("cat", "/sys/module/qcom_dload_mode/parameters/download_mode"),
                ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
                ("cat", "/sys/module/ramoops/parameters/max_reason"),
                ("cat", "/sys/module/kernel/parameters/panic"),
                ("cat", "/sys/module/kernel/parameters/panic_on_warn"),
            ],
        )
        flattened = " ".join(" ".join(command.argv) for command in probe.ALL_COMMANDS)
        self.assertNotIn("getprop", flattened)
        self.assertNotIn("adb", flattened)
        self.assertNotIn("run", [command.argv[0] for command in probe.ALL_COMMANDS])


class ParserTests(unittest.TestCase):
    def test_exact_version_binding(self) -> None:
        payload = (
            b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\n"
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        self.assertTrue(probe.validate_version(payload)["identity_exact"])
        with self.assertRaisesRegex(ValueError, "does not bind"):
            probe.validate_version(payload.replace(b"0.9.285", b"0.9.286"))

    def test_cmdline_selects_only_public_eligibility_keys(self) -> None:
        parsed = probe.parse_cmdline(
            b"console=tty0 androidboot.debug_level=0x494d "
            b"androidboot.force_upload=1 androidboot.serialno=SECRET "
            b"androidboot.fmm_lock=0 root=/dev/ram0\n"
        )
        self.assertEqual(
            parsed["selected"],
            {
                "androidboot.debug_level": "0x494d",
                "androidboot.force_upload": "1",
                "androidboot.fmm_lock": "0",
            },
        )
        self.assertNotIn("SECRET", json.dumps(parsed))

    def test_debug_level_known_values(self) -> None:
        self.assertEqual(probe.decode_debug_level("0x4f4c")["label"], "LOW")
        self.assertEqual(probe.decode_debug_level("18765")["label"], "MID")
        self.assertEqual(probe.decode_debug_level("0x4948")["label"], "HIGH")
        self.assertEqual(probe.decode_debug_level("garbage")["label"], "UNKNOWN")

    def test_duplicate_interesting_cmdline_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            probe.parse_cmdline(
                b"androidboot.force_upload=0 androidboot.force_upload=1\n"
            )


class EligibilityTests(unittest.TestCase):
    def parsed(self, debug: str | None, force: str | None) -> dict[str, object]:
        selected = {}
        if debug is not None:
            selected["androidboot.debug_level"] = debug
        if force is not None:
            selected["androidboot.force_upload"] = force
        return {"selected": selected}

    def test_positive_signals_still_leave_xbl_eligibility_unknown(self) -> None:
        result = probe.derive_eligibility(
            self.parsed("0x494d", "1"),
            {"qcom_download_mode": None, "msm_poweroff_download_mode": "1"},
        )
        self.assertEqual(
            result["classification"],
            "DUMP_ENTRY_SIGNALS_PRESENT_FMM_TOKEN_UNKNOWN",
        )
        self.assertEqual(result["actual_xbl_rawdump_eligibility"], "UNKNOWN")
        self.assertEqual(
            result["download_mode"]["source"],
            "/sys/module/msm_poweroff/parameters/download_mode",
        )

    def test_low_or_disabled_signal_is_incomplete(self) -> None:
        result = probe.derive_eligibility(
            self.parsed("0x4f4c", "1"), {"qcom_download_mode": "1"}
        )
        self.assertEqual(result["classification"], "DUMP_ENTRY_SIGNALS_INCOMPLETE")
        self.assertEqual(result["signals"]["debug_level"], "NEGATIVE")

    def test_absent_signal_is_partial_not_positive(self) -> None:
        result = probe.derive_eligibility(
            self.parsed("0x4948", None),
            {"qcom_download_mode": None, "msm_poweroff_download_mode": None},
        )
        self.assertEqual(result["classification"], "DUMP_ENTRY_SIGNALS_PARTIAL")


class CollectionTests(unittest.TestCase):
    def args(self, root: Path) -> argparse.Namespace:
        return argparse.Namespace(
            experiment_id="fixture-a90-eligibility",
            host="127.0.0.1",
            port=54321,
            timeout=1.0,
            output_root=str(root),
        )

    def responses(self) -> list[Frame]:
        version = (
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        return [
            fake_frame("version", version),
            fake_frame(
                "cat",
                b"androidboot.debug_level=0x494d androidboot.force_upload=1 "
                b"androidboot.serialno=NEVER_PUBLIC\n",
            ),
            fake_frame("cat", b"cat: missing\n", rc=-2, status="error"),
            fake_frame("cat", b"1\n"),
            fake_frame("cat", b"4\n"),
            fake_frame("cat", b"5\n"),
            fake_frame("cat", b"0\n"),
        ]

    def test_collection_is_no_clobber_and_public_output_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(probe, "exchange", side_effect=self.responses()) as call:
                raw_path, manifest_path, manifest = probe.collect(self.args(root))
            self.assertEqual(call.call_count, 7)
            self.assertEqual(raw_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o644)
            public_text = manifest_path.read_text()
            self.assertNotIn("NEVER_PUBLIC", public_text)
            self.assertEqual(
                manifest["classification"],
                "DUMP_ENTRY_SIGNALS_PRESENT_FMM_TOKEN_UNKNOWN",
            )
            with mock.patch.object(probe, "exchange", side_effect=self.responses()):
                with self.assertRaises(FileExistsError):
                    probe.collect(self.args(root))

    def test_wrong_version_stops_before_any_surface_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrong = fake_frame(
                "version",
                b"version: 0.9.286 build=other\n"
                b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n",
            )
            with mock.patch.object(probe, "exchange", return_value=wrong) as call:
                with self.assertRaisesRegex(ValueError, "does not bind"):
                    probe.collect(self.args(Path(temporary)))
            self.assertEqual(call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
