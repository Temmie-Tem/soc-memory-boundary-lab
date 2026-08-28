from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest import mock

from tools import a90_native_recovery_entry as entry
from tools import a90_twrp_system_boot as twrp
from tools.a90_acm_snapshot import Frame


VERSION = (
    b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\n"
    b"made by device owner\n"
    b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
    b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
)
CMDLINE = (
    b"skip_initramfs rootwait ro "
    b"androidboot.em.model=SM-A908N "
    b"androidboot.bootloader=A908NKSU5EWA3 "
    b"androidboot.debug_level=0x4f4c "
    b"androidboot.force_upload=0x0 "
    b"sec_debug.dump_sink=0x0\n"
)
SOC_ID = b"339\n"
BOOT_ID = b"7501ac1e-373b-46d9-b2ee-eec653c170c5\n"
PANIC = b"1\n"
SELFTEST = b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12\n"


def frame(command: str, payload: bytes = b"", evidence_id: str = "") -> Frame:
    del evidence_id
    begin = {"seq": "1", "cmd": command}
    end = {**begin, "rc": "0", "status": "ok"}
    return Frame(begin, end, payload, b"A90P1 frame")


def binding() -> dict[str, object]:
    return {
        "listener": {"host": entry.BRIDGE_HOST, "port": entry.BRIDGE_PORT},
        "serial_device": "/dev/ttyACM0",
        "serial_identity": "/dev/serial/by-id/usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00",
        "serial_realpath": "/dev/ttyACM0",
        "process_pid": 123,
        "process_argv": ["serial_tcp_bridge.py", "--host", entry.BRIDGE_HOST],
        "validated_utc": "2026-08-27T00:00:00+00:00",
    }


def recovery_receipt() -> dict[str, object]:
    return {
        "a90p1_begin_observed": True,
        "recovery_marker_observed": True,
        "socket_disconnect_observed": True,
        "begin": {"seq": "7", "cmd": "recovery", "argc": "1", "flags": "0x14"},
        "transcript_sha256": "a" * 64,
        "transcript_size": 120,
    }


class Endpoint:
    def __init__(self, serial: str = "A90-RECOVERY") -> None:
        self.serial = serial
        self.state = "recovery"

    @property
    def serial_sha256(self) -> str:
        return hashlib.sha256(self.serial.encode()).hexdigest()


class RecoveryEntryTests(unittest.TestCase):
    def tearDown(self) -> None:
        entry.REPO_ROOT = Path(entry.__file__).resolve().parents[1]

    def args(self, root: Path, *, execute: bool = True, phase: str = "control") -> argparse.Namespace:
        entry.REPO_ROOT = root
        return argparse.Namespace(
            experiment_id="verification-024-entry-test",
            phase=phase,
            execute=execute,
        )

    def fake_exchange(self, calls: list[tuple[str, tuple[str, ...]]]):
        payloads = {
            "version_before": VERSION,
            "cmdline_before": CMDLINE,
            "soc_id_before": SOC_ID,
            "boot_id_before": BOOT_ID,
            "panic_on_oops_before": PANIC,
            "selftest_before": SELFTEST,
            "boot_id_claim": BOOT_ID,
        }

        def exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout, kwargs
            calls.append((command.evidence_id, tuple(command.argv)))
            if command.evidence_id == "stophud":
                return frame("stophud")
            return frame(command.argv[0], payloads[command.evidence_id])

        return exchange

    def run_success(self, root: Path, *, exchange=None):
        calls: list[tuple[str, tuple[str, ...]]] = []
        exchange = exchange or self.fake_exchange(calls)
        endpoint = Endpoint()
        # Make the fixture's serial hash equal the immutable Recovery pin.
        endpoint.serial = "serial"
        recovery = {
            "state": "recovery",
            "model": entry.RECOVERY_TARGET_MODEL,
            "device": entry.RECOVERY_TARGET_DEVICE,
            "twrp_version": entry.TWRP_VERSION,
            "serial_sha256": entry.TARGET_SERIAL_SHA256,
            "twrp_help_sha256": "b" * 64,
            "twrp_help_size": 90,
            "other_endpoints_untouched": True,
        }
        args = self.args(root)

        def stophud(host, port, timeout, exchange_fn, *, frame_records=None, persist=None):
            del host, port, timeout
            journal_paths = list((root / "evidence" / "private").glob("*.journal.json"))
            self.assertEqual(len(journal_paths), 1)
            calls.append(("stophud-helper", ("stophud",)))
            exchange_fn(
                entry.BRIDGE_HOST,
                entry.BRIDGE_PORT,
                entry.Command("stophud", ("stophud",)),
                1.0,
                allow_error=True,
            )
            if frame_records is not None:
                frame_records.append({"evidence_id": "stophud"})
            if persist is not None:
                persist([])
            return {"accepted": True, "busy_retries": 0}

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(entry, "REPO_ROOT", root))
            stack.enter_context(mock.patch.object(entry, "validate_bridge_binding", side_effect=[binding(), binding(), binding(), binding()]))
            stack.enter_context(mock.patch.object(entry, "run_stophud", side_effect=stophud))
            stack.enter_context(mock.patch.object(entry, "exchange", side_effect=exchange))
            stack.enter_context(mock.patch.object(entry, "_dispatch_recovery_once", return_value=recovery_receipt()))
            stack.enter_context(mock.patch.object(entry, "wait_for_exact_recovery", return_value=(endpoint, recovery)))
            paths = entry.collect(args)
        return paths, calls

    def test_import_is_contact_free_and_cli_is_fixed(self) -> None:
        parser = entry.build_parser()
        parsed = parser.parse_args(["--experiment-id", "x", "--phase", "read", "--execute"])
        self.assertEqual(parsed.phase, "read")
        self.assertTrue(parsed.execute)
        with self.assertRaises(SystemExit):
            parser.parse_args(["--experiment-id", "x", "--phase", "read", "--host", "1.2.3.4"])
        with mock.patch.object(entry, "validate_bridge_binding") as validate, mock.patch.object(
            entry, "exchange"
        ) as exchange:
            module = __import__("importlib").import_module("tools.a90_native_recovery_entry")
            self.assertIs(module, entry)
            validate.assert_not_called()
            exchange.assert_not_called()

    def test_missing_execute_refuses_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(entry, "validate_bridge_binding") as validate, mock.patch.object(
                entry, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(entry.RecoveryEntryError, "explicit --execute"):
                    entry.collect(self.args(Path(directory), execute=False))
            validate.assert_not_called()
            exchange.assert_not_called()

    def test_injected_output_root_is_refused_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root)
            args.output_root = root / "redirected"
            with mock.patch.object(entry, "validate_bridge_binding") as validate, mock.patch.object(
                entry, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(entry.RecoveryEntryError, "output_root"):
                    entry.collect(args)
            validate.assert_not_called()
            exchange.assert_not_called()

    def test_injected_nonfixed_adb_is_refused_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root)
            args.adb = "adb"
            with mock.patch.object(entry, "validate_bridge_binding") as validate, mock.patch.object(
                entry, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(entry.RecoveryEntryError, "fixed adb"):
                    entry.collect(args)
            validate.assert_not_called()
            exchange.assert_not_called()

    def test_stale_journal_refuses_before_bridge_or_device_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "evidence" / "private"
            private.mkdir(parents=True)
            journal = private / "verification-024-entry-test.journal.json"
            journal.write_text("stale\n", encoding="utf-8")
            with mock.patch.object(entry, "validate_bridge_binding") as validate, mock.patch.object(
                entry, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(entry.RecoveryEntryError, "replay forbidden"):
                    entry.collect(self.args(root))
            validate.assert_not_called()
            exchange.assert_not_called()

    def test_stophud_is_first_device_command_and_target_gate_failure_dispatches_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls: list[tuple[str, tuple[str, ...]]] = []
            exchange = self.fake_exchange(calls)

            def bad_exchange(host, port, command, timeout, **kwargs):
                if command.evidence_id == "version_before":
                    return frame("version", VERSION.replace(b"0.9.285", b"0.9.286", 1))
                return exchange(host, port, command, timeout, **kwargs)

            def stophud(host, port, timeout, exchange_fn, *, frame_records=None, persist=None):
                del host, port, timeout, frame_records
                calls.append(("stophud-helper", ("stophud",)))
                exchange_fn(entry.BRIDGE_HOST, entry.BRIDGE_PORT, entry.Command("stophud", ("stophud",)), 1.0, allow_error=True)
                if persist is not None:
                    persist([])
                return {"accepted": True, "busy_retries": 0}

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(entry, "validate_bridge_binding", side_effect=[binding(), binding(), binding()]))
                stack.enter_context(mock.patch.object(entry, "run_stophud", side_effect=stophud))
                stack.enter_context(mock.patch.object(entry, "exchange", side_effect=bad_exchange))
                dispatch = stack.enter_context(mock.patch.object(entry, "_dispatch_recovery_once"))
                with self.assertRaisesRegex(entry.RecoveryEntryError, "target gate"):
                    entry.collect(self.args(root))
            dispatch.assert_not_called()
            self.assertEqual(calls[0][0], "stophud-helper")
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertFalse(record["effect_dispatched"])
            self.assertEqual(record["effect_dispatch_count"], 0)

    def test_exact_one_dispatch_marker_and_recovery_success_is_redacted_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, calls = self.run_success(root)
            journal_path, manifest_path = paths
            self.assertEqual(calls[0][0], "stophud-helper")
            self.assertEqual(journal_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o644)
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(journal["status"], entry.SUCCESS_STATUS)
            self.assertEqual(journal["phase"], "control")
            self.assertEqual(journal["effect_dispatch_count"], 1)
            self.assertTrue(journal["effect_dispatched"])
            self.assertFalse(journal["effect_replayed"])
            self.assertTrue(journal["physical_effect_claim"]["claimed"])
            self.assertEqual(
                journal["physical_effect_claim"]["boot_id"],
                BOOT_ID.decode().strip(),
            )
            self.assertEqual(manifest["status"], entry.SUCCESS_STATUS)
            self.assertEqual(manifest["phase"], "control")
            self.assertEqual(manifest["effect"]["dispatch_count"], 1)
            self.assertFalse(manifest["partition_writes"])
            rendered = manifest_path.read_text(encoding="utf-8")
            self.assertNotIn("cmdline_base64", rendered)
            self.assertNotIn("A90-RECOVERY", rendered)
            self.assertNotIn("serial\"", rendered)
            self.assertTrue(manifest["raw_cmdline_omitted"])
            self.assertTrue(manifest["raw_transcript_omitted"])

    def test_dispatch_wire_and_exact_begin_marker_without_end(self) -> None:
        class SocketFixture:
            def __init__(self, chunks):
                self.chunks = iter(chunks)
                self.sent: list[bytes] = []

            def settimeout(self, value):
                self.timeout = value

            def sendall(self, value):
                self.sent.append(value)

            def recv(self, _size):
                return next(self.chunks)

            def close(self):
                pass

        transcript = (
            b"\r\na90:/# cmdv1 recovery\r\n"
            b"A90P1 BEGIN seq=7 cmd=recovery argc=1 flags=0x14\r\n"
            b"recovery: syncing and rebooting to recovery\r\n"
        )
        sock = SocketFixture([transcript, b""])
        result = entry._dispatch_recovery_once(
            socket_factory=lambda *_args, **_kwargs: sock,
            clock=iter([0.0, 0.0, 0.0, 1.0]).__next__,
            timeout=2.0,
            capability=entry._TRANSACTION_CAPABILITY,
        )
        self.assertEqual(sock.sent, [entry.RECOVERY_WIRE])
        self.assertTrue(result["a90p1_begin_observed"])
        self.assertTrue(result["recovery_marker_observed"])
        self.assertNotIn("end", result)

    def test_direct_recovery_dispatch_bypasses_refuse_before_socket(self) -> None:
        with mock.patch.object(entry.socket, "create_connection") as connect:
            with self.assertRaises(entry.RecoveryDispatchError):
                entry.dispatch_recovery_once()
            with self.assertRaises(entry.RecoveryDispatchError):
                entry.dispatch_once()
            with self.assertRaises(entry.RecoveryDispatchError):
                entry._socket_dispatch(entry.BRIDGE_HOST, entry.BRIDGE_PORT, 1.0)
        connect.assert_not_called()
        self.assertNotIn("dispatch_once", entry.__all__)
        self.assertNotIn("dispatch_recovery_once", entry.__all__)

    def test_timeout_before_marker_is_ambiguous_and_never_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls: list[tuple[str, tuple[str, ...]]] = []
            endpoint_observer = mock.patch.object(entry, "wait_for_exact_recovery")
            timeout = entry.RecoveryDispatchError(
                "timeout before marker", transcript=b"A90P1 BEGIN seq=1 cmd=recovery argc=1 flags=0x14\n", disconnected=True
            )
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(entry, "validate_bridge_binding", side_effect=[binding(), binding(), binding()]))
                stack.enter_context(mock.patch.object(entry, "run_stophud", side_effect=lambda *args, **kwargs: {"accepted": True, "busy_retries": 0}))
                stack.enter_context(mock.patch.object(entry, "exchange", side_effect=self.fake_exchange(calls)))
                dispatch = stack.enter_context(mock.patch.object(entry, "_dispatch_recovery_once", side_effect=timeout))
                observer = stack.enter_context(endpoint_observer)
                with self.assertRaisesRegex(entry.RecoveryEntryError, "ambiguous"):
                    entry.collect(self.args(root, phase="read"))
            dispatch.assert_called_once()
            observer.assert_not_called()
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], entry.RECONCILIATION_STATUS)
            self.assertEqual(record["effect_dispatch_count"], 1)
            self.assertTrue(record["effect_dispatched"])

    def test_recovery_observation_failure_keeps_dispatch_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(entry, "validate_bridge_binding", side_effect=[binding(), binding(), binding()]))
                stack.enter_context(mock.patch.object(entry, "run_stophud", return_value={"accepted": True, "busy_retries": 0}))
                stack.enter_context(mock.patch.object(entry, "exchange", side_effect=self.fake_exchange([])))
                stack.enter_context(mock.patch.object(entry, "_dispatch_recovery_once", return_value=recovery_receipt()))
                observer = stack.enter_context(mock.patch.object(entry, "wait_for_exact_recovery", side_effect=entry.RecoveryObservationError("not observed")))
                with self.assertRaisesRegex(entry.RecoveryEntryError, "reconciliation"):
                    entry.collect(self.args(root, phase="rollback"))
            observer.assert_called_once()
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], entry.RECONCILIATION_STATUS)
            self.assertEqual(record["effect_dispatch_count"], 1)

    def test_wait_for_recovery_is_finite_and_unmatched_endpoint_is_not_probed(self) -> None:
        serial = "exact-recovery"
        expected_hash = hashlib.sha256(serial.encode()).hexdigest()
        calls: list[tuple[str, ...]] = []
        help_text = f"TWRP openrecoveryscript command line tool, TWRP version {entry.TWRP_VERSION}\n"

        def run(argv):
            call = tuple(argv)
            calls.append(call)
            if call == (entry.ADB, "devices"):
                return "List of devices attached\nexact-recovery\trecovery\nforeign\trecovery\n"
            if call[-1] == "getprop ro.product.model":
                self.assertEqual(call[2], serial)
                return "SM-A908N\n"
            if call[-1] == "getprop ro.product.device":
                self.assertEqual(call[2], serial)
                return "r3q\n"
            if call[-1] == "twrp --help 2>&1":
                return help_text
            raise AssertionError(call)

        def selector(adb, *, run):
            return twrp.select_exact_recovery(adb, run=run, expected_serial_sha256=expected_hash)

        with mock.patch.object(entry, "TARGET_SERIAL_SHA256", expected_hash):
            endpoint, identity = entry.wait_for_exact_recovery(
                timeout=1.0,
                poll_interval=0.1,
                select_fn=selector,
                run=run,
                clock=iter([0.0, 0.0, 0.0, 0.5]).__next__,
                sleep_fn=lambda _delay: None,
            )
        self.assertEqual(endpoint.serial, serial)
        self.assertEqual(identity["twrp_version"], entry.TWRP_VERSION)
        self.assertFalse(any(call[2] == "foreign" for call in calls if len(call) > 2))

        def never(_adb, *, run):
            raise twrp.BootError("no recovery")

        count = 0

        def counting(*args, **kwargs):
            nonlocal count
            count += 1
            return never(*args, **kwargs)

        with self.assertRaises(entry.RecoveryObservationError):
            entry.wait_for_exact_recovery(
                timeout=1.0,
                poll_interval=0.01,
                select_fn=counting,
                run=run,
                clock=lambda: 0.0,
                sleep_fn=lambda _delay: None,
            )
        self.assertEqual(count, entry.MAX_RECOVERY_POLL_ATTEMPTS)

    def test_transcript_validation_rejects_wrong_marker_or_end(self) -> None:
        begin = b"A90P1 BEGIN seq=1 cmd=recovery argc=1 flags=0x14\r\n"
        with self.assertRaises(entry.RecoveryDispatchError):
            entry.validate_recovery_transcript(begin)
        with self.assertRaises(entry.RecoveryDispatchError):
            entry.validate_recovery_transcript(
                begin + entry.RECOVERY_MARKER + b"\r\nA90P1 END seq=1 cmd=recovery rc=0 status=ok\r\n"
            )
        with self.assertRaises(entry.RecoveryDispatchError):
            entry.validate_recovery_transcript(
                begin + entry.RECOVERY_MARKER + b"\r\nA90P1 END\r\n"
            )

    def test_transcript_validation_rejects_numeric_flag_alias(self) -> None:
        transcript = (
            b"A90P1 BEGIN seq=1 cmd=recovery argc=1 flags=20\r\n"
            + entry.RECOVERY_MARKER
            + b"\r\n"
        )
        with self.assertRaises(entry.RecoveryDispatchError):
            entry.validate_recovery_transcript(transcript)

    def test_transcript_validation_rejects_adversarial_argc_flags_and_duplicate_begin(self) -> None:
        marker = entry.RECOVERY_MARKER + b"\r\n"
        begin = b"A90P1 BEGIN seq=1 cmd=recovery argc=1 flags=0x14\r\n"
        for bad in (
            begin.replace(b"argc=1", b"argc=99") + marker,
            begin.replace(b"flags=0x14", b"flags=0x5") + marker,
            begin + marker + begin,
            begin
            + marker
            + b"A90P1 END seq=1 cmd=recovery rc=1 status=error\r\n",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(entry.RecoveryDispatchError):
                    entry.validate_recovery_transcript(bad)

    def test_stophud_busy_retry_rebind_drift_sends_no_second_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls: list[str] = []
            initial = binding()
            drifted = {**initial, "process_pid": 999}
            busy = Frame(
                {"seq": "1", "cmd": "stophud"},
                {"seq": "1", "cmd": "stophud", "rc": "-16", "status": "busy"},
                b"",
                b"A90P1 busy",
            )

            def fake_exchange(host, port, command, timeout, **kwargs):
                del host, port, timeout, kwargs
                calls.append(command.evidence_id)
                if command.evidence_id == "stophud":
                    return busy
                raise AssertionError(command.evidence_id)

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(entry, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        entry,
                        "validate_bridge_binding",
                        side_effect=[initial, initial, drifted],
                    )
                )
                stack.enter_context(mock.patch.object(entry, "exchange", side_effect=fake_exchange))
                with self.assertRaisesRegex(entry.RecoveryEntryError, "target gate"):
                    entry.collect(self.args(root))
            self.assertEqual(calls, ["stophud"])
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], entry.REFUSED_STATUS)
            self.assertEqual(record["effect_dispatch_count"], 0)
            self.assertEqual(record["stophud_attempts"][-1]["attempt"], 2)
            self.assertIn("transport_error_type", record["stophud_attempts"][-1])


if __name__ == "__main__":
    unittest.main()
