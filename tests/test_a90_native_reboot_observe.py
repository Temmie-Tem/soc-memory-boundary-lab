from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from tools import a90_native_reboot_observe as reboot


class FakeFrame:
    def __init__(self, payload: bytes, command: str, *, rc: int = 0, status: str = "ok"):
        self.payload = payload
        self.transcript = b"A90P1 " + payload
        self.begin = {"cmd": command, "seq": "1"}
        self.end = {
            "cmd": command,
            "seq": "1",
            "rc": str(rc),
            "status": status,
        }


OLD_BOOT = "00000000-0000-0000-0000-000000000001"
NEW_BOOT = "00000000-0000-0000-0000-000000000002"
VERSION = b"A90 Linux init 0.9.285\n"


class A90NativeRebootObserveTests(unittest.TestCase):
    def test_cmd_no_done_transcript_requires_both_markers(self) -> None:
        transcript = (
            b"a90:/# cmdv1 reboot\r\n"
            b"A90P1 BEGIN seq=9 cmd=reboot argc=1 flags=0x14\r\n"
            b"reboot: syncing and restarting\r\n"
        )
        parsed = reboot.validate_reboot_transcript(transcript)
        self.assertTrue(parsed["a90p1_begin_observed"])
        self.assertTrue(parsed["reboot_marker_observed"])
        with self.assertRaises(ValueError):
            reboot.validate_reboot_transcript(b"reboot: syncing and restarting")

    def test_cmd_no_done_receipt_rejects_conflicting_fields_duplicates_and_end(self) -> None:
        begin = b"A90P1 BEGIN seq=9 cmd=reboot argc=1 flags=0x14\r\n"
        marker = b"reboot: syncing and restarting\r\n"
        for bad in (
            begin.replace(b"argc=1", b"argc=99") + marker,
            begin.replace(b"flags=0x14", b"flags=0x5") + marker,
            begin + marker + begin,
            begin + marker + b"A90P1 END seq=9 cmd=reboot rc=1 status=error\r\n",
            begin + marker + b"A90P1 END\r\n",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    reboot.validate_reboot_transcript(bad)

    def test_boot_id_parser_requires_exact_uuid_shape(self) -> None:
        malformed = b"1234567-12345-1234-1234-1234567890ab\n"
        with self.assertRaises(reboot.AvailabilityFrameError):
            reboot._parse_boot_id(malformed, "boot_id")

    def test_reboot_parser_has_no_output_root_selector(self) -> None:
        parser = reboot.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "--experiment-id",
                        "x",
                        "--expect-debug-after",
                        "mid",
                        "--output-root",
                        "x",
                    ]
                )

    def test_private_reboot_wire_requires_transaction_capability(self) -> None:
        with mock.patch.object(reboot.socket, "create_connection") as connect:
            with self.assertRaisesRegex(RuntimeError, "durable collector"):
                reboot._dispatch_reboot_wire("127.0.0.1", 54321, 1.0)
        connect.assert_not_called()

    def test_initial_journal_claim_race_has_one_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence" / "private" / "same.journal.json"
            gate = threading.Barrier(2)
            results: list[str] = []

            def owner(label: str) -> None:
                gate.wait()
                try:
                    reboot._create_initial_json(path, {"owner": label})
                except FileExistsError:
                    results.append("lost")
                else:
                    results.append("won")

            threads = [threading.Thread(target=owner, args=(label,)) for label in ("a", "b")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(results), ["lost", "won"])
            self.assertTrue(path.exists())

    def test_reboot_effect_claim_excludes_debug_profile_and_experiment_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity, key = reboot._reboot_effect_identity(OLD_BOOT)
            claim_path = reboot._reboot_effect_claim_path(root, key)
            first = reboot._create_reboot_effect_claim(
                claim_path,
                identity=identity,
                key_sha256=key,
                experiment_id="low-owner",
            )
            self.assertTrue(first)
            self.assertNotIn("expect_debug_after", identity)
            with self.assertRaisesRegex(ValueError, "replay forbidden"):
                reboot._create_reboot_effect_claim(
                    claim_path,
                    identity=identity,
                    key_sha256=key,
                    experiment_id="mid-owner",
                )

    def test_debug_expectations_are_fixed(self) -> None:
        self.assertEqual(reboot.DEBUG_CMDLINE, {"low": "0x4f4c", "mid": "0x494d"})
        parser = reboot.build_parser()
        parsed = parser.parse_args(
            [
                "--experiment-id",
                "test",
                "--expect-debug-after",
                "mid",
                "--execute",
            ]
        )
        self.assertTrue(parsed.execute)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    ["--experiment-id", "test", "--expect-debug-after", "high"]
                )

    def test_postboot_stophud_waits_for_new_boot_id_and_reobserves(self) -> None:
        calls: list[str] = []
        polls = iter((OLD_BOOT, NEW_BOOT))
        stop_results = iter(((-16, "busy"), (-16, "busy"), (0, "ok")))

        def fake_exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout
            calls.append(command.evidence_id)
            if command.evidence_id == "version_after":
                return FakeFrame(VERSION, "version")
            if command.evidence_id == "boot_id_after":
                return FakeFrame((next(polls) + "\n").encode(), "cat")
            if command.evidence_id == "stophud":
                rc, status = next(stop_results)
                return FakeFrame(b"", "stophud", rc=rc, status=status)
            if command.evidence_id == "version_after_stophud":
                return FakeFrame(VERSION, "version")
            if command.evidence_id == "boot_id_after_stophud":
                return FakeFrame((NEW_BOOT + "\n").encode(), "cat")
            raise AssertionError(command.evidence_id)

        with mock.patch.object(reboot, "exchange", side_effect=fake_exchange):
            with mock.patch.object(reboot.time, "sleep", return_value=None):
                with mock.patch.object(
                    reboot, "validate_bridge_binding", return_value={"pid": 1}
                ) as validate:
                    frames: list[dict[str, object]] = []
                    result = reboot.wait_for_new_boot(
                        "127.0.0.1", 54321, OLD_BOOT, 1.0, 0.01, stophud_frames=frames
                    )
        self.assertEqual(validate.call_count, 3)
        self.assertEqual(result["candidate_boot_id"], NEW_BOOT)
        self.assertEqual(result["boot_id"], NEW_BOOT)
        self.assertEqual(calls.count("stophud"), 3)
        self.assertEqual(calls[:2], ["version_after", "boot_id_after"])
        self.assertEqual(calls[-2:], ["version_after_stophud", "boot_id_after_stophud"])
        self.assertEqual(len(frames), 3)

    def test_postboot_stophud_transport_is_incomplete_without_retry(self) -> None:
        calls: list[str] = []

        def fake_exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout, kwargs
            calls.append(command.evidence_id)
            if command.evidence_id == "version_after":
                return FakeFrame(VERSION, "version")
            if command.evidence_id == "boot_id_after":
                return FakeFrame((NEW_BOOT + "\n").encode(), "cat")
            if command.evidence_id == "stophud":
                raise TimeoutError("bridge disconnect")
            raise AssertionError(command.evidence_id)

        with mock.patch.object(reboot, "exchange", side_effect=fake_exchange):
            with mock.patch.object(
                reboot, "validate_bridge_binding", return_value={"pid": 1}
            ) as validate:
                with self.assertRaisesRegex(TimeoutError, "incomplete"):
                    reboot.wait_for_new_boot("127.0.0.1", 54321, OLD_BOOT, 1.0, 0.01)
        self.assertEqual(validate.call_count, 1)
        self.assertEqual(calls.count("stophud"), 1)
        self.assertNotIn("version_after_stophud", calls)

    def test_stophud_busy_retry_rebind_drift_sends_no_second_attempt(self) -> None:
        calls: list[str] = []

        def fake_exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout, kwargs
            calls.append(command.evidence_id)
            if command.evidence_id == "version_after":
                return FakeFrame(b"", "version", rc=-16, status="busy")
            if command.evidence_id == "stophud":
                return FakeFrame(b"", "stophud", rc=-16, status="busy")
            raise AssertionError(command.evidence_id)

        with mock.patch.object(reboot, "exchange", side_effect=fake_exchange):
            with mock.patch.object(
                reboot,
                "validate_bridge_binding",
                side_effect=[{"pid": 1}, {"pid": 2}],
            ) as validate:
                with self.assertRaisesRegex(TimeoutError, "arbitration incomplete"):
                    reboot.wait_for_new_boot(
                        "127.0.0.1",
                        54321,
                        OLD_BOOT,
                        1.0,
                        0.01,
                    )
        self.assertEqual(calls, ["version_after", "stophud"])
        self.assertEqual(validate.call_count, 2)

    def test_availability_busy_is_arbitrated_then_converges_on_new_boot(self) -> None:
        calls: list[tuple[str, bool]] = []
        state = {
            "version_busy": True,
            "boot_busy": True,
            "boot_id": 0,
        }

        def fake_exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout
            calls.append((command.evidence_id, bool(kwargs.get("allow_error"))))
            if command.evidence_id == "version_after":
                if state["version_busy"]:
                    state["version_busy"] = False
                    return FakeFrame(b"", "version", rc=-16, status="busy")
                return FakeFrame(VERSION, "version")
            if command.evidence_id == "boot_id_after":
                if state["boot_busy"]:
                    state["boot_busy"] = False
                    return FakeFrame(b"", "cat", rc=-16, status="busy")
                state["boot_id"] += 1
                return FakeFrame((NEW_BOOT + "\n").encode(), "cat")
            if command.evidence_id == "stophud":
                return FakeFrame(b"", "stophud")
            if command.evidence_id == "version_after_stophud":
                return FakeFrame(VERSION, "version")
            if command.evidence_id == "boot_id_after_stophud":
                return FakeFrame((NEW_BOOT + "\n").encode(), "cat")
            raise AssertionError(command.evidence_id)

        with mock.patch.object(reboot, "exchange", side_effect=fake_exchange):
            with mock.patch.object(reboot.time, "sleep", return_value=None):
                with mock.patch.object(
                    reboot, "validate_bridge_binding", return_value={"pid": 1}
                ) as validate:
                    frames: list[dict[str, object]] = []
                    result = reboot.wait_for_new_boot(
                        "127.0.0.1", 54321, OLD_BOOT, 1.0, 0.01, stophud_frames=frames
                    )
        self.assertEqual(validate.call_count, 3)
        self.assertEqual(result["boot_id"], NEW_BOOT)
        self.assertEqual(result["stophud_events"][0]["reason"], "version_availability_busy")
        self.assertEqual(result["stophud_events"][1]["reason"], "boot_id_availability_busy")
        self.assertEqual(result["stophud_events"][2]["reason"], "new_boot_candidate")
        self.assertEqual(len(result["stophud_events"]), 3)
        self.assertEqual(calls.count(("stophud", True)), 3)
        self.assertTrue(all(allow_error for evidence_id, allow_error in calls if evidence_id in {
            "version_after", "boot_id_after", "version_after_stophud", "boot_id_after_stophud"
        }))

    def test_availability_nonbusy_frame_fails_closed_without_stophud(self) -> None:
        calls: list[str] = []

        def fake_exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout, kwargs
            calls.append(command.evidence_id)
            if command.evidence_id == "version_after":
                return FakeFrame(b"", "version", rc=1, status="error")
            raise AssertionError(command.evidence_id)

        with mock.patch.object(reboot, "exchange", side_effect=fake_exchange):
            with self.assertRaisesRegex(TimeoutError, "availability failed"):
                reboot.wait_for_new_boot("127.0.0.1", 54321, OLD_BOOT, 1.0, 0.01)
        self.assertEqual(calls, ["version_after"])

    def test_stophud_nonbusy_after_availability_busy_is_fatal_without_retry(self) -> None:
        calls: list[str] = []

        def fake_exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout, kwargs
            calls.append(command.evidence_id)
            if command.evidence_id == "version_after":
                return FakeFrame(b"", "version", rc=-16, status="busy")
            if command.evidence_id == "stophud":
                return FakeFrame(b"", "stophud", rc=1, status="error")
            raise AssertionError(command.evidence_id)

        with mock.patch.object(reboot, "exchange", side_effect=fake_exchange):
            with mock.patch.object(
                reboot, "validate_bridge_binding", return_value={"pid": 1}
            ) as validate:
                with self.assertRaisesRegex(TimeoutError, "arbitration incomplete"):
                    reboot.wait_for_new_boot("127.0.0.1", 54321, OLD_BOOT, 1.0, 0.01)
        self.assertEqual(validate.call_count, 1)
        self.assertEqual(calls, ["version_after", "stophud"])

    def test_final_bridge_drift_refuses_reboot_before_dispatch(self) -> None:
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        before = {
            "version": VERSION,
            "cmdline": {
                "androidboot.em.model": "SM-A908N",
                "androidboot.bootloader": "A908NKSU5EWA3",
                "androidboot.debug_level": "0x4f4c",
            },
            "boot_id": OLD_BOOT,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="reboot-final-bind-fail",
                expect_debug_after="mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                dispatch_timeout=1.0,
                boot_timeout=1.0,
                poll_interval=0.01,
            )
            with mock.patch.object(reboot, "REPO_ROOT", root), mock.patch.object(
                reboot, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                reboot, "revalidate_bridge_binding", side_effect=RuntimeError("bridge drift")
            ), mock.patch.object(
                reboot, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(reboot, "_preflight", return_value=before), mock.patch.object(
                reboot, "dispatch_once"
            ) as dispatch:
                with self.assertRaisesRegex(RuntimeError, "bridge drift"):
                    reboot.collect(args)
            dispatch.assert_not_called()
            journal = json.loads(
                (root / "evidence/private/reboot-final-bind-fail.journal.json").read_text()
            )
        self.assertFalse(journal["effect_dispatched"])
        self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")

    def test_nonpinned_bridge_host_or_port_fails_before_contact(self) -> None:
        for host, port in (("localhost", 54321), ("127.0.0.1", 54322)):
            with self.subTest(host=host, port=port), tempfile.TemporaryDirectory() as directory:
                args = Namespace(
                    execute=True,
                    experiment_id="reboot-endpoint-fail",
                    expect_debug_after="mid",
                    host=host,
                    port=port,
                    command_timeout=1.0,
                    dispatch_timeout=1.0,
                    boot_timeout=1.0,
                    poll_interval=0.01,
                )
                with mock.patch.object(reboot, "validate_bridge_binding") as bind, mock.patch.object(
                    reboot, "dispatch_once"
                ) as dispatch:
                    with self.assertRaisesRegex(ValueError, "pinned"):
                        reboot.collect(args)
                bind.assert_not_called()
                dispatch.assert_not_called()

    def test_timeout_values_reject_nonfinite_nonpositive_and_out_of_range_before_contact(self) -> None:
        for value in (float("nan"), float("inf"), 0.0, -1.0, reboot.MAX_COMMAND_TIMEOUT_SEC + 1.0):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                args = Namespace(
                    execute=True,
                    experiment_id="reboot-timeout-fail",
                    expect_debug_after="mid",
                    host="127.0.0.1",
                    port=54321,
                    command_timeout=value,
                    dispatch_timeout=1.0,
                    boot_timeout=1.0,
                    poll_interval=0.01,
                )
                with mock.patch.object(reboot, "validate_bridge_binding") as bind:
                    with self.assertRaises(ValueError):
                        reboot.collect(args)
                bind.assert_not_called()


if __name__ == "__main__":
    unittest.main()
