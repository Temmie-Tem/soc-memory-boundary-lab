from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from tools import a90_native_reboot_observe as reboot
from tools import a90_native_reboot_public_repair as repair


class FakeFrame:
    def __init__(self, payload: bytes, command: str, *, rc: int = 0, status: str = "ok"):
        if command == "stophud" and rc == 0 and status == "ok" and payload == b"":
            payload = b"autohud: stopped"
        self.payload = payload
        self.transcript = b"A90P1 " + payload
        self.begin = {"cmd": command, "seq": "1"}
        self.end = {
            "cmd": command,
            "seq": "1",
            "rc": str(rc),
            "status": status,
        }
        if command == "stophud":
            self.begin.update({"argc": "1", "flags": "0x8"})
            self.end.update(
                {
                    "errno": str(abs(rc)),
                    "duration_ms": "0",
                    "flags": "0x8",
                }
            )
            terminal = (
                b"[done] stophud (0ms)\r\n"
                if rc == 0 and status == "ok"
                else b"[busy] auto menu active; send hide/q before command\r\n"
                if rc == -16 and status == "busy"
                else f"[err] stophud rc={rc} (0ms)\r\n".encode("ascii")
            )
            self.transcript = (
                b"A90P1 BEGIN seq=1 cmd=stophud argc=1 flags=0x8\r\n"
                + payload
                + b"\r\n"
                + terminal
                + b"A90P1 END seq=1 cmd=stophud rc="
                + str(rc).encode("ascii")
                + b" errno="
                + str(abs(rc)).encode("ascii")
                + b" duration_ms=0 flags=0x8 status="
                + status.encode("ascii")
                + b"\r\n"
            )


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
        self.assertIsNone(parsed.expect_debug_before)
        explicit = parser.parse_args(
            [
                "--experiment-id",
                "test",
                "--expect-debug-before",
                "mid",
                "--expect-debug-after",
                "mid",
            ]
        )
        self.assertEqual(explicit.expect_debug_before, "mid")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    ["--experiment-id", "test", "--expect-debug-after", "high"]
                )

    def test_mid_to_mid_collect_binds_explicit_profile_and_public_summary(self) -> None:
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        before = {
            "version": VERSION,
            "cmdline": {
                "androidboot.em.model": "SM-A908N",
                "androidboot.bootloader": "A908NKSU5EWA3",
                "androidboot.debug_level": "0x494d",
            },
            "boot_id": OLD_BOOT,
        }
        after = {
            "version": (
                b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\n"
                b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
                b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
            ),
            "boot_id": NEW_BOOT,
            "attempts": 1,
            "stophud": {"accepted": True, "busy_retries": 0},
            "stophud_events": [],
            "candidate_version": VERSION,
            "candidate_boot_id": NEW_BOOT,
        }
        args = Namespace(
            execute=True,
            experiment_id="reboot-mid-to-mid",
            expect_debug_before="mid",
            expect_debug_after="mid",
            host="127.0.0.1",
            port=54321,
            command_timeout=1.0,
            dispatch_timeout=1.0,
            boot_timeout=1.0,
            poll_interval=0.01,
        )
        transcript = (
            b"A90P1 BEGIN seq=1 cmd=reboot argc=1 flags=0x14\r\n"
            b"reboot: syncing and restarting\r\n"
        )

        def fake_read(host, port, evidence_id, argv, timeout):
            del host, port, argv, timeout
            return {
                "boot_id_claim": (OLD_BOOT + "\n").encode("ascii"),
                "cmdline_after": (
                    b"androidboot.em.model=SM-A908N "
                    b"androidboot.bootloader=A908NKSU5EWA3 "
                    b"androidboot.debug_level=0x494d "
                    b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0\n"
                ),
                "download_mode_after": b"1\n",
                "selftest_after": (
                    b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12\n"
                ),
                "boot_id_final": (NEW_BOOT + "\n").encode("ascii"),
            }[evidence_id]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(reboot, "REPO_ROOT", root), mock.patch.object(
                reboot, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                reboot, "revalidate_bridge_binding", return_value=binding
            ), mock.patch.object(
                reboot,
                "run_stophud",
                return_value={"accepted": True, "busy_retries": 0},
            ), mock.patch.object(
                reboot, "_preflight", return_value=before
            ), mock.patch.object(
                reboot, "wait_for_new_boot", return_value=after
            ), mock.patch.object(
                reboot, "_read", side_effect=fake_read
            ), mock.patch.object(
                reboot, "_dispatch_reboot_wire", return_value=(transcript, True)
            ) as dispatch:
                journal_path, manifest_path = reboot.collect(args)
            journal = json.loads(journal_path.read_text())
            manifest = json.loads(manifest_path.read_text())

        self.assertEqual(journal["expected_debug_before"], "mid")
        self.assertTrue(journal["expected_debug_before_explicit"])
        self.assertEqual(journal["expected_debug_after"], "mid")
        self.assertEqual(
            manifest["debug_profile_summary"],
            {"before": "mid", "after": "mid", "before_explicit": True},
        )
        dispatch.assert_called_once()

    def test_explicit_wrong_pre_profile_stops_before_claim_and_dispatch(self) -> None:
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        for suffix, (expected_before, observed_before, expected_after) in enumerate(
            (("mid", "low", "mid"), ("low", "mid", "low")),
            start=1,
        ):
            with self.subTest(
                expected_before=expected_before,
                observed_before=observed_before,
                expected_after=expected_after,
            ), tempfile.TemporaryDirectory() as directory:
                experiment_id = f"reboot-explicit-before-mismatch-{suffix}"
                args = Namespace(
                    execute=True,
                    experiment_id=experiment_id,
                    expect_debug_before=expected_before,
                    expect_debug_after=expected_after,
                    host="127.0.0.1",
                    port=54321,
                    command_timeout=1.0,
                    dispatch_timeout=1.0,
                    boot_timeout=1.0,
                    poll_interval=0.01,
                )
                before = {
                    "version": VERSION,
                    "cmdline": {
                        "androidboot.em.model": "SM-A908N",
                        "androidboot.bootloader": "A908NKSU5EWA3",
                        "androidboot.debug_level": reboot.DEBUG_CMDLINE[observed_before],
                    },
                    "boot_id": OLD_BOOT,
                }
                root = Path(directory)
                with mock.patch.object(reboot, "REPO_ROOT", root), mock.patch.object(
                    reboot, "validate_bridge_binding", return_value=binding
                ), mock.patch.object(
                    reboot,
                    "run_stophud",
                    return_value={"accepted": True, "busy_retries": 0},
                ), mock.patch.object(
                    reboot, "_preflight", return_value=before
                ), mock.patch.object(
                    reboot, "claim_native_transition"
                ) as claim, mock.patch.object(
                    reboot, "_dispatch_reboot_wire"
                ) as dispatch:
                    with self.assertRaisesRegex(ValueError, "current predecessor"):
                        reboot.collect(args)
                journal = json.loads(
                    (root / "evidence/private" / f"{experiment_id}.journal.json").read_text()
                )

            claim.assert_not_called()
            dispatch.assert_not_called()
            self.assertEqual(journal["expected_debug_before"], expected_before)
            self.assertTrue(journal["expected_debug_before_explicit"])
            self.assertFalse(journal["effect_dispatched"])
            self.assertFalse(journal["physical_effect_claim"]["attempted"])

    def test_legacy_predecessor_mapping_is_retained_when_before_is_omitted(self) -> None:
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
        args = Namespace(
            execute=True,
            experiment_id="reboot-legacy-predecessor",
            expect_debug_after="mid",
            host="127.0.0.1",
            port=54321,
            command_timeout=1.0,
            dispatch_timeout=1.0,
            boot_timeout=1.0,
            poll_interval=0.01,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(reboot, "REPO_ROOT", root), mock.patch.object(
                reboot, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                reboot,
                "run_stophud",
                return_value={"accepted": True, "busy_retries": 0},
            ), mock.patch.object(
                reboot, "_preflight", return_value=before
            ), mock.patch.object(
                reboot,
                "revalidate_bridge_binding",
                side_effect=RuntimeError("stop before effect"),
            ), mock.patch.object(reboot, "_dispatch_reboot_wire") as dispatch:
                with self.assertRaisesRegex(RuntimeError, "stop before effect"):
                    reboot.collect(args)
            journal = json.loads(
                (root / "evidence/private/reboot-legacy-predecessor.journal.json").read_text()
            )

        self.assertEqual(
            journal["expected_debug_before"],
            reboot.EXPECTED_DEBUG_PREDECESSOR["mid"],
        )
        self.assertFalse(journal["expected_debug_before_explicit"])
        dispatch.assert_not_called()

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

    def _stage_public_repair_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        """Synthesize a complete pinned-shape fixture without live evidence."""

        public = root / "evidence/manifests" / repair.PUBLIC_MANIFEST_NAME
        journal = root / "evidence/private" / repair.JOURNAL_NAME
        public.parent.mkdir(parents=True, exist_ok=True)
        journal.parent.mkdir(parents=True, exist_ok=True)
        boot_before = "11111111-1111-4111-8111-111111111111"
        boot_after = "22222222-2222-4222-8222-222222222222"
        claim_identity = {
            "schema": repair.NATIVE_TRANSITION_CLAIM_SCHEMA,
            "resource": repair.NATIVE_TRANSITION_RESOURCE,
            "current_native_boot_id": boot_before,
        }
        claim_key = repair.sha256(repair._json_bytes(claim_identity))
        claim_name = f"verification-024-native-boot-transition-{claim_key}.claim.json"
        claim = root / "evidence/private" / claim_name
        claim_value = {
            "schema": repair.NATIVE_TRANSITION_CLAIM_SCHEMA,
            "claim_key_sha256": claim_key,
            "claim_identity": claim_identity,
            "claimed_by_experiment_id": repair.EXPERIMENT_ID,
            "provenance": {"owner_kind": "native-reboot", "effect": "cmdv1 reboot"},
            "effect_replayed": False,
            "claim_status": "COMPLETE",
            "created_utc": "2026-08-28T00:00:00+00:00",
        }
        claim_data = repair._json_bytes(claim_value)
        claim.write_bytes(claim_data)
        claim.chmod(0o600)
        journal_value = {
            "schema": repair.JOURNAL_SCHEMA,
            "experiment_id": repair.EXPERIMENT_ID,
            "started_utc": "2026-08-28T00:00:00+00:00",
            "completed_utc": "2026-08-28T00:01:00+00:00",
            "status": "NEW_BOOT_PROVED",
            "effect": "cmdv1 reboot",
            "effect_dispatched": True,
            "effect_replayed": False,
            "before": {"boot_id": boot_before},
            "after": {
                "boot_id": boot_after,
                "cmdline": {
                    "androidboot.debug_level": "0x494d",
                    "androidboot.force_upload": "0x0",
                    "sec_debug.dump_sink": "0x0",
                },
                "download_mode": "1",
                "selftest": {"passed": 11, "warn": 1, "fail": 0, "duration": 43, "entries": 12},
                "stophud": {"accepted": True, "busy_retries": 0},
            },
            "dispatch_receipt": {
                "a90p1_begin_observed": True,
                "reboot_marker_observed": True,
                "begin": {"seq": "1", "cmd": "reboot", "argc": "1", "flags": "0x14"},
                "socket_disconnect_observed": True,
                "transcript_sha256": "a" * 64,
                "transcript_size": 105,
            },
            "physical_effect_claim": {
                "claimed": True,
                "attempted": True,
                "key_sha256": claim_key,
                "claim_path": str(claim),
                "claim_sha256": repair.sha256(claim_data),
                "claim_size": len(claim_data),
                "boot_id": boot_before,
            },
            "pre_stophud": {"accepted": True, "busy_retries": 0},
        }
        journal_data = repair._json_bytes(journal_value)
        journal.write_bytes(journal_data)
        journal.chmod(0o600)
        public_data = repair._json_bytes(repair._legacy_public_projection(journal_value))
        public.write_bytes(public_data)
        public.chmod(0o644)
        self._repair_pin_overrides = {
            "LEGACY_PUBLIC_SIZE": len(public_data),
            "LEGACY_PUBLIC_SHA256": repair.sha256(public_data),
            "JOURNAL_SIZE": len(journal_data),
            "JOURNAL_SHA256": repair.sha256(journal_data),
            "CLAIM_NAME": claim_name,
            "CLAIM_SIZE": len(claim_data),
            "CLAIM_SHA256": repair.sha256(claim_data),
        }
        return public, journal, claim

    def _repair_context(self, root: Path):
        return mock.patch.multiple(
            repair,
            REPO_ROOT=root,
            **getattr(self, "_repair_pin_overrides", {}),
        )

    def test_future_public_projection_is_v2_and_contains_no_raw_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _public_path, journal_path, _claim_path = self._stage_public_repair_fixture(root)
            journal = json.loads(journal_path.read_text())
            boot_id = journal["before"]["boot_id"]
            journal["physical_effect_claim"]["current_native_boot_id"] = boot_id
            journal_data = reboot.json_bytes(journal)
            public = reboot.public_manifest_v2(
                journal,
                journal_filename=repair.JOURNAL_NAME,
                journal_sha256=reboot.sha256(journal_data),
                journal_size=len(journal_data),
                boot_id=boot_id,
            )
            encoded = json.dumps(public, ensure_ascii=True, sort_keys=True)
            self.assertEqual(public["schema"], reboot.PUBLIC_MANIFEST_SCHEMA_V2)
            self.assertNotIn("boot_id", public["physical_effect_claim"])
            self.assertEqual(
                public["physical_effect_claim"]["boot_id_sha256"],
                reboot.sha256(boot_id.encode("ascii")),
            )
            self.assertEqual(
                public["private_journal"],
                {
                    "filename": repair.JOURNAL_NAME,
                    "sha256": reboot.sha256(journal_data),
                    "size": len(journal_data),
                    "git_ignored": True,
                },
            )
            self.assertNotRegex(encoded, reboot.BOOT_ID_SUBSTRING_RE)
            self.assertNotIn("claim_path", encoded)
            self.assertNotIn("serial_device", encoded)

    def test_public_projection_rejects_a_durable_journal_different_from_memory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _public_path, journal_path, _claim_path = self._stage_public_repair_fixture(root)
            journal = json.loads(journal_path.read_text())
            changed = json.loads(journal_path.read_text())
            changed["status"] = "EFFECT_DISPATCHED_OBSERVATION_INCOMPLETE"
            journal_path.write_bytes(reboot.json_bytes(changed))
            journal_path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "changed"):
                reboot._load_final_journal(journal_path, journal)

    def test_host_only_repair_archives_legacy_then_publishes_v2_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, _journal, _claim = self._stage_public_repair_fixture(root)
            legacy = public.read_bytes()
            with self._repair_context(root):
                output = repair.repair_legacy_public_manifest()
                self.assertEqual(output, public)
                first_v2 = public.read_bytes()
                first_inode = public.stat().st_ino
                self.assertNotEqual(first_v2, legacy)
                self.assertEqual(
                    json.loads(first_v2.decode())["schema"],
                    repair.PUBLIC_MANIFEST_SCHEMA_V2,
                )
                self.assertNotRegex(first_v2.decode("ascii"), repair.BOOT_ID_SUBSTRING_RE)
                archive = root / "evidence/private" / repair.LEGACY_ARCHIVE_NAME
                self.assertEqual(archive.read_bytes(), legacy)
                self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
                self.assertEqual(repair.repair(), public)
                self.assertEqual(public.read_bytes(), first_v2)
                self.assertEqual(public.stat().st_ino, first_inode)

    def test_repair_archive_failure_leaves_legacy_public_untouched_and_no_device_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, _journal, _claim = self._stage_public_repair_fixture(root)
            legacy = public.read_bytes()
            with self._repair_context(root), mock.patch.object(
                repair, "_write_exclusive_archive", side_effect=repair.RepairError("archive fsync failed")
            ) as archive_write:
                with self.assertRaisesRegex(repair.RepairError, "archive fsync failed"):
                    repair.repair_legacy_public_manifest()
            archive_write.assert_called_once()
            self.assertEqual(public.read_bytes(), legacy)
            self.assertFalse((root / "evidence/private" / repair.LEGACY_ARCHIVE_NAME).exists())

    def test_repair_privacy_gate_runs_before_archive_or_public_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, _journal, _claim = self._stage_public_repair_fixture(root)
            legacy = public.read_bytes()
            leaked = {
                "schema": repair.PUBLIC_MANIFEST_SCHEMA_V2,
                "boot_id": "11111111-1111-4111-8111-111111111111",
                "claim_path": "/private/absolute/claim.json",
            }
            with self._repair_context(root), mock.patch.object(
                repair, "_public_v2_projection", return_value=leaked
            ):
                with self.assertRaisesRegex(repair.RepairError, "private|UUID"):
                    repair.repair_legacy_public_manifest()
            self.assertEqual(public.read_bytes(), legacy)
            self.assertFalse((root / "evidence/private" / repair.LEGACY_ARCHIVE_NAME).exists())

    def test_repair_final_state_rejects_archive_or_source_mutation_after_archive(self) -> None:
        for mutation in ("archive", "journal", "claim"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                public, journal, claim = self._stage_public_repair_fixture(root)
                archive = root / "evidence/private" / repair.LEGACY_ARCHIVE_NAME
                original_replace = repair._replace_public

                def mutate_then_replace(path: Path, data: bytes) -> None:
                    target = {"archive": archive, "journal": journal, "claim": claim}[mutation]
                    changed = bytearray(target.read_bytes())
                    changed[-1] ^= 0x01
                    target.write_bytes(bytes(changed))
                    target.chmod(0o644 if target == public else 0o600)
                    original_replace(path, data)

                with self._repair_context(root), mock.patch.object(
                    repair, "_replace_public", side_effect=mutate_then_replace
                ):
                    with self.assertRaises(repair.RepairError):
                        repair.repair_legacy_public_manifest()
                # The operation may have published v2 before the final source
                # re-read detects the persistent mutation; that state is
                # intentionally explicit reconciliation evidence.
                self.assertTrue(public.exists())
                self.assertTrue(archive.exists())

    def test_future_and_repair_v2_projections_have_parity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _public, journal_path, _claim = self._stage_public_repair_fixture(root)
            journal = json.loads(journal_path.read_text())
            boot_id = journal["before"]["boot_id"]
            journal["physical_effect_claim"]["current_native_boot_id"] = boot_id
            journal_data = repair._json_bytes(journal)
            repaired = repair._public_v2_projection(journal, journal_data, boot_id)
            future = reboot.public_manifest_v2(
                journal,
                journal_filename=repair.JOURNAL_NAME,
                journal_sha256=repair.sha256(journal_data),
                journal_size=len(journal_data),
                boot_id=boot_id,
            )
            # The only private difference in a real producer call is the
            # source binding supplied by the caller; normalize it explicitly
            # so this test detects semantic projection drift, not caller
            # metadata formatting.
            future["private_journal"] = repaired["private_journal"]
            self.assertEqual(future, repaired)

    def test_repair_rejects_partial_states_and_all_pinned_source_attacks(self) -> None:
        source_names = ("public", "journal", "claim")
        for source_name in source_names:
            with self.subTest(source=source_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                public, journal, claim = self._stage_public_repair_fixture(root)
                source = {"public": public, "journal": journal, "claim": claim}[source_name]
                data = bytearray(source.read_bytes())
                data[-1] ^= 0x01
                source.write_bytes(bytes(data))
                source.chmod(0o644 if source_name == "public" else 0o600)
                with self._repair_context(root):
                    with self.assertRaises(repair.RepairError):
                        repair.repair_legacy_public_manifest()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, journal, claim = self._stage_public_repair_fixture(root)
            for path in (public, journal, claim):
                with self.subTest(kind="symlink", path=path.name):
                    replacement = path.with_name(path.name + ".copy")
                    shutil.copyfile(path, replacement)
                    path.unlink()
                    path.symlink_to(replacement)
                    try:
                        with self._repair_context(root):
                            with self.assertRaises(repair.RepairError):
                                repair.repair_legacy_public_manifest()
                    finally:
                        path.unlink(missing_ok=True)
                        replacement.unlink(missing_ok=True)
                        self._stage_public_repair_fixture(root)
                        public, journal, claim = (
                            root / "evidence/manifests" / repair.PUBLIC_MANIFEST_NAME,
                            root / "evidence/private" / repair.JOURNAL_NAME,
                            root / "evidence/private" / repair.CLAIM_NAME,
                        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, _journal, _claim = self._stage_public_repair_fixture(root)
            public.chmod(0o600)
            with self._repair_context(root):
                with self.assertRaises(repair.RepairError):
                    repair.repair_legacy_public_manifest()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._stage_public_repair_fixture(root)
            with self._repair_context(root), mock.patch.object(
                repair.os, "getuid", return_value=0
            ):
                with self.assertRaises(repair.RepairError):
                    repair.repair_legacy_public_manifest()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, _journal, _claim = self._stage_public_repair_fixture(root)
            archive = root / "evidence/private" / repair.LEGACY_ARCHIVE_NAME
            archive.write_bytes(public.read_bytes())
            archive.chmod(0o600)
            with self._repair_context(root):
                with self.assertRaisesRegex(repair.RepairError, "partial"):
                    repair.repair_legacy_public_manifest()

    def test_repair_revalidates_claim_identity_owner_and_uuid_without_device_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, journal_path, claim_path = self._stage_public_repair_fixture(root)
            journal = json.loads(journal_path.read_text())
            claim_data = claim_path.read_bytes()
            journal["before"]["boot_id"] = "00000000-0000-0000-0000-000000000002"
            with mock.patch.object(repair, "REPO_ROOT", root):
                with self.assertRaises(repair.RepairError):
                    repair._validate_private_claim(root, journal, claim_path, claim_data)
            self.assertEqual(public.read_bytes()[0], ord("{"))


if __name__ == "__main__":
    unittest.main()
