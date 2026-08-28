from __future__ import annotations

import json
import tempfile
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from tools import a90_inline_remapper_mid_probe as probe
from tools import a90_runtime_health as health


class FakeFrame:
    def __init__(
        self,
        payload: bytes,
        command: str,
        *,
        rc: int = 0,
        status: str = "ok",
        argc: int | None = None,
    ) -> None:
        if command == "stophud" and rc == 0 and status == "ok" and payload == b"":
            payload = b"autohud: stopped"
        self.payload = payload
        protocol_flags = probe.protocol_flags_for_argv((command,))
        if protocol_flags is None:
            raise AssertionError(f"test command has no native flag contract: {command}")
        default_argc = {
            "run": 5,
            "stophud": 1,
            "writefile": 3,
            "version": 1,
            "cat": 2,
            "selftest": 2,
            "mknodb": 4,
            "stat": 2,
        }[command]
        argc = default_argc if argc is None else argc
        self.begin = {
            "cmd": command,
            "seq": "1",
            "argc": str(argc),
            "flags": protocol_flags,
        }
        self.end = {
            "cmd": command,
            "seq": "1",
            "rc": str(rc),
            "errno": str(abs(rc)),
            "duration_ms": "0",
            "flags": protocol_flags,
            "status": status,
        }
        if rc == 0 and status == "ok":
            terminal = f"[done] {command} (0ms)\n".encode("ascii")
        elif rc == -16 and status == "busy":
            terminal = b"[busy] auto menu active; send hide/q before command\n"
        elif rc < 0:
            terminal = (
                f"[err] {command} rc={rc} errno={abs(rc)} (error) (0ms)\n"
            ).encode("ascii")
        else:
            terminal = f"[err] {command} rc={rc} (0ms)\n".encode("ascii")
        self.transcript = (
            b"A90P1 BEGIN seq=1 cmd=" + command.encode("ascii")
            + b" argc=" + str(argc).encode("ascii")
            + b" flags=" + protocol_flags.encode("ascii") + b"\n"
            + payload + b"\n" + terminal
            + b"A90P1 END seq=1 cmd=" + command.encode("ascii")
            + b" rc=" + str(rc).encode("ascii")
            + b" errno=" + str(abs(rc)).encode("ascii")
            + b" duration_ms=0 flags=" + protocol_flags.encode("ascii")
            + b" status=" + status.encode("ascii") + b"\n"
        )


VERSION = (
    b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\n"
    b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
    b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
)
CMDLINE = (
    b"skip_initramfs rootwait ro "
    b"androidboot.em.model=SM-A908N "
    b"androidboot.bootloader=A908NKSU5EWA3 "
    b"androidboot.debug_level=0x4f4c "
    b"androidboot.force_upload=0x0 "
    b"sec_debug.dump_sink=0x0 "
    b"androidboot.serialno=ABC123 root=PARTUUID=01234567-89ab-cdef-0123-456789abcdef "
    b"video=1080x2400@60,bpp=32\n"
)
SELFTEST = b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12\n"


class A90RuntimeHealthTests(unittest.TestCase):
    def test_parses_exact_version_and_selftest(self) -> None:
        version = health.parse_version(
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\r\n"
        )
        self.assertEqual(version["version"], "0.9.285")
        self.assertEqual(version["build"], "v2321-usb-clean-identity-rodata")
        selftest = health.parse_selftest(
            b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12\r\n"
        )
        self.assertEqual(selftest["fail"], 0)
        self.assertEqual(selftest["entries"], 12)

    def test_rejects_selftest_failure_or_wrong_counts(self) -> None:
        with self.assertRaisesRegex(ValueError, "reports failures"):
            health.parse_selftest(
                b"selftest: pass=10 warn=1 fail=1 duration=43ms entries=12\n"
            )
        with self.assertRaisesRegex(ValueError, "exact 11/1/0/12"):
            health.parse_selftest(
                b"selftest: pass=10 warn=2 fail=0 duration=43ms entries=12\n"
            )

    def test_target_requires_low_zero_zero_soc_and_panic_one(self) -> None:
        result = health.validate_target(VERSION, CMDLINE, b"339\n", b"1\n")
        self.assertEqual(result[0]["build"], "v2321-usb-clean-identity-rodata")
        self.assertEqual(result[1]["androidboot.debug_level"], "0x4f4c")
        with self.assertRaisesRegex(ValueError, "debug_level"):
            health.validate_target(
                VERSION, CMDLINE.replace(b"0x4f4c", b"0x494d"), b"339\n", b"1\n"
            )
        with self.assertRaisesRegex(ValueError, "soc_id"):
            health.validate_target(VERSION, CMDLINE, b"356\n", b"1\n")
        with self.assertRaisesRegex(ValueError, "panic_on_oops"):
            health.validate_target(VERSION, CMDLINE, b"339\n", b"0\n")

    def test_cmdline_accepts_ascii_space_runs_and_rejects_other_whitespace(self) -> None:
        expected = health.parse_cmdline(CMDLINE)
        for count in (2, 3, 9):
            with self.subTest(space_count=count):
                spaced = CMDLINE[:-1].replace(b" ", b" " * count) + b"\n"
                self.assertEqual(health.parse_cmdline(spaced), expected)
        body = CMDLINE[:-1]
        for whitespace in (b"\t", b"\v", b"\f", b"\r", b"\n"):
            with self.subTest(whitespace=whitespace):
                with self.assertRaises(ValueError):
                    health.parse_cmdline(body.replace(b" ", whitespace, 1) + b"\n")
        with self.assertRaises(ValueError):
            health.parse_cmdline(body.replace(b" ro ", b" ro  ro ") + b"\n")
        for bad in (
            b" " + CMDLINE,
            CMDLINE[:-1] + b" \n",
            CMDLINE + b"\n",
            CMDLINE[:-1] + b"\r\n\n",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    health.parse_cmdline(bad)

    def _run_collect(
        self,
        *,
        stophud_results: list[tuple[int, str]] | None = None,
        cmdline: bytes = CMDLINE,
        rebind_drift_attempt: int | None = None,
        bad_frame_id: str | None = None,
    ) -> tuple[tempfile.TemporaryDirectory[str], list[str], Path | None]:
        temp = tempfile.TemporaryDirectory()
        calls: list[str] = []
        outcomes = list(stophud_results or [(0, "ok")])
        stop_index = 0

        def binding() -> dict[str, object]:
            return {"process_pid": 123, "serial": "private"}

        rebind_calls = 0

        def rebind(initial: dict[str, object]) -> dict[str, object]:
            nonlocal rebind_calls
            rebind_calls += 1
            if rebind_drift_attempt == rebind_calls:
                return {**initial, "process_pid": 999}
            return dict(initial)

        def fake_exchange(host, port, command, timeout, **kwargs):
            nonlocal stop_index
            del host, port, timeout
            calls.append(command.evidence_id)
            if command.evidence_id == bad_frame_id:
                return FakeFrame(b"error\n", command.argv[0], rc=7, status="error")
            if command.evidence_id == "stophud":
                rc, status = outcomes[min(stop_index, len(outcomes) - 1)]
                stop_index += 1
                return FakeFrame(b"", "stophud", rc=rc, status=status)
            if command.evidence_id == "version":
                return FakeFrame(VERSION, "version")
            if command.evidence_id == "cmdline":
                return FakeFrame(cmdline, "cat")
            if command.evidence_id == "soc_id":
                return FakeFrame(b"339\n", "cat")
            if command.evidence_id == "panic_on_oops":
                return FakeFrame(b"1\n", "cat")
            if command.evidence_id == "selftest":
                return FakeFrame(SELFTEST, "selftest")
            if command.evidence_id == "battery_capacity":
                return FakeFrame(b"77\n", "cat")
            if command.evidence_id == "boot_sysfs_uevent":
                return FakeFrame(
                    b"MAJOR=259\nMINOR=27\nDEVNAME=sda24\nDEVTYPE=partition\n"
                    b"PARTN=24\nPARTNAME=boot\n",
                    "cat",
                )
            if command.evidence_id == "boot_sysfs_size":
                return FakeFrame(b"131072\n", "cat")
            if command.evidence_id == "boot_sysfs_ro":
                return FakeFrame(b"0\n", "cat")
            def toybox(body: bytes = b"", *, argc: int = 5) -> FakeFrame:
                payload = b"run: pid=1, q/Ctrl-C cancels\n" + body
                if body and not body.endswith(b"\n"):
                    payload += b"\n"
                payload += b"[exit 0]\n"
                return FakeFrame(payload, "run", argc=argc)

            if command.evidence_id.startswith("boot_attest_"):
                if command.evidence_id == "boot_attest_stat_node":
                    return FakeFrame(
                        b"mode=0600 uid=0 gid=0 size=0\n"
                        b"rdev=259:27\n",
                        "stat",
                    )
                if command.evidence_id == "boot_attest_mknod":
                    return FakeFrame(b"", "mknodb")
                if command.evidence_id == "boot_attest_hash":
                    return toybox(
                        f"{health.ROLLBACK_BOOT_SHA256}  {health.BOOT_ATTEST_FILE}".encode(),
                        argc=len(command.argv),
                    )
                if command.evidence_id == "boot_attest_size":
                    return toybox(
                        f"{health.BOOT_PREFIX_SIZE} {health.BOOT_ATTEST_FILE}".encode(),
                        argc=len(command.argv),
                    )
                return toybox(argc=len(command.argv))
            if command.evidence_id.startswith("v024_temp_"):
                return toybox(argc=len(command.argv))
            raise AssertionError(command.evidence_id)

        args = health.make_parser().parse_args(
            ["--experiment-id", health.RUNTIME_HEALTH_EXPERIMENT_ID, "--execute"]
        )
        args.output_root = Path(temp.name)
        try:
            with mock.patch.object(health, "REPO_ROOT", Path(temp.name)), mock.patch.object(
                health, "validate_bridge_binding", side_effect=binding
            ), mock.patch.object(
                health, "revalidate_bridge_binding", side_effect=rebind
            ), mock.patch.object(health, "exchange", side_effect=fake_exchange):
                result = health.collect(args)
        except BaseException:
            result = None
        return temp, calls, result[1] if result is not None else None

    def test_collect_stophud_first_exact_reads_and_redacts(self) -> None:
        temp, calls, manifest_path = self._run_collect(
            stophud_results=[(-16, "busy"), (-16, "busy"), (0, "ok")]
        )
        self.addCleanup(temp.cleanup)
        self.assertEqual(calls[0], "stophud")
        self.assertEqual(calls.count("stophud"), 3)
        self.assertEqual(calls[3:7], ["version", "cmdline", "soc_id", "panic_on_oops"])
        self.assertIn("selftest", calls)
        self.assertIn("battery_capacity", calls)
        self.assertIsNotNone(manifest_path)
        manifest = json.loads(Path(manifest_path).read_text())
        self.assertTrue(manifest["target_verified"])
        self.assertEqual(manifest["stophud_busy_retries"], 2)
        self.assertTrue(manifest["stophud_device_state_write"])
        self.assertTrue(manifest["temporary_filesystem_mutations"])
        self.assertTrue(manifest["temporary_block_node_mutations"])
        self.assertFalse(manifest["partition_writes"])
        self.assertFalse(manifest["persistent_writes"])
        self.assertNotIn("other_device_writes", manifest)
        self.assertEqual(manifest["health_scope"], "FINAL_ROLLBACK_ONLY")
        self.assertNotIn("payload_base64", json.dumps(manifest))
        self.assertNotIn("/dev/serial", json.dumps(manifest))
        raw = json.loads(
            (Path(temp.name) / f"evidence/private/{health.RUNTIME_HEALTH_EXPERIMENT_ID}.json").read_text()
        )
        self.assertEqual(raw["target"]["soc_id"], 339)
        self.assertEqual(raw["target"]["panic_on_oops"], 1)
        self.assertEqual(raw["boot_attestation"]["captured_size"], health.BOOT_PREFIX_SIZE)
        self.assertTrue(raw["boot_attestation"]["cleanup_ok"])
        self.assertTrue(raw["v024_temp_absence"]["absence_verified"])
        self.assertTrue(
            any(record["evidence_id"].startswith("stophud_") for record in raw["stophud_frames"])
        )

    def test_stophud_nonbusy_failure_is_retained_before_reads(self) -> None:
        temp, calls, manifest_path = self._run_collect(stophud_results=[(1, "error")])
        self.addCleanup(temp.cleanup)
        self.assertIsNone(manifest_path)
        self.assertEqual(calls, ["stophud"])
        journal = Path(temp.name) / f"evidence/private/{health.RUNTIME_HEALTH_EXPERIMENT_ID}.journal.json"
        self.assertEqual(json.loads(journal.read_text())["status"], "PREFLIGHT_FAILED")

    def test_stophud_busy_retry_revalidates_and_stops_on_bridge_drift(self) -> None:
        temp, calls, manifest_path = self._run_collect(
            stophud_results=[(-16, "busy"), (0, "ok")],
            rebind_drift_attempt=2,
        )
        self.addCleanup(temp.cleanup)
        self.assertIsNone(manifest_path)
        # The second busy attempt is refused before the actual stophud
        # exchange, and no substantive command follows the drift.
        self.assertEqual(calls, ["stophud"])
        self.assertNotIn("version", calls)
        journal = json.loads(
            (Path(temp.name) / f"evidence/private/{health.RUNTIME_HEALTH_EXPERIMENT_ID}.journal.json").read_text()
        )
        self.assertEqual(journal["status"], "PREFLIGHT_FAILED")

    def test_wrong_low_target_fails_before_health_reads(self) -> None:
        temp, calls, manifest_path = self._run_collect(
            cmdline=CMDLINE.replace(b"0x4f4c", b"0x494d")
        )
        self.addCleanup(temp.cleanup)
        self.assertIsNone(manifest_path)
        self.assertEqual(calls, ["stophud", "version", "cmdline", "soc_id", "panic_on_oops"])
        self.assertNotIn("selftest", calls)

    def test_nonzero_or_error_terminal_frame_is_incident_not_pass(self) -> None:
        temp, calls, manifest_path = self._run_collect(bad_frame_id="selftest")
        self.addCleanup(temp.cleanup)
        self.assertIsNone(manifest_path)
        self.assertEqual(calls[-1], "selftest")
        journal = json.loads(
            (Path(temp.name) / f"evidence/private/{health.RUNTIME_HEALTH_EXPERIMENT_ID}.journal.json").read_text()
        )
        self.assertEqual(journal["status"], "INCIDENT")
        self.assertIn("selftest", journal["error"])

    def test_output_root_symlink_is_rejected_before_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                with mock.patch.object(health, "REPO_ROOT", real):
                    health.collect(
                        Namespace(
                            experiment_id=health.RUNTIME_HEALTH_EXPERIMENT_ID,
                            execute=True,
                            host="127.0.0.1",
                            port=54321,
                            timeout=1.0,
                            output_root=link,
                        )
                    )

    def test_execute_and_timeout_gates_precede_output_or_bridge(self) -> None:
        for execute, timeout in ((False, 1.0), (True, 0.0), (True, float("inf")), (True, float("nan"))):
            with self.subTest(execute=execute, timeout=timeout), tempfile.TemporaryDirectory() as directory:
                bind = mock.Mock()
                contact = mock.Mock()
                with mock.patch.object(health, "REPO_ROOT", Path(directory)), mock.patch.object(
                    health, "validate_bridge_binding", bind
                ), mock.patch.object(health, "exchange", contact):
                    with self.assertRaises(ValueError):
                        health.collect(Namespace(
                            experiment_id=health.RUNTIME_HEALTH_EXPERIMENT_ID,
                            execute=execute,
                            host="127.0.0.1",
                            port=54321,
                            timeout=timeout,
                            output_root=Path(directory),
                        ))
                bind.assert_not_called()
                contact.assert_not_called()

    def test_output_root_is_not_a_production_parser_option(self) -> None:
        with self.assertRaises(SystemExit):
            health.make_parser().parse_args(
                ["--experiment-id", health.RUNTIME_HEALTH_EXPERIMENT_ID, "--execute", "--output-root", "."]
            )

    def test_injected_alternate_root_is_rejected_before_bridge_contact(self) -> None:
        with tempfile.TemporaryDirectory() as fixed, tempfile.TemporaryDirectory() as alternate:
            args = Namespace(
                experiment_id=health.RUNTIME_HEALTH_EXPERIMENT_ID,
                execute=True,
                host="127.0.0.1",
                port=54321,
                timeout=1.0,
                output_root=Path(alternate),
            )
            with mock.patch.object(health, "REPO_ROOT", Path(fixed)), mock.patch.object(
                health, "validate_bridge_binding"
            ) as bind, mock.patch.object(health, "exchange") as contact:
                with self.assertRaisesRegex(ValueError, "fixed to REPO_ROOT"):
                    health.collect(args)
            bind.assert_not_called()
            contact.assert_not_called()

    def test_arbitrary_experiment_id_is_rejected_before_bridge_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = Namespace(
                experiment_id="runtime-health-other",
                execute=True,
                host="127.0.0.1",
                port=54321,
                timeout=1.0,
                output_root=Path(directory),
            )
            with mock.patch.object(health, "REPO_ROOT", Path(directory)), mock.patch.object(
                health, "validate_bridge_binding"
            ) as bind, mock.patch.object(health, "exchange") as contact:
                with self.assertRaisesRegex(ValueError, "fixed to runtime-health"):
                    health.collect(args)
            bind.assert_not_called()
            contact.assert_not_called()

    def test_initial_final_journal_is_a_single_o_excl_owner_and_partial_claim_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence/private/runtime-health.journal.json"
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def owner() -> None:
                barrier.wait()
                try:
                    health._exclusive_json(path, {"owner": True})
                except FileExistsError:
                    outcomes.append("lost")
                else:
                    outcomes.append("won")

            threads = [threading.Thread(target=owner) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes), ["lost", "won"])
            self.assertEqual(json.loads(path.read_text()), {"owner": True})
            path.write_bytes(b"partial-claim")
            with self.assertRaises(FileExistsError):
                health._exclusive_json(path, {"owner": "replay"})
            self.assertEqual(path.read_bytes(), b"partial-claim")


if __name__ == "__main__":
    unittest.main()
