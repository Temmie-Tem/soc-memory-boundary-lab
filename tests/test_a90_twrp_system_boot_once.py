from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import a90_twrp_system_boot_once as once
from tools import a90_twrp_system_boot as twrp


SERIAL = "verification-024-recovery"
SERIAL_HASH = hashlib.sha256(SERIAL.encode()).hexdigest()
RECOVERY_BOOT_ID = "00000000-0000-0000-0000-000000000001"
HELP = (
    "TWRP openrecoveryscript command line tool, "
    f"TWRP version {once.TWRP_VERSION}\n"
)


class FixedRunner:
    """A command recorder with no real device/USB/ADB contact."""

    def __init__(self, *, prep_read: str = "system", effect_error: BaseException | None = None):
        self.calls: list[tuple[str, ...]] = []
        self.prep_read = prep_read
        self.effect_error = effect_error

    def __call__(self, argv) -> str:
        call = tuple(argv)
        self.calls.append(call)
        self.assert_fixed(call)
        command = call[-1]
        if command == "getprop ro.product.model":
            return f"{once.TARGET_MODEL}\n"
        if command == "getprop ro.product.device":
            return f"{once.TARGET_DEVICE}\n"
        if command == "twrp --help 2>&1":
            return HELP
        if command == "twrp get tw_gui_done":
            return "tw_gui_done = 0\n"
        if command == "cat /proc/sys/kernel/random/boot_id":
            return f"{RECOVERY_BOOT_ID}\n"
        if command == once.PREPARATION_READ_COMMAND:
            return f"tw_reboot_arg = {self.prep_read}\n"
        if command == once.EFFECT_COMMAND and self.effect_error is not None:
            raise self.effect_error
        if command == ("adb", "devices")[-1]:
            return "List of devices attached\n"
        return ""

    @staticmethod
    def assert_fixed(call: tuple[str, ...]) -> None:
        # Every shell request is tied to the one bound serial.  The selector
        # itself is mocked in these tests, so no command can reach a host ADB.
        if len(call) >= 5 and call[0:3] == (once.ADB, "-s", SERIAL):
            return
        if call == (once.ADB, "devices"):
            return
        raise AssertionError(call)


class Endpoint:
    serial = SERIAL
    state = "recovery"


class A90TwrpSystemBootOnceTests(unittest.TestCase):
    def tearDown(self) -> None:
        once.REPO_ROOT = Path(once.__file__).resolve().parents[1]

    def args(
        self,
        root: Path,
        *,
        execute: bool = True,
        phase: str = "control",
        experiment_id: str = "verification-024-system-boot-test",
    ) -> argparse.Namespace:
        once.REPO_ROOT = root
        return argparse.Namespace(
            experiment_id=experiment_id,
            phase=phase,
            execute=execute,
        )

    def run_collect(
        self,
        root: Path,
        runner: FixedRunner | None = None,
        *,
        wait_result: bool = True,
        phase: str = "control",
    ):
        runner = runner or FixedRunner()
        endpoint = Endpoint()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(once, "REPO_ROOT", root))
            stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
            stack.enter_context(mock.patch.object(once, "select_exact_recovery", return_value=endpoint))
            stack.enter_context(mock.patch.object(once, "run_checked", side_effect=runner))
            wait = stack.enter_context(mock.patch.object(once, "wait_for_disconnect", return_value=wait_result))
            paths = once.collect(self.args(root, phase=phase))
        return paths, runner, wait

    def test_import_and_cli_are_contact_free_and_fixed(self) -> None:
        parser = once.build_parser()
        args = parser.parse_args(
            ["--experiment-id", "x", "--phase", "read", "--execute"]
        )
        self.assertEqual(args.phase, "read")
        self.assertTrue(args.execute)
        for option in ("--adb", "--serial", "--command", "--timeout", "--output-root"):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    ["--experiment-id", "x", "--phase", "read", option, "x"]
                )
            with mock.patch.object(once, "run_checked") as run:
                __import__("importlib").import_module("tools.a90_twrp_system_boot_once")
                run.assert_not_called()

    def test_boot_id_parser_accepts_only_exact_transport_forms(self) -> None:
        accepted = (
            RECOVERY_BOOT_ID,
            f"{RECOVERY_BOOT_ID}\n",
            f"{RECOVERY_BOOT_ID}\r\n",
            RECOVERY_BOOT_ID.encode("utf-8"),
            f"{RECOVERY_BOOT_ID}\n".encode("utf-8"),
            f"{RECOVERY_BOOT_ID}\r\n".encode("utf-8"),
        )
        for raw in accepted:
            with self.subTest(accepted=raw):
                self.assertEqual(once._parse_boot_id(raw), RECOVERY_BOOT_ID)

        refused = (
            f" {RECOVERY_BOOT_ID}",
            f"{RECOVERY_BOOT_ID} ",
            f"\t{RECOVERY_BOOT_ID}",
            f"{RECOVERY_BOOT_ID}\t",
            f"{RECOVERY_BOOT_ID}\n\n",
            f"{RECOVERY_BOOT_ID}\r",
            f"{RECOVERY_BOOT_ID}\r\r\n",
            f"{RECOVERY_BOOT_ID}\r\n\n",
            f"{RECOVERY_BOOT_ID}extra",
            f"{RECOVERY_BOOT_ID}\x00",
            f"{RECOVERY_BOOT_ID}\u00a0",
            f"{RECOVERY_BOOT_ID}\n".encode("utf-8") + b"extra",
        )
        for raw in refused:
            with self.subTest(refused=raw):
                with self.assertRaisesRegex(once.BootError, "exactly|valid"):
                    once._parse_boot_id(raw)

    def test_missing_execute_and_stale_outputs_refuse_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(once, "select_exact_recovery") as select, mock.patch.object(
                once, "run_checked"
            ) as run:
                with self.assertRaisesRegex(once.BootError, "explicit --execute"):
                    once.collect(self.args(root, execute=False))
            select.assert_not_called()
            run.assert_not_called()

    def test_injected_output_root_is_refused_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root)
            args.output_root = root / "redirected"
            with mock.patch.object(once, "select_exact_recovery") as select, mock.patch.object(
                once, "run_checked"
            ) as run:
                with self.assertRaisesRegex(once.BootError, "output_root"):
                    once.collect(args)
            select.assert_not_called()
            run.assert_not_called()

    def test_injected_nonfixed_adb_is_refused_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root)
            args.adb = "adb"
            with mock.patch.object(once, "select_exact_recovery") as select, mock.patch.object(
                once, "run_checked"
            ) as run:
                with self.assertRaisesRegex(once.BootError, "fixed adb"):
                    once.collect(args)
            select.assert_not_called()
            run.assert_not_called()

    def test_direct_mutation_helpers_refuse_before_runner(self) -> None:
        runner = mock.Mock()
        for helper in (
            once.prepare_system_boot,
            once.prepare_system_boot_once,
            once.dispatch_system_boot_once,
            once.dispatch_once,
        ):
            with self.subTest(helper=helper.__name__):
                with self.assertRaises(once.BootError):
                    helper(once.ADB, "serial", runner)
        with self.assertRaises(once.BootError):
            once.adb_shell(once.ADB, "serial", once.PREPARATION_COMMAND, runner)
        runner.assert_not_called()
        self.assertNotIn("prepare_system_boot", once.__all__)
        self.assertNotIn("prepare_system_boot_once", once.__all__)
        self.assertNotIn("dispatch_system_boot_once", once.__all__)
        self.assertNotIn("dispatch_once", once.__all__)

    def test_system_effect_claim_excludes_phase_and_experiment_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity, key = once._system_effect_identity(RECOVERY_BOOT_ID)
            claim_path = once._system_effect_claim_path(root, key)
            first = once._create_system_effect_claim(
                claim_path,
                identity=identity,
                key_sha256=key,
                experiment_id="control-owner",
            )
            self.assertTrue(first)
            # A new phase/experiment must map to the same physical claim and
            # therefore cannot dispatch a second tw_gui_done effect.
            with self.assertRaisesRegex(once.BootError, "replay forbidden"):
                once._create_system_effect_claim(
                    claim_path,
                    identity=identity,
                    key_sha256=key,
                    experiment_id="read-owner",
                )

        for stale_kind in ("temp", "symlink"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private = root / "evidence" / "private"
                private.mkdir(parents=True)
                journal = private / f"{self.args(root).experiment_id}.journal.json"
                if stale_kind == "temp":
                    journal.with_name(journal.name + ".tmp").write_text(
                        "stale temp\n", encoding="utf-8"
                    )
                else:
                    target = root / "outside"
                    target.write_text("must not be touched\n", encoding="utf-8")
                    journal.symlink_to(target)
                with mock.patch.object(once, "select_exact_recovery") as select, mock.patch.object(
                    once, "run_checked"
                ) as run:
                    with self.assertRaisesRegex(once.BootError, "replay forbidden|symlink"):
                        once.collect(self.args(root))
                select.assert_not_called()
                run.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "evidence" / "private"
            private.mkdir(parents=True)
            stale = private / f"{self.args(root).experiment_id}.journal.json"
            stale.write_text("stale\n", encoding="utf-8")
            with mock.patch.object(once, "select_exact_recovery") as select, mock.patch.object(
                once, "run_checked"
            ) as run:
                with self.assertRaisesRegex(once.BootError, "replay forbidden"):
                    once.collect(self.args(root))
            select.assert_not_called()
            run.assert_not_called()

    def test_exact_endpoint_and_preconditions_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            endpoint = Endpoint()
            runner = FixedRunner()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                selector = stack.enter_context(
                    mock.patch.object(once, "select_exact_recovery", return_value=endpoint)
                )
                stack.enter_context(mock.patch.object(once, "run_checked", side_effect=runner))
                wait = stack.enter_context(mock.patch.object(once, "wait_for_disconnect", return_value=True))
                once.collect(self.args(root, phase="read"))
            self.assertEqual(selector.call_count, 6)
            self.assertEqual(
                [call[-1] for call in runner.calls],
                [
                    "getprop ro.product.model",
                    "getprop ro.product.device",
                    "twrp --help 2>&1",
                    "twrp get tw_gui_done",
                    "cat /proc/sys/kernel/random/boot_id",
                    "getprop ro.product.model",
                    "getprop ro.product.device",
                    "twrp --help 2>&1",
                    "twrp get tw_gui_done",
                    "cat /proc/sys/kernel/random/boot_id",
                    "getprop ro.product.model",
                    "getprop ro.product.device",
                    "twrp --help 2>&1",
                    "twrp get tw_gui_done",
                    "cat /proc/sys/kernel/random/boot_id",
                    once.PREPARATION_COMMAND,
                    once.PREPARATION_READ_COMMAND,
                    "getprop ro.product.model",
                    "getprop ro.product.device",
                    "twrp --help 2>&1",
                    "twrp get tw_gui_done",
                    "cat /proc/sys/kernel/random/boot_id",
                    once.PREPARATION_READ_COMMAND,
                    once.SYNC_COMMAND,
                    "getprop ro.product.model",
                    "getprop ro.product.device",
                    "twrp --help 2>&1",
                    "twrp get tw_gui_done",
                    "cat /proc/sys/kernel/random/boot_id",
                    once.PREPARATION_READ_COMMAND,
                    "getprop ro.product.model",
                    "getprop ro.product.device",
                    "twrp --help 2>&1",
                    "twrp get tw_gui_done",
                    "cat /proc/sys/kernel/random/boot_id",
                    once.PREPARATION_READ_COMMAND,
                    once.EFFECT_COMMAND,
                ],
            )
            wait.assert_called_once_with(
                once.ADB,
                endpoint,
                once.DISCONNECT_TIMEOUT_SEC,
                run=mock.ANY,
            )

    def test_one_preparation_one_effect_and_redacted_durable_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths, runner, _wait = self.run_collect(Path(directory), phase="rollback")
            journal_path, manifest_path = paths
            self.assertEqual(
                [call[-1] for call in runner.calls].count(once.PREPARATION_COMMAND), 1
            )
            self.assertEqual(
                [call[-1] for call in runner.calls].count(once.PREPARATION_READ_COMMAND), 4
            )
            self.assertEqual(
                [call[-1] for call in runner.calls].count(once.EFFECT_COMMAND), 1
            )
            self.assertEqual(
                [call[-1] for call in runner.calls].count(once.SYNC_COMMAND), 1
            )
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(journal["status"], once.SUCCESS_STATUS)
            self.assertEqual(journal["preparation"]["write_count"], 1)
            self.assertEqual(journal["preparation"]["read_count"], 1)
            self.assertEqual(journal["preparation"]["sync"]["write_count"], 1)
            self.assertTrue(journal["preparation"]["sync"]["verified"])
            self.assertEqual(journal["effect"]["command"], once.EFFECT_COMMAND)
            self.assertEqual(journal["effect_dispatch_count"], 1)
            self.assertEqual(journal["dispatch_count"], 1)
            self.assertTrue(journal["effect_dispatched"])
            self.assertFalse(journal["effect_replayed"])
            self.assertTrue(journal["physical_effect_claim"]["claimed"])
            self.assertEqual(
                journal["physical_effect_claim"]["boot_id"], RECOVERY_BOOT_ID
            )
            semantic_boot_id_sha256 = hashlib.sha256(
                RECOVERY_BOOT_ID.encode("utf-8")
            ).hexdigest()
            raw_boot_id_sha256 = hashlib.sha256(
                f"{RECOVERY_BOOT_ID}\n".encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                journal["target"]["boot_id_sha256"], semantic_boot_id_sha256
            )
            self.assertEqual(
                journal["target"]["boot_id_receipt"]["sha256"], raw_boot_id_sha256
            )
            self.assertNotEqual(
                journal["target"]["boot_id_sha256"],
                journal["target"]["boot_id_receipt"]["sha256"],
            )
            self.assertTrue(journal["observation"]["disconnect_observed"])
            self.assertEqual(journal_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o644)
            expected_boot_id_sha256 = hashlib.sha256(
                RECOVERY_BOOT_ID.encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                manifest["target"]["boot_id_sha256"], expected_boot_id_sha256
            )
            self.assertEqual(
                manifest["physical_effect_claim"]["boot_id_sha256"],
                expected_boot_id_sha256,
            )
            rendered = manifest_path.read_text(encoding="utf-8")
            self.assertNotIn(SERIAL, rendered)
            self.assertNotIn(RECOVERY_BOOT_ID, rendered)
            self.assertNotIn("base64", rendered)
            self.assertIn(SERIAL_HASH, rendered)
            self.assertTrue(manifest["raw_serial_omitted"])
            self.assertTrue(manifest["raw_commands_omitted"])
            self.assertFalse(manifest["partition_writes"])
            self.assertEqual(manifest["effect"]["command"], once.EFFECT_COMMAND)

            def assert_no_raw_boot_id(value: object) -> None:
                if isinstance(value, dict):
                    self.assertNotIn("boot_id", value)
                    for nested in value.values():
                        assert_no_raw_boot_id(nested)
                elif isinstance(value, list):
                    for nested in value:
                        assert_no_raw_boot_id(nested)

            assert_no_raw_boot_id(manifest)

    def test_public_manifest_rejects_missing_malformed_or_nonstring_boot_id(self) -> None:
        base = once._initial_journal(
            "verification-024-public-boot-id", "control", "2026-08-28T00:00:00+00:00"
        )
        for value in (None, "not-a-uuid", 17):
            with self.subTest(boot_id=value):
                journal = dict(base)
                journal["target_verified"] = True
                journal["target"] = {
                    "model": once.TARGET_MODEL,
                    "device": once.TARGET_DEVICE,
                    "twrp_version": once.TWRP_VERSION,
                    "serial_sha256": SERIAL_HASH,
                    "state": "recovery",
                }
                if value is not None:
                    journal["target"]["boot_id"] = value
                with self.assertRaisesRegex(once.BootError, "boot_id"):
                    once._public_manifest(journal, b"private-journal")

    def test_public_manifest_never_copies_private_physical_boot_id(self) -> None:
        journal = once._initial_journal(
            "verification-024-public-boot-id-private", "read", "2026-08-28T00:00:00+00:00"
        )
        journal["target_verified"] = True
        journal["target"] = {
            "model": once.TARGET_MODEL,
            "device": once.TARGET_DEVICE,
            "twrp_version": once.TWRP_VERSION,
            "serial_sha256": SERIAL_HASH,
            "state": "recovery",
            "boot_id": RECOVERY_BOOT_ID,
        }
        journal["physical_effect_claim"] = {"boot_id": RECOVERY_BOOT_ID}
        manifest = once._public_manifest(journal, b"private-journal")
        rendered = json.dumps(manifest, sort_keys=True)
        self.assertNotIn(RECOVERY_BOOT_ID, rendered)
        self.assertNotIn('"boot_id":', rendered)
        self.assertEqual(
            manifest["target"]["boot_id_sha256"],
            hashlib.sha256(RECOVERY_BOOT_ID.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            manifest["physical_effect_claim"]["boot_id_sha256"],
            hashlib.sha256(RECOVERY_BOOT_ID.encode("utf-8")).hexdigest(),
        )

    def test_public_manifest_rejects_malformed_or_missing_claim_boot_id(self) -> None:
        for claim in (
            {"claimed": True},
            {"claimed": True, "boot_id": "not-a-uuid"},
            {"claimed": True, "boot_id": 17},
        ):
            with self.subTest(claim=claim):
                journal = once._initial_journal(
                    "verification-024-public-claim-boot-id",
                    "control",
                    "2026-08-28T00:00:00+00:00",
                )
                journal["target_verified"] = True
                journal["target"] = {"boot_id": RECOVERY_BOOT_ID}
                journal["physical_effect_claim"] = claim
                with self.assertRaisesRegex(once.BootError, "boot_id"):
                    once._public_manifest(journal, b"private-journal")

    def test_preparation_timeout_or_bad_readback_stops_without_effect_or_retry(self) -> None:
        class PreparationTimeoutRunner(FixedRunner):
            def __call__(self, argv) -> str:
                if tuple(argv)[-1] == once.PREPARATION_COMMAND:
                    self.calls.append(tuple(argv))
                    raise TimeoutError("preparation timeout")
                return super().__call__(argv)

        for runner in (PreparationTimeoutRunner(), FixedRunner(prep_read="unexpected")):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                    stack.enter_context(mock.patch.object(once, "select_exact_recovery", return_value=Endpoint()))
                    stack.enter_context(mock.patch.object(once, "run_checked", side_effect=runner))
                    with self.assertRaises(once.BootError):
                        once.collect(self.args(root))
                journal = next((root / "evidence" / "private").glob("*.journal.json"))
                record = json.loads(journal.read_text(encoding="utf-8"))
                self.assertEqual(record["preparation"]["write_count"], 1)
                self.assertEqual(record["effect_dispatch_count"], 0)
                self.assertFalse(any(call[-1] == once.EFFECT_COMMAND for call in runner.calls))

    def test_effect_timeout_is_ambiguous_and_never_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FixedRunner(effect_error=TimeoutError("effect timeout"))
            with self.assertRaisesRegex(once.BootError, "ambiguous"):
                self.run_collect(root, runner)
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], once.RECONCILIATION_STATUS)
            self.assertEqual(record["effect_dispatch_count"], 1)
            self.assertEqual(record["dispatch_count"], 1)
            self.assertEqual(
                [call[-1] for call in runner.calls].count(once.EFFECT_COMMAND), 1
            )

    def test_disconnect_success_and_failure_are_bounded_without_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, _runner, wait = self.run_collect(root, wait_result=True)
            self.assertEqual(json.loads(paths[0].read_text())["status"], once.SUCCESS_STATUS)
            wait.assert_called_once()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FixedRunner()
            with self.assertRaisesRegex(once.BootError, "did not disconnect"):
                self.run_collect(root, runner, wait_result=False)
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], once.OBSERVATION_INCOMPLETE_STATUS)
            self.assertEqual(record["effect_dispatch_count"], 1)
            self.assertFalse(record["observation"]["disconnect_observed"])
            self.assertEqual(
                [call[-1] for call in runner.calls].count(once.EFFECT_COMMAND), 1
            )

    def test_wrong_endpoint_identity_fails_before_preconditions(self) -> None:
        class WrongEndpoint:
            serial = "different"
            state = "recovery"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                stack.enter_context(mock.patch.object(once, "select_exact_recovery", return_value=WrongEndpoint()))
                run = stack.enter_context(mock.patch.object(once, "run_checked"))
                with self.assertRaisesRegex(once.BootError, "serial hash"):
                    once.collect(self.args(root))
            run.assert_not_called()

    def test_unverified_failure_manifest_separates_actual_and_expected_target(self) -> None:
        class WrongEndpoint:
            serial = "different"
            state = "recovery"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                stack.enter_context(mock.patch.object(once, "select_exact_recovery", return_value=WrongEndpoint()))
                stack.enter_context(mock.patch.object(once, "run_checked"))
                with self.assertRaises(once.BootError):
                    once.collect(self.args(root))
            manifest_path = next((root / "evidence" / "manifests").glob("*.manifest.json"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertFalse(manifest["preflight"]["target_verified"])
            self.assertFalse(manifest["target_verified"])
            self.assertEqual(manifest["target_evaluation"], "NOT_EVALUATED")
            self.assertIsNone(manifest["target_model"])
            self.assertIsNone(manifest["target_device"])
            self.assertIsNone(manifest["twrp_version"])
            self.assertEqual(manifest["target"]["status"], "NOT_EVALUATED")
            self.assertIsNone(manifest["target"]["model"])
            self.assertIsNone(manifest["target"]["device"])
            self.assertIsNone(manifest["target"]["twrp_version"])
            self.assertIsNone(manifest["target"]["serial_sha256"])
            self.assertEqual(manifest["expected_target"]["model"], once.TARGET_MODEL)
            self.assertEqual(manifest["expected_target"]["device"], once.TARGET_DEVICE)

    def test_preparation_revalidation_drift_refuses_before_any_preparation_write(self) -> None:
        class DriftEndpoint:
            serial = "drifted-recovery"
            state = "recovery"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FixedRunner()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                selector = stack.enter_context(
                    mock.patch.object(
                        once,
                        "select_exact_recovery",
                        side_effect=[Endpoint(), DriftEndpoint()],
                    )
                )
                stack.enter_context(mock.patch.object(once, "run_checked", side_effect=runner))
                with self.assertRaisesRegex(once.BootError, "revalidation"):
                    once.collect(self.args(root))
            commands = [call[-1] for call in runner.calls]
            self.assertEqual(selector.call_count, 2)
            self.assertNotIn(once.PREPARATION_COMMAND, commands)
            self.assertNotIn(once.EFFECT_COMMAND, commands)
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["preparation_write_count"], 0)
            self.assertEqual(record["preparation"]["write_count"], 0)
            self.assertEqual(record["effect_dispatch_count"], 0)
            self.assertFalse(record["revalidation_before_preparation"]["verified"])

    def test_final_revalidation_drift_refuses_after_preparation_before_effect_marker(self) -> None:
        class DriftEndpoint:
            serial = "drifted-recovery"
            state = "recovery"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FixedRunner()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                selector = stack.enter_context(
                    mock.patch.object(
                        once,
                        "select_exact_recovery",
                        side_effect=[
                            Endpoint(),
                            Endpoint(),
                            Endpoint(),
                            Endpoint(),
                            DriftEndpoint(),
                        ],
                    )
                )
                stack.enter_context(mock.patch.object(once, "run_checked", side_effect=runner))
                with self.assertRaisesRegex(once.BootError, "revalidation"):
                    once.collect(self.args(root))
            commands = [call[-1] for call in runner.calls]
            self.assertEqual(selector.call_count, 5)
            self.assertEqual(commands.count(once.PREPARATION_COMMAND), 1)
            self.assertNotIn(once.EFFECT_COMMAND, commands)
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["preparation_write_count"], 1)
            self.assertEqual(record["preparation"]["write_count"], 1)
            self.assertEqual(record["effect_dispatch_count"], 0)
            self.assertFalse(record["revalidation_before_effect"]["verified"])

    def test_sync_marker_revalidation_drift_sends_no_sync_or_effect(self) -> None:
        class DriftEndpoint:
            serial = "drifted-recovery"
            state = "recovery"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FixedRunner()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                selector = stack.enter_context(
                    mock.patch.object(
                        once,
                        "select_exact_recovery",
                        side_effect=[Endpoint(), Endpoint(), Endpoint(), DriftEndpoint()],
                    )
                )
                stack.enter_context(mock.patch.object(once, "run_checked", side_effect=runner))
                with self.assertRaisesRegex(once.BootError, "sync outcome"):
                    once.collect(self.args(root))
            commands = [call[-1] for call in runner.calls]
            self.assertEqual(selector.call_count, 4)
            self.assertEqual(commands.count(once.PREPARATION_COMMAND), 1)
            self.assertNotIn(once.SYNC_COMMAND, commands)
            self.assertNotIn(once.EFFECT_COMMAND, commands)
            record = json.loads(
                next((root / "evidence" / "private").glob("*.journal.json")).read_text()
            )
            self.assertEqual(record["status"], once.SYNC_PREPARATION_RECONCILIATION_STATUS)
            self.assertFalse(record["preparation"]["sync"]["verified"])
            self.assertFalse(record["revalidation_before_sync"]["verified"])
            self.assertEqual(record["effect_dispatch_count"], 0)

    def test_final_revalidation_requires_tw_reboot_arg_system(self) -> None:
        class FinalReadbackRunner(FixedRunner):
            def __init__(self) -> None:
                super().__init__()
                self.reboot_arg_reads = 0

            def __call__(self, argv) -> str:
                if tuple(argv)[-1] == once.PREPARATION_READ_COMMAND:
                    self.calls.append(tuple(argv))
                    self.reboot_arg_reads += 1
                    value = "system" if self.reboot_arg_reads <= 2 else "rollback"
                    self.assert_fixed(tuple(argv))
                    return f"tw_reboot_arg = {value}\n"
                return super().__call__(argv)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FinalReadbackRunner()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(once, "TARGET_SERIAL_SHA256", SERIAL_HASH))
                selector = stack.enter_context(
                    mock.patch.object(
                        once,
                        "select_exact_recovery",
                        side_effect=[Endpoint(), Endpoint(), Endpoint(), Endpoint(), Endpoint()],
                    )
                )
                stack.enter_context(mock.patch.object(once, "run_checked", side_effect=runner))
                with self.assertRaisesRegex(once.BootError, "reboot_arg"):
                    once.collect(self.args(root))
            commands = [call[-1] for call in runner.calls]
            self.assertEqual(selector.call_count, 5)
            self.assertEqual(commands.count(once.PREPARATION_COMMAND), 1)
            self.assertEqual(commands.count(once.PREPARATION_READ_COMMAND), 3)
            self.assertNotIn(once.EFFECT_COMMAND, commands)
            journal = next((root / "evidence" / "private").glob("*.journal.json"))
            record = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(record["preparation_write_count"], 1)
            self.assertEqual(record["effect_dispatch_count"], 0)

    def test_run_text_inherits_finite_timeout_primitive(self) -> None:
        with mock.patch.object(
            twrp.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired((once.ADB, "devices"), 1.0),
        ) as run:
            with self.assertRaisesRegex(twrp.BootError, "timed out"):
                once.run_text((once.ADB, "devices"))
        self.assertEqual(run.call_args.kwargs["timeout"], once.SUBPROCESS_TIMEOUT_SEC)


if __name__ == "__main__":
    unittest.main()
