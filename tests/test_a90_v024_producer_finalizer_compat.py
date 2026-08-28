from __future__ import annotations

import contextlib
import base64
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools import a90_inline_remapper_mid_probe as probe
from tools import a90_last_kmsg_capture as capture
from tools.a90_acm_snapshot import Frame
from tools import a90_twrp_remapper_boot_flash as flash
from tools import a90_verification024_finalize as finalizer


class _ProducerAdb:
    """Mock only the fixed ADB receipts consumed by the real flash owner."""

    def __init__(
        self,
        *,
        profile: str,
        expected_hash: str,
        predecessor: str,
        guard_failure: bool = False,
    ) -> None:
        self.profile = profile
        self.expected_hash = expected_hash
        self.predecessor = predecessor
        self.staging = flash.REMOTE_STAGING_BY_PROFILE[profile]
        self.guard_failure = guard_failure
        self.prefix_hash_calls = 0
        self.write_count = 0
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: object) -> str:
        call = tuple(argv)  # type: ignore[arg-type]
        self.calls.append(call)
        if call[:2] == (flash.ADB, "devices"):
            return "List of devices attached\nserial\trecovery\nother\tdevice\n"
        if (
            len(call) == 6
            and call[:3] == (flash.ADB, "-s", "serial")
            and call[3] == "push"
        ):
            if call[-1] != self.staging:
                raise AssertionError(call)
            return ""
        if call[:3] != (flash.ADB, "-s", "serial") or len(call) < 5 or call[3] != "shell":
            raise AssertionError(call)
        command = call[4]
        if command == "twrp --help 2>&1":
            return (
                "TWRP openrecoveryscript command line tool, "
                f"TWRP version {flash.TWRP_VERSION}\n"
            )
        if command == f"readlink -f {flash.BOOT_BLOCK_ALIAS}":
            return f"{flash.BOOT_BLOCK_RESOLVED}\n"
        if command.startswith("dd if=/dev/block/sda24") and "sha256sum" in command:
            self.prefix_hash_calls += 1
            value = self.expected_hash if self.prefix_hash_calls >= 3 else self.predecessor
            return f"{value}\n"
        if command.startswith("dd if=/dev/block/sda24") and "wc -c" in command:
            return f"{flash.BOOT_PREFIX_SIZE}\n"
        if command == f"sha256sum {self.staging}":
            return f"{self.expected_hash}  {self.staging}\n"
        if command == f"wc -c < {self.staging}":
            return f"{flash.BOOT_PREFIX_SIZE}\n"
        if command.startswith("set -e; "):
            if self.guard_failure:
                return (
                    "A90V024 GUARD_FAIL "
                    f"current_sha256={self.predecessor} current_size={flash.BOOT_PREFIX_SIZE} "
                    f"staging_sha256={'0' * 64} staging_size={flash.BOOT_PREFIX_SIZE}\n"
                )
            self.write_count += 1
            return (
                "A90V024 GUARD_PASS "
                f"current_sha256={self.predecessor} current_size={flash.BOOT_PREFIX_SIZE} "
                f"staging_sha256={self.expected_hash} staging_size={flash.BOOT_PREFIX_SIZE}\n"
                f"A90V024 DD_RESULT rc=0 count={flash.DD_BLOCK_COUNT}\n"
            )
        if command == f"rm -f {self.staging}":
            return ""
        if command == (
            f"if [ -e {self.staging} ] || [ -L {self.staging} ]; then echo present; "
            "else echo absent; fi"
        ):
            return "absent\n"
        raise AssertionError(call)


class ProducerFinalizerCompatibilityTests(unittest.TestCase):
    def tearDown(self) -> None:
        flash.REPO_ROOT = Path(flash.__file__).resolve().parents[1]

    @staticmethod
    def _endpoint() -> object:
        # Keep the endpoint's computed serial hash equal to the production pin
        # while retaining a short, deterministic mock serial in command logs.
        return SimpleNamespace(
            serial="serial",
            state="recovery",
            serial_sha256=flash.TARGET_SERIAL_SHA256,
        )

    @staticmethod
    def _protocol_frame(
        evidence_id: str,
        argv: tuple[str, ...],
        *,
        rc: int,
        status: str,
        message: bytes | None = None,
        duration_ms: int = 0,
        payload: bytes = b"",
    ) -> tuple[dict[str, object], Frame]:
        """Build one native-shaped frame for cross-consumer contract tests."""

        flags = probe.protocol_flags_for_argv(argv)
        if flags is None:
            raise AssertionError(argv)
        errno = -rc if rc < 0 else 0
        command = argv[0].encode("ascii")
        if rc == 0 and status == "ok":
            terminal = b"[done] " + command + f" ({duration_ms}ms)\n".encode("ascii")
        elif rc == -16 and status == "busy":
            terminal = b"[busy] auto menu active; send hide/q before command\n"
        elif rc < 0 and status == "error":
            if message is None:
                message = probe._PROTOCOL_ERRNO_MESSAGES.get(errno)
            if message is None:
                raise AssertionError(errno)
            terminal = (
                b"[err] "
                + command
                + f" rc={rc} errno={errno} (".encode("ascii")
                + message
                + f") ({duration_ms}ms)\n".encode("ascii")
            )
        elif rc > 0 and status == "error":
            terminal = b"[err] " + command + f" rc={rc} ({duration_ms}ms)\n".encode("ascii")
        else:
            raise AssertionError((rc, status))
        begin = {
            "cmd": argv[0],
            "seq": "1",
            "argc": str(len(argv)),
            "flags": flags,
        }
        end = {
            "cmd": argv[0],
            "seq": "1",
            "rc": str(rc),
            "errno": str(errno),
            "duration_ms": str(duration_ms),
            "flags": flags,
            "status": status,
        }
        transcript = (
            b"A90P1 BEGIN seq=1 cmd="
            + command
            + b" argc="
            + str(len(argv)).encode("ascii")
            + b" flags="
            + flags.encode("ascii")
            + b"\n"
            + payload
            + b"\n"
            + terminal
            + b"A90P1 END seq=1 cmd="
            + command
            + f" rc={rc} errno={errno} duration_ms={duration_ms} flags={flags} status={status}\n".encode("ascii")
        )
        record = probe.frame_record(
            evidence_id,
            argv,
            Frame(begin=begin, end=end, payload=payload, transcript=transcript),
        )
        return record, Frame(begin=begin, end=end, payload=payload, transcript=transcript)

    def test_native_result_errno_and_marker_contract_round_trips_all_consumers(self) -> None:
        """Positive rc errors use errno=0; negative text is source-exact."""

        argv = ("run", "/bin/true", "probe")
        positive_record, positive_frame = self._protocol_frame(
            "version_before", ("version",), rc=1, status="error"
        )
        # The producer validator admits a returned positive error only as an
        # incident path; it must not turn that result into a successful frame.
        probe.validate_complete_frame(
            positive_frame,
            ("version",),
            validate_result_semantics=False,
        )
        finalizer._validate_protocol_frame(
            positive_record,
            "version_before",
            ("version",),
            "positive error",
            expected_rc="1",
            expected_status="error",
        )
        capture._validate_source_protocol_frame(
            positive_record,
            "version_before",
            ("version",),
            "positive error",
            expected_rc="1",
            expected_status="error",
        )

        negative_record, negative_frame = self._protocol_frame(
            "version_before", ("version",), rc=-16, status="error"
        )
        probe.validate_complete_frame(
            negative_frame,
            ("version",),
            validate_result_semantics=False,
        )
        finalizer._validate_protocol_frame(
            negative_record,
            "version_before",
            ("version",),
            "negative error",
            expected_rc="-16",
            expected_status="error",
        )
        capture._validate_source_protocol_frame(
            negative_record,
            "version_before",
            ("version",),
            "negative error",
            expected_rc="-16",
            expected_status="error",
        )

        forged_record, forged_frame = self._protocol_frame(
            "version_before",
            ("version",),
            rc=-16,
            status="error",
            message=b"FORGED",
        )
        for consumer in (
            lambda: probe.validate_complete_frame(
                forged_frame,
                ("version",),
                validate_result_semantics=False,
            ),
            lambda: finalizer._validate_protocol_frame(
                forged_record,
                "version_before",
                ("version",),
                "forged negative error",
                expected_rc="-16",
                expected_status="error",
            ),
            lambda: capture._validate_source_protocol_frame(
                forged_record,
                "version_before",
                ("version",),
                "forged negative error",
                expected_rc="-16",
                expected_status="error",
            ),
        ):
            with self.assertRaises((probe.ProbeError, finalizer.FinalizeError, ValueError)):
                consumer()

    def test_controller_busy_duration_is_exactly_zero_in_all_consumers(self) -> None:
        record, frame = self._protocol_frame(
            "stophud_1", ("stophud",), rc=-16, status="busy", duration_ms=1
        )
        for consumer in (
            lambda: probe.validate_complete_frame(
                frame, ("stophud",), allow_stophud_busy=True
            ),
            lambda: finalizer._validate_protocol_frame(
                record,
                "stophud_1",
                ("stophud",),
                "busy duration",
                expected_rc="-16",
                expected_status="busy",
            ),
            lambda: capture._validate_source_protocol_frame(
                record,
                "stophud_1",
                ("stophud",),
                "busy duration",
                expected_rc="-16",
                expected_status="busy",
            ),
        ):
            with self.assertRaises((probe.ProbeError, finalizer.FinalizeError, ValueError)):
                consumer()

    def test_real_inline_frame_serializer_accepts_complete_end_for_each_panic_frame(self) -> None:
        """Bind the consumers to the producer's actual frame serializer."""

        panic_payloads = {
            "panic_before": b"1\n",
            "panic_set_0": b"",
            "panic_zero_verify": b"0\n",
        }
        records: list[dict[str, object]] = []
        for evidence_id in finalizer._expected_full_frame_ids(
            1, allow_fixed=False, restored=False
        ):
            argv = finalizer._frame_expected_argv(evidence_id)
            if evidence_id == "boot_attest_mknod":
                argv = ("mknodb", "/tmp/a90-native/verification-024-sda24", "259", "8")
            assert argv is not None
            protocol_flags = finalizer.inline_protocol_flags_for_argv(argv)
            assert protocol_flags is not None
            payload = panic_payloads.get(evidence_id, b"")
            if evidence_id.startswith("stophud_"):
                payload = b"autohud: stopped"
            transcript = (
                b"A90P1 BEGIN seq=1 cmd="
                + argv[0].encode("ascii")
                + b" argc=" + str(len(argv)).encode("ascii") + b" flags=" + protocol_flags.encode("ascii") + b"\n"
                + payload
                + f"\n[done] {argv[0]} (0ms)\nA90P1 END seq=1 cmd=".encode("ascii")
                + argv[0].encode("ascii")
                + b" rc=0 errno=0 duration_ms=0 flags=" + protocol_flags.encode("ascii") + b" status=ok\n"
            )
            frame = Frame(
                begin={"seq": "1", "cmd": argv[0], "argc": str(len(argv)), "flags": finalizer.inline_protocol_flags_for_argv(argv)},
                end={"seq": "1", "cmd": argv[0], "rc": "0", "errno": "0", "duration_ms": "0", "flags": finalizer.inline_protocol_flags_for_argv(argv), "status": "ok"},
                payload=payload,
                transcript=transcript,
            )
            records.append(probe.frame_record(evidence_id, argv, frame))
        finalizer._validate_frame_list(
            records, "actual inline producer frames", restored=False, allow_fixed=False
        )
        capture._validate_source_frame_list(records, "actual inline producer frames")
        stophud_record = next(
            record for record in records if record["evidence_id"] == "stophud_1"
        )
        self.assertEqual(
            base64.b64decode(stophud_record["payload_base64"]),
            b"autohud: stopped",
        )
        for success_payload in (b"autohud: stopped", b"autohud: not running"):
            with self.subTest(success_payload=success_payload):
                record, frame = self._protocol_frame(
                    "stophud_1",
                    ("stophud",),
                    rc=0,
                    status="ok",
                    payload=success_payload,
                )
                probe.validate_complete_frame(
                    frame, ("stophud",), allow_stophud_busy=True
                )
                finalizer._validate_protocol_frame(
                    record,
                    "stophud_1",
                    ("stophud",),
                    "exact stophud success",
                )
                capture._validate_source_protocol_frame(
                    record,
                    "stophud_1",
                    ("stophud",),
                    "exact stophud success",
                )

    @staticmethod
    def _profiles(image: Path) -> dict[str, dict[str, object]]:
        return {
            "control": {
                "path": image,
                "sha256": flash.CONTROL_SHA256,
                "allowed_predecessors": {flash.ROLLBACK_SHA256},
            },
            "read": {
                "path": image,
                "sha256": flash.READ_SHA256,
                "allowed_predecessors": {flash.CONTROL_SHA256},
            },
            "rollback": {
                "path": image,
                "sha256": flash.ROLLBACK_SHA256,
                "allowed_predecessors": {flash.CONTROL_SHA256, flash.READ_SHA256},
            },
        }

    def _run_real_flash(
        self,
        root: Path,
        profile: str,
        *,
        guard_failure: bool = False,
    ) -> tuple[Path, _ProducerAdb]:
        image = root / f"{profile}.img"
        image.write_bytes(b"mock producer image")
        expected_hash = {
            "control": flash.CONTROL_SHA256,
            "read": flash.READ_SHA256,
            "rollback": flash.ROLLBACK_SHA256,
        }[profile]
        predecessor = {
            "control": flash.ROLLBACK_SHA256,
            "read": flash.CONTROL_SHA256,
            "rollback": flash.READ_SHA256,
        }[profile]
        fake = _ProducerAdb(
            profile=profile,
            expected_hash=expected_hash,
            predecessor=predecessor,
            guard_failure=guard_failure,
        )
        endpoint = self._endpoint()
        flash.REPO_ROOT = root
        args = Namespace(profile=profile, execute=True)
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(flash, "profile_table", return_value=self._profiles(image))
            )
            stack.enter_context(
                mock.patch.object(
                    flash,
                    "_stable_file_digest",
                    return_value=(flash.BOOT_PREFIX_SIZE, expected_hash),
                )
            )
            stack.enter_context(mock.patch.object(flash, "run_checked", side_effect=fake))
            stack.enter_context(
                mock.patch.object(flash, "select_exact_recovery", return_value=endpoint)
            )
            try:
                path = flash.flash(args)
            except flash.FlashError:
                if not guard_failure:
                    raise
                path = root / "evidence/private" / (
                    f"verification-024-remapper-boot-flash-{profile}.journal.json"
                )
        return path, fake

    def test_real_control_and_read_flash_outputs_validate_as_consumer_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control_path, control_fake = self._run_real_flash(root, "control")
            read_path, read_fake = self._run_real_flash(root, "read")
            rollback_path, rollback_fake = self._run_real_flash(root, "rollback")
            self.assertEqual(control_fake.write_count, 1)
            self.assertEqual(read_fake.write_count, 1)
            self.assertEqual(rollback_fake.write_count, 1)
            for profile, path, predecessor in (
                ("control", control_path, finalizer.ROLLBACK_SHA256),
                ("read", read_path, finalizer.CONTROL_SHA256),
            ):
                with self.subTest(profile=profile):
                    receipt = probe.verify_flash_journal(path, profile, root=root)
                    self.assertEqual(receipt["predecessor_sha256"], predecessor)
                    binding = {
                        "path": str(path),
                        "sha256": receipt["sha256"],
                        "size": receipt["size"],
                        "profile": profile,
                        "image_sha256": receipt["image_sha256"],
                        "readback_sha256": receipt["readback_sha256"],
                        "predecessor_sha256": receipt["predecessor_sha256"],
                    }
                    self.assertEqual(
                        finalizer._validate_flash_reference(
                            binding,
                            profile=profile,
                            expected_predecessor=predecessor,
                            root=root,
                            label=f"{profile} producer",
                        ),
                        binding,
                    )
            rollback = finalizer.validate_rollback_flash(rollback_path, root)
            self.assertEqual(rollback["predecessor_sha256"], finalizer.READ_SHA256)

    def test_real_rollback_ambiguous_output_is_the_only_torn_source_edge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, fake = self._run_real_flash(root, "rollback", guard_failure=True)
            self.assertEqual(fake.write_count, 0)
            source = json.loads(path.read_text())
            self.assertEqual(source["profile"], "rollback")
            self.assertEqual(source["predecessor_sha256"], finalizer.READ_SHA256)
            self.assertEqual(source["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED")
            final_source = finalizer._validate_ambiguous_source(
                source,
                "real rollback producer",
                source_path=path,
                root=root,
            )
            self.assertEqual(final_source["profile"], "rollback")
            self.assertEqual(final_source["predecessor_sha256"], finalizer.READ_SHA256)

    def test_real_rollback_ambiguous_then_recovery_continuation_validates_end_to_end(self) -> None:
        """Consume the real ambiguous flash journal through real recovery output."""

        from tests.test_a90_twrp_boot_rollback_recovery import FakeAdb
        from tools import a90_twrp_boot_rollback_recovery as recovery

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path, _ = self._run_real_flash(
                root, "rollback", guard_failure=True
            )
            image = root / "rollback.img"
            image.write_bytes(b"mock recovery rollback image")
            fake = FakeAdb(current_hash=finalizer.READ_SHA256)
            endpoint = SimpleNamespace(
                serial="serial",
                state="recovery",
                serial_sha256=finalizer.TARGET_SERIAL_SHA256,
            )
            args = Namespace(
                experiment_id="torn-final",
                flash_journal=str(source_path),
                execute=True,
            )
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(recovery, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(recovery, "ROLLBACK_IMAGE", image)
                )
                stack.enter_context(
                    mock.patch.object(
                        recovery, "select_exact_recovery", return_value=endpoint
                    )
                )
                stack.enter_context(
                    mock.patch.object(recovery, "run_checked", side_effect=fake)
                )
                stack.enter_context(
                    mock.patch.object(
                        recovery,
                        "_stable_image_digest",
                        return_value=(
                            recovery.BOOT_PREFIX_SIZE,
                            recovery.ROLLBACK_SHA256,
                        ),
                    )
                )
                recovery_path, _ = recovery.collect(args)
            recovery_private = json.loads(recovery_path.read_text())
            physical = recovery_private["physical_effect_claim"]
            self.assertTrue(physical["continued_from_normal_ambiguous"])
            self.assertEqual(
                recovery_private["source_profile"], "rollback"
            )
            self.assertEqual(
                recovery_private["source_evidence"]["predecessor_sha256"],
                finalizer.READ_SHA256,
            )
            receipt = finalizer.validate_rollback_flash(recovery_path, root)
            self.assertTrue(receipt["rescue_terminal"])
            self.assertEqual(receipt["predecessor_sha256"], finalizer.READ_SHA256)

    def test_system_producer_serializer_round_trips_through_finalizer_and_private_hashes(self) -> None:
        from tools import a90_twrp_system_boot_once as system
        from tests.test_a90_verification024_finalize import Verification024FinalizerTests

        fixture = Verification024FinalizerTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        private_path = fixture.system_boot
        journal = json.loads(private_path.read_text())
        boot_id = journal["target"]["boot_id"]
        endpoint = SimpleNamespace(
            serial="serial",
            state="recovery",
            serial_sha256=finalizer.TARGET_SERIAL_SHA256,
        )

        def target_runner(argv: object) -> str:
            call = tuple(argv)  # type: ignore[arg-type]
            command = call[-1] if call else ""
            if command == "getprop ro.product.model":
                return f"{system.TARGET_MODEL}\n"
            if command == "getprop ro.product.device":
                return f"{system.TARGET_DEVICE}\n"
            if command == "twrp --help 2>&1":
                return f"TWRP openrecoveryscript command line tool, TWRP version {system.TWRP_VERSION}\n"
            if command == "twrp get tw_gui_done":
                return "tw_gui_done = 0\n"
            if command == "cat /proc/sys/kernel/random/boot_id":
                return f"{boot_id}\n"
            if command == "twrp get tw_reboot_arg":
                return "tw_reboot_arg = system\n"
            raise AssertionError(call)

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(system, "select_exact_recovery", return_value=endpoint)
            )
            # The fake serial is intentionally short; retain the producer's
            # real endpoint/hash validation while making its test identity
            # deterministic and device-free.
            stack.enter_context(
                mock.patch.object(
                    system,
                    "_endpoint_hash",
                    return_value=finalizer.TARGET_SERIAL_SHA256,
                )
            )
            _, collected_target = system.preflight_recovery(
                system.ADB, run=target_runner
            )
            _, collected_reboot_target = system.preflight_recovery(
                system.ADB, run=target_runner, require_reboot_arg=True
            )
        self.assertEqual(collected_target["boot_id"], boot_id)
        self.assertEqual(collected_target["boot_id_receipt"]["base64"], base64.b64encode(f"{boot_id}\n".encode("ascii")).decode("ascii"))
        journal["target"] = collected_target
        for key in (
            "revalidation_before_preparation",
            "revalidation_after_preparation_marker",
            "revalidation_before_sync",
            "revalidation_before_effect",
            "revalidation_after_effect_marker",
        ):
            require_arg = key in {
                "revalidation_before_sync",
                "revalidation_before_effect",
                "revalidation_after_effect_marker",
            }
            journal[key]["target"] = (
                collected_reboot_target if require_arg else collected_target
            )
            journal[key]["require_reboot_arg"] = require_arg
            if require_arg:
                journal[key]["tw_reboot_arg"] = "system"
        boot_hash = collected_target["boot_id_sha256"]
        private_bytes = fixture._write(private_path, journal)
        public = system._public_manifest(journal, private_bytes)
        public_path = fixture.root / "evidence/manifests" / (
            f"{finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID}.manifest.json"
        )
        fixture._write(public_path, public)
        self.assertEqual(public["experiment_id"], finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID)
        self.assertEqual(public["target"]["boot_id_sha256"], boot_hash)
        self.assertEqual(public["physical_effect_claim"]["boot_id_sha256"], boot_hash)
        self.assertNotIn('"boot_id":', json.dumps(public))
        self.assertEqual(
            finalizer.validate_system_boot(private_path, fixture.root)["experiment_id"],
            finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID,
        )

        forged = json.loads(json.dumps(public))
        forged["target"]["boot_id_sha256"] = "0" * 64
        fixture._write(public_path, forged)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_system_boot(private_path, fixture.root)

        forged = json.loads(json.dumps(public))
        forged["physical_effect_claim"]["boot_id_sha256"] = "1" * 64
        fixture._write(public_path, forged)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_system_boot(private_path, fixture.root)

        forged = json.loads(json.dumps(public))
        forged["physical_effect_claim"]["boot_id"] = boot_id
        fixture._write(public_path, forged)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_system_boot(private_path, fixture.root)

        forged = json.loads(json.dumps(public))
        forged["target"]["boot_id"] = boot_id
        fixture._write(public_path, forged)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_system_boot(private_path, fixture.root)

        forged_private = json.loads(json.dumps(journal))
        forged_private["revalidation_before_sync"]["target"]["boot_id_sha256"] = "1" * 64
        forged_private_bytes = fixture._write(private_path, forged_private)
        fixture._write(
            public_path,
            system._public_manifest(forged_private, forged_private_bytes),
        )
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_system_boot(private_path, fixture.root)


if __name__ == "__main__":
    unittest.main()
