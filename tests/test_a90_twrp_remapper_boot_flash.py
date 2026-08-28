from __future__ import annotations

import contextlib
import json
import os
import subprocess
import tempfile
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from tools import a90_twrp_boot_rollback_recovery as rollback
from tools import a90_twrp_remapper_boot_flash as flash
from tools import a90_v024_physical_claim as claims
from tools.a90_twrp_system_boot import AdbEndpoint


class FakeAdb:
    """Fixed-output ADB transport; no command reaches a real device."""

    def __init__(
        self,
        expected_hash: str,
        *,
        before_hash: str,
        post_hash: str | None = None,
        post_staging_hash: str | None = None,
        mutate_staging_after_marker: bool = False,
        remote_staging: str = flash.REMOTE_STAGING,
    ) -> None:
        self.expected_hash = expected_hash
        self.before_hash = before_hash
        self.post_hash = post_hash or expected_hash
        self.post_staging_hash = post_staging_hash or before_hash
        self.mutate_staging_after_marker = mutate_staging_after_marker
        self.remote_staging = remote_staging
        self.commands: list[tuple[str, ...]] = []
        self.write_count = 0
        self.remote_hash_count = 0
        self.readback_count = 0

    def __call__(self, argv) -> str:
        call = tuple(argv)
        self.commands.append(call)
        if call[:2] == (flash.ADB, "devices"):
            return "List of devices attached\nserial\trecovery\nother\tdevice\n"
        if len(call) >= 5 and call[3] == "push" and call[-1] == self.remote_staging:
            return ""
        if call[:3] == (flash.ADB, "-s", "serial") and call[3] == "shell":
            command = call[4]
            if command == "twrp --help 2>&1":
                return (
                    "TWRP openrecoveryscript command line tool, "
                    f"TWRP version {flash.TWRP_VERSION}\n"
                )
            if command == f"readlink -f {flash.BOOT_BLOCK_ALIAS}":
                return f"{flash.BOOT_BLOCK_RESOLVED}\n"
            if command.startswith("dd if=/dev/block/sda24") and "sha256sum" in command:
                self.readback_count += 1
                if self.readback_count == 1:
                    value = self.before_hash
                elif self.readback_count == 2:
                    value = self.post_staging_hash
                else:
                    value = self.post_hash
                return f"{value}\n"
            if command.startswith("dd if=/dev/block/sda24") and "wc -c" in command:
                return f"{flash.BOOT_PREFIX_SIZE}\n"
            if command == f"sha256sum {self.remote_staging}":
                self.remote_hash_count += 1
                if self.mutate_staging_after_marker and self.remote_hash_count >= 2:
                    return f"{'0' * 64}  {self.remote_staging}\n"
                return f"{self.expected_hash}  {self.remote_staging}\n"
            if command == f"wc -c < {self.remote_staging}":
                return f"{flash.BOOT_PREFIX_SIZE}\n"
            if command.startswith("set -e; "):
                self.remote_hash_count += 1
                if self.mutate_staging_after_marker:
                    return (
                        "A90V024 GUARD_FAIL "
                        f"current_sha256={self.before_hash} current_size={flash.BOOT_PREFIX_SIZE} "
                        f"staging_sha256={'0' * 64} staging_size={flash.BOOT_PREFIX_SIZE}\n"
                    )
                self.write_count += 1
                return (
                    "A90V024 GUARD_PASS "
                    f"current_sha256={self.before_hash} current_size={flash.BOOT_PREFIX_SIZE} "
                    f"staging_sha256={self.expected_hash} staging_size={flash.BOOT_PREFIX_SIZE}\n"
                    f"A90V024 DD_RESULT rc=0 count={flash.DD_BLOCK_COUNT}\n"
                )
            if command.startswith(f"dd if={self.remote_staging} of="):
                self.write_count += 1
                return ""
            if command == f"rm -f {self.remote_staging}":
                return ""
            if command == (
                f"if [ -e {self.remote_staging} ] || [ -L {self.remote_staging} ]; then echo present; "
                "else echo absent; fi"
            ):
                return "absent\n"
        raise AssertionError(call)


class TwrpRemapperBootFlashTests(unittest.TestCase):
    def tearDown(self) -> None:
        flash.REPO_ROOT = Path(flash.__file__).resolve().parents[1]

    @staticmethod
    def _journal_path(root: Path, profile: str = "control") -> Path:
        return root / "evidence/private" / (
            f"verification-024-remapper-boot-flash-{profile}.journal.json"
        )

    def test_run_text_uses_fixed_timeout_and_maps_timeout_to_flash_error(self) -> None:
        with mock.patch.object(
            flash.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired((flash.ADB, "devices"), 1.0),
        ) as run:
            with self.assertRaisesRegex(flash.FlashError, "timed out"):
                flash.run_text((flash.ADB, "devices"))
        self.assertEqual(run.call_args.kwargs["timeout"], flash.SUBPROCESS_TIMEOUT_SEC)

    def _args(self, root: Path, profile: str = "control") -> Namespace:
        # Internal embedding seam: production ``flash`` always resolves its
        # journal below the module's fixed REPO_ROOT.
        flash.REPO_ROOT = root
        return Namespace(
            profile=profile,
            execute=True,
        )

    def _profile_patch(self, image: Path, image_hash: str = flash.CONTROL_SHA256):
        return {
            "control": {
                "path": image,
                "sha256": image_hash,
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

    def _run_flash(
        self, root: Path, fake: FakeAdb, *, profile: str = "control"
    ) -> Path:
        image = root / "candidate.img"
        image.write_bytes(b"candidate")
        endpoint = AdbEndpoint("serial", "recovery")
        expected_hash = {
            "control": flash.CONTROL_SHA256,
            "read": flash.READ_SHA256,
            "rollback": flash.ROLLBACK_SHA256,
        }[profile]
        profiles = self._profile_patch(image, expected_hash)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(flash, "profile_table", return_value=profiles))
            stack.enter_context(
                mock.patch.object(
                    flash,
                    "_stable_file_digest",
                    return_value=(flash.BOOT_PREFIX_SIZE, expected_hash),
                )
            )
            stack.enter_context(mock.patch.object(flash, "run_checked", side_effect=fake))
            stack.enter_context(mock.patch.object(flash, "select_exact_recovery", return_value=endpoint))
            stack.enter_context(mock.patch.object(flash, "TARGET_SERIAL_SHA256", endpoint.serial_sha256))
            return flash.flash(self._args(root, profile=profile))

    def test_exact_geometry_hashes_and_predecessor_matrix(self) -> None:
        self.assertEqual(flash.BOOT_PREFIX_SIZE, 60_882_944)
        self.assertEqual(flash.DD_BLOCK_SIZE * flash.DD_BLOCK_COUNT, flash.BOOT_PREFIX_SIZE)
        self.assertEqual((flash.DD_BLOCK_SIZE, flash.DD_BLOCK_COUNT), (4096, 14864))
        self.assertEqual(flash.BOOT_BLOCK_ALIAS, "/dev/block/by-name/boot")
        self.assertEqual(flash.BOOT_BLOCK_RESOLVED, "/dev/block/sda24")
        self.assertEqual(
            {
                "control": flash.CONTROL_SHA256,
                "read": flash.READ_SHA256,
                "rollback": flash.ROLLBACK_SHA256,
            },
            {
                "control": "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247",
                "read": "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed",
                "rollback": "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb",
            },
        )
        profiles = flash.profile_table(Path("/tmp"))
        self.assertEqual(profiles["control"]["allowed_predecessors"], {flash.ROLLBACK_SHA256})
        self.assertEqual(profiles["read"]["allowed_predecessors"], {flash.CONTROL_SHA256})
        self.assertEqual(
            profiles["rollback"]["allowed_predecessors"],
            {flash.CONTROL_SHA256, flash.READ_SHA256},
        )

    def test_parser_constructs_with_repo_default(self) -> None:
        parser = flash.make_parser()
        args = parser.parse_args(["--profile", "control", "--execute"])
        self.assertEqual(args.profile, "control")
        self.assertTrue(args.execute)
        for option in ("--adb", "--journal", "--receipt", "--output-root"):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--profile", "control", "--execute", option, "x"])

    def test_injected_nonfixed_adb_is_refused_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root)
            args.adb = "adb"
            with mock.patch.object(flash, "_stable_file_digest") as digest, mock.patch.object(
                flash, "run_checked"
            ) as contact:
                with self.assertRaisesRegex(flash.FlashError, "fixed adb"):
                    flash.flash(args)
            digest.assert_not_called()
            contact.assert_not_called()

    def test_initial_journal_claim_race_has_one_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence" / "private" / "same.journal.json"
            gate = threading.Barrier(2)
            results: list[str] = []

            def owner(label: str) -> None:
                gate.wait()
                try:
                    flash._create_initial_json(path, {"owner": label})
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

    def test_execute_gate_rejects_omission_before_any_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root)
            args.execute = False
            with mock.patch.object(flash, "_stable_file_digest") as digest, mock.patch.object(
                flash, "run_checked"
            ) as contact:
                with self.assertRaisesRegex(flash.FlashError, "--execute"):
                    flash.flash(args)
            digest.assert_not_called()
            contact.assert_not_called()

    def test_nonpinned_adb_transport_fails_before_hash_or_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root)
            args.adb = "/tmp/other-adb"
            with mock.patch.object(flash, "_stable_file_digest") as digest, mock.patch.object(
                flash, "run_checked"
            ) as contact:
                with self.assertRaisesRegex(flash.FlashError, "fixed adb"):
                    flash.flash(args)
            digest.assert_not_called()
            contact.assert_not_called()

    def test_local_image_reader_rejects_symlink_parent_and_toctou(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            image = real / "candidate.img"
            image.write_bytes(b"candidate")
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(flash.FlashError, "parent component"):
                flash._stable_file_digest(link / "candidate.img")
            original_fstat = flash.os.fstat
            calls = 0

            def changing_fstat(fd):
                nonlocal calls
                calls += 1
                value = original_fstat(fd)
                if calls == 2:
                    fields = list(value)
                    fields[6] += 1  # st_size
                    return os.stat_result(fields)
                return value

            with mock.patch.object(flash.os, "fstat", side_effect=changing_fstat):
                with self.assertRaisesRegex(flash.FlashError, "changed"):
                    flash._stable_file_digest(image)

    def test_success_is_one_write_no_reboot_and_complete_rebind_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(flash.CONTROL_SHA256, before_hash=flash.ROLLBACK_SHA256)
            path = self._run_flash(root, fake)
            self.assertEqual(fake.write_count, 1)
            self.assertFalse(any("reboot" in part for call in fake.commands for part in call))
            journal = json.loads(path.read_text())
            self.assertEqual(journal["status"], flash.PASS_READBACK_AND_CLEANUP)
            self.assertEqual(journal["write_count"], 1)
            self.assertEqual(journal["image_size"], flash.BOOT_PREFIX_SIZE)
            self.assertEqual(journal["allowed_predecessors"], [flash.ROLLBACK_SHA256])
            self.assertEqual(
                journal["effect_argv"],
                [
                    "dd", "if=/tmp/sdm855-remapper-boot.img", "of=/dev/block/sda24",
                    "bs=4096", "count=14864", "conv=fsync",
                ],
            )
            self.assertEqual(journal["remote_staging"], flash.REMOTE_STAGING)
            self.assertEqual(journal["remote_staging_sha256"], flash.CONTROL_SHA256)
            self.assertEqual(journal["remote_staging_size"], flash.BOOT_PREFIX_SIZE)
            self.assertEqual(
                journal["post_staging_predecessor_sha256"], flash.ROLLBACK_SHA256
            )
            self.assertEqual(
                journal["post_staging_predecessor_size"], flash.BOOT_PREFIX_SIZE
            )
            self.assertTrue(journal["post_staging_predecessor_revalidated"])
            self.assertEqual(
                journal["guarded_effect_receipt"],
                {
                    "schema": flash.GUARDED_EFFECT_SCHEMA,
                    "guard": {
                        "current_sha256": flash.ROLLBACK_SHA256,
                        "current_size": str(flash.BOOT_PREFIX_SIZE),
                        "staging_sha256": flash.CONTROL_SHA256,
                        "staging_size": str(flash.BOOT_PREFIX_SIZE),
                    },
                    "dd_result": {"rc": "0", "count": str(flash.DD_BLOCK_COUNT)},
                    "write_count": 1,
                },
            )
            self.assertEqual(
                journal["post_dispatch_predecessor_sha256"], flash.ROLLBACK_SHA256
            )
            self.assertEqual(
                journal["post_dispatch_predecessor_size"], flash.BOOT_PREFIX_SIZE
            )
            self.assertEqual(
                journal["post_dispatch_staging_sha256"], flash.CONTROL_SHA256
            )
            self.assertEqual(
                journal["post_dispatch_staging_size"], flash.BOOT_PREFIX_SIZE
            )
            self.assertTrue(journal["post_dispatch_revalidated"])
            self.assertTrue(journal["final_revalidated"])
            self.assertIsNone(journal["cleanup_error"])
            self.assertIsNone(journal["pre_cleanup_error"])

    def test_staging_attempt_is_durable_before_push(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(flash.CONTROL_SHA256, before_hash=flash.ROLLBACK_SHA256)
            image = root / "candidate.img"
            image.write_bytes(b"candidate")
            endpoint = AdbEndpoint("serial", "recovery")
            profiles = self._profile_patch(image)
            statuses: list[tuple[str, bool]] = []
            real_atomic = flash._atomic_json

            def record_atomic(path, value, mode=0o600):
                if isinstance(value, dict):
                    statuses.append((str(value.get("status")), bool(value.get("staging_attempted"))))
                return real_atomic(path, value, mode)

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(flash, "profile_table", return_value=profiles))
                stack.enter_context(mock.patch.object(flash, "_stable_file_digest", return_value=(flash.BOOT_PREFIX_SIZE, flash.CONTROL_SHA256)))
                stack.enter_context(mock.patch.object(flash, "run_checked", side_effect=fake))
                stack.enter_context(mock.patch.object(flash, "select_exact_recovery", return_value=endpoint))
                stack.enter_context(mock.patch.object(flash, "TARGET_SERIAL_SHA256", endpoint.serial_sha256))
                stack.enter_context(mock.patch.object(flash, "_atomic_json", side_effect=record_atomic))
                flash.flash(self._args(root))
            push_index = next(
                index
                for index, call in enumerate(fake.commands)
                if len(call) >= 5 and call[3] == "push"
            )
            # The durable revision immediately preceding push must carry the
            # attempt marker; transport command ordering is independently
            # checked against the recorder.
            self.assertTrue(any(attempted for _status, attempted in statuses))
            self.assertTrue(statuses[-1][1] or any(status == "STAGING_PUSH_STARTED" and attempted for status, attempted in statuses))
            journal = json.loads(self._journal_path(root).read_text())
            self.assertTrue(journal["staging_attempted"])
            self.assertEqual(journal["staging_attempt_count"], 1)

    def test_wrong_predecessor_refuses_before_push(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(flash.CONTROL_SHA256, before_hash=flash.READ_SHA256)
            image = root / "candidate.img"
            image.write_bytes(b"candidate")
            endpoint = AdbEndpoint("serial", "recovery")
            profiles = self._profile_patch(image)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(flash, "profile_table", return_value=profiles))
                stack.enter_context(mock.patch.object(flash, "_stable_file_digest", return_value=(flash.BOOT_PREFIX_SIZE, flash.CONTROL_SHA256)))
                stack.enter_context(mock.patch.object(flash, "run_checked", side_effect=fake))
                stack.enter_context(mock.patch.object(flash, "select_exact_recovery", return_value=endpoint))
                stack.enter_context(mock.patch.object(flash, "TARGET_SERIAL_SHA256", endpoint.serial_sha256))
                with self.assertRaises(flash.FlashError):
                    flash.flash(self._args(root))
            self.assertEqual(fake.write_count, 0)
            journal = json.loads(self._journal_path(root).read_text())
            self.assertEqual(journal["status"], "REFUSED_PRE_EFFECT")

    def test_stale_predecessor_after_staging_refuses_before_effect_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(
                flash.CONTROL_SHA256,
                before_hash=flash.ROLLBACK_SHA256,
                post_staging_hash=flash.READ_SHA256,
            )
            with self.assertRaises(flash.FlashError):
                self._run_flash(root, fake)
            self.assertEqual(fake.write_count, 0)
            self.assertFalse(
                any(
                    len(call) >= 5
                    and call[3] == "shell"
                    and call[4].startswith("set -e; ")
                    for call in fake.commands
                )
            )
            journal = json.loads(self._journal_path(root).read_text())
            self.assertEqual(journal["status"], "REFUSED_PRE_EFFECT")
            self.assertEqual(journal["post_staging_predecessor_sha256"], flash.READ_SHA256)
            self.assertFalse(journal["effect_dispatched"])

    def test_profile_staging_paths_are_distinct_and_guarded(self) -> None:
        self.assertEqual(
            flash._remote_staging_for_profile("control"), flash.REMOTE_STAGING
        )
        self.assertNotEqual(
            flash._remote_staging_for_profile("control"),
            flash._remote_staging_for_profile("read"),
        )
        self.assertNotEqual(
            flash._remote_staging_for_profile("read"),
            flash._remote_staging_for_profile("rollback"),
        )
        command = flash._guarded_effect_command(
            remote_staging=flash._remote_staging_for_profile("read"),
            expected_predecessor_sha256=flash.CONTROL_SHA256,
            expected_staging_sha256=flash.READ_SHA256,
        )
        self.assertIn(
            f"sha256sum {flash._remote_staging_for_profile('read')}", command
        )
        self.assertIn(
            f"dd if={flash._remote_staging_for_profile('read')} of=",
            command,
        )

    def test_post_marker_staging_mutation_has_no_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(
                flash.CONTROL_SHA256,
                before_hash=flash.ROLLBACK_SHA256,
                mutate_staging_after_marker=True,
            )
            with self.assertRaises(flash.FlashError):
                self._run_flash(root, fake)
            self.assertEqual(fake.write_count, 0)
            journal = json.loads(self._journal_path(root).read_text())
            self.assertEqual(journal["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED")
            self.assertEqual(journal["write_count"], 1)
            self.assertEqual(journal["current_state"], "UNKNOWN")
            self.assertTrue(journal["staging_cleanup_deferred"])
            self.assertTrue(journal["reconcile_required"])
            self.assertEqual(journal["remote_staging"], flash.REMOTE_STAGING)
            self.assertEqual(journal["remote_staging_sha256"], flash.CONTROL_SHA256)
            self.assertEqual(journal["remote_staging_size"], flash.BOOT_PREFIX_SIZE)
            self.assertEqual(
                journal["post_staging_predecessor_sha256"], flash.ROLLBACK_SHA256
            )
            self.assertEqual(
                journal["post_staging_predecessor_size"], flash.BOOT_PREFIX_SIZE
            )
            self.assertTrue(journal["post_staging_predecessor_revalidated"])
            self.assertNotIn("guarded_effect_receipt", journal)
            for key in (
                "post_dispatch_predecessor_sha256",
                "post_dispatch_predecessor_size",
                "post_dispatch_staging_sha256",
                "post_dispatch_staging_size",
            ):
                self.assertNotIn(key, journal)
            cleanup_commands = [
                call for call in fake.commands
                if len(call) >= 5
                and call[3] == "shell"
                and call[4] in {
                    f"rm -f {flash.REMOTE_STAGING}",
                    f"if [ -e {flash.REMOTE_STAGING} ] || [ -L {flash.REMOTE_STAGING} ]; then echo present; else echo absent; fi",
                }
            ]
            self.assertEqual(len(cleanup_commands), 2)

    def test_ambiguous_producer_journal_is_consumable_by_torn_recovery(self) -> None:
        """The real remapper producer shape is accepted without fake guard data."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(
                flash.CONTROL_SHA256,
                before_hash=flash.ROLLBACK_SHA256,
                mutate_staging_after_marker=True,
            )
            with self.assertRaises(flash.FlashError):
                self._run_flash(root, fake)
            source_path = self._journal_path(root)
            source = json.loads(source_path.read_text(encoding="utf-8"))
            endpoint = AdbEndpoint("serial", "recovery")
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback, "TARGET_SERIAL_SHA256", endpoint.serial_sha256
                    )
                )
                evidence = rollback._validate_source(
                    source, source_path=source_path
                )
            self.assertEqual(evidence["profile"], "control")
            self.assertEqual(evidence["remote_staging"], flash.REMOTE_STAGING)
            self.assertIsNone(evidence["guarded_effect_receipt"])

            for field in (
                "remote_staging",
                "remote_staging_sha256",
                "remote_staging_size",
                "post_staging_predecessor_sha256",
                "post_staging_predecessor_size",
                "effect_argv",
            ):
                with self.subTest(field=field):
                    forged = dict(source)
                    forged.pop(field)
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                        stack.enter_context(
                            mock.patch.object(
                                rollback, "TARGET_SERIAL_SHA256", endpoint.serial_sha256
                            )
                        )
                        with self.assertRaises(rollback.RollbackRecoveryError):
                            rollback._validate_source(
                                forged, source_path=source_path
                            )

    def test_ambiguous_rollback_claim_provenance_is_exact_and_recoverable(self) -> None:
        """A real rollback-profile producer claim passes the shared continuation contract."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote_staging = flash._remote_staging_for_profile("rollback")
            fake = FakeAdb(
                flash.ROLLBACK_SHA256,
                before_hash=flash.CONTROL_SHA256,
                mutate_staging_after_marker=True,
                remote_staging=remote_staging,
            )
            with self.assertRaises(flash.FlashError):
                self._run_flash(root, fake, profile="rollback")

            source_path = self._journal_path(root, "rollback")
            source = json.loads(source_path.read_text(encoding="utf-8"))
            self.assertEqual(
                source["allowed_predecessors"],
                [flash.READ_SHA256, flash.CONTROL_SHA256],
            )
            claim = claims.inspect_boot_prefix_claim(root, flash.CONTROL_SHA256)
            self.assertIsNotNone(claim)
            assert claim is not None
            provenance = claim.record["provenance"]
            self.assertEqual(provenance["image_size"], flash.BOOT_PREFIX_SIZE)
            claims.validate_normal_remapper_continuation(
                claim,
                root=root,
                journal_path=source_path,
                profile="rollback",
                predecessor_sha256=flash.CONTROL_SHA256,
            )

            for image_size in (None, flash.BOOT_PREFIX_SIZE - 1):
                with self.subTest(image_size=image_size):
                    forged_record = dict(claim.record)
                    forged_provenance = dict(provenance)
                    if image_size is None:
                        forged_provenance.pop("image_size", None)
                    else:
                        forged_provenance["image_size"] = image_size
                    forged_record["provenance"] = forged_provenance
                    forged_claim = claims.ClaimRecord(
                        kind=claim.kind,
                        path=claim.path,
                        key_sha256=claim.key_sha256,
                        identity=claim.identity,
                        record=forged_record,
                        data=claim.data,
                    )
                    with self.assertRaisesRegex(
                        claims.PhysicalClaimError, "image size"
                    ):
                        claims.validate_normal_remapper_continuation(
                            forged_claim,
                            root=root,
                            journal_path=source_path,
                            profile="rollback",
                            predecessor_sha256=flash.CONTROL_SHA256,
                        )

    def test_final_rebind_has_no_write_after_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(flash.CONTROL_SHA256, before_hash=flash.ROLLBACK_SHA256)
            good = AdbEndpoint("serial", "recovery")
            bad = AdbEndpoint("different", "recovery")
            count = 0

            def revalidate(adb, initial):
                nonlocal count
                count += 1
                if count == 4:
                    raise flash.FlashError("final rebind")
                return good

            image = root / "candidate.img"
            image.write_bytes(b"candidate")
            profiles = self._profile_patch(image)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(flash, "profile_table", return_value=profiles))
                stack.enter_context(mock.patch.object(flash, "_stable_file_digest", return_value=(flash.BOOT_PREFIX_SIZE, flash.CONTROL_SHA256)))
                stack.enter_context(mock.patch.object(flash, "run_checked", side_effect=fake))
                stack.enter_context(mock.patch.object(flash, "select_exact_recovery", return_value=good))
                stack.enter_context(mock.patch.object(flash, "TARGET_SERIAL_SHA256", good.serial_sha256))
                stack.enter_context(mock.patch.object(flash, "_revalidate_recovery", side_effect=revalidate))
                with self.assertRaisesRegex(flash.FlashError, "different|rebind"):
                    flash.flash(self._args(root))
            self.assertEqual(fake.write_count, 0)

    def test_post_dd_readback_mismatch_defers_cleanup_without_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(
                flash.CONTROL_SHA256,
                before_hash=flash.ROLLBACK_SHA256,
                post_hash="0" * 64,
            )
            with self.assertRaises(flash.FlashError):
                self._run_flash(root, fake)
            self.assertEqual(fake.write_count, 1)
            cleanup_commands = [
                call for call in fake.commands
                if len(call) >= 5
                and call[3] == "shell"
                and call[4] in {
                    f"rm -f {flash.REMOTE_STAGING}",
                    f"if [ -e {flash.REMOTE_STAGING} ] || [ -L {flash.REMOTE_STAGING} ]; then echo present; else echo absent; fi",
                }
            ]
            # Only the pre-effect stale-object cleanup is allowed.
            self.assertEqual(len(cleanup_commands), 2)
            journal = json.loads(self._journal_path(root).read_text())
            self.assertEqual(journal["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED")
            self.assertTrue(journal["staging_cleanup_deferred"])
            self.assertEqual(journal["current_state"], "UNKNOWN")
            self.assertTrue(journal["reconcile_required"])

    def test_dd_failure_is_ambiguous_and_replay_is_refused(self) -> None:
        class DdFailure(FakeAdb):
            def __call__(self, argv) -> str:
                call = tuple(argv)
                if len(call) >= 5 and call[3] == "shell" and call[4].startswith(
                    "set -e; "
                ):
                    self.commands.append(call)
                    self.write_count += 1
                    raise TimeoutError("timeout after dd")
                return super().__call__(argv)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = DdFailure(flash.CONTROL_SHA256, before_hash=flash.ROLLBACK_SHA256)
            with self.assertRaises((flash.FlashError, TimeoutError)):
                self._run_flash(root, fake)
            calls_after = len(fake.commands)
            # Replay is refused before profile hashing or any ADB command.
            with self.assertRaisesRegex(flash.FlashError, "replay forbidden"):
                self._run_flash(root, fake)
            self.assertEqual(len(fake.commands), calls_after)
            journal = json.loads(self._journal_path(root).read_text())
            self.assertEqual(journal["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED")
            self.assertEqual(journal["write_count"], 1)
            self.assertEqual(journal["current_state"], "UNKNOWN")

    def test_readback_verified_but_cleanup_failure_is_distinct(self) -> None:
        class CleanupFailure(FakeAdb):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.remove_count = 0

            def __call__(self, argv) -> str:
                call = tuple(argv)
                if len(call) >= 5 and call[3] == "shell" and call[4] == (
                    f"rm -f {flash.REMOTE_STAGING}"
                ):
                    self.commands.append(call)
                    self.remove_count += 1
                    if self.remove_count > 1:
                        raise TimeoutError("cleanup unavailable")
                return super().__call__(argv)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = CleanupFailure(flash.CONTROL_SHA256, before_hash=flash.ROLLBACK_SHA256)
            with self.assertRaisesRegex(flash.FlashError, "close cleanly"):
                self._run_flash(root, fake)
            journal = json.loads(self._journal_path(root).read_text())
            self.assertEqual(journal["status"], "CLEANUP_FAILED")
            self.assertEqual(journal["write_count"], 1)

    def test_final_cleanup_rebind_failure_defers_without_cleanup_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(flash.CONTROL_SHA256, before_hash=flash.ROLLBACK_SHA256)
            image = root / "candidate.img"
            image.write_bytes(b"candidate")
            endpoint = AdbEndpoint("serial", "recovery")
            profiles = self._profile_patch(image)
            rebind_count = 0

            def revalidate(_adb, _initial):
                nonlocal rebind_count
                rebind_count += 1
                if rebind_count == 6:
                    raise flash.FlashError("final cleanup rebind drift")
                return endpoint

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(flash, "profile_table", return_value=profiles))
                stack.enter_context(mock.patch.object(flash, "_stable_file_digest", return_value=(flash.BOOT_PREFIX_SIZE, flash.CONTROL_SHA256)))
                stack.enter_context(mock.patch.object(flash, "run_checked", side_effect=fake))
                stack.enter_context(mock.patch.object(flash, "select_exact_recovery", return_value=endpoint))
                stack.enter_context(mock.patch.object(flash, "TARGET_SERIAL_SHA256", endpoint.serial_sha256))
                stack.enter_context(mock.patch.object(flash, "_revalidate_recovery", side_effect=revalidate))
                with self.assertRaisesRegex(flash.FlashError, "close cleanly"):
                    flash.flash(self._args(root))
            cleanup_commands = [
                call for call in fake.commands
                if len(call) >= 5
                and call[3] == "shell"
                and call[4] in {
                    f"rm -f {flash.REMOTE_STAGING}",
                    f"if [ -e {flash.REMOTE_STAGING} ] || [ -L {flash.REMOTE_STAGING} ]; then echo present; else echo absent; fi",
                }
            ]
            # The two pre-effect stale-object cleanup calls happened before
            # the write.  The failed final rebind must add zero new cleanup
            # calls after readback.
            self.assertEqual(len(cleanup_commands), 2)
            journal = json.loads(self._journal_path(root).read_text())
            self.assertEqual(journal["status"], "CLEANUP_REBIND_FAILED_RECONCILIATION_REQUIRED")
            self.assertTrue(journal["staging_cleanup_deferred"])
            self.assertTrue(journal["reconcile_required"])


if __name__ == "__main__":
    unittest.main()
