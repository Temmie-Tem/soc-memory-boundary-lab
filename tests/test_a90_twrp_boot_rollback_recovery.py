from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from tools import a90_twrp_boot_rollback_recovery as rollback
from tools import a90_v024_physical_claim as claims


SERIAL = "serial"
PRE_HASH = "f" * 64
ROLLBACK_STAGING_PREFIX = "/tmp/sdm855-remapper-boot-rollback-"


def source_record(
    *,
    profile: str = "control",
    pre_hash: str | None = None,
    status: str = rollback.SOURCE_AMBIGUOUS_STATUS,
) -> dict[str, object]:
    images = {
        "control": "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247",
        "read": "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed",
        "rollback": rollback.ROLLBACK_SHA256,
    }
    predecessors = {
        "control": [rollback.ROLLBACK_SHA256],
        "read": [images["control"]],
        # Match the normal producer's ``sorted(allowed)`` serialization.
        "rollback": [images["read"], images["control"]],
    }
    allowed = predecessors[profile]
    if pre_hash is None:
        pre_hash = allowed[0]
    return {
        "schema": rollback.SOURCE_SCHEMA,
        "status": status,
        "profile": profile,
        "target_model": rollback.TARGET_MODEL,
        "target_device": rollback.TARGET_DEVICE,
        "target_serial_sha256": hashlib.sha256(SERIAL.encode()).hexdigest(),
        "boot_alias": rollback.BOOT_BLOCK_ALIAS,
        "boot_node": rollback.BOOT_BLOCK_RESOLVED,
        "image_sha256": images[profile],
        "image_size": rollback.BOOT_PREFIX_SIZE,
        "remote_staging": rollback.REMOTE_STAGING_BY_PROFILE[profile],
        "remote_staging_sha256": images[profile],
        "remote_staging_size": rollback.BOOT_PREFIX_SIZE,
        "effect_dispatched": True,
        "effect_armed": True,
        "effect_replayed": False,
        "effect_ambiguous": True,
        "automatic_retries": False,
        "reboot_dispatched": False,
        "write_count": 1,
        "partition_writes": True,
        "staging_attempted": True,
        "staging_attempt_count": 1,
        "staging_dispatch_count": 1,
        "staging_status": "STAGING_PUSH_RETURNED",
        "pre_staging_removed": True,
        "pre_cleanup_revalidated": True,
        "pre_push_revalidated": True,
        "staging_removed": False,
        "allowed_predecessors": allowed,
        "effect_argv": [
            "dd",
            f"if={rollback.REMOTE_STAGING_BY_PROFILE[profile]}",
            f"of={rollback.BOOT_BLOCK_RESOLVED}",
            "bs=4096",
            f"count={rollback.DD_BLOCK_COUNT}",
            "conv=fsync",
        ],
        "current_state": "UNKNOWN",
        "staging_cleanup_deferred": True,
        "reconcile_required": True,
        "predecessor_sha256": pre_hash,
        "predecessor_size": rollback.BOOT_PREFIX_SIZE,
        "post_staging_predecessor_sha256": pre_hash,
        "post_staging_predecessor_size": rollback.BOOT_PREFIX_SIZE,
        "post_staging_predecessor_revalidated": True,
        "pre_effect_revalidated": True,
    }


class FakeAdb:
    def __init__(self, *, current_hash: str = PRE_HASH, fail_write: bool = False) -> None:
        self.current_hash = current_hash
        self.fail_write = fail_write
        self.commands: list[tuple[str, ...]] = []
        self.write_count = 0
        self.boot_hash_reads = 0
        self.remote_staging: str | None = None

    def __call__(self, argv) -> str:
        call = tuple(argv)
        self.commands.append(call)
        if call == (rollback.ADB, "devices"):
            return "List of devices attached\nserial\trecovery\n"
        if call[-1] == "getprop ro.product.model":
            return f"{rollback.TARGET_MODEL}\n"
        if call[-1] == "getprop ro.product.device":
            return f"{rollback.TARGET_DEVICE}\n"
        if call[-1] == "twrp --help 2>&1":
            return (
                "TWRP openrecoveryscript command line tool, "
                f"TWRP version {rollback.TWRP_VERSION}\n"
            )
        if call[-1] == f"readlink -f {rollback.BOOT_BLOCK_ALIAS}":
            return f"{rollback.BOOT_BLOCK_RESOLVED}\n"
        command = call[-1] if len(call) >= 5 and call[3] == "shell" else ""
        if command.startswith("dd if=/dev/block/sda24") and "sha256sum" in command:
            self.boot_hash_reads += 1
            # Unknown-preimage tests mock the binary capture.  The first
            # read is the initial preimage and the second is the mandatory
            # post-staging predecessor recheck; the next read is the
            # post-write rollback readback.
            value = self.current_hash if self.boot_hash_reads <= 2 else rollback.ROLLBACK_SHA256
            return f"{value}\n"
        if command.startswith("dd if=/dev/block/sda24") and "wc -c" in command:
            return f"{rollback.BOOT_PREFIX_SIZE}\n"
        if command.startswith("sha256sum /tmp/sdm855-remapper-boot-rollback-"):
            self.remote_staging = command[len("sha256sum ") :]
            return f"{rollback.ROLLBACK_SHA256}  {self.remote_staging}\n"
        if command.startswith("wc -c < /tmp/sdm855-remapper-boot-rollback-"):
            self.remote_staging = command[len("wc -c < ") :]
            return f"{rollback.BOOT_PREFIX_SIZE}\n"
        if command.startswith("set -e; "):
            if self.fail_write:
                # The remote transaction reached its sole dd even though the
                # transport receipt is intentionally malformed/ambiguous.
                self.write_count += 1
                return (
                    "A90V024 GUARD_PASS "
                    f"current_sha256={self.current_hash} current_size={rollback.BOOT_PREFIX_SIZE} "
                    f"staging_sha256={rollback.ROLLBACK_SHA256} staging_size={rollback.BOOT_PREFIX_SIZE}\n"
                )
            self.write_count += 1
            return (
                "A90V024 GUARD_PASS "
                f"current_sha256={self.current_hash} current_size={rollback.BOOT_PREFIX_SIZE} "
                f"staging_sha256={rollback.ROLLBACK_SHA256} staging_size={rollback.BOOT_PREFIX_SIZE}\n"
                f"A90V024 DD_RESULT rc=0 count={rollback.DD_BLOCK_COUNT}\n"
            )
        if command.startswith("dd if=/tmp/sdm855-remapper-boot-rollback-"):
            self.write_count += 1
            if self.fail_write:
                raise TimeoutError("timeout after durable write marker")
            return ""
        if command.startswith("rm -f /tmp/sdm855-remapper-boot-rollback-"):
            self.remote_staging = command[len("rm -f ") :]
            return ""
        if command.startswith(
            "if [ -e /tmp/sdm855-remapper-boot-rollback-"
        ):
            return "absent\n"
        if command == (
            f"if [ -e {rollback.REMOTE_STAGING} ] || [ -L {rollback.REMOTE_STAGING} ]; then "
            "echo present; else echo absent; fi"
        ):
            return "absent\n"
        if len(call) >= 5 and call[3] == "push":
            return ""
        raise AssertionError(call)


class RollbackRecoveryTests(unittest.TestCase):
    def tearDown(self) -> None:
        rollback.REPO_ROOT = Path(rollback.__file__).resolve().parents[1]

    def _args(self, root: Path, *, execute: bool = True) -> argparse.Namespace:
        rollback.REPO_ROOT = root
        source = root / "evidence" / "private" / (
            "verification-024-remapper-boot-flash-control.journal.json"
        )
        return argparse.Namespace(
            experiment_id="torn-rollback-test",
            flash_journal=source,
            execute=execute,
        )

    def _prepare_source(
        self,
        root: Path,
        value: dict[str, object] | None = None,
        *,
        profile: str = "control",
    ) -> Path:
        source = root / "evidence" / "private" / (
            f"verification-024-remapper-boot-flash-{profile}.journal.json"
        )
        source.parent.mkdir(parents=True)
        source.write_text(json.dumps(value or source_record()) + "\n", encoding="utf-8")
        return source

    @staticmethod
    def _semantic_hash(source: Path) -> str:
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", source.parents[2]))
            stack.enter_context(
                mock.patch.object(
                    rollback,
                    "TARGET_SERIAL_SHA256",
                    hashlib.sha256(SERIAL.encode()).hexdigest(),
                )
            )
            return str(
                rollback._validate_source(
                    source_record(), source_path=source
                )["semantic_sha256"]
            )

    def _run(self, root: Path, fake: FakeAdb, **kwargs):
        self._prepare_source(root, kwargs.pop("source", None))
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
            stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=fake))
            stack.enter_context(
                mock.patch.object(
                    rollback,
                    "TARGET_SERIAL_SHA256",
                    hashlib.sha256(SERIAL.encode()).hexdigest(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    rollback,
                    "_stable_image_digest",
                    return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256),
                )
            )
            # The ordinary fixture uses an unknown torn candidate so the
            # production path now requires the bounded capture/mixture proof.
            # Keep these transaction tests focused on journal/effect ordering;
            # dedicated tests exercise the real capture validator below.
            if fake.current_hash not in rollback.KNOWN_V024_BOOT_HASHES:
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_capture_unknown_preimage",
                        return_value={
                            "capture_sha256": fake.current_hash,
                            "capture_size": rollback.BOOT_PREFIX_SIZE,
                            "device_before_sha256": fake.current_hash,
                            "device_before_size": rollback.BOOT_PREFIX_SIZE,
                            "host_capture_sha256": fake.current_hash,
                            "host_capture_size": rollback.BOOT_PREFIX_SIZE,
                            "device_after_sha256": fake.current_hash,
                            "device_after_size": rollback.BOOT_PREFIX_SIZE,
                            "block_size": rollback.CAPTURE_BLOCK_SIZE,
                            "block_count": rollback.DD_BLOCK_COUNT,
                            "allowed_block_count": rollback.DD_BLOCK_COUNT,
                            "mixture_valid": True,
                            "predecessor_sha256": rollback.ROLLBACK_SHA256,
                            "intended_sha256": rollback.CONTROL_SHA256,
                        },
                    )
                )
            return rollback.collect(self._args(root))

    def _collect(self, root: Path, *, execute: bool = True):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
            stack.enter_context(
                mock.patch.object(
                    rollback,
                    "TARGET_SERIAL_SHA256",
                    hashlib.sha256(SERIAL.encode()).hexdigest(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    rollback,
                    "_stable_image_digest",
                    return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256),
                )
            )
            return rollback.collect(self._args(root, execute=execute))

    def test_import_and_cli_are_fixed_no_arbitrary_inputs(self) -> None:
        parser = rollback.build_parser()
        parsed = parser.parse_args(
            ["--experiment-id", "x", "--flash-journal", "source.json", "--execute"]
        )
        self.assertTrue(parsed.execute)
        for option in ("--adb", "--image", "--profile", "--timeout", "--output-root"):
            with self.subTest(option=option):
                with self.assertRaises(SystemExit):
                    parser.parse_args(
                        ["--experiment-id", "x", "--flash-journal", "source.json", option, "x"]
                    )
        with mock.patch.object(rollback, "run_checked") as run:
            __import__("importlib").import_module("tools.a90_twrp_boot_rollback_recovery")
        run.assert_not_called()

    def test_missing_execute_and_source_gate_have_zero_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._prepare_source(root)
            fake = FakeAdb()
            with mock.patch.object(rollback, "run_checked", side_effect=fake):
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "--execute"):
                    self._collect(root, execute=False)
            self.assertEqual(fake.commands, [])
            bad_root = root / "bad"
            bad_root.mkdir()
            self._prepare_source(bad_root, source_record(status="READBACK_VERIFIED"))
            with mock.patch.object(rollback, "run_checked", side_effect=fake):
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "ambiguous"):
                    self._collect(bad_root)
            self.assertEqual(fake.commands, [])

    def test_injected_output_root_is_refused_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._prepare_source(root)
            args = self._args(root)
            args.output_root = root / "redirected"
            fake = FakeAdb()
            with mock.patch.object(rollback, "run_checked", side_effect=fake):
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "output_root"):
                    rollback.collect(args)
            self.assertEqual(fake.commands, [])

    def test_injected_nonfixed_adb_is_refused_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._prepare_source(root)
            args = self._args(root)
            args.adb = "adb"
            fake = FakeAdb()
            with mock.patch.object(rollback, "run_checked", side_effect=fake):
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "fixed adb"):
                    rollback.collect(args)
            self.assertEqual(fake.commands, [])

    def test_source_journal_is_strict_and_producer_fields_are_required(self) -> None:
        invalid_fields = {
            "target_model": "other",
            "target_device": "other",
            "target_serial_sha256": "b" * 64,
            "boot_alias": "/dev/block/by-name/other",
            "boot_node": "/dev/block/sdb1",
            "profile": "custom",
            "image_sha256": "b" * 64,
            "image_size": 1,
            "effect_dispatched": False,
            "write_count": 2,
            "current_state": "unknown",
            "staging_cleanup_deferred": False,
            "reconcile_required": False,
            "predecessor_sha256": "short",
            "predecessor_size": 1,
            "remote_staging": "/tmp/not-the-profile-staging.img",
            "remote_staging_sha256": "b" * 64,
            "remote_staging_size": 1,
            "post_staging_predecessor_sha256": "b" * 64,
            "post_staging_predecessor_size": 1,
            "effect_ambiguous": False,
            "automatic_retries": True,
            "reboot_dispatched": True,
            "partition_writes": False,
            "staging_attempted": False,
            "staging_attempt_count": 0,
            "staging_dispatch_count": 0,
            "staging_status": "STAGING_PUSH_STARTED",
            "pre_staging_removed": False,
            "pre_cleanup_revalidated": False,
            "pre_push_revalidated": False,
            "staging_removed": True,
            "post_staging_predecessor_revalidated": False,
            "pre_effect_revalidated": False,
        }
        for field, value in invalid_fields.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record = source_record()
                record[field] = value
                self._prepare_source(root, record)
                fake = FakeAdb()
                with mock.patch.object(rollback, "run_checked", side_effect=fake):
                    with self.assertRaises(rollback.RollbackRecoveryError):
                        self._collect(root)
                self.assertEqual(fake.commands, [])

        for field, value in {
            "effect_ambiguous": 1,
            "automatic_retries": 0,
            "reboot_dispatched": 0,
            "partition_writes": 1,
            "staging_attempt_count": True,
            "staging_dispatch_count": True,
        }.items():
            with self.subTest(exact_type=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record = source_record()
                record[field] = value
                self._prepare_source(root, record)
                with self.assertRaises(rollback.RollbackRecoveryError):
                    self._collect(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence" / "private" / (
                "verification-024-remapper-boot-flash-control.journal.json"
            )
            source.parent.mkdir(parents=True)
            source.write_text(
                '{"schema":"%s","schema":"%s"}\n' % (rollback.SOURCE_SCHEMA, rollback.SOURCE_SCHEMA),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(rollback.RollbackRecoveryError, "duplicate"):
                self._collect(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence" / "private" / (
                "verification-024-remapper-boot-flash-control.journal.json"
            )
            source.parent.mkdir(parents=True)
            source.write_text('{"value":NaN}\n', encoding="utf-8")
            with self.assertRaisesRegex(rollback.RollbackRecoveryError, "non-finite"):
                self._collect(root)

    def test_source_guard_receipt_and_projections_are_optional_only_on_ambiguous_transport(self) -> None:
        """A returned guard binds exact projections; an absent receipt means no projections."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = self._prepare_source(root)
            receipt = {
                "schema": "sdm855-a90-remapper-guarded-effect-v1",
                "guard": {
                    "current_sha256": rollback.ROLLBACK_SHA256,
                    "current_size": str(rollback.BOOT_PREFIX_SIZE),
                    "staging_sha256": rollback.CONTROL_SHA256,
                    "staging_size": str(rollback.BOOT_PREFIX_SIZE),
                },
                "dd_result": {
                    "rc": "0",
                    "count": str(rollback.DD_BLOCK_COUNT),
                },
                "write_count": 1,
            }
            complete = source_record()
            complete.update(
                {
                    "guarded_effect_receipt": receipt,
                    "post_dispatch_predecessor_sha256": rollback.ROLLBACK_SHA256,
                    "post_dispatch_predecessor_size": rollback.BOOT_PREFIX_SIZE,
                    "post_dispatch_staging_sha256": rollback.CONTROL_SHA256,
                    "post_dispatch_staging_size": rollback.BOOT_PREFIX_SIZE,
                }
            )
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                validated = rollback._validate_source(
                    complete, source_path=source_path
                )
                self.assertEqual(validated["guarded_effect_receipt"], receipt)
                self.assertEqual(
                    validated["post_dispatch_predecessor_sha256"],
                    rollback.ROLLBACK_SHA256,
                )
                self.assertEqual(
                    validated["post_dispatch_staging_sha256"], rollback.CONTROL_SHA256
                )

            for update in (
                {"post_dispatch_predecessor_sha256": "b" * 64},
                {"post_dispatch_predecessor_size": rollback.BOOT_PREFIX_SIZE - 1},
                {"post_dispatch_staging_sha256": "b" * 64},
                {"post_dispatch_staging_size": rollback.BOOT_PREFIX_SIZE - 1},
                {"guarded_effect_receipt": {**receipt, "write_count": True}},
                {
                    "guarded_effect_receipt": {
                        **receipt,
                        "guard": {
                            **receipt["guard"],
                            "staging_sha256": rollback.READ_SHA256,
                        },
                    }
                },
            ):
                with self.subTest(update=update):
                    forged = dict(complete)
                    forged.update(update)
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                        stack.enter_context(
                            mock.patch.object(
                                rollback,
                                "TARGET_SERIAL_SHA256",
                                hashlib.sha256(SERIAL.encode()).hexdigest(),
                            )
                        )
                        with self.assertRaises(rollback.RollbackRecoveryError):
                            rollback._validate_source(
                                forged, source_path=source_path
                            )

            no_receipt = source_record()
            no_receipt["post_dispatch_predecessor_sha256"] = None
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                with self.assertRaises(rollback.RollbackRecoveryError):
                    rollback._validate_source(no_receipt, source_path=source_path)

    def test_source_must_be_the_fixed_profile_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = self._prepare_source(root)
            alternate = root / "evidence" / "private" / "renamed-source.json"
            alternate.write_bytes(canonical.read_bytes())
            args = self._args(root)
            args.flash_journal = alternate
            fake = FakeAdb()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=fake))
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "canonical"):
                    rollback.collect(args)
            self.assertEqual(fake.commands, [])

    def test_semantic_source_claim_ignores_formatting_and_extra_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)
            source = self._prepare_source(root)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_image_digest",
                        return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256),
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=first))
                rollback.collect(self._args(root))

            reformatted = json.loads(source.read_text(encoding="utf-8"))
            reformatted["ignored_extra"] = {"reformatted": True}
            source.write_text(
                json.dumps(reformatted, indent=4, sort_keys=False) + "\n",
                encoding="utf-8",
            )
            second = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)
            args = self._args(root)
            args.experiment_id = "torn-rollback-semantic-reformat"
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=second))
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "replay forbidden"):
                    rollback.collect(args)
            self.assertEqual(second.commands, [])

    def test_source_predecessor_matrix_is_exact_and_known_impossible_state_refuses(self) -> None:
        invalid = (
            {"allowed_predecessors": [rollback.READ_SHA256]},
            {"predecessor_sha256": rollback.READ_SHA256},
            {"predecessor_size": rollback.BOOT_PREFIX_SIZE - 1},
        )
        for update in invalid:
            with self.subTest(update=update), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._prepare_source(root, {**source_record(), **update})
                fake = FakeAdb()
                with mock.patch.object(rollback, "run_checked", side_effect=fake):
                    with self.assertRaises(rollback.RollbackRecoveryError):
                        self._collect(root)
                self.assertEqual(fake.commands, [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(current_hash=rollback.READ_SHA256)
            with self.assertRaisesRegex(rollback.RollbackRecoveryError, "causally possible"):
                self._run(root, fake)
            self.assertEqual(fake.write_count, 0)
            self.assertFalse(
                any(
                    path.name.startswith(rollback.SOURCE_CLAIM_PREFIX)
                    for path in (root / "evidence" / "private").iterdir()
                )
            )

    def test_rollback_predecessor_order_matches_sorted_flash_producer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = source_record(
                profile="rollback", pre_hash=rollback.CONTROL_SHA256
            )
            source = self._prepare_source(root, record, profile="rollback")
            target_serial_sha256 = hashlib.sha256(SERIAL.encode()).hexdigest()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback, "TARGET_SERIAL_SHA256", target_serial_sha256
                    )
                )
                validated = rollback._validate_source(record, source_path=source)
            expected = [rollback.READ_SHA256, rollback.CONTROL_SHA256]
            self.assertEqual(validated["allowed_predecessors"], expected)
            self.assertEqual(
                validated["semantic_identity"]["allowed_predecessors"], expected
            )

            reversed_record = dict(record)
            reversed_record["allowed_predecessors"] = list(reversed(expected))
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback, "TARGET_SERIAL_SHA256", target_serial_sha256
                    )
                )
                with self.assertRaisesRegex(
                    rollback.RollbackRecoveryError, "predecessor matrix"
                ):
                    rollback._validate_source(
                        reversed_record, source_path=source
                    )

    def test_existing_output_and_symlink_source_refuse_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._prepare_source(root)
            output = root / "evidence" / "private" / (
                "verification-024-boot-torn-rollback-torn-rollback-test.journal.json"
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("stale\n", encoding="utf-8")
            fake = FakeAdb()
            with mock.patch.object(rollback, "run_checked", side_effect=fake):
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "replay forbidden"):
                    self._collect(root)
            self.assertEqual(fake.commands, [])
            output.unlink()
            source.unlink()
            source.symlink_to(root / "missing-source.json")
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=fake))
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "symlink"):
                    rollback.collect(self._args(root))
            self.assertEqual(fake.commands, [])

    def test_one_durable_write_complete_readback_cleanup_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb()
            with mock.patch.object(rollback, "_stable_image_digest", return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256)):
                paths = self._run(root, fake)
            journal_path, manifest_path = paths
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(fake.write_count, 1)
            self.assertEqual(journal["status"], rollback.PASS_STATUS)
            self.assertEqual(journal["write_count"], 1)
            self.assertEqual(journal["readback_sha256"], rollback.ROLLBACK_SHA256)
            self.assertEqual(journal_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o644)
            self.assertTrue(manifest["target_verified"])
            self.assertEqual(
                manifest["target"]["serial_sha256"],
                hashlib.sha256(SERIAL.encode()).hexdigest(),
            )
            rendered = manifest_path.read_text(encoding="utf-8")
            self.assertNotIn('"serial":', rendered)
            self.assertNotIn("serial\"", rendered)
            self.assertNotIn("of=/dev/block", rendered)
            cleanup = [
                call for call in fake.commands
                if len(call) >= 5 and call[3] == "shell" and (
                    call[4].startswith(f"rm -f {ROLLBACK_STAGING_PREFIX}")
                    or call[4].startswith("if [ -e")
                )
            ]
            # One remove/absence pair is required before push and one fresh
            # pair closes the verified readback.
            self.assertEqual(len(cleanup), 4)

    def test_staging_and_dd_order_is_fixed_around_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(current_hash=PRE_HASH)
            self._run(root, fake)
            commands = fake.commands

            def index_of(predicate, start=0):
                return next(
                    index
                    for index, call in enumerate(commands[start:], start)
                    if predicate(call)
                )

            remove = index_of(
                lambda call: len(call) >= 5
                and call[3] == "shell"
                and call[4].startswith(f"rm -f {ROLLBACK_STAGING_PREFIX}")
            )
            absent = index_of(
                lambda call: len(call) >= 5
                and call[3] == "shell"
                and call[4].startswith("if [ -e")
            )
            push = index_of(lambda call: len(call) >= 5 and call[3] == "push")
            remote_hashes = [
                index
                for index, call in enumerate(commands)
                if len(call) >= 5
                and call[3] == "shell"
                and call[4].startswith(f"sha256sum {ROLLBACK_STAGING_PREFIX}")
            ]
            remote_sizes = [
                index
                for index, call in enumerate(commands)
                if len(call) >= 5
                and call[3] == "shell"
                and call[4].startswith(f"wc -c < {ROLLBACK_STAGING_PREFIX}")
            ]
            writes = [
                index
                for index, call in enumerate(commands)
                if len(call) >= 5
                and call[3] == "shell"
                and call[4].startswith("set -e; ")
            ]
            self.assertLess(remove, absent)
            self.assertLess(absent, push)
            # The pre-marker staging hash/size is recorded separately.  The
            # post-marker staging check is embedded in the guarded shell
            # transaction that also owns the sole dd.
            self.assertEqual(len(remote_hashes), 1)
            self.assertEqual(len(remote_sizes), 1)
            self.assertLess(push, remote_hashes[0])
            self.assertEqual(len(writes), 1)
            self.assertLess(remote_hashes[0], writes[0])
            # The guarded shell command follows the final exact rebind and
            # contains both the staging rehash and the sole rollback dd.
            self.assertEqual(commands[writes[0] - 1][4], f"readlink -f {rollback.BOOT_BLOCK_ALIAS}")
            guarded = commands[writes[0]][4]
            self.assertIn("staging_hash=$(sha256sum", guarded)
            self.assertIn(f"dd if={ROLLBACK_STAGING_PREFIX}", guarded)

    def test_timeout_after_effect_is_ambiguous_without_retry_or_post_marker_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(fail_write=True)
            with self.assertRaises(rollback.RollbackRecoveryError):
                self._run(root, fake)
            journal = json.loads(
                (root / "evidence" / "private" / "verification-024-boot-torn-rollback-torn-rollback-test.journal.json").read_text()
            )
            self.assertEqual(fake.write_count, 1)
            self.assertEqual(journal["status"], rollback.AMBIGUOUS_STATUS)
            self.assertEqual(journal["write_count"], 1)
            self.assertTrue(journal["staging_cleanup_deferred"])
            cleanup = [
                call for call in fake.commands
                if len(call) >= 5
                and call[3] == "shell"
                and (
                    call[4].startswith(f"rm -f {ROLLBACK_STAGING_PREFIX}")
                    or call[4].startswith(f"if [ -e {ROLLBACK_STAGING_PREFIX}")
                )
            ]
            # The pre-push stale-object cleanup is allowed; no cleanup may be
            # appended after the ambiguous write marker/effect.
            self.assertEqual(len(cleanup), 2)

    def test_already_rollback_is_idempotent_with_zero_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)
            paths = self._run(root, fake)
            journal = json.loads(paths[0].read_text(encoding="utf-8"))
            self.assertEqual(journal["status"], rollback.PASS_ALREADY_STATUS)
            self.assertEqual(journal["write_count"], 0)
            self.assertEqual(fake.write_count, 0)
            self.assertFalse(any(len(call) >= 4 and call[3] == "push" for call in fake.commands))

    def test_source_consumption_claim_blocks_new_experiment_without_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)
            self._run(root, first)
            second = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)
            args = self._args(root)
            args.experiment_id = "torn-rollback-second-experiment"
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                with mock.patch.object(rollback, "run_checked", side_effect=second):
                    with self.assertRaisesRegex(rollback.RollbackRecoveryError, "replay forbidden"):
                        rollback.collect(args)
            self.assertEqual(second.commands, [])

    def test_source_effect_replayed_true_is_rejected_without_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._prepare_source(root, {**source_record(), "effect_replayed": True})
            fake = FakeAdb()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                with mock.patch.object(rollback, "run_checked", side_effect=fake):
                    with self.assertRaisesRegex(rollback.RollbackRecoveryError, "effect_replayed"):
                        rollback.collect(self._args(root))
            self.assertEqual(fake.commands, [])

    def test_source_claim_lock_crash_blocks_retry_without_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._prepare_source(root)
            claim_hash = self._semantic_hash(source)
            claim_tmp = root / "evidence" / "private" / (
                f"{rollback.SOURCE_CLAIM_PREFIX}{claim_hash}.claim.json.tmp"
            )
            claim_tmp.write_text("incomplete lock", encoding="utf-8")
            fake = FakeAdb()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                with mock.patch.object(rollback, "run_checked", side_effect=fake):
                    with self.assertRaisesRegex(rollback.RollbackRecoveryError, "lock exists"):
                        rollback.collect(self._args(root))
            self.assertEqual(fake.commands, [])

    def test_source_claim_malformed_final_inode_blocks_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._prepare_source(root)
            claim_hash = self._semantic_hash(source)
            claim_path = root / "evidence" / "private" / (
                f"{rollback.SOURCE_CLAIM_PREFIX}{claim_hash}.claim.json"
            )
            claim_path.write_bytes(b"{\"partial\":")
            fake = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=fake))
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "replay forbidden"):
                    rollback.collect(self._args(root))
            self.assertEqual(fake.commands, [])
            self.assertEqual(claim_path.read_bytes(), b"{\"partial\":")

    def test_claim_creation_crash_leaves_immutable_no_replay_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._prepare_source(root)
            fake = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)

            def crash_after_claim_inode(claim_path, **_kwargs):
                claim_path.write_bytes(b"partial claim")
                raise OSError("simulated fsync crash")

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_image_digest",
                        return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256),
                    )
                )
                stack.enter_context(
                    mock.patch.object(rollback, "run_checked", side_effect=fake)
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_create_source_claim",
                        side_effect=crash_after_claim_inode,
                    )
                )
                with self.assertRaisesRegex(
                    rollback.RollbackRecoveryError,
                    "reconciliation",
                ):
                    rollback.collect(self._args(root))

            source = root / "evidence" / "private" / (
                "verification-024-remapper-boot-flash-control.journal.json"
            )
            claim_hash = self._semantic_hash(source)
            claim_path = root / "evidence" / "private" / (
                f"{rollback.SOURCE_CLAIM_PREFIX}{claim_hash}.claim.json"
            )
            self.assertEqual(claim_path.read_bytes(), b"partial claim")

            second = FakeAdb(current_hash=rollback.ROLLBACK_SHA256)
            args = self._args(root)
            args.experiment_id = "torn-rollback-crash-retry"
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=second))
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "replay forbidden"):
                    rollback.collect(args)
            self.assertEqual(second.commands, [])

    def test_final_cleanup_rebind_failure_sends_zero_cleanup_commands_and_no_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._prepare_source(root)
            fake = FakeAdb()
            endpoint = rollback.AdbEndpoint(SERIAL, "recovery")
            # Initial bind, pre-cleanup bind, staging-attempt bind,
            # post-staging bind, and post-marker/final-dd bind all succeed;
            # the sixth call is the final cleanup bind and must fail before
            # any cleanup.
            rebinds = iter((endpoint, endpoint, endpoint, endpoint, endpoint))

            def rebind(_initial=None):
                try:
                    return next(rebinds)
                except StopIteration as exc:
                    raise rollback.RollbackRecoveryError("final cleanup drift") from exc

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=fake))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "_stable_image_digest", return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256)))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_capture_unknown_preimage",
                        return_value={
                            "capture_sha256": fake.current_hash,
                            "capture_size": rollback.BOOT_PREFIX_SIZE,
                            "device_before_sha256": fake.current_hash,
                            "device_before_size": rollback.BOOT_PREFIX_SIZE,
                            "host_capture_sha256": fake.current_hash,
                            "host_capture_size": rollback.BOOT_PREFIX_SIZE,
                            "device_after_sha256": fake.current_hash,
                            "device_after_size": rollback.BOOT_PREFIX_SIZE,
                            "block_size": rollback.CAPTURE_BLOCK_SIZE,
                            "block_count": rollback.DD_BLOCK_COUNT,
                            "allowed_block_count": rollback.DD_BLOCK_COUNT,
                            "mixture_valid": True,
                        },
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "_revalidate_recovery", side_effect=rebind))
                with self.assertRaises(rollback.RollbackRecoveryError):
                    rollback.collect(self._args(root))
            journal = json.loads(
                (root / "evidence" / "private" / "verification-024-boot-torn-rollback-torn-rollback-test.journal.json").read_text()
            )
            self.assertEqual(journal["status"], "CLEANUP_REBIND_FAILED_RECONCILIATION_REQUIRED")
            self.assertTrue(journal["reconcile_required"])
            # Only the required pre-push stale-object cleanup ran; the failed
            # final rebind added no post-readback cleanup command.
            self.assertEqual(
                sum(
                    len(call) >= 5
                    and call[4].startswith(f"rm -f {ROLLBACK_STAGING_PREFIX}")
                    for call in fake.commands
                ),
                1,
            )

    def _unknown_capture_fixture(self) -> tuple[bytes, bytes, bytes, str]:
        predecessor = b"P" * rollback.BOOT_PREFIX_SIZE
        intended = b"I" * rollback.BOOT_PREFIX_SIZE
        mixed = bytearray(predecessor)
        for offset in range(0, rollback.BOOT_PREFIX_SIZE, 8192):
            mixed[offset : offset + rollback.CAPTURE_BLOCK_SIZE] = intended[
                offset : offset + rollback.CAPTURE_BLOCK_SIZE
            ]
        mixed_bytes = bytes(mixed)
        return predecessor, intended, mixed_bytes, rollback.sha256(mixed_bytes)

    def test_unknown_preimage_valid_mixed_blocks_is_captured_and_proved(self) -> None:
        predecessor, intended, mixed, current_hash = self._unknown_capture_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = source_record()
            with contextlib.ExitStack() as stack:
                stable = stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_artifact_bytes",
                        side_effect=[predecessor, intended],
                    )
                )
                capture = stack.enter_context(
                    mock.patch.object(rollback, "run_capture", return_value=mixed)
                )
                stack.enter_context(mock.patch.object(rollback, "_boot_hash", return_value=current_hash))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_boot_size",
                        return_value=rollback.BOOT_PREFIX_SIZE,
                    )
                )
                result = rollback._capture_unknown_preimage(
                    root,
                    "mixed-capture",
                    SERIAL,
                    current_hash,
                    rollback.BOOT_PREFIX_SIZE,
                    source,
                )
            self.assertTrue(result["mixture_valid"])
            self.assertEqual(result["allowed_block_count"], rollback.DD_BLOCK_COUNT)
            self.assertEqual(result["capture_sha256"], current_hash)
            stable.assert_has_calls(
                [
                    mock.call(mock.ANY, rollback.ROLLBACK_SHA256),
                    mock.call(mock.ANY, rollback.CONTROL_SHA256),
                ]
            )
            capture.assert_called_once()
            capture_argv = capture.call_args.args[0]
            self.assertEqual(capture_argv[0], rollback.ADB)
            self.assertEqual(capture_argv[3], "exec-out")
            self.assertIn(f"count={rollback.DD_BLOCK_COUNT}", capture_argv[4])
            private_capture = Path(result["capture_path"])
            self.assertTrue(private_capture.is_file())
            self.assertEqual(private_capture.stat().st_size, rollback.BOOT_PREFIX_SIZE)
            self.assertEqual(private_capture.stat().st_mode & 0o777, 0o600)

    def test_unknown_preimage_unrelated_block_is_refused_without_capture_publish(self) -> None:
        predecessor, intended, mixed, _current_hash = self._unknown_capture_fixture()
        corrupt = bytearray(mixed)
        corrupt[rollback.CAPTURE_BLOCK_SIZE * 3 : rollback.CAPTURE_BLOCK_SIZE * 4] = (
            b"X" * rollback.CAPTURE_BLOCK_SIZE
        )
        corrupt = bytes(corrupt)
        current_hash = rollback.sha256(corrupt)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_artifact_bytes",
                        side_effect=[predecessor, intended],
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "run_capture", return_value=corrupt))
                stack.enter_context(mock.patch.object(rollback, "_boot_hash", return_value=current_hash))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_boot_size",
                        return_value=rollback.BOOT_PREFIX_SIZE,
                    )
                )
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "unrelated block"):
                    rollback._capture_unknown_preimage(
                        root,
                        "corrupt-capture",
                        SERIAL,
                        current_hash,
                        rollback.BOOT_PREFIX_SIZE,
                        source_record(),
                    )
            self.assertFalse(
                any(
                    path.name.startswith(rollback.CAPTURE_PREFIX)
                    for path in (root / "evidence" / "private").glob("*")
                )
            )

    def test_unknown_preimage_before_host_after_hash_mismatch_is_refused(self) -> None:
        predecessor, intended, mixed, current_hash = self._unknown_capture_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_artifact_bytes",
                        side_effect=[predecessor, intended],
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "run_capture",
                        return_value=b"Z" * rollback.BOOT_PREFIX_SIZE,
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "_boot_hash", return_value=current_hash))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_boot_size",
                        return_value=rollback.BOOT_PREFIX_SIZE,
                    )
                )
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "before and host"):
                    rollback._capture_unknown_preimage(
                        root,
                        "before-host-mismatch",
                        SERIAL,
                        current_hash,
                        rollback.BOOT_PREFIX_SIZE,
                        source_record(),
                    )
            self.assertFalse((root / "evidence" / "private").exists())

    def test_unknown_preimage_device_after_drift_is_refused(self) -> None:
        predecessor, intended, mixed, current_hash = self._unknown_capture_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_artifact_bytes",
                        side_effect=[predecessor, intended],
                    )
                )
                stack.enter_context(mock.patch.object(rollback, "run_capture", return_value=mixed))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_boot_hash",
                        return_value="c" * 64,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_boot_size",
                        return_value=rollback.BOOT_PREFIX_SIZE,
                    )
                )
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "after"):
                    rollback._capture_unknown_preimage(
                        root,
                        "after-drift",
                        SERIAL,
                        current_hash,
                        rollback.BOOT_PREFIX_SIZE,
                        source_record(),
                    )
            self.assertFalse((root / "evidence" / "private").exists())

    def test_physical_rollback_claim_is_source_and_experiment_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(rollback, "REPO_ROOT", root):
                identity, key = rollback._rollback_effect_identity(
                    "d" * 64,
                    rollback.BOOT_PREFIX_SIZE,
                )
                claim_path = rollback._rollback_effect_claim_path(key)
                first = rollback._create_rollback_effect_claim(
                    claim_path,
                    identity=identity,
                    effect_key_sha256=key,
                    experiment_id="first-profile-id",
                    terminal="before_recovery_effect_marker",
                )
                self.assertTrue(first)
                with self.assertRaisesRegex(rollback.RollbackRecoveryError, "replay forbidden"):
                    rollback._create_rollback_effect_claim(
                        claim_path,
                        identity=identity,
                        effect_key_sha256=key,
                        experiment_id="second-profile-id",
                        terminal="before_recovery_effect_marker",
                    )

    def test_same_source_normal_ambiguous_claim_allows_zero_write_recovery(self) -> None:
        """A matching normal owner may be reconciled without a second dd."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._prepare_source(root)
            preimage = rollback.ROLLBACK_SHA256
            with mock.patch.object(rollback, "REPO_ROOT", root):
                identity, key = rollback._rollback_effect_identity(
                    preimage,
                    rollback.BOOT_PREFIX_SIZE,
                )
                claim_path = claims.boot_prefix_claim_path(root, key)
                claims.create_boot_prefix_claim(
                    claim_path,
                    identity=identity,
                    key_sha256=key,
                    experiment_id="normal-control-owner",
                    provenance={
                        "owner_kind": "normal-remapper",
                        "profile": "control",
                        "predecessor_sha256": rollback.ROLLBACK_SHA256,
                        "predecessor_size": rollback.BOOT_PREFIX_SIZE,
                        "image_sha256": rollback.CONTROL_SHA256,
                        "image_size": rollback.BOOT_PREFIX_SIZE,
                        "journal_path": str(source),
                    },
                )
            fake = FakeAdb(current_hash=preimage)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=fake))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_image_digest",
                        return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256),
                    )
                )
                rollback.collect(self._args(root))
            self.assertEqual(fake.write_count, 0)
            journals = list(
                (root / "evidence" / "private").glob(
                    "verification-024-boot-torn-rollback-*.journal.json"
                )
            )
            self.assertEqual(len(journals), 1)
            journal = json.loads(journals[0].read_text(encoding="utf-8"))
            self.assertTrue(journal["physical_effect_claim"]["claimed"])
            self.assertTrue(
                journal["physical_effect_claim"]["continued_from_normal_ambiguous"]
            )

    def test_same_source_continuations_lease_before_staging_one_writer(self) -> None:
        """Only the source-lease winner may mutate staging or issue the dd."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence" / "private" / (
                "verification-024-remapper-boot-flash-read.journal.json"
            )
            source.parent.mkdir(parents=True)
            source.write_text(
                json.dumps(
                    source_record(
                        profile="read",
                        pre_hash=rollback.CONTROL_SHA256,
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            identity, key = rollback._rollback_effect_identity(
                rollback.CONTROL_SHA256,
                rollback.BOOT_PREFIX_SIZE,
            )
            claim_path = claims.boot_prefix_claim_path(root, key)
            claims.create_boot_prefix_claim(
                claim_path,
                identity=identity,
                key_sha256=key,
                experiment_id="normal-read-owner",
                provenance={
                    "owner_kind": "normal-remapper",
                    "profile": "read",
                    "predecessor_sha256": rollback.CONTROL_SHA256,
                    "predecessor_size": rollback.BOOT_PREFIX_SIZE,
                    "image_sha256": rollback.READ_SHA256,
                    "image_size": rollback.BOOT_PREFIX_SIZE,
                    "journal_path": str(source),
                },
            )

            gate = threading.Barrier(2, timeout=10.0)
            local = threading.local()
            fakes = [FakeAdb(current_hash=rollback.CONTROL_SHA256) for _ in range(2)]
            outcomes: list[tuple[str, object]] = []

            def routed_run(argv):
                return local.fake(argv)

            def gated_source_claim(*args, **kwargs):
                gate.wait()
                return real_source_claim(*args, **kwargs)

            real_source_claim = rollback._create_source_claim

            def owner(index: int) -> None:
                local.fake = fakes[index]
                args = argparse.Namespace(
                    experiment_id=f"torn-lease-race-{index}",
                    flash_journal=source,
                    execute=True,
                )
                try:
                    result = rollback.collect(args)
                except BaseException as exc:  # one loser is expected
                    outcomes.append(("error", exc))
                else:
                    outcomes.append(("ok", result))

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=routed_run))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_image_digest",
                        return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_create_source_claim",
                        side_effect=gated_source_claim,
                    )
                )
                threads = [
                    threading.Thread(target=owner, args=(index,))
                    for index in range(2)
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(15.0)
                self.assertTrue(all(not thread.is_alive() for thread in threads))

            self.assertEqual(len(outcomes), 2)
            self.assertEqual(sum(kind == "ok" for kind, _ in outcomes), 1)
            self.assertEqual(sum(kind == "error" for kind, _ in outcomes), 1)
            for fake in fakes:
                mutation_commands = []
                for command in fake.commands:
                    shell = command[-1] if len(command) >= 5 and command[3] == "shell" else ""
                    if shell.startswith("set -e; ") or shell.startswith("rm -f ") or (
                        len(command) >= 5 and command[3] == "push"
                    ):
                        mutation_commands.append(command)
                if fake.write_count == 1:
                    self.assertEqual(
                        sum(
                            command[-1].startswith("set -e; ")
                            for command in mutation_commands
                        ),
                        1,
                    )
                else:
                    self.assertEqual(fake.write_count, 0)
                    self.assertEqual(mutation_commands, [])
            journals = list(
                (root / "evidence" / "private").glob(
                    "verification-024-boot-torn-rollback-torn-lease-race-*.journal.json"
                )
            )
            self.assertEqual(len(journals), 2)
            winner_journals = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in journals
                if json.loads(path.read_text(encoding="utf-8"))["status"]
                in {rollback.PASS_STATUS, rollback.PASS_ALREADY_STATUS}
            ]
            self.assertEqual(len(winner_journals), 1)
            winner = winner_journals[0]
            self.assertEqual(
                winner["source_consumption_claim_phase"],
                "before_staging_cleanup",
            )
            with mock.patch.object(
                rollback,
                "TARGET_SERIAL_SHA256",
                hashlib.sha256(SERIAL.encode()).hexdigest(),
            ):
                with mock.patch.object(rollback, "REPO_ROOT", root):
                    claim_hash = rollback._validate_source(
                        source_record(
                            profile="read",
                            pre_hash=rollback.CONTROL_SHA256,
                        ),
                        source_path=source,
                    )["semantic_sha256"]
            source_claim = root / "evidence" / "private" / (
                f"{rollback.SOURCE_CLAIM_PREFIX}{claim_hash}.claim.json"
            )
            self.assertEqual(
                json.loads(source_claim.read_text(encoding="utf-8"))["claim_phase"],
                "before_staging_cleanup",
            )

    def test_same_source_zero_write_continuations_lease_before_cleanup_one_owner(self) -> None:
        """Zero-write cleanup is also serialized by both claims."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._prepare_source(root)
            preimage = rollback.ROLLBACK_SHA256
            identity, key = rollback._rollback_effect_identity(
                preimage,
                rollback.BOOT_PREFIX_SIZE,
            )
            claim_path = claims.boot_prefix_claim_path(root, key)
            claims.create_boot_prefix_claim(
                claim_path,
                identity=identity,
                key_sha256=key,
                experiment_id="normal-control-owner",
                provenance={
                    "owner_kind": "normal-remapper",
                    "profile": "control",
                    "predecessor_sha256": rollback.ROLLBACK_SHA256,
                    "predecessor_size": rollback.BOOT_PREFIX_SIZE,
                    "image_sha256": rollback.CONTROL_SHA256,
                    "image_size": rollback.BOOT_PREFIX_SIZE,
                    "journal_path": str(source),
                },
            )

            gate = threading.Barrier(2, timeout=10.0)
            local = threading.local()
            fakes = [FakeAdb(current_hash=preimage) for _ in range(2)]
            outcomes: list[tuple[str, object]] = []

            def routed_run(argv):
                return local.fake(argv)

            real_source_claim = rollback._create_source_claim

            def gated_source_claim(*args, **kwargs):
                gate.wait()
                return real_source_claim(*args, **kwargs)

            def owner(index: int) -> None:
                local.fake = fakes[index]
                args = argparse.Namespace(
                    experiment_id=f"torn-zero-lease-race-{index}",
                    flash_journal=source,
                    execute=True,
                )
                try:
                    result = rollback.collect(args)
                except BaseException as exc:  # one loser is expected
                    outcomes.append(("error", exc))
                else:
                    outcomes.append(("ok", result))

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(rollback, "REPO_ROOT", root))
                stack.enter_context(mock.patch.object(rollback, "run_checked", side_effect=routed_run))
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "TARGET_SERIAL_SHA256",
                        hashlib.sha256(SERIAL.encode()).hexdigest(),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_stable_image_digest",
                        return_value=(rollback.BOOT_PREFIX_SIZE, rollback.ROLLBACK_SHA256),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        rollback,
                        "_create_source_claim",
                        side_effect=gated_source_claim,
                    )
                )
                threads = [
                    threading.Thread(target=owner, args=(index,))
                    for index in range(2)
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(15.0)
                self.assertTrue(all(not thread.is_alive() for thread in threads))

            self.assertEqual(len(outcomes), 2)
            self.assertEqual(sum(kind == "ok" for kind, _ in outcomes), 1)
            self.assertEqual(sum(kind == "error" for kind, _ in outcomes), 1)
            for fake in fakes:
                mutation_commands = []
                for command in fake.commands:
                    shell = command[-1] if len(command) >= 5 and command[3] == "shell" else ""
                    if shell.startswith("set -e; ") or shell.startswith("rm -f ") or (
                        len(command) >= 5 and command[3] == "push"
                    ):
                        mutation_commands.append(command)
                self.assertEqual(fake.write_count, 0)
                if mutation_commands:
                    # Exactly one owner reaches the cleanup rebind/rm pair;
                    # the losing owner must have no rm/push/effect command.
                    self.assertEqual(
                        sum(command[-1].startswith("rm -f ") for command in mutation_commands),
                        1,
                    )
                else:
                    self.assertEqual(mutation_commands, [])

            journals = list(
                (root / "evidence" / "private").glob(
                    "verification-024-boot-torn-rollback-torn-zero-lease-race-*.journal.json"
                )
            )
            self.assertEqual(len(journals), 2)
            winner_journals = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in journals
                if json.loads(path.read_text(encoding="utf-8"))["status"]
                == rollback.PASS_ALREADY_STATUS
            ]
            self.assertEqual(len(winner_journals), 1)
            self.assertEqual(
                winner_journals[0]["source_consumption_claim_phase"],
                "before_staging_cleanup",
            )
            self.assertEqual(
                winner_journals[0]["source_consumption_claim_terminal"],
                "terminal_zero_write_close",
            )
            self.assertEqual(
                winner_journals[0]["physical_effect_claim"]["terminal"],
                "before_zero_write_cleanup",
            )


if __name__ == "__main__":
    unittest.main()
