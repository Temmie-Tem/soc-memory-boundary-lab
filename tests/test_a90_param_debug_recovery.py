from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import a90_param_debug_recovery as recovery


def source_record(*, action: str = "apply-mid") -> dict[str, object]:
    if action == "apply-mid":
        before_hex, after_hex = "444c4f57", "444d4944"
        before_label, after_label = "LOW", "MID"
        before_sha, after_sha = recovery.ROLLBACK_SHA256, recovery.MID_SHA256
        before_stable, after_stable = (
            recovery.PARAM_STABLE_LOW_SHA256,
            recovery.PARAM_STABLE_MID_SHA256,
        )
    else:
        before_hex, after_hex = "444d4944", "444c4f57"
        before_label, after_label = "MID", "LOW"
        before_sha, after_sha = recovery.MID_SHA256, recovery.ROLLBACK_SHA256
        before_stable, after_stable = (
            recovery.PARAM_STABLE_MID_SHA256,
            recovery.PARAM_STABLE_LOW_SHA256,
        )
    target = {
        "model": recovery.TARGET_MODEL,
        "soc": recovery.TARGET_SOC,
        "bootloader": recovery.TARGET_BOOTLOADER,
        "runtime": recovery.TARGET_RUNTIME,
        "kernel": recovery.TARGET_KERNEL,
    }
    return {
        "schema": recovery.SOURCE_SCHEMA,
        "experiment_id": "ambiguous-param-source",
        "action": action,
        "status": recovery.AMBIGUOUS_STATUS,
        "effect_dispatched": True,
        "effect_armed": True,
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "cleanup_deferred": True,
        "reconcile_required": True,
        "expected_target": dict(target),
        "target": dict(target),
        "target_verified": True,
        "cmdline_before": {
            "androidboot.em.model": recovery.TARGET_MODEL,
            "androidboot.bootloader": recovery.TARGET_BOOTLOADER,
            "androidboot.debug_level": "0x4f4c" if action == "apply-mid" else "0x494d",
            "androidboot.force_upload": "0x0",
            "sec_debug.dump_sink": "0x0",
            "androidboot.upload_offset": recovery.PARAM_CMDLINE_UPLOAD_OFFSET,
            "unrelated": "retained-private-value",
        },
        "download_mode_before": "1",
        "partition": {
            "partname": recovery.PARAM_PARTNAME,
            "devname": recovery.PARAM_DEVNAME,
            "major": recovery.PARAM_MAJOR,
            "minor": recovery.PARAM_MINOR,
            "sectors": recovery.PARAM_SECTORS,
            "byte_size": recovery.PARAM_PARTITION_BYTES,
            "read_only": recovery.PARAM_READ_ONLY,
            "logical_block_size": recovery.PARAM_LOGICAL_BLOCK_SIZE,
            "start_sector": recovery.PARAM_START_SECTOR,
        },
        "transition": {
            "partition_offset": "0x900000",
            "size": 4,
            "before_label": before_label,
            "after_label": after_label,
            "before_bytes_hex": before_hex,
            "after_bytes_hex": after_hex,
            "before_sha256": before_sha,
            "after_sha256": after_sha,
            "before_stable_sha256": before_stable,
            "after_stable_sha256": after_stable,
            "stable_mask": {
                "excluded_ranges": [[0, 1]],
                "stable_ranges": [[1, recovery.PARAM_PARTITION_BYTES]],
                "stable_size": recovery.PARAM_STABLE_SIZE,
            },
        },
        "device_sha256_before": before_sha,
        "device_stable_sha256_before": before_stable,
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[1, recovery.PARAM_PARTITION_BYTES]],
            "stable_size": recovery.PARAM_STABLE_SIZE,
        },
        "stable_range": {
            "start": recovery.PARAM_STABLE_OFFSET,
            "end": recovery.PARAM_PARTITION_BYTES,
            "size": recovery.PARAM_STABLE_SIZE,
            "sha256": before_stable,
        },
        "volatile_byte0_before": 0,
        "payload": {
            "path": recovery.PAYLOAD_PATH,
            "size": 4,
            "sha256": recovery.sha256(
                recovery.MID_BYTES if action == "apply-mid" else recovery.LOW_BYTES
            ),
            "readback_base64": "RE1JRA==" if action == "apply-mid" else "RExPVw==",
        },
        "regular_file_dd_smoke": {
            "args": list(recovery.SMOKE_DD_ARGS),
            "passed": True,
            "expected_sha256": recovery.SMOKE_EXPECTED_SHA256[
                recovery.MID_BYTES if action == "apply-mid" else recovery.LOW_BYTES
            ],
            "readback_sha256": recovery.SMOKE_EXPECTED_SHA256[
                recovery.MID_BYTES if action == "apply-mid" else recovery.LOW_BYTES
            ],
        },
        "effect_argv": list(recovery.FIXED_EFFECT_ARGV),
    }


class A90ParamDebugRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.low, self.mid = recovery.pinned_images()

    def test_exact_low_and_mid_classification(self) -> None:
        self.assertEqual(recovery.classify_live_image(self.low), recovery.ALREADY_LOW)
        self.assertEqual(recovery.classify_live_image(self.mid), recovery.RECOVERABLE_MID)
        self.assertEqual(len(self.low), recovery.PARAM_PARTITION_BYTES)
        self.assertEqual(self.low[recovery.PARAM_DEBUG_OFFSET : recovery.PARAM_DEBUG_OFFSET + 4], b"DLOW")
        self.assertEqual(self.mid[recovery.PARAM_DEBUG_OFFSET : recovery.PARAM_DEBUG_OFFSET + 4], b"DMID")

    def test_representative_torn_four_byte_fields_are_recoverable(self) -> None:
        for field in (b"\0\0\0\0", b"\xff\xff\xff\xff", b"DL0W", b"XXXX", b"DLO\0"):
            with self.subTest(field=field):
                torn = bytearray(self.low)
                torn[recovery.PARAM_DEBUG_OFFSET : recovery.PARAM_DEBUG_OFFSET + 4] = field
                self.assertEqual(
                    recovery.classify_live_image(bytes(torn)), recovery.RECOVERABLE_TORN
                )

    def test_volatile_byte0_delta_is_accepted_but_stable_delta_is_refused(self) -> None:
        for source in (self.low, self.mid):
            with self.subTest(source=source[recovery.PARAM_DEBUG_OFFSET : recovery.PARAM_DEBUG_OFFSET + 4]):
                changed = bytearray(source)
                changed[0] ^= 0x01
                expected = (
                    recovery.ALREADY_LOW
                    if source is self.low
                    else recovery.RECOVERABLE_MID
                )
                self.assertEqual(recovery.classify_live_image(bytes(changed)), expected)
                stable_changed = bytearray(changed)
                stable_changed[1] ^= 0x01
                with self.assertRaisesRegex(recovery.RecoveryError, "stable range"):
                    recovery.classify_live_image(bytes(stable_changed))

    def test_wrong_size_and_wrong_known_hash_are_refused(self) -> None:
        with self.assertRaisesRegex(recovery.RecoveryError, "size"):
            recovery.classify_live_image(self.low[:-1])
        with self.assertRaisesRegex(recovery.RecoveryError, "size"):
            recovery.classify_live_image(self.low + b"\0")

        # A four-byte MID field with a changed outside byte must never be
        # accepted as the pinned MID image.
        wrong = bytearray(self.mid)
        wrong[-1] ^= 0x01
        with self.assertRaisesRegex(recovery.RecoveryError, "outside"):
            recovery.classify_live_image(bytes(wrong))

    def test_source_validator_accepts_both_ambiguous_transition_actions(self) -> None:
        for action in ("apply-mid", "restore-low"):
            with self.subTest(action=action):
                result = recovery.validate_source_journal(source_record(action=action))
                self.assertEqual(result["action"], action)
                self.assertTrue(result["effect_armed"])
                self.assertEqual(result["effect_dispatched_count"], 1)
                self.assertTrue(result["reconcile_required"])
        restore_low_state = source_record(action="restore-low")
        restore_low_state["cmdline_before"]["androidboot.debug_level"] = "0x4f4c"  # type: ignore[index]
        result = recovery.validate_source_journal(restore_low_state)
        self.assertEqual(result["cmdline_relevant"]["androidboot.debug_level"], "0x4f4c")

    def test_source_cmdline_and_download_mode_are_exact_and_summary_is_safe(self) -> None:
        record = source_record()
        summary = recovery.safe_source_summary(record)
        self.assertEqual(
            summary["cmdline_relevant"],
            {
                "androidboot.em.model": recovery.TARGET_MODEL,
                "androidboot.bootloader": recovery.TARGET_BOOTLOADER,
                "androidboot.debug_level": "0x4f4c",
                "androidboot.force_upload": "0x0",
                "sec_debug.dump_sink": "0x0",
                "androidboot.upload_offset": recovery.PARAM_CMDLINE_UPLOAD_OFFSET,
            },
        )
        self.assertEqual(summary["download_mode_before"], "1")
        self.assertNotIn("unrelated", summary["cmdline_relevant"])
        for field, value in (
            ("androidboot.em.model", "SM-S906N"),
            ("androidboot.bootloader", "other"),
            ("androidboot.debug_level", "0x494d"),
            ("androidboot.force_upload", "0x1"),
            ("sec_debug.dump_sink", "0x1"),
            ("androidboot.upload_offset", "0"),
        ):
            with self.subTest(field=field):
                mutated = source_record()
                mutated["cmdline_before"][field] = value  # type: ignore[index]
                with self.assertRaises(recovery.RecoveryError):
                    recovery.validate_source_journal(mutated)
        restore_wrong = source_record(action="restore-low")
        restore_wrong["cmdline_before"]["androidboot.debug_level"] = "0x55ff"  # type: ignore[index]
        with self.assertRaises(recovery.RecoveryError):
            recovery.validate_source_journal(restore_wrong)
        mutated = source_record()
        mutated["download_mode_before"] = "0"
        with self.assertRaises(recovery.RecoveryError):
            recovery.validate_source_journal(mutated)

    def test_current_transition_final_shape_derives_arm_proof(self) -> None:
        record = source_record()
        # The producer's reconstructed final journal omits these convenience
        # fields; its exact target plus ambiguous status/dispatch marker is
        # the durable proof retained after an effect-side exception.
        for key in ("expected_target", "target_verified", "effect_armed", "effect_dispatched_count"):
            record.pop(key)
        result = recovery.validate_source_journal(record)
        self.assertEqual(result["target"], record["target"])
        self.assertTrue(result["effect_armed"])
        self.assertEqual(result["effect_dispatched_count"], 1)

    def test_recovery_plan_keeps_mid_torn_and_pending_states_open(self) -> None:
        torn = bytearray(self.low)
        torn[recovery.PARAM_DEBUG_OFFSET : recovery.PARAM_DEBUG_OFFSET + 4] = b"XXXX"
        cases = (
            (self.low, recovery.ALREADY_LOW, False, False),
            (self.mid, recovery.RECOVERABLE_MID, True, True),
            (bytes(torn), recovery.RECOVERABLE_TORN, True, True),
            (None, None, True, True),
        )
        for image, expected, reconcile, write_required in cases:
            with self.subTest(expected=expected):
                plan = recovery.recovery_plan(source_record(), image)
                self.assertEqual(plan["classification"], expected)
                self.assertEqual(plan["reconcile_required"], reconcile)
                self.assertEqual(plan["recovery_write_required"], write_required)
                self.assertEqual(plan["closure_ready"], expected == recovery.ALREADY_LOW)

    def test_source_validator_rejects_nonexact_effect_and_target_fields(self) -> None:
        invalid = {
            "status": "APPLIED_VERIFIED",
            "action": "other",
            "target.model": "SM-S906N",
            "target.soc": "SM8250",
            "target.runtime": "other",
            "partition.devname": "sda11",
            "partition.partname": "other",
            "partition.start_sector": recovery.PARAM_START_SECTOR + 8,
            "transition.partition_offset": "0x900004",
            "transition.size": 8,
            "device_stable_sha256_before": "b" * 64,
            "payload.path": "/tmp/arbitrary-payload",
            "payload.size": 8,
            "payload.sha256": "b" * 64,
            "payload.readback_base64": "AAAA",
            "regular_file_dd_smoke.passed": False,
            "regular_file_dd_smoke.args": ["dd", "if=/tmp/other"],
            "regular_file_dd_smoke.expected_sha256": "b" * 64,
            "regular_file_dd_smoke.readback_sha256": "b" * 64,
            "effect_argv": list(recovery.FIXED_EFFECT_ARGV[:-1]) + ["status=progress"],
            "effect_dispatched": False,
            "effect_armed": False,
            "effect_dispatched_count": 2,
            "effect_replayed": True,
            "cleanup_deferred": False,
            "reconcile_required": False,
        }
        for label, value in invalid.items():
            with self.subTest(field=label):
                record = source_record()
                if "." not in label:
                    record[label] = value
                else:
                    parent, key = label.split(".", 1)
                    if parent == "target":
                        record["target"][key] = value  # type: ignore[index]
                    elif parent == "partition":
                        record["partition"][key] = value  # type: ignore[index]
                    elif parent == "transition":
                        record["transition"][key] = value  # type: ignore[index]
                    elif parent == "payload":
                        record["payload"][key] = value  # type: ignore[index]
                    else:
                        record["regular_file_dd_smoke"][key] = value  # type: ignore[index]
                with self.assertRaises(recovery.RecoveryError):
                    recovery.validate_source_journal(record)

    def test_source_requires_stable_identity_not_full_only(self) -> None:
        record = source_record()
        record["device_sha256_before"] = "a" * 64
        self.assertEqual(
            recovery.validate_source_journal(record)["device_sha256_before"], "a" * 64
        )
        missing = source_record()
        missing["transition"].pop("before_stable_sha256")  # type: ignore[index]
        with self.assertRaisesRegex(recovery.RecoveryError, "stable"):
            recovery.validate_source_journal(missing)
        missing = source_record()
        missing.pop("stable_mask")
        with self.assertRaisesRegex(recovery.RecoveryError, "stable"):
            recovery.validate_source_journal(missing)

    def test_strict_source_json_positive_and_negatives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_bytes(json.dumps(source_record(), separators=(",", ":")).encode("utf-8"))
            value, raw, digest = recovery.parse_source_journal(source)
            self.assertEqual(value["schema"], recovery.SOURCE_SCHEMA)
            self.assertEqual(raw, source.read_bytes())
            self.assertEqual(digest, recovery.sha256(raw))

            source.write_bytes(b'{"schema":"x","schema":"y"}')
            with self.assertRaisesRegex(recovery.RecoveryError, "duplicate"):
                recovery.parse_source_journal(source)

            source.write_bytes(b'{"nested":{"v":NaN}}')
            with self.assertRaisesRegex(recovery.RecoveryError, "non-finite"):
                recovery.parse_source_journal(source)

            source.write_bytes(b"{\xff")
            with self.assertRaisesRegex(recovery.RecoveryError, "UTF-8"):
                recovery.parse_source_journal(source)

            source.write_bytes(b"{}")
            temp_sibling = source.with_name(source.name + ".tmp")
            temp_sibling.write_bytes(b"stale")
            with self.assertRaisesRegex(recovery.RecoveryError, "temporary sibling"):
                recovery.parse_source_journal(source)

            temp_sibling.unlink()
            source.write_bytes(b"0" * (recovery.MAX_SOURCE_BYTES + 1))
            with self.assertRaisesRegex(recovery.RecoveryError, "bound"):
                recovery.parse_source_journal(source)

    def test_source_parser_rejects_leaf_and_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual.json"
            actual.write_text(json.dumps(source_record()), encoding="utf-8")
            leaf = root / "leaf.json"
            leaf.symlink_to(actual)
            with self.assertRaisesRegex(recovery.RecoveryError, "symlink"):
                recovery.parse_source_journal(leaf)

            parent = root / "link-parent"
            parent.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(recovery.RecoveryError, "symlink"):
                recovery.parse_source_journal(parent / "actual.json")

    def test_source_consumption_claim_is_fixed_and_single_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "evidence" / "private" / "ambiguous-param-source.journal.json"
            source_path.parent.mkdir(parents=True)
            source_path.write_bytes(json.dumps(source_record(), sort_keys=True).encode() + b"\n")
            summary = recovery.validate_source_path(source_path, root=root)
            claim = recovery.claim_source_consumption(
                summary,
                "recovery-one",
                root=root,
                reason="ALREADY_LOW_TERMINAL",
            )
            self.assertTrue(recovery.source_consumption_claim_exists(summary, root=root))
            self.assertEqual(claim["source_journal_sha256"], summary["source_sha256"])
            with self.assertRaisesRegex(recovery.RecoveryError, "consumed"):
                recovery.claim_source_consumption(
                    summary,
                    "recovery-two",
                    root=root,
                    reason="ALREADY_LOW_TERMINAL",
                )

    def test_partial_source_claim_remains_a_replay_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "evidence" / "private" / "ambiguous-param-source.journal.json"
            source_path.parent.mkdir(parents=True)
            source_path.write_bytes(json.dumps(source_record(), sort_keys=True).encode() + b"\n")
            summary = recovery.validate_source_path(source_path, root=root)
            original_write = recovery.os.write
            try:
                recovery.os.write = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("crash"))  # type: ignore[assignment]
                with self.assertRaises(OSError):
                    recovery.claim_source_consumption(
                        summary,
                        "recovery-crash",
                        root=root,
                        reason="DLOW_EFFECT_MARKER",
                    )
            finally:
                recovery.os.write = original_write  # type: ignore[assignment]
            self.assertTrue(recovery.source_consumption_claim_exists(summary, root=root))

    def test_cli_has_only_explicit_execute_and_experiment_id(self) -> None:
        parser = recovery.build_parser()
        parsed = parser.parse_args(["--experiment-id", "x", "--execute"])
        self.assertTrue(parsed.execute)
        for option in (
            "--partition",
            "--offset",
            "--value",
            "--path",
            "--payload",
            "--source-journal",
            "--device",
            "--host",
            "--port",
        ):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(["--experiment-id", "x", "--execute", option, "x"])

    def test_execute_gate_and_recovery_plan_are_contact_free(self) -> None:
        args = type("Args", (), {"experiment_id": "ambiguous-param-source", "execute": False})()
        source = source_record()
        with mock.patch.object(recovery.os, "open", side_effect=AssertionError("contact")):
            with self.assertRaisesRegex(recovery.RecoveryError, "--execute"):
                recovery.execute(args, source_path=Path("unused"))

        args.execute = True
        plan = recovery.recovery_plan(source, self.mid)
        self.assertEqual(plan["classification"], recovery.RECOVERABLE_MID)
        self.assertFalse(plan["effect_dispatched"])
        self.assertEqual(plan["effect_dispatched_count"], 0)

    def test_import_has_no_filesystem_or_device_side_effect(self) -> None:
        with mock.patch.object(recovery.os, "open", side_effect=AssertionError("open")), mock.patch.object(
            recovery.os, "stat", side_effect=AssertionError("stat")
        ):
            importlib.reload(recovery)


if __name__ == "__main__":
    unittest.main()
