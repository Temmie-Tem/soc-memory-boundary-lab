from __future__ import annotations

import base64
import json
import math
import shutil
import tempfile
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from tools import a90_last_kmsg_capture as capture
from tools import a90_inline_remapper_mid_probe as probe
from tools import a90_v024_r2_incident as r2_incident
from tools import a90_verification024_finalize as finalizer


def _complete_fixed_op_frame(value: str) -> dict[str, object]:
    """Build one producer-shaped complete fixed-op frame for positive cases."""

    payload = (
        b"run: pid=1, q/Ctrl-C cancels\n"
        + f"A90R{int(value, 16):x}\n[exit 0]\n".encode("ascii")
    )
    protocol_flags = finalizer.inline_protocol_flags_for_argv(finalizer.fixed_op_argv())
    assert protocol_flags is not None
    transcript = (
        f"A90P1 BEGIN seq=1 cmd=run argc=5 flags={protocol_flags}\n".encode("ascii")
        + payload
        + b"\n[done] run (0ms)\n"
        + f"A90P1 END seq=1 cmd=run rc=0 errno=0 duration_ms=0 flags={protocol_flags} status=ok\n".encode("ascii")
    )
    return {
        "evidence_id": "fixed_op_4",
        "argv": list(finalizer.fixed_op_argv()),
        "begin": {"cmd": "run", "seq": "1", "argc": "5", "flags": protocol_flags},
        "end": {"cmd": "run", "seq": "1", "rc": "0", "errno": "0", "duration_ms": "0", "flags": protocol_flags, "status": "ok"},
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
        "payload_size": len(payload),
        "transcript_base64": base64.b64encode(transcript).decode("ascii"),
        "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
        "transcript_size": len(transcript),
    }


class Verification024FinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._original_repo_root = finalizer.REPO_ROOT
        self._original_capsule_sha256 = finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256
        self._original_capsule_size = finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE
        self._original_inline_capsule_sha256 = probe.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256
        self._original_inline_capsule_size = probe.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE
        # The production finalizer is fixed to its module repository root;
        # patch that explicit test seam for this isolated evidence universe.
        finalizer.REPO_ROOT = self.root
        self.predecessor_capsule = {
            "schema": finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA,
            "semantic_capsule": {
                "schema": "fixture-semantic-v1",
                "effect_grades": {"fixed_op": "PROVED_ZERO"},
                "claims": {"live_authority": False},
            },
            "historical_git_verification": {
                "schema": "fixture-historical-git-v1",
                "commit_id": "fixture-commit",
                "commit_type": "commit",
                "sources": {},
            },
        }
        self.predecessor_capsule_bytes = finalizer.control_retry.canonical_capsule_bytes(
            self.predecessor_capsule
        )
        self.predecessor_capsule_sha256 = finalizer.hashlib.sha256(
            self.predecessor_capsule_bytes
        ).hexdigest()
        self.predecessor_capsule_size = len(self.predecessor_capsule_bytes)
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = self.predecessor_capsule_sha256
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = self.predecessor_capsule_size
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = self.predecessor_capsule_sha256
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = self.predecessor_capsule_size
        self._capsule_builder_patch = mock.patch.object(
            finalizer.control_retry,
            "build_predecessor_capsule",
            return_value=self.predecessor_capsule,
        )
        self._capsule_builder_patch.start()
        (self.root / "evidence/private").mkdir(parents=True)
        (self.root / "evidence/manifests").mkdir(parents=True)
        # The fixed incident validator is intentionally exercised against an
        # isolated evidence root.  Copy only its redacted checkpoint; private
        # R2 artifacts remain outside this fixture and are never reopened.
        incident_source = (
            r2_incident.REPO_ROOT / r2_incident.MANIFEST_RELATIVE_PATH
        )
        incident_target = self.root / r2_incident.MANIFEST_RELATIVE_PATH
        incident_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(incident_source, incident_target)
        r3_incident_source = (
            r2_incident.REPO_ROOT / r2_incident.R3_MANIFEST_RELATIVE_PATH
        )
        r3_incident_target = self.root / r2_incident.R3_MANIFEST_RELATIVE_PATH
        r3_incident_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(r3_incident_source, r3_incident_target)
        self._make_receipts()
        self._upgrade_receipts_for_v024_contract()

    def tearDown(self) -> None:
        self._capsule_builder_patch.stop()
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = self._original_inline_capsule_sha256
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = self._original_inline_capsule_size
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = self._original_capsule_sha256
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = self._original_capsule_size
        finalizer.REPO_ROOT = self._original_repo_root
        self.temp.cleanup()

    def _write(self, path: Path, value: object) -> bytes:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        path.write_bytes(data)
        return data

    def _make_receipts(self) -> None:
        completed = "2026-08-27T00:00:00+00:00"
        control_id = finalizer.CONTROL_EXPERIMENT_ID
        control_raw = {
            "schema": "sdm855-a90-inline-remapper-mid-private-v1",
            "experiment_id": control_id,
            "mode": "control",
            "completed_utc": completed,
            "candidate_sha256": finalizer.CONTROL_SHA256,
            "candidate_size": finalizer.BOOT_PREFIX_SIZE,
            "target": {
                "model": "SM-A908N",
                "soc": "SM8150",
                "soc_id": "339",
                "runtime_version": "0.9.285",
                "runtime_build": "v2321-usb-clean-identity-rodata",
                "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
                "bootloader": "A908NKSU5EWA3",
                "debug_level": "0x494d",
                "force_upload": "0",
                "dump_sink": "0",
            },
            "flash_journal": {"profile": "control", "image_sha256": finalizer.CONTROL_SHA256, "readback_sha256": finalizer.CONTROL_SHA256, "predecessor_sha256": finalizer.ROLLBACK_SHA256},
            "fixed_op_measurement": {
                "op": 4,
                "args": [],
                "rc": 0,
                "status": "ok",
                "value": "0x000000000000c071",
            },
            "outcome": "CONTROL_PASS",
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": False,
            "effect_replayed": False,
            **finalizer.CONTROL_SAFETY_EFFECT_PROJECTION,
            "health_after": {
                "ok": True,
                "target": {
                    "model": "SM-A908N",
                    "soc": "SM8150",
                    "soc_id": "339",
                    "runtime_version": "0.9.285",
                    "runtime_build": "v2321-usb-clean-identity-rodata",
                    "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
                    "bootloader": "A908NKSU5EWA3",
                    "debug_level": "0x494d",
                    "force_upload": "0",
                    "dump_sink": "0",
                },
                "selftest": {"passed": 11, "warn": 1, "fail": 0, "duration": 43, "entries": 12},
            },
            "cleanup_ok": True,
            "panic_on_oops_restored": True,
        }
        control_raw_bytes = self._write(self.root / "evidence/private" / f"{control_id}.json", control_raw)
        control_journal = {
            "schema": "sdm855-a90-inline-remapper-mid-journal-v1",
            "experiment_id": control_id,
            "mode": "control",
            "status": "CONTROL_VERIFIED",
            "outcome": "CONTROL_PASS",
            "completed_utc": completed,
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": False,
            "effect_replayed": False,
            **finalizer.CONTROL_SAFETY_EFFECT_PROJECTION,
            "value": "0x000000000000c071",
            "cleanup_ok": True,
            "panic_on_oops_restored": True,
        }
        control_journal_bytes = self._write(self.root / "evidence/private" / f"{control_id}.journal.json", control_journal)
        control_manifest = {
            "schema": "sdm855-a90-inline-remapper-mid-public-v1",
            "experiment_id": control_id,
            "mode": "control",
            "completed_utc": completed,
            "candidate_sha256": finalizer.CONTROL_SHA256,
            "candidate_size": finalizer.BOOT_PREFIX_SIZE,
            "target_verified": True,
            "target_evaluation": "VERIFIED",
            "target_model": finalizer.TARGET_MODEL,
            "soc": finalizer.TARGET_SOC,
            "runtime": "0.9.285",
            "outcome": "CONTROL_PASS",
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": False,
            "effect_replayed": False,
            "health_after_ok": True,
            "cleanup_ok": True,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": True,
            "automatic_retries": False,
            **finalizer.CONTROL_SAFETY_EFFECT_PROJECTION,
            "flash_journal_bound": True,
            "flash_profile": "control",
            "flash_image_sha256": finalizer.CONTROL_SHA256,
            "flash_readback_sha256": finalizer.CONTROL_SHA256,
            "flash_predecessor_sha256": finalizer.ROLLBACK_SHA256,
            "fixed_op": {"op": 4, "args": [], "buffer_size": 0x58, "buffer_sha256": finalizer._fixed_op_buffer_hash()},
            "raw_snapshot_sha256": finalizer.hashlib.sha256(control_raw_bytes).hexdigest(),
            "raw_snapshot_size": len(control_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(control_journal_bytes).hexdigest(),
            "journal_size": len(control_journal_bytes),
            "private_record": {"filename": f"{control_id}.json", "journal_filename": f"{control_id}.journal.json"},
        }
        control_manifest_path = self.root / "evidence/manifests" / finalizer.CONTROL_MANIFEST_NAME
        control_manifest_bytes = self._write(control_manifest_path, control_manifest)
        self.control_manifest = control_manifest_path
        self.control_public = control_manifest

        read_id = finalizer.READ_SOURCE_EXPERIMENT_ID
        read_raw = {
            "schema": "sdm855-a90-inline-remapper-mid-private-v1",
            "experiment_id": read_id,
            "mode": "read",
            "candidate_sha256": finalizer.READ_SHA256,
            "candidate_size": finalizer.BOOT_PREFIX_SIZE,
            "completed_utc": "2026-08-27T00:01:00+00:00",
            "target": {
                "model": "SM-A908N",
                "soc": "SM8150",
                "soc_id": "339",
                "runtime_version": "0.9.285",
                "runtime_build": "v2321-usb-clean-identity-rodata",
                "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
                "bootloader": "A908NKSU5EWA3",
                "debug_level": "0x494d",
                "force_upload": "0",
                "dump_sink": "0",
            },
            "value": None,
            "outcome": "REFUSED_AT_MID_CANDIDATE",
            "effect_ambiguous": True,
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_replayed": False,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "flash_journal": {
                "profile": "read",
                "image_sha256": finalizer.READ_SHA256,
                "readback_sha256": finalizer.READ_SHA256,
                "predecessor_sha256": finalizer.CONTROL_SHA256,
            },
        }
        read_raw_bytes = self._write(self.root / "evidence/private" / f"{read_id}.json", read_raw)
        read_journal = {
            "schema": "sdm855-a90-inline-remapper-mid-journal-v1",
            "experiment_id": read_id,
            "mode": "read",
            "status": "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED",
            "outcome": "REFUSED_AT_MID_CANDIDATE",
            "completed_utc": "2026-08-27T00:01:00+00:00",
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": True,
            "effect_replayed": False,
            "value": None,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
        }
        read_journal_bytes = self._write(self.root / "evidence/private" / f"{read_id}.journal.json", read_journal)
        control_binding = {
            "experiment_id": control_id,
            "manifest_sha256": finalizer.hashlib.sha256(control_manifest_bytes).hexdigest(),
            "manifest_size": len(control_manifest_bytes),
            "raw_sha256": finalizer.hashlib.sha256(control_raw_bytes).hexdigest(),
            "raw_size": len(control_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(control_journal_bytes).hexdigest(),
            "journal_size": len(control_journal_bytes),
            "completed_utc": completed,
            "candidate_sha256": finalizer.CONTROL_SHA256,
            "candidate_size": finalizer.BOOT_PREFIX_SIZE,
            "value": "0x000000000000c071",
        }
        read_raw["control_manifest"] = control_binding
        read_raw_bytes = self._write(self.root / "evidence/private" / f"{read_id}.json", read_raw)
        read_manifest = {
            "schema": "sdm855-a90-inline-remapper-mid-public-v1",
            "experiment_id": read_id,
            "mode": "read",
            "completed_utc": "2026-08-27T00:01:00+00:00",
            "candidate_sha256": finalizer.READ_SHA256,
            "candidate_size": finalizer.BOOT_PREFIX_SIZE,
            "target_verified": True,
            "target_evaluation": "VERIFIED",
            "target_model": finalizer.TARGET_MODEL,
            "soc": finalizer.TARGET_SOC,
            "runtime": "0.9.285",
            "effect_replayed": False,
            "automatic_retries": False,
            "partition_writes": False,
            "flash_journal_bound": True,
            "flash_profile": "read",
            "flash_image_sha256": finalizer.READ_SHA256,
            "flash_readback_sha256": finalizer.READ_SHA256,
            "flash_predecessor_sha256": finalizer.CONTROL_SHA256,
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": True,
            "outcome": "REFUSED_AT_MID_CANDIDATE",
            "returned_value_present": False,
            "returned_value_sha256": None,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "health_after_ok": False,
            "raw_snapshot_sha256": finalizer.hashlib.sha256(read_raw_bytes).hexdigest(),
            "raw_snapshot_size": len(read_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(read_journal_bytes).hexdigest(),
            "journal_size": len(read_journal_bytes),
            "private_record": {"filename": f"{read_id}.json", "journal_filename": f"{read_id}.journal.json"},
            "control_manifest": control_binding,
        }
        self.read_manifest = self.root / "evidence/manifests" / f"{read_id}.manifest.json"
        self._write(self.read_manifest, read_manifest)

        last_id = finalizer.LAST_KMSG_EXPERIMENT_ID
        last_log = bytearray(b"\0" * capture.LAST_KMSG_REFERENCE_SIZE)
        lines = {
            "bark": b"Watchdog bark! Now = 69.080467\n",
            "last_pet": b"Watchdog last pet at 58.080193\n",
            "debug_level": b"DebugLevel : 1145654596, ForceUploadFlag : 0\n",
            "upload_cause": b"UploadCause[Non Secure Watchdog Bark], Don't check hangcnt\n",
            "collect_upload": b"collect_rr_data : upload_cause = Non Secure Watchdog Bark\n",
            "tz_reason": b"collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT\n",
        }
        for key, offset in capture.EXACT_REFERENCE_OFFSETS.items():
            # The retained parser is line-anchored.  Keep each marker at its
            # historical byte offset while giving it the newline boundary of
            # the real /proc/last_kmsg source.
            if offset:
                last_log[offset - 1] = 0x0A
            last_log[offset : offset + len(lines[key])] = lines[key]
        captured_log_bytes = bytes(last_log)
        last_signature = capture.parse_exact_reset_signature(captured_log_bytes)
        last_raw = {"exact_reset_signature": last_signature}
        last_signature_bytes = json.dumps(last_raw, indent=2, ensure_ascii=True, sort_keys=False).encode() + b"\n"
        last_raw_path = self.root / "evidence/private" / f"{last_id}.last_kmsg.bin"
        last_raw_path.write_bytes(last_signature_bytes)
        captured_path = self.root / "evidence/private" / f"{last_id}.last_kmsg.raw.bin"
        captured_path.write_bytes(captured_log_bytes)
        last_metadata = {
            "schema": "sdm855-a90-last-kmsg-capture-private-v2",
            "experiment_id": last_id,
            "completed_utc": "2026-08-27T00:02:00+00:00",
            "target": {"model": finalizer.TARGET_MODEL, "soc": finalizer.TARGET_SOC, "runtime": "0.9.285"},
            "last_kmsg": {"sha256": finalizer.hashlib.sha256(last_signature_bytes).hexdigest(), "size": len(last_signature_bytes)},
            "captured_log": {"filename": captured_path.name, "sha256": finalizer.hashlib.sha256(captured_log_bytes).hexdigest(), "size": len(captured_log_bytes)},
            "exact_reset_signature": last_signature,
        }
        self._write(self.root / "evidence/private" / f"{last_id}.private.json", last_metadata)
        self._write(self.root / "evidence/private" / f"{last_id}.journal.json", {
            "schema": "sdm855-a90-last-kmsg-capture-private-v2",
            "experiment_id": last_id,
            "status": "COMPLETE",
            "target_verified": True,
            "effect_dispatched": False,
            "effect_replayed": False,
            "last_kmsg_read_once": True,
            "private_record": f"{last_id}.private.json",
            "raw_filename": f"{last_id}.last_kmsg.bin",
            "captured_log_filename": f"{last_id}.last_kmsg.raw.bin",
            "completed_utc": "2026-08-27T00:02:00+00:00",
            "retained_sha256": finalizer.hashlib.sha256(last_signature_bytes).hexdigest(),
            "retained_size": len(last_signature_bytes),
            "captured_log_sha256": finalizer.hashlib.sha256(captured_log_bytes).hexdigest(),
            "captured_log_size": len(captured_log_bytes),
        })
        self.last_kmsg = self.root / "evidence/manifests" / finalizer.LAST_KMSG_MANIFEST_NAME
        last_public = {
            "schema": "sdm855-a90-last-kmsg-capture-public-v2",
            "experiment_id": last_id,
            "completed_utc": "2026-08-27T00:02:00+00:00",
            "target_verified": True,
            "target_model": finalizer.TARGET_MODEL,
            "soc": finalizer.TARGET_SOC,
            "runtime": "0.9.285",
            "transport_module": "tools.a90_pa28_live",
            "transport_source": "tools/a90_pa28_live.py",
            "reboot_dispatched": False,
            "last_kmsg_read_once": True,
            "exact_reset_signature": last_signature,
            "retained_sha256": finalizer.hashlib.sha256(last_signature_bytes).hexdigest(),
            "retained_size": len(last_signature_bytes),
            "captured_log_sha256": finalizer.hashlib.sha256(captured_log_bytes).hexdigest(),
            "captured_log_size": len(captured_log_bytes),
            "private_record": {"filename": f"{last_id}.last_kmsg.bin", "metadata_filename": f"{last_id}.private.json", "journal_filename": f"{last_id}.journal.json", "captured_log_filename": f"{last_id}.last_kmsg.raw.bin"},
        }
        # The producer intentionally preserves ordered_offsets insertion
        # order; sorted JSON would turn a valid signature into a forged one.
        self.last_kmsg.write_bytes(
            json.dumps(last_public, ensure_ascii=True, sort_keys=False).encode() + b"\n"
        )

        self.rollback_flash = self.root / "evidence/private" / finalizer.FLASH_JOURNAL_NAMES["rollback"]
        self._write(self.rollback_flash, {
            "schema": "sdm855-a90-remapper-boot-flash-private-v1",
            "profile": "rollback",
            "status": "PASS_READBACK_AND_CLEANUP",
            "write_count": 1,
            "effect_dispatched": True,
            "effect_armed": True,
            "partition_writes": True,
            "staging_attempted": True,
            "staging_attempt_count": 1,
            "staging_dispatch_count": 1,
            "staging_status": "STAGING_PUSH_RETURNED",
            "staging_removed": True,
            "staging_cleanup_deferred": False,
            "pre_staging_removed": True,
            "pre_cleanup_error": None,
            "reboot_dispatched": False,
            "cleanup_error": None,
            "error": None,
            "target_model": finalizer.TARGET_MODEL,
            "target_device": finalizer.TARGET_DEVICE,
            "target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "boot_alias": "/dev/block/by-name/boot",
            "boot_node": "/dev/block/sda24",
            "post_staging_revalidated": True,
            "post_staging_predecessor_sha256": finalizer.READ_SHA256,
            "post_staging_predecessor_size": finalizer.BOOT_PREFIX_SIZE,
            "post_staging_predecessor_revalidated": True,
            "pre_cleanup_revalidated": True,
            "pre_push_revalidated": True,
            "pre_effect_revalidated": True,
            "post_dispatch_revalidated": True,
            "final_revalidated": True,
            "final_cleanup_revalidated": True,
            "pre_cleanup_target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "pre_push_target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "post_staging_target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "pre_effect_target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "post_dispatch_target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "final_target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "final_cleanup_target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "post_staging_rebind_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "pre_effect_rebind_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "post_dispatch_rebind_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "final_rebind_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "remote_staging": "/tmp/sdm855-remapper-boot-rollback.img",
            "effect_argv": ["dd", "if=/tmp/sdm855-remapper-boot-rollback.img", "of=/dev/block/sda24", "bs=4096", "count=14864", "conv=fsync"],
            "image_sha256": finalizer.ROLLBACK_SHA256,
            "remote_staging_sha256": finalizer.ROLLBACK_SHA256,
            "readback_sha256": finalizer.ROLLBACK_SHA256,
            "post_dispatch_staging_sha256": finalizer.ROLLBACK_SHA256,
            "image_size": finalizer.BOOT_PREFIX_SIZE,
            "remote_staging_size": finalizer.BOOT_PREFIX_SIZE,
            "readback_size": finalizer.BOOT_PREFIX_SIZE,
            "post_dispatch_staging_size": finalizer.BOOT_PREFIX_SIZE,
            "post_dispatch_predecessor_sha256": finalizer.READ_SHA256,
            "post_dispatch_predecessor_size": finalizer.BOOT_PREFIX_SIZE,
            "predecessor_size": finalizer.BOOT_PREFIX_SIZE,
            "allowed_predecessors": list(finalizer.ROLLBACK_ALLOWED_PREDECESSORS),
            "predecessor_sha256": finalizer.READ_SHA256,
            "guarded_effect_receipt": {
                "schema": "sdm855-a90-remapper-guarded-effect-v1",
                "guard": {
                    "current_sha256": finalizer.READ_SHA256,
                    "current_size": str(finalizer.BOOT_PREFIX_SIZE),
                    "staging_sha256": finalizer.ROLLBACK_SHA256,
                    "staging_size": str(finalizer.BOOT_PREFIX_SIZE),
                },
                "dd_result": {"rc": "0", "count": "14864"},
                "write_count": 1,
            },
            "completed_utc": "2026-08-27T00:04:00+00:00",
        })
        self.system_boot = self.root / "evidence/private" / finalizer.ROLLBACK_SYSTEM_JOURNAL_NAME
        system_id = finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID
        system_obj = {
            "schema": "sdm855-a90-twrp-system-boot-once-journal-v1",
            "experiment_id": system_id,
            "phase": "rollback",
            "status": "SYSTEM_BOOT_DISCONNECT_OBSERVED",
            "completed_utc": "2026-08-27T00:05:00+00:00",
            "expected_target": {
                "model": finalizer.TARGET_MODEL,
                "device": finalizer.TARGET_DEVICE,
                "twrp_version": "3.7.0_12-0",
                "serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            },
            "target": {
                "state": "recovery",
                "model": finalizer.TARGET_MODEL,
                "device": finalizer.TARGET_DEVICE,
                "twrp_version": "3.7.0_12-0",
                "serial_sha256": finalizer.TARGET_SERIAL_SHA256,
                "boot_id": "00000000-0000-0000-0000-000000000001",
            },
            "target_verified": True,
            "target_model": finalizer.TARGET_MODEL,
            "target_device": finalizer.TARGET_DEVICE,
            "twrp_version": "3.7.0_12-0",
            "effect_dispatched": True,
            "effect_replayed": False,
            "effect_dispatch_count": 1,
            "dispatch_count": 1,
            "write_count": 1,
            "preparation_write_count": 1,
            "preparation_read_count": 1,
            "preparation_verified": True,
            "preparation_command": "twrp set tw_reboot_arg system",
            "preparation_read_command": "twrp get tw_reboot_arg",
            "effect_command": "sync; twrp set tw_gui_done 1",
            "effect_argv": ["sync; twrp set tw_gui_done 1"],
            "reboot_dispatched": True,
            "automatic_retries": False,
            "partition_writes": False,
            "preparation": {
                "command": "twrp set tw_reboot_arg system",
                "read_command": "twrp get tw_reboot_arg",
                "expected_value": "system",
                "write_count": 1,
                "read_count": 1,
                "read_attempt_count": 1,
                "dispatched": True,
                "verified": True,
            },
            "effect": {
                "command": "sync; twrp set tw_gui_done 1",
                "argv": ["sync; twrp set tw_gui_done 1"],
                "dispatch_count": 1,
                "dispatched": True,
                "replayed": False,
                "status": "SYSTEM_BOOT_DISCONNECT_OBSERVED",
                "returned": True,
            },
            "observation": {"disconnect_observed": True},
        }
        system_bytes = self._write(self.system_boot, system_obj)
        self._write(self.root / "evidence/manifests" / f"{system_id}.manifest.json", {
            "schema": "sdm855-a90-twrp-system-boot-once-public-v1",
            "experiment_id": system_id,
            "phase": "rollback",
            "status": "SYSTEM_BOOT_DISCONNECT_OBSERVED",
            "completed_utc": "2026-08-27T00:05:00+00:00",
            "target_verified": True,
            "target_model": finalizer.TARGET_MODEL,
            "target_device": finalizer.TARGET_DEVICE,
            "twrp_version": "3.7.0_12-0",
            "target": {
                "model": finalizer.TARGET_MODEL,
                "device": finalizer.TARGET_DEVICE,
                "twrp_version": "3.7.0_12-0",
                "serial_sha256": finalizer.TARGET_SERIAL_SHA256,
                "state": "recovery",
                "status": "VERIFIED",
            },
            "expected_target": {
                "model": finalizer.TARGET_MODEL,
                "device": finalizer.TARGET_DEVICE,
                "twrp_version": "3.7.0_12-0",
                "serial_sha256": finalizer.TARGET_SERIAL_SHA256,
                "state": "recovery",
            },
            "preparation": {"write_count": 1, "read_count": 1, "verified": True},
            "effect": {"dispatch_count": 1, "effect_dispatched_count": 1, "effect_replayed": False},
            "observation": {"disconnect_observed": True},
            "dispatch_count": 1,
            "effect_dispatched_count": 1,
            "effect_replayed": False,
            "partition_writes": False,
            "journal_sha256": finalizer.hashlib.sha256(system_bytes).hexdigest(),
            "journal_size": len(system_bytes),
        })
        self.param_capture = self.root / "evidence/manifests" / finalizer.PARAM_CAPTURE_MANIFEST_NAME
        param_id = finalizer.PARAM_CAPTURE_EXPERIMENT_ID
        param_dir = self.root / "evidence/private" / param_id
        param_dir.mkdir()
        shutil.copyfile(
            Path("evidence/private/verification-023-a90-param-final-verify-20260827-01/param--sda10.bin"),
            param_dir / "param--sda10.bin",
        )
        metadata = {
            "schema": "sdm855-a90-param-capture-private-v1",
            "experiment_id": param_id,
            "completed_utc": "2026-08-27T00:06:00+00:00",
            "capture": {"size": finalizer.PARAM_CAPTURE_SIZE, "sha256": finalizer.PARAM_LOW_SHA256, "device_sha256_before": finalizer.PARAM_LOW_SHA256, "device_sha256_after": finalizer.PARAM_LOW_SHA256},
        }
        self._write(param_dir / "capture-metadata.json", metadata)
        self._write(param_dir / "capture-journal.json", {"schema": "sdm855-a90-param-capture-arbitration-journal-v1", "experiment_id": param_id, "status": "COMPLETE", "retained_sha256": finalizer.PARAM_LOW_SHA256, "retained_size": finalizer.PARAM_CAPTURE_SIZE, "completed_utc": "2026-08-27T00:06:00+00:00"})
        self._write(self.param_capture, {
            "schema": "sdm855-a90-param-capture-public-v1",
            "experiment_id": param_id,
            "completed_utc": "2026-08-27T00:06:00+00:00",
            "capture": {
                "size": finalizer.PARAM_CAPTURE_SIZE,
                "sha256": finalizer.PARAM_LOW_SHA256,
                "device_sha256_before": finalizer.PARAM_LOW_SHA256,
                "device_sha256_after": finalizer.PARAM_LOW_SHA256,
                "triple_hash_match": True,
            },
            "full_hash_verified": True,
            "partition_writes": False,
            "cmdline_relevant": {"androidboot.debug_level": "0x4f4c"},
        })
        self.runtime_health = self.root / "evidence/manifests" / finalizer.RUNTIME_HEALTH_MANIFEST_NAME
        runtime_id = finalizer.RUNTIME_HEALTH_EXPERIMENT_ID
        runtime_raw = {
            "schema": "sdm855-a90-runtime-health-private-v2",
            "health_scope": "FINAL_ROLLBACK_ONLY",
            "experiment_id": runtime_id,
            "completed_utc": "2026-08-27T00:07:00+00:00",
            "transport_module": "tools.a90_pa28_live",
            "transport_source": "tools/a90_pa28_live.py",
            "transport_source_sha256": "0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66",
            "transport_source_size": 150104,
            "target": {
                "model": finalizer.TARGET_MODEL,
                "soc": finalizer.TARGET_SOC,
                "runtime": "0.9.285",
                "soc_id": 339,
                "panic_on_oops": 1,
                "cmdline": {
                    "androidboot.em.model": finalizer.TARGET_MODEL,
                    "androidboot.debug_level": "0x4f4c",
                    "androidboot.force_upload": "0x0",
                    "sec_debug.dump_sink": "0x0",
                },
            },
            "boot_attestation": {
                "expected_sha256": finalizer.ROLLBACK_SHA256,
                "captured_sha256": finalizer.ROLLBACK_SHA256,
                "captured_size": finalizer.BOOT_PREFIX_SIZE,
                "cleanup_ok": True,
                "hash_matches_candidate": True,
                "size_matches_candidate": True,
            },
            "v024_temp_absence": {"absence_verified": True, "paths": [
                "/tmp/a90-native/verification-024-sda24",
                "/tmp/a90-native/verification-024-boot-prefix.bin",
                "/tmp/sdm855_mblab_param_debug_payload",
                "/tmp/sdm855_mblab_param_debug_dd_smoke",
                "/dev/sdm855_mblab_sda10",
            ], "paths_count": 5, "paths_sha256": finalizer.V024_TEMP_PATHS_SHA256},
            "selftest": {"passed": 11, "warn": 1, "fail": 0, "duration": 43, "entries": 12},
            "device_writes": {
                "stophud": True,
                "temporary_filesystem_mutations": True,
                "temporary_block_node_mutations": True,
                "temporary_mutation_paths": [
                    "/tmp/a90-native/verification-024-sda24",
                    "/tmp/a90-native/verification-024-boot-prefix.bin",
                    "/tmp/sdm855_mblab_param_debug_payload",
                    "/tmp/sdm855_mblab_param_debug_dd_smoke",
                    "/dev/sdm855_mblab_sda10",
                ],
                "temporary_mutation_operations": ["mkdir", "mknodb", "dd_to_temp", "rm", "absence_checks"],
                "partition_writes": False,
                "mmio_writes": False,
                "controller_writes": False,
                "security_state_writes": False,
                "persistent_writes": False,
            },
        }
        runtime_raw_bytes = self._write(self.root / "evidence/private" / f"{runtime_id}.json", runtime_raw)
        runtime_journal_bytes = self._write(self.root / "evidence/private" / f"{runtime_id}.journal.json", {
            "schema": "sdm855-a90-runtime-health-private-v2",
            "experiment_id": runtime_id,
            "status": "COMPLETE",
            "completed_utc": "2026-08-27T00:07:00+00:00",
            "effect_dispatched": False,
            "effect_replayed": False,
            "raw_sha256": finalizer.hashlib.sha256(runtime_raw_bytes).hexdigest(),
            "raw_size": len(runtime_raw_bytes),
        })
        self._write(self.runtime_health, {
            "schema": "sdm855-a90-runtime-health-public-v2",
            "health_scope": "FINAL_ROLLBACK_ONLY",
            "experiment_id": runtime_id,
            "completed_utc": "2026-08-27T00:07:00+00:00",
            "transport_module": "tools.a90_pa28_live",
            "transport_source": "tools/a90_pa28_live.py",
            "target_verified": True,
            "target_model": finalizer.TARGET_MODEL,
            "soc": finalizer.TARGET_SOC,
            "runtime": "0.9.285",
            "cmdline_debug_level": "0x4f4c",
            "cmdline_force_upload": "0x0",
            "cmdline_dump_sink": "0x0",
            "panic_on_oops": 1,
            "boot_prefix_sha256": finalizer.ROLLBACK_SHA256,
            "boot_prefix_size": finalizer.BOOT_PREFIX_SIZE,
            "persistent_writes": False,
            "partition_writes": False,
            "mmio_writes": False,
            "controller_writes": False,
            "security_state_writes": False,
            "temporary_filesystem_mutations": True,
            "temporary_block_node_mutations": True,
            "stophud_device_state_write": True,
            "bridge_binding_verified": True,
            "soc_id": 339,
            "selftest": {"passed": 11, "warn": 1, "fail": 0, "entries": 12},
            "boot_attestation": {
                "expected_sha256": finalizer.ROLLBACK_SHA256,
                "captured_sha256": finalizer.ROLLBACK_SHA256,
                "captured_size": finalizer.BOOT_PREFIX_SIZE,
                "cleanup_ok": True,
                "hash_matches_candidate": True,
                "size_matches_candidate": True,
            },
            "v024_temp_absence": {"paths_count": 5, "absence_verified": True, "paths_sha256": finalizer.V024_TEMP_PATHS_SHA256},
            "raw_snapshot_sha256": finalizer.hashlib.sha256(runtime_raw_bytes).hexdigest(),
            "raw_snapshot_size": len(runtime_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(runtime_journal_bytes).hexdigest(),
            "journal_size": len(runtime_journal_bytes),
            "private_record": {"filename": f"{runtime_id}.json", "journal_filename": f"{runtime_id}.journal.json"},
            "device_writes": {
                "stophud": True,
                "temporary_filesystem_mutations": True,
                "temporary_block_node_mutations": True,
                "persistent_writes": False,
                "partition_writes": False,
                "mmio_writes": False,
                "controller_writes": False,
                "security_state_writes": False,
            },
        })

    def _upgrade_receipts_for_v024_contract(self) -> None:
        """Add the producer-complete fields used by the hardened validators."""

        boot_id = "11111111-1111-4111-8111-111111111111"
        boot_hash = capture.sha256(boot_id.encode())
        attestation = {
            "sysfs_root": "/sys/class/block/sda24",
            "block_node": "/dev/block/sda24",
            "bs": 4096,
            "count": 14864,
            "expected_size": finalizer.BOOT_PREFIX_SIZE,
            "captured_size": finalizer.BOOT_PREFIX_SIZE,
            "expected_sha256": finalizer.CONTROL_SHA256,
            "captured_sha256": finalizer.CONTROL_SHA256,
            "sectors": 131072,
            "ro": 0,
            "hash_matches_candidate": True,
            "size_matches_candidate": True,
            "cleanup_ok": True,
            "cleanup_error": None,
            "sysfs_uevent": {"MAJOR": "259", "MINOR": "8", "DEVNAME": "sda24", "DEVTYPE": "partition", "PARTN": "24", "PARTNAME": "boot"},
            "stat": {"mode": "0600", "uid": "0", "gid": "0", "size": "0", "rdev": "259:8"},
        }
        attestation_private = {**attestation, "attest_node": "/tmp/a90-native/verification-024-sda24", "attest_file": "/tmp/a90-native/verification-024-boot-prefix.bin"}
        r2_incident_summary = r2_incident.validate_r2_incident(self.root)

        def frame(evidence_id: str, argv: tuple[str, ...], payload: bytes) -> dict[str, object]:
            protocol_flags = finalizer.inline_protocol_flags_for_argv(argv)
            if protocol_flags is None:
                raise AssertionError(f"test command has no native flag contract: {argv}")
            begin = {"cmd": argv[0], "seq": "1", "argc": str(len(argv)), "flags": protocol_flags}
            end = {"cmd": argv[0], "seq": "1", "rc": "0", "errno": "0", "duration_ms": "0", "flags": protocol_flags, "status": "ok"}
            transcript = (
                f"A90P1 BEGIN seq=1 cmd={argv[0]} argc={len(argv)} flags={protocol_flags}\n".encode("ascii")
                + payload
                + f"\n[done] {argv[0]} (0ms)\n".encode("ascii")
                + f"A90P1 END seq=1 cmd={argv[0]} rc=0 errno=0 duration_ms=0 flags={protocol_flags} status=ok\n".encode("ascii")
            )
            return {
                "evidence_id": evidence_id,
                "argv": list(argv),
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_sha256": capture.sha256(payload),
                "payload_size": len(payload),
                "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                "transcript_sha256": capture.sha256(transcript),
                "transcript_size": len(transcript),
                "begin": begin,
                "end": end,
            }

        panic_payloads = {
            "panic_before": b"1\n",
            "panic_set_0": b"writefile: ok",
            "panic_zero_verify": b"0\n",
            "panic_set_1": b"writefile: ok",
            "panic_restore_verify": b"1\n",
        }
        semantic_payloads = {
            "version_before": (
                b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\r\n"
                b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\r\n"
                b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\r\n"
                b"made by device owner\r\n"
                b"display: 1080x2400 connector=28 crtc=133 fb=208"
            ),
            "cmdline_before": (
                b"androidboot.em.model=SM-A908N androidboot.bootloader=A908NKSU5EWA3 "
                b"androidboot.debug_level=0x494d androidboot.force_upload=0x0 sec_debug.dump_sink=0x0\n"
            ),
            "soc_id_before": b"339\n",
            "selftest_before": b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12",
            "boot_id_before_read": boot_id.encode("ascii") + b"\n",
            "boot_sysfs_uevent": b"MAJOR=259\nMINOR=8\nDEVNAME=sda24\nDEVTYPE=partition\nPARTN=24\nPARTNAME=boot\n",
            "boot_sysfs_size": b"131072\n",
            "boot_sysfs_ro": b"0\n",
            "boot_attest_stat_node": b"mode=0600 uid=0 gid=0 size=0\r\nrdev=259:8",
            "boot_attest_mknod": b"",
        }
        transition = {
            "before": 1,
            "zero_write_attempted": True,
            "zero_set": True,
            "zero_verified": True,
            "restore_write_attempted": True,
            "restored": True,
            "restore_deferred": False,
            "proof_frame_ids": ["panic_before", "panic_set_0", "panic_zero_verify", "panic_set_1", "panic_restore_verify"],
        }
        r3_incident_summary = r2_incident.validate_r3_incident(self.root)
        fixed = {
            "argv": list(finalizer.fixed_op_argv()),
            "buffer_size": 0x58,
            "buffer_sha256": finalizer._fixed_op_buffer_hash(),
            "magic": "0xa90c0de5deadbeef",
            "op": 4,
            "args": [],
            "rc": 0,
            "status": "ok",
            "value": "0x000000000000c071",
            "a90r_record": "A90Rc071",
        }

        def fixed_frame(value: str) -> dict[str, object]:
            # Retain the same complete A90P1 exchange the inline producer
            # receives.  A summary measurement alone must never authorize a
            # returned-value classification.
            payload = (
                b"run: pid=1, q/Ctrl-C cancels\n"
                + f"A90R{int(value, 16):x}\n[exit 0]\n".encode("ascii")
            )
            protocol_flags = finalizer.inline_protocol_flags_for_argv(finalizer.fixed_op_argv())
            assert protocol_flags is not None
            transcript = (
                f"A90P1 BEGIN seq=1 cmd=run argc=5 flags={protocol_flags}\n".encode("ascii")
                + payload
                + b"\n[done] run (0ms)\n"
                + f"A90P1 END seq=1 cmd=run rc=0 errno=0 duration_ms=0 flags={protocol_flags} status=ok\n".encode("ascii")
            )
            return {
                "evidence_id": "fixed_op_4",
                "argv": list(finalizer.fixed_op_argv()),
                "begin": {"cmd": "run", "seq": "1", "argc": "5", "flags": protocol_flags},
                "end": {"cmd": "run", "seq": "1", "rc": "0", "errno": "0", "duration_ms": "0", "flags": protocol_flags, "status": "ok"},
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                "payload_size": len(payload),
                "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                "transcript_size": len(transcript),
            }

        def producer_frames(
            *, allow_fixed: bool, restored: bool, include_health: bool = False,
            candidate_sha256: str = finalizer.CONTROL_SHA256,
        ) -> list[dict[str, object]]:
            records: list[dict[str, object]] = []
            for evidence_id in finalizer._expected_full_frame_ids(
                1,
                allow_fixed=allow_fixed,
                restored=restored,
                include_health=include_health,
            ):
                argv = finalizer._frame_expected_argv(evidence_id)
                if evidence_id == "boot_attest_mknod":
                    argv = ("mknodb", "/tmp/a90-native/verification-024-sda24", "259", "8")
                assert argv is not None
                if evidence_id == "fixed_op_4":
                    records.append(fixed_frame(fixed["value"]))
                else:
                    payload = semantic_payloads.get(evidence_id, panic_payloads.get(evidence_id, b""))
                    if evidence_id.startswith("stophud_"):
                        payload = b"autohud: stopped"
                    elif evidence_id in {"version_before", "cmdline_before", "soc_id_before", "selftest_before", "boot_id_before_read"}:
                        pass
                    elif evidence_id in {"version_after", "cmdline_after", "soc_id_after", "selftest_after"}:
                        payload = semantic_payloads[evidence_id.replace("_after", "_before")]
                    elif evidence_id == "boot_attest_hash":
                        payload = (
                            b"run: pid=1, q/Ctrl-C cancels\n"
                            + f"{candidate_sha256}  /tmp/a90-native/verification-024-boot-prefix.bin\n[exit 0]\n".encode("ascii")
                        )
                    elif evidence_id == "boot_attest_size":
                        payload = b"run: pid=1, q/Ctrl-C cancels\n60882944 /tmp/a90-native/verification-024-boot-prefix.bin\n[exit 0]\n"
                    elif evidence_id in {
                        "boot_attest_remove_node", "boot_attest_remove_file",
                        "boot_attest_node_absent", "boot_attest_node_absent_not_symlink",
                        "boot_attest_file_absent", "boot_attest_file_absent_not_symlink",
                        "boot_attest_pre_node_absent", "boot_attest_pre_node_absent_not_symlink",
                        "boot_attest_pre_file_absent", "boot_attest_pre_file_absent_not_symlink",
                        "boot_attest_mkdir", "boot_attest_capture",
                    }:
                        payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n"
                    records.append(
                        frame(
                            evidence_id,
                            argv,
                            payload,
                        )
                    )
            return records

        control_frames = producer_frames(
            allow_fixed=True, restored=True, include_health=True,
            candidate_sha256=finalizer.CONTROL_SHA256,
        )
        control_raw_path = self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.json"
        control_journal_path = self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.journal.json"
        control_raw = json.loads(control_raw_path.read_text())
        control_raw["target"]["selftest_before"] = {
            "passed": 11, "warn": 1, "fail": 0, "duration": 43, "entries": 12
        }
        control_journal = json.loads(control_journal_path.read_text())
        rollback_flash_path = self.rollback_flash
        control_flash_path = self.root / "evidence/private" / finalizer.FLASH_JOURNAL_NAMES["control"]
        control_flash = json.loads(rollback_flash_path.read_text())
        control_flash.update({
            "profile": "control",
            "remote_staging": "/tmp/sdm855-remapper-boot.img",
            "image_sha256": finalizer.CONTROL_SHA256,
            "remote_staging_sha256": finalizer.CONTROL_SHA256,
            "readback_sha256": finalizer.CONTROL_SHA256,
            "post_dispatch_staging_sha256": finalizer.CONTROL_SHA256,
            "allowed_predecessors": [finalizer.ROLLBACK_SHA256],
            "predecessor_sha256": finalizer.ROLLBACK_SHA256,
            "post_staging_predecessor_sha256": finalizer.ROLLBACK_SHA256,
            "post_dispatch_predecessor_sha256": finalizer.ROLLBACK_SHA256,
            "guarded_effect_receipt": {
                "schema": "sdm855-a90-remapper-guarded-effect-v1",
                "guard": {
                    "current_sha256": finalizer.ROLLBACK_SHA256,
                    "current_size": str(finalizer.BOOT_PREFIX_SIZE),
                    "staging_sha256": finalizer.CONTROL_SHA256,
                    "staging_size": str(finalizer.BOOT_PREFIX_SIZE),
                },
                "dd_result": {"rc": "0", "count": "14864"},
                "write_count": 1,
            },
            "completed_utc": "2026-08-26T23:59:00+00:00",
        })
        control_flash["effect_argv"] = ["dd", "if=/tmp/sdm855-remapper-boot.img", "of=/dev/block/sda24", "bs=4096", "count=14864", "conv=fsync"]
        for key in ("image_sha256", "remote_staging_sha256", "readback_sha256", "post_dispatch_staging_sha256"):
            control_flash[key] = finalizer.CONTROL_SHA256
        control_flash_path.write_bytes(
            json.dumps(control_flash, sort_keys=True, separators=(",", ":")).encode()
        )
        flash_path = control_flash_path
        flash_bytes = flash_path.read_bytes()
        def install_claim(mode: str, candidate_sha256: str, experiment_id: str) -> tuple[Path, str, int, str]:
            key = finalizer._semantic_claim_key(mode, candidate_sha256, finalizer.BOOT_PREFIX_SIZE, boot_id)
            claim_path = self.root / "evidence/private" / f"verification-024-inline-op-{key}.claim.json"
            claim = {
                "schema": finalizer.SEMANTIC_CLAIM_SCHEMA,
                "mode": mode,
                "candidate_sha256": candidate_sha256,
                "candidate_size": finalizer.BOOT_PREFIX_SIZE,
                "boot_id": boot_id,
                "boot_id_sha256": boot_hash,
                "key_sha256": key,
                "claimed_by_experiment_id": experiment_id,
                "effect_replayed": False,
            }
            claim_data = self._write(claim_path, claim)
            return claim_path, finalizer.hashlib.sha256(claim_data).hexdigest(), len(claim_data), key
        control_claim_path, control_claim_hash, control_claim_size, control_claim_key = install_claim("control", finalizer.CONTROL_SHA256, finalizer.CONTROL_EXPERIMENT_ID)
        control_raw.update({
            "r2_incident_manifest_sha256": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "flash_journal": {"path": str(flash_path), "sha256": finalizer.hashlib.sha256(flash_bytes).hexdigest(), "size": len(flash_bytes), "profile": "control", "remote_staging": "/tmp/sdm855-remapper-boot.img", "image_sha256": finalizer.CONTROL_SHA256, "readback_sha256": finalizer.CONTROL_SHA256, "predecessor_sha256": finalizer.ROLLBACK_SHA256},
            "current_boot_attestation": attestation_private,
            "boot_id_before_read": boot_id,
            "boot_id_before_read_sha256": boot_hash,
            "value": fixed["value"],
            "fixed_op_measurement": fixed,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": True,
            "panic_restore_deferred": False,
            "panic_transition": transition,
            "dispatch_returned": True,
            "dispatch_failed": False,
            "frames": control_frames,
            "semantic_claim_path": str(control_claim_path),
            "semantic_claim_sha256": control_claim_hash,
            "semantic_claim_size": control_claim_size,
            "semantic_claim_key_sha256": control_claim_key,
            "semantic_claimed": True,
        })
        control_journal.update({
            "r2_incident_manifest_sha256": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "candidate_sha256": finalizer.CONTROL_SHA256,
            "candidate_size": finalizer.BOOT_PREFIX_SIZE,
            "op": 4,
            "op_args": [],
            "target": control_raw["target"],
            "health_after": control_raw["health_after"],
            "current_boot_attestation": attestation_private,
            "boot_id_before_read": boot_id,
            "boot_id_before_read_sha256": boot_hash,
            "fixed_op": {"op": 4, "args": [], "buffer_size": 0x58, "buffer_sha256": finalizer._fixed_op_buffer_hash()},
            "fixed_op_measurement": fixed,
            "flash_journal": control_raw["flash_journal"],
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": True,
            "panic_restore_deferred": False,
            "panic_transition": transition,
            "dispatch_returned": True,
            "dispatch_failed": False,
            "frames": control_frames,
            "semantic_claim_path": str(control_claim_path),
            "semantic_claim_sha256": control_claim_hash,
            "semantic_claim_size": control_claim_size,
            "semantic_claim_key_sha256": control_claim_key,
            "semantic_claimed": True,
        })
        preclaim = probe._control_r4_preclaim()
        preclaim_bytes = probe.json_bytes(preclaim)
        control_journal["control_r2_predecessor"] = {
            "preclaim_sha256": finalizer.hashlib.sha256(preclaim_bytes).hexdigest(),
            "preclaim_size": len(preclaim_bytes),
            "capsule": self.predecessor_capsule,
            "capsule_sha256": self.predecessor_capsule_sha256,
            "capsule_size": self.predecessor_capsule_size,
        }
        control_journal["control_r3_reconciliation"] = {
            "preclaim_sha256": finalizer.hashlib.sha256(preclaim_bytes).hexdigest(),
            "preclaim_size": len(preclaim_bytes),
            "r2_incident": r2_incident_summary,
        }
        control_journal["control_r4_reconciliation"] = {
            "preclaim_sha256": finalizer.hashlib.sha256(preclaim_bytes).hexdigest(),
            "preclaim_size": len(preclaim_bytes),
            "r3_incident": r3_incident_summary,
        }
        control_raw_bytes = self._write(control_raw_path, control_raw)
        control_journal_bytes = self._write(control_journal_path, control_journal)
        control_manifest = json.loads(self.control_manifest.read_text())
        control_manifest.update({
            "r2_incident_manifest_sha256": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "dispatch_returned": True,
            "dispatch_failed": False,
            "panic_transition": transition,
            "current_boot_attestation": attestation,
            "boot_id_before_read_sha256": boot_hash,
            "flash_journal_sha256": finalizer.hashlib.sha256(flash_bytes).hexdigest(),
            "flash_journal_size": len(flash_bytes),
            "fixed_op": {**control_manifest["fixed_op"], "rc": 0, "status": "ok", "value": fixed["value"]},
            "semantic_claim": {"filename": control_claim_path.name, "sha256": control_claim_hash, "size": control_claim_size, "key_sha256": control_claim_key},
            "raw_snapshot_sha256": finalizer.hashlib.sha256(control_raw_bytes).hexdigest(),
            "raw_snapshot_size": len(control_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(control_journal_bytes).hexdigest(),
            "journal_size": len(control_journal_bytes),
        })
        self._write(self.control_manifest, control_manifest)
        control_manifest_bytes = self.control_manifest.read_bytes()
        control_binding = {
            "experiment_id": control_manifest["experiment_id"],
            "mode": "control",
            "manifest_sha256": finalizer.hashlib.sha256(control_manifest_bytes).hexdigest(),
            "manifest_size": len(control_manifest_bytes),
            "raw_sha256": control_manifest["raw_snapshot_sha256"],
            "raw_size": control_manifest["raw_snapshot_size"],
            "journal_sha256": control_manifest["journal_sha256"],
            "journal_size": control_manifest["journal_size"],
            "completed_utc": control_manifest["completed_utc"],
            "candidate_sha256": control_manifest["candidate_sha256"],
            "candidate_size": control_manifest["candidate_size"],
            "value": control_manifest["fixed_op"]["value"],
            "target_dmid": finalizer.TARGET_DMID,
            "current_boot_attestation": control_manifest["current_boot_attestation"],
            "boot_id_before_read_sha256": control_manifest["boot_id_before_read_sha256"],
            "fixed_op_measurement": fixed,
            "predecessor_capsule_sha256": self.predecessor_capsule_sha256,
            "predecessor_capsule_size": self.predecessor_capsule_size,
            "r2_incident_manifest_sha256": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
        }

        read_raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        read_journal_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        read_raw = json.loads(read_raw_path.read_text())
        read_journal = json.loads(read_journal_path.read_text())
        read_flash_path = self.root / "evidence/private" / finalizer.FLASH_JOURNAL_NAMES["read"]
        read_flash = json.loads(rollback_flash_path.read_text())
        read_flash.update({
            "profile": "read",
            "remote_staging": "/tmp/sdm855-remapper-boot-read.img",
            "image_sha256": finalizer.READ_SHA256,
            "remote_staging_sha256": finalizer.READ_SHA256,
            "readback_sha256": finalizer.READ_SHA256,
            "post_dispatch_staging_sha256": finalizer.READ_SHA256,
            "allowed_predecessors": [finalizer.CONTROL_SHA256],
            "predecessor_sha256": finalizer.CONTROL_SHA256,
            "post_staging_predecessor_sha256": finalizer.CONTROL_SHA256,
            "post_dispatch_predecessor_sha256": finalizer.CONTROL_SHA256,
            "guarded_effect_receipt": {
                "schema": "sdm855-a90-remapper-guarded-effect-v1",
                "guard": {
                    "current_sha256": finalizer.CONTROL_SHA256,
                    "current_size": str(finalizer.BOOT_PREFIX_SIZE),
                    "staging_sha256": finalizer.READ_SHA256,
                    "staging_size": str(finalizer.BOOT_PREFIX_SIZE),
                },
                "dd_result": {"rc": "0", "count": "14864"},
                "write_count": 1,
            },
            "completed_utc": "2026-08-27T00:00:30+00:00",
        })
        read_flash["effect_argv"] = ["dd", "if=/tmp/sdm855-remapper-boot-read.img", "of=/dev/block/sda24", "bs=4096", "count=14864", "conv=fsync"]
        read_flash_path.write_bytes(
            json.dumps(read_flash, sort_keys=True, separators=(",", ":")).encode()
        )
        read_flash_bytes = read_flash_path.read_bytes()
        read_raw["flash_journal"] = {
            "path": str(read_flash_path),
            "sha256": finalizer.hashlib.sha256(read_flash_bytes).hexdigest(),
            "size": len(read_flash_bytes),
            "profile": "read",
            "remote_staging": "/tmp/sdm855-remapper-boot-read.img",
            "image_sha256": finalizer.READ_SHA256,
            "readback_sha256": finalizer.READ_SHA256,
            "predecessor_sha256": finalizer.CONTROL_SHA256,
        }
        read_journal["flash_journal"] = dict(read_raw["flash_journal"])
        read_attestation = {**attestation, "expected_sha256": finalizer.READ_SHA256, "captured_sha256": finalizer.READ_SHA256}
        read_attestation_private = {**read_attestation, "attest_node": "/tmp/a90-native/verification-024-sda24", "attest_file": "/tmp/a90-native/verification-024-boot-prefix.bin"}
        read_claim_path, read_claim_hash, read_claim_size, read_claim_key = install_claim("read", finalizer.READ_SHA256, finalizer.READ_SOURCE_EXPERIMENT_ID)
        refused_transition = {**transition, "restore_write_attempted": False, "restored": False, "restore_deferred": True, "proof_frame_ids": ["panic_before", "panic_set_0", "panic_zero_verify"]}
        partial_transcript = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
        no_value_error = {
            "exception_type": "TransportFailure", "exception_text": "bridge closed before terminal frame", "evidence_id": "fixed_op_4", "argv": fixed["argv"], "transport_no_value": True, "partial_evidence_present": True, "bounded": True, "a90r_present": False, "payload_base64": "", "payload_sha256": finalizer.hashlib.sha256(b"").hexdigest(), "payload_size": 0, "transcript_base64": base64.b64encode(partial_transcript).decode("ascii"), "transcript_sha256": finalizer.hashlib.sha256(partial_transcript).hexdigest(), "transcript_size": len(partial_transcript), "payload_bounded": True, "transcript_bounded": True, "begin": {"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"}, "end": None,
        }
        read_frames = producer_frames(
            allow_fixed=False, restored=False, candidate_sha256=finalizer.READ_SHA256
        )
        read_raw["target"]["selftest_before"] = {
            "passed": 11, "warn": 1, "fail": 0, "duration": 43, "entries": 12
        }
        read_raw.update({
            "target": control_raw["target"],
            "r2_incident_manifest_sha256": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "current_boot_attestation": read_attestation_private,
            "boot_id_before_read": boot_id,
            "boot_id_before_read_sha256": boot_hash,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "cleanup_ok": False,
            "panic_transition": refused_transition,
            "dispatch_returned": False,
            "dispatch_failed": True,
            "error": no_value_error,
            "frames": read_frames,
            "cleanup_ok": False,
            "control_manifest": control_binding,
            "semantic_claim_path": str(read_claim_path),
            "semantic_claim_sha256": read_claim_hash,
            "semantic_claim_size": read_claim_size,
            "semantic_claim_key_sha256": read_claim_key,
            "semantic_claimed": True,
        })
        read_journal.update({
            "candidate_sha256": finalizer.READ_SHA256,
            "candidate_size": finalizer.BOOT_PREFIX_SIZE,
            "r2_incident_manifest_sha256": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "op": 4,
            "op_args": [],
            "target": control_raw["target"],
            "current_boot_attestation": read_attestation_private,
            "boot_id_before_read": boot_id,
            "boot_id_before_read_sha256": boot_hash,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "cleanup_ok": False,
            "panic_transition": refused_transition,
            "dispatch_returned": False,
            "dispatch_failed": True,
            "fixed_op": {"op": 4, "args": [], "buffer_size": 0x58, "buffer_sha256": finalizer._fixed_op_buffer_hash()},
            "fixed_op_measurement": None,
            "error": no_value_error,
            "control_manifest": control_binding,
            "semantic_claim_path": str(read_claim_path),
            "semantic_claim_sha256": read_claim_hash,
            "semantic_claim_size": read_claim_size,
            "semantic_claim_key_sha256": read_claim_key,
            "semantic_claimed": True,
            "frames": read_frames,
        })
        read_raw_bytes = self._write(read_raw_path, read_raw)
        read_journal_bytes = self._write(read_journal_path, read_journal)
        read_manifest = json.loads(self.read_manifest.read_text())
        read_manifest.update({
            "r2_incident_manifest_sha256": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": finalizer.CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "dispatch_returned": False,
            "dispatch_failed": True,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "panic_transition": refused_transition,
            "transport_no_value": True,
            "cleanup_ok": False,
            "flash_journal_sha256": finalizer.hashlib.sha256(read_flash_bytes).hexdigest(),
            "flash_journal_size": len(read_flash_bytes),
            "current_boot_attestation": read_attestation,
            "boot_id_before_read_sha256": boot_hash,
            "fixed_op": {"op": 4, "args": [], "buffer_size": 0x58, "buffer_sha256": finalizer._fixed_op_buffer_hash(), "rc": None, "status": None, "value": None},
            "semantic_claim": {"filename": read_claim_path.name, "sha256": read_claim_hash, "size": read_claim_size, "key_sha256": read_claim_key},
            "raw_snapshot_sha256": finalizer.hashlib.sha256(read_raw_bytes).hexdigest(),
            "raw_snapshot_size": len(read_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(read_journal_bytes).hexdigest(),
            "journal_size": len(read_journal_bytes),
            "control_manifest": control_binding,
        })
        self._write(self.read_manifest, read_manifest)

        # Last-kmsg fixture is joined to the fixed read source
        # experiment ID and exact source hashes/boot UUID.
        source_summary = {
            "experiment_id": finalizer.READ_SOURCE_EXPERIMENT_ID,
            "manifest_sha256": finalizer.hashlib.sha256(self.read_manifest.read_bytes()).hexdigest(),
            "manifest_size": self.read_manifest.stat().st_size,
            "raw_sha256": finalizer.hashlib.sha256(read_raw_bytes).hexdigest(),
            "raw_size": len(read_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(read_journal_bytes).hexdigest(),
            "journal_size": len(read_journal_bytes),
            "completed_utc": read_manifest["completed_utc"],
            "source_pre_read_boot_id_sha256": boot_hash,
        }
        last_public = json.loads(self.last_kmsg.read_text())
        last_public.update({"read_source": source_summary, "source_pre_read_boot_id_sha256": boot_hash, "current_boot_id_sha256": capture.sha256("22222222-2222-4222-8222-222222222222".encode()), "boot_id_changed": True})
        self.last_kmsg.write_bytes(json.dumps(last_public, ensure_ascii=True, sort_keys=False).encode() + b"\n")
        last_metadata_path = self.root / "evidence/private/last-kmsg-final.private.json"
        last_metadata = json.loads(last_metadata_path.read_text())
        captured_log_bytes = (
            self.root / "evidence/private/last-kmsg-final.last_kmsg.raw.bin"
        ).read_bytes()
        last_current_boot_id = "22222222-2222-4222-8222-222222222222"
        last_cmdline = (
            b"skip_initramfs  rootwait   ro androidboot.em.model=SM-A908N  "
            b"androidboot.bootloader=A908NKSU5EWA3   androidboot.debug_level=0x494d  "
            b"androidboot.force_upload=0x0  sec_debug.dump_sink=0x0 "
            b"androidboot.serialno=ABC123 root=PARTUUID=01234567-89ab-cdef-0123-456789abcdef\n"
        )
        last_payloads = [
            b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\r\n"
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\r\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\r\n"
            b"made by device owner\r\n"
            b"display: 1080x2400 connector=28 crtc=133 fb=208",
            last_cmdline,
            (last_current_boot_id + "\n").encode("ascii"),
            captured_log_bytes,
            b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12",
        ]

        def last_record(evidence_id: str, argv: tuple[str, ...], payload: bytes) -> dict[str, object]:
            command = argv[0].encode("ascii")
            protocol_flags = finalizer.inline_protocol_flags_for_argv(argv)
            if protocol_flags is None:
                raise AssertionError(f"test command has no native flag contract: {argv}")
            begin = {"cmd": argv[0], "seq": "1", "argc": str(len(argv)), "flags": protocol_flags}
            end = {"cmd": argv[0], "seq": "1", "rc": "0", "errno": "0", "duration_ms": "0", "flags": protocol_flags, "status": "ok"}
            transcript = (
                b"A90P1 BEGIN seq=1 cmd=" + command + b" argc=" + str(len(argv)).encode("ascii") + b" flags=" + protocol_flags.encode("ascii") + b"\n"
                + payload
                + b"\n"
                + f"[done] {argv[0]} (0ms)\n".encode("ascii")
                + b"A90P1 END seq=1 cmd=" + command + b" rc=0 errno=0 duration_ms=0 flags=" + protocol_flags.encode("ascii") + b" status=ok\n"
            )
            return {
                "evidence_id": evidence_id,
                "argv": list(argv),
                "begin": begin,
                "end": end,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                "payload_size": len(payload),
                "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                "transcript_size": len(transcript),
            }

        last_records = [
            last_record("version_before", ("version",), last_payloads[0]),
            last_record("cmdline_before", ("cat", "/proc/cmdline"), last_payloads[1]),
            last_record("boot_id_after_source", ("cat", "/proc/sys/kernel/random/boot_id"), last_payloads[2]),
            last_record("last_kmsg", ("cat", "/proc/last_kmsg"), last_payloads[3]),
            last_record("selftest_after", ("selftest", "status"), last_payloads[4]),
        ]
        stophud_frame = last_record(
            "stophud_1", ("stophud",), b"autohud: stopped"
        )
        stophud = {
            "accepted": True,
            "attempts": [{
                "attempt": 1,
                "rc": 0,
                "status": "ok",
                "evidence_id": "stophud_1",
                "payload_size": stophud_frame["payload_size"],
                "payload_sha256": stophud_frame["payload_sha256"],
                "transcript_size": stophud_frame["transcript_size"],
                "transcript_sha256": stophud_frame["transcript_sha256"],
            }],
            "busy_retries": 0,
        }
        last_metadata.update({"records": last_records, "stophud": stophud, "stophud_frames": [stophud_frame], "read_source": {**source_summary, "source_pre_read_boot_id": boot_id}, "source_pre_read_boot_id": boot_id, "current_boot_id": last_current_boot_id, "source_pre_read_boot_id_sha256": boot_hash, "current_boot_id_sha256": capture.sha256(last_current_boot_id.encode()), "boot_id_changed": True, "selftest_status": "ok", "target": {"model": finalizer.TARGET_MODEL, "soc": finalizer.TARGET_SOC, "runtime": "0.9.285", "cmdline": finalizer._last_cmdline(last_cmdline)}})
        self._write(last_metadata_path, last_metadata)
        last_journal_path = self.root / "evidence/private/last-kmsg-final.journal.json"
        last_journal = json.loads(last_journal_path.read_text())
        last_journal.update({"records": last_records, "stophud": stophud, "stophud_attempts": stophud["attempts"], "stophud_frames": [stophud_frame], "read_source": {**source_summary, "source_pre_read_boot_id": boot_id}, "source_pre_read_boot_id": boot_id, "current_boot_id": last_current_boot_id, "current_boot_id_sha256": capture.sha256(last_current_boot_id.encode()), "boot_id_changed": True})
        last_public = json.loads(self.last_kmsg.read_text())
        last_public.update({"stophud_accepted": True, "stophud_busy_retries": 0, "stophud_device_state_write": True})
        self.last_kmsg.write_bytes(json.dumps(last_public, ensure_ascii=True, sort_keys=False).encode() + b"\n")
        self._write(last_journal_path, last_journal)

        # Replace the minimal param fixture with the real producer-shaped
        # public/private/journal contract.
        param_manifest = json.loads(self.param_capture.read_text())
        param_id = param_manifest["experiment_id"]
        param_dir = self.root / "evidence/private" / param_id
        param_raw = param_dir / "param--sda10.bin"
        param_bytes = param_raw.read_bytes()
        param_full_hash = finalizer.hashlib.sha256(param_bytes).hexdigest()
        param_stable_hash = finalizer.hashlib.sha256(
            param_bytes[finalizer.PARAM_STABLE_OFFSET : finalizer.PARAM_STABLE_END]
        ).hexdigest()
        param_volatile_byte0 = param_bytes[0]
        param_stable_projection = {
            "stable_sha256": param_stable_hash,
            "stable_range": {
                "start": finalizer.PARAM_STABLE_OFFSET,
                "end": finalizer.PARAM_STABLE_END,
                "size": finalizer.PARAM_STABLE_SIZE,
                "sha256": param_stable_hash,
            },
            "stable_mask": {
                "excluded_ranges": [[0, 1]],
                "stable_ranges": [[finalizer.PARAM_STABLE_OFFSET, finalizer.PARAM_STABLE_END]],
                "stable_size": finalizer.PARAM_STABLE_SIZE,
            },
            "volatile_byte0": param_volatile_byte0,
            "observed_boot_cycle_volatile_byte0": param_volatile_byte0,
        }
        param_decoded = {
            "debuglevel": {"partition_offset": "0x900000", "record_offset": "0x000", "value": "0x574f4c44", "label": "LOW"},
            "force_upload_flag": {"partition_offset": "0x9003f4", "record_offset": "0x3f4", "value": "0x00000000", "label": "NOT_ENABLED_VALUE_5"},
            "FMM_lock": {"partition_offset": "0x9003fc", "record_offset": "0x3fc", "value": "0x00000000", "label": "NOT_LOCK_MAGIC"},
            "dump_sink": {"partition_offset": "0x900400", "record_offset": "0x400", "value": "0x00000000", "label": "USB_DEFAULT"},
        }
        param_manifest.update({
            "started_utc": "2026-08-27T00:06:00+00:00", "completed_utc": "2026-08-27T00:06:00+00:00", "stophud_accepted": True, "stophud_busy_retries": 0, "target_model": finalizer.TARGET_MODEL, "soc": finalizer.TARGET_SOC, "runtime": "v2321-usb-clean-identity-rodata", "kernel": finalizer.TARGET_KERNEL, "bootloader": finalizer.TARGET_BOOTLOADER, "download_mode": "1", "classification": "PARAM_CAPTURED_DEBUG_ONLY_PRECONDITIONS_MET", "partition_writes": False, "raw_artifact_git_ignored": True,
            "partition": {"partname": "param", "devname": "sda10", "major": 8, "minor": 10, "sectors": 20480, "byte_size": 10485760, "start_sector": 125080, "read_only": 0, "logical_block_size": 4096},
            **param_stable_projection,
            "capture": {"size": finalizer.PARAM_CAPTURE_SIZE, "sha256": param_full_hash, "full_sha256": param_full_hash, "device_sha256_before": param_full_hash, "device_sha256_after": param_full_hash, **param_stable_projection, "triple_hash_match": True}, "decoded_gate_fields": param_decoded,
            "cmdline_relevant": {"androidboot.em.model": finalizer.TARGET_MODEL, "androidboot.bootloader": finalizer.TARGET_BOOTLOADER, "androidboot.debug_level": "0x4f4c", "androidboot.force_upload": "0x0", "sec_debug.dump_sink": "0x0", "androidboot.upload_offset": "9438196"},
        })
        self._write(self.param_capture, param_manifest)
        metadata_path = param_dir / "capture-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.update({"started_utc": param_manifest["started_utc"], "completed_utc": param_manifest["completed_utc"], "target_model": finalizer.TARGET_MODEL, "soc": finalizer.TARGET_SOC, "download_mode": "1", "partition_writes": False, "arbitration_journal": "capture-journal.json", "runtime_payload": "A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\r\nversion: 0.9.285 build=v2321-usb-clean-identity-rodata\r\nkernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\r\ndisplay: 1080x2400 connector=28", "cmdline": param_manifest["cmdline_relevant"], "partition": {**param_manifest["partition"], "node_path": "/dev/sdm855_mblab_sda10"}, **param_stable_projection, "capture": {"private_filename": "param--sda10.bin", "size": finalizer.PARAM_CAPTURE_SIZE, "sha256": param_full_hash, "full_sha256": param_full_hash, "stable_sha256": param_stable_hash, "stable_range": param_stable_projection["stable_range"], "stable_mask": param_stable_projection["stable_mask"], "volatile_byte0": param_volatile_byte0, "observed_boot_cycle_volatile_byte0": param_volatile_byte0, "device_sha256_before": param_full_hash, "device_sha256_after": param_full_hash, "a90p1_end": {"cmd": "cat", "errno": "0", "flags": "0x0", "rc": "0", "status": "ok", "seq": "1", "duration_ms": "1"}}, "decoded_gate_fields": param_decoded})
        self._write(metadata_path, metadata)
        journal_path = param_dir / "capture-journal.json"
        param_journal = json.loads(journal_path.read_text())
        param_journal.update({"completed_utc": param_manifest["completed_utc"], "effect_dispatched": False, "effect_replayed": False, "cleanup_deferred": False, "reconcile_required": False, "cleanup_error": None, "target_verified": True, "target": {"model": finalizer.TARGET_MODEL, "soc": finalizer.TARGET_SOC, "bootloader": finalizer.TARGET_BOOTLOADER, "runtime": finalizer.PARAM_RUNTIME, "kernel": finalizer.TARGET_KERNEL}, "private_metadata": "capture-metadata.json", "retained_sha256": param_full_hash, "retained_stable_sha256": param_stable_hash, "retained_volatile_byte0": param_volatile_byte0, "retained_size": finalizer.PARAM_CAPTURE_SIZE})
        self._write(journal_path, param_journal)

        # Refresh the System-boot receipt to the producer's current chain:
        # sync is a separately journaled preparation and the sole physical
        # effect is twrp set tw_gui_done 1, protected by the recovery boot-ID
        # claim.  This keeps the positive fixture producer-shaped and makes
        # the retired combined command an explicit negative.
        system = json.loads(self.system_boot.read_text())
        system_id = finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID
        recovery_boot_id = "00000000-0000-0000-0000-000000000001"
        claim_identity = {
            "schema": "sdm855-a90-twrp-system-effect-claim-v1",
            "current_recovery_boot_id": recovery_boot_id,
            "transition": "twrp-system-boot",
            "preparation": "twrp set tw_reboot_arg system",
            "effect": "twrp set tw_gui_done 1",
        }
        claim_key = finalizer.hashlib.sha256(finalizer._runtime_json_bytes(claim_identity)).hexdigest()
        claim_path = self.root / "evidence/private" / f"verification-024-twrp-system-effect-{claim_key}.claim.json"
        claim_data = self._write(claim_path, {
            "schema": "sdm855-a90-twrp-system-effect-claim-v1",
            "effect_key_sha256": claim_key,
            "effect_identity": claim_identity,
            "claimed_by_experiment_id": system_id,
            "effect_replayed": False,
            "created_utc": "2026-08-27T00:05:00+00:00",
        })
        empty_receipt = {"base64": "", "sha256": finalizer.hashlib.sha256(b"").hexdigest(), "size": 0}
        recovery_boot_id_sha256 = finalizer.hashlib.sha256(recovery_boot_id.encode("ascii")).hexdigest()
        recovery_boot_id_raw = f"{recovery_boot_id}\n".encode("ascii")
        recovery_boot_id_receipt = {
            "base64": base64.b64encode(recovery_boot_id_raw).decode("ascii"),
            "sha256": finalizer.hashlib.sha256(recovery_boot_id_raw).hexdigest(),
            "size": len(recovery_boot_id_raw),
        }
        system["target"].update({"tw_gui_done": "0", "boot_id": recovery_boot_id, "boot_id_sha256": recovery_boot_id_sha256, "boot_id_receipt": recovery_boot_id_receipt})
        sync_target = {**system["target"], "tw_reboot_arg": "system"}
        system["preparation"].update({
            "replayed": False,
            "write_receipt": empty_receipt,
            "read_receipt": empty_receipt,
            "write_sha256": empty_receipt["sha256"],
            "read_sha256": empty_receipt["sha256"],
            "readback": "system",
            "sync": {"command": "sync", "status": "SYNC_PREPARATION_VERIFIED", "write_count": 1, "verified": True, "dispatched": True, "receipt": empty_receipt, "receipt_sha256": empty_receipt["sha256"]},
        })
        system.update({
            "started_utc": "2026-08-27T00:04:30+00:00",
            "sync_command": "sync", "sync_write_count": 1, "sync_verified": True,
            "physical_effect_claim": {"attempted": True, "claimed": True, "key_sha256": claim_key, "claim_path": str(claim_path), "claim_sha256": finalizer.hashlib.sha256(claim_data).hexdigest(), "claim_size": len(claim_data), "boot_id": recovery_boot_id},
            "revalidation_before_preparation": {"verified": True, "target_verified": True, "target": sync_target, "require_reboot_arg": False},
            "revalidation_before_sync": {"verified": True, "target_verified": True, "target": sync_target, "require_reboot_arg": True, "tw_reboot_arg": "system"},
            "revalidation_after_preparation_marker": {"verified": True, "target_verified": True, "target": sync_target, "require_reboot_arg": False},
            "revalidation_before_effect": {"verified": True, "target_verified": True, "target": sync_target, "require_reboot_arg": True, "tw_reboot_arg": "system"},
            "revalidation_after_effect_marker": {"verified": True, "target_verified": True, "target": sync_target, "require_reboot_arg": True, "tw_reboot_arg": "system"},
            "effect_command": "twrp set tw_gui_done 1", "effect_argv": ["twrp set tw_gui_done 1"],
            "effect": {"command": "twrp set tw_gui_done 1", "argv": ["twrp set tw_gui_done 1"], "dispatch_count": 1, "dispatched": True, "replayed": False, "status": "SYSTEM_BOOT_DISCONNECT_OBSERVED", "returned": True, "receipt": empty_receipt, "receipt_sha256": empty_receipt["sha256"]},
        })
        system_bytes = self._write(self.system_boot, system)
        system_public_path = self.root / "evidence/manifests" / f"{system_id}.manifest.json"
        # Serialize the exact current producer projection so the fixture
        # exercises the closed public key contract rather than a hand-built
        # historical subset.
        from tools import a90_twrp_system_boot_once as system_producer

        system_public = system_producer._public_manifest(system, system_bytes)
        self._write(system_public_path, system_public)

        # Install the complete runtime producer shape used by the strict
        # finalizer.  The original fixture intentionally represented only
        # summary fields; keep all 41 framed exchanges so mutations can be
        # tested against the actual evidence boundary.
        runtime_raw_path = self.root / "evidence/private" / f"{finalizer.RUNTIME_HEALTH_EXPERIMENT_ID}.json"
        runtime_journal_path = self.root / "evidence/private" / f"{finalizer.RUNTIME_HEALTH_EXPERIMENT_ID}.journal.json"
        runtime_manifest_path = self.runtime_health
        runtime_raw = json.loads(runtime_raw_path.read_text())

        def runtime_frame(evidence_id: str, argv: tuple[str, ...], payload: bytes) -> dict[str, object]:
            protocol_flags = finalizer.inline_protocol_flags_for_argv(argv)
            if protocol_flags is None:
                raise AssertionError(f"test command has no native flag contract: {argv}")
            begin = {"cmd": argv[0], "seq": "1", "argc": str(len(argv)), "flags": protocol_flags}
            end = {"cmd": argv[0], "seq": "1", "rc": "0", "errno": "0", "duration_ms": "0", "flags": protocol_flags, "status": "ok"}
            transcript = (
                b"A90P1 BEGIN seq=1 cmd=" + argv[0].encode("ascii") + b" argc=" + str(len(argv)).encode("ascii") + b" flags=" + protocol_flags.encode("ascii") + b"\n"
                + payload
                + f"\n[done] {argv[0]} (0ms)\n".encode("ascii")
                + b"A90P1 END seq=1 cmd=" + argv[0].encode("ascii") + b" rc=0 errno=0 duration_ms=0 flags=" + protocol_flags.encode("ascii") + b" status=ok\n"
            )
            return {
                "evidence_id": evidence_id,
                "argv": list(argv),
                "begin": begin,
                "end": end,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                "payload_size": len(payload),
                "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                "transcript_size": len(transcript),
            }

        wrapper = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]"
        wrapper_prefix = b"run: pid=1, q/Ctrl-C cancels\n"
        payload_by_id: dict[str, bytes] = {
            "version": (
                b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\r\n"
                b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\r\n"
                b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\r\n"
                b"made by device owner\r\n"
                b"display: 1080x2400 connector=28 crtc=133 fb=208"
            ),
            "cmdline": (
                b"skip_initramfs  rootwait   ro androidboot.em.model=SM-A908N  "
                b"androidboot.bootloader=A908NKSU5EWA3   androidboot.debug_level=0x4f4c  "
                b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0\n"
            ),
            "soc_id": b"339\n",
            "panic_on_oops": b"1\n",
            "boot_sysfs_uevent": b"MAJOR=259\nMINOR=8\nDEVNAME=sda24\nDEVTYPE=partition\nPARTN=24\nPARTNAME=boot\n",
            "boot_sysfs_size": b"131072\n",
            "boot_sysfs_ro": b"0\n",
            "boot_attest_stat_node": b"mode=0600 uid=0 gid=0 size=0\r\nrdev=259:8",
            "boot_attest_hash": (wrapper_prefix + f"{finalizer.ROLLBACK_SHA256}  /tmp/a90-native/verification-024-boot-prefix.bin\n[exit 0]".encode()),
            "boot_attest_size": (wrapper_prefix + b"60882944 /tmp/a90-native/verification-024-boot-prefix.bin\n[exit 0]"),
            "boot_attest_mknod": b"",
            "selftest": b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12",
            "battery_capacity": b"77\n",
        }
        runtime_records: list[dict[str, object]] = []
        for evidence_id, argv in finalizer._RUNTIME_EXPECTED_COMMANDS:
            if evidence_id == "boot_attest_mknod":
                argv = ("mknodb", "/tmp/a90-native/verification-024-sda24", "259", "8")
            assert argv is not None
            payload = payload_by_id.get(evidence_id, wrapper)
            runtime_records.append(runtime_frame(evidence_id, argv, payload))
        runtime_raw["target"].update({
            "kernel": finalizer.TARGET_KERNEL,
            "bootloader": finalizer.TARGET_BOOTLOADER,
            "version": {"version": finalizer.TARGET_RUNTIME, "build": finalizer.TARGET_RUNTIME_BUILD},
            "cmdline": {
                "skip_initramfs": "", "rootwait": "", "ro": "",
                "androidboot.em.model": finalizer.TARGET_MODEL,
                "androidboot.bootloader": finalizer.TARGET_BOOTLOADER,
                "androidboot.debug_level": "0x4f4c",
                "androidboot.force_upload": "0x0",
                "sec_debug.dump_sink": "0x0",
            },
        })
        runtime_bridge_binding = {"process_pid": 1, "serial": "private"}
        runtime_raw["bridge_binding"] = runtime_bridge_binding
        runtime_raw["post_stophud_bridge_binding"] = dict(runtime_bridge_binding)
        runtime_raw["final_bridge_binding"] = dict(runtime_bridge_binding)
        runtime_raw["records"] = runtime_records
        runtime_raw["stophud"] = {
            "accepted": True,
            "attempts": [{"attempt": 1, "rc": 0, "status": "ok", "evidence_id": "stophud_1", "payload_size": 0, "payload_sha256": finalizer.hashlib.sha256(b"").hexdigest(), "transcript_size": 6, "transcript_sha256": finalizer.hashlib.sha256(b"A90P1 ").hexdigest()}],
            "busy_retries": 0,
        }
        stophud_frame = runtime_frame(
            "stophud_1", ("stophud",), b"autohud: stopped"
        )
        # The shared stophud arbiter's accepted attempt points at this frame;
        # retain a complete protocol transcript for finalizer validation.
        runtime_raw["stophud"]["attempts"][0].update(
            {
                "payload_size": stophud_frame["payload_size"],
                "payload_sha256": stophud_frame["payload_sha256"],
                "transcript_size": stophud_frame["transcript_size"],
                "transcript_sha256": stophud_frame["transcript_sha256"],
            }
        )
        runtime_raw["stophud_frames"] = [stophud_frame]
        runtime_raw["battery_capacity_percent"] = 77
        runtime_raw["boot_attestation"] = {
            "sysfs_root": "/sys/class/block/sda24", "block_node": "/dev/block/sda24",
            "attest_node": "/tmp/a90-native/verification-024-sda24", "attest_file": "/tmp/a90-native/verification-024-boot-prefix.bin",
            "bs": 4096, "count": 14864, "expected_size": finalizer.BOOT_PREFIX_SIZE, "captured_size": finalizer.BOOT_PREFIX_SIZE,
            "expected_sha256": finalizer.ROLLBACK_SHA256, "captured_sha256": finalizer.ROLLBACK_SHA256, "sectors": 131072, "ro": 0,
            "hash_matches_candidate": True, "size_matches_candidate": True, "cleanup_ok": True, "cleanup_error": None,
            "binding_failure": False, "pre_cleanup_error": None,
            "sysfs_uevent": {"MAJOR": "259", "MINOR": "8", "DEVNAME": "sda24", "DEVTYPE": "partition", "PARTN": "24", "PARTNAME": "boot"},
            "stat": {"mode": "0600", "uid": "0", "gid": "0", "size": "0", "rdev": "259:8"},
            "binding_events": [
                {"stage": stage, "bridge_binding": dict(runtime_bridge_binding)}
                for stage in finalizer._RUNTIME_BOOT_BINDING_STAGES
            ],
        }
        runtime_raw["v024_temp_absence"] = {
            "paths": list(finalizer._RUNTIME_TEMP_PATHS), "paths_count": 5, "absence_verified": True,
            "frame_count": 10, "paths_sha256": finalizer.hashlib.sha256(finalizer._runtime_json_bytes(finalizer._RUNTIME_TEMP_PATHS)).hexdigest(),
        }
        runtime_raw["boot_attestation_frames"] = runtime_records[4:29]
        runtime_raw["v024_temp_absence_frames"] = runtime_records[29:39]
        runtime_raw_bytes = self._write(runtime_raw_path, runtime_raw)
        runtime_journal = json.loads(runtime_journal_path.read_text())
        runtime_journal.update({
            "status": "COMPLETE", "transport_module": "tools.a90_pa28_live", "transport_source": "tools/a90_pa28_live.py", "records": runtime_records, "stophud": runtime_raw["stophud"],
            "stophud_attempts": runtime_raw["stophud"]["attempts"], "stophud_frames": runtime_raw["stophud_frames"],
            "bridge_binding": runtime_raw["bridge_binding"],
            "post_stophud_bridge_binding": runtime_raw["bridge_binding"],
            "final_bridge_binding": runtime_raw["bridge_binding"],
            "boot_attestation": {**runtime_raw["boot_attestation"], "frames": runtime_raw["boot_attestation_frames"]},
            "v024_temp_absence": {**runtime_raw["v024_temp_absence"], "frames": runtime_raw["v024_temp_absence_frames"]},
            "raw_sha256": finalizer.hashlib.sha256(runtime_raw_bytes).hexdigest(), "raw_size": len(runtime_raw_bytes),
        })
        runtime_journal_bytes = self._write(runtime_journal_path, runtime_journal)
        runtime_public = json.loads(runtime_manifest_path.read_text())
        runtime_public.update({
            "version": "A90 Linux init 0.9.285", "build": finalizer.TARGET_RUNTIME_BUILD,
            "kernel": finalizer.TARGET_KERNEL, "bootloader": finalizer.TARGET_BOOTLOADER,
            "records": [finalizer._runtime_public_record(record) for record in runtime_records],
            "stophud": runtime_raw["stophud"],
            "stophud_frames": [{key: frame[key] for key in ("evidence_id", "argv", "begin", "end", "payload_sha256", "payload_size", "transcript_sha256", "transcript_size")} for frame in runtime_raw["stophud_frames"]],
            "boot_attestation": {"expected_sha256": finalizer.ROLLBACK_SHA256, "captured_sha256": finalizer.ROLLBACK_SHA256, "captured_size": finalizer.BOOT_PREFIX_SIZE, "cleanup_ok": True, "hash_matches_candidate": True, "size_matches_candidate": True, "binding_event_count": len(finalizer._RUNTIME_BOOT_BINDING_STAGES)},
            "v024_temp_absence": {"paths_count": 5, "absence_verified": True, "frame_count": 10, "paths_sha256": finalizer.hashlib.sha256(finalizer._runtime_json_bytes(finalizer._RUNTIME_TEMP_PATHS)).hexdigest()},
            "selftest": runtime_raw["selftest"], "battery_capacity_percent": runtime_raw["battery_capacity_percent"],
            "raw_snapshot_sha256": finalizer.hashlib.sha256(runtime_raw_bytes).hexdigest(), "raw_snapshot_size": len(runtime_raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(runtime_journal_bytes).hexdigest(), "journal_size": len(runtime_journal_bytes),
        })
        self._write(runtime_manifest_path, runtime_public)

    def _refresh_param_contract(self, raw_bytes: bytes | None = None) -> bytes:
        """Rewrite every param projection from the retained raw image."""

        param_dir = self.root / "evidence/private" / finalizer.PARAM_CAPTURE_EXPERIMENT_ID
        raw_path = param_dir / "param--sda10.bin"
        if raw_bytes is None:
            raw_bytes = raw_path.read_bytes()
        self.assertEqual(len(raw_bytes), finalizer.PARAM_CAPTURE_SIZE)
        raw_path.write_bytes(raw_bytes)
        full_hash = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        stable_hash = finalizer.hashlib.sha256(
            raw_bytes[finalizer.PARAM_STABLE_OFFSET : finalizer.PARAM_STABLE_END]
        ).hexdigest()
        volatile_byte0 = raw_bytes[0]
        projection = {
            "stable_sha256": stable_hash,
            "stable_range": {
                "start": finalizer.PARAM_STABLE_OFFSET,
                "end": finalizer.PARAM_STABLE_END,
                "size": finalizer.PARAM_STABLE_SIZE,
                "sha256": stable_hash,
            },
            "stable_mask": {
                "excluded_ranges": [[0, 1]],
                "stable_ranges": [[finalizer.PARAM_STABLE_OFFSET, finalizer.PARAM_STABLE_END]],
                "stable_size": finalizer.PARAM_STABLE_SIZE,
            },
            "volatile_byte0": volatile_byte0,
            "observed_boot_cycle_volatile_byte0": volatile_byte0,
        }

        public = json.loads(self.param_capture.read_text())
        public.update(projection)
        public_capture = dict(public["capture"])
        public_capture.update(
            {
                "size": finalizer.PARAM_CAPTURE_SIZE,
                "sha256": full_hash,
                "full_sha256": full_hash,
                "device_sha256_before": full_hash,
                "device_sha256_after": full_hash,
                **projection,
                "triple_hash_match": True,
            }
        )
        public["capture"] = public_capture
        self._write(self.param_capture, public)

        metadata_path = param_dir / "capture-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.update(projection)
        metadata_capture = dict(metadata["capture"])
        metadata_capture.update(
            {
                "private_filename": "param--sda10.bin",
                "size": finalizer.PARAM_CAPTURE_SIZE,
                "sha256": full_hash,
                "full_sha256": full_hash,
                "device_sha256_before": full_hash,
                "device_sha256_after": full_hash,
                **projection,
            }
        )
        metadata["capture"] = metadata_capture
        self._write(metadata_path, metadata)

        journal_path = param_dir / "capture-journal.json"
        journal = json.loads(journal_path.read_text())
        journal.update(
            {
                "retained_sha256": full_hash,
                "retained_stable_sha256": stable_hash,
                "retained_volatile_byte0": volatile_byte0,
                "retained_size": finalizer.PARAM_CAPTURE_SIZE,
            }
        )
        self._write(journal_path, journal)
        return raw_bytes

    def _promote_read_receipt_to_value(self, value: str = "0x0000000000001234") -> None:
        """Mutate the refusal fixture into a complete positive read receipt."""

        raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        journal_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        raw = json.loads(raw_path.read_text())
        journal = json.loads(journal_path.read_text())
        control_raw = json.loads(
            (self.root / f"evidence/private/{finalizer.CONTROL_EXPERIMENT_ID}.json").read_text()
        )
        fixed = {
            "argv": list(finalizer.fixed_op_argv()),
            "buffer_size": 0x58,
            "buffer_sha256": finalizer._fixed_op_buffer_hash(),
            "magic": "0xa90c0de5deadbeef",
            "op": 4,
            "args": [],
            "rc": 0,
            "status": "ok",
            "value": value,
            "a90r_record": f"A90R{int(value, 16):x}",
        }
        fixed_frame = _complete_fixed_op_frame(value)
        full_frames = []
        for frame in control_raw["frames"]:
            evidence_id = frame.get("evidence_id")
            if evidence_id in {
                "version_after",
                "cmdline_after",
                "selftest_after",
                "soc_id_after",
            }:
                continue
            if evidence_id == "fixed_op_4":
                full_frames.append(fixed_frame)
            elif evidence_id == "boot_attest_hash":
                replacement = dict(frame)
                payload = (
                    b"run: pid=1, q/Ctrl-C cancels\n"
                    + f"{finalizer.READ_SHA256}  /tmp/a90-native/verification-024-boot-prefix.bin\n[exit 0]\n".encode("ascii")
                )
                begin = dict(replacement["begin"])
                end = dict(replacement["end"])
                transcript = (
                    f"A90P1 BEGIN seq={begin['seq']} cmd={begin['cmd']} argc={begin['argc']} flags={begin['flags']}\n".encode("ascii")
                    + payload
                    + f"\n[done] {begin['cmd']} (0ms)\n".encode("ascii")
                    + f"A90P1 END seq={end['seq']} cmd={end['cmd']} rc={end['rc']} errno={end['errno']} duration_ms={end['duration_ms']} flags={end['flags']} status={end['status']}\n".encode("ascii")
                )
                replacement.update({
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                    "payload_size": len(payload),
                    "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                    "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                    "transcript_size": len(transcript),
                })
                full_frames.append(replacement)
            else:
                full_frames.append(frame)
        transition = {
            "before": 1,
            "zero_write_attempted": True,
            "zero_set": True,
            "zero_verified": True,
            "restore_write_attempted": True,
            "restored": True,
            "restore_deferred": False,
            "proof_frame_ids": [
                "panic_before",
                "panic_set_0",
                "panic_zero_verify",
                "panic_set_1",
                "panic_restore_verify",
            ],
        }
        raw.update({
            "value": value,
            "fixed_op_measurement": fixed,
            "outcome": "READABLE_SECURITY_INDICATOR",
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": False,
            "dispatch_returned": True,
            "dispatch_failed": False,
            "panic_on_oops_restored": True,
            "panic_restore_deferred": False,
            "cleanup_ok": True,
            "panic_transition": transition,
            "frames": full_frames,
            "error": None,
        })
        journal.update({
            "status": "READABLE_SECURITY_INDICATOR",
            "outcome": "READABLE_SECURITY_INDICATOR",
            "value": value,
            "fixed_op": {**journal.get("fixed_op", {}), "rc": 0, "status": "ok", "value": value},
            "fixed_op_measurement": fixed,
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": False,
            "dispatch_returned": True,
            "dispatch_failed": False,
            "panic_on_oops_restored": True,
            "panic_restore_deferred": False,
            "cleanup_ok": True,
            "panic_transition": transition,
            "frames": full_frames,
            "error": None,
        })
        raw_bytes = self._write(raw_path, raw)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.read_manifest.read_text())
        public.update({
            "returned_value_present": True,
            "returned_value_sha256": finalizer.hashlib.sha256(value.encode("ascii")).hexdigest(),
            "outcome": "READABLE_SECURITY_INDICATOR",
            "dispatch_count": 1,
            "effect_dispatched": True,
            "effect_ambiguous": False,
            "dispatch_returned": True,
            "dispatch_failed": False,
            "panic_on_oops_restored": True,
            "panic_restore_deferred": False,
            "cleanup_ok": True,
            "panic_transition": transition,
            "fixed_op": {**public["fixed_op"], "rc": 0, "status": "ok", "value": value},
            "raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(),
            "raw_snapshot_size": len(raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(),
            "journal_size": len(journal_bytes),
        })
        self._write(self.read_manifest, public)

    def _args(self, experiment_id: str = finalizer.FINAL_EXPERIMENT_ID) -> Namespace:
        return Namespace(
            experiment_id=experiment_id,
            output_root=self.root,
            control_manifest=self.control_manifest,
            read_manifest=self.read_manifest,
            last_kmsg=self.last_kmsg,
            rollback_flash=self.rollback_flash,
            rollback_system_boot=self.system_boot,
            param_capture=self.param_capture,
            runtime_health=self.runtime_health,
        )

    def test_inline_complete_frames_bind_each_payload_class_to_its_fact(self) -> None:
        raw = json.loads(
            (self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.json").read_text()
        )

        def mutate(frame: dict[str, object], payload: bytes) -> None:
            frame["payload_base64"] = base64.b64encode(payload).decode("ascii")
            frame["payload_sha256"] = finalizer.hashlib.sha256(payload).hexdigest()
            frame["payload_size"] = len(payload)
            begin = frame["begin"]
            end = frame["end"]
            assert isinstance(begin, dict) and isinstance(end, dict)
            transcript = (
                f"A90P1 BEGIN seq={begin['seq']} cmd={begin['cmd']} argc={begin['argc']} flags={begin['flags']}\n".encode("ascii")
                + payload
                + f"\n[done] {begin['cmd']} (0ms)\n".encode("ascii")
                + f"A90P1 END seq={end['seq']} cmd={end['cmd']} rc={end['rc']} errno={end['errno']} duration_ms={end['duration_ms']} flags={end['flags']} status={end['status']}\n".encode("ascii")
            )
            frame["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
            frame["transcript_sha256"] = finalizer.hashlib.sha256(transcript).hexdigest()
            frame["transcript_size"] = len(transcript)

        mutations = {
            "version_before": b"garbage\n",
            "cmdline_before": b"androidboot.em.model=SM-A908N androidboot.em.model=SM-A908N\n",
            "soc_id_before": b"340\n",
            "selftest_before": b"selftest: pass=11 warn=1 fail=1 duration=43ms entries=12\n",
            "boot_id_before_read": b"22222222-2222-4222-8222-222222222222\n",
            "boot_sysfs_uevent": b"MAJOR=8\nMINOR=27\nDEVNAME=sda24\nDEVTYPE=partition\nPARTN=24\nPARTNAME=boot\n",
            "boot_sysfs_size": b"1\n",
            "boot_sysfs_ro": b"1\n",
            "boot_attest_stat_node": b"mode=0644 uid=0 gid=0 size=0\nrdev=259:27\n",
            "boot_attest_capture": b"run: pid=1, q/Ctrl-C cancels\nextra\n[exit 0]\n",
            "boot_attest_hash": b"run: pid=1, q/Ctrl-C cancels\n" + b"0" * 64 + b"  /tmp/a90-native/verification-024-boot-prefix.bin\n[exit 0]\n",
            "selftest_after": b"selftest: pass=11 warn=1 fail=1 duration=43ms entries=12\n",
        }
        for evidence_id, payload in mutations.items():
            with self.subTest(evidence_id=evidence_id):
                frames = json.loads(json.dumps(raw["frames"]))
                matches = [item for item in frames if item.get("evidence_id") == evidence_id]
                self.assertEqual(len(matches), 1)
                mutate(matches[0], payload)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_inline_frame_payload_semantics(
                        frames,
                        target=raw["target"],
                        attestation=raw["current_boot_attestation"],
                        candidate_sha256=finalizer.CONTROL_SHA256,
                        candidate_size=finalizer.BOOT_PREFIX_SIZE,
                        boot_id_before_read=raw["boot_id_before_read"],
                        label=f"hostile {evidence_id}",
                        include_health=True,
                        health_target=raw["health_after"]["target"],
                        health_selftest=raw["health_after"]["selftest"],
                    )

    def test_inline_health_continuity_is_semantic_not_raw_byte_identity(self) -> None:
        raw = json.loads(
            (self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.json").read_text()
        )

        def payload_for(frame: dict[str, object]) -> bytes:
            return base64.b64decode(str(frame["payload_base64"]).encode("ascii"))

        def line_variant(payload: bytes, ending: bytes) -> bytes:
            normalized = payload.replace(b"\r\n", b"\n")
            if normalized.endswith(b"\n"):
                normalized = normalized[:-1]
            return normalized.replace(b"\n", ending) + (ending if ending else b"")

        def rewrite(frame: dict[str, object], payload: bytes) -> None:
            begin = dict(frame["begin"])
            end = dict(frame["end"])
            command = str(begin["cmd"]).encode("ascii")
            frame["payload_base64"] = base64.b64encode(payload).decode("ascii")
            frame["payload_sha256"] = finalizer.hashlib.sha256(payload).hexdigest()
            frame["payload_size"] = len(payload)
            transcript = (
                b"A90P1 BEGIN seq=" + str(begin["seq"]).encode("ascii")
                + b" cmd=" + command
                + b" argc=" + str(begin["argc"]).encode("ascii")
                + b" flags=" + str(begin["flags"]).encode("ascii")
                + b"\n" + payload + b"\n"
                + b"[done] " + command
                + b" (" + str(end["duration_ms"]).encode("ascii") + b"ms)\n"
                + b"A90P1 END seq=" + str(end["seq"]).encode("ascii")
                + b" cmd=" + command
                + b" rc=" + str(end["rc"]).encode("ascii")
                + b" errno=" + str(end["errno"]).encode("ascii")
                + b" duration_ms=" + str(end["duration_ms"]).encode("ascii")
                + b" flags=" + str(end["flags"]).encode("ascii")
                + b" status=" + str(end["status"]).encode("ascii") + b"\n"
            )
            frame["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
            frame["transcript_sha256"] = finalizer.hashlib.sha256(transcript).hexdigest()
            frame["transcript_size"] = len(transcript)

        frames = json.loads(json.dumps(raw["frames"]))
        by_id = {str(frame["evidence_id"]): frame for frame in frames}
        for before_id, after_id in (
            ("version_before", "version_after"),
            ("cmdline_before", "cmdline_after"),
            ("soc_id_before", "soc_id_after"),
        ):
            before_payload = payload_for(by_id[before_id])
            after_payload = payload_for(by_id[after_id])
            rewrite(by_id[before_id], line_variant(before_payload, b"\n"))
            rewrite(by_id[after_id], line_variant(after_payload, b"\r\n"))

        before_selftest = payload_for(by_id["selftest_before"])
        after_selftest = payload_for(by_id["selftest_after"])
        after_selftest = after_selftest.replace(b"duration=43", b"duration=44")
        rewrite(by_id["selftest_before"], line_variant(before_selftest, b""))
        rewrite(by_id["selftest_after"], line_variant(after_selftest, b"\r\n"))
        health_selftest = dict(raw["health_after"]["selftest"])
        health_selftest["duration"] = 44

        finalizer._validate_inline_frame_payload_semantics(
            frames,
            target=raw["target"],
            attestation=raw["current_boot_attestation"],
            candidate_sha256=finalizer.CONTROL_SHA256,
            candidate_size=finalizer.BOOT_PREFIX_SIZE,
            boot_id_before_read=raw["boot_id_before_read"],
            label="semantic continuity variants",
            include_health=True,
            health_target=raw["health_after"]["target"],
            health_selftest=health_selftest,
        )

        changed_frames = json.loads(json.dumps(frames))
        changed_by_id = {str(frame["evidence_id"]): frame for frame in changed_frames}
        changed_selftest = payload_for(changed_by_id["selftest_after"]).replace(
            b"warn=1", b"warn=2"
        )
        rewrite(changed_by_id["selftest_after"], changed_selftest)
        changed_health_selftest = dict(health_selftest)
        changed_health_selftest["warn"] = 2
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_inline_frame_payload_semantics(
                changed_frames,
                target=raw["target"],
                attestation=raw["current_boot_attestation"],
                candidate_sha256=finalizer.CONTROL_SHA256,
                candidate_size=finalizer.BOOT_PREFIX_SIZE,
                boot_id_before_read=raw["boot_id_before_read"],
                label="semantic continuity changed stable field",
                include_health=True,
                health_target=raw["health_after"]["target"],
                health_selftest=changed_health_selftest,
            )

    def test_command_flags_are_source_backed_and_cleanup_occurrences_keep_dynamic_pids(self) -> None:
        expected_flags = {
            "run": "0x2",
            "writefile": "0x0",
            "version": "0x0",
            "cat": "0x0",
            "selftest": "0x0",
            "mknodb": "0x0",
            "stophud": "0x8",
        }
        for command, expected in expected_flags.items():
            with self.subTest(command=command):
                self.assertEqual(
                    finalizer.inline_protocol_flags_for_argv((command,)), expected
                )

        raw = json.loads(
            (self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.json").read_text()
        )

        def rewrite_payload(frame: dict[str, object], payload: bytes) -> None:
            argv = tuple(frame["argv"])
            protocol_flags = finalizer.inline_protocol_flags_for_argv(argv)
            self.assertIsNotNone(protocol_flags)
            begin = frame["begin"]
            end = frame["end"]
            self.assertIsInstance(begin, dict)
            self.assertIsInstance(end, dict)
            begin = dict(begin)
            end = dict(end)
            begin["flags"] = protocol_flags
            end["flags"] = protocol_flags
            frame["begin"] = begin
            frame["end"] = end
            command = argv[0].encode("ascii")
            transcript = (
                b"A90P1 BEGIN seq=" + str(begin["seq"]).encode("ascii")
                + b" cmd=" + command + b" argc=" + str(len(argv)).encode("ascii")
                + b" flags=" + str(protocol_flags).encode("ascii") + b"\n"
                + payload + f"\n[done] {command.decode('ascii')} (0ms)\n".encode("ascii")
                + b"A90P1 END seq=" + str(end["seq"]).encode("ascii")
                + b" cmd=" + command + b" rc=" + str(end["rc"]).encode("ascii")
                + b" errno=" + str(end["errno"]).encode("ascii")
                + b" duration_ms=" + str(end["duration_ms"]).encode("ascii")
                + b" flags=" + str(protocol_flags).encode("ascii")
                + b" status=" + str(end["status"]).encode("ascii") + b"\n"
            )
            frame.update(
                {
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                    "payload_size": len(payload),
                    "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                    "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                    "transcript_size": len(transcript),
                }
            )

        frames = json.loads(json.dumps(raw["frames"]))
        cleanup_frames = [
            frame for frame in frames
            if frame.get("evidence_id") in finalizer._SEMANTIC_DUPLICATE_FRAME_IDS
        ]
        self.assertGreaterEqual(len(cleanup_frames), 2)
        for pid, frame in enumerate(cleanup_frames, 1):
            old_payload = finalizer._decode_frame_bytes(
                frame["payload_base64"], frame["payload_size"], frame["payload_sha256"], "cleanup"
            )
            self.assertIn(b"pid=1", old_payload)
            rewrite_payload(
                frame,
                old_payload.replace(b"pid=1", f"pid={pid + 1}".encode("ascii"), 1),
            )
        finalizer._validate_frame_list(
            frames, "dynamic cleanup frames", restored=True, allow_fixed=True, include_health=True
        )
        finalizer._validate_inline_frame_payload_semantics(
            frames,
            target=raw["target"],
            attestation=raw["current_boot_attestation"],
            candidate_sha256=finalizer.CONTROL_SHA256,
            candidate_size=finalizer.BOOT_PREFIX_SIZE,
            boot_id_before_read=raw["boot_id_before_read"],
            label="dynamic cleanup frames",
            include_health=True,
            health_target=raw["health_after"]["target"],
            health_selftest=raw["health_after"]["selftest"],
        )

        for invalid_pid in (b"pid=0", b"pid=-1", b"pid=abc"):
            hostile = json.loads(json.dumps(raw["frames"]))
            frame = next(
                frame for frame in hostile
                if frame.get("evidence_id") == "boot_attest_remove_node"
            )
            payload = finalizer._decode_frame_bytes(
                frame["payload_base64"], frame["payload_size"], frame["payload_sha256"], "cleanup"
            )
            rewrite_payload(frame, payload.replace(b"pid=1", invalid_pid, 1))
            with self.subTest(invalid_pid=invalid_pid):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_inline_frame_payload_semantics(
                        hostile,
                        target=raw["target"],
                        attestation=raw["current_boot_attestation"],
                        candidate_sha256=finalizer.CONTROL_SHA256,
                        candidate_size=finalizer.BOOT_PREFIX_SIZE,
                        boot_id_before_read=raw["boot_id_before_read"],
                        label="invalid cleanup PID",
                        include_health=True,
                        health_target=raw["health_after"]["target"],
                        health_selftest=raw["health_after"]["selftest"],
                    )

        bad_lengths = json.loads(json.dumps(raw["frames"]))
        remove_index = next(
            index for index, frame in enumerate(bad_lengths)
            if frame.get("evidence_id") == "boot_attest_remove_node"
        )
        bad_lengths.pop(remove_index)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_frame_list(
                bad_lengths, "missing cleanup occurrence", restored=True, allow_fixed=True, include_health=True
            )
        extra = json.loads(json.dumps(raw["frames"]))
        extra.insert(remove_index + 1, json.loads(json.dumps(extra[remove_index])))
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_frame_list(
                extra, "third cleanup occurrence", restored=True, allow_fixed=True, include_health=True
            )
        reordered = json.loads(json.dumps(raw["frames"]))
        reordered[remove_index], reordered[remove_index + 1] = (
            reordered[remove_index + 1], reordered[remove_index]
        )
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_frame_list(
                reordered, "reordered cleanup occurrences", restored=True, allow_fixed=True, include_health=True
            )

        wrong_flags = json.loads(json.dumps(raw["frames"]))
        fixed = next(frame for frame in wrong_flags if frame.get("evidence_id") == "fixed_op_4")
        fixed["begin"]["flags"] = "0x0"
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_fixed_op_frame(wrong_flags, "0x000000000000c071", "wrong run flags")

    def test_v024_version_and_toybox_retained_transcript_grammar(self) -> None:
        version = (
            b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\r\n"
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\r\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\r\n"
            b"made by device owner\r\n"
            b"display: 1080x2400 connector=28 crtc=133 fb=208"
        )
        parsed = finalizer._parse_v024_version_payload(version, "retained version")
        self.assertEqual(parsed["runtime_version"], finalizer.TARGET_RUNTIME)
        self.assertEqual(parsed["runtime_build"], finalizer.TARGET_RUNTIME_BUILD)
        self.assertEqual(parsed["kernel"], finalizer.TARGET_KERNEL)
        for mutation in (
            version + b"\r",  # bare CR after the no-final-newline record
            version.replace(b"made by device owner", b"made by device owner\r\nmade by device owner"),
            version.replace(b"display: 1080x2400", b"display: 1080x2400\ndisplay: 1080x2400"),
            version.replace(b"kernel: Linux", b"unknown: retained\r\nkernel: Linux"),
            version.replace(b"version: 0.9.285", b"version: 0.9.285\r\nversion: 0.9.285"),
            version.replace(b"kernel: Linux", b"kernel: Linux\r\nA90 Linux init"),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._parse_v024_version_payload(mutation, "hostile version")

        wrapper = b"run: pid=7, q/Ctrl-C cancels\nhello\n[exit 0]"
        self.assertEqual(finalizer._semantic_toybox_body(wrapper, "retained toybox"), b"hello")
        self.assertEqual(
            finalizer._semantic_toybox_body(wrapper + b"\n", "retained toybox LF"),
            b"hello",
        )
        self.assertEqual(
            finalizer._semantic_toybox_body(wrapper.replace(b"\n", b"\r\n"), "retained toybox CRLF"),
            b"hello",
        )
        for mutation in (
            wrapper + b"\n\n",
            wrapper.replace(b"[exit 0]", b"[exit 0]\n[exit 0]"),
            wrapper.replace(b"[exit 0]", b"[exit 0]\nextra"),
            wrapper.replace(b"run: pid=7", b"junk\nrun: pid=7"),
            wrapper.replace(b"\n", b"\r", 1),
        ):
            with self.subTest(toybox=mutation):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._semantic_toybox_body(mutation, "hostile toybox")

    def test_multiline_payloads_accept_no_final_or_one_line_ending_only(self) -> None:
        selftest = b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12"
        expected_selftest = {
            "passed": 11,
            "warn": 1,
            "fail": 0,
            "duration": 43,
            "entries": 12,
        }
        self.assertEqual(
            finalizer._semantic_selftest(selftest, "no-final selftest"),
            expected_selftest,
        )
        self.assertEqual(
            finalizer._semantic_selftest(selftest + b"\n", "LF selftest"),
            expected_selftest,
        )
        self.assertEqual(
            finalizer._semantic_selftest(selftest + b"\r\n", "CRLF selftest"),
            expected_selftest,
        )
        uevent = (
            b"MAJOR=259\nMINOR=8\nDEVNAME=sda24\nDEVTYPE=partition\n"
            b"PARTN=24\nPARTNAME=boot"
        )
        expected_uevent = {
            "MAJOR": "259",
            "MINOR": "8",
            "DEVNAME": "sda24",
            "DEVTYPE": "partition",
            "PARTN": "24",
            "PARTNAME": "boot",
        }
        self.assertEqual(
            finalizer._semantic_uevent_payload(uevent, "no-final uevent"),
            expected_uevent,
        )
        self.assertEqual(
            finalizer._semantic_uevent_payload(uevent + b"\r\n", "CRLF uevent"),
            expected_uevent,
        )
        for malformed in (
            selftest + b"\n\n",
            selftest.replace(b"warn=1 ", b"warn=1\n\n"),
            selftest.replace(b"warn=1 ", b"warn=1\r"),
            uevent + b"\n\n",
            uevent.replace(b"MINOR=8\n", b"MINOR=8\n\n"),
            uevent.replace(b"MINOR=8\n", b"MINOR=8\r"),
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._semantic_lines(malformed, "hostile multiline payload")

    def test_boot_devt_is_dynamic_but_canonically_cross_bound(self) -> None:
        """Accept valid kernel dev_t values and reject grammar/identity drift."""

        def payload(major: str, minor: str) -> bytes:
            return (
                f"MAJOR={major}\nMINOR={minor}\nDEVNAME=sda24\n"
                "DEVTYPE=partition\nPARTN=24\nPARTNAME=boot"
            ).encode("ascii")

        for major, minor in (("259", "8"), ("8", "27"), ("1", "0"), ("4095", "1048575")):
            with self.subTest(major=major, minor=minor):
                parsed = finalizer._semantic_uevent_payload(
                    payload(major, minor), "dynamic uevent"
                )
                self.assertEqual(parsed["MAJOR"], major)
                self.assertEqual(parsed["MINOR"], minor)
                self.assertEqual(
                    finalizer._validate_dynamic_mknod_argv(
                        ("mknodb", "/tmp/a90-native/verification-024-sda24", major, minor),
                        "dynamic mknod",
                    )[2:],
                    (major, minor),
                )

        malformed = (
            b"MAJOR=259\nDEVNAME=sda24\nDEVTYPE=partition\nPARTN=24\nPARTNAME=boot",
            payload("259", "8") + b"\nEXTRA=field",
            payload("0259", "8"),
            payload("4096", "8"),
            payload("259", "1048576"),
            payload("+259", "8"),
        )
        for item in malformed:
            with self.subTest(malformed=item):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._semantic_uevent_payload(item, "malformed uevent")

        raw = json.loads(
            (self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.json").read_text()
        )
        for field in ("argv", "stat"):
            frames = json.loads(json.dumps(raw["frames"]))
            if field == "argv":
                frame = next(item for item in frames if item["evidence_id"] == "boot_attest_mknod")
                frame["argv"][-1] = "9"
            else:
                frame = next(item for item in frames if item["evidence_id"] == "boot_attest_stat_node")
                forged = b"mode=0600 uid=0 gid=0 size=0\nrdev=259:9"
                frame.update(
                    {
                        "payload_base64": base64.b64encode(forged).decode("ascii"),
                        "payload_sha256": finalizer.hashlib.sha256(forged).hexdigest(),
                        "payload_size": len(forged),
                    }
                )
            with self.subTest(cross_binding=field):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_inline_frame_payload_semantics(
                        frames,
                        target=raw["target"],
                        attestation=raw["current_boot_attestation"],
                        candidate_sha256=finalizer.CONTROL_SHA256,
                        candidate_size=finalizer.BOOT_PREFIX_SIZE,
                        boot_id_before_read=raw["boot_id_before_read"],
                        label=f"mismatched {field}",
                        include_health=True,
                        health_target=raw["health_after"]["target"],
                        health_selftest=raw["health_after"]["selftest"],
                    )

    def test_complete_frame_boundaries_have_no_optional_fields(self) -> None:
        raw = json.loads(
            (self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.json").read_text()
        )
        frame = next(item for item in raw["frames"] if item["evidence_id"] == "version_before")
        argv = tuple(frame["argv"])
        for mutation in ("missing_begin_argc", "bad_begin_flags", "bad_errno", "bad_duration", "extra_end"):
            hostile = json.loads(json.dumps(frame))
            if mutation == "missing_begin_argc":
                hostile["begin"].pop("argc")
            elif mutation == "bad_begin_flags":
                hostile["begin"]["flags"] = "0x2"
            elif mutation == "bad_errno":
                hostile["end"]["errno"] = "00"
            elif mutation == "bad_duration":
                hostile["end"]["duration_ms"] = "-1"
            else:
                hostile["end"]["extra"] = "x"
            with self.subTest(mutation=mutation):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_protocol_frame(
                        hostile,
                        "version_before",
                        argv,
                        f"hostile {mutation}",
                    )

    def test_finalizer_stophud_evidence_size_bound_matches_shared_contract(self) -> None:
        self.assertEqual(finalizer.STOPHUD_MAX_PAYLOAD_BYTES, 20)
        self.assertEqual(finalizer.STOPHUD_MAX_TRANSCRIPT_BYTES, 4096)

        def make_frame(payload: bytes, transcript: bytes) -> dict[str, object]:
            return {
                "evidence_id": "stophud_1",
                "argv": ["stophud"],
                "begin": {
                    "cmd": "stophud",
                    "seq": "1",
                    "argc": "1",
                    "flags": "0x8",
                },
                "end": {
                    "cmd": "stophud",
                    "seq": "1",
                    "rc": "0",
                    "errno": "0",
                    "duration_ms": "0",
                    "flags": "0x8",
                    "status": "ok",
                },
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                "payload_size": len(payload),
                "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                "transcript_size": len(transcript),
            }

        def transcript_for(payload: bytes) -> bytes:
            return (
                b"A90P1 BEGIN seq=1 cmd=stophud argc=1 flags=0x8\n"
                + payload
                + b"\n[done] stophud (0ms)\n"
                b"A90P1 END seq=1 cmd=stophud rc=0 errno=0 duration_ms=0 "
                b"flags=0x8 status=ok\n"
            )

        payload = b"autohud: not running"
        base = transcript_for(payload)
        for target in (
            finalizer.STOPHUD_MAX_TRANSCRIPT_BYTES - 1,
            finalizer.STOPHUD_MAX_TRANSCRIPT_BYTES,
        ):
            with self.subTest(target=target):
                prefix_size = target - len(base)
                transcript = b"x" * (prefix_size - 1) + b"\n" + base
                finalizer._validate_protocol_frame(
                    make_frame(payload, transcript),
                    "stophud_1",
                    ("stophud",),
                    "boundary stophud",
                )

        for transcript in (
            b"x"
            * (finalizer.STOPHUD_MAX_TRANSCRIPT_BYTES + 1 - len(base) - 1)
            + b"\n"
            + base,
            base
            + b"x" * (finalizer.STOPHUD_MAX_TRANSCRIPT_BYTES + 1 - len(base)),
        ):
            with self.subTest(transcript_size=len(transcript)):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_protocol_frame(
                        make_frame(payload, transcript),
                        "stophud_1",
                        ("stophud",),
                        "oversized stophud",
                    )

        oversized_payload = b"x" * (finalizer.STOPHUD_MAX_PAYLOAD_BYTES + 1)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_protocol_frame(
                make_frame(oversized_payload, transcript_for(oversized_payload)),
                "stophud_1",
                ("stophud",),
                "oversized stophud payload",
            )

    def test_complete_chain_emits_refused_at_mid_and_no_device_contact(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        self.assertEqual(control["value"], "0x000000000000c071")
        self.assertEqual(
            control["predecessor_capsule_sha256"], self.predecessor_capsule_sha256
        )
        self.assertEqual(
            control["predecessor_capsule_size"], self.predecessor_capsule_size
        )
        self.assertEqual(
            control["r3_incident_manifest_sha256"],
            finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        )
        self.assertEqual(
            control["r3_incident_manifest_size"],
            finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        )
        self.assertTrue(control["r3_zero_op_restored_validated"])
        read = finalizer.validate_read(self.read_manifest, self.root, control)
        self.assertFalse(read["value_present"])
        self.assertEqual(
            read["r2_incident_manifest_sha256"],
            finalizer.CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        )
        self.assertEqual(
            read["r3_incident_manifest_sha256"],
            finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        )
        self.assertTrue(read["r3_zero_op_restored_validated"])
        private, public = finalizer.finalize(self._args())
        manifest = json.loads(public.read_text())
        self.assertEqual(manifest["classification"], "REFUSED_AT_MID")
        self.assertTrue(manifest["clean_negative"])
        self.assertTrue(manifest["host_only"])
        self.assertFalse(manifest["device_contact"])
        self.assertNotIn("serial", json.dumps(manifest))
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)

    def _rewrite_control_journal(self, journal: dict[str, object]) -> None:
        journal_path = self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.journal.json"
        journal_bytes = self._write(journal_path, journal)
        manifest = json.loads(self.control_manifest.read_text())
        manifest["journal_sha256"] = finalizer.hashlib.sha256(journal_bytes).hexdigest()
        manifest["journal_size"] = len(journal_bytes)
        self._write(self.control_manifest, manifest)

    def test_control_r2_predecessor_capsule_and_preclaim_are_exactly_bound(self) -> None:
        journal_path = self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.journal.json"
        journal = json.loads(journal_path.read_text())
        section = journal["control_r2_predecessor"]
        self.assertEqual(
            set(section),
            {
                "preclaim_sha256",
                "preclaim_size",
                "capsule",
                "capsule_sha256",
                "capsule_size",
            },
        )
        self.assertEqual(section["capsule"], self.predecessor_capsule)
        self.assertEqual(section["capsule_sha256"], self.predecessor_capsule_sha256)
        self.assertEqual(section["capsule_size"], self.predecessor_capsule_size)
        preclaim = probe._control_r2_preclaim()
        preclaim_bytes = probe.json_bytes(preclaim)
        self.assertEqual(
            section["preclaim_sha256"], finalizer.hashlib.sha256(preclaim_bytes).hexdigest()
        )
        self.assertEqual(section["preclaim_size"], len(preclaim_bytes))
        validated = finalizer.validate_control(self.control_manifest, self.root)
        self.assertEqual(validated["predecessor_capsule_sha256"], self.predecessor_capsule_sha256)

    def test_control_r2_predecessor_missing_extra_mutated_and_spliced_receipts_fail(self) -> None:
        mutations = (
            "missing",
            "extra",
            "capsule",
            "capsule_bool_int",
            "capsule_hash",
            "capsule_size",
            "preclaim_hash",
            "preclaim_size",
        )
        journal_path = self.root / "evidence/private" / f"{finalizer.CONTROL_EXPERIMENT_ID}.journal.json"
        baseline_journal = json.loads(journal_path.read_text())
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                journal = json.loads(json.dumps(baseline_journal))
                section = journal["control_r2_predecessor"]
                if mutation == "missing":
                    del section["capsule"]
                elif mutation == "extra":
                    section["unexpected"] = False
                elif mutation == "capsule":
                    section["capsule"] = {
                        **section["capsule"],
                        "semantic_capsule": {"forged": True},
                    }
                elif mutation == "capsule_bool_int":
                    section["capsule"]["semantic_capsule"]["claims"]["live_authority"] = 0
                elif mutation == "capsule_hash":
                    section["capsule_sha256"] = "0" * 64
                elif mutation == "capsule_size":
                    section["capsule_size"] += 1
                elif mutation == "preclaim_hash":
                    section["preclaim_sha256"] = "0" * 64
                else:
                    section["preclaim_size"] += 1
                self._rewrite_control_journal(journal)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_control(self.control_manifest, self.root)

    def test_control_r2_consumed_id_can_never_become_active(self) -> None:
        baseline = self.control_manifest.read_bytes()
        for consumed_id in (
            finalizer.CONTROL_R2_EXPERIMENT_ID,
            finalizer.CONTROL_R3_EXPERIMENT_ID,
        ):
            with self.subTest(consumed_id=consumed_id):
                consumed_path = self.root / "evidence/manifests" / (
                    f"{consumed_id}.manifest.json"
                )
                consumed_path.write_bytes(baseline)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_control(consumed_path, self.root)

                manifest = json.loads(baseline)
                manifest["experiment_id"] = consumed_id
                self._write(self.control_manifest, manifest)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_control(self.control_manifest, self.root)
                self.control_manifest.write_bytes(baseline)

    def test_control_r4_preclaim_and_reconciliation_are_exact(self) -> None:
        baseline_journal = json.loads(
            (
                self.root
                / "evidence/private"
                / f"{finalizer.CONTROL_EXPERIMENT_ID}.journal.json"
            ).read_text()
        )
        baseline_manifest = json.loads(self.control_manifest.read_text())
        base_preclaim = probe._control_r4_preclaim()
        self.assertEqual(base_preclaim["experiment_id"], finalizer.CONTROL_EXPERIMENT_ID)
        self.assertEqual(
            base_preclaim["consumed_r2_experiment_id"],
            finalizer.CONTROL_R2_EXPERIMENT_ID,
        )
        self.assertEqual(
            base_preclaim["consumed_r3_experiment_id"],
            finalizer.CONTROL_R3_EXPERIMENT_ID,
        )
        self.assertEqual(
            base_preclaim["r3_incident"],
            {
                "schema": finalizer.CONTROL_R3_INCIDENT_VALIDATION_SCHEMA,
                "sha256": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SHA256,
                "size": finalizer.CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            },
        )

        def write_journal(journal: dict[str, object]) -> None:
            journal_bytes = self._write(
                self.root
                / "evidence/private"
                / f"{finalizer.CONTROL_EXPERIMENT_ID}.journal.json",
                journal,
            )
            manifest = json.loads(json.dumps(baseline_manifest))
            manifest["journal_sha256"] = finalizer.hashlib.sha256(
                journal_bytes
            ).hexdigest()
            manifest["journal_size"] = len(journal_bytes)
            self._write(self.control_manifest, manifest)

        mutations = (
            "preclaim_consumed_r2",
            "preclaim_consumed_r3",
            "preclaim_capsule_missing",
            "preclaim_r2_incident_extra",
            "preclaim_r2_incident_hash",
            "preclaim_r3_incident_missing",
            "preclaim_r3_incident_extra",
            "preclaim_r3_incident_hash",
            "r2_summary_missing",
            "r2_summary_extra",
            "r2_summary_mutated",
            "r3_summary_missing",
            "r3_summary_extra",
            "r3_summary_status",
            "r3_summary_incident_fact",
            "r4_missing",
            "r4_extra",
            "r4_preclaim_hash",
            "r4_preclaim_size",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                journal = json.loads(json.dumps(baseline_journal))
                if mutation.startswith("preclaim_"):
                    mutated_preclaim = json.loads(json.dumps(base_preclaim))
                    if mutation == "preclaim_consumed_r2":
                        mutated_preclaim["consumed_r2_experiment_id"] = (
                            finalizer.CONTROL_EXPERIMENT_ID
                        )
                    elif mutation == "preclaim_consumed_r3":
                        mutated_preclaim["consumed_r3_experiment_id"] = (
                            finalizer.CONTROL_R2_EXPERIMENT_ID
                        )
                    elif mutation == "preclaim_capsule_missing":
                        del mutated_preclaim["predecessor_capsule"]
                    elif mutation == "preclaim_r2_incident_extra":
                        mutated_preclaim["r2_incident"]["unexpected"] = False
                    elif mutation == "preclaim_r2_incident_hash":
                        mutated_preclaim["r2_incident"]["sha256"] = "0" * 64
                    elif mutation == "preclaim_r3_incident_missing":
                        del mutated_preclaim["r3_incident"]
                    elif mutation == "preclaim_r3_incident_extra":
                        mutated_preclaim["r3_incident"]["unexpected"] = False
                    else:
                        mutated_preclaim["r3_incident"]["sha256"] = "0" * 64
                    mutated_preclaim_bytes = probe.json_bytes(mutated_preclaim)
                    journal["control_r2_predecessor"]["preclaim_sha256"] = (
                        finalizer.hashlib.sha256(mutated_preclaim_bytes).hexdigest()
                    )
                    journal["control_r2_predecessor"]["preclaim_size"] = len(
                        mutated_preclaim_bytes
                    )
                    journal["control_r3_reconciliation"]["preclaim_sha256"] = (
                        finalizer.hashlib.sha256(mutated_preclaim_bytes).hexdigest()
                    )
                    journal["control_r3_reconciliation"]["preclaim_size"] = len(
                        mutated_preclaim_bytes
                    )
                    journal["control_r4_reconciliation"]["preclaim_sha256"] = (
                        finalizer.hashlib.sha256(mutated_preclaim_bytes).hexdigest()
                    )
                    journal["control_r4_reconciliation"]["preclaim_size"] = len(
                        mutated_preclaim_bytes
                    )
                    with mock.patch.object(
                        probe,
                        "_control_r4_preclaim",
                        return_value=mutated_preclaim,
                    ):
                        write_journal(journal)
                        with self.assertRaises(finalizer.FinalizeError):
                            finalizer.validate_control(self.control_manifest, self.root)
                elif mutation.startswith("r2_summary"):
                    summary = journal["control_r3_reconciliation"]["r2_incident"]
                    assert isinstance(summary, dict)
                    if mutation == "r2_summary_missing":
                        del summary["classification"]
                    elif mutation == "r2_summary_extra":
                        summary["unexpected"] = False
                    else:
                        summary["security_boundary_result"] = "FORGED"
                    write_journal(journal)
                    with self.assertRaises(finalizer.FinalizeError):
                        finalizer.validate_control(self.control_manifest, self.root)
                elif mutation.startswith("r3_summary"):
                    summary = journal["control_r4_reconciliation"]["r3_incident"]
                    assert isinstance(summary, dict)
                    if mutation == "r3_summary_missing":
                        del summary["incident_facts"]
                    elif mutation == "r3_summary_extra":
                        summary["unexpected"] = False
                    elif mutation == "r3_summary_status":
                        summary["status"] = "VALIDATED_ZERO_EFFECT"
                    else:
                        summary["incident_facts"]["panic_restore_verified"] = False
                    write_journal(journal)
                    with self.assertRaises(finalizer.FinalizeError):
                        finalizer.validate_control(self.control_manifest, self.root)
                else:
                    if mutation == "r4_missing":
                        del journal["control_r4_reconciliation"]
                    elif mutation == "r4_extra":
                        journal["control_r4_reconciliation"]["unexpected"] = False
                    elif mutation == "r4_preclaim_hash":
                        journal["control_r4_reconciliation"]["preclaim_sha256"] = "0" * 64
                    else:
                        journal["control_r4_reconciliation"]["preclaim_size"] += 1
                    write_journal(journal)
                    with self.assertRaises(finalizer.FinalizeError):
                        finalizer.validate_control(self.control_manifest, self.root)

    def test_control_r4_reconciliation_projections_cannot_drift(self) -> None:
        baseline_manifest = json.loads(self.control_manifest.read_text())
        baseline_raw_path = (
            self.root
            / "evidence/private"
            / f"{finalizer.CONTROL_EXPERIMENT_ID}.json"
        )
        baseline_journal_path = (
            self.root
            / "evidence/private"
            / f"{finalizer.CONTROL_EXPERIMENT_ID}.journal.json"
        )
        baseline_raw = json.loads(baseline_raw_path.read_text())
        baseline_journal = json.loads(baseline_journal_path.read_text())
        for owner in (
            "manifest_r2",
            "raw_r2",
            "journal_r2",
            "manifest_r3",
            "raw_r3",
            "journal_r3",
        ):
            with self.subTest(owner=owner):
                manifest = json.loads(json.dumps(baseline_manifest))
                raw = json.loads(json.dumps(baseline_raw))
                journal = json.loads(json.dumps(baseline_journal))
                if owner == "manifest_r2":
                    manifest["r2_incident_manifest_size"] += 1
                elif owner == "raw_r2":
                    raw["r2_zero_effect_validated"] = False
                elif owner == "journal_r2":
                    journal["r2_incident_manifest_sha256"] = "0" * 64
                elif owner == "manifest_r3":
                    manifest["r3_incident_manifest_size"] += 1
                elif owner == "raw_r3":
                    raw["r3_zero_op_restored_validated"] = False
                else:
                    journal["r3_incident_manifest_sha256"] = "0" * 64
                raw_bytes = self._write(baseline_raw_path, raw)
                journal_bytes = self._write(baseline_journal_path, journal)
                manifest["raw_snapshot_sha256"] = finalizer.hashlib.sha256(
                    raw_bytes
                ).hexdigest()
                manifest["raw_snapshot_size"] = len(raw_bytes)
                manifest["journal_sha256"] = finalizer.hashlib.sha256(
                    journal_bytes
                ).hexdigest()
                manifest["journal_size"] = len(journal_bytes)
                self._write(self.control_manifest, manifest)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_control(self.control_manifest, self.root)

    def test_control_r2_old_id_and_old_manifest_path_are_rejected(self) -> None:
        old_path = self.root / "evidence/manifests" / (
            f"{finalizer.CONTROL_PREDECESSOR_EXPERIMENT_ID}.manifest.json"
        )
        old_path.write_bytes(self.control_manifest.read_bytes())
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_control(old_path, self.root)

        manifest = json.loads(self.control_manifest.read_text())
        manifest["experiment_id"] = finalizer.CONTROL_PREDECESSOR_EXPERIMENT_ID
        self._write(self.control_manifest, manifest)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_control(self.control_manifest, self.root)

    def test_read_control_capsule_descriptor_is_required_and_exactly_typed(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        read_raw_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        read_journal_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        base_raw = json.loads(read_raw_path.read_text())
        base_journal = json.loads(read_journal_path.read_text())
        base_manifest = json.loads(self.read_manifest.read_text())
        field_cases = (
            ("public_missing", "public", "predecessor_capsule_sha256", None),
            ("public_float", "public", "predecessor_capsule_size", float(self.predecessor_capsule_size)),
            ("raw_missing", "raw", "predecessor_capsule_sha256", None),
            ("raw_bool", "raw", "predecessor_capsule_size", True),
            ("journal_missing", "journal", "predecessor_capsule_sha256", None),
            ("journal_float", "journal", "predecessor_capsule_size", float(self.predecessor_capsule_size)),
            ("public_r3_missing", "public", "r3_incident_manifest_sha256", None),
            ("public_r3_size_float", "public", "r3_incident_manifest_size", 3455.0),
            ("public_r3_bool", "public", "r3_zero_op_restored_validated", False),
            ("raw_r3_missing", "raw", "r3_incident_manifest_sha256", None),
            ("journal_r3_size_float", "journal", "r3_incident_manifest_size", 3455.0),
            ("journal_r3_bool", "journal", "r3_zero_op_restored_validated", False),
        )
        for name, owner, key, replacement in field_cases:
            with self.subTest(case=name):
                raw = json.loads(json.dumps(base_raw))
                journal = json.loads(json.dumps(base_journal))
                manifest = json.loads(json.dumps(base_manifest))
                if owner == "public":
                    if replacement is None:
                        del manifest["control_manifest"][key]
                    else:
                        manifest["control_manifest"][key] = replacement
                elif owner == "raw":
                    if replacement is None:
                        del raw["control_manifest"][key]
                    else:
                        raw["control_manifest"][key] = replacement
                else:
                    if replacement is None:
                        del journal["control_manifest"][key]
                    else:
                        journal["control_manifest"][key] = replacement
                raw_bytes = self._write(read_raw_path, raw)
                journal_bytes = self._write(read_journal_path, journal)
                manifest["raw_snapshot_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
                manifest["raw_snapshot_size"] = len(raw_bytes)
                manifest["journal_sha256"] = finalizer.hashlib.sha256(journal_bytes).hexdigest()
                manifest["journal_size"] = len(journal_bytes)
                self._write(self.read_manifest, manifest)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_read(self.read_manifest, self.root, control)

    def test_read_r3_reconciliation_projections_cannot_drift(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        raw_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        journal_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        baseline_manifest = json.loads(self.read_manifest.read_text())
        baseline_raw = json.loads(raw_path.read_text())
        baseline_journal = json.loads(journal_path.read_text())
        for owner in ("manifest", "raw", "journal"):
            with self.subTest(owner=owner):
                manifest = json.loads(json.dumps(baseline_manifest))
                raw = json.loads(json.dumps(baseline_raw))
                journal = json.loads(json.dumps(baseline_journal))
                if owner == "manifest":
                    manifest["r3_incident_manifest_size"] += 1
                elif owner == "raw":
                    raw["r3_zero_op_restored_validated"] = False
                else:
                    journal["r3_incident_manifest_sha256"] = "0" * 64
                raw_bytes = self._write(raw_path, raw)
                journal_bytes = self._write(journal_path, journal)
                manifest["raw_snapshot_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
                manifest["raw_snapshot_size"] = len(raw_bytes)
                manifest["journal_sha256"] = finalizer.hashlib.sha256(journal_bytes).hexdigest()
                manifest["journal_size"] = len(journal_bytes)
                self._write(self.read_manifest, manifest)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_read(self.read_manifest, self.root, control)

    def test_inline_frame_consumer_rejects_zero_or_missing_stophud_sequence(self) -> None:
        raw = json.loads(
            (
                self.root
                / "evidence/private"
                / f"{finalizer.CONTROL_EXPERIMENT_ID}.json"
            ).read_text()
        )
        panic_only = [
            frame
            for frame in raw["frames"]
            if frame.get("evidence_id")
            in {"panic_before", "panic_set_0", "panic_zero_verify"}
        ]
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_frame_list(
                panic_only,
                "hostile missing stophud",
                restored=False,
                allow_fixed=False,
            )
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_frame_list(
                [],
                "hostile zero stophud",
                restored=False,
                allow_fixed=False,
            )

    def _rewrite_read_transport_error(
        self,
        error: dict[str, object],
        *,
        journal_error: dict[str, object] | None = None,
    ) -> None:
        """Replace the refusal transport in both private receipts.

        The public manifest only carries the private snapshot hashes.  Updating
        those hashes here keeps each case at the real finalizer boundary and
        lets the validator distinguish a typed partial exchange from an
        outcome-only or cross-spliced error summary.
        """

        raw_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        journal_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        raw = json.loads(raw_path.read_text())
        journal = json.loads(journal_path.read_text())
        raw["error"] = dict(error)
        journal["error"] = dict(journal_error if journal_error is not None else error)
        raw_bytes = self._write(raw_path, raw)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.read_manifest.read_text())
        public.update(
            {
                "raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(),
                "raw_snapshot_size": len(raw_bytes),
                "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(),
                "journal_size": len(journal_bytes),
            }
        )
        self._write(self.read_manifest, public)

    @staticmethod
    def _typed_partial_error() -> dict[str, object]:
        begin_only = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
        return {
            "exception_type": "TransportFailure",
            "exception_text": "bridge closed before terminal frame",
            "evidence_id": "fixed_op_4",
            "argv": list(finalizer.fixed_op_argv()),
            "transport_no_value": True,
            "bounded": True,
            "partial_evidence_present": True,
            "a90r_present": False,
            "payload_base64": "",
            "payload_sha256": finalizer.hashlib.sha256(b"").hexdigest(),
            "payload_size": 0,
            "transcript_base64": base64.b64encode(begin_only).decode("ascii"),
            "transcript_sha256": finalizer.hashlib.sha256(begin_only).hexdigest(),
            "transcript_size": len(begin_only),
            "payload_bounded": True,
            "transcript_bounded": True,
            "begin": {"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
            "end": None,
        }

    def test_finalizer_accepts_only_typed_partial_transport_for_refused_read(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        self._rewrite_read_transport_error(self._typed_partial_error())
        result = finalizer.validate_read(self.read_manifest, self.root, control)
        self.assertFalse(result["value_present"])

    def test_finalizer_transport_no_value_rejects_native_completion_markers(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        begin_line = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
        bodies = (
            b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\n[exit 1]\n",
            b"run: pid=1, q/Ctrl-C cancels\n[signal 9]\n",
            b"run: pid=1, q/Ctrl-C cancels\n[done] run (0ms)\n",
            b"run: pid=1, q/Ctrl-C cancels\n[err] run rc=-1 errno=1 (x) (0ms)\n",
            b"run: pid=1, q/Ctrl-C cancels\n[busy] auto menu active; send hide/q before command\n",
            b"run: fork: Resource temporarily unavailable\n",
            b"run: wait: Input/output error\n",
            b"run: unknown child status\n",
            b"usage: run <path> [args...]\n",
            b"A\n",
            b"A90\n",
            b"A90R\n",
        )
        for body in bodies:
            with self.subTest(body=body):
                error = self._typed_partial_error()
                payload = body
                transcript = begin_line + body
                error.update(
                    {
                        "payload_base64": base64.b64encode(payload).decode("ascii"),
                        "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                        "payload_size": len(payload),
                        "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                        "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                        "transcript_size": len(transcript),
                    }
                )
                self._rewrite_read_transport_error(error)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_read(self.read_manifest, self.root, control)

    def test_finalizer_transport_no_value_accepts_split_dispatch_prefix(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        body = b"run: pid=123, q/Ctrl-C cancels"
        for index in range(len(body) + 1):
            with self.subTest(index=index):
                error = self._typed_partial_error()
                payload = body[:index]
                begin_line = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
                transcript = begin_line + payload
                error.update(
                    {
                        "payload_base64": base64.b64encode(payload).decode("ascii"),
                        "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                        "payload_size": len(payload),
                        "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                        "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                        "transcript_size": len(transcript),
                    }
                )
                self._rewrite_read_transport_error(error)
                result = finalizer.validate_read(self.read_manifest, self.root, control)
                self.assertFalse(result["value_present"])

    def test_finalizer_rejects_legacy_timeout_even_with_partial_shape(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        error = self._typed_partial_error()
        error["exception_type"] = "TimeoutError"
        self._rewrite_read_transport_error(error)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(self.read_manifest, self.root, control)

    def test_finalizer_binds_partial_begin_to_exact_transcript(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        valid = self._typed_partial_error()
        cases: list[dict[str, object]] = []
        missing_begin = dict(valid)
        missing_begin["begin"] = None
        cases.append(missing_begin)
        wrong_command = dict(valid)
        wrong_command["begin"] = {"cmd": "cat", "seq": "1"}
        cases.append(wrong_command)
        wrong_argc = dict(valid)
        wrong_argc["transcript_base64"] = base64.b64encode(
            b"A90P1 BEGIN seq=1 cmd=run argc=1\n"
        ).decode("ascii")
        wrong_argc["transcript_sha256"] = finalizer.hashlib.sha256(
            base64.b64decode(wrong_argc["transcript_base64"])
        ).hexdigest()
        wrong_argc["transcript_size"] = len(
            base64.b64decode(wrong_argc["transcript_base64"])
        )
        cases.append(wrong_argc)
        duplicate_begin = dict(valid)
        duplicate = b"A90P1 BEGIN seq=1 cmd=run\nA90P1 BEGIN seq=1 cmd=run\n"
        duplicate_begin["transcript_base64"] = base64.b64encode(duplicate).decode(
            "ascii"
        )
        duplicate_begin["transcript_sha256"] = finalizer.hashlib.sha256(
            duplicate
        ).hexdigest()
        duplicate_begin["transcript_size"] = len(duplicate)
        cases.append(duplicate_begin)
        payload_mismatch = dict(valid)
        payload = b"forged post-BEGIN payload"
        payload_mismatch["payload_base64"] = base64.b64encode(payload).decode("ascii")
        payload_mismatch["payload_sha256"] = finalizer.hashlib.sha256(payload).hexdigest()
        payload_mismatch["payload_size"] = len(payload)
        cases.append(payload_mismatch)
        no_begin_payload = dict(valid)
        no_begin_transcript = b"bridge opened without a protocol BEGIN\n"
        no_begin_payload.update(
            {
                "begin": None,
                "payload_base64": "",
                "payload_sha256": finalizer.hashlib.sha256(b"").hexdigest(),
                "payload_size": 0,
                "transcript_base64": base64.b64encode(no_begin_transcript).decode("ascii"),
                "transcript_sha256": finalizer.hashlib.sha256(no_begin_transcript).hexdigest(),
                "transcript_size": len(no_begin_transcript),
            }
        )
        cases.append(no_begin_payload)
        for error in cases:
            with self.subTest(error=error):
                self._rewrite_read_transport_error(error)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_read(self.read_manifest, self.root, control)

    def test_finalizer_rejects_extra_or_hidden_transport_evidence_aliases(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        for extra in (
            {"partial_end": None},
            {"partial": {"end": None}},
            {"hidden_fixed_op_frame": {"evidence_id": "fixed_op_4"}},
        ):
            with self.subTest(extra=extra):
                error = self._typed_partial_error()
                error.update(extra)
                self._rewrite_read_transport_error(error)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_read(self.read_manifest, self.root, control)

    def test_finalizer_rejects_renamed_complete_fixed_op_frame(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        raw_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        journal_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        raw = json.loads(raw_path.read_text())
        journal = json.loads(journal_path.read_text())
        hidden = _complete_fixed_op_frame("0x000000000000c071")
        hidden["evidence_id"] = "fixed_op_hidden"
        raw["frames"].append(hidden)
        journal["frames"].append(hidden)
        raw_bytes = self._write(raw_path, raw)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.read_manifest.read_text())
        public.update(
            {
                "raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(),
                "raw_snapshot_size": len(raw_bytes),
                "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(),
                "journal_size": len(journal_bytes),
            }
        )
        self._write(self.read_manifest, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(self.read_manifest, self.root, control)

    def test_fixed_op_terminal_kind_and_prompt_tail_are_exact(self) -> None:
        for marker in (
            b"[err] run rc=0 (0ms)\n",
            b"[busy] auto menu active; send hide/q before command\n",
        ):
            with self.subTest(marker=marker):
                frame = _complete_fixed_op_frame("0x000000000000c071")
                transcript = base64.b64decode(frame["transcript_base64"])
                transcript = transcript.replace(
                    b"[done] run (0ms)\n", marker, 1
                )
                frame["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
                frame["transcript_sha256"] = finalizer.hashlib.sha256(transcript).hexdigest()
                frame["transcript_size"] = len(transcript)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_fixed_op_frame(
                        [frame], "0x000000000000c071", "hostile fixed terminal"
                    )

        frame = _complete_fixed_op_frame("0x000000000000c071")
        transcript = base64.b64decode(frame["transcript_base64"]) + b"garbage-after-end"
        frame["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
        frame["transcript_sha256"] = finalizer.hashlib.sha256(transcript).hexdigest()
        frame["transcript_size"] = len(transcript)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_fixed_op_frame(
                [frame], "0x000000000000c071", "hostile fixed tail"
            )

    def test_finalizer_requires_ordered_panic_frames_for_negative_and_returned_paths(self) -> None:
        raw_path = self.root / "evidence/private" / f"{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        raw = json.loads(raw_path.read_text())
        panic = [
            frame
            for frame in raw["frames"]
            if frame.get("evidence_id")
            in {"panic_before", "panic_set_0", "panic_zero_verify"}
        ]
        for bad_frames in (
            [panic[1], panic[0], panic[2]],
            [*panic, panic[0]],
        ):
            with self.subTest(frame_ids=[frame.get("evidence_id") for frame in bad_frames]):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_panic_frame_set(
                        bad_frames, "read refusal hostile", restored=False
                    )

    def test_finalizer_rejects_typed_complete_frame_or_pre_exchange_failure(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        payload = b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\n[exit 0]\n"
        transcript = (
            b"A90P1 BEGIN seq=1 cmd=run\n"
            + payload
            + b"\n[done] run (0ms)\n"
            + b"A90P1 END seq=1 cmd=run rc=0 status=ok\n"
        )
        complete = self._typed_partial_error()
        complete.update(
            {
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_sha256": finalizer.hashlib.sha256(payload).hexdigest(),
                "payload_size": len(payload),
                "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                "transcript_size": len(transcript),
                "a90r_present": True,
                "end": {"cmd": "run", "seq": "1", "rc": "0", "status": "ok"},
            }
        )
        complete_without_value = dict(complete)
        no_value_payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n"
        no_value_transcript = (
            b"A90P1 BEGIN seq=1 cmd=run\n"
            + no_value_payload
            + b"\n[done] run (0ms)\n"
            + b"A90P1 END seq=1 cmd=run rc=0 status=ok\n"
        )
        complete_without_value.update(
            {
                "payload_base64": base64.b64encode(no_value_payload).decode("ascii"),
                "payload_sha256": finalizer.hashlib.sha256(no_value_payload).hexdigest(),
                "payload_size": len(no_value_payload),
                "transcript_base64": base64.b64encode(no_value_transcript).decode("ascii"),
                "transcript_sha256": finalizer.hashlib.sha256(no_value_transcript).hexdigest(),
                "transcript_size": len(no_value_transcript),
                "a90r_present": False,
            }
        )
        for error in (
            complete,
            complete_without_value,
            {
                **self._typed_partial_error(),
                "partial_evidence_present": False,
            },
        ):
            with self.subTest(error=error):
                self._rewrite_read_transport_error(error)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_read(self.read_manifest, self.root, control)

    def test_finalizer_rejects_cross_bound_typed_transport_error(self) -> None:
        control = finalizer.validate_control(self.control_manifest, self.root)
        error = self._typed_partial_error()
        journal_error = dict(error)
        journal_error["transcript_sha256"] = "0" * 64
        self._rewrite_read_transport_error(error, journal_error=journal_error)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(self.read_manifest, self.root, control)

    def test_runtime_cmdline_binds_relevant_subset_but_retains_real_extra_tokens(self) -> None:
        parsed = finalizer._runtime_cmdline(
            b"skip_initramfs rootwait ro androidboot.em.model=SM-A908N "
            b"androidboot.bootloader=A908NKSU5EWA3 androidboot.debug_level=0x4f4c "
            b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0 "
            b"root=PARTUUID=01234567-89ab-cdef-0123-456789abcdef video=1080x2400@60,bpp=32\n"
        )
        self.assertEqual(parsed["root"], "PARTUUID=01234567-89ab-cdef-0123-456789abcdef")
        self.assertEqual(parsed["video"], "1080x2400@60,bpp=32")
        for payload in (
            b"androidboot.em.model=SM-A908N androidboot.em.model=SM-A908N\n",
            b"androidboot.em.model=SM-A908N malformed\n",
            b"androidboot.em.model=SM-A908N bad$key=value\n",
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._runtime_cmdline(payload)

    def test_finalizer_cmdlines_accept_live_space_runs_and_reject_other_whitespace(self) -> None:
        runtime_payload = (
            b"skip_initramfs  rootwait   ro androidboot.em.model=SM-A908N  "
            b"androidboot.bootloader=A908NKSU5EWA3   androidboot.debug_level=0x4f4c  "
            b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0\r\n"
        )
        last_payload = (
            b"skip_initramfs  rootwait   ro androidboot.em.model=SM-A908N  "
            b"androidboot.bootloader=A908NKSU5EWA3   androidboot.debug_level=0x494d  "
            b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0  "
            b"androidboot.serialno=ABC123\n"
        )
        for parser, payload in (
            (finalizer._runtime_cmdline, runtime_payload),
            (finalizer._last_cmdline, last_payload),
        ):
            with self.subTest(parser=parser.__name__):
                compact = b" ".join(payload.rstrip(b"\r\n").split()) + b"\n"
                self.assertEqual(parser(payload), parser(compact))
                malformed = (
                    payload.replace(b" ", b"\t", 1),
                    payload.replace(b" ", b"\x0b", 1),
                    payload.replace(b" ", b"\x0c", 1),
                    payload.replace(b" ", b"\n", 1),
                    payload.replace(b" ", b"\r", 1),
                    b" " + payload,
                    payload[:-1] + b" ",
                    payload + b"\n",
                    payload.replace(b" ", b"\x00", 1),
                    payload.replace(
                        b"androidboot.em.model=SM-A908N",
                        b"androidboot.em.model=SM-A908N   androidboot.em.model=SM-A908N",
                        1,
                    ),
                )
                for bad_payload in malformed:
                    with self.subTest(bad_payload=bad_payload):
                        with self.assertRaises(finalizer.FinalizeError):
                            parser(bad_payload)

    def test_runtime_health_accepts_producer_shaped_cmdline_and_live_stat(self) -> None:
        raw = json.loads(
            (self.root / "evidence/private" / f"{finalizer.RUNTIME_HEALTH_EXPERIMENT_ID}.json").read_text()
        )
        records = raw["records"]
        stat_frame = next(item for item in records if item["evidence_id"] == "boot_attest_stat_node")
        cmdline_frame = next(item for item in records if item["evidence_id"] == "cmdline")
        self.assertEqual(
            base64.b64decode(stat_frame["payload_base64"]),
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=259:8",
        )
        self.assertIn(
            b"  rootwait   ",
            base64.b64decode(cmdline_frame["payload_base64"]),
        )
        result = finalizer.validate_runtime_health(self.runtime_health, self.root)
        self.assertEqual(result["kind"], "runtime_health")

    def test_runtime_health_rejects_forged_stat_spacing_after_full_rebinding(self) -> None:
        forged = b"mode=0600  uid=0 gid=0 size=0\r\nrdev=259:8"
        with self.assertRaises(probe.ProbeError):
            probe._parse_stat_identity(forged, "259", "8")

        raw_path = self.root / "evidence/private/runtime-health.json"
        journal_path = self.root / "evidence/private/runtime-health.journal.json"
        raw = json.loads(raw_path.read_text())
        journal = json.loads(journal_path.read_text())

        def rewrite(frame: dict[str, object]) -> None:
            if frame.get("evidence_id") != "boot_attest_stat_node":
                return
            begin = frame["begin"]
            end = frame["end"]
            assert isinstance(begin, dict) and isinstance(end, dict)
            transcript = (
                f"A90P1 BEGIN seq={begin['seq']} cmd={begin['cmd']} argc={begin['argc']} flags={begin['flags']}\n".encode("ascii")
                + forged
                + f"\n[done] {begin['cmd']} (0ms)\n".encode("ascii")
                + f"A90P1 END seq={end['seq']} cmd={end['cmd']} rc={end['rc']} errno={end['errno']} duration_ms={end['duration_ms']} flags={end['flags']} status={end['status']}\n".encode("ascii")
            )
            frame.update(
                {
                    "payload_base64": base64.b64encode(forged).decode("ascii"),
                    "payload_sha256": finalizer.hashlib.sha256(forged).hexdigest(),
                    "payload_size": len(forged),
                    "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                    "transcript_sha256": finalizer.hashlib.sha256(transcript).hexdigest(),
                    "transcript_size": len(transcript),
                }
            )

        rewrite_all = (raw["records"], raw["boot_attestation_frames"])
        for frames in rewrite_all:
            matches = [frame for frame in frames if frame.get("evidence_id") == "boot_attest_stat_node"]
            self.assertEqual(len(matches), 1)
            rewrite(matches[0])
        journal["records"] = raw["records"]
        journal_boot = dict(journal["boot_attestation"])
        journal_boot["frames"] = raw["boot_attestation_frames"]
        journal["boot_attestation"] = journal_boot
        raw_bytes = self._write(raw_path, raw)
        journal["raw_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        journal["raw_size"] = len(raw_bytes)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.runtime_health.read_text())
        public["records"] = [finalizer._runtime_public_record(frame) for frame in raw["records"]]
        public.update(
            {
                "raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(),
                "raw_snapshot_size": len(raw_bytes),
                "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(),
                "journal_size": len(journal_bytes),
            }
        )
        self._write(self.runtime_health, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_runtime_health(self.runtime_health, self.root)

    def test_runtime_summary_only_or_forged_transport_records_fail_closed(self) -> None:
        raw_path = self.root / "evidence/private/runtime-health.json"
        raw = json.loads(raw_path.read_text())
        raw.pop("records")
        raw_bytes = self._write(raw_path, raw)
        public = json.loads(self.runtime_health.read_text())
        public.update({"raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(), "raw_snapshot_size": len(raw_bytes)})
        self._write(self.runtime_health, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_runtime_health(self.runtime_health, self.root)

    def test_runtime_stophud_busy_retry_is_frame_bound_and_mismatch_fails(self) -> None:
        raw_path = self.root / "evidence/private/runtime-health.json"
        journal_path = self.root / "evidence/private/runtime-health.journal.json"
        raw = json.loads(raw_path.read_text())
        journal = json.loads(journal_path.read_text())

        def rewrite_frame(frame: dict[str, object], *, evidence_id: str, rc: str, status: str, transcript: bytes) -> dict[str, object]:
            result = dict(frame)
            result["evidence_id"] = evidence_id
            argv = tuple(result["argv"])
            protocol_flags = finalizer.inline_protocol_flags_for_argv(argv)
            if protocol_flags is None:
                raise AssertionError(f"test command has no native flag contract: {argv}")
            errno = str(abs(int(rc, 10)))
            result["begin"] = {"cmd": argv[0], "seq": "1", "argc": str(len(argv)), "flags": protocol_flags}
            result["end"] = {"cmd": argv[0], "seq": "1", "rc": rc, "errno": errno, "duration_ms": "0", "flags": protocol_flags, "status": status}
            command = result["argv"][0].encode("ascii")
            if status == "busy":
                marker = b"[busy] auto menu active; send hide/q before command\n"
            elif rc == "0":
                marker = f"[done] {argv[0]} (0ms)\n".encode("ascii")
            elif rc.startswith("-"):
                marker = (
                    f"[err] {argv[0]} rc={rc} errno={errno} (error) (0ms)\n"
                ).encode("ascii")
            else:
                marker = f"[err] {argv[0]} rc={rc} (0ms)\n".encode("ascii")
            result["payload_base64"] = base64.b64encode(transcript).decode("ascii")
            result["payload_sha256"] = finalizer.hashlib.sha256(transcript).hexdigest()
            result["payload_size"] = len(transcript)
            framed = (
                b"A90P1 BEGIN seq=1 cmd=" + command + b" argc=" + str(len(argv)).encode("ascii") + b" flags=" + protocol_flags.encode("ascii") + b"\n"
                + transcript
                + (b"\n" if transcript and not transcript.endswith(b"\n") else b"")
                + marker
                + b"A90P1 END seq=1 cmd=" + command
                + b" rc=" + rc.encode("ascii") + b" errno=" + errno.encode("ascii")
                + b" duration_ms=0 flags=" + protocol_flags.encode("ascii") + b" status=" + status.encode("ascii") + b"\n"
            )
            result["transcript_base64"] = base64.b64encode(framed).decode("ascii")
            result["transcript_sha256"] = finalizer.hashlib.sha256(framed).hexdigest()
            result["transcript_size"] = len(framed)
            return result

        first_frame = rewrite_frame(raw["stophud_frames"][0], evidence_id="stophud_1", rc="-16", status="busy", transcript=b"")
        second_frame = rewrite_frame(raw["stophud_frames"][0], evidence_id="stophud_2", rc="0", status="ok", transcript=b"autohud: stopped")
        attempts = [
            {"attempt": 1, "rc": -16, "status": "busy", "evidence_id": "stophud_1", "payload_size": first_frame["payload_size"], "payload_sha256": first_frame["payload_sha256"], "transcript_size": first_frame["transcript_size"], "transcript_sha256": first_frame["transcript_sha256"]},
            {"attempt": 2, "rc": 0, "status": "ok", "evidence_id": "stophud_2", "payload_size": second_frame["payload_size"], "payload_sha256": second_frame["payload_sha256"], "transcript_size": second_frame["transcript_size"], "transcript_sha256": second_frame["transcript_sha256"]},
        ]
        stophud = {"accepted": True, "attempts": attempts, "busy_retries": 1}
        raw["stophud"] = stophud
        raw["stophud_frames"] = [first_frame, second_frame]
        journal["stophud"] = stophud
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = [first_frame, second_frame]
        raw_bytes = self._write(raw_path, raw)
        journal["raw_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        journal["raw_size"] = len(raw_bytes)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.runtime_health.read_text())
        public["stophud"] = stophud
        public["stophud_frames"] = [{key: frame[key] for key in ("evidence_id", "argv", "begin", "end", "payload_sha256", "payload_size", "transcript_sha256", "transcript_size")} for frame in (first_frame, second_frame)]
        public.update({"raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(), "raw_snapshot_size": len(raw_bytes), "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(), "journal_size": len(journal_bytes)})
        self._write(self.runtime_health, public)
        finalizer.validate_runtime_health(self.runtime_health, self.root)

        # stophud is a first-success transaction: an accepted 0/ok must be
        # terminal.  A later busy retry or second success is replay-shaped
        # evidence and must not validate as one lifecycle.
        success_one = rewrite_frame(
            raw["stophud_frames"][0],
            evidence_id="stophud_1",
            rc="0",
            status="ok",
            transcript=b"",
        )
        busy_two = rewrite_frame(
            raw["stophud_frames"][0],
            evidence_id="stophud_2",
            rc="-16",
            status="busy",
            transcript=b"",
        )
        success_three = rewrite_frame(
            raw["stophud_frames"][0],
            evidence_id="stophud_3",
            rc="0",
            status="ok",
            transcript=b"",
        )
        for bad_frames in ([success_one, busy_two, success_three], [success_one, success_three]):
            attempts = [
                {
                    "attempt": index,
                    "rc": int(frame["end"]["rc"], 0),
                    "status": frame["end"]["status"],
                    "evidence_id": frame["evidence_id"],
                    "payload_size": frame["payload_size"],
                    "payload_sha256": frame["payload_sha256"],
                    "transcript_size": frame["transcript_size"],
                    "transcript_sha256": frame["transcript_sha256"],
                }
                for index, frame in enumerate(bad_frames, 1)
            ]
            bad_stophud = {
                "accepted": True,
                "attempts": attempts,
                "busy_retries": sum(item["rc"] == -16 for item in attempts),
            }
            bad_raw = {**raw, "stophud": bad_stophud, "stophud_frames": bad_frames}
            bad_journal = {
                **journal,
                "stophud": bad_stophud,
                "stophud_attempts": attempts,
                "stophud_frames": bad_frames,
            }
            bad_public = {
                "stophud": bad_stophud,
                "stophud_frames": [
                    {
                        key: frame[key]
                        for key in (
                            "evidence_id",
                            "argv",
                            "begin",
                            "end",
                            "payload_sha256",
                            "payload_size",
                            "transcript_sha256",
                            "transcript_size",
                        )
                    }
                    for frame in bad_frames
                ],
            }
            with self.assertRaises(finalizer.FinalizeError):
                finalizer._runtime_validate_stophud(
                    bad_public, bad_raw, bad_journal
                )

        raw["stophud_frames"][0]["end"]["rc"] = "0"
        raw_bytes = self._write(raw_path, raw)
        journal["stophud_frames"] = raw["stophud_frames"]
        journal["raw_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        journal["raw_size"] = len(raw_bytes)
        journal_bytes = self._write(journal_path, journal)
        public["stophud_frames"] = [{key: frame[key] for key in ("evidence_id", "argv", "begin", "end", "payload_sha256", "payload_size", "transcript_sha256", "transcript_size")} for frame in raw["stophud_frames"]]
        public.update({"raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(), "raw_snapshot_size": len(raw_bytes), "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(), "journal_size": len(journal_bytes)})
        self._write(self.runtime_health, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_runtime_health(self.runtime_health, self.root)

    def test_stophud_four_attempt_sequence_is_outside_fixed_bound(self) -> None:
        raw_path = self.root / "evidence/private/runtime-health.json"
        raw = json.loads(raw_path.read_text())
        frame = raw["stophud_frames"][0]
        attempts = [
            {
                **raw["stophud"]["attempts"][0],
                "attempt": index,
                "evidence_id": f"stophud_{index}",
            }
            for index in range(1, finalizer.STOPHUD_MAX_ATTEMPTS + 2)
        ]
        frames = [
            {**frame, "evidence_id": f"stophud_{index}"}
            for index in range(1, finalizer.STOPHUD_MAX_ATTEMPTS + 2)
        ]
        stophud = {"accepted": True, "attempts": attempts, "busy_retries": 3}
        raw["stophud"] = stophud
        raw["stophud_frames"] = frames
        journal = json.loads(
            (self.root / "evidence/private/runtime-health.journal.json").read_text()
        )
        journal["stophud"] = stophud
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = frames
        public = json.loads(self.runtime_health.read_text())
        public["stophud"] = stophud
        public["stophud_frames"] = [
            {
                key: item[key]
                for key in (
                    "evidence_id",
                    "argv",
                    "begin",
                    "end",
                    "payload_sha256",
                    "payload_size",
                    "transcript_sha256",
                    "transcript_size",
                )
            }
            for item in frames
        ]
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._runtime_validate_stophud(public, raw, journal)

    def test_last_kmsg_four_stophud_attempts_are_outside_fixed_bound(self) -> None:
        metadata = json.loads(
            (self.root / "evidence/private/last-kmsg-final.private.json").read_text()
        )
        journal = json.loads(
            (self.root / "evidence/private/last-kmsg-final.journal.json").read_text()
        )
        public = json.loads(self.last_kmsg.read_text())
        base_attempt = metadata["stophud"]["attempts"][0]
        base_frame = metadata["stophud_frames"][0]
        attempts = [
            {
                **base_attempt,
                "attempt": index,
                "evidence_id": f"stophud_{index}",
            }
            for index in range(1, finalizer.STOPHUD_MAX_ATTEMPTS + 2)
        ]
        frames = [
            {**base_frame, "evidence_id": f"stophud_{index}"}
            for index in range(1, finalizer.STOPHUD_MAX_ATTEMPTS + 2)
        ]
        stophud = {"accepted": True, "attempts": attempts, "busy_retries": 3}
        metadata["stophud"] = stophud
        metadata["stophud_frames"] = frames
        journal["stophud"] = stophud
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = frames
        public["stophud_accepted"] = True
        public["stophud_busy_retries"] = 3
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_last_stophud(public, metadata, journal)

    def test_runtime_nonzero_terminal_and_forged_toybox_exit_fail_closed(self) -> None:
        raw_path = self.root / "evidence/private/runtime-health.json"
        raw = json.loads(raw_path.read_text())
        raw["records"][0]["end"]["rc"] = "7"
        raw_bytes = self._write(raw_path, raw)
        journal_path = self.root / "evidence/private/runtime-health.journal.json"
        journal = json.loads(journal_path.read_text())
        journal["records"] = raw["records"]
        journal["raw_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        journal["raw_size"] = len(raw_bytes)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.runtime_health.read_text())
        public["records"] = [finalizer._runtime_public_record(record) for record in raw["records"]]
        public.update({"raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(), "raw_snapshot_size": len(raw_bytes), "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(), "journal_size": len(journal_bytes)})
        self._write(self.runtime_health, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_runtime_health(self.runtime_health, self.root)

        # Rebuild the fixture for an independent framing mutation.  Keep all
        # outer hashes and projections current so the validator reaches the
        # toybox terminal marker rather than failing on stale metadata.
        self.tearDown()
        self.setUp()
        raw_path = self.root / "evidence/private/runtime-health.json"
        raw = json.loads(raw_path.read_text())
        payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 7]\n"
        frame = raw["boot_attestation_frames"][0]
        frame["payload_base64"] = base64.b64encode(payload).decode("ascii")
        frame["payload_sha256"] = finalizer.hashlib.sha256(payload).hexdigest()
        frame["payload_size"] = len(payload)
        transcript = base64.b64decode(frame["transcript_base64"].encode("ascii"))
        old_payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n"
        if old_payload in transcript:
            transcript = transcript.replace(old_payload, payload)
        else:
            transcript = (
                b"A90P1 BEGIN seq=1 cmd=" + frame["argv"][0].encode("ascii") + b"\n"
                + payload
                + b"A90P1 END seq=1 cmd=" + frame["argv"][0].encode("ascii")
                + b" rc=0 status=ok\n"
            )
        frame["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
        frame["transcript_sha256"] = finalizer.hashlib.sha256(transcript).hexdigest()
        frame["transcript_size"] = len(transcript)
        raw_bytes = self._write(raw_path, raw)
        journal_path = self.root / "evidence/private/runtime-health.journal.json"
        journal = json.loads(journal_path.read_text())
        journal["records"] = raw["records"]
        journal["boot_attestation"]["frames"] = raw["boot_attestation_frames"]
        journal["raw_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        journal["raw_size"] = len(raw_bytes)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.runtime_health.read_text())
        public["records"] = [finalizer._runtime_public_record(record) for record in raw["records"]]
        public["raw_snapshot_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        public["raw_snapshot_size"] = len(raw_bytes)
        public["journal_sha256"] = finalizer.hashlib.sha256(journal_bytes).hexdigest()
        public["journal_size"] = len(journal_bytes)
        self._write(self.runtime_health, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_runtime_health(self.runtime_health, self.root)

    def test_system_boot_rejects_retired_combined_sync_effect_command(self) -> None:
        private = json.loads(self.system_boot.read_text())
        private["effect_command"] = "sync; twrp set tw_gui_done 1"
        private["effect_argv"] = ["sync; twrp set tw_gui_done 1"]
        private["effect"]["command"] = "sync; twrp set tw_gui_done 1"
        private["effect"]["argv"] = ["sync; twrp set tw_gui_done 1"]
        private_bytes = self._write(self.system_boot, private)
        public_path = self.root / "evidence/manifests" / f"{finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID}.manifest.json"
        public = json.loads(public_path.read_text())
        public["journal_sha256"] = finalizer.hashlib.sha256(private_bytes).hexdigest()
        public["journal_size"] = len(private_bytes)
        self._write(public_path, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_system_boot(self.system_boot, self.root)

    def test_system_boot_rejects_b1_to_b2_recovery_uuid_splice(self) -> None:
        private = json.loads(self.system_boot.read_text())
        rebound = dict(private["revalidation_before_sync"]["target"])
        rebound_boot_id = "00000000-0000-0000-0000-000000000002"
        rebound["boot_id"] = rebound_boot_id
        rebound["boot_id_sha256"] = finalizer.hashlib.sha256(rebound_boot_id.encode("ascii")).hexdigest()
        private["revalidation_before_sync"] = {
            **private["revalidation_before_sync"],
            "target": rebound,
        }
        private_bytes = self._write(self.system_boot, private)
        public_path = self.root / "evidence/manifests" / f"{finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID}.manifest.json"
        public = json.loads(public_path.read_text())
        public["journal_sha256"] = finalizer.hashlib.sha256(private_bytes).hexdigest()
        public["journal_size"] = len(private_bytes)
        self._write(public_path, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_system_boot(self.system_boot, self.root)

    def test_system_boot_requires_exact_private_boot_id_receipts(self) -> None:
        base_private = json.loads(self.system_boot.read_text())
        public_path = self.root / "evidence/manifests" / f"{finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID}.manifest.json"
        base_public = json.loads(public_path.read_text())
        other_id = "00000000-0000-0000-0000-000000000099"
        other_raw = f"{other_id}\n".encode("ascii")
        other_receipt = {
            "base64": base64.b64encode(other_raw).decode("ascii"),
            "sha256": finalizer.hashlib.sha256(other_raw).hexdigest(),
            "size": len(other_raw),
        }
        boot_id = base_private["target"]["boot_id"]
        malformed_raws = (
            f" {boot_id}\n".encode("ascii"),
            f"{boot_id}\n\n".encode("ascii"),
            f"{boot_id}\r".encode("ascii"),
            f"{boot_id}\t\n".encode("ascii"),
            f"{boot_id}\x00\n".encode("ascii"),
        )
        cases = {
            "missing": lambda private: private["target"].pop("boot_id_receipt"),
            "other_uuid": lambda private: private["target"].update(
                {"boot_id_receipt": other_receipt}
            ),
            "bad_hash": lambda private: private["target"]["boot_id_receipt"].update(
                {"sha256": "0" * 64}
            ),
            "revalidation_other_uuid": lambda private: private[
                "revalidation_before_sync"
            ]["target"].update({"boot_id_receipt": other_receipt}),
        }
        # Include the producer's exact UUID/LF/CRLF grammar negatives without
        # relaxing the existing target/revalidation cross-binding cases.
        for index, malformed in enumerate(malformed_raws):
            malformed_receipt = {
                "base64": base64.b64encode(malformed).decode("ascii"),
                "sha256": finalizer.hashlib.sha256(malformed).hexdigest(),
                "size": len(malformed),
            }
            cases[f"malformed_{index}"] = lambda private, receipt=malformed_receipt: private[
                "target"
            ].update({"boot_id_receipt": receipt})
        for name, mutate in cases.items():
            with self.subTest(case=name):
                private = json.loads(json.dumps(base_private))
                mutate(private)
                private_bytes = self._write(self.system_boot, private)
                public = json.loads(json.dumps(base_public))
                public["journal_sha256"] = finalizer.hashlib.sha256(private_bytes).hexdigest()
                public["journal_size"] = len(private_bytes)
                self._write(public_path, public)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_system_boot(self.system_boot, self.root)

    def test_system_boot_public_projection_is_closed_and_private_only(self) -> None:
        public_path = self.root / "evidence/manifests" / (
            f"{finalizer.ROLLBACK_SYSTEM_EXPERIMENT_ID}.manifest.json"
        )
        base = json.loads(public_path.read_text())
        cases = {
            "top_extra": (lambda value: value.update({"boot_id_receipt": {}})),
            "target_extra": (lambda value: value["target"].update({"boot_id_receipt": {}})),
            "physical_raw_boot_id": (
                lambda value: value["physical_effect_claim"].update(
                    {"boot_id": "00000000-0000-0000-0000-000000000001"}
                )
            ),
            "claims_extra": (
                lambda value: value["claims"].update({"private": "leak"})
            ),
            "uuid_substring": (
                lambda value: value["claims"]["PROVED"].append(
                    "copied UUID 00000000-0000-0000-0000-000000000001"
                )
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                public = json.loads(json.dumps(base))
                mutate(public)
                self._write(public_path, public)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_system_boot(self.system_boot, self.root)

    def test_last_kmsg_rejects_missing_or_forged_stophud_receipts(self) -> None:
        metadata_path = self.root / "evidence/private/last-kmsg-final.private.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.pop("stophud_frames")
        self._write(metadata_path, metadata)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(self.last_kmsg, self.root)

        self.tearDown()
        self.setUp()
        metadata_path = self.root / "evidence/private/last-kmsg-final.private.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["stophud_frames"][0]["transcript_sha256"] = "0" * 64
        self._write(metadata_path, metadata)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(self.last_kmsg, self.root)

    def test_runtime_duplicate_protocol_frames_fail_closed(self) -> None:
        raw_path = self.root / "evidence/private/runtime-health.json"
        raw = json.loads(raw_path.read_text())
        record = raw["records"][0]
        transcript = base64.b64decode(record["transcript_base64"].encode("ascii"))
        duplicate = transcript + transcript
        record["transcript_base64"] = base64.b64encode(duplicate).decode("ascii")
        record["transcript_sha256"] = finalizer.hashlib.sha256(duplicate).hexdigest()
        record["transcript_size"] = len(duplicate)
        raw_bytes = self._write(raw_path, raw)
        journal_path = self.root / "evidence/private/runtime-health.journal.json"
        journal = json.loads(journal_path.read_text())
        journal["records"] = raw["records"]
        journal["raw_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        journal["raw_size"] = len(raw_bytes)
        journal_bytes = self._write(journal_path, journal)
        public = json.loads(self.runtime_health.read_text())
        public["records"] = [finalizer._runtime_public_record(item) for item in raw["records"]]
        public["raw_snapshot_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        public["raw_snapshot_size"] = len(raw_bytes)
        public["journal_sha256"] = finalizer.hashlib.sha256(journal_bytes).hexdigest()
        public["journal_size"] = len(journal_bytes)
        self._write(self.runtime_health, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_runtime_health(self.runtime_health, self.root)

    def test_output_root_selector_is_not_a_production_parser_option(self) -> None:
        argv = [
            "--experiment-id",
            "final-test",
            "--output-root",
            str(self.root),
        ]
        with self.assertRaises(SystemExit):
            finalizer.make_parser().parse_args(argv)

    def test_finalizer_experiment_id_is_fixed_and_replay_namespace_is_rejected(self) -> None:
        args = self._args("verification-024-final-replay")
        with mock.patch.object(finalizer, "validate_control") as control:
            with self.assertRaisesRegex(finalizer.FinalizeError, "fixed to verification-024-final"):
                finalizer.finalize(args)
        control.assert_not_called()

    def test_injected_alternate_root_or_producer_path_is_rejected_before_validation(self) -> None:
        args = self._args("selector-test")
        with tempfile.TemporaryDirectory() as alternate:
            args.output_root = Path(alternate)
            with mock.patch.object(finalizer, "validate_control") as control, mock.patch.object(
                finalizer, "validate_read"
            ) as read:
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.finalize(args)
            control.assert_not_called()
            read.assert_not_called()

        args = self._args("selector-path-test")
        with tempfile.TemporaryDirectory() as alternate:
            args.control_manifest = Path(alternate) / "verification-024-control.manifest.json"
            with mock.patch.object(finalizer, "validate_control") as control:
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.finalize(args)
            control.assert_not_called()

    def test_returned_read_value_is_potential_not_negative(self) -> None:
        self._promote_read_receipt_to_value()
        _, public = finalizer.finalize(self._args())
        result = json.loads(public.read_text())
        self.assertEqual(result["classification"], "POTENTIAL_SECURITY_BOUNDARY_BYPASS")
        self.assertFalse(result["clean_negative"])

    def test_forged_value_summary_without_actual_fixed_frame_is_incident(self) -> None:
        """A value/hash summary cannot replace the retained transport frame."""

        raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        raw = json.loads(raw_path.read_text())
        value = "0x0000000000001234"
        raw.update({
            "value": value,
            "outcome": "READABLE_SECURITY_INDICATOR",
            "fixed_op_measurement": {
                "argv": list(finalizer.fixed_op_argv()),
                "buffer_size": 0x58,
                "buffer_sha256": finalizer._fixed_op_buffer_hash(),
                "magic": "0xa90c0de5deadbeef",
                "op": 4,
                "args": [],
                "rc": 0,
                "status": "ok",
                "value": value,
                "a90r_record": "A90R1234",
            },
        })
        # Deliberately leave the refusal frame list without fixed_op_4.
        raw_bytes = self._write(raw_path, raw)
        public = json.loads(self.read_manifest.read_text())
        public.update({
            "returned_value_present": True,
            "returned_value_sha256": finalizer.hashlib.sha256(value.encode("ascii")).hexdigest(),
            "outcome": "READABLE_SECURITY_INDICATOR",
            "raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(),
            "raw_snapshot_size": len(raw_bytes),
        })
        self._write(self.read_manifest, public)
        _, final_public = finalizer.finalize(self._args())
        result = json.loads(final_public.read_text())
        self.assertEqual(result["classification"], "INCIDENT")
        self.assertFalse(result["returned_value_present"])

    def test_missing_bad_receipt_is_incident_and_does_not_claim_target(self) -> None:
        self.runtime_health.unlink()
        _, public = finalizer.finalize(self._args())
        result = json.loads(public.read_text())
        self.assertEqual(result["classification"], "INCIDENT")
        self.assertIn("runtime_health", result["gate_failures"])
        self.assertFalse(result["target_verified"])
        self.assertIsNone(result["target_model"])

    def test_refused_chain_requires_current_boot_attestation_and_bounded_read_transport(self) -> None:
        manifest = json.loads(self.control_manifest.read_text())
        manifest["current_boot_attestation"] = None
        self._write(self.control_manifest, manifest)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_control(self.control_manifest, self.root)

        self.tearDown()
        self.setUp()
        control = finalizer.validate_control(self.control_manifest, self.root)
        read_public = json.loads(self.read_manifest.read_text())
        read_public["current_boot_attestation"] = None
        self._write(self.read_manifest, read_public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(self.read_manifest, self.root, control)

        # Rebuild a clean fixture, then remove the actual no-value proof from
        # the private read receipt while preserving its public hash binding.
        self.tearDown()
        self.setUp()
        control = finalizer.validate_control(self.control_manifest, self.root)
        raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        raw = json.loads(raw_path.read_text())
        raw["error"]["transport_no_value"] = False
        raw_bytes = self._write(raw_path, raw)
        read_manifest = json.loads(self.read_manifest.read_text())
        read_manifest["raw_snapshot_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        read_manifest["raw_snapshot_size"] = len(raw_bytes)
        self._write(self.read_manifest, read_manifest)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(self.read_manifest, self.root, control)

    def test_returned_value_remains_potential_when_rollback_or_health_is_missing(self) -> None:
        self._promote_read_receipt_to_value()
        self.runtime_health.unlink()
        # A returned 32-bit value remains a safety stop even when both the
        # rollback and final-health validators fail independently.
        self.rollback_flash.unlink()
        _, public = finalizer.finalize(self._args())
        result = json.loads(public.read_text())
        self.assertEqual(result["classification"], "POTENTIAL_SECURITY_BOUNDARY_BYPASS")
        self.assertTrue(result["returned_value_present"])

    def test_duplicate_nan_oversize_and_symlink_inputs_fail_closed(self) -> None:
        duplicate = self.root / "evidence/manifests/duplicate.json"
        duplicate.write_text('{"x":1,"x":2}')
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(duplicate, self.root)
        nan = self.root / "evidence/manifests/nan.json"
        nan.write_text('{"exact_reset_signature":{"status":"x","n":NaN}}')
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(nan, self.root)
        oversized = self.root / "evidence/manifests/oversized.json"
        oversized.write_bytes(b"{" + b" " * finalizer.MAX_RECEIPT_BYTES + b"}")
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(oversized, self.root)
        link = self.root / "evidence/manifests/link.json"
        link.symlink_to(self.last_kmsg)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(link, self.root)

    def test_private_hash_mutation_and_bad_offset_order_fail_closed(self) -> None:
        raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        raw = json.loads(raw_path.read_text())
        raw["candidate_size"] = 1
        raw_bytes = self._write(raw_path, raw)
        manifest = json.loads(self.read_manifest.read_text())
        manifest["raw_snapshot_sha256"] = finalizer.hashlib.sha256(raw_bytes).hexdigest()
        manifest["raw_snapshot_size"] = len(raw_bytes)
        self._write(self.read_manifest, manifest)
        control = finalizer.validate_control(self.control_manifest, self.root)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(self.read_manifest, self.root, control)

        signature = json.loads(self.last_kmsg.read_text())
        signature["exact_reset_signature"]["ordered_offsets"]["debug_level"] = 1
        self._write(self.last_kmsg, signature)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(self.last_kmsg, self.root)

    def test_param_gate_rejects_historical_or_incomplete_capture_shapes(self) -> None:
        manifest = json.loads(self.param_capture.read_text())
        del manifest["capture"]["device_sha256_after"]
        self._write(self.param_capture, manifest)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_param_capture(self.param_capture, self.root)

    def test_param_stable_contract_accepts_byte0_variants_without_full_hash_whitelist(self) -> None:
        baseline = self._refresh_param_contract()
        self.assertEqual(baseline[0], 0)
        accepted = finalizer.validate_param_capture(self.param_capture, self.root)
        self.assertEqual(accepted["stable_sha256"], finalizer.PARAM_STABLE_LOW_SHA256)
        self.assertEqual(accepted["volatile_byte0"], 0)

        for byte0 in (2, 127, 255):
            with self.subTest(byte0=byte0):
                variant = bytearray(baseline)
                variant[0] = byte0
                self._refresh_param_contract(bytes(variant))
                accepted = finalizer.validate_param_capture(self.param_capture, self.root)
                self.assertEqual(accepted["stable_sha256"], finalizer.PARAM_STABLE_LOW_SHA256)
                self.assertEqual(accepted["volatile_byte0"], byte0)
                self.assertEqual(
                    accepted["raw_sha256"],
                    finalizer.hashlib.sha256(bytes(variant)).hexdigest(),
                )
                if byte0 == 2:
                    self.assertEqual(
                        accepted["raw_sha256"],
                        "3dbda88548761e757aab3aaa6a59556dc81f07c320694860685c602367a5170b",
                    )

    def test_param_stable_range_and_raw_debug_offsets_are_recomputed_and_bound(self) -> None:
        baseline = self._refresh_param_contract()

        stable_mutation = bytearray(baseline)
        stable_mutation[1] ^= 0x01
        self._refresh_param_contract(bytes(stable_mutation))
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_param_capture(self.param_capture, self.root)

        raw_offset_mutation = bytearray(baseline)
        raw_offset_mutation[finalizer.PARAM_DEBUG_OFFSET : finalizer.PARAM_DEBUG_OFFSET + 4] = b"DMID"
        self._refresh_param_contract(bytes(raw_offset_mutation))
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_param_capture(self.param_capture, self.root)

    def test_param_forged_stable_full_volatile_and_journal_projections_fail_closed(self) -> None:
        def reject(mutate: object) -> None:
            self._refresh_param_contract()
            mutate()
            with self.assertRaises(finalizer.FinalizeError):
                finalizer.validate_param_capture(self.param_capture, self.root)

        def public_top_mask() -> None:
            public = json.loads(self.param_capture.read_text())
            public["stable_mask"]["stable_size"] = 1
            self._write(self.param_capture, public)

        def public_capture_range() -> None:
            public = json.loads(self.param_capture.read_text())
            public["capture"]["stable_range"]["start"] = 0
            self._write(self.param_capture, public)

        def private_top_stable() -> None:
            path = self.root / "evidence/private/param-low/capture-metadata.json"
            metadata = json.loads(path.read_text())
            metadata["stable_sha256"] = "0" * 64
            self._write(path, metadata)

        def private_capture_mask() -> None:
            path = self.root / "evidence/private/param-low/capture-metadata.json"
            metadata = json.loads(path.read_text())
            metadata["capture"]["stable_mask"]["excluded_ranges"] = [[0, 2]]
            self._write(path, metadata)

        def public_full() -> None:
            public = json.loads(self.param_capture.read_text())
            public["capture"]["full_sha256"] = "0" * 64
            self._write(self.param_capture, public)

        def private_full() -> None:
            path = self.root / "evidence/private/param-low/capture-metadata.json"
            metadata = json.loads(path.read_text())
            metadata["capture"]["full_sha256"] = "0" * 64
            self._write(path, metadata)

        def public_volatile() -> None:
            public = json.loads(self.param_capture.read_text())
            public["volatile_byte0"] = 256
            self._write(self.param_capture, public)

        def journal_stable() -> None:
            path = self.root / "evidence/private/param-low/capture-journal.json"
            journal = json.loads(path.read_text())
            journal["retained_stable_sha256"] = "0" * 64
            self._write(path, journal)

        def journal_volatile() -> None:
            path = self.root / "evidence/private/param-low/capture-journal.json"
            journal = json.loads(path.read_text())
            journal["retained_volatile_byte0"] = 256
            self._write(path, journal)

        for name, mutation in (
            ("public top mask", public_top_mask),
            ("public capture range", public_capture_range),
            ("private top stable", private_top_stable),
            ("private capture mask", private_capture_mask),
            ("public full alias", public_full),
            ("private full alias", private_full),
            ("public volatile", public_volatile),
            ("journal stable", journal_stable),
            ("journal volatile", journal_volatile),
        ):
            with self.subTest(mutation=name):
                reject(mutation)

    def test_param_historic_full_claim_and_triple_mismatch_cannot_authorize_variant(self) -> None:
        baseline = self._refresh_param_contract()
        variant = bytearray(baseline)
        variant[0] = 2
        self._refresh_param_contract(bytes(variant))
        public = json.loads(self.param_capture.read_text())
        metadata_path = self.root / "evidence/private/param-low/capture-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        journal_path = self.root / "evidence/private/param-low/capture-journal.json"
        journal = json.loads(journal_path.read_text())
        for obj in (public["capture"], metadata["capture"]):
            for key in ("sha256", "full_sha256", "device_sha256_before", "device_sha256_after"):
                obj[key] = finalizer.PARAM_LOW_SHA256
        journal["retained_sha256"] = finalizer.PARAM_LOW_SHA256
        self._write(self.param_capture, public)
        self._write(metadata_path, metadata)
        self._write(journal_path, journal)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_param_capture(self.param_capture, self.root)

        self._refresh_param_contract()
        public = json.loads(self.param_capture.read_text())
        public["capture"]["device_sha256_after"] = "0" * 64
        self._write(self.param_capture, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_param_capture(self.param_capture, self.root)

    def test_read_flash_completion_must_follow_control_even_after_hash_refresh(self) -> None:
        flash_path = self.root / "evidence/private" / finalizer.FLASH_JOURNAL_NAMES["read"]
        flash = json.loads(flash_path.read_text())
        flash["completed_utc"] = "2026-08-27T00:00:00+00:00"
        flash_bytes = self._write(flash_path, flash)
        raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        raw = json.loads(raw_path.read_text())
        raw["flash_journal"].update({
            "sha256": finalizer.hashlib.sha256(flash_bytes).hexdigest(),
            "size": len(flash_bytes),
        })
        raw_bytes = self._write(raw_path, raw)
        journal_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        journal = json.loads(journal_path.read_text())
        journal["flash_journal"] = dict(raw["flash_journal"])
        journal_bytes = self._write(journal_path, journal)
        manifest = json.loads(self.read_manifest.read_text())
        manifest.update({
            "flash_journal_sha256": finalizer.hashlib.sha256(flash_bytes).hexdigest(),
            "flash_journal_size": len(flash_bytes),
            "raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(),
            "raw_snapshot_size": len(raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(),
            "journal_size": len(journal_bytes),
        })
        self._write(self.read_manifest, manifest)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(
                self.read_manifest,
                self.root,
                finalizer.validate_control(self.control_manifest, self.root),
            )

    def test_normal_rollback_serial_and_staging_pins_are_exact(self) -> None:
        valid = json.loads(self.rollback_flash.read_text())
        for field, bad in (
            ("target_serial_sha256", "0" * 64),
            ("post_staging_target_serial_sha256", "1" * 64),
            ("pre_effect_target_serial_sha256", "2" * 64),
            ("post_dispatch_target_serial_sha256", "3" * 64),
            ("final_target_serial_sha256", "4" * 64),
            ("post_dispatch_staging_sha256", "5" * 64),
            ("post_dispatch_staging_size", 1),
            ("final_rebind_serial_sha256", "6" * 64),
        ):
            with self.subTest(field=field):
                rollback = json.loads(json.dumps(valid))
                rollback[field] = bad
                self._write(self.rollback_flash, rollback)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_rollback_flash(self.rollback_flash, self.root)

        rollback = json.loads(json.dumps(valid))
        rollback["predecessor_sha256"] = finalizer.CONTROL_SHA256
        self._write(self.rollback_flash, rollback)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_rollback_flash(self.rollback_flash, self.root)

        for bad_allowed in (
            list(reversed(finalizer.ROLLBACK_ALLOWED_PREDECESSORS)),
            [finalizer.READ_SHA256, finalizer.ROLLBACK_SHA256],
        ):
            with self.subTest(allowed_predecessors=bad_allowed):
                rollback = json.loads(json.dumps(valid))
                rollback["allowed_predecessors"] = bad_allowed
                self._write(self.rollback_flash, rollback)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_rollback_flash(self.rollback_flash, self.root)

        for label, mutate in (
            (
                "post_staging_predecessor",
                lambda item: item.update(
                    {"post_staging_predecessor_sha256": finalizer.CONTROL_SHA256}
                ),
            ),
            (
                "post_dispatch_predecessor",
                lambda item: item.update(
                    {"post_dispatch_predecessor_sha256": finalizer.CONTROL_SHA256}
                ),
            ),
            (
                "guard_current_predecessor",
                lambda item: item["guarded_effect_receipt"]["guard"].update(
                    {"current_sha256": finalizer.CONTROL_SHA256}
                ),
            ),
        ):
            with self.subTest(label=label):
                rollback = json.loads(json.dumps(valid))
                mutate(rollback)
                self._write(self.rollback_flash, rollback)
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer.validate_rollback_flash(self.rollback_flash, self.root)

    def test_last_kmsg_metadata_completion_and_signature_are_bound(self) -> None:
        metadata_path = self.root / "evidence/private/last-kmsg-final.private.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["completed_utc"] = "2026-08-27T00:02:01+00:00"
        self._write(metadata_path, metadata)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(self.last_kmsg, self.root)

        # Restore the valid metadata and mutate only its copied signature.
        self._write(
            metadata_path,
            {
                **metadata,
                "completed_utc": "2026-08-27T00:02:00+00:00",
                "exact_reset_signature": {
                    **metadata["exact_reset_signature"],
                    "a90r_count": 1,
                },
            },
        )
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(self.last_kmsg, self.root)

    def test_last_kmsg_cannot_join_an_unrelated_or_stale_read_source(self) -> None:
        manifest = json.loads(self.last_kmsg.read_text())
        manifest["read_source"]["raw_sha256"] = "0" * 64
        self.last_kmsg.write_bytes(
            json.dumps(manifest, ensure_ascii=True, sort_keys=False).encode() + b"\n"
        )
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_last_kmsg(self.last_kmsg, self.root)

    def test_hashed_forged_read_journal_cannot_become_potential(self) -> None:
        journal_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        journal = json.loads(journal_path.read_text())
        journal["value"] = "0x0000000000001234"
        journal_bytes = self._write(journal_path, journal)
        manifest = json.loads(self.read_manifest.read_text())
        manifest["journal_sha256"] = finalizer.hashlib.sha256(journal_bytes).hexdigest()
        manifest["journal_size"] = len(journal_bytes)
        self._write(self.read_manifest, manifest)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(
                self.read_manifest,
                self.root,
                finalizer.validate_control(self.control_manifest, self.root),
            )

    def test_map_failure_return_is_not_promoted_to_potential(self) -> None:
        raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        raw = json.loads(raw_path.read_text())
        raw["value"] = "0xffffffffffffffff"
        raw["fixed_op_measurement"] = {"op": 4, "args": [], "rc": 0, "status": "ok", "value": "0xffffffffffffffff"}
        raw["outcome"] = "MAP_FAILED"
        raw["effect_ambiguous"] = False
        raw["panic_on_oops_restored"] = True
        raw["panic_restore_deferred"] = False
        raw_bytes = self._write(raw_path, raw)
        journal_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        journal = json.loads(journal_path.read_text())
        journal.update({"status": "EFFECT_RETURNED", "outcome": "MAP_FAILED", "effect_ambiguous": False, "value": "0xffffffffffffffff", "panic_on_oops_restored": True, "effect_dispatched": True})
        journal_bytes = self._write(journal_path, journal)
        manifest = json.loads(self.read_manifest.read_text())
        manifest.update({
            "returned_value_present": True,
            "returned_value_sha256": finalizer.hashlib.sha256(b"0xffffffffffffffff").hexdigest(),
            "outcome": "MAP_FAILED",
            "effect_ambiguous": False,
            "panic_on_oops_restored": True,
            "panic_restore_deferred": False,
            "raw_snapshot_sha256": finalizer.hashlib.sha256(raw_bytes).hexdigest(),
            "raw_snapshot_size": len(raw_bytes),
            "journal_sha256": finalizer.hashlib.sha256(journal_bytes).hexdigest(),
            "journal_size": len(journal_bytes),
        })
        self._write(self.read_manifest, manifest)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_read(self.read_manifest, self.root, finalizer.validate_control(self.control_manifest, self.root))

    def test_torn_rollback_requires_private_public_and_source_bindings(self) -> None:
        source = {
            "schema": "sdm855-a90-remapper-boot-flash-private-v1",
            "status": "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED",
            "profile": "rollback",
            "target_model": finalizer.TARGET_MODEL,
            "target_device": finalizer.TARGET_DEVICE,
            "target_serial_sha256": finalizer.TARGET_SERIAL_SHA256,
            "boot_alias": "/dev/block/by-name/boot",
            "boot_node": "/dev/block/sda24",
            "image_sha256": finalizer.ROLLBACK_SHA256,
            "image_size": finalizer.BOOT_PREFIX_SIZE,
            "allowed_predecessors": list(finalizer.ROLLBACK_ALLOWED_PREDECESSORS),
            "effect_armed": True,
            "effect_dispatched": True,
            "effect_ambiguous": True,
            "effect_replayed": False,
            "automatic_retries": False,
            "partition_writes": True,
            "staging_attempted": True,
            "staging_attempt_count": 1,
            "staging_dispatch_count": 1,
            "staging_status": "STAGING_PUSH_RETURNED",
            "pre_staging_removed": True,
            "pre_cleanup_revalidated": True,
            "pre_push_revalidated": True,
            "staging_removed": False,
            "post_staging_revalidated": True,
            "post_staging_predecessor_revalidated": True,
            "pre_effect_revalidated": True,
            "reboot_dispatched": False,
            "write_count": 1,
            "remote_staging": "/tmp/sdm855-remapper-boot-rollback.img",
            "remote_staging_sha256": finalizer.ROLLBACK_SHA256,
            "remote_staging_size": finalizer.BOOT_PREFIX_SIZE,
            "post_staging_predecessor_sha256": finalizer.READ_SHA256,
            "post_staging_predecessor_size": finalizer.BOOT_PREFIX_SIZE,
            "post_staging_predecessor_revalidated": True,
            "effect_argv": ["dd", "if=/tmp/sdm855-remapper-boot-rollback.img", "of=/dev/block/sda24", "bs=4096", "count=14864", "conv=fsync"],
            "current_state": "UNKNOWN",
            "staging_cleanup_deferred": True,
            "reconcile_required": True,
            "predecessor_sha256": finalizer.READ_SHA256,
            "predecessor_size": finalizer.BOOT_PREFIX_SIZE,
        }
        source_path = self.root / "evidence/private/verification-024-remapper-boot-flash-rollback.journal.json"
        source_bytes = self._write(source_path, source)
        torn_id = "torn-final"
        for bad_allowed in (
            list(reversed(finalizer.ROLLBACK_ALLOWED_PREDECESSORS)),
            [finalizer.READ_SHA256, finalizer.ROLLBACK_SHA256],
        ):
            bad_source = json.loads(json.dumps(source))
            bad_source["allowed_predecessors"] = bad_allowed
            with self.subTest(torn_allowed_predecessors=bad_allowed):
                with self.assertRaises(finalizer.FinalizeError):
                    finalizer._validate_ambiguous_source(
                        bad_source,
                        "torn source predecessor matrix",
                        source_path=source_path,
                        root=self.root,
                    )
        source_contract = finalizer._validate_ambiguous_source(
            source, "torn source", source_path=source_path, root=self.root
        )
        semantic_sha256 = source_contract["semantic_sha256"]
        semantic_identity = source_contract["semantic_identity"]
        claim_path = self.root / "evidence/private" / f"verification-024-remapper-source-consumed-{semantic_sha256}.claim.json"
        source_stat = source_path.stat()
        source_identity = {
            "st_dev": source_stat.st_dev,
            "st_ino": source_stat.st_ino,
            "st_mode": source_stat.st_mode,
            "st_size": source_stat.st_size,
            "st_mtime_ns": source_stat.st_mtime_ns,
            "st_ctime_ns": source_stat.st_ctime_ns,
            "sha256": finalizer.hashlib.sha256(source_bytes).hexdigest(),
        }
        claim = {
            "schema": "sdm855-a90-remapper-source-consumption-claim-v1",
            "source_journal_path": str(source_path),
            "source_journal_sha256": finalizer.hashlib.sha256(source_bytes).hexdigest(),
            "source_semantic_sha256": semantic_sha256,
            "key_sha256": semantic_sha256,
            "source_semantic_identity": semantic_identity,
            "source_profile": "rollback",
            "source_journal_size": len(source_bytes),
            "source_journal_identity": source_identity,
            "consumed_by_experiment_id": torn_id,
            "terminal": "before_recovery_effect_marker",
            "claim_phase": "before_staging_cleanup",
            "effect_replayed": False,
            "created_utc": "2026-08-27T00:04:00+00:00",
        }
        claim_bytes = self._write(claim_path, claim)
        current_pre_hash = "e" * 64
        physical_identity, physical_key = finalizer.boot_prefix_claim_identity(
            current_pre_hash, finalizer.BOOT_PREFIX_SIZE
        )
        physical_path = finalizer.boot_prefix_claim_path(self.root, physical_key)
        physical_claim = {
            "schema": "sdm855-a90-v024-boot-prefix-physical-claim-v1",
            "claim_key_sha256": physical_key,
            "claim_identity": physical_identity,
            "claimed_by_experiment_id": torn_id,
            "provenance": {
                "owner_kind": "torn-rollback-recovery",
                "terminal": "before_recovery_effect_marker",
            },
            "effect_replayed": False,
            "claim_status": "COMPLETE",
            "created_utc": "2026-08-27T00:04:00+00:00",
        }
        physical_claim_bytes = self._write(physical_path, physical_claim)
        torn = {
            "schema": "sdm855-a90-boot-torn-rollback-recovery-private-v1",
            "experiment_id": torn_id,
            "status": "PASS_ROLLBACK_READBACK_AND_CLEANUP",
            "completed_utc": "2026-08-27T00:04:30+00:00",
            "target_verified": True,
            "target": {"model": finalizer.TARGET_MODEL, "device": finalizer.TARGET_DEVICE, "twrp_version": "3.7.0_12-0", "serial_sha256": finalizer.TARGET_SERIAL_SHA256},
            "rollback_image_sha256": finalizer.ROLLBACK_SHA256,
            "rollback_image_size": finalizer.BOOT_PREFIX_SIZE,
            "boot_alias": "/dev/block/by-name/boot",
            "boot_node": "/dev/block/sda24",
            "cleanup_proved": True,
            "cleanup_error": None,
            "effect_replayed": False,
            "partition_writes": True,
            "write_count": 1,
            "effect_armed": True,
            "effect_dispatched": True,
            "readback_sha256": finalizer.ROLLBACK_SHA256,
            "readback_size": finalizer.BOOT_PREFIX_SIZE,
            "source_flash_journal_path": str(source_path),
            "source_flash_journal_sha256": finalizer.hashlib.sha256(source_bytes).hexdigest(),
            "source_flash_journal_size": len(source_bytes),
            "source_flash_journal_identity": source_identity,
            "source_semantic_sha256": semantic_sha256,
            "source_consumption_claim_key_sha256": semantic_sha256,
            "source_semantic_identity": semantic_identity,
            "source_profile": "rollback",
            "source_consumption_claim_path": str(claim_path),
            "source_consumption_claimed": True,
            "source_consumption_claim_attempted": True,
            "source_consumption_claim_sha256": finalizer.hashlib.sha256(claim_bytes).hexdigest(),
            "source_consumption_claim_size": len(claim_bytes),
            "source_consumption_claim_terminal": "before_recovery_effect_marker",
            "source_consumption_claim_phase": "before_staging_cleanup",
            "current_pre_hash_sha256": current_pre_hash,
            "current_pre_hash_size": finalizer.BOOT_PREFIX_SIZE,
            "physical_effect_claim": {
                "attempted": True,
                "claimed": True,
                "key_sha256": physical_key,
                "claim_path": str(physical_path),
                "claim_sha256": finalizer.hashlib.sha256(physical_claim_bytes).hexdigest(),
                "claim_size": len(physical_claim_bytes),
                "terminal": "before_recovery_effect_marker",
            },
        }
        torn_path = self.root / "evidence/private" / f"verification-024-boot-torn-rollback-{torn_id}.journal.json"
        torn_bytes = self._write(torn_path, torn)
        self._write(self.root / "evidence/manifests" / f"verification-024-boot-torn-rollback-{torn_id}.manifest.json", {
            "schema": "sdm855-a90-boot-torn-rollback-recovery-public-v1",
            "experiment_id": torn_id,
            "status": torn["status"],
            "completed_utc": "2026-08-27T00:04:30.100000+00:00",
            "target_verified": True,
            "target_evaluation": "VERIFIED",
            "target": {
                "model": finalizer.TARGET_MODEL,
                "device": finalizer.TARGET_DEVICE,
                "twrp_version": "3.7.0_12-0",
                "serial_sha256": finalizer.TARGET_SERIAL_SHA256,
                "status": "VERIFIED",
            },
            "expected_target": {
                "model": finalizer.TARGET_MODEL,
                "device": finalizer.TARGET_DEVICE,
                "twrp_version": "3.7.0_12-0",
                "serial_sha256": finalizer.TARGET_SERIAL_SHA256,
                "boot_alias": "/dev/block/by-name/boot",
                "boot_node": "/dev/block/sda24",
            },
            "effect": {
                "command": "fixed boot-prefix rollback dd",
                "transport": finalizer.ROLLBACK_ADB,
                "write_count": 1,
                "effect_replayed": False,
                "partition": "/dev/block/sda24",
            },
            "source_flash_journal_sha256": torn["source_flash_journal_sha256"],
            "source_flash_journal_size": torn["source_flash_journal_size"],
            "source_consumption": {"claimed": True, "attempted": True, "claim_sha256": torn["source_consumption_claim_sha256"], "claim_size": torn["source_consumption_claim_size"], "key_sha256": semantic_sha256, "source_journal_sha256": torn["source_flash_journal_sha256"], "source_journal_size": torn["source_flash_journal_size"], "source_profile": "rollback"},
            "rollback_sha256": finalizer.ROLLBACK_SHA256,
            "rollback_size": finalizer.BOOT_PREFIX_SIZE,
            "current_pre_hash_sha256": current_pre_hash,
            "current_pre_hash_size": finalizer.BOOT_PREFIX_SIZE,
            "partition_writes": 1,
            "physical_effect_claim": {"claimed": True, "attempted": True, "key_sha256": physical_key, "claim_sha256": finalizer.hashlib.sha256(physical_claim_bytes).hexdigest(), "claim_size": len(physical_claim_bytes)},
            "cleanup_proved": True,
            "private_receipt_sha256": finalizer.hashlib.sha256(torn_bytes).hexdigest(),
            "private_receipt_size": len(torn_bytes),
        })
        # The recovery continuation owns one pre-registered internal ID and
        # one fixed public counterpart.  Re-labeling the receipt in place
        # must not create a second accepted torn namespace.
        renamed = json.loads(json.dumps(torn))
        renamed["experiment_id"] = "torn-final-alt"
        renamed_bytes = self._write(torn_path, renamed)
        renamed_public_path = (
            self.root
            / "evidence/manifests"
            / f"verification-024-boot-torn-rollback-{torn_id}.manifest.json"
        )
        renamed_public = json.loads(renamed_public_path.read_text())
        renamed_public["private_receipt_sha256"] = finalizer.hashlib.sha256(
            renamed_bytes
        ).hexdigest()
        renamed_public["private_receipt_size"] = len(renamed_bytes)
        self._write(renamed_public_path, renamed_public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_rollback_flash(torn_path, self.root)
        # Restore the truthful producer pair before the remaining continuation
        # and claim-splice adversarial cases.
        torn_bytes = self._write(torn_path, torn)
        restored_public = json.loads(renamed_public_path.read_text())
        restored_public["experiment_id"] = torn_id
        restored_public["private_receipt_sha256"] = finalizer.hashlib.sha256(
            torn_bytes
        ).hexdigest()
        restored_public["private_receipt_size"] = len(torn_bytes)
        self._write(renamed_public_path, restored_public)
        receipt = finalizer.validate_rollback_flash(torn_path, self.root)
        self.assertTrue(receipt["rescue_terminal"])
        continued_forgery = json.loads(torn_path.read_text())
        continued_forgery["physical_effect_claim"][
            "continued_from_normal_ambiguous"
        ] = True
        continued_bytes = self._write(torn_path, continued_forgery)
        public_path = self.root / "evidence/manifests" / f"verification-024-boot-torn-rollback-{torn_id}.manifest.json"
        public = json.loads(public_path.read_text())
        public["private_receipt_sha256"] = finalizer.hashlib.sha256(continued_bytes).hexdigest()
        public["private_receipt_size"] = len(continued_bytes)
        self._write(public_path, public)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_rollback_flash(torn_path, self.root)
        claim_mutated = dict(claim)
        claim_mutated["source_semantic_sha256"] = "0" * 64
        self._write(claim_path, claim_mutated)
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_rollback_flash(torn_path, self.root)
        bad_predecessor = dict(source)
        bad_predecessor["predecessor_sha256"] = finalizer.CONTROL_SHA256
        with self.assertRaises(finalizer.FinalizeError):
            finalizer._validate_ambiguous_source(bad_predecessor, "torn predecessor")
        source_path.write_bytes(source_bytes.replace(b'"current_state":"UNKNOWN"', b'"current_state":"changed"'))
        with self.assertRaises(finalizer.FinalizeError):
            finalizer.validate_rollback_flash(torn_path, self.root)

    def test_chronology_is_strict_and_not_receipt_order_only(self) -> None:
        # Make the read receipt complete after its later reset receipt while
        # keeping all individual receipts otherwise valid.
        read = json.loads(self.read_manifest.read_text())
        read["completed_utc"] = "2026-08-27T00:03:00+00:00"
        read_raw_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.json"
        read_raw_obj = json.loads(read_raw_path.read_text())
        read_raw_obj["completed_utc"] = "2026-08-27T00:03:00+00:00"
        read_bytes = self._write(read_raw_path, read_raw_obj)
        read_journal_path = self.root / f"evidence/private/{finalizer.READ_SOURCE_EXPERIMENT_ID}.journal.json"
        read_journal = json.loads(read_journal_path.read_text())
        read_journal["completed_utc"] = "2026-08-27T00:03:00+00:00"
        read_journal_bytes = self._write(read_journal_path, read_journal)
        read["raw_snapshot_sha256"] = finalizer.hashlib.sha256(read_bytes).hexdigest()
        read["raw_snapshot_size"] = len(read_bytes)
        read["journal_sha256"] = finalizer.hashlib.sha256(read_journal_bytes).hexdigest()
        read["journal_size"] = len(read_journal_bytes)
        self._write(self.read_manifest, read)
        # Keep the causal last-kmsg source join valid so the test reaches the
        # chronology gate rather than failing early on a stale source hash.
        source_summary = {
            "experiment_id": finalizer.READ_SOURCE_EXPERIMENT_ID,
            "manifest_sha256": finalizer.hashlib.sha256(self.read_manifest.read_bytes()).hexdigest(),
            "manifest_size": self.read_manifest.stat().st_size,
            "raw_sha256": finalizer.hashlib.sha256(read_bytes).hexdigest(),
            "raw_size": len(read_bytes),
            "journal_sha256": finalizer.hashlib.sha256(read_journal_bytes).hexdigest(),
            "journal_size": len(read_journal_bytes),
            "completed_utc": read["completed_utc"],
            "source_pre_read_boot_id_sha256": read["boot_id_before_read_sha256"],
        }
        last_public = json.loads(self.last_kmsg.read_text())
        last_public["read_source"] = source_summary
        self.last_kmsg.write_bytes(
            json.dumps(last_public, ensure_ascii=True, sort_keys=False).encode() + b"\n"
        )
        last_metadata_path = self.root / "evidence/private/last-kmsg-final.private.json"
        last_metadata = json.loads(last_metadata_path.read_text())
        last_metadata["read_source"] = {
            **source_summary,
            "source_pre_read_boot_id": "11111111-1111-4111-8111-111111111111",
        }
        self._write(last_metadata_path, last_metadata)
        last_journal_path = self.root / "evidence/private/last-kmsg-final.journal.json"
        last_journal = json.loads(last_journal_path.read_text())
        last_journal["read_source"] = {
            **source_summary,
            "source_pre_read_boot_id": "11111111-1111-4111-8111-111111111111",
        }
        self._write(last_journal_path, last_journal)
        args = self._args()
        _, public = finalizer.finalize(args)
        result = json.loads(public.read_text())
        self.assertEqual(result["classification"], "INCIDENT")
        self.assertIn("chronology", result["gate_failures"])

    def test_atomic_publication_stages_and_preserves_pair_recovery(self) -> None:
        private = self.root / "evidence/private/atomic.json"
        public = self.root / "evidence/manifests/atomic.json"
        finalizer._write_new(private, b"private", 0o600)
        self.assertEqual(private.read_bytes(), b"private")
        self.assertFalse(private.with_name("atomic.json.tmp").exists())

        def fail_second_link(source, target, *, follow_symlinks=True):
            if target == public:
                # Simulate a second owner winning between the pair's
                # precheck and its no-replace publication.
                public.write_bytes(b"first-owner")
            return original_link(source, target, follow_symlinks=follow_symlinks)

        original_link = finalizer.os.link
        with mock.patch.object(finalizer.os, "link", side_effect=fail_second_link):
            with self.assertRaises(finalizer.FinalizeError):
                finalizer._write_pair(
                    self.root / "evidence/private/pair.json",
                    b"private-pair",
                    public,
                    b"public-pair",
                )
        self.assertTrue((self.root / "evidence/private/pair.json").exists())
        self.assertTrue(public.with_name("atomic.json.tmp").exists())
        self.assertEqual(public.read_bytes(), b"first-owner")

    def test_atomic_publication_first_final_collision_preserves_winner_and_temp(self) -> None:
        path = self.root / "evidence/private/race.json"
        original_link = finalizer.os.link

        def race_link(source, target, *, follow_symlinks=True):
            if target == path and not target.exists():
                target.write_bytes(b"first-owner")
            return original_link(source, target, follow_symlinks=follow_symlinks)

        with mock.patch.object(finalizer.os, "link", side_effect=race_link):
            with self.assertRaises(finalizer.FinalizeError):
                finalizer._write_new(path, b"second-owner", 0o600)
        self.assertEqual(path.read_bytes(), b"first-owner")
        self.assertTrue(path.with_name("race.json.tmp").exists())

    def test_atomic_publication_two_owners_one_final_and_recoverable_temp(self) -> None:
        final = self.root / "evidence/private/two-owner.json"
        first_temp = final.with_name("two-owner.first.tmp")
        second_temp = final.with_name("two-owner.second.tmp")
        first_temp.write_bytes(b"first-owner")
        second_temp.write_bytes(b"second-owner")
        barrier = threading.Barrier(2)
        original_link = finalizer.os.link
        outcomes: list[str] = []

        def gated_link(source, target, *, follow_symlinks=True):
            if target == final:
                barrier.wait()
            return original_link(source, target, follow_symlinks=follow_symlinks)

        def owner(temp: Path) -> None:
            try:
                finalizer._publish_temp_noreplace(temp, final)
            except finalizer.FinalizeError:
                outcomes.append("lost")
            else:
                outcomes.append("won")

        threads = [threading.Thread(target=owner, args=(item,)) for item in (first_temp, second_temp)]
        with mock.patch.object(finalizer.os, "link", side_effect=gated_link):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(sorted(outcomes), ["lost", "won"])
        self.assertIn(final.read_bytes(), {b"first-owner", b"second-owner"})
        remaining = [item for item in (first_temp, second_temp) if item.exists()]
        self.assertEqual(len(remaining), 1)

    def test_atomic_publication_rejects_interposed_temp_regular_file(self) -> None:
        path = self.root / "evidence/private/substituted-file.json"
        temporary = path.with_name(path.name + ".tmp")
        original_link = finalizer.os.link

        def interpose(source, target, *, follow_symlinks=True):
            self.assertEqual(Path(source), temporary)
            temporary.unlink()
            temporary.write_bytes(b"attacker")
            return original_link(source, target, follow_symlinks=follow_symlinks)

        with mock.patch.object(finalizer.os, "link", side_effect=interpose):
            with self.assertRaises(finalizer.FinalizeError):
                finalizer._write_new(path, b"owner", 0o600)
        # The hostile link hook may have created an attacker-owned final
        # inode, but the publisher must raise and never report it as success.
        self.assertEqual(path.read_bytes(), b"attacker")
        self.assertTrue(temporary.exists())
        self.assertEqual(temporary.read_bytes(), b"attacker")

    def test_atomic_publication_rejects_interposed_temp_symlink(self) -> None:
        path = self.root / "evidence/private/substituted-link.json"
        temporary = path.with_name(path.name + ".tmp")
        original_link = finalizer.os.link

        def interpose(source, target, *, follow_symlinks=True):
            self.assertEqual(Path(source), temporary)
            temporary.unlink()
            temporary.symlink_to(path)
            return original_link(source, target, follow_symlinks=follow_symlinks)

        with mock.patch.object(finalizer.os, "link", side_effect=interpose):
            with self.assertRaises(finalizer.FinalizeError):
                finalizer._write_new(path, b"owner", 0o600)
        self.assertFalse(path.exists())
        self.assertTrue(temporary.is_symlink())

    def test_atomic_publication_rejects_same_size_in_place_temp_overwrite(self) -> None:
        path = self.root / "evidence/private/same-size-overwrite.json"
        temporary = path.with_name(path.name + ".tmp")
        original_link = finalizer.os.link

        def interpose(source, target, *, follow_symlinks=True):
            self.assertEqual(Path(source), temporary)
            with temporary.open("r+b") as staged:
                staged.seek(0)
                staged.write(b"FAKE!")
                staged.flush()
            return original_link(source, target, follow_symlinks=follow_symlinks)

        with mock.patch.object(finalizer.os, "link", side_effect=interpose):
            with self.assertRaises(finalizer.FinalizeError):
                finalizer._write_new(path, b"owner", 0o600)
        self.assertEqual(path.read_bytes(), b"FAKE!")
        self.assertEqual(temporary.read_bytes(), b"FAKE!")

    def test_short_write_leaves_only_recoverable_temp(self) -> None:
        private = self.root / "evidence/private/short.json"
        with mock.patch.object(finalizer.os, "write", return_value=0):
            with self.assertRaises(finalizer.FinalizeError):
                finalizer._write_new(private, b"x", 0o600)
        self.assertFalse(private.exists())
        self.assertTrue(private.with_name("short.json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
