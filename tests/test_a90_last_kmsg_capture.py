from __future__ import annotations

import base64
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tools import a90_inline_remapper_mid_probe as probe
from tools import a90_last_kmsg_capture as capture


class FakeFrame:
    def __init__(
        self,
        payload: bytes,
        command: str,
        *,
        rc: int = 0,
        status: str = "ok",
    ) -> None:
        argc = {
            "run": 5,
            "stophud": 1,
            "writefile": 3,
            "selftest": 2,
            "stat": 2,
        }.get(command, 2 if command == "cat" else 1)
        protocol_flags = capture._protocol_flags_for_argv((command,))
        if protocol_flags is None:
            raise AssertionError(f"test command has no native flag contract: {command}")
        errno = str(-rc if rc < 0 else 0)
        self.payload = payload
        if rc == 0 and status == "ok":
            terminal = f"[done] {command} (0ms)\n".encode("ascii")
        elif rc == -16 and status == "busy":
            terminal = b"[busy] auto menu active; send hide/q before command\n"
        elif rc < 0:
            message = probe._PROTOCOL_ERRNO_MESSAGES.get(-rc)
            if message is None:
                raise AssertionError(f"test errno has no native message: {-rc}")
            terminal = (
                f"[err] {command} rc={rc} errno={errno} ("
                + message.decode("ascii")
                + ") (0ms)\n"
            ).encode("ascii")
        else:
            terminal = f"[err] {command} rc={rc} (0ms)\n".encode("ascii")
        self.transcript = (
            f"A90P1 BEGIN seq=1 cmd={command} argc={argc} flags={protocol_flags}\n".encode()
            + payload
            + b"\n"
            + terminal
            + f"A90P1 END seq=1 cmd={command} rc={rc} errno={errno} duration_ms=0 flags={protocol_flags} status={status}\n".encode()
        )
        self.begin = {"seq": "1", "cmd": command, "argc": str(argc), "flags": protocol_flags}
        self.end = {
            "seq": "1",
            "cmd": command,
            "rc": str(rc),
            "errno": errno,
            "duration_ms": "0",
            "flags": protocol_flags,
            "status": status,
        }


def _version() -> bytes:
    return (
        b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\r\n"
        b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\r\n"
        b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\r\n"
        b"made by device owner\r\n"
        b"display: 1080x2400 connector=28 crtc=133 fb=208"
    )


def _cmdline() -> bytes:
    return (
        b"androidboot.em.model=SM-A908N "
        b"androidboot.bootloader=A908NKSU5EWA3 "
        b"androidboot.debug_level=0x494d "
        b"androidboot.force_upload=0x0 "
        b"sec_debug.dump_sink=0x0\n"
    )


def _exact_log(
    *,
    order: tuple[str, ...] = (
        "bark",
        "last_pet",
        "debug_level",
        "upload_cause",
        "collect_upload",
        "tz_reason",
    ),
    debug: str = "1145654596",
    bark: str = "69.080467",
    last_pet: str = "58.080193",
    a90r: bytes = b"",
) -> bytes:
    lines = {
        "bark": f"Watchdog bark! Now = {bark}\n".encode(),
        "last_pet": f"Watchdog last pet at {last_pet}\n".encode(),
        "debug_level": f"DebugLevel : {debug}, ForceUploadFlag : 0\n".encode(),
        "upload_cause": b"UploadCause[Non Secure Watchdog Bark], Don't check hangcnt\n",
        "collect_upload": b"collect_rr_data : upload_cause = Non Secure Watchdog Bark\n",
        "tz_reason": b"collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT\n",
    }
    return b"".join(lines[name] for name in order) + a90r


def _prefixed_exact_log() -> bytes:
    """A retained-source shape with the exact printk/TZ line prefixes."""

    return (
        b"<6>[   69.080719] I[0:      swapper/0:    0] msm_watchdog 17c10000.qcom,wdt: Watchdog bark! Now = 69.080467\n"
        b"<6>[   69.080732] I[0:      swapper/0:    0] msm_watchdog 17c10000.qcom,wdt: Watchdog last pet at 58.080193\n"
        b"{441213} DebugLevel : 1145654596, ForceUploadFlag : 0\n"
        b"{4926024} UploadCause[Non Secure Watchdog Bark], Don't check hangcnt\n"
        b"{5184512} collect_rr_data : upload_cause = Non Secure Watchdog Bark\n"
        b"{5184573} collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT\n"
    )


class A90LastKmsgCaptureTests(unittest.TestCase):
    def _write_read_source(self, root: Path) -> None:
        """Install a complete fixed no-value source receipt for the collector."""

        private = root / "evidence/private"
        manifests = root / "evidence/manifests"
        private.mkdir(parents=True, exist_ok=True)
        manifests.mkdir(parents=True, exist_ok=True)
        source_id = capture.READ_SOURCE_EXPERIMENT_ID
        completed = "2026-08-27T00:00:00+00:00"
        boot_id = "11111111-1111-4111-8111-111111111111"
        boot_hash = capture.sha256(boot_id.encode())
        attestation = {
            "sysfs_root": "/sys/class/block/sda24",
            "block_node": "/dev/block/sda24",
            "bs": 4096,
            "count": 14864,
            "expected_size": capture.BOOT_PREFIX_SIZE,
            "captured_size": capture.BOOT_PREFIX_SIZE,
            "expected_sha256": capture.READ_CANDIDATE_SHA256,
            "captured_sha256": capture.READ_CANDIDATE_SHA256,
            "sectors": 131072,
            "ro": 0,
            "hash_matches_candidate": True,
            "size_matches_candidate": True,
            "cleanup_ok": True,
            "cleanup_error": None,
            "stat": dict(capture.BOOT_ATTEST_STAT),
        }
        attestation_private = {
            **attestation,
            "attest_node": capture.BOOT_ATTEST_NODE,
            "attest_file": capture.BOOT_ATTEST_FILE,
        }

        def frame(evidence_id: str, argv: tuple[str, ...], payload: bytes) -> dict[str, object]:
            protocol_flags = capture._protocol_flags_for_argv(argv)
            if protocol_flags is None:
                raise AssertionError(f"test command has no native flag contract: {argv}")
            begin = {"cmd": argv[0], "seq": "1", "argc": str(len(argv)), "flags": protocol_flags}
            end = {"cmd": argv[0], "seq": "1", "rc": "0", "errno": "0", "duration_ms": "0", "flags": protocol_flags, "status": "ok"}
            transcript = (
                f"A90P1 BEGIN seq=1 cmd={argv[0]} argc={len(argv)} flags={protocol_flags}\n".encode("ascii")
                + payload
                + f"\n[done] {argv[0]} (0ms)\n".encode("ascii")
                + f"A90P1 END seq=1 cmd={argv[0]} errno=0 duration_ms=0 rc=0 flags={protocol_flags} status=ok\n".encode("ascii")
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
            "panic_set_0": b"",
            "panic_zero_verify": b"0\n",
        }
        semantic_payloads = {
            "version_before": _version(),
            "cmdline_before": _cmdline(),
            "soc_id_before": b"339\n",
            "selftest_before": b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12",
            "boot_id_before_read": boot_id.encode("ascii") + b"\n",
            "boot_sysfs_uevent": b"MAJOR=259\nMINOR=27\nDEVNAME=sda24\nDEVTYPE=partition\nPARTN=24\nPARTNAME=boot",
            "boot_sysfs_size": b"131072\n",
            "boot_sysfs_ro": b"0\n",
            "boot_attest_stat_node": b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\n",
            "boot_attest_mknod": b"",
        }
        toybox_empty = {
            "boot_attest_remove_node", "boot_attest_remove_file",
            "boot_attest_node_absent", "boot_attest_node_absent_not_symlink",
            "boot_attest_file_absent", "boot_attest_file_absent_not_symlink",
            "boot_attest_pre_node_absent", "boot_attest_pre_node_absent_not_symlink",
            "boot_attest_pre_file_absent", "boot_attest_pre_file_absent_not_symlink",
            "boot_attest_mkdir", "boot_attest_capture",
        }
        panic_frames = []
        for evidence_id in capture._source_expected_full_frame_ids(1):
            argv = capture._source_frame_argv(evidence_id)
            assert argv is not None
            payload = semantic_payloads.get(evidence_id, panic_payloads.get(evidence_id, b""))
            if evidence_id in toybox_empty:
                payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]"
            elif evidence_id == "boot_attest_hash":
                payload = (
                    b"run: pid=1, q/Ctrl-C cancels\n"
                    + f"{capture.READ_CANDIDATE_SHA256}  {capture.BOOT_ATTEST_FILE}\n[exit 0]".encode("ascii")
                )
            elif evidence_id == "boot_attest_size":
                payload = f"run: pid=1, q/Ctrl-C cancels\n{capture.BOOT_PREFIX_SIZE} {capture.BOOT_ATTEST_FILE}\n[exit 0]".encode("ascii")
            panic_frames.append(
                frame(evidence_id, argv, payload)
            )
        partial_transcript = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
        error = {
            "exception_type": "TransportFailure",
            "exception_text": "bridge closed before terminal frame",
            "evidence_id": "fixed_op_4",
            "argv": list(probe.fixed_op_argv()),
            "transport_no_value": True,
            "partial_evidence_present": True,
            "bounded": True,
            "a90r_present": False,
            "payload_base64": "",
            "payload_sha256": capture.sha256(b""),
            "payload_size": 0,
            "transcript_base64": base64.b64encode(partial_transcript).decode("ascii"),
            "transcript_sha256": capture.sha256(partial_transcript),
            "transcript_size": len(partial_transcript),
            "payload_bounded": True,
            "transcript_bounded": True,
            "begin": {"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
            "end": None,
        }
        control_binding = {
            "experiment_id": probe.CONTROL_EXPERIMENT_ID,
            "mode": "control",
            "manifest_sha256": "a" * 64,
            "manifest_size": 100,
            "raw_sha256": "b" * 64,
            "raw_size": 101,
            "journal_sha256": "c" * 64,
            "journal_size": 102,
            "completed_utc": "2026-08-26T23:59:00+00:00",
            "candidate_sha256": capture.CONTROL_CANDIDATE_SHA256,
            "candidate_size": capture.BOOT_PREFIX_SIZE,
            "value": "0x000000000000c071",
            "target_dmid": "SM-A908N/SM8150",
            "current_boot_attestation": {**attestation, "expected_sha256": capture.CONTROL_CANDIDATE_SHA256, "captured_sha256": capture.CONTROL_CANDIDATE_SHA256},
            "boot_id_before_read_sha256": boot_hash,
        "fixed_op_measurement": {"argv": list(probe.fixed_op_argv()), "op": 4, "args": [], "buffer_size": capture.FIXED_OP_BUFFER_SIZE, "buffer_sha256": capture._fixed_op_buffer_hash(), "magic": "0xa90c0de5deadbeef", "rc": 0, "status": "ok", "value": "0x000000000000c071", "a90r_record": "A90Rc071"},
        }
        transition = {"before": 1, "zero_write_attempted": True, "zero_set": True, "zero_verified": True, "restore_write_attempted": False, "restored": False, "restore_deferred": True, "proof_frame_ids": ["panic_before", "panic_set_0", "panic_zero_verify"]}
        fixed_op = {"op": 4, "args": [], "buffer_size": capture.FIXED_OP_BUFFER_SIZE, "buffer_sha256": capture._fixed_op_buffer_hash(), "rc": None, "status": None, "value": None}
        journal_fixed_op = {
            key: fixed_op[key]
            for key in ("op", "args", "buffer_size", "buffer_sha256")
        }
        flash_path = private / "verification-024-remapper-boot-flash-read.journal.json"
        flash_record = {
            "schema": "sdm855-a90-remapper-boot-flash-private-v1",
            "profile": "read",
            "image_sha256": capture.READ_CANDIDATE_SHA256,
            "image_size": capture.BOOT_PREFIX_SIZE,
            "remote_staging": "/tmp/sdm855-remapper-boot-read.img",
            "remote_staging_sha256": capture.READ_CANDIDATE_SHA256,
            "remote_staging_size": capture.BOOT_PREFIX_SIZE,
            "readback_sha256": capture.READ_CANDIDATE_SHA256,
            "readback_size": capture.BOOT_PREFIX_SIZE,
            "predecessor_size": capture.BOOT_PREFIX_SIZE,
            "post_staging_predecessor_sha256": capture.CONTROL_CANDIDATE_SHA256,
            "post_staging_predecessor_size": capture.BOOT_PREFIX_SIZE,
            "post_staging_predecessor_revalidated": True,
            "allowed_predecessors": [capture.CONTROL_CANDIDATE_SHA256],
            "write_count": 1,
            "effect_dispatched": True,
            "effect_armed": True,
            "effect_argv": ["dd", "if=/tmp/sdm855-remapper-boot-read.img", "of=/dev/block/sda24", "bs=4096", "count=14864", "conv=fsync"],
            "status": "PASS_READBACK_AND_CLEANUP",
            "staging_removed": True,
            "pre_staging_removed": True,
            "pre_cleanup_error": None,
            "cleanup_error": None,
            "error": None,
            "reboot_dispatched": False,
            "partition_writes": True,
            "staging_attempted": True,
            "staging_attempt_count": 1,
            "staging_dispatch_count": 1,
            "staging_status": "STAGING_PUSH_RETURNED",
            "target_model": "SM-A908N",
            "target_device": "r3q",
            "target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "boot_alias": "/dev/block/by-name/boot",
            "boot_node": "/dev/block/sda24",
            "post_staging_revalidated": True,
            "pre_cleanup_revalidated": True,
            "pre_push_revalidated": True,
            "pre_effect_revalidated": True,
            "post_dispatch_revalidated": True,
            "final_revalidated": True,
            "final_cleanup_revalidated": True,
            "post_dispatch_predecessor_sha256": capture.CONTROL_CANDIDATE_SHA256,
            "post_dispatch_predecessor_size": capture.BOOT_PREFIX_SIZE,
            "post_dispatch_staging_sha256": capture.READ_CANDIDATE_SHA256,
            "post_dispatch_staging_size": capture.BOOT_PREFIX_SIZE,
            "pre_cleanup_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "pre_push_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_staging_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "pre_effect_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_dispatch_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "final_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "final_cleanup_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_staging_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "pre_effect_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_dispatch_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "final_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "predecessor_sha256": capture.CONTROL_CANDIDATE_SHA256,
            "completed_utc": "2026-08-26T23:59:30+00:00",
            "guarded_effect_receipt": {
                "schema": "sdm855-a90-remapper-guarded-effect-v1",
                "guard": {
                    "current_sha256": capture.CONTROL_CANDIDATE_SHA256,
                    "current_size": str(capture.BOOT_PREFIX_SIZE),
                    "staging_sha256": capture.READ_CANDIDATE_SHA256,
                    "staging_size": str(capture.BOOT_PREFIX_SIZE),
                },
                "dd_result": {"rc": "0", "count": "14864"},
                "write_count": 1,
            },
        }
        flash_bytes = json.dumps(flash_record, sort_keys=True, separators=(",", ":")).encode()
        flash_path.write_bytes(flash_bytes)
        flash_binding = {"path": str(flash_path), "sha256": capture.sha256(flash_bytes), "size": len(flash_bytes), "profile": "read", "image_sha256": capture.READ_CANDIDATE_SHA256, "readback_sha256": capture.READ_CANDIDATE_SHA256, "predecessor_sha256": capture.CONTROL_CANDIDATE_SHA256}
        claim_path, claim_data, claim_key = probe._semantic_claim(root, "read", capture.READ_CANDIDATE_SHA256, capture.BOOT_PREFIX_SIZE, boot_id, source_id)
        claim_hash = capture.sha256(claim_data)
        claim_size = len(claim_data)
        raw = {
            "schema": "sdm855-a90-inline-remapper-mid-private-v1",
            "experiment_id": source_id,
            "mode": "read",
            "completed_utc": completed,
            "candidate_sha256": capture.READ_CANDIDATE_SHA256,
            "candidate_size": capture.BOOT_PREFIX_SIZE,
            "target": {"model": "SM-A908N", "soc": "SM8150", "soc_id": "339", "runtime_version": "0.9.285", "runtime_build": "v2321-usb-clean-identity-rodata", "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64", "bootloader": "A908NKSU5EWA3", "debug_level": "0x494d", "force_upload": "0", "dump_sink": "0", "selftest_before": {"passed": 11, "warn": 1, "fail": 0, "duration": 43, "entries": 12}},
            "flash_journal": flash_binding,
            "control_manifest": control_binding,
            "current_boot_attestation": attestation_private,
            "boot_id_before_read": boot_id,
            "boot_id_before_read_sha256": boot_hash,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "panic_transition": transition,
            "dispatch_count": 1,
            "dispatch_returned": False,
            "dispatch_failed": True,
            "effect_dispatched": True,
            "effect_ambiguous": True,
            "effect_replayed": False,
            "outcome": "REFUSED_AT_MID_CANDIDATE",
            "cleanup_ok": False,
            "health_after": {"ok": False, "skipped": True, "reason": "dispatch_exception_restore_deferred"},
            "error": error,
            "frames": panic_frames,
            "fixed_op_measurement": None,
            "semantic_claim_path": str(claim_path),
            "semantic_claim_sha256": claim_hash,
            "semantic_claim_size": claim_size,
            "semantic_claim_key_sha256": claim_key,
            "semantic_claimed": True,
        }
        raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        (private / f"{source_id}.json").write_bytes(raw_bytes)
        journal = {
            "schema": "sdm855-a90-inline-remapper-mid-journal-v1",
            "experiment_id": source_id,
            "mode": "read",
            "status": "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED",
            "candidate_sha256": capture.READ_CANDIDATE_SHA256,
            "candidate_size": capture.BOOT_PREFIX_SIZE,
            "op": 4,
            "op_args": [],
            "completed_utc": completed,
            "outcome": "REFUSED_AT_MID_CANDIDATE",
            "dispatch_count": 1,
            "dispatch_returned": False,
            "dispatch_failed": True,
            "effect_dispatched": True,
            "effect_ambiguous": True,
            "effect_replayed": False,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "panic_transition": transition,
            "target": raw["target"],
            "current_boot_attestation": attestation_private,
            "boot_id_before_read": boot_id,
            "boot_id_before_read_sha256": boot_hash,
            "fixed_op": journal_fixed_op,
            "flash_journal": flash_binding,
            "control_manifest": control_binding,
            "fixed_op_measurement": None,
            "error": error,
            "semantic_claim_path": str(claim_path),
            "semantic_claim_sha256": claim_hash,
            "semantic_claim_size": claim_size,
            "semantic_claim_key_sha256": claim_key,
            "semantic_claimed": True,
            "frames": panic_frames,
        }
        journal_bytes = json.dumps(journal, sort_keys=True, separators=(",", ":")).encode()
        (private / f"{source_id}.journal.json").write_bytes(journal_bytes)
        public = {
            "schema": "sdm855-a90-inline-remapper-mid-public-v1",
            "experiment_id": source_id,
            "mode": "read",
            "completed_utc": completed,
            "candidate_sha256": capture.READ_CANDIDATE_SHA256,
            "candidate_size": capture.BOOT_PREFIX_SIZE,
            "target_verified": True,
            "target_evaluation": "VERIFIED",
            "target_model": "SM-A908N",
            "soc": "SM8150",
            "runtime": "0.9.285",
            "outcome": "REFUSED_AT_MID_CANDIDATE",
            "dispatch_count": 1,
            "dispatch_returned": False,
            "dispatch_failed": True,
            "effect_dispatched": True,
            "effect_ambiguous": True,
            "effect_replayed": False,
            "automatic_retries": False,
            "returned_value_present": False,
            "returned_value_sha256": None,
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": False,
            "panic_restore_deferred": True,
            "health_after_ok": False,
            "transport_no_value": True,
            "cleanup_ok": False,
            "fixed_op": fixed_op,
            "flash_profile": "read",
            "flash_image_sha256": capture.READ_CANDIDATE_SHA256,
            "flash_readback_sha256": capture.READ_CANDIDATE_SHA256,
            "flash_predecessor_sha256": "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247",
            "current_boot_attestation": attestation,
            "boot_id_before_read_sha256": boot_hash,
            "panic_transition": transition,
            "semantic_claim": {"filename": claim_path.name, "sha256": claim_hash, "size": claim_size, "key_sha256": claim_key},
            "private_record": {"filename": f"{source_id}.json", "journal_filename": f"{source_id}.journal.json"},
            "raw_snapshot_sha256": capture.sha256(raw_bytes),
            "raw_snapshot_size": len(raw_bytes),
            "journal_sha256": capture.sha256(journal_bytes),
            "journal_size": len(journal_bytes),
        }
        (manifests / f"{source_id}.manifest.json").write_bytes(
            json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
        )

    def test_marker_summary_distinguishes_result_and_watchdog(self) -> None:
        summary = capture.marker_summary(
            b"A90R0000c071\nNon Secure Watchdog Bark\nlast pet\n"
        )
        self.assertTrue(summary["non_secure_watchdog_bark_present"])
        self.assertTrue(summary["a90r_result_present"])
        self.assertEqual(summary["counts"]["last pet"], 1)

    def test_empty_log_has_no_markers(self) -> None:
        summary = capture.marker_summary(b"")
        self.assertFalse(summary["non_secure_watchdog_bark_present"])
        self.assertFalse(summary["a90r_result_present"])

    def _run_collect(
        self,
        *,
        model: bytes = b"SM-A908N",
        debug_level: bytes = b"0x494d",
        current_boot_id: bytes = b"22222222-2222-4222-8222-222222222222\n",
        stophud_results: list[tuple[int, str]] | None = None,
        fail_last: BaseException | None = None,
        fail_selftest: BaseException | None = None,
        rebind_drift_attempt: int | None = None,
    ) -> tuple[tempfile.TemporaryDirectory[str], list[str], Path | None]:
        temp = tempfile.TemporaryDirectory()
        self._write_read_source(Path(temp.name))
        calls: list[str] = []
        stop_results = list(stophud_results or [(0, "ok")])
        state = {"stophud": 0, "last": 0}

        def binding() -> dict[str, object]:
            return {"process_pid": 123, "serial": "exact"}

        rebind_calls = 0

        def rebind(initial: dict[str, object]) -> dict[str, object]:
            nonlocal rebind_calls
            rebind_calls += 1
            if rebind_drift_attempt == rebind_calls:
                return {**initial, "process_pid": 999}
            self.assertEqual(initial, {"process_pid": 123, "serial": "exact"})
            return dict(initial)

        def fake_exchange(host, port, command, timeout, **kwargs):
            del host, port, timeout, kwargs
            calls.append(command.evidence_id)
            if command.evidence_id == "stophud":
                index = state["stophud"]
                state["stophud"] += 1
                rc, status = stop_results[min(index, len(stop_results) - 1)]
                return FakeFrame(b"", "stophud", rc=rc, status=status)
            if command.evidence_id == "version_before":
                return FakeFrame(_version(), "version")
            if command.evidence_id == "cmdline_before":
                payload = _cmdline().replace(b"SM-A908N", model).replace(
                    b"0x494d", debug_level
                )
                return FakeFrame(payload, "cat")
            if command.evidence_id == "boot_id_after_source":
                return FakeFrame(current_boot_id, "cat")
            if command.evidence_id == "last_kmsg":
                state["last"] += 1
                if fail_last is not None:
                    raise fail_last
                return FakeFrame(_exact_log(), "cat")
            if command.evidence_id == "selftest_after":
                if fail_selftest is not None:
                    raise fail_selftest
                return FakeFrame(b"selftest: pass=1 fail=0\n", "selftest")
            raise AssertionError(command.evidence_id)

        args = capture.make_parser().parse_args(
            ["--experiment-id", capture.LAST_KMSG_EXPERIMENT_ID, "--execute"]
        )
        # The production parser has no root selector.  The module-level root
        # is the only test seam, and an injected equal selector remains a
        # positive fixed-root binding.
        args.output_root = Path(temp.name)
        args.read_source_experiment_id = capture.READ_SOURCE_EXPERIMENT_ID
        with mock.patch.object(capture, "REPO_ROOT", Path(temp.name)), mock.patch.object(
            capture, "validate_bridge_binding", side_effect=binding
        ), mock.patch.object(
            capture, "revalidate_bridge_binding", side_effect=rebind
        ), mock.patch.object(capture, "exchange", side_effect=fake_exchange):
            try:
                result = capture.collect(args)
            except BaseException:
                result = None
        manifest = Path(temp.name) / f"evidence/manifests/{capture.LAST_KMSG_EXPERIMENT_ID}.manifest.json"
        return temp, calls, result[1] if result is not None else (manifest if manifest.exists() else None)

    def test_stophud_is_first_and_last_kmsg_is_one_shot(self) -> None:
        temp, calls, manifest_path = self._run_collect(
            stophud_results=[(-16, "busy"), (-16, "busy"), (0, "ok")]
        )
        self.addCleanup(temp.cleanup)
        self.assertEqual(calls[0], "stophud")
        self.assertEqual(calls.count("stophud"), 3)
        self.assertEqual(calls.count("last_kmsg"), 1)
        self.assertIsNotNone(manifest_path)
        manifest = json.loads(Path(manifest_path).read_text())
        self.assertTrue(manifest["target_verified"])
        self.assertTrue(manifest["last_kmsg_read_once"])
        self.assertEqual(manifest["stophud_busy_retries"], 2)
        self.assertNotIn("payload_base64", json.dumps(manifest))
        self.assertNotIn("/dev/serial", json.dumps(manifest))

    def test_wrong_runtime_target_stops_before_last_kmsg(self) -> None:
        temp, calls, manifest_path = self._run_collect(model=b"SM-S906N")
        self.addCleanup(temp.cleanup)
        self.assertIsNotNone(manifest_path)
        self.assertEqual(calls, ["stophud", "version_before", "cmdline_before"])
        journal = Path(temp.name) / f"evidence/private/{capture.LAST_KMSG_EXPERIMENT_ID}.journal.json"
        self.assertTrue(journal.exists())
        self.assertEqual(json.loads(journal.read_text())["status"], "PREFLIGHT_FAILED")

    def test_non_mid_runtime_stops_before_last_kmsg(self) -> None:
        temp, calls, manifest_path = self._run_collect(debug_level=b"0x4f4c")
        self.addCleanup(temp.cleanup)
        self.assertIsNotNone(manifest_path)
        self.assertNotIn("last_kmsg", calls)

    def test_last_kmsg_transport_incident_is_retained_without_followup(self) -> None:
        error = TimeoutError("disconnect")
        temp, calls, manifest_path = self._run_collect(fail_last=error)
        self.addCleanup(temp.cleanup)
        self.assertIsNotNone(manifest_path)
        self.assertEqual(calls[-1], "last_kmsg")
        self.assertNotIn("selftest_after", calls)
        journal = Path(temp.name) / f"evidence/private/{capture.LAST_KMSG_EXPERIMENT_ID}.journal.json"
        data = json.loads(journal.read_text())
        self.assertEqual(data["status"], "INCIDENT")
        self.assertEqual(data["records"][-1]["transport_error_type"], "TimeoutError")

    def test_stophud_busy_retry_revalidates_and_stops_on_bridge_drift(self) -> None:
        temp, calls, manifest_path = self._run_collect(
            stophud_results=[(-16, "busy"), (0, "ok")],
            rebind_drift_attempt=2,
        )
        self.addCleanup(temp.cleanup)
        self.assertIsNotNone(manifest_path)
        # The incident manifest is published, but the drifted retry itself
        # never reaches the transport and no version/last_kmsg command runs.
        self.assertEqual(calls, ["stophud"])
        self.assertNotIn("version_before", calls)
        journal = json.loads(
            (Path(temp.name) / f"evidence/private/{capture.LAST_KMSG_EXPERIMENT_ID}.journal.json").read_text()
        )
        self.assertEqual(journal["status"], "PREFLIGHT_FAILED")

    def test_source_boot_freshness_is_required_before_last_kmsg(self) -> None:
        temp, calls, manifest_path = self._run_collect(
            current_boot_id=b"11111111-1111-4111-8111-111111111111\n"
        )
        self.addCleanup(temp.cleanup)
        self.assertIsNotNone(manifest_path)
        self.assertNotIn("last_kmsg", calls)
        journal = json.loads(
            (Path(temp.name) / f"evidence/private/{capture.LAST_KMSG_EXPERIMENT_ID}.journal.json").read_text()
        )
        self.assertEqual(journal["status"], "PREFLIGHT_FAILED")

    def test_source_receipt_hash_mutation_fails_before_bridge_contact(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self._write_read_source(root)
        source = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json"
        source.write_bytes(source.read_bytes().replace(b'"mode":"read"', b'"mode":"read"', 1) + b" ")
        args = capture.make_parser().parse_args(
            ["--experiment-id", capture.LAST_KMSG_EXPERIMENT_ID, "--execute"]
        )
        args.output_root = root
        with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
            capture, "validate_bridge_binding"
        ) as binding:
            with self.assertRaises(ValueError):
                capture.collect(args)
        binding.assert_not_called()

    def test_arbitrary_source_experiment_id_is_rejected(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self._write_read_source(root)
        args = capture.make_parser().parse_args(
            ["--experiment-id", capture.LAST_KMSG_EXPERIMENT_ID, "--execute"]
        )
        args.output_root = root
        args.read_source_experiment_id = "old-read"
        with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
            capture, "validate_bridge_binding"
        ) as binding:
            with self.assertRaises(ValueError):
                capture.collect(args)
        binding.assert_not_called()

    def test_arbitrary_source_path_is_rejected_before_bridge_contact(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self._write_read_source(root)
        args = capture.make_parser().parse_args(
            ["--experiment-id", capture.LAST_KMSG_EXPERIMENT_ID, "--execute"]
        )
        args.output_root = root
        args.read_source_path = root / "copied-read.journal.json"
        with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
            capture, "validate_bridge_binding"
        ) as binding:
            with self.assertRaises(ValueError):
                capture.collect(args)
        binding.assert_not_called()

    def test_arbitrary_experiment_id_is_rejected_before_bridge_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = capture.make_parser().parse_args(
                ["--experiment-id", "last-kmsg-other", "--execute"]
            )
            args.output_root = Path(directory)
            with mock.patch.object(capture, "REPO_ROOT", Path(directory)), mock.patch.object(
                capture, "validate_bridge_binding"
            ) as binding:
                with self.assertRaisesRegex(ValueError, "fixed to last-kmsg-final"):
                    capture.collect(args)
            binding.assert_not_called()

    def test_source_no_value_evidence_rejects_extra_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            raw_path = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json"
            journal_path = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.journal.json"
            manifest_path = root / "evidence/manifests" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.manifest.json"
            for extra in (
                {"partial_end": None},
                {"partial": {"end": None}},
                {"hidden_frame": {"evidence_id": "fixed_op_4"}},
            ):
                raw = json.loads(raw_path.read_text())
                journal = json.loads(journal_path.read_text())
                raw["error"].update(extra)
                journal["error"] = dict(raw["error"])
                raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
                journal_bytes = json.dumps(journal, sort_keys=True, separators=(",", ":")).encode()
                raw_path.write_bytes(raw_bytes)
                journal_path.write_bytes(journal_bytes)
                public = json.loads(manifest_path.read_text())
                public.update(
                    {
                        "raw_snapshot_sha256": capture.sha256(raw_bytes),
                        "raw_snapshot_size": len(raw_bytes),
                        "journal_sha256": capture.sha256(journal_bytes),
                        "journal_size": len(journal_bytes),
                    }
                )
                manifest_path.write_bytes(
                    json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
                )
                with self.subTest(extra=extra):
                    with self.assertRaises(ValueError):
                        capture._validate_source_read(root)

    def test_source_frame_consumer_rejects_zero_or_missing_stophud_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            raw = json.loads(
                (
                    root
                    / "evidence/private"
                    / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json"
                ).read_text()
            )
            panic_only = [
                frame
                for frame in raw["frames"]
                if frame.get("evidence_id")
                in {"panic_before", "panic_set_0", "panic_zero_verify"}
            ]
            with self.assertRaises(ValueError):
                capture._validate_source_frame_list(
                    panic_only, "hostile missing stophud"
                )
            with self.assertRaises(ValueError):
                capture._validate_source_frame_list([], "hostile zero stophud")

    def test_source_no_value_evidence_rejects_legacy_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            raw_path = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json"
            journal_path = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.journal.json"
            raw = json.loads(raw_path.read_text())
            journal = json.loads(journal_path.read_text())
            raw["error"]["exception_type"] = "TimeoutError"
            journal["error"] = dict(raw["error"])
            raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
            journal_bytes = json.dumps(journal, sort_keys=True, separators=(",", ":")).encode()
            raw_path.write_bytes(raw_bytes)
            journal_path.write_bytes(journal_bytes)
            manifest_path = root / "evidence/manifests" / capture.READ_SOURCE_MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text())
            manifest.update(
                {
                    "raw_snapshot_sha256": capture.sha256(raw_bytes),
                    "raw_snapshot_size": len(raw_bytes),
                    "journal_sha256": capture.sha256(journal_bytes),
                    "journal_size": len(journal_bytes),
                }
            )
            manifest_path.write_bytes(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            )
            with self.assertRaises(ValueError):
                capture._validate_source_read(root)

    def test_source_no_value_evidence_rejects_native_completion_markers(self) -> None:
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
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_read_source(root)
                raw_path = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json"
                journal_path = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.journal.json"
                manifest_path = root / "evidence/manifests" / capture.READ_SOURCE_MANIFEST_NAME
                raw = json.loads(raw_path.read_text())
                journal = json.loads(journal_path.read_text())
                payload = body
                transcript = begin_line + body
                for owner in (raw, journal):
                    error = dict(owner["error"])
                    error.update(
                        {
                            "payload_base64": base64.b64encode(payload).decode("ascii"),
                            "payload_sha256": capture.sha256(payload),
                            "payload_size": len(payload),
                            "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                            "transcript_sha256": capture.sha256(transcript),
                            "transcript_size": len(transcript),
                        }
                    )
                    owner["error"] = error
                raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
                journal_bytes = json.dumps(journal, sort_keys=True, separators=(",", ":")).encode()
                raw_path.write_bytes(raw_bytes)
                journal_path.write_bytes(journal_bytes)
                manifest = json.loads(manifest_path.read_text())
                manifest.update(
                    {
                        "raw_snapshot_sha256": capture.sha256(raw_bytes),
                        "raw_snapshot_size": len(raw_bytes),
                        "journal_sha256": capture.sha256(journal_bytes),
                        "journal_size": len(journal_bytes),
                    }
                )
                manifest_path.write_bytes(
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                )
                with self.assertRaises(ValueError):
                    capture._validate_source_read(root)

    def test_source_complete_frames_bind_identity_attestation_and_cleanup_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            raw = json.loads(
                (root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json").read_text()
            )

            def mutate(frame: dict[str, object], payload: bytes) -> None:
                frame["payload_base64"] = base64.b64encode(payload).decode("ascii")
                frame["payload_sha256"] = capture.sha256(payload)
                frame["payload_size"] = len(payload)

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
                "boot_attest_hash": b"run: pid=1, q/Ctrl-C cancels\n" + b"0" * 64 + b"  " + capture.BOOT_ATTEST_FILE.encode() + b"\n[exit 0]\n",
            }
            for evidence_id, payload in mutations.items():
                with self.subTest(evidence_id=evidence_id):
                    frames = json.loads(json.dumps(raw["frames"]))
                    match = next(item for item in frames if item.get("evidence_id") == evidence_id)
                    mutate(match, payload)
                    with self.assertRaises(ValueError):
                        capture._validate_source_frame_payload_semantics(
                            frames,
                            target=raw["target"],
                            attestation=raw["current_boot_attestation"],
                            candidate_sha256=capture.READ_CANDIDATE_SHA256,
                            candidate_size=capture.BOOT_PREFIX_SIZE,
                            boot_id_before_read=raw["boot_id_before_read"],
                            label=f"hostile {evidence_id}",
                        )

    def test_source_v024_version_and_toybox_retained_transcript_grammar(self) -> None:
        version = _version()
        parsed = capture._parse_v024_version_payload(version, "retained version")
        self.assertEqual(parsed["runtime_version"], capture.EXPECTED_RUNTIME)
        self.assertEqual(parsed["runtime_build"], capture.EXPECTED_RUNTIME_BUILD)
        self.assertEqual(parsed["kernel"], capture.EXPECTED_KERNEL)
        for mutation in (
            version + b"\r",
            version.replace(b"made by device owner", b"made by device owner\r\nmade by device owner"),
            version.replace(b"display: 1080x2400", b"display: 1080x2400\ndisplay: 1080x2400"),
            version.replace(b"kernel: Linux", b"unknown: retained\r\nkernel: Linux"),
            version.replace(b"version: 0.9.285", b"version: 0.9.285\r\nversion: 0.9.285"),
            version.replace(b"kernel: Linux", b"kernel: Linux\r\nA90 Linux init"),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    capture._parse_v024_version_payload(mutation, "hostile version")

        wrapper = b"run: pid=7, q/Ctrl-C cancels\nhello\n[exit 0]"
        self.assertEqual(
            capture._source_semantic_toybox_body(wrapper, "retained toybox"), b"hello"
        )
        self.assertEqual(
            capture._source_semantic_toybox_body(wrapper + b"\n", "retained toybox LF"),
            b"hello",
        )
        self.assertEqual(
            capture._source_semantic_toybox_body(
                wrapper.replace(b"\n", b"\r\n"), "retained toybox CRLF"
            ),
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
                with self.assertRaises(ValueError):
                    capture._source_semantic_toybox_body(mutation, "hostile toybox")

    def test_source_command_flags_and_cleanup_occurrences_are_exact(self) -> None:
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
                    capture._protocol_flags_for_argv((command,)), expected
                )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            raw_path = root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json"
            raw = json.loads(raw_path.read_text())

            def rewrite_payload(frame: dict[str, object], payload: bytes) -> None:
                argv = tuple(frame["argv"])
                protocol_flags = capture._protocol_flags_for_argv(argv)
                self.assertIsNotNone(protocol_flags)
                begin = dict(frame["begin"])
                end = dict(frame["end"])
                begin["flags"] = protocol_flags
                end["flags"] = protocol_flags
                frame["begin"] = begin
                frame["end"] = end
                command = argv[0].encode("ascii")
                transcript = (
                    b"A90P1 BEGIN seq=" + str(begin["seq"]).encode("ascii")
                    + b" cmd=" + command + b" argc=" + str(len(argv)).encode("ascii")
                    + b" flags=" + str(protocol_flags).encode("ascii") + b"\n"
                    + payload + f"\n[done] {argv[0]} (0ms)\n".encode("ascii")
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
                        "payload_sha256": capture.sha256(payload),
                        "payload_size": len(payload),
                        "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                        "transcript_sha256": capture.sha256(transcript),
                        "transcript_size": len(transcript),
                    }
                )

            frames = json.loads(json.dumps(raw["frames"]))
            cleanup_frames = [
                frame for frame in frames
                if frame.get("evidence_id") in capture._SOURCE_SEMANTIC_DUPLICATE_FRAME_IDS
            ]
            self.assertGreaterEqual(len(cleanup_frames), 2)
            for pid, frame in enumerate(cleanup_frames, 1):
                payload = capture._source_decode_frame_bytes(
                    frame["payload_base64"], frame["payload_size"], frame["payload_sha256"], "cleanup"
                )
                self.assertIn(b"pid=1", payload)
                rewrite_payload(
                    frame,
                    payload.replace(b"pid=1", f"pid={pid + 1}".encode("ascii"), 1),
                )
            capture._validate_source_frame_list(frames, "dynamic source cleanup frames")
            self.assertIsNone(
                capture._validate_source_frame_payload_semantics(
                    frames,
                    target=raw["target"],
                    attestation=raw["current_boot_attestation"],
                    candidate_sha256=capture.READ_CANDIDATE_SHA256,
                    candidate_size=capture.BOOT_PREFIX_SIZE,
                    boot_id_before_read=raw["boot_id_before_read"],
                    label="dynamic source cleanup frames",
                )
            )

            invalid = json.loads(json.dumps(raw["frames"]))
            frame = next(
                frame for frame in invalid
                if frame.get("evidence_id") == "boot_attest_remove_node"
            )
            payload = capture._source_decode_frame_bytes(
                frame["payload_base64"], frame["payload_size"], frame["payload_sha256"], "cleanup"
            )
            rewrite_payload(frame, payload.replace(b"pid=1", b"pid=0", 1))
            with self.assertRaises(ValueError):
                capture._validate_source_frame_payload_semantics(
                    invalid,
                    target=raw["target"],
                    attestation=raw["current_boot_attestation"],
                    candidate_sha256=capture.READ_CANDIDATE_SHA256,
                    candidate_size=capture.BOOT_PREFIX_SIZE,
                    boot_id_before_read=raw["boot_id_before_read"],
                    label="invalid source cleanup PID",
                )

            missing = json.loads(json.dumps(raw["frames"]))
            remove_index = next(
                index for index, frame in enumerate(missing)
                if frame.get("evidence_id") == "boot_attest_remove_node"
            )
            missing.pop(remove_index)
            with self.assertRaises(ValueError):
                capture._validate_source_frame_list(missing, "missing source cleanup occurrence")

    def test_source_terminal_kind_and_prompt_tail_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            raw = json.loads(
                (root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json").read_text()
            )
            original = next(
                frame for frame in raw["frames"] if frame.get("evidence_id") == "version_before"
            )
            argv = tuple(original["argv"])
            for replacement in (
                b"[err] version rc=0 (0ms)\n",
                b"[busy] auto menu active; send hide/q before command\n",
            ):
                with self.subTest(replacement=replacement):
                    hostile = dict(original)
                    transcript = base64.b64decode(hostile["transcript_base64"])
                    transcript = transcript.replace(
                        b"[done] version (0ms)\n", replacement, 1
                    )
                    hostile["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
                    hostile["transcript_sha256"] = capture.sha256(transcript)
                    hostile["transcript_size"] = len(transcript)
                    with self.assertRaises(ValueError):
                        capture._validate_source_protocol_frame(
                            hostile, "version_before", argv, "hostile source terminal"
                        )

            hostile = dict(original)
            transcript = base64.b64decode(hostile["transcript_base64"]) + b"garbage-after-end"
            hostile["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
            hostile["transcript_sha256"] = capture.sha256(transcript)
            hostile["transcript_size"] = len(transcript)
            with self.assertRaises(ValueError):
                capture._validate_source_protocol_frame(
                    hostile, "version_before", argv, "hostile source tail"
                )

    def test_source_multiline_payloads_accept_no_final_or_one_line_ending_only(self) -> None:
        selftest = b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12"
        expected_selftest = {
            "passed": 11,
            "warn": 1,
            "fail": 0,
            "duration": 43,
            "entries": 12,
        }
        self.assertEqual(
            capture._source_semantic_selftest(selftest, "no-final selftest"),
            expected_selftest,
        )
        self.assertEqual(
            capture._source_semantic_selftest(selftest + b"\n", "LF selftest"),
            expected_selftest,
        )
        self.assertEqual(
            capture._source_semantic_selftest(selftest + b"\r\n", "CRLF selftest"),
            expected_selftest,
        )
        uevent = (
            b"MAJOR=259\nMINOR=27\nDEVNAME=sda24\nDEVTYPE=partition\n"
            b"PARTN=24\nPARTNAME=boot"
        )
        expected_uevent = {
            "MAJOR": "259",
            "MINOR": "27",
            "DEVNAME": "sda24",
            "DEVTYPE": "partition",
            "PARTN": "24",
            "PARTNAME": "boot",
        }
        lines = capture._source_semantic_lines(uevent, "no-final uevent")
        for candidate in (uevent, uevent + b"\r\n"):
            parsed = {}
            for line in capture._source_semantic_lines(candidate, "uevent"):
                key, value = line.split("=", 1)
                parsed[key] = value
            self.assertEqual(parsed, expected_uevent)
        self.assertEqual(len(lines), 6)
        for malformed in (
            selftest + b"\n\n",
            selftest.replace(b"warn=1 ", b"warn=1\n\n"),
            selftest.replace(b"warn=1 ", b"warn=1\r"),
            uevent + b"\n\n",
            uevent.replace(b"MINOR=27\n", b"MINOR=27\n\n"),
            uevent.replace(b"MINOR=27\n", b"MINOR=27\r"),
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    capture._source_semantic_lines(malformed, "hostile multiline payload")

    def test_source_complete_frame_boundaries_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            raw = json.loads(
                (root / "evidence/private" / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json").read_text()
            )
            frame = next(item for item in raw["frames"] if item["evidence_id"] == "version_before")
            argv = tuple(frame["argv"])
            for mutation in ("missing_begin_argc", "bad_flags", "bad_errno", "bad_duration", "extra_end"):
                hostile = json.loads(json.dumps(frame))
                if mutation == "missing_begin_argc":
                    hostile["begin"].pop("argc")
                elif mutation == "bad_flags":
                    hostile["end"]["flags"] = "0x2"
                elif mutation == "bad_errno":
                    hostile["end"]["errno"] = "00"
                elif mutation == "bad_duration":
                    hostile["end"]["duration_ms"] = "-1"
                else:
                    hostile["end"]["extra"] = "x"
                with self.subTest(mutation=mutation):
                    with self.assertRaises(ValueError):
                        capture._validate_source_protocol_frame(
                            hostile, "version_before", argv, f"hostile {mutation}"
                        )

    def test_source_panic_frames_require_exact_order_and_count(self) -> None:
        frames = [
            {
                "evidence_id": "panic_before",
                "argv": ["cat", "/proc/sys/kernel/panic_on_oops"],
                "begin": {"cmd": "cat", "seq": "1"},
                "end": {"cmd": "cat", "seq": "1", "rc": "0", "status": "ok"},
                "payload_base64": base64.b64encode(b"1\n").decode(),
                "payload_sha256": capture.sha256(b"1\n"),
                "payload_size": 2,
                "transcript_base64": base64.b64encode(
                    b"A90P1 BEGIN seq=1 cmd=cat\n1\n\n[done] cat (0ms)\nA90P1 END seq=1 cmd=cat rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ).decode(),
                "transcript_sha256": capture.sha256(
                    b"A90P1 BEGIN seq=1 cmd=cat\n1\n\n[done] cat (0ms)\nA90P1 END seq=1 cmd=cat rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ),
                "transcript_size": len(
                    b"A90P1 BEGIN seq=1 cmd=cat\n1\n\n[done] cat (0ms)\nA90P1 END seq=1 cmd=cat rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ),
            },
            {
                "evidence_id": "panic_set_0",
                "argv": ["writefile", "/proc/sys/kernel/panic_on_oops", "0"],
                "begin": {"cmd": "writefile", "seq": "1"},
                "end": {"cmd": "writefile", "seq": "1", "rc": "0", "status": "ok"},
                "payload_base64": "",
                "payload_sha256": capture.sha256(b""),
                "payload_size": 0,
                "transcript_base64": base64.b64encode(
                    b"A90P1 BEGIN seq=1 cmd=writefile argc=3 flags=0x0\n\n[done] writefile (0ms)\nA90P1 END seq=1 cmd=writefile rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ).decode(),
                "transcript_sha256": capture.sha256(
                    b"A90P1 BEGIN seq=1 cmd=writefile argc=3 flags=0x0\n\n[done] writefile (0ms)\nA90P1 END seq=1 cmd=writefile rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ),
                "transcript_size": len(
                    b"A90P1 BEGIN seq=1 cmd=writefile argc=3 flags=0x0\n\n[done] writefile (0ms)\nA90P1 END seq=1 cmd=writefile rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ),
            },
            {
                "evidence_id": "panic_zero_verify",
                "argv": ["cat", "/proc/sys/kernel/panic_on_oops"],
                "begin": {"cmd": "cat", "seq": "1"},
                "end": {"cmd": "cat", "seq": "1", "rc": "0", "status": "ok"},
                "payload_base64": base64.b64encode(b"0\n").decode(),
                "payload_sha256": capture.sha256(b"0\n"),
                "payload_size": 2,
                "transcript_base64": base64.b64encode(
                    b"A90P1 BEGIN seq=1 cmd=cat argc=2 flags=0x0\n0\n\n[done] cat (0ms)\nA90P1 END seq=1 cmd=cat rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ).decode(),
                "transcript_sha256": capture.sha256(
                    b"A90P1 BEGIN seq=1 cmd=cat argc=2 flags=0x0\n0\n\n[done] cat (0ms)\nA90P1 END seq=1 cmd=cat rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ),
                "transcript_size": len(
                    b"A90P1 BEGIN seq=1 cmd=cat argc=2 flags=0x0\n0\n\n[done] cat (0ms)\nA90P1 END seq=1 cmd=cat rc=0 errno=0 duration_ms=0 flags=0x0 status=ok\n"
                ),
            },
        ]
        for bad in (
            [frames[1], frames[0], frames[2]],
            [*frames, frames[0]],
        ):
            with self.subTest(frame_ids=[item["evidence_id"] for item in bad]):
                with self.assertRaises(ValueError):
                    capture._validate_source_panic_frames(bad, "hostile source")

    def test_source_rejects_renamed_complete_fixed_op_frame(self) -> None:
        hidden = {
            "evidence_id": "fixed_op_hidden",
            "argv": list(probe.fixed_op_argv()),
        }
        with self.assertRaises(ValueError):
            capture._reject_hidden_complete_fixed_op_frames(
                [hidden], "hostile source"
            )

    def test_source_transport_begin_is_bound_to_retained_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_read_source(root)
            private = root / "evidence/private"
            manifests = root / "evidence/manifests"
            raw_path = private / f"{capture.READ_SOURCE_EXPERIMENT_ID}.json"
            journal_path = private / f"{capture.READ_SOURCE_EXPERIMENT_ID}.journal.json"
            manifest_path = manifests / capture.READ_SOURCE_MANIFEST_NAME
            base_raw = json.loads(raw_path.read_text())
            base_journal = json.loads(journal_path.read_text())
            base_manifest = json.loads(manifest_path.read_text())
            base_error = dict(base_raw["error"])
            begin_only = b"A90P1 BEGIN seq=1 cmd=run\n"
            cases = []
            missing_summary = dict(base_error)
            missing_summary.update(
                {
                    "transcript_base64": base64.b64encode(begin_only).decode("ascii"),
                    "transcript_sha256": capture.sha256(begin_only),
                    "transcript_size": len(begin_only),
                }
            )
            cases.append(missing_summary)
            wrong_summary = dict(missing_summary)
            wrong_summary["begin"] = {"cmd": "cat", "seq": "1"}
            cases.append(wrong_summary)
            payload_mismatch = dict(base_error)
            forged_payload = b"forged post-BEGIN payload"
            payload_mismatch.update(
                {
                    "payload_base64": base64.b64encode(forged_payload).decode("ascii"),
                    "payload_sha256": capture.sha256(forged_payload),
                    "payload_size": len(forged_payload),
                    "transcript_base64": base64.b64encode(begin_only).decode("ascii"),
                    "transcript_sha256": capture.sha256(begin_only),
                    "transcript_size": len(begin_only),
                }
            )
            cases.append(payload_mismatch)
            no_begin_payload = dict(base_error)
            no_begin_transcript = b"bridge opened without a protocol BEGIN\n"
            no_begin_payload.update(
                {
                    "begin": None,
                    "payload_base64": "",
                    "payload_sha256": capture.sha256(b""),
                    "payload_size": 0,
                    "transcript_base64": base64.b64encode(no_begin_transcript).decode("ascii"),
                    "transcript_sha256": capture.sha256(no_begin_transcript),
                    "transcript_size": len(no_begin_transcript),
                }
            )
            cases.append(no_begin_payload)
            for error in cases:
                with self.subTest(error=error):
                    raw = json.loads(json.dumps(base_raw))
                    journal = json.loads(json.dumps(base_journal))
                    raw["error"] = error
                    journal["error"] = dict(error)
                    raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
                    journal_bytes = json.dumps(journal, sort_keys=True, separators=(",", ":")).encode()
                    raw_path.write_bytes(raw_bytes)
                    journal_path.write_bytes(journal_bytes)
                    public = json.loads(json.dumps(base_manifest))
                    public.update(
                        {
                            "raw_snapshot_sha256": capture.sha256(raw_bytes),
                            "raw_snapshot_size": len(raw_bytes),
                            "journal_sha256": capture.sha256(journal_bytes),
                            "journal_size": len(journal_bytes),
                        }
                    )
                    manifest_path.write_bytes(
                        json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
                    )
                    with self.assertRaises(ValueError):
                        capture._validate_source_read(root)

    def test_initial_final_journal_is_a_single_o_excl_owner_and_partial_claim_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence/private/last-kmsg-final.journal.json"
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def owner() -> None:
                barrier.wait()
                try:
                    capture._create_initial_journal(path, {"owner": True})
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
                capture._create_initial_journal(path, {"owner": "replay"})
            self.assertEqual(path.read_bytes(), b"partial-claim")

    def test_root_and_source_selectors_are_not_production_parser_options(self) -> None:
        for option in ("--output-root", "--read-source-experiment-id"):
            with self.subTest(option=option):
                with self.assertRaises(SystemExit):
                    capture.make_parser().parse_args(
                        ["--experiment-id", capture.LAST_KMSG_EXPERIMENT_ID, option, "x"]
                    )

    def test_injected_alternate_root_is_rejected_before_bridge_contact(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self._write_read_source(root)
        args = capture.make_parser().parse_args(
            ["--experiment-id", capture.LAST_KMSG_EXPERIMENT_ID, "--execute"]
        )
        args.output_root = root
        with tempfile.TemporaryDirectory() as alternate:
            args.output_root = Path(alternate)
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "validate_bridge_binding"
            ) as binding:
                with self.assertRaises(ValueError):
                    capture.collect(args)
        binding.assert_not_called()

    def test_selftest_failure_preserves_one_shot_log_and_signature_without_replay(self) -> None:
        error = ConnectionError("selftest disconnect")
        temp, calls, manifest_path = self._run_collect(fail_selftest=error)
        self.addCleanup(temp.cleanup)
        self.assertIsNotNone(manifest_path)
        self.assertEqual(calls.count("last_kmsg"), 1)
        self.assertEqual(calls.count("selftest_after"), 1)
        private = Path(temp.name) / "evidence/private"
        raw_log = private / f"{capture.LAST_KMSG_EXPERIMENT_ID}.last_kmsg.raw.bin"
        signature = private / f"{capture.LAST_KMSG_EXPERIMENT_ID}.last_kmsg.bin"
        journal = private / f"{capture.LAST_KMSG_EXPERIMENT_ID}.journal.json"
        self.assertTrue(raw_log.exists())
        self.assertTrue(signature.exists())
        self.assertTrue(journal.exists())
        self.assertEqual(
            json.loads(journal.read_text())["retained_sha256"],
            capture.sha256(signature.read_bytes()),
        )
        manifest = json.loads(Path(manifest_path).read_text())
        self.assertEqual(manifest["status"], "INCIDENT")
        self.assertEqual(manifest["private_record"]["filename"], signature.name)
        self.assertEqual(manifest["private_record"]["captured_log"]["filename"], raw_log.name)

    def test_exact_signature_has_reference_order_and_delta(self) -> None:
        signature = capture.parse_exact_reset_signature(_exact_log())
        self.assertEqual(signature["status"], "EXACT_V024_MID_NONSECURE_WDT")
        self.assertEqual(signature["debug_level_decimal"], 1145654596)
        self.assertEqual(signature["a90r_count"], 0)
        self.assertEqual(
            tuple(signature["ordered_offsets"]),
            ("bark", "last_pet", "debug_level", "upload_cause", "collect_upload", "tz_reason"),
        )
        self.assertAlmostEqual(signature["bark_last_pet_delta_seconds"], 11.000274, places=6)
        self.assertTrue(signature["uniqueness"]["all_required_unique"])

    def test_exact_signature_accepts_only_the_retained_prefixed_source_lines(self) -> None:
        signature = capture.parse_exact_reset_signature(_prefixed_exact_log())
        self.assertEqual(signature["status"], "EXACT_V024_MID_NONSECURE_WDT")
        self.assertEqual(signature["ordered_offsets"]["bark"], _prefixed_exact_log().index(b"Watchdog bark"))
        self.assertEqual(signature["ordered_offsets"]["upload_cause"], _prefixed_exact_log().index(b"UploadCause"))
        for mutation in (
            b"GARBAGE " + _prefixed_exact_log(),
            _prefixed_exact_log().replace(b"Watchdog bark! Now = 69.080467", b"JUNK Watchdog bark! Now = 69.080467"),
            _prefixed_exact_log().replace(b"Watchdog bark! Now = 69.080467\n", b"Watchdog bark! Now = 69.080467garbage\n"),
            _prefixed_exact_log().replace(b"Watchdog bark! Now = 69.080467\n", b"Watchdog bark! Now = 69.080467\r"),
            _prefixed_exact_log().replace(b"{441213} DebugLevel : 1145654596, ForceUploadFlag : 0\n", b"{441213} DebugLevel : 1145654596, ForceUploadFlag : 0 extra\n"),
        ):
            with self.subTest(mutation=mutation[:40]):
                self.assertEqual(capture.parse_exact_reset_signature(mutation)["status"], "INCIDENT")

    def test_signature_reordered_duplicate_stale_a90r_wrong_debug_and_nonfinite_are_incidents(self) -> None:
        reordered = capture.parse_exact_reset_signature(
            _exact_log(
                order=(
                    "last_pet",
                    "bark",
                    "debug_level",
                    "upload_cause",
                    "collect_upload",
                    "tz_reason",
                )
            )
        )
        self.assertEqual(reordered["status"], "INCIDENT")
        duplicate = capture.parse_exact_reset_signature(_exact_log() + b"Watchdog bark! Now = 69.080467\n")
        self.assertEqual(duplicate["status"], "INCIDENT")
        stale = capture.parse_exact_reset_signature(_exact_log(a90r=b"A90R0000\n"))
        self.assertEqual(stale["status"], "INCIDENT")
        wrong_debug = capture.parse_exact_reset_signature(_exact_log(debug="1145654595"))
        self.assertEqual(wrong_debug["status"], "INCIDENT")
        nonfinite = capture.parse_exact_reset_signature(_exact_log(bark="NaN"))
        self.assertEqual(nonfinite["status"], "INCIDENT")

    def test_each_reset_marker_requires_an_exact_terminal_boundary(self) -> None:
        suffixes = (
            b"Watchdog bark! Now = 69.080467garbage\n",
            b"Watchdog last pet at 58.080193garbage\n",
            b"DebugLevel : 1145654596, ForceUploadFlag : 0garbage\n",
            b"UploadCause[Non Secure Watchdog Bark], Don't check hangcntgarbage\n",
            b"collect_rr_data : upload_cause = Non Secure Watchdog Barkgarbage\n",
            b"collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDTgarbage\n",
        )
        for malformed in suffixes:
            with self.subTest(malformed=malformed):
                # Replace the corresponding exact line while retaining every
                # other marker, so only the boundary mutation is under test.
                exact = _exact_log()
                marker = malformed.split(b"garbage", 1)[0]
                if marker.startswith(b"Watchdog bark"):
                    exact = exact.replace(b"Watchdog bark! Now = 69.080467\n", malformed)
                elif marker.startswith(b"Watchdog last pet"):
                    exact = exact.replace(b"Watchdog last pet at 58.080193\n", malformed)
                elif marker.startswith(b"DebugLevel"):
                    exact = exact.replace(b"DebugLevel : 1145654596, ForceUploadFlag : 0\n", malformed)
                elif marker.startswith(b"UploadCause"):
                    exact = exact.replace(b"UploadCause[Non Secure Watchdog Bark], Don't check hangcnt\n", malformed)
                elif marker.startswith(b"collect_rr_data : upload_cause"):
                    exact = exact.replace(b"collect_rr_data : upload_cause = Non Secure Watchdog Bark\n", malformed)
                else:
                    exact = exact.replace(b"collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT\n", malformed)
                self.assertEqual(capture.parse_exact_reset_signature(exact)["status"], "INCIDENT")

    def test_execute_and_timeout_gates_fail_before_output(self) -> None:
        for argv in (
            ["--experiment-id", "gate"],
            ["--experiment-id", "gate", "--execute", "--timeout", "nan"],
            ["--experiment-id", "gate", "--execute", "--timeout", "inf"],
            ["--experiment-id", "gate", "--execute", "--timeout", "0"],
        ):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as directory:
                args = capture.make_parser().parse_args(argv)
                args.output_root = Path(directory)
                with mock.patch.object(capture, "REPO_ROOT", Path(directory)), mock.patch.object(
                    capture, "validate_bridge_binding"
                ) as bind:
                    with self.assertRaises(ValueError):
                        capture.collect(args)
                bind.assert_not_called()

if __name__ == "__main__":
    unittest.main()
