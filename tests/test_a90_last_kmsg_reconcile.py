from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import a90_last_kmsg_capture as capture
from tools import a90_last_kmsg_reconcile as reconcile
from tools import a90_verification024_finalize as finalizer


BOOT_ID = "22222222-2222-4222-8222-222222222222"
SOURCE_BOOT_ID = "11111111-1111-4111-8111-111111111111"
COMPLETED = "2026-08-28T13:08:38+00:00"
READ_COMPLETED = "2026-08-28T13:01:52+00:00"


def _frame(evidence_id: str, argv: list[str], payload: bytes, *, flags: str = "0x0") -> dict[str, object]:
    transcript = b"frame:" + evidence_id.encode("ascii") + b"\n" + payload
    protocol_flags = capture._protocol_flags_for_argv(tuple(argv))
    if protocol_flags != flags:
        raise AssertionError(f"unexpected test protocol flags for {argv}: {protocol_flags!r}")
    transcript = (
        f"A90P1 BEGIN seq=1 cmd={argv[0]} argc={len(argv)} flags={flags}\n".encode("ascii")
        + payload
        + b"\n[done] "
        + argv[0].encode("ascii")
        + b" (0ms)\n"
        + f"A90P1 END seq=1 cmd={argv[0]} rc=0 errno=0 duration_ms=0 flags={flags} status=ok\n".encode("ascii")
    )
    begin = {
        "cmd": argv[0],
        "seq": "1",
        "argc": str(len(argv)),
        "flags": flags,
    }
    end = {
        "cmd": argv[0],
        "seq": "1",
        "rc": "0",
        "errno": "0",
        "duration_ms": "0",
        "flags": flags,
        "status": "ok",
    }
    return {
        "argv": list(argv),
        "begin": begin,
        "end": end,
        "evidence_id": evidence_id,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_size": len(payload),
        "transcript_base64": base64.b64encode(transcript).decode("ascii"),
        "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
        "transcript_size": len(transcript),
    }


def _exact_raw() -> bytes:
    return (
        b"<6>[   97.880696] I[0:   msm_watchdog:   78] "
        b"msm_watchdog 17c10000.qcom,wdt: Watchdog bark! Now = 97.880454\n"
        b"<6>[   97.880708] I[0:   msm_watchdog:   78] "
        b"msm_watchdog 17c10000.qcom,wdt: Watchdog last pet at 86.880167\n"
        b"DebugLevel : 1145654596, ForceUploadFlag : 0\n"
        b"UploadCause[Non Secure Watchdog Bark], Don't check hangcnt\n"
        b"collect_rr_data : upload_cause = Non Secure Watchdog Bark\n"
        b"collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT\n"
    )


def _incident_raw() -> bytes:
    return (
        b"wrong-prefix Watchdog bark! Now = 97.880454\n"
        b"wrong-prefix Watchdog last pet at 86.880167\n"
        b"DebugLevel : 1145654596, ForceUploadFlag : 0\n"
        b"UploadCause[Non Secure Watchdog Bark], Don't check hangcnt\n"
        b"collect_rr_data : upload_cause = Non Secure Watchdog Bark\n"
        b"collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT\n"
    )


def _write_json(path: Path, value: object) -> bytes:
    data = json.dumps(value, ensure_ascii=True, sort_keys=False, indent=2).encode("utf-8") + b"\n"
    path.write_bytes(data)
    return data


def _fixed_read_summary() -> dict[str, object]:
    return {
        "completed_utc": READ_COMPLETED,
        "experiment_id": "verification-024-read",
        "journal_sha256": "a" * 64,
        "journal_size": 10,
        "manifest_sha256": "b" * 64,
        "manifest_size": 10,
        "raw_sha256": "c" * 64,
        "raw_size": 10,
        "source_pre_read_boot_id": SOURCE_BOOT_ID,
        "source_pre_read_boot_id_sha256": hashlib.sha256(SOURCE_BOOT_ID.encode("ascii")).hexdigest(),
    }


def _make_source(root: Path, *, captured: bytes | None = None) -> None:
    private = root / "evidence/private"
    manifests = root / "evidence/manifests"
    private.mkdir(parents=True)
    manifests.mkdir(parents=True)
    captured = _exact_raw() if captured is None else captured
    signature = capture.parse_exact_reset_signature(_incident_raw())
    signature_bytes = _write_json(
        private / "last-kmsg-final.last_kmsg.bin",
        {"exact_reset_signature": signature},
    )
    captured_path = private / "last-kmsg-final.last_kmsg.raw.bin"
    captured_path.write_bytes(captured)
    captured_hash = hashlib.sha256(captured).hexdigest()
    target = {
        "bootloader": "A908NKSU5EWA3",
        "model": "SM-A908N",
        "runtime": "0.9.285",
        "soc": "SM8150",
    }
    version = (
        b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\n"
        b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
        b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
    )
    cmdline = (
        b"androidboot.em.model=SM-A908N androidboot.bootloader=A908NKSU5EWA3 "
        b"androidboot.debug_level=0x494d androidboot.force_upload=0x0 "
        b"sec_debug.dump_sink=0x0\n"
    )
    records = [
        _frame("version_before", ["version"], version),
        _frame("cmdline_before", ["cat", "/proc/cmdline"], cmdline),
        _frame(
            "boot_id_after_source",
            ["cat", "/proc/sys/kernel/random/boot_id"],
            (BOOT_ID + "\n").encode("ascii"),
        ),
        _frame("last_kmsg", ["cat", "/proc/last_kmsg"], captured),
    ]
    stop_frame = _frame(
        "stophud_1", ["stophud"], b"autohud: stopped", flags="0x8"
    )
    stop_attempt = {
        "attempt": 1,
        "evidence_id": "stophud_1",
        "payload_sha256": stop_frame["payload_sha256"],
        "payload_size": stop_frame["payload_size"],
        "rc": 0,
        "status": "ok",
        "transcript_sha256": stop_frame["transcript_sha256"],
        "transcript_size": stop_frame["transcript_size"],
    }
    stophud = {"accepted": True, "attempts": [stop_attempt], "busy_retries": 0}
    read_source = {
        "completed_utc": READ_COMPLETED,
        "experiment_id": "verification-024-read",
        "journal_sha256": "a" * 64,
        "journal_size": 10,
        "manifest_sha256": "b" * 64,
        "manifest_size": 10,
        "raw_sha256": "c" * 64,
        "raw_size": 10,
        "source_pre_read_boot_id": SOURCE_BOOT_ID,
        "source_pre_read_boot_id_sha256": hashlib.sha256(SOURCE_BOOT_ID.encode("ascii")).hexdigest(),
    }
    journal = {
        "boot_id_changed": True,
        "bridge_binding": {},
        "captured_log_filename": "last-kmsg-final.last_kmsg.raw.bin",
        "captured_log_sha256": captured_hash,
        "captured_log_size": len(captured),
        "current_boot_id": BOOT_ID,
        "current_boot_id_sha256": hashlib.sha256(BOOT_ID.encode("ascii")).hexdigest(),
        "effect_dispatched": False,
        "effect_replayed": False,
        "expected_target": {},
        "experiment_id": "last-kmsg-final",
        "last_kmsg_read_once": True,
        "live_bridge_binding_before_last_kmsg": {},
        "post_stophud_bridge_binding": {},
        "private_record": "last-kmsg-final.private.json",
        "raw_filename": "last-kmsg-final.last_kmsg.bin",
        "read_source": read_source,
        "records": records,
        "retained_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        "retained_size": len(signature_bytes),
        "schema": "sdm855-a90-last-kmsg-capture-private-v2",
        "source_pre_read_boot_id": SOURCE_BOOT_ID,
        "started_utc": COMPLETED,
        "status": "INCIDENT",
        "stophud": stophud,
        "stophud_attempts": [stop_attempt],
        "stophud_frames": [stop_frame],
        "target": target,
        "target_verified": True,
        "transport_module": "tools.a90_pa28_live",
        "transport_source": "tools/a90_pa28_live.py",
    }
    journal_bytes = _write_json(private / "last-kmsg-final.journal.json", journal)
    metadata = {
        "completed_utc": COMPLETED,
        "exact_reset_signature": signature,
        "experiment_id": "last-kmsg-final",
        "journal_filename": "last-kmsg-final.journal.json",
        "last_kmsg": {
            "captured_log_filename": "last-kmsg-final.last_kmsg.raw.bin",
            "captured_log_sha256": captured_hash,
            "captured_log_size": len(captured),
            "filename": "last-kmsg-final.last_kmsg.bin",
            "markers": {},
            "sha256": hashlib.sha256(signature_bytes).hexdigest(),
            "size": len(signature_bytes),
        },
        "schema": "sdm855-a90-last-kmsg-capture-private-v2",
        "started_utc": COMPLETED,
    }
    metadata_bytes = _write_json(private / "last-kmsg-final.private.json", metadata)
    public = {
        "classification": "INCIDENT",
        "completed_utc": COMPLETED,
        "effect_dispatched": False,
        "effect_dispatched_count": 0,
        "effect_replayed": False,
        "error": "exact V024 reset signature status: INCIDENT",
        "expected_target": {
            "bootloader": "A908NKSU5EWA3",
            "build": "v2321-usb-clean-identity-rodata",
            "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
            "model": "SM-A908N",
            "runtime": "0.9.285",
            "soc": "SM8150",
            "version": "A90 Linux init 0.9.285",
        },
        "experiment_id": "last-kmsg-final",
        "journal_filename": "last-kmsg-final.journal.json",
        "partition_writes": False,
        "private_record": {
            "captured_log": {
                "filename": "last-kmsg-final.last_kmsg.raw.bin",
                "sha256": captured_hash,
                "size": len(captured),
            },
            "filename": "last-kmsg-final.last_kmsg.bin",
            "journal_filename": "last-kmsg-final.journal.json",
            "sha256": hashlib.sha256(signature_bytes).hexdigest(),
            "size": len(signature_bytes),
        },
        "redaction": {"cmdline": "omitted", "raw_transcript": "omitted", "serial_identity": "omitted"},
        "schema": "sdm855-a90-last-kmsg-capture-public-v2",
        "started_utc": COMPLETED,
        "status": "INCIDENT",
        "target": target,
        "target_verified": True,
    }
    _write_json(manifests / "last-kmsg-final.manifest.json", public)


class LastKmsgReconcileTests(unittest.TestCase):
    def _produce(self, root: Path) -> tuple[Path, Path]:
        _make_source(root)
        return reconcile.reconcile(root=root)

    def _validate(self, root: Path, manifest_path: Path) -> dict[str, object]:
        with mock.patch.object(
            finalizer,
            "_validate_fixed_read_source",
            return_value=_fixed_read_summary(),
        ):
            return finalizer.validate_last_kmsg(manifest_path, root)

    def test_reconcile_and_finalizer_consume_synthetic_exact_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path, manifest_path = self._produce(root)
            public = json.loads(manifest_path.read_text())
            self.assertEqual(public["reclassified_status"], "EXACT_V024_MID_NONSECURE_WDT")
            self.assertTrue(public["parser_false_negative"])
            self.assertFalse(public["device_contact"])
            self.assertEqual(
                public["selftest_after"],
                "NOT_OBSERVED_DUE_TO_PRE_FIX_PARSER_STOP",
            )
            self.assertEqual(
                public["exact_reset_signature"]["bark_last_pet_delta_seconds"],
                11.000287,
            )
            result = self._validate(root, manifest_path)
            self.assertEqual(result["experiment_id"], reconcile.EXPERIMENT_ID)
            self.assertEqual(result["raw_size"], len(_exact_raw()))
            self.assertEqual(result["delta_seconds"], 11.000287)
            self.assertTrue(journal_path.is_file())
            self.assertEqual(reconcile.reconcile(root=root), (journal_path, manifest_path))

    def test_source_raw_mutation_is_rejected_without_reclassifying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_source(root)
            raw_path = root / "evidence/private/last-kmsg-final.last_kmsg.raw.bin"
            raw_path.write_bytes(_exact_raw().replace(b"msm_watchdog:   78", b"msm_watchdog:   79", 1))
            with self.assertRaises(reconcile.ReconcileError):
                reconcile.reconcile(root=root)
            self.assertFalse(
                (root / "evidence/manifests/last-kmsg-final-reconciled.manifest.json").exists()
            )

    def test_public_read_source_zeroing_is_rejected_by_fixed_read_join(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest_path = self._produce(root)
            manifest = json.loads(manifest_path.read_text())
            manifest["read_source"]["journal_sha256"] = "0" * 64
            _write_json(manifest_path, manifest)
            with self.assertRaises(finalizer.FinalizeError):
                self._validate(root, manifest_path)

    def test_output_record_and_stophud_projections_are_source_derived(self) -> None:
        for mutation in ("record", "stophud"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, manifest_path = self._produce(root)
                manifest = json.loads(manifest_path.read_text())
                if mutation == "record":
                    manifest["records"][0]["transcript_size"] += 1
                else:
                    manifest["stophud"]["attempts"][0]["payload_size"] += 1
                _write_json(manifest_path, manifest)
                with self.assertRaises(finalizer.FinalizeError):
                    self._validate(root, manifest_path)

    def test_source_current_boot_hash_and_preboot_join_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest_path = self._produce(root)
            source_journal_path = root / "evidence/private/last-kmsg-final.journal.json"
            source_journal = json.loads(source_journal_path.read_text())
            source_journal["current_boot_id_sha256"] = "0" * 64
            _write_json(source_journal_path, source_journal)
            with self.assertRaises(finalizer.FinalizeError):
                self._validate(root, manifest_path)

    def test_reconciled_public_shape_rejects_raw_identity_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest_path = self._produce(root)
            manifest = json.loads(manifest_path.read_text())
            manifest["serial"] = "A90"
            manifest["read_source"]["source_pre_read_boot_id"] = SOURCE_BOOT_ID
            _write_json(manifest_path, manifest)
            with self.assertRaises(finalizer.FinalizeError):
                self._validate(root, manifest_path)


if __name__ == "__main__":
    unittest.main()
