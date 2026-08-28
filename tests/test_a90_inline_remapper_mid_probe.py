from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import struct
import tempfile
import time
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from typing import Mapping
from unittest import mock

from tools import a90_autohud_arbitration as hud
from tools import a90_inline_remapper_mid_probe as probe
from tools import a90_verification024_finalize as finalizer


VERSION = (
    b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\n"
    b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
    b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
)
CMDLINE = (
    b"skip_initramfs rootwait ro "
    b"androidboot.em.model=SM-A908N "
    b"androidboot.bootloader=A908NKSU5EWA3 "
    b"androidboot.debug_level=0x494d "
    b"androidboot.force_upload=0x0 "
    b"sec_debug.dump_sink=0x0\n"
)
SELFTEST = b"selftest: pass=11 warn=1 fail=0 duration=43ms entries=12\n"
BOOT_ID = "11111111-1111-4111-8111-111111111111"
UEVENT = (
    b"MAJOR=259\nMINOR=27\nDEVNAME=sda24\nDEVTYPE=partition\n"
    b"PARTN=24\nPARTNAME=boot\n"
)


class FakeFrame:
    def __init__(
        self,
        payload: bytes = b"",
        command: str = "run",
        *,
        rc: int = 0,
        status: str = "ok",
        argc: int | None = None,
    ) -> None:
        self.payload = payload
        command_argc = {
            "stophud": 1,
            "version": 1,
            "cat": 2,
            "selftest": 2,
            "writefile": 3,
            "run": 5,
            "stat": 2,
            "mknodb": 4,
        }.get(command, 1)
        protocol_flags = probe.protocol_flags_for_argv((command,))
        if protocol_flags is None:
            raise AssertionError(f"test command has no native flag contract: {command}")
        begin_fields = (
            f"seq=1 cmd={command} argc={argc if argc is not None else command_argc} "
            f"flags={protocol_flags}"
        )
        errno = -rc if rc < 0 else 0
        end_fields = (
            f"seq=1 cmd={command} rc={rc} errno={errno} duration_ms=0 "
            f"flags={protocol_flags} status={status}"
        )
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
            b"A90P1 BEGIN "
            + begin_fields.encode("ascii")
            + b"\n"
            + payload
            + b"\n"
            + terminal
            + b"A90P1 END "
            + end_fields.encode("ascii")
            + b"\n"
        )
        self.begin = dict(item.split("=", 1) for item in begin_fields.split())
        self.end = dict(item.split("=", 1) for item in end_fields.split())


class FakeSession:
    def __init__(self, value=probe.CONTROL_SENTINEL, op_exception=None) -> None:
        self.panic_state = 1
        self.panic_values: list[int] = []
        self.op_calls: list[tuple[int, tuple[int, ...], bool]] = []
        self.value = value
        self.op_exception = op_exception
        self.restore_exception: BaseException | None = None

    def set_panic_on_oops(self, value: int) -> None:
        self.panic_values.append(value)
        if value == 1 and self.restore_exception is not None:
            raise self.restore_exception
        self.panic_state = value

    def _op_values(self, op: int, args: tuple[int, ...], *, replay_safe: bool):
        self.op_calls.append((op, tuple(args), replay_safe))
        if self.op_exception is not None:
            raise self.op_exception
        return [self.value]


def target_binding() -> dict[str, object]:
    return {
        "listener": {"host": probe.BRIDGE_HOST, "port": probe.BRIDGE_PORT},
        "serial_device": probe.BRIDGE_SERIAL_DEVICE,
        "serial_identity": probe.BRIDGE_SERIAL_ID,
        "serial_realpath": probe.BRIDGE_SERIAL_DEVICE,
        "serial_stat": {
            "st_dev": 1,
            "st_ino": 2,
            "st_rdev": 3,
            "mode": 0o600,
            "character_device": True,
        },
        "process_pid": 123,
        "process_argv": [
            "python3",
            str(probe.BRIDGE_PROCESS_SCRIPT_PATH),
            "--host",
            probe.BRIDGE_HOST,
            "--port",
            str(probe.BRIDGE_PORT),
            "--device",
            probe.BRIDGE_SERIAL_DEVICE,
            "--expect-realpath",
            probe.BRIDGE_SERIAL_DEVICE,
            "--device-glob",
            probe.BRIDGE_SERIAL_GLOB_TOKEN,
        ],
        "bridge_process_script": probe.BRIDGE_PROCESS_SCRIPT,
        "bridge_process_script_path": str(probe.BRIDGE_PROCESS_SCRIPT_PATH),
        "bridge_process_script_descriptor": {
            "basename": "serial_tcp_bridge.py",
            "size_bytes": 21170,
            "sha256": "f" * 64,
        },
        "unique_process": True,
        "validated_utc": "2026-08-27T00:00:00+00:00",
    }


class InlineRemapperMidProbeTests(unittest.TestCase):
    def _flash_record(self, mode: str) -> dict[str, object]:
        expected = probe.EXPECTED_CANDIDATE_HASHES[mode]
        predecessor = sorted(probe.ALLOWED_PREDECESSORS[mode])[0]
        staging = (
            "/tmp/sdm855-remapper-boot.img"
            if mode == probe.MODE_CONTROL
            else "/tmp/sdm855-remapper-boot-read.img"
        )
        return {
            "schema": "sdm855-a90-remapper-boot-flash-private-v1",
            "profile": mode,
            "image_sha256": expected,
            "image_size": probe.BOOT_PREFIX_SIZE,
            "remote_staging": staging,
            "remote_staging_sha256": expected,
            "remote_staging_size": probe.BOOT_PREFIX_SIZE,
            "readback_sha256": expected,
            "readback_size": probe.BOOT_PREFIX_SIZE,
            "predecessor_size": probe.BOOT_PREFIX_SIZE,
            "allowed_predecessors": sorted(probe.ALLOWED_PREDECESSORS[mode]),
            "write_count": 1,
            "effect_dispatched": True,
            "effect_armed": True,
            "effect_argv": [
                "dd", f"if={staging}", "of=/dev/block/sda24",
                "bs=4096", "count=14864", "conv=fsync",
            ],
            "status": probe.PASS_READBACK_AND_CLEANUP,
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
            "post_staging_predecessor_sha256": predecessor,
            "post_staging_predecessor_size": probe.BOOT_PREFIX_SIZE,
            "post_staging_predecessor_revalidated": True,
            "pre_effect_revalidated": True,
            "post_dispatch_revalidated": True,
            "final_revalidated": True,
            "pre_cleanup_revalidated": True,
            "pre_push_revalidated": True,
            "final_cleanup_revalidated": True,
            "pre_cleanup_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "pre_push_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_dispatch_staging_sha256": expected,
            "post_dispatch_staging_size": probe.BOOT_PREFIX_SIZE,
            "post_dispatch_predecessor_sha256": predecessor,
            "post_dispatch_predecessor_size": probe.BOOT_PREFIX_SIZE,
            "post_staging_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "pre_effect_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_dispatch_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "final_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "final_cleanup_target_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_staging_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "pre_effect_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "post_dispatch_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "final_rebind_serial_sha256": "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46",
            "guarded_effect_receipt": {
                "schema": "sdm855-a90-remapper-guarded-effect-v1",
                "guard": {
                    "current_sha256": predecessor,
                    "current_size": str(probe.BOOT_PREFIX_SIZE),
                    "staging_sha256": expected,
                    "staging_size": str(probe.BOOT_PREFIX_SIZE),
                },
                "dd_result": {"rc": "0", "count": "14864"},
                "write_count": 1,
            },
            "predecessor_sha256": predecessor,
            "completed_utc": "2026-08-27T00:00:00+00:00",
        }

    def _args(self, root: Path, mode: str, *, read_flash_completed: str | None = None) -> Namespace:
        flash_journal = probe._fixed_flash_journal_path(root, mode)
        flash_journal.parent.mkdir(parents=True, exist_ok=True)
        existing_control_manifest = probe._fixed_control_manifest_path(root)
        had_existing_control = (
            existing_control_manifest.exists() or existing_control_manifest.is_symlink()
        )
        flash_record = self._flash_record(mode)
        effective_read_flash_completed: str | None = None
        if mode == probe.MODE_READ:
            effective_read_flash_completed = read_flash_completed
            if effective_read_flash_completed is None and had_existing_control:
                try:
                    existing_control = json.loads(existing_control_manifest.read_text())
                    control_completed = dt.datetime.fromisoformat(
                        str(existing_control["completed_utc"])
                    )
                    effective_read_flash_completed = (
                        control_completed + dt.timedelta(seconds=1)
                    ).isoformat()
                except (KeyError, OSError, TypeError, ValueError):
                    effective_read_flash_completed = None
            flash_record["completed_utc"] = (
                effective_read_flash_completed or "2026-08-27T00:01:00+00:00"
            )
        flash_journal.write_text(json.dumps(flash_record))
        if (
            mode == probe.MODE_READ
            and had_existing_control
            and read_flash_completed is None
            and effective_read_flash_completed
        ):
            try:
                flash_completed = dt.datetime.fromisoformat(
                    effective_read_flash_completed
                )
                wait_deadline = time.monotonic() + 3.0
                while (
                    dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
                    <= flash_completed
                    and time.monotonic() < wait_deadline
                ):
                    time.sleep(0.01)
            except ValueError:
                pass
        predecessor = sorted(probe.ALLOWED_PREDECESSORS[probe.MODE_CONTROL])[0]
        image = root / "candidate.img"
        image.write_bytes(b"candidate")
        control_manifest = None
        if (
            mode == probe.MODE_READ
            and not had_existing_control
        ):
            completed = "2026-08-27T00:00:00+00:00"
            control_id = probe.CONTROL_EXPERIMENT_ID
            def panic_record(evidence_id: str, argv: tuple[str, ...], payload: bytes) -> dict[str, object]:
                return probe.frame_record(
                    evidence_id,
                    argv,
                    FakeFrame(payload, argv[0], argc=len(argv)),
                )

            panic_frames = [
                panic_record("panic_before", ("cat", "/proc/sys/kernel/panic_on_oops"), b"1\n"),
                panic_record("panic_set_0", ("writefile", "/proc/sys/kernel/panic_on_oops", "0"), b""),
                panic_record("panic_zero_verify", ("cat", "/proc/sys/kernel/panic_on_oops"), b"0\n"),
                panic_record("panic_set_1", ("writefile", "/proc/sys/kernel/panic_on_oops", "1"), b""),
                panic_record("panic_restore_verify", ("cat", "/proc/sys/kernel/panic_on_oops"), b"1\n"),
            ]
            fixed_payload = b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\n[exit 0]\n"
            fixed_exchange = FakeFrame(fixed_payload, "run")
            fixed_exchange.transcript = (
                b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
                + fixed_payload
                + b"\n[done] run (0ms)\n"
                b"A90P1 END seq=1 cmd=run rc=0 errno=0 duration_ms=0 flags=0x2 status=ok\n"
            )
            control_frames = [
                *panic_frames,
                probe.frame_record(
                    "fixed_op_4", probe.fixed_op_argv(), fixed_exchange
                ),
            ]
            attestation = {
                "sysfs_root": probe.BOOT_SYSFS_ROOT,
                "block_node": probe.BOOT_BLOCK_NODE,
                "attest_node": probe.BOOT_ATTEST_NODE,
                "attest_file": probe.BOOT_ATTEST_FILE,
                "attest_node": probe.BOOT_ATTEST_NODE,
                "attest_file": probe.BOOT_ATTEST_FILE,
                "bs": 4096,
                "count": 14864,
                "expected_size": probe.BOOT_PREFIX_SIZE,
                "captured_size": probe.BOOT_PREFIX_SIZE,
                "expected_sha256": probe.CONTROL_SHA256,
                "captured_sha256": probe.CONTROL_SHA256,
                "sectors": 131072,
                "ro": 0,
                "hash_matches_candidate": True,
                "size_matches_candidate": True,
                "cleanup_ok": True,
                "cleanup_error": None,
                "stat": {"mode": "0600", "uid": "0", "gid": "0", "size": "0", "rdev": "259:27"},
            }
            panic_transition = {
                "before": 1,
                "zero_write_attempted": True,
                "zero_set": True,
                "zero_verified": True,
                "restore_write_attempted": True,
                "restored": True,
                "restore_deferred": False,
                "proof_frame_ids": [
                    "panic_before", "panic_set_0", "panic_zero_verify",
                    "panic_set_1", "panic_restore_verify",
                ],
            }
            control_flash_journal = probe._fixed_flash_journal_path(root, probe.MODE_CONTROL)
            control_flash = self._flash_record(probe.MODE_CONTROL)
            control_flash["completed_utc"] = "2026-08-26T23:59:00+00:00"
            control_flash_journal.write_text(json.dumps(control_flash))
            flash_bytes = control_flash_journal.read_bytes()
            claim_path, claim_data, claim_key = probe._semantic_claim(
                root,
                probe.MODE_CONTROL,
                probe.CONTROL_SHA256,
                probe.BOOT_PREFIX_SIZE,
                BOOT_ID,
                control_id,
            )
            claim_hash = probe.sha256_bytes(claim_data)
            claim_size = len(claim_data)
            control_raw = {
                "schema": "sdm855-a90-inline-remapper-mid-private-v1",
                "experiment_id": control_id,
                "mode": probe.MODE_CONTROL,
                "completed_utc": completed,
                "candidate_sha256": probe.CONTROL_SHA256,
                "candidate_size": probe.BOOT_PREFIX_SIZE,
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
                "flash_journal": {
                    "path": str(control_flash_journal),
                    "sha256": probe.sha256_bytes(flash_bytes),
                    "size": len(flash_bytes),
                    "profile": probe.MODE_CONTROL,
                    "image_sha256": probe.CONTROL_SHA256,
                    "readback_sha256": probe.CONTROL_SHA256,
                    "predecessor_sha256": predecessor,
                },
                "fixed_op_measurement": {
                    "argv": list(probe.fixed_op_argv()),
                    "buffer_size": probe.FIXED_OP_BUFFER_SIZE,
                    "buffer_sha256": probe.sha256_bytes(probe.build_fixed_op_buffer()),
                    "magic": f"0x{probe.FIXED_OP_MAGIC:016x}",
                    "op": 4,
                    "args": [],
                    "rc": 0,
                    "status": "ok",
                    "value": "0x000000000000c071",
                    "a90r_record": "A90Rc071",
                },
                "value": "0x000000000000c071",
                "outcome": "CONTROL_PASS",
                "dispatch_count": 1,
                "effect_dispatched": True,
                "effect_ambiguous": False,
                "effect_replayed": False,
                "health_after": {"ok": True, "target": {"model": "SM-A908N", "soc": "SM8150", "soc_id": "339", "runtime_version": "0.9.285", "runtime_build": "v2321-usb-clean-identity-rodata", "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64", "bootloader": "A908NKSU5EWA3", "debug_level": "0x494d", "force_upload": "0", "dump_sink": "0"}, "selftest": {"passed": 11, "warn": 1, "fail": 0, "duration": 43, "entries": 12}},
                "cleanup_ok": True,
                "current_boot_attestation": attestation,
                "boot_id_before_read": BOOT_ID,
                "boot_id_before_read_sha256": probe.sha256_bytes(BOOT_ID.encode()),
                "semantic_claim_path": str(claim_path),
                "semantic_claim_sha256": claim_hash,
                "semantic_claim_size": claim_size,
                "semantic_claim_key_sha256": claim_key,
                "semantic_claimed": True,
                "panic_on_oops_restored": True,
                "panic_on_oops_before": 1,
                "panic_on_oops_zero_set": True,
                "panic_on_oops_zero_verified": True,
                "panic_restore_deferred": False,
                "panic_transition": panic_transition,
                "dispatch_returned": True,
                "dispatch_failed": False,
                "frames": control_frames,
            }
            control_raw_bytes = json.dumps(control_raw, sort_keys=True, separators=(",", ":")).encode()
            control_journal = {
                "schema": "sdm855-a90-inline-remapper-mid-journal-v1",
                "experiment_id": control_id,
                "mode": probe.MODE_CONTROL,
                "status": "CONTROL_VERIFIED",
                "outcome": "CONTROL_PASS",
                "completed_utc": completed,
                "candidate_sha256": probe.CONTROL_SHA256,
                "candidate_size": probe.BOOT_PREFIX_SIZE,
                "op": 4,
                "op_args": [],
                "fixed_op": {
                    "op": 4,
                    "args": [],
                    "buffer_size": probe.FIXED_OP_BUFFER_SIZE,
                    "buffer_sha256": probe.sha256_bytes(probe.build_fixed_op_buffer()),
                },
                "flash_journal": control_raw["flash_journal"],
                "value": "0x000000000000c071",
                "dispatch_count": 1,
                "effect_dispatched": True,
                "effect_ambiguous": False,
                "effect_replayed": False,
                "cleanup_ok": True,
                "target": control_raw["target"],
                "health_after": control_raw["health_after"],
                "panic_on_oops_restored": True,
                "panic_on_oops_before": 1,
                "panic_on_oops_zero_set": True,
                "panic_on_oops_zero_verified": True,
                "panic_restore_deferred": False,
                "panic_transition": panic_transition,
                "dispatch_returned": True,
                "dispatch_failed": False,
                "current_boot_attestation": attestation,
                "boot_id_before_read": BOOT_ID,
                "boot_id_before_read_sha256": probe.sha256_bytes(BOOT_ID.encode()),
                "fixed_op_measurement": control_raw["fixed_op_measurement"],
                "semantic_claim_path": str(claim_path),
                "semantic_claim_sha256": claim_hash,
                "semantic_claim_size": claim_size,
                "semantic_claim_key_sha256": claim_key,
                "semantic_claimed": True,
                "frames": control_frames,
            }
            control_journal_bytes = json.dumps(control_journal, sort_keys=True, separators=(",", ":")).encode()
            control_private = root / "evidence/private"
            control_public = root / "evidence/manifests"
            control_private.mkdir(parents=True, exist_ok=True)
            control_public.mkdir(parents=True, exist_ok=True)
            (control_private / f"{control_id}.json").write_bytes(control_raw_bytes)
            (control_private / f"{control_id}.journal.json").write_bytes(control_journal_bytes)
            control_manifest_obj = {
                "schema": "sdm855-a90-inline-remapper-mid-public-v1",
                "experiment_id": control_id,
                "mode": probe.MODE_CONTROL,
                "completed_utc": completed,
                "candidate_sha256": probe.CONTROL_SHA256,
                "candidate_size": probe.BOOT_PREFIX_SIZE,
                "target_verified": True,
                "target_evaluation": "VERIFIED",
                "target_model": "SM-A908N",
                "soc": "SM8150",
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
                "reboot_dispatched": False,
                "memory_or_mmio_writes": False,
                "partition_writes": False,
                "dispatch_returned": True,
                "dispatch_failed": False,
                "flash_journal_bound": True,
                "flash_profile": probe.MODE_CONTROL,
                "flash_image_sha256": probe.CONTROL_SHA256,
                "flash_readback_sha256": probe.CONTROL_SHA256,
                "flash_predecessor_sha256": probe.ROLLBACK_SHA256,
                "panic_transition": panic_transition,
                "current_boot_attestation": {
                    key: attestation[key]
                    for key in (
                        "sysfs_root",
                        "block_node",
                        "bs",
                        "count",
                        "expected_size",
                        "captured_size",
                        "expected_sha256",
                        "captured_sha256",
                        "stat",
                        "sectors",
                        "ro",
                        "hash_matches_candidate",
                        "size_matches_candidate",
                        "cleanup_ok",
                    )
                },
                "boot_id_before_read_sha256": probe.sha256_bytes(BOOT_ID.encode()),
                "fixed_op": {
                    "op": 4,
                    "args": [],
                    "buffer_size": probe.FIXED_OP_BUFFER_SIZE,
                    "buffer_sha256": probe.sha256_bytes(probe.build_fixed_op_buffer()),
                    "rc": 0,
                    "status": "ok",
                    "value": "0x000000000000c071",
                },
                "semantic_claim": {"filename": claim_path.name, "sha256": claim_hash, "size": claim_size, "key_sha256": claim_key},
                "flash_journal_sha256": probe.sha256_bytes(flash_bytes),
                "flash_journal_size": len(flash_bytes),
                "raw_snapshot_sha256": probe.sha256_bytes(control_raw_bytes),
                "raw_snapshot_size": len(control_raw_bytes),
                "journal_sha256": probe.sha256_bytes(control_journal_bytes),
                "journal_size": len(control_journal_bytes),
                "private_record": {
                    "filename": f"{control_id}.json",
                    "journal_filename": f"{control_id}.journal.json",
                },
            }
            control_manifest = probe._fixed_control_manifest_path(root)
            control_manifest.write_text(json.dumps(control_manifest_obj, sort_keys=True, separators=(",", ":")))
        elif mode == probe.MODE_READ:
            # A real control producer receipt owns this fixed path.  Preserve
            # it for the subsequent read authorization instead of replacing
            # it with a test-only summary.
            control_manifest = existing_control_manifest
        values = dict(
            experiment_id=(
                probe.CONTROL_EXPERIMENT_ID
                if mode == probe.MODE_CONTROL
                else probe.READ_SOURCE_EXPERIMENT_ID
            ),
            mode=mode,
            execute=True,
            host=probe.BRIDGE_HOST,
            port=probe.BRIDGE_PORT,
            timeout=1.0,
            flash_journal=flash_journal,
            journal=root / "evidence/private" / (
                f"{probe.CONTROL_EXPERIMENT_ID if mode == probe.MODE_CONTROL else probe.READ_SOURCE_EXPERIMENT_ID}.journal.json"
            ),
            output_root=root,
        )
        if mode == probe.MODE_READ:
            values["control_manifest"] = control_manifest
        return Namespace(**values)

    def _run_collect(
        self,
        root: Path,
        mode: str,
        value=probe.CONTROL_SENTINEL,
        *,
        op_exception: BaseException | None = None,
        final_health: bool = True,
        panic_value: int = 1,
        boot_hash: str | None = None,
        read_flash_completed: str | None = None,
        cmdline: bytes = CMDLINE,
        bad_complete_frame_id: str | None = None,
        bad_fixed_end_field: tuple[str, str] | None = None,
        bad_terminal_frame: tuple[str, bytes] | None = None,
        bad_tail_frame_id: str | None = None,
        bad_payloads: Mapping[str, bytes] | None = None,
        stophud_payload: bytes | None = None,
        stophud_results: list[tuple[int, str]] | None = None,
        rebind: bool = False,
        stophud_rebind_drift_attempt: int | None = None,
        drift_after_status: str | None = None,
        restore_exception: BaseException | None = None,
        op_return_error: bool = False,
        op_malformed_wrapper: bool = False,
    ):
        frozen_now: dt.datetime | None = None
        if mode == probe.MODE_READ:
            control_path = probe._fixed_control_manifest_path(root)
            if not control_path.exists() and not control_path.is_symlink():
                control_result, _control_session, _control_ids = self._run_collect(
                    root, probe.MODE_CONTROL
                )
                self.assertIsNotNone(control_result)
            try:
                control_record = json.loads(control_path.read_text())
                control_completed = dt.datetime.fromisoformat(
                    str(control_record["completed_utc"])
                )
                if read_flash_completed is None:
                    read_flash_completed = (
                        control_completed + dt.timedelta(seconds=1)
                    ).isoformat()
                frozen_now = control_completed + dt.timedelta(seconds=2)
            except (KeyError, OSError, TypeError, ValueError):
                frozen_now = None
        args = self._args(root, mode, read_flash_completed=read_flash_completed)
        session = FakeSession(value, op_exception)
        session.restore_exception = restore_exception
        binding = target_binding()
        rebinding = dict(binding)
        if rebind:
            rebinding["process_pid"] = 999
        exchange_ids: list[str] = []
        stop_results = list(stophud_results or [(0, "ok")])
        selected_boot_hash = boot_hash or probe.EXPECTED_CANDIDATE_HASHES[mode]
        panic_state = panic_value

        def fake_exchange(host, port, command, timeout, *, allow_error=False):
            nonlocal panic_state
            del host, port, timeout
            exchange_ids.append(command.evidence_id)
            def toybox(body: bytes = b"", *, argc: int = 5) -> FakeFrame:
                payload = b"run: pid=1, q/Ctrl-C cancels\n" + body
                if body and not body.endswith(b"\n"):
                    payload += b"\n"
                payload += b"[exit 0]\n"
                return FakeFrame(payload, "run", argc=argc)

            if command.evidence_id == "stophud":
                self.assertTrue(allow_error)
                self.assertEqual(command.argv, ("stophud",))
                rc, status = stop_results.pop(0) if stop_results else (0, "ok")
                payload = stophud_payload
                if payload is None:
                    payload = (
                        b"autohud: stopped"
                        if rc == 0 and status == "ok"
                        else b""
                    )
                return FakeFrame(payload, "stophud", rc=rc, status=status)
            if command.evidence_id == "fixed_op_4":
                if op_return_error:
                    return FakeFrame(b"unexpected\n", "run", rc=1, status="error")
                if op_malformed_wrapper:
                    session._op_values(4, (), replay_safe=False)
                    return FakeFrame(b"unexpected\n", "run", rc=0, status="ok")
                op_values = session._op_values(4, (), replay_safe=False)
                return FakeFrame(
                    b"run: pid=1, q/Ctrl-C cancels\n"
                    + f"A90R{int(op_values[0]):x}\n[exit 0]\n".encode(),
                    "run",
                )
            if command.evidence_id == "panic_set_0":
                self.assertEqual(
                    command.argv,
                    ("writefile", "/proc/sys/kernel/panic_on_oops", "0"),
                )
                session.panic_values.append(0)
                panic_state = 0
                return FakeFrame(b"", "writefile")
            if command.evidence_id == "panic_set_1":
                self.assertEqual(
                    command.argv,
                    ("writefile", "/proc/sys/kernel/panic_on_oops", "1"),
                )
                session.panic_values.append(1)
                if restore_exception is not None:
                    raise restore_exception
                panic_state = 1
                return FakeFrame(b"", "writefile")
            if command.evidence_id in {"version_before", "version_after"}:
                return FakeFrame(VERSION, "version")
            if command.evidence_id in {"cmdline_before", "cmdline_after"}:
                if command.evidence_id == "cmdline_after" and not final_health:
                    raise RuntimeError("final cmdline unavailable")
                return FakeFrame(cmdline, "cat")
            if command.evidence_id in {"soc_id_before", "soc_id_after"}:
                return FakeFrame(b"339\n", "cat")
            if command.evidence_id in {"selftest_before", "selftest_after"}:
                if command.evidence_id == "selftest_after" and not final_health:
                    raise RuntimeError("final selftest unavailable")
                return FakeFrame(SELFTEST, "selftest")
            if command.evidence_id == "panic_before":
                return FakeFrame(f"{panic_value}\n".encode(), "cat")
            if command.evidence_id in {"panic_zero_verify", "panic_restore_verify"}:
                return FakeFrame(f"{panic_state}\n".encode(), "cat")
            if command.evidence_id == "boot_id_before_read":
                return FakeFrame(f"{BOOT_ID}\n".encode(), "cat")
            if command.evidence_id == "boot_sysfs_uevent":
                return FakeFrame(UEVENT, "cat")
            if command.evidence_id == "boot_sysfs_size":
                return FakeFrame(b"131072\n", "cat")
            if command.evidence_id == "boot_sysfs_ro":
                return FakeFrame(b"0\n", "cat")
            if command.evidence_id.startswith("boot_attest_"):
                expected_argv = {
                    "boot_attest_remove_node": (
                        "run", "/bin/toybox", "rm", "-f", probe.BOOT_ATTEST_NODE
                    ),
                    "boot_attest_remove_file": (
                        "run", "/bin/toybox", "rm", "-f", probe.BOOT_ATTEST_FILE
                    ),
                    "boot_attest_node_absent": (
                        "run", "/bin/toybox", "test", "!", "-e", probe.BOOT_ATTEST_NODE
                    ),
                    "boot_attest_node_absent_not_symlink": (
                        "run", "/bin/toybox", "test", "!", "-L", probe.BOOT_ATTEST_NODE
                    ),
                    "boot_attest_file_absent": (
                        "run", "/bin/toybox", "test", "!", "-e", probe.BOOT_ATTEST_FILE
                    ),
                    "boot_attest_file_absent_not_symlink": (
                        "run", "/bin/toybox", "test", "!", "-L", probe.BOOT_ATTEST_FILE
                    ),
                    "boot_attest_pre_node_absent": (
                        "run", "/bin/toybox", "test", "!", "-e", probe.BOOT_ATTEST_NODE
                    ),
                    "boot_attest_pre_node_absent_not_symlink": (
                        "run", "/bin/toybox", "test", "!", "-L", probe.BOOT_ATTEST_NODE
                    ),
                    "boot_attest_pre_file_absent": (
                        "run", "/bin/toybox", "test", "!", "-e", probe.BOOT_ATTEST_FILE
                    ),
                    "boot_attest_pre_file_absent_not_symlink": (
                        "run", "/bin/toybox", "test", "!", "-L", probe.BOOT_ATTEST_FILE
                    ),
                    "boot_attest_mkdir": (
                        "run", "/bin/toybox", "mkdir", "-p", probe.BOOT_ATTEST_DIR
                    ),
                    "boot_attest_hash": (
                        "run", "/bin/toybox", "sha256sum", probe.BOOT_ATTEST_FILE
                    ),
                    "boot_attest_size": (
                        "run", "/bin/toybox", "wc", "-c", probe.BOOT_ATTEST_FILE
                    ),
                    "boot_attest_capture": (
                        "run", "/bin/toybox", "dd",
                        f"if={probe.BOOT_ATTEST_NODE}",
                        f"of={probe.BOOT_ATTEST_FILE}",
                        "bs=4096", "count=14864", "conv=fsync", "status=none",
                    ),
                    "boot_attest_mknod": (
                        "mknodb", probe.BOOT_ATTEST_NODE, "259", "27"
                    ),
                }
                if command.evidence_id in expected_argv:
                    self.assertEqual(command.argv, expected_argv[command.evidence_id])
                if command.evidence_id == "boot_attest_stat_node":
                    self.assertEqual(command.argv, ("stat", probe.BOOT_ATTEST_NODE))
                    return FakeFrame(
                        b"mode=0600 uid=0 gid=0 size=0\n"
                        b"rdev=259:27\n",
                        "stat",
                    )
                if command.evidence_id == "boot_attest_hash":
                    return toybox(
                        f"{selected_boot_hash}  {probe.BOOT_ATTEST_FILE}".encode(),
                        argc=len(command.argv),
                    )
                if command.evidence_id == "boot_attest_size":
                    return toybox(
                        f"60882944 {probe.BOOT_ATTEST_FILE}".encode(),
                        argc=len(command.argv),
                    )
                if command.argv and command.argv[0] == "run":
                    return toybox(argc=len(command.argv))
                return FakeFrame(b"", command.argv[0])
            raise AssertionError(command.evidence_id)

        rebind_calls = 0

        def fake_revalidate(initial: Mapping[str, object]) -> Mapping[str, object]:
            nonlocal rebind_calls
            rebind_calls += 1
            if stophud_rebind_drift_attempt == rebind_calls:
                return {**initial, "process_pid": 999}
            if drift_after_status is not None:
                journal_path = root / "evidence/private" / f"{args.experiment_id}.journal.json"
                if journal_path.exists():
                    try:
                        journal_status = json.loads(journal_path.read_text()).get("status")
                    except (OSError, ValueError):
                        journal_status = None
                    if journal_status == drift_after_status:
                        return {**initial, "process_pid": 999}
            if rebind:
                return rebinding
            return dict(binding)

        stable_digest = probe._stable_file_digest
        def mutate_complete_frame(frame: FakeFrame, command: probe.Command) -> FakeFrame:
            if bad_payloads is not None and command.evidence_id in bad_payloads:
                payload = bad_payloads[command.evidence_id]
                begin_matches = list(probe.BEGIN_RE.finditer(frame.transcript))
                terminal = probe._PROTOCOL_TERMINAL_RE.search(frame.transcript)
                if len(begin_matches) != 1 or terminal is None:
                    raise AssertionError("test frame lacks replaceable protocol body")
                frame.payload = payload
                frame.transcript = (
                    frame.transcript[: begin_matches[0].end()]
                    + payload
                    + frame.transcript[terminal.start() :]
                )
            if command.evidence_id == bad_complete_frame_id:
                expected = probe.protocol_flags_for_argv(command.argv)
                if expected is None:
                    raise AssertionError(command.argv)
                wrong = "0x2" if expected == "0x0" else "0x0"
                frame.begin["flags"] = wrong
                frame.end["flags"] = wrong
                frame.transcript = frame.transcript.replace(
                    f"flags={expected}".encode("ascii"),
                    f"flags={wrong}".encode("ascii"),
                )
            if command.evidence_id == "fixed_op_4" and bad_fixed_end_field is not None:
                field, replacement = bad_fixed_end_field
                original = frame.end[field]
                frame.end[field] = replacement
                frame.transcript = frame.transcript.replace(
                    f"{field}={original}".encode("ascii"),
                    f"{field}={replacement}".encode("ascii"),
                )
            if bad_terminal_frame is not None and command.evidence_id == bad_terminal_frame[0]:
                match = probe._PROTOCOL_TERMINAL_RE.search(frame.transcript)
                if match is None:
                    raise AssertionError("test frame lacks terminal marker")
                replacement = bad_terminal_frame[1]
                if not replacement.endswith(b"\n"):
                    replacement += b"\n"
                if match.group(0).startswith(b"\n"):
                    replacement = b"\n" + replacement
                frame.transcript = (
                    frame.transcript[: match.start()]
                    + replacement
                    + frame.transcript[match.end() :]
                )
            if command.evidence_id == bad_tail_frame_id:
                frame.transcript += b"garbage-after-end"
            return frame

        original_fake_exchange = fake_exchange

        def guarded_fake_exchange(host, port, command, timeout, *, allow_error=False):
            frame = original_fake_exchange(
                host, port, command, timeout, allow_error=allow_error
            )
            return mutate_complete_frame(frame, command)

        patches = [
            mock.patch.object(
                probe,
                "DEFAULT_CANDIDATES",
                {mode: root / "candidate.img"},
            ),
            mock.patch.object(probe, "REPO_ROOT", root),
            mock.patch.object(
                probe,
                "_validate_local_transport",
                return_value={
                    "source_size": probe.LOCAL_TRANSPORT_SOURCE_SIZE,
                    "source_sha256": probe.LOCAL_TRANSPORT_SOURCE_SHA256,
                },
            ),
            mock.patch.object(
                probe,
                "_stable_file_digest",
                side_effect=lambda path: (
                    (probe.BOOT_PREFIX_SIZE, probe.EXPECTED_CANDIDATE_HASHES[mode])
                    if Path(path).name == "candidate.img"
                    else stable_digest(path)
                ),
            ),
            mock.patch.object(probe, "validate_bridge_binding", return_value=binding),
            mock.patch.object(
                probe,
                "revalidate_bridge_binding",
                side_effect=fake_revalidate,
            ),
            mock.patch.object(probe, "exchange", side_effect=guarded_fake_exchange),
        ]
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            if frozen_now is not None:
                class FrozenDateTime(dt.datetime):
                    @classmethod
                    def now(cls, tz=None):
                        if tz is None:
                            return cls(
                                frozen_now.year,
                                frozen_now.month,
                                frozen_now.day,
                                frozen_now.hour,
                                frozen_now.minute,
                                frozen_now.second,
                            )
                        return cls(
                            frozen_now.year,
                            frozen_now.month,
                            frozen_now.day,
                            frozen_now.hour,
                            frozen_now.minute,
                            frozen_now.second,
                            tzinfo=tz,
                        )

                stack.enter_context(
                    mock.patch.object(probe.dt, "datetime", FrozenDateTime)
                )
            try:
                result = probe.collect(args)
            except probe.ProbeError:
                result = None
        return result, session, exchange_ids

    def test_exact_target_cmdline_and_fixed_pins(self) -> None:
        target = probe.validate_target(VERSION, CMDLINE, b"339\n")
        self.assertEqual(target["model"], "SM-A908N")
        self.assertEqual(target["soc"], "SM8150")
        self.assertEqual(target["debug_level"], "0x494d")
        self.assertEqual(probe.BOOT_PREFIX_SIZE, 60_882_944)
        self.assertEqual(probe.OP_FIXED_READ, 4)
        self.assertEqual(len(probe.LOCAL_TRANSPORT_SOURCE_SHA256), 64)
        self.assertEqual(probe.BOOT_ATTEST_NODE, "/tmp/a90-native/verification-024-sda24")
        with self.assertRaisesRegex(probe.ProbeError, "DMID"):
            probe.validate_target(VERSION, CMDLINE.replace(b"0x494d", b"0x4f4c"), b"339\n")
        with self.assertRaisesRegex(probe.ProbeError, "soc_id"):
            probe.validate_target(VERSION, CMDLINE, b"356\n")

    def test_every_pre_effect_complete_frame_is_validated_before_next_exchange(self) -> None:
        pre_effect_ids = (
            "version_before",
            "cmdline_before",
            "soc_id_before",
            "selftest_before",
            "panic_before",
            "boot_attest_mkdir",
            "boot_id_before_read",
        )
        for evidence_id in pre_effect_ids:
            with self.subTest(evidence_id=evidence_id), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_complete_frame_id=evidence_id,
                )
                self.assertIsNone(result)
                self.assertNotIn("fixed_op_4", exchange_ids)
                self.assertNotIn("panic_set_0", exchange_ids)
                self.assertEqual(session.panic_values, [])
                self.assertLess(
                    exchange_ids.index(evidence_id),
                    len(exchange_ids),
                )

        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory),
                probe.MODE_CONTROL,
                bad_complete_frame_id="panic_zero_verify",
            )
            self.assertIsNone(result)
            self.assertIn("panic_set_0", exchange_ids)
            self.assertIn("panic_zero_verify", exchange_ids)
            self.assertNotIn("fixed_op_4", exchange_ids)
            self.assertEqual(session.panic_values, [0])
            self.assertNotIn("panic_set_1", exchange_ids)

        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory),
                probe.MODE_CONTROL,
                bad_complete_frame_id="stophud",
            )
            self.assertIsNone(result)
            self.assertEqual(exchange_ids, ["stophud"])
            self.assertNotIn("fixed_op_4", exchange_ids)
            self.assertEqual(session.panic_values, [])

    def test_fixed_returned_frame_result_bindings_cannot_bypass_restore(self) -> None:
        for field, replacement in (("errno", "1"), ("duration_ms", "-1")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_fixed_end_field=(field, replacement),
                )
                self.assertIsNone(result)
                self.assertEqual(session.panic_values, [0, 1])
                self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
                self.assertEqual(exchange_ids.count("panic_set_1"), 1)
                self.assertEqual(exchange_ids.count("panic_restore_verify"), 1)
                self.assertNotIn("version_after", exchange_ids)
                public = json.loads(
                    (
                        Path(directory)
                        / "evidence/manifests/verification-024-control.manifest.json"
                    ).read_text()
                )
                self.assertEqual(public["outcome"], "INCIDENT")

    def test_terminal_kind_and_tail_are_bound_before_continuation(self) -> None:
        stophud_cases = (
            ([(0, "ok")], b"[busy] auto menu active; send hide/q before command\n"),
            ([(-16, "busy")], b"[done] stophud (0ms)\n"),
        )
        for stop_results, marker in stophud_cases:
            with self.subTest(stophud=stop_results, marker=marker), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    stophud_results=stop_results,
                    bad_terminal_frame=("stophud", marker),
                )
                self.assertIsNone(result)
                self.assertEqual(exchange_ids, ["stophud"])
                self.assertEqual(session.panic_values, [])
                self.assertNotIn("fixed_op_4", exchange_ids)

        for marker in (
            b"[err] run rc=0 (0ms)\n",
            b"[busy] auto menu active; send hide/q before command\n",
        ):
            with self.subTest(fixed_marker=marker), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_terminal_frame=("fixed_op_4", marker),
                )
                self.assertIsNone(result)
                self.assertEqual(session.panic_values, [0, 1])
                self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
                self.assertEqual(exchange_ids.count("panic_set_1"), 1)
                self.assertEqual(exchange_ids.count("panic_restore_verify"), 1)
                self.assertEqual(exchange_ids.count("version_after"), 0)

        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory),
                probe.MODE_CONTROL,
                bad_tail_frame_id="fixed_op_4",
            )
            self.assertIsNone(result)
            self.assertEqual(session.panic_values, [0, 1])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertNotIn("version_after", exchange_ids)

    def test_stophud_evidence_size_bound_matches_shared_contract(self) -> None:
        self.assertEqual(probe.STOPHUD_MAX_PAYLOAD_BYTES, 20)
        self.assertEqual(probe.STOPHUD_MAX_TRANSCRIPT_BYTES, 4096)
        base = FakeFrame(b"autohud: stopped", "stophud").transcript
        for target in (
            probe.STOPHUD_MAX_TRANSCRIPT_BYTES - 1,
            probe.STOPHUD_MAX_TRANSCRIPT_BYTES,
        ):
            with self.subTest(target=target):
                frame = FakeFrame(b"autohud: stopped", "stophud")
                prefix_size = target - len(frame.transcript)
                frame.transcript = b"x" * (prefix_size - 1) + b"\n" + frame.transcript
                probe.validate_complete_frame(
                    frame,
                    ("stophud",),
                    "boundary stophud",
                    allow_stophud_busy=True,
                )

        for transcript in (
            b"x"
            * (probe.STOPHUD_MAX_TRANSCRIPT_BYTES + 1 - len(base) - 1)
            + b"\n"
            + base,
            base + b"x" * (probe.STOPHUD_MAX_TRANSCRIPT_BYTES + 1 - len(base)),
        ):
            with self.subTest(transcript_size=len(transcript)):
                frame = FakeFrame(b"autohud: stopped", "stophud")
                frame.transcript = transcript
                with self.assertRaises(probe.ProbeError):
                    probe.validate_complete_frame(
                        frame,
                        ("stophud",),
                        "oversized stophud",
                        allow_stophud_busy=True,
                    )

    def test_actual_mocked_producer_output_round_trips_through_finalizer(self) -> None:
        """Use ``collect`` output itself, not a hand-built summary, as input."""

        from tools import a90_verification024_finalize as finalizer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, _session, _exchange_ids = self._run_collect(
                root, probe.MODE_CONTROL
            )
            self.assertIsNotNone(result)
            assert result is not None
            raw = json.loads(result[0].read_text())
            public = json.loads(result[1].read_text())
            self.assertEqual(
                {key: raw[key] for key in ("effect_dispatched", "dispatch_returned", "dispatch_failed")},
                {"effect_dispatched": True, "dispatch_returned": True, "dispatch_failed": False},
            )
            self.assertEqual(
                {key: public[key] for key in ("effect_dispatched", "dispatch_returned", "dispatch_failed")},
                {"effect_dispatched": True, "dispatch_returned": True, "dispatch_failed": False},
            )
            control = finalizer.validate_control(result[1], root)
            self.assertEqual(control["value"], "0x000000000000c071")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control_result, _session, _exchange_ids = self._run_collect(
                root, probe.MODE_CONTROL
            )
            self.assertIsNotNone(control_result)
            assert control_result is not None
            control = finalizer.validate_control(
                root / "evidence/manifests/verification-024-control.manifest.json",
                root,
            )
            result, _session, _exchange_ids = self._run_collect(
                root, probe.MODE_READ, value=0x1234
            )
            self.assertIsNotNone(result)
            assert result is not None
            read = finalizer.validate_read(result[1], root, control)
            self.assertTrue(read["value_present"])
            self.assertEqual(read["value"], "0x0000000000001234")

    def test_stat_parser_accepts_live_framing_and_closed_terminal_variants(self) -> None:
        live = b"mode=0600 uid=0 gid=0 size=0\r\nrdev=259:27"
        self.assertEqual(len(live), 41)
        self.assertEqual(
            hashlib.sha256(live).hexdigest(),
            "774a5e3b7e833ee1573bc79732a73bd1fc2bbaa95340d238ae89fd5c42a03edc",
        )
        for payload in (
            live,
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27",
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=259:27\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\n",
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=259:27\r\n",
        ):
            with self.subTest(payload=payload):
                parsed = probe._parse_stat_identity(payload)
                self.assertEqual(
                    parsed,
                    {
                        "mode": "0600",
                        "uid": "0",
                        "gid": "0",
                        "size": "0",
                        "rdev": "259:27",
                    },
                )
        parsed = probe._parse_stat_identity(live)
        self.assertEqual(
            parsed,
            {
                "mode": "0600",
                "uid": "0",
                "gid": "0",
                "size": "0",
                "rdev": "259:27",
            },
        )

    def test_stat_parser_rejects_missing_duplicate_wrong_and_malformed_fields(self) -> None:
        valid = b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\n"
        invalid = (
            b"uid=0 gid=0 size=0\nrdev=259:27\n",  # missing mode
            b"mode=0600 mode=0600 uid=0 gid=0 size=0\nrdev=259:27\n",  # duplicate
            b"mode=0600  uid=0 gid=0 size=0\nrdev=259:27\n",  # double space
            b"mode=0600\tuid=0 gid=0 size=0\nrdev=259:27\n",  # tab space
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27 \n",  # rdev trailing space
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\r",  # bare CR
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:28\n",  # wrong rdev
            b"mode=0680 uid=0 gid=0 size=0\nrdev=259:27\n",  # malformed mode
            b"mode=0600 uid=x gid=0 size=0\nrdev=259:27\n",  # malformed decimal
            b"mode=0600 uid=0 gid=0 size=0 rdev=259:27\n",  # wrong line contract
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\nextra",  # extra line
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\n\n",  # empty line
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\x00\n",  # NUL
            b"mode=0600 uid=0 gid=0 size=0\nrdev=259:27\xff\n",  # non-ASCII
            b"mode=0600 uid=0 gid=0 size=0\nfoo=bar\nrdev=259:27\n",  # unknown line
        )
        self.assertEqual(probe._parse_stat_identity(valid)["rdev"], "259:27")
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(probe.ProbeError):
                    probe._parse_stat_identity(payload)

    def test_stat_parser_rejects_nonexact_metadata_values(self) -> None:
        for field, value in (
            ("mode", "0644"),
            ("uid", "1"),
            ("gid", "1"),
            ("size", "1"),
        ):
            payload = (
                f"mode={value if field == 'mode' else '0600'} "
                f"uid={value if field == 'uid' else '0'} "
                f"gid={value if field == 'gid' else '0'} "
                f"size={value if field == 'size' else '0'}\n"
                "rdev=259:27\n"
            ).encode()
            with self.subTest(field=field):
                with self.assertRaises(probe.ProbeError):
                    probe._parse_stat_identity(payload)

    def test_execute_gate_rejects_omission_before_any_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root, probe.MODE_CONTROL)
            args.execute = False
            with mock.patch.object(probe, "REPO_ROOT", root), mock.patch.object(
                probe, "_stable_file_digest"
            ) as digest, mock.patch.object(
                probe, "validate_bridge_binding"
            ) as bind, mock.patch.object(probe, "exchange") as contact:
                with self.assertRaisesRegex(probe.ProbeError, "--execute"):
                    probe.collect(args)
            digest.assert_not_called()
            bind.assert_not_called()
            contact.assert_not_called()

    def test_read_requires_control_manifest_and_control_rejects_option_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            read_args = self._args(root, probe.MODE_READ)
            read_args.control_manifest = None
            with mock.patch.object(probe, "REPO_ROOT", root), mock.patch.object(
                probe, "_stable_file_digest"
            ) as digest, mock.patch.object(
                probe, "validate_bridge_binding"
            ) as bind, mock.patch.object(probe, "exchange") as contact:
                with self.assertRaisesRegex(probe.ProbeError, "control_manifest"):
                    probe.collect(read_args)
            digest.assert_not_called()
            bind.assert_not_called()
            contact.assert_not_called()

            control_args = self._args(root, probe.MODE_CONTROL)
            control_args.control_manifest = root / "evidence/manifests/unused.json"
            with mock.patch.object(probe, "REPO_ROOT", root), mock.patch.object(
                probe, "_stable_file_digest"
            ) as digest, mock.patch.object(
                probe, "validate_bridge_binding"
            ) as bind, mock.patch.object(probe, "exchange") as contact:
                with self.assertRaisesRegex(probe.ProbeError, "rejects"):
                    probe.collect(control_args)
            digest.assert_not_called()
            bind.assert_not_called()
            contact.assert_not_called()

    def test_attestation_cleanup_binding_drift_sends_no_later_mutation(self) -> None:
        frames: list[dict[str, object]] = []
        commands: list[str] = []
        binding = {"serial": "pinned", "pid": 1}
        rebind_count = 0

        def rebind(initial):
            nonlocal rebind_count
            rebind_count += 1
            if rebind_count == 2:
                drift = dict(initial)
                drift["pid"] = 999
                return drift
            return dict(initial)

        def exchange(host, port, command, timeout):
            del host, port, timeout
            commands.append(command.evidence_id)
            if command.evidence_id == "boot_sysfs_uevent":
                return FakeFrame(UEVENT, "cat")
            if command.evidence_id == "boot_sysfs_size":
                return FakeFrame(b"131072\n", "cat")
            if command.evidence_id == "boot_sysfs_ro":
                return FakeFrame(b"0\n", "cat")
            return FakeFrame(b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n", command.argv[0])

        with self.assertRaises(probe.ProbeError):
            probe.attest_current_boot(
                probe.BRIDGE_HOST,
                probe.BRIDGE_PORT,
                1.0,
                probe.CONTROL_SHA256,
                frames,
                bridge_binding=binding,
                exchange_fn=exchange,
                revalidate_fn=rebind,
            )
        self.assertNotIn("boot_attest_remove_node", commands)
        self.assertNotIn("boot_attest_mkdir", commands)

    def test_fixed_op_buffer_and_extended_argv_are_exact(self) -> None:
        buffer = probe.build_fixed_op_buffer()
        self.assertEqual(len(buffer), 0x58)
        self.assertEqual(struct.unpack_from("<Q", buffer, 0)[0], 0xA90C0DE5DEADBEEF)
        self.assertEqual(buffer[8], 4)
        self.assertEqual(buffer[9:], b"\0" * (0x58 - 9))
        argv = probe.fixed_op_argv()
        self.assertEqual(argv[:3], ("run", "/bin/busybox", "sh"))
        self.assertEqual(argv[3], "-c")
        self.assertIn("printf '", argv[4])
        self.assertIn("/sys/class/kgsl/kgsl-3d0/force_no_nap", argv[4])
        self.assertIn("tail -n 16", argv[4])
        self.assertIn("before_log=$(dmesg", argv[4])
        self.assertIn("before_count", argv[4])
        self.assertIn("tail -n +$((before_count + 1))", argv[4])
        self.assertNotIn("dmesg -c", argv[4])
        command = probe.ExtendedCommand("fixed_op_4", argv)
        self.assertNotIn(b"dmesg -c", command.wire)
        encoded_fields = command.wire[len(b"cmdv1x ") : -1].split()
        self.assertEqual(
            encoded_fields[:4],
            [
                b"3:72756e",
                b"12:2f62696e2f62757379626f78",
                b"2:7368",
                b"2:2d63",
            ],
        )
        self.assertTrue(command.wire.endswith(b"\n"))

    def test_toybox_wrapper_requires_terminal_run_and_exit(self) -> None:
        valid = b"run: pid=1, q/Ctrl-C cancels\nhello\n[exit 0]\n"
        self.assertEqual(probe.parse_toybox_payload(valid, "fixture"), b"hello")
        invalid = (
            b"hello\nrun: pid=1, q/Ctrl-C cancels\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\ntrailing\n",
            b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\nrun: pid=2, q/Ctrl-C cancels\n[exit 0]\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(probe.ProbeError):
                    probe.parse_toybox_payload(payload, "fixture")

    def test_toybox_wc_count_requires_canonical_unsigned_decimal(self) -> None:
        path = probe.BOOT_ATTEST_FILE

        def wrapped(body: bytes) -> bytes:
            return (
                b"run: pid=1, q/Ctrl-C cancels\n"
                + body
                + b"\n[exit 0]\n"
            )

        self.assertEqual(
            probe.parse_toybox_wc_count(
                wrapped(f"60882944 {path}".encode("ascii")), path
            ),
            60882944,
        )
        for body in (
            f"060882944 {path}".encode("ascii"),
            f"00 {path}".encode("ascii"),
            f"+60882944 {path}".encode("ascii"),
        ):
            with self.subTest(body=body):
                with self.assertRaises(probe.ProbeError):
                    probe.parse_toybox_wc_count(wrapped(body), path)

    def test_fixed_op_requires_one_complete_a90r_record(self) -> None:
        valid = b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\n[exit 0]\n"
        self.assertEqual(probe.parse_fixed_op_result(valid), (0xC071, "A90Rc071"))
        invalid = (
            b"run: pid=1, q/Ctrl-C cancels\nA90Rc071garbage\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\nxxA90Rc071\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\nA90Rc071\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\ntrailing\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\nA90RC071\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\nA90R000c071\n[exit 0]\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(probe.OperationReturnedError):
                    probe.parse_fixed_op_result(payload)

    def test_pre_read_boot_id_requires_one_exact_terminal_line(self) -> None:
        self.assertEqual(probe.parse_boot_id(f"{BOOT_ID}\n".encode()), BOOT_ID)
        for payload in (
            f" {BOOT_ID}\n".encode(),
            f"{BOOT_ID} \n".encode(),
            f"{BOOT_ID}\n\n".encode(),
            f"{BOOT_ID}\r\nextra".encode(),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(probe.ProbeError):
                    probe.parse_boot_id(payload)

    def test_semantic_claim_serializes_same_boot_mode_and_candidate_owners(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_path, first_data, first_key = probe._semantic_claim(
                root,
                probe.MODE_READ,
                probe.READ_SHA256,
                probe.BOOT_PREFIX_SIZE,
                BOOT_ID,
                "first-owner",
            )
            self.assertTrue(first_path.exists())
            self.assertEqual(first_key, json.loads(first_path.read_text())["key_sha256"])
            self.assertEqual(first_data, first_path.read_bytes())
            with self.assertRaisesRegex(probe.ProbeError, "already exists"):
                probe._semantic_claim(
                    root,
                    probe.MODE_READ,
                    probe.READ_SHA256,
                    probe.BOOT_PREFIX_SIZE,
                    BOOT_ID,
                    "second-owner",
                )
            # A different boot session is a distinct semantic key and does
            # not collide with the first owner.
            second_path, _, second_key = probe._semantic_claim(
                root,
                probe.MODE_READ,
                probe.READ_SHA256,
                probe.BOOT_PREFIX_SIZE,
                "22222222-2222-4222-8222-222222222222",
                "second-owner",
            )
            self.assertNotEqual(first_key, second_key)
            self.assertTrue(second_path.exists())

    def test_semantic_claim_concurrent_owners_have_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "evidence/private" / "initial.journal.json"
            probe._exclusive_json(journal_path, {"status": "INTENT"})
            with self.assertRaisesRegex(probe.ProbeError, "already exists"):
                probe._exclusive_json(journal_path, {"status": "other"})
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def owner(experiment_id: str) -> None:
                barrier.wait()
                try:
                    probe._semantic_claim(
                        root,
                        probe.MODE_CONTROL,
                        probe.CONTROL_SHA256,
                        probe.BOOT_PREFIX_SIZE,
                        BOOT_ID,
                        experiment_id,
                    )
                except probe.ProbeError:
                    outcomes.append("lost")
                else:
                    outcomes.append("won")

            threads = [threading.Thread(target=owner, args=(f"owner-{index}",)) for index in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes), ["lost", "won"])

    def test_local_transport_source_is_stable_and_hash_pinned(self) -> None:
        self.assertEqual(
            probe._validate_local_transport()["source_sha256"],
            probe.LOCAL_TRANSPORT_SOURCE_SHA256,
        )
        with mock.patch.object(
            probe,
            "_stable_file_digest",
            return_value=(probe.LOCAL_TRANSPORT_SOURCE_SIZE, "0" * 64),
        ):
            with self.assertRaisesRegex(probe.ProbeError, "source SHA-256"):
                probe._validate_local_transport()
        with mock.patch.object(probe.native_transport, "__file__", "/tmp/other.py"):
            with self.assertRaisesRegex(probe.ProbeError, "module path"):
                probe._validate_local_transport()

    def test_transport_source_mismatch_precedes_any_bridge_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root, probe.MODE_CONTROL)
            image = root / "candidate.img"
            bridge = mock.Mock()

            def stable(path):
                if Path(path).name == "candidate.img":
                    return probe.BOOT_PREFIX_SIZE, probe.CONTROL_SHA256
                return probe.LOCAL_TRANSPORT_SOURCE_SIZE, "0" * 64

            with mock.patch.object(probe, "REPO_ROOT", root), mock.patch.object(
                probe, "DEFAULT_CANDIDATES", {probe.MODE_CONTROL: image}
            ), mock.patch.object(
                probe, "_stable_file_digest", side_effect=stable
            ), mock.patch.object(
                probe.native_transport, "__file__", str(root / "tools/a90_pa28_live.py")
            ), mock.patch.object(
                probe, "validate_bridge_binding", bridge
            ), mock.patch.object(probe, "exchange"):
                with self.assertRaisesRegex(probe.ProbeError, "source SHA-256"):
                    probe.collect(args)
            bridge.assert_not_called()

    def test_cmdline_rejects_malformed_and_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(probe.ProbeError, "duplicate"):
            probe.parse_cmdline(CMDLINE.rstrip() + b" androidboot.debug_level=0x494d\n")
        with self.assertRaisesRegex(probe.ProbeError, "malformed"):
            probe.parse_cmdline(b"androidboot.debug_level=0x494d malformed\n")

    def test_cmdline_accepts_ascii_space_runs_and_rejects_other_whitespace(self) -> None:
        expected = probe.parse_cmdline(CMDLINE)
        for count in (2, 3, 9):
            with self.subTest(space_count=count):
                spaced = CMDLINE[:-1].replace(b" ", b" " * count) + b"\n"
                self.assertEqual(probe.parse_cmdline(spaced), expected)
        body = CMDLINE[:-1]
        for whitespace in (b"\t", b"\v", b"\f", b"\r", b"\n"):
            with self.subTest(whitespace=whitespace):
                with self.assertRaises(probe.ProbeError):
                    probe.parse_cmdline(body.replace(b" ", whitespace, 1) + b"\n")
        with self.assertRaises(probe.ProbeError):
            probe.parse_cmdline(body.replace(b" ro ", b" ro  ro ") + b"\n")
        for bad in (
            b" " + CMDLINE,
            CMDLINE[:-1] + b" \n",
            CMDLINE + b"\n",
            CMDLINE[:-1] + b"\r\n\n",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(probe.ProbeError):
                    probe.parse_cmdline(bad)

    def test_double_space_live_cmdline_matches_finalizer_parser(self) -> None:
        live_shape = CMDLINE[:-1].replace(
            b"androidboot.bootloader=", b"  androidboot.bootloader=", 1
        ) + b"\n"
        self.assertEqual(
            probe.parse_cmdline(live_shape),
            finalizer.inline_parse_cmdline(live_shape),
        )

    def test_classification_map_failure_precedes_mode(self) -> None:
        self.assertEqual(probe.classify_value(probe.MODE_CONTROL, probe.MAP_FAILURE_RESULT), "MAP_FAILED")
        self.assertEqual(probe.classify_value(probe.MODE_READ, probe.MAP_FAILURE_RESULT), "MAP_FAILED")
        self.assertEqual(probe.classify_value(probe.MODE_CONTROL, -1), "MAP_FAILED")
        self.assertEqual(probe.classify_value(probe.MODE_READ, 0), "READABLE_SECURITY_INDICATOR")

    def test_flash_journal_strict_provenance_duplicate_nan_oversize_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root, probe.MODE_CONTROL)
            self.assertEqual(
                probe.verify_flash_journal(args.flash_journal, probe.MODE_CONTROL, root=root)["size"],
                args.flash_journal.stat().st_size,
            )
            duplicate = args.flash_journal
            duplicate.write_text('{"schema":"x","schema":"y"}')
            with self.assertRaisesRegex(probe.ProbeError, "duplicate"):
                probe.verify_flash_journal(duplicate, probe.MODE_CONTROL, root=root)
            nan = args.flash_journal
            nan.write_text(json.dumps(self._flash_record(probe.MODE_CONTROL))[:-1] + ',"bad":NaN}\n')
            with self.assertRaisesRegex(probe.ProbeError, "non-finite"):
                probe.verify_flash_journal(nan, probe.MODE_CONTROL, root=root)
            oversized = args.flash_journal
            oversized.write_bytes(b"{" + b" " * probe.MAX_FLASH_JOURNAL_BYTES + b"}")
            with self.assertRaisesRegex(probe.ProbeError, "bounded"):
                probe.verify_flash_journal(oversized, probe.MODE_CONTROL, root=root)
            missing = args.flash_journal
            record = self._flash_record(probe.MODE_CONTROL)
            del record["final_target_serial_sha256"]
            missing.write_text(json.dumps(record))
            with self.assertRaisesRegex(probe.ProbeError, "final_target"):
                probe.verify_flash_journal(missing, probe.MODE_CONTROL, root=root)

            stable = args.flash_journal
            stable.write_text(json.dumps(self._flash_record(probe.MODE_CONTROL)))
            original_fstat = probe.os.fstat
            calls = 0

            def changing_fstat(fd):
                nonlocal calls
                calls += 1
                value = original_fstat(fd)
                if calls == 2:
                    fields = list(value)
                    fields[6] += 1
                    return os.stat_result(fields)
                return value

            with mock.patch.object(probe.os, "fstat", side_effect=changing_fstat):
                with self.assertRaisesRegex(probe.ProbeError, "changed"):
                    probe.verify_flash_journal(stable, probe.MODE_CONTROL, root=root)

    def test_flash_journal_symlink_and_local_candidate_toctou_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root, probe.MODE_CONTROL)
            link = root / "evidence/private/link.json"
            link.symlink_to(args.flash_journal)
            with self.assertRaisesRegex(probe.ProbeError, "symlink"):
                probe.verify_flash_journal(link, probe.MODE_CONTROL, root=root)

            image = root / "image.bin"
            image.write_bytes(b"candidate")
            parent = root / "parent-link"
            parent.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(probe.ProbeError, "parent component"):
                probe._stable_file_digest(parent / "image.bin")
            original = probe.os.fstat
            calls = 0

            def changing(fd):
                nonlocal calls
                calls += 1
                value = original(fd)
                if calls == 2:
                    fields = list(value)
                    fields[6] += 1
                    return os.stat_result(fields)
                return value

            with mock.patch.object(probe.os, "fstat", side_effect=changing):
                with self.assertRaisesRegex(probe.ProbeError, "changed"):
                    probe._stable_file_digest(image)

    def test_control_pass_uses_actual_fixed_helper_restores_panic_and_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory), probe.MODE_CONTROL, probe.CONTROL_SENTINEL,
                stophud_results=[(-16, "busy"), (-16, "busy"), (0, "ok")],
            )
            self.assertIsNotNone(result)
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(session.panic_values, [0, 1])
            self.assertEqual(exchange_ids.count("stophud"), 3)
            self.assertLess(exchange_ids.index("panic_restore_verify"), exchange_ids.index("version_after"))
            assert result is not None
            raw, public = result
            journal = json.loads((Path(directory) / "evidence/private/verification-024-control.journal.json").read_text())
            self.assertEqual(journal["status"], "CONTROL_VERIFIED")
            self.assertTrue(journal["panic_on_oops_restored"])
            self.assertTrue(journal["stophud_accepted"])
            public_obj = json.loads(public.read_text())
            self.assertTrue(public_obj["target_verified"])
            claim = public_obj["semantic_claim"]
            self.assertTrue((Path(directory) / "evidence/private" / claim["filename"]).exists())
            self.assertEqual(json.loads(raw.read_text())["value"], "0x000000000000c071")

    def test_readable_is_stop_after_restore_with_no_final_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory), probe.MODE_READ, 0x12345678
            )
            self.assertIsNotNone(result)
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(session.panic_values, [0, 1])
            self.assertNotIn("version_after", exchange_ids)
            assert result is not None
            raw, public = result
            manifest = json.loads(public.read_text())
            self.assertEqual(manifest["outcome"], "READABLE_SECURITY_INDICATOR")
            self.assertEqual(manifest["promotion"], "STOP_AND_ROLLBACK_REQUIRED")
            self.assertNotIn("value", manifest)
            self.assertNotIn("/tmp", public.read_text())
            self.assertNotIn("/dev/tty", public.read_text())
            self.assertNotIn("candidate.img", public.read_text())
            self.assertIn("12345678", json.loads(raw.read_text())["value"])

    def test_read_flash_completion_equal_to_control_is_rejected_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory), probe.MODE_READ, read_flash_completed="2026-08-27T00:00:00+00:00"
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [])
            self.assertNotIn("fixed_op_4", exchange_ids)

    def test_stale_hand_built_control_is_rejected_by_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root, probe.MODE_READ)
            with self.assertRaises(probe.ProbeError):
                probe.verify_control_manifest(args.control_manifest, root=root)

    def test_read_authorization_requires_complete_control_source_evidence(self) -> None:
        mutations = ("manifest_attestation", "raw_health", "journal_measurement", "flash_source")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = self._args(root, probe.MODE_READ)
                if mutation == "manifest_attestation":
                    manifest = json.loads(args.control_manifest.read_text())
                    manifest["current_boot_attestation"]["captured_size"] = 1
                    args.control_manifest.write_text(json.dumps(manifest))
                elif mutation == "raw_health":
                    raw_path = root / "evidence/private/verification-024-control.json"
                    raw = json.loads(raw_path.read_text())
                    raw["health_after"]["selftest"]["fail"] = 1
                    raw_path.write_text(json.dumps(raw))
                    manifest = json.loads(args.control_manifest.read_text())
                    manifest["raw_snapshot_sha256"] = probe.sha256_file(raw_path)
                    manifest["raw_snapshot_size"] = raw_path.stat().st_size
                    args.control_manifest.write_text(json.dumps(manifest))
                elif mutation == "journal_measurement":
                    journal_path = root / "evidence/private/verification-024-control.journal.json"
                    journal = json.loads(journal_path.read_text())
                    journal["fixed_op_measurement"]["value"] = "0x000000000000c072"
                    journal_path.write_text(json.dumps(journal))
                    manifest = json.loads(args.control_manifest.read_text())
                    manifest["journal_sha256"] = probe.sha256_file(journal_path)
                    manifest["journal_size"] = journal_path.stat().st_size
                    args.control_manifest.write_text(json.dumps(manifest))
                else:
                    flash_path = probe._fixed_flash_journal_path(root, probe.MODE_CONTROL)
                    flash = json.loads(flash_path.read_text())
                    flash["readback_sha256"] = probe.READ_SHA256
                    flash_path.write_text(json.dumps(flash))
                with self.assertRaises(probe.ProbeError):
                    probe.verify_control_manifest(args.control_manifest, root=root)

    def test_returned_map_failure_is_map_failed_in_both_modes(self) -> None:
        for mode in probe.MODES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                result, session, _ = self._run_collect(
                    Path(directory), mode, probe.MAP_FAILURE_RESULT
                )
                self.assertIsNone(result)
                self.assertEqual(session.op_calls, [(4, (), False)])
                public = json.loads(
                    (Path(directory) / f"evidence/manifests/verification-024-{mode}.manifest.json").read_text()
                )
                self.assertEqual(public["outcome"], "MAP_FAILED")

    def test_dispatch_disconnect_retains_incident_and_sends_no_post_commands(self) -> None:
        partial = probe.native_transport.PartialEvidence(
            payload=b"",
            transcript=b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n",
            begin={"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
            end=None,
        )
        disconnect = probe.native_transport.TransportFailure(
            "bridge disconnected before A90R", partial=partial
        )
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory), probe.MODE_READ,
                op_exception=disconnect,
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(session.panic_values, [0])
            self.assertNotIn("panic_restore_verify", exchange_ids)
            self.assertNotIn("version_after", exchange_ids)
            journal = json.loads((Path(directory) / "evidence/private/verification-024-read.journal.json").read_text())
            self.assertEqual(journal["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED")
            self.assertEqual(journal["outcome"], "REFUSED_AT_MID_CANDIDATE")
            self.assertTrue(journal["panic_restore_deferred"])
            self.assertTrue(journal["effect_ambiguous"])

    def test_legacy_transport_exceptions_are_incident(self) -> None:
        for error in (
            TimeoutError("bridge disconnected before A90R"),
            ConnectionError("bridge connection reset"),
            OSError("bridge timed out"),
        ):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result, session, exchange_ids = self._run_collect(
                    root, probe.MODE_READ, op_exception=error
                )
                self.assertIsNone(result)
                self.assertEqual(session.panic_values, [0])
                self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
                self.assertNotIn("panic_set_1", exchange_ids)
                self.assertNotIn("panic_restore_verify", exchange_ids)
                public = json.loads(
                    (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
                )
                self.assertFalse(public["transport_no_value"])
                self.assertEqual(public["outcome"], "INCIDENT")

    def test_complete_op_error_restores_before_stopping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory),
                probe.MODE_READ,
                op_return_error=True,
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [])
            self.assertEqual(session.panic_values, [0, 1])
            self.assertLess(
                exchange_ids.index("panic_restore_verify"),
                len(exchange_ids),
            )
            self.assertNotIn("version_after", exchange_ids)
            public = json.loads(
                (
                    Path(directory)
                    / "evidence/manifests/verification-024-read.manifest.json"
                ).read_text()
            )
            self.assertEqual(public["outcome"], "INCIDENT")

    def test_complete_ok_frame_with_malformed_wrapper_restores_before_stopping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root,
                probe.MODE_READ,
                op_malformed_wrapper=True,
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(session.panic_values, [0, 1])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertLess(
                exchange_ids.index("panic_set_1"),
                exchange_ids.index("panic_restore_verify"),
            )
            self.assertNotIn("version_after", exchange_ids)
            raw = json.loads(
                (root / "evidence/private/verification-024-read.json").read_text()
            )
            public = json.loads(
                (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
            )
            for receipt in (raw, public):
                self.assertTrue(receipt["dispatch_returned"])
                self.assertFalse(receipt["dispatch_failed"])
                self.assertFalse(receipt["effect_ambiguous"])
                self.assertEqual(receipt["outcome"], "INCIDENT")
            self.assertFalse(raw["error"]["transport_no_value"])
            self.assertFalse(public["transport_no_value"])

    def test_typed_transport_failure_partial_without_end_is_the_only_typed_no_value(self) -> None:
        partial = probe.native_transport.PartialEvidence(
            payload=b"",
            transcript=b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n",
            begin={"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
            end=None,
        )
        error = probe.native_transport.TransportFailure(
            "bridge closed before terminal frame", partial=partial
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root, probe.MODE_READ, op_exception=error
            )
            self.assertIsNone(result)
            self.assertEqual(session.panic_values, [0])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertNotIn("panic_set_1", exchange_ids)
            self.assertNotIn("panic_restore_verify", exchange_ids)
            raw = json.loads(
                (root / "evidence/private/verification-024-read.json").read_text()
            )
            public = json.loads(
                (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
            )
            self.assertEqual(raw["error"]["exception_type"], "TransportFailure")
            self.assertTrue(raw["error"]["partial_evidence_present"])
            self.assertTrue(raw["error"]["transport_no_value"])
            self.assertEqual(public["outcome"], "REFUSED_AT_MID_CANDIDATE")

    def test_typed_transport_failure_with_foreign_begin_is_incident(self) -> None:
        partial = probe.native_transport.PartialEvidence(
            payload=b"",
            transcript=b"A90P1 BEGIN seq=1 cmd=cat\n",
            begin={"cmd": "cat", "seq": "1"},
            end=None,
        )
        error = probe.native_transport.TransportFailure(
            "bridge closed after a foreign command BEGIN", partial=partial
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root, probe.MODE_READ, op_exception=error
            )
            self.assertIsNone(result)
            self.assertEqual(session.panic_values, [0])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertNotIn("panic_set_1", exchange_ids)
            self.assertNotIn("panic_restore_verify", exchange_ids)
            self.assertNotIn("version_after", exchange_ids)
            raw = json.loads(
                (root / "evidence/private/verification-024-read.json").read_text()
            )
            public = json.loads(
                (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
            )
            self.assertFalse(raw["dispatch_returned"])
            self.assertTrue(raw["dispatch_failed"])
            self.assertTrue(raw["effect_ambiguous"])
            self.assertTrue(raw["error"]["partial_evidence_present"])
            self.assertFalse(raw["error"]["transport_no_value"])
            self.assertFalse(public["dispatch_returned"])
            self.assertTrue(public["dispatch_failed"])
            self.assertTrue(public["effect_ambiguous"])
            self.assertFalse(public["transport_no_value"])
            self.assertEqual(public["outcome"], "INCIDENT")

    def test_typed_transport_failure_without_begin_is_incident(self) -> None:
        error = probe.native_transport.TransportFailure(
            "bridge closed before BEGIN",
            partial=probe.native_transport.PartialEvidence(
                payload=None,
                transcript=b"",
                begin=None,
                end=None,
            ),
        )
        self.assertFalse(
            probe._retained_partial_begin_matches_fixed_op(error, probe.fixed_op_argv())
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root, probe.MODE_READ, op_exception=error
            )
            self.assertIsNone(result)
            self.assertEqual(session.panic_values, [0])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertNotIn("panic_set_1", exchange_ids)
            public = json.loads(
                (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
            )
            self.assertEqual(public["outcome"], "INCIDENT")
            self.assertFalse(public["transport_no_value"])

    def test_typed_transport_failure_native_dispatch_prefix_remains_refused(self) -> None:
        body = b"run: pid=1, q/Ctrl-C cancels\n"
        begin = {"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"}
        transcript = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n" + body
        error = probe.native_transport.TransportFailure(
            "bridge closed with a native partial payload",
            partial=probe.native_transport.PartialEvidence(
                payload=body,
                transcript=transcript,
                begin=begin,
                end=None,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root, probe.MODE_READ, op_exception=error
            )
            self.assertIsNone(result)
            self.assertEqual(session.panic_values, [0])
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertNotIn("panic_set_1", exchange_ids)
            self.assertNotIn("panic_restore_verify", exchange_ids)
            raw = json.loads(
                (root / "evidence/private/verification-024-read.json").read_text()
            )
            public = json.loads(
                (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
            )
            self.assertTrue(raw["error"]["transport_no_value"])
            self.assertEqual(raw["error"]["payload_size"], len(body))
            self.assertEqual(public["outcome"], "REFUSED_AT_MID_CANDIDATE")

    def test_typed_transport_failure_native_completion_markers_are_incident(self) -> None:
        begin = {"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"}
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
                error = probe.native_transport.TransportFailure(
                    "bridge closed after native completion marker",
                    partial=probe.native_transport.PartialEvidence(
                        payload=body,
                        transcript=begin_line + body,
                        begin=begin,
                        end=None,
                    ),
                )
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    result, session, exchange_ids = self._run_collect(
                        root, probe.MODE_READ, op_exception=error
                    )
                    self.assertIsNone(result)
                    self.assertEqual(session.panic_values, [0])
                    self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
                    raw = json.loads(
                        (root / "evidence/private/verification-024-read.json").read_text()
                    )
                    public = json.loads(
                        (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
                    )
                    self.assertFalse(raw["error"]["transport_no_value"])
                    self.assertFalse(public["transport_no_value"])
                    self.assertEqual(public["outcome"], "INCIDENT")

    def test_transport_no_value_accepts_only_dispatch_prefixes(self) -> None:
        wrapper = b"run: pid=123, q/Ctrl-C cancels"
        for index in range(len(wrapper) + 1):
            with self.subTest(index=index):
                self.assertTrue(probe.is_transport_no_value_payload(wrapper[:index]))
        for payload in (
            b"run: pid=0",
            b"run: pid=01",
            b"run: pid=1, q/Ctrl-C cancels\nextra",
            b"run: pid=1, q/Ctrl-C cancels\rX",
            b"run: pid=1, q/Ctrl-C cancels\n[exit 0]",
            b"run: pid=1, q/Ctrl-C cancels\r\n[exit 0]",
            b"run: pid=1, q/Ctrl-C cancels\nA90R",
        ):
            with self.subTest(payload=payload):
                self.assertFalse(probe.is_transport_no_value_payload(payload))

    def test_typed_transport_failure_partial_payload_transcript_mismatch_is_incident(self) -> None:
        begin = {"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"}
        begin_line = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
        cases = {
            "payload_without_begin": {
                "payload": b"unexpected",
                "transcript": b"",
                "begin": None,
            },
            "different_payload_suffix": {
                "payload": b"wrong",
                "transcript": begin_line + b"actual",
                "begin": begin,
            },
            "missing_payload_suffix": {
                "payload": None,
                "transcript": begin_line + b"actual",
                "begin": begin,
            },
        }
        for name, fields in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                error = probe.native_transport.TransportFailure(
                    f"retained partial payload/transcript mismatch: {name}",
                    partial=probe.native_transport.PartialEvidence(
                        payload=fields["payload"],
                        transcript=fields["transcript"],
                        begin=fields["begin"],
                        end=None,
                    ),
                )
                root = Path(directory)
                result, session, exchange_ids = self._run_collect(
                    root, probe.MODE_READ, op_exception=error
                )
                self.assertIsNone(result)
                self.assertEqual(session.panic_values, [0])
                self.assertEqual(session.op_calls, [(4, (), False)])
                self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
                self.assertNotIn("panic_set_1", exchange_ids)
                self.assertNotIn("panic_restore_verify", exchange_ids)
                raw = json.loads(
                    (root / "evidence/private/verification-024-read.json").read_text()
                )
                public = json.loads(
                    (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
                )
                self.assertFalse(raw["error"]["transport_no_value"])
                self.assertTrue(raw["dispatch_failed"])
                self.assertTrue(raw["effect_ambiguous"])
                self.assertEqual(public["outcome"], "INCIDENT")

    def test_typed_transport_failure_partial_begin_negative_corpus_is_incident(self) -> None:
        cases = {
            "missing_fields": (
                b"A90P1 BEGIN seq=1 cmd=run\n",
                {"cmd": "run", "seq": "1"},
            ),
            "wrong_argc": (
                b"A90P1 BEGIN seq=1 cmd=run argc=4 flags=0x2\n",
                {"cmd": "run", "seq": "1", "argc": "4", "flags": "0x2"},
            ),
            "wrong_flags": (
                b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x0\n",
                {"cmd": "run", "seq": "1", "argc": "5", "flags": "0x0"},
            ),
            "extra_field": (
                b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2 extra=x\n",
                {
                    "cmd": "run",
                    "seq": "1",
                    "argc": "5",
                    "flags": "0x2",
                    "extra": "x",
                },
            ),
            "wrong_seq": (
                b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n",
                {"cmd": "run", "seq": "2", "argc": "5", "flags": "0x2"},
            ),
            "multiple": (
                b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
                b"A90P1 BEGIN seq=2 cmd=run argc=5 flags=0x2\n",
                {"cmd": "run", "seq": "2", "argc": "5", "flags": "0x2"},
            ),
        }
        for name, (transcript, begin) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                error = probe.native_transport.TransportFailure(
                    f"malformed retained BEGIN: {name}",
                    partial=probe.native_transport.PartialEvidence(
                        payload=b"",
                        transcript=transcript,
                        begin=begin,
                        end=None,
                    ),
                )
                root = Path(directory)
                result, session, exchange_ids = self._run_collect(
                    root, probe.MODE_READ, op_exception=error
                )
                self.assertIsNone(result)
                self.assertEqual(session.panic_values, [0])
                self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
                self.assertNotIn("panic_set_1", exchange_ids)
                self.assertNotIn("panic_restore_verify", exchange_ids)
                raw = json.loads(
                    (root / "evidence/private/verification-024-read.json").read_text()
                )
                public = json.loads(
                    (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
                )
                self.assertFalse(raw["error"]["transport_no_value"])
                self.assertFalse(public["transport_no_value"])
                self.assertEqual(public["outcome"], "INCIDENT")

    def test_typed_transport_failure_with_complete_end_or_without_partial_is_incident(self) -> None:
        payload = b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\n[exit 0]\n"
        transcript = (
            b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
            + payload
            + b"\n[done] ok\n"
            b"A90P1 END seq=1 cmd=run rc=0 errno=0 duration_ms=0 flags=0x2 status=ok\n"
        )
        complete = probe.native_transport.TransportFailure(
            "frame had a terminal error",
            partial=probe.native_transport.PartialEvidence(
                payload=payload,
                transcript=transcript,
                begin={"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
                end={
                    "cmd": "run",
                    "seq": "1",
                    "rc": "0",
                    "errno": "0",
                    "duration_ms": "0",
                    "flags": "0x2",
                    "status": "ok",
                },
            ),
        )
        for error in (
            complete,
            probe.native_transport.TransportFailure("A90P1 command timeout is invalid"),
        ):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result, _session, _ids = self._run_collect(
                    root, probe.MODE_READ, op_exception=error
                )
                self.assertIsNone(result)
                raw = json.loads(
                    (root / "evidence/private/verification-024-read.json").read_text()
                )
                public = json.loads(
                    (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
                )
                self.assertFalse(raw["error"]["transport_no_value"])
                self.assertEqual(public["outcome"], "INCIDENT")

    def test_complete_raw_end_without_outer_result_is_returned_and_restored(self) -> None:
        begin_line = b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
        end_line = (
            b"A90P1 END seq=1 cmd=run rc=0 errno=0 duration_ms=0 "
            b"flags=0x2 status=ok\n"
        )
        child_and_end = (
            b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\n[exit 0]\n" + end_line
        )
        error = probe.native_transport.TransportFailure(
            "bridge closed after protocol END without outer result",
            partial=probe.native_transport.PartialEvidence(
                payload=child_and_end,
                transcript=begin_line + child_and_end,
                begin={"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
                end=None,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root, probe.MODE_CONTROL, op_exception=error
            )
            self.assertIsNone(result)
            self.assertEqual(session.panic_values, [0, 1])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertEqual(exchange_ids.count("panic_set_1"), 1)
            self.assertEqual(exchange_ids.count("panic_restore_verify"), 1)
            raw = json.loads(
                (root / "evidence/private/verification-024-control.json").read_text()
            )
            public = json.loads(
                (root / "evidence/manifests/verification-024-control.manifest.json").read_text()
            )
            self.assertTrue(raw["dispatch_returned"])
            self.assertFalse(raw["dispatch_failed"])
            self.assertFalse(raw["error"].get("transport_no_value", False))
            self.assertEqual(public["outcome"], "INCIDENT")

    def test_typed_transport_failure_fabricated_end_without_transcript_end_is_ambiguous(self) -> None:
        partial = probe.native_transport.PartialEvidence(
            payload=b"",
            transcript=b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n",
            begin={"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
            # The retained mapping is fabricated: the transcript has no END.
            end={
                "cmd": "run",
                "seq": "1",
                "rc": "malformed",
                "errno": "0",
                "duration_ms": "0",
                "flags": "0x2",
                "status": "ok",
            },
        )
        error = probe.native_transport.TransportFailure(
            "frame return code was malformed but END was not retained",
            partial=partial,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root, probe.MODE_READ, op_exception=error
            )
            self.assertIsNone(result)
            self.assertEqual(session.panic_values, [0])
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertNotIn("panic_set_1", exchange_ids)
            self.assertNotIn("panic_restore_verify", exchange_ids)
            raw = json.loads(
                (root / "evidence/private/verification-024-read.json").read_text()
            )
            public = json.loads(
                (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
            )
            self.assertFalse(raw["dispatch_returned"])
            self.assertTrue(raw["dispatch_failed"])
            self.assertTrue(raw["effect_ambiguous"])
            self.assertFalse(raw["error"]["transport_no_value"])
            self.assertFalse(public["dispatch_returned"])
            self.assertTrue(public["dispatch_failed"])
            self.assertTrue(public["effect_ambiguous"])
            self.assertFalse(public["transport_no_value"])
            self.assertEqual(public["outcome"], "INCIDENT")

    def test_typed_transport_failure_matching_complete_end_restores_before_stopping(self) -> None:
        payload = b"run: pid=1, q/Ctrl-C cancels\nA90Rc071\n[exit 0]\n"
        transcript = (
            b"A90P1 BEGIN seq=1 cmd=run argc=5 flags=0x2\n"
            + payload
            + b"\n[done] ok\n"
            b"A90P1 END seq=1 cmd=run rc=malformed errno=0 duration_ms=0 flags=0x2 status=ok\n"
        )
        error = probe.native_transport.TransportFailure(
            "frame return code was malformed",
            partial=probe.native_transport.PartialEvidence(
                payload=payload,
                transcript=transcript,
                begin={"cmd": "run", "seq": "1", "argc": "5", "flags": "0x2"},
                end={
                    "cmd": "run",
                    "seq": "1",
                    "rc": "malformed",
                    "errno": "0",
                    "duration_ms": "0",
                    "flags": "0x2",
                    "status": "ok",
                },
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, session, exchange_ids = self._run_collect(
                root,
                probe.MODE_READ,
                op_exception=error,
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(session.panic_values, [0, 1])
            self.assertEqual(exchange_ids.count("fixed_op_4"), 1)
            self.assertLess(
                exchange_ids.index("panic_set_1"),
                exchange_ids.index("panic_restore_verify"),
            )
            self.assertNotIn("version_after", exchange_ids)
            raw = json.loads(
                (root / "evidence/private/verification-024-read.json").read_text()
            )
            public = json.loads(
                (root / "evidence/manifests/verification-024-read.manifest.json").read_text()
            )
            self.assertTrue(raw["dispatch_returned"])
            self.assertFalse(raw["dispatch_failed"])
            self.assertFalse(raw["effect_ambiguous"])
            self.assertFalse(raw["error"]["transport_no_value"])
            self.assertTrue(public["dispatch_returned"])
            self.assertFalse(public["dispatch_failed"])
            self.assertFalse(public["effect_ambiguous"])
            self.assertFalse(public["transport_no_value"])
            self.assertEqual(public["outcome"], "INCIDENT")

    def test_returned_control_restore_failure_blocks_final_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory),
                probe.MODE_CONTROL,
                probe.CONTROL_SENTINEL,
                restore_exception=TimeoutError("restore disconnected"),
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [(4, (), False)])
            self.assertEqual(session.panic_values, [0, 1])
            self.assertNotIn("version_after", exchange_ids)
            public = json.loads(
                (Path(directory) / "evidence/manifests/verification-024-control.manifest.json").read_text()
            )
            self.assertEqual(public["outcome"], "CONTROL_FAILED")
            self.assertTrue(public["panic_restore_deferred"])

    def test_wrong_current_boot_fails_even_with_valid_flash_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory), probe.MODE_CONTROL, probe.CONTROL_SENTINEL,
                boot_hash="0" * 64,
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [])
            self.assertFalse(session.panic_values)
            self.assertNotIn("panic_zero_verify", exchange_ids)
            manifest = json.loads((Path(directory) / "evidence/manifests/verification-024-control.manifest.json").read_text())
            self.assertFalse(manifest["target_verified"])
            self.assertIsNone(manifest["target_model"])
            self.assertIsNone(manifest["runtime"])
            self.assertEqual(
                manifest["current_boot_attestation"]["captured_sha256"], "0" * 64
            )

    def test_wrong_panic_precondition_fails_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, _ = self._run_collect(
                Path(directory), probe.MODE_CONTROL, probe.CONTROL_SENTINEL, panic_value=0
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [])
            self.assertEqual(session.panic_values, [])
            journal = json.loads((Path(directory) / "evidence/private/verification-024-control.journal.json").read_text())
            self.assertEqual(journal["status"], "REFUSED_PRE_DISPATCH")
            public = json.loads((Path(directory) / "evidence/manifests/verification-024-control.manifest.json").read_text())
            self.assertFalse(public["target_verified"])
            self.assertIsNone(public["target_model"])

    def test_nonbusy_stophud_error_fails_before_target_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory), probe.MODE_CONTROL, probe.CONTROL_SENTINEL,
                stophud_results=[(1, "error")],
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [])
            self.assertNotIn("version_before", exchange_ids)
            public = json.loads((Path(directory) / "evidence/manifests/verification-024-control.manifest.json").read_text())
            self.assertFalse(public["target_verified"])

    def test_stophud_invalid_success_payload_fails_before_continuation(self) -> None:
        for payload in (
            b"",
            b"\n",
            b"\r\n",
            b"autohud: stopped\n",
            b"autohud: not running\r\n",
            b"forged",
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    stophud_payload=payload,
                    stophud_results=[(0, "ok")],
                )
                self.assertIsNone(result)
                self.assertEqual(exchange_ids, ["stophud"])
                self.assertEqual(session.panic_values, [])
                self.assertNotIn("version_before", exchange_ids)
                self.assertNotIn("fixed_op_4", exchange_ids)

    def test_stophud_both_success_payloads_allow_continuation(self) -> None:
        for payload in sorted(hud.STOPHUD_SUCCESS_PAYLOADS):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    stophud_payload=payload,
                )
                self.assertIsNotNone(result)
                self.assertEqual(session.panic_values, [0, 1])
                self.assertIn("fixed_op_4", exchange_ids)

    def test_stophud_busy_with_nonempty_payload_fails_without_retry_or_continuation(self) -> None:
        for payload in (b"\n", b"\r\n", b"forged"):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    stophud_payload=payload,
                    stophud_results=[(-16, "busy"), (0, "ok")],
                )
                self.assertIsNone(result)
                self.assertEqual(exchange_ids, ["stophud"])
                self.assertEqual(session.panic_values, [])
                self.assertNotIn("version_before", exchange_ids)
                self.assertNotIn("fixed_op_4", exchange_ids)

    def test_pre_effect_payload_semantics_fail_closed_before_panic_or_fixed_op(self) -> None:
        empty_body_violation = b"run: pid=1, q/Ctrl-C cancels\nextra\n[exit 0]\n"
        attestation_cases = (
            ("boot_attest_remove_node", empty_body_violation),
            ("boot_attest_mkdir", empty_body_violation),
            ("boot_attest_mknod", b"unexpected\n"),
            ("boot_attest_capture", empty_body_violation),
            ("boot_sysfs_uevent", UEVENT + b"EXTRA=1\n"),
        )
        for evidence_id, payload in attestation_cases:
            with self.subTest(evidence_id=evidence_id), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_payloads={evidence_id: payload},
                )
                self.assertIsNone(result)
                self.assertIn(evidence_id, exchange_ids)
                self.assertNotIn("panic_set_0", exchange_ids)
                self.assertNotIn("fixed_op_4", exchange_ids)
                self.assertEqual(session.panic_values, [])

        pre_effect_cases = (
            ("version_before", VERSION + b"\n"),
            ("cmdline_before", CMDLINE.replace(b"ro ", b"ro ro ", 1)),
            ("soc_id_before", b"339\n340\n"),
            ("selftest_before", SELFTEST + b"\n"),
            ("panic_before", b" 1\n"),
            ("boot_id_before_read", f"{BOOT_ID}\n\n".encode("ascii")),
        )
        for evidence_id, payload in pre_effect_cases:
            with self.subTest(evidence_id=evidence_id), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_payloads={evidence_id: payload},
                )
                self.assertIsNone(result)
                self.assertIn(evidence_id, exchange_ids)
                self.assertNotIn("panic_set_0", exchange_ids)
                self.assertNotIn("fixed_op_4", exchange_ids)
                self.assertEqual(session.panic_values, [])

        for evidence_id, payload in (
            ("panic_before", b"1"),
            ("panic_before", b"1\r"),
            ("panic_zero_verify", b"0"),
            ("panic_zero_verify", b"0\r"),
        ):
            with self.subTest(evidence_id=evidence_id, payload=payload), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_payloads={evidence_id: payload},
                )
                self.assertIsNone(result)
                self.assertNotIn("fixed_op_4", exchange_ids)
                if evidence_id == "panic_before":
                    self.assertNotIn("panic_set_0", exchange_ids)
                    self.assertEqual(session.panic_values, [])
                else:
                    self.assertEqual(exchange_ids.count("panic_set_0"), 1)
                    self.assertEqual(session.panic_values, [0])

        def wrapped(body: bytes, *, terminal_crlf: bool = False) -> bytes:
            ending = b"\r\n" if terminal_crlf else b"\n"
            return (
                b"run: pid=1, q/Ctrl-C cancels\n"
                + body
                + ending
                + b"[exit 0]"
                + ending
            )

        candidate_hash = probe.EXPECTED_CANDIDATE_HASHES[probe.MODE_CONTROL]
        hash_path = probe.BOOT_ATTEST_FILE.encode("ascii")
        hash_variants = (
            candidate_hash.encode("ascii") + b" " + hash_path,
            candidate_hash.encode("ascii") + b"\t" + hash_path,
            candidate_hash.encode("ascii") + b"   " + hash_path,
        )
        for payload in hash_variants:
            with self.subTest(evidence_id="boot_attest_hash", payload=payload), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_payloads={"boot_attest_hash": wrapped(payload)},
                )
                self.assertIsNone(result)
                self.assertNotIn("panic_set_0", exchange_ids)
                self.assertNotIn("fixed_op_4", exchange_ids)
                self.assertEqual(session.panic_values, [])

        size_path = probe.BOOT_ATTEST_FILE.encode("ascii")
        size_variants = (
            b"60882944\t" + size_path,
            b"60882944  " + size_path,
            b"60882944   " + size_path,
        )
        for payload in size_variants:
            with self.subTest(evidence_id="boot_attest_size", payload=payload), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_payloads={"boot_attest_size": wrapped(payload)},
                )
                self.assertIsNone(result)
                self.assertNotIn("panic_set_0", exchange_ids)
                self.assertNotIn("fixed_op_4", exchange_ids)
                self.assertEqual(session.panic_values, [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            leading_zero = wrapped(
                b"060882944 " + probe.BOOT_ATTEST_FILE.encode("ascii")
            )
            result, _session, exchange_ids = self._run_collect(
                root,
                probe.MODE_CONTROL,
                bad_payloads={"boot_attest_size": leading_zero},
            )
            self.assertIsNone(result)
            self.assertNotIn("fixed_op_4", exchange_ids)
            from tools import a90_verification024_finalize as finalizer

            manifest = root / "evidence/manifests/verification-024-control.manifest.json"
            with self.assertRaises(probe.ProbeError):
                probe.verify_control_manifest(manifest, root=root)
            with self.assertRaises(finalizer.FinalizeError):
                finalizer.validate_control(manifest, root)

        cleanup_blank_variants = (
            b"\nrun: pid=1, q/Ctrl-C cancels\n[exit 0]\n",
            b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n\n",
            b"run: pid=1, q/Ctrl-C cancels\n\n[exit 0]\n",
        )
        for payload in cleanup_blank_variants:
            with self.subTest(evidence_id="boot_attest_remove_node", payload=payload), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    bad_payloads={"boot_attest_remove_node": payload},
                )
                self.assertIsNone(result)
                self.assertNotIn("panic_set_0", exchange_ids)
                self.assertNotIn("fixed_op_4", exchange_ids)
                self.assertEqual(session.panic_values, [])

        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory),
                probe.MODE_CONTROL,
                bad_payloads={"panic_set_0": b"\n"},
            )
            self.assertIsNone(result)
            self.assertEqual(exchange_ids.count("panic_set_0"), 1)
            self.assertNotIn("panic_zero_verify", exchange_ids)
            self.assertNotIn("fixed_op_4", exchange_ids)
            self.assertEqual(session.panic_values, [0])

    def test_stophud_busy_retry_revalidates_and_stops_on_bridge_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory),
                probe.MODE_CONTROL,
                probe.CONTROL_SENTINEL,
                stophud_results=[(-16, "busy"), (0, "ok")],
                stophud_rebind_drift_attempt=2,
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [])
            self.assertEqual(exchange_ids, ["stophud"])
            self.assertNotIn("version_before", exchange_ids)
            journal = json.loads(
                (Path(directory) / "evidence/private/verification-024-control.journal.json").read_text()
            )
            self.assertEqual(journal["status"], "REFUSED_PRE_DISPATCH")

    def test_effects_are_adjacent_to_fresh_bind_after_each_durable_marker(self) -> None:
        # A drift observed after a durable intent must prevent the associated
        # write/effect and every later substantive command.
        cases = (
            ("PANIC_TRANSITION_INTENT_DURABLE", (), ("panic_set_0",)),
            ("EFFECT_DISPATCH_STARTED", (0,), ("fixed_op_4",)),
            ("PANIC_RESTORE_INTENT_DURABLE", (0,), ("panic_set_1",)),
        )
        for status, expected_panic, forbidden in cases:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                result, session, exchange_ids = self._run_collect(
                    Path(directory),
                    probe.MODE_CONTROL,
                    probe.CONTROL_SENTINEL,
                    drift_after_status=status,
                )
                self.assertIsNone(result)
                self.assertEqual(session.panic_values, list(expected_panic))
                self.assertTrue(set(forbidden).isdisjoint(exchange_ids))
                self.assertNotIn("version_after", exchange_ids)

    def test_bridge_rebind_refuses_before_op_after_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, session, exchange_ids = self._run_collect(
                Path(directory), probe.MODE_CONTROL, probe.CONTROL_SENTINEL, rebind=True
            )
            self.assertIsNone(result)
            self.assertEqual(session.op_calls, [])
            self.assertEqual(session.panic_values, [])
            self.assertNotIn("version_after", exchange_ids)
            journal = json.loads((Path(directory) / "evidence/private/verification-024-control.journal.json").read_text())
            self.assertEqual(journal["dispatch_count"], 0)
            self.assertFalse(journal["panic_restore_deferred"])

    def test_output_paths_and_cli_cannot_accept_arbitrary_effect_inputs(self) -> None:
        parser = probe.make_parser()
        for option in (
            "--address",
            "--value",
            "--call-target",
            "--retry",
            "--candidate",
            "--output-root",
            "--journal",
            "--flash-journal",
            "--control-manifest",
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(["--experiment-id", "x", "--mode", "control", "--flash-journal", "x", option, "1"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self._args(root, probe.MODE_CONTROL)
            args.journal = Path("../outside.json")
            with mock.patch.object(probe, "REPO_ROOT", root), mock.patch.object(
                probe, "_stable_file_digest", return_value=(probe.BOOT_PREFIX_SIZE, probe.CONTROL_SHA256)
            ):
                with self.assertRaisesRegex(probe.ProbeError, "fixed producer path"):
                    probe.collect(args)

            args = self._args(root, probe.MODE_CONTROL)
            args.output_root = root / "alternate"
            with mock.patch.object(probe, "REPO_ROOT", root), mock.patch.object(
                probe, "validate_bridge_binding"
            ) as bind, mock.patch.object(probe, "exchange") as contact:
                with self.assertRaisesRegex(probe.ProbeError, "fixed to REPO_ROOT"):
                    probe.collect(args)
            bind.assert_not_called()
            contact.assert_not_called()


if __name__ == "__main__":
    unittest.main()
