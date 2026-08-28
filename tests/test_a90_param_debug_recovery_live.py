from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tools import a90_param_debug_recovery as core
from tools import a90_param_capture as capture_contract
from tools import a90_param_debug_recovery_live as live
from tools import a90_param_debug_transition as transition
from tools.a90_partition_capture import Partition


def source_record() -> dict[str, object]:
    target = {
        "model": core.TARGET_MODEL,
        "soc": core.TARGET_SOC,
        "bootloader": core.TARGET_BOOTLOADER,
        "runtime": core.TARGET_RUNTIME,
        "kernel": core.TARGET_KERNEL,
    }
    return {
        "schema": core.SOURCE_SCHEMA,
        "experiment_id": "ambiguous-param-source",
        "action": "apply-mid",
        "status": core.AMBIGUOUS_STATUS,
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
            "androidboot.em.model": core.TARGET_MODEL,
            "androidboot.bootloader": core.TARGET_BOOTLOADER,
            "androidboot.debug_level": "0x4f4c",
            "androidboot.force_upload": "0x0",
            "sec_debug.dump_sink": "0x0",
            "androidboot.upload_offset": core.PARAM_CMDLINE_UPLOAD_OFFSET,
        },
        "download_mode_before": "1",
        "partition": {
            "partname": core.PARAM_PARTNAME,
            "devname": core.PARAM_DEVNAME,
            "major": core.PARAM_MAJOR,
            "minor": core.PARAM_MINOR,
            "sectors": core.PARAM_SECTORS,
            "byte_size": core.PARAM_PARTITION_BYTES,
            "read_only": core.PARAM_READ_ONLY,
            "logical_block_size": core.PARAM_LOGICAL_BLOCK_SIZE,
            "start_sector": core.PARAM_START_SECTOR,
        },
        "transition": {
            "partition_offset": "0x900000",
            "size": 4,
            "before_label": "LOW",
            "after_label": "MID",
            "before_bytes_hex": core.LOW_BYTES.hex(),
            "after_bytes_hex": core.MID_BYTES.hex(),
            "before_sha256": core.ROLLBACK_SHA256,
            "after_sha256": core.MID_SHA256,
            "before_stable_sha256": core.PARAM_STABLE_LOW_SHA256,
            "after_stable_sha256": core.PARAM_STABLE_MID_SHA256,
            "stable_mask": {
                "excluded_ranges": [[0, 1]],
                "stable_ranges": [[1, core.PARAM_PARTITION_BYTES]],
                "stable_size": core.PARAM_STABLE_SIZE,
            },
        },
        "device_sha256_before": core.ROLLBACK_SHA256,
        "device_stable_sha256_before": core.PARAM_STABLE_LOW_SHA256,
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[1, core.PARAM_PARTITION_BYTES]],
            "stable_size": core.PARAM_STABLE_SIZE,
        },
        "stable_range": {
            "start": core.PARAM_STABLE_OFFSET,
            "end": core.PARAM_PARTITION_BYTES,
            "size": core.PARAM_STABLE_SIZE,
            "sha256": core.PARAM_STABLE_LOW_SHA256,
        },
        "volatile_byte0_before": 0,
        "payload": {
            "path": core.PAYLOAD_PATH,
            "size": 4,
            "sha256": core.sha256(core.MID_BYTES),
            "readback_base64": "RE1JRA==",
        },
        "regular_file_dd_smoke": {
            "args": list(core.SMOKE_DD_ARGS),
            "passed": True,
            "expected_sha256": core.SMOKE_EXPECTED_SHA256[core.MID_BYTES],
            "readback_sha256": core.SMOKE_EXPECTED_SHA256[core.MID_BYTES],
        },
        "effect_argv": list(core.FIXED_EFFECT_ARGV),
    }


def source_record_for_action(action: str) -> dict[str, object]:
    if action == "apply-mid":
        return source_record()
    if action != "restore-low":
        raise ValueError(action)
    source = source_record()
    source["action"] = "restore-low"
    source["cmdline_before"] = {
        **source["cmdline_before"],
        "androidboot.debug_level": "0x494d",
    }
    source["device_sha256_before"] = core.MID_SHA256
    source["device_stable_sha256_before"] = core.PARAM_STABLE_MID_SHA256
    source["stable_range"] = {
        "start": core.PARAM_STABLE_OFFSET,
        "end": core.PARAM_PARTITION_BYTES,
        "size": core.PARAM_STABLE_SIZE,
        "sha256": core.PARAM_STABLE_MID_SHA256,
    }
    source["transition"] = {
        "partition_offset": "0x900000",
        "size": 4,
        "before_label": "MID",
        "after_label": "LOW",
        "before_bytes_hex": core.MID_BYTES.hex(),
        "after_bytes_hex": core.LOW_BYTES.hex(),
        "before_sha256": core.MID_SHA256,
        "after_sha256": core.ROLLBACK_SHA256,
        "before_stable_sha256": core.PARAM_STABLE_MID_SHA256,
        "after_stable_sha256": core.PARAM_STABLE_LOW_SHA256,
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[1, core.PARAM_PARTITION_BYTES]],
            "stable_size": core.PARAM_STABLE_SIZE,
        },
    }
    source["payload"] = {
        "path": core.PAYLOAD_PATH,
        "size": 4,
        "sha256": core.sha256(core.LOW_BYTES),
        "readback_base64": "RExPVw==",
    }
    source["regular_file_dd_smoke"] = {
        "args": list(core.SMOKE_DD_ARGS),
        "passed": True,
        "expected_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
        "readback_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
    }
    return source


def args_for(experiment_id: str, source_id: str) -> argparse.Namespace:
    return argparse.Namespace(
        experiment_id=experiment_id,
        source_experiment_id=source_id,
        execute=True,
        command_timeout=1.0,
        hash_timeout=1.0,
        capture_timeout=1.0,
        effect_timeout=1.0,
        total_timeout=30.0,
    )


class A90ParamDebugRecoveryLiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "evidence" / "private").mkdir(parents=True)
        (self.root / "evidence" / "manifests").mkdir(parents=True)
        self.source_id = "ambiguous-param-source"
        source_path = self.root / "evidence" / "private" / f"{self.source_id}.journal.json"
        source_path.write_bytes(json.dumps(source_record(), sort_keys=True).encode() + b"\n")
        self.source_path = source_path
        self.low, self.mid = core.pinned_images()
        self.partition = Partition(
            core.PARAM_PARTNAME,
            core.PARAM_DEVNAME,
            core.PARAM_MAJOR,
            core.PARAM_MINOR,
            core.PARAM_SECTORS,
            core.PARAM_PARTITION_BYTES,
            core.PARAM_READ_ONLY,
            core.PARAM_LOGICAL_BLOCK_SIZE,
        )
        self.binding = {
            "listener": {"host": live.BRIDGE_HOST, "port": live.BRIDGE_PORT},
            "process_pid": 123,
            "serial_device": "/dev/ttyACM0",
            "validated_utc": "now",
        }
        self.old_root = live.REPO_ROOT
        live.REPO_ROOT = self.root

    def _set_source_action(self, action: str) -> None:
        self.source_path.write_bytes(
            json.dumps(source_record_for_action(action), sort_keys=True).encode() + b"\n"
        )

    def tearDown(self) -> None:
        live.REPO_ROOT = self.old_root
        self.temp.cleanup()

    def _capture(self, image: bytes, path: Path | None = None) -> dict[str, object]:
        digest = hashlib.sha256(image).hexdigest()
        evidence = capture_contract.stable_param_evidence(image)
        evidence.update({
            "path": path.name if path is not None else "live.preimage.bin",
            "private_filename": path.name if path is not None else "live.preimage.bin",
            "device_sha256_before": digest,
            "device_sha256_after": digest,
            "a90p1_end": {"rc": "0", "status": "ok"},
            "image": image,
        })
        return evidence

    def _run(self, image: bytes, *, cleanup_errors: list[str] | None = None):
        stophud = {"accepted": True, "busy_retries": 0, "attempts": []}

        def capture(*capture_args, **capture_kwargs):
            del capture_kwargs
            path = Path(capture_args[1])
            path.write_bytes(image)
            return self._capture(image, path)

        with mock.patch.object(live, "validate_bridge_binding", return_value=self.binding), \
             mock.patch.object(live, "revalidate_bridge_binding", return_value=self.binding), \
             mock.patch.object(live, "run_stophud", return_value=stophud) as stop, \
             mock.patch.object(
                 live,
                 "_validate_live_identity",
                 return_value=(
                     {
                         "androidboot.em.model": core.TARGET_MODEL,
                         "androidboot.bootloader": core.TARGET_BOOTLOADER,
                         "androidboot.debug_level": "0x4f4c",
                         "androidboot.force_upload": "0x0",
                         "sec_debug.dump_sink": "0x0",
                     },
                     "1",
                     self.partition,
                     core.PARAM_START_SECTOR,
                     {
                         **{
                             "partname": core.PARAM_PARTNAME,
                             "devname": core.PARAM_DEVNAME,
                             "major": core.PARAM_MAJOR,
                             "minor": core.PARAM_MINOR,
                             "sectors": core.PARAM_SECTORS,
                             "byte_size": core.PARAM_PARTITION_BYTES,
                             "read_only": core.PARAM_READ_ONLY,
                             "logical_block_size": core.PARAM_LOGICAL_BLOCK_SIZE,
                         },
                         "start_sector": core.PARAM_START_SECTOR,
                     },
                 ),
             ), \
             mock.patch.object(live, "create_and_validate_node"), \
             mock.patch.object(live, "_capture_preimage", side_effect=capture), \
             mock.patch.object(live, "_cleanup_all", return_value=cleanup_errors or []):
            result = live.execute(args_for("live", self.source_id))
        stop.assert_called_once()
        return result

    def _run_effect(
        self,
        image: bytes,
        *,
        experiment_id: str = "live",
        dispatch: object | None = None,
        post_hash: str | None = None,
        stage_error: BaseException | None = None,
        smoke_error: BaseException | None = None,
        rebind_error: BaseException | None = None,
        cleanup_errors: list[str] | None = None,
        persist_marker_error: BaseException | None = None,
        target_error: BaseException | None = None,
        live_debug_level: str | None = None,
    ) -> tuple[tuple[Path, Path] | None, list[str], mock.Mock, mock.Mock]:
        """Run the real frozen coordinator with production-bound closures."""

        events: list[str] = []
        stophud = {"accepted": True, "busy_retries": 0, "attempts": []}

        def fake_create(*args, before_mutation=None):
            del args
            events.append("create")
            if before_mutation is not None:
                before_mutation("create_inner")

        def capture(*capture_args, **capture_kwargs):
            before_remote = capture_kwargs.get("before_remote")
            path = Path(capture_args[1])
            if before_remote is not None:
                events.append("capture_before_hash")
                before_remote("capture_before_hash")
                events.append("capture_binary")
                before_remote("capture_binary")
                events.append("capture_after_hash")
                before_remote("capture_after_hash")
            path.write_bytes(image)
            return self._capture(image, path)

        def stage(*args, before_mutation=None):
            del args
            events.append("stage")
            if before_mutation is not None:
                before_mutation("stage_inner")
            if stage_error is not None:
                raise stage_error
            return {
                "path": core.PAYLOAD_PATH,
                "size": core.DLOW_PAYLOAD_SIZE,
                "sha256": core.DLOW_PAYLOAD_SHA256,
                "readback_base64": "RExPVw==",
            }

        def smoke(*args, before_mutation=None):
            del args
            events.append("smoke")
            if before_mutation is not None:
                before_mutation("smoke_inner")
            if smoke_error is not None:
                raise smoke_error
            smoke_hash = core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES]
            return {
                "args": list(core.SMOKE_DD_ARGS),
                "passed": True,
                "expected_sha256": smoke_hash,
                "readback_sha256": smoke_hash,
            }

        def fake_exchange(host, port, command, timeout, *, allow_error=False):
            del host, port, timeout, allow_error
            if live_debug_level is not None:
                identity_payloads = {
                    "version": (
                        b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
                        b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
                    ),
                    "proc_cmdline": (
                        "androidboot.em.model=SM-A908N "
                        "androidboot.bootloader=A908NKSU5EWA3 "
                        f"androidboot.debug_level={live_debug_level} "
                        "androidboot.force_upload=0x0 sec_debug.dump_sink=0x0 "
                        "androidboot.upload_offset=9438196\n"
                    ).encode(),
                    "download_mode": b"1\n",
                }
                if command.evidence_id in identity_payloads:
                    identity_command = (
                        "version" if command.evidence_id == "version" else "cat"
                    )
                    return SimpleNamespace(
                        begin={"seq": command.evidence_id, "cmd": identity_command},
                        end={
                            "seq": command.evidence_id,
                            "cmd": identity_command,
                            "rc": "0",
                            "status": "ok",
                        },
                        payload=identity_payloads[command.evidence_id],
                        transcript=b"",
                    )
            events.append("dispatch")
            if dispatch is not None:
                if isinstance(dispatch, BaseException):
                    raise dispatch
                return dispatch
            begin = {"seq": "1", "cmd": "run"}
            end = {"seq": "1", "cmd": "run", "rc": "0", "status": "ok"}
            return SimpleNamespace(begin=begin, end=end, payload=b"", transcript=b"")

        def fake_hash(*args):
            del args
            events.append("post_hash")
            return post_hash if post_hash is not None else core.ROLLBACK_SHA256

        def fake_binary(*args):
            del args
            events.append("post_hash")
            image = self.mid if post_hash == core.MID_SHA256 else self.low
            return ({"cmd": "run", "rc": "0", "status": "ok"}, image)

        binding_values: list[object] = [self.binding, self.binding]
        if rebind_error is not None:
            binding_values.append(rebind_error)

        def fake_rebind(binding):
            del binding
            value = binding_values.pop(0) if binding_values else self.binding
            if isinstance(value, BaseException):
                raise value
            return value

        def fake_persist(path, journal):
            if (
                persist_marker_error is not None
                and journal.get("status") == "EFFECT_DISPATCH_STARTED"
            ):
                raise persist_marker_error
            return original_persist(path, journal)

        def fake_target_verify(*_args, **_kwargs):
            if target_error is not None:
                raise target_error
            return {"ok": True}

        def fake_cleanup(*args):
            del args
            events.append("cleanup")
            return cleanup_errors or []

        original_persist = live._persist
        args = args_for(experiment_id, self.source_id)
        args.effect_timeout = 1.0
        identity_patch = (
            mock.patch.object(
                live,
                "discover_param",
                return_value=(self.partition, core.PARAM_START_SECTOR),
            )
            if live_debug_level is not None
            else mock.patch.object(
                live,
                "_validate_live_identity",
                return_value=(
                    {
                        "androidboot.em.model": core.TARGET_MODEL,
                        "androidboot.bootloader": core.TARGET_BOOTLOADER,
                        "androidboot.debug_level": "0x4f4c",
                        "androidboot.force_upload": "0x0",
                        "sec_debug.dump_sink": "0x0",
                    },
                    "1",
                    self.partition,
                    core.PARAM_START_SECTOR,
                    {
                        "partname": core.PARAM_PARTNAME,
                        "devname": core.PARAM_DEVNAME,
                        "major": core.PARAM_MAJOR,
                        "minor": core.PARAM_MINOR,
                        "sectors": core.PARAM_SECTORS,
                        "byte_size": core.PARAM_PARTITION_BYTES,
                        "read_only": core.PARAM_READ_ONLY,
                        "logical_block_size": core.PARAM_LOGICAL_BLOCK_SIZE,
                        "start_sector": core.PARAM_START_SECTOR,
                    },
                ),
            )
        )
        with mock.patch.object(live, "validate_bridge_binding", return_value=self.binding), \
             mock.patch.object(live, "revalidate_bridge_binding", side_effect=fake_rebind), \
             mock.patch.object(live, "run_stophud", return_value=stophud), \
             identity_patch, \
             mock.patch.object(live, "create_and_validate_node", side_effect=fake_create), \
             mock.patch.object(live, "_capture_preimage", side_effect=capture), \
             mock.patch.object(live, "_write_ascii_payload", side_effect=stage) as stage_mock, \
             mock.patch.object(live, "verify_regular_file_dd", side_effect=smoke) as smoke_mock, \
             mock.patch.object(live, "verify_exact_param_target", side_effect=fake_target_verify), \
             mock.patch.object(live, "exchange", side_effect=fake_exchange) as exchange_mock, \
             mock.patch.object(live, "binary_exchange", side_effect=fake_binary), \
             mock.patch.object(live, "device_sha256", side_effect=fake_hash) as hash_mock, \
             mock.patch.object(live, "_cleanup_all", side_effect=fake_cleanup) as cleanup_mock, \
             mock.patch.object(live, "_persist", side_effect=fake_persist):
            self.last_effect_events = events
            self.last_effect_exchange = exchange_mock
            self.last_effect_cleanup = cleanup_mock
            result: tuple[Path, Path] | None = None
            error: BaseException | None = None
            try:
                result = live.execute(args)
            except BaseException as exc:
                error = exc
            if error is not None:
                raise error
        return result, events, exchange_mock, cleanup_mock

    def _discard_run_artifacts(self, result: tuple[Path, Path] | None, experiment_id: str) -> None:
        source_claim = live._source_claim_path(
            core.validate_source_path(self.source_path, root=self.root)
        )
        if source_claim.exists():
            source_claim.unlink()
        for effect_claim in (
            self.root / "evidence" / "private" / ".param-debug-effect-consumption"
        ).glob("*.claim.json"):
            effect_claim.unlink()
        if result is not None:
            for path in result:
                path.unlink(missing_ok=True)
        (self.root / "evidence" / "private" / f"{experiment_id}.preimage.bin").unlink(
            missing_ok=True
        )

    def test_gate_and_import_do_not_contact(self) -> None:
        parser = live.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "--experiment-id",
                    "live",
                    "--source-experiment-id",
                    self.source_id,
                    "--host",
                    "127.0.0.1",
                ]
            )
        with mock.patch.object(live, "validate_bridge_binding") as binding, \
             mock.patch.object(live, "exchange") as exchange:
            with self.assertRaises(live.LiveRecoveryError):
                live.execute(argparse.Namespace(
                    experiment_id="live",
                    source_experiment_id=self.source_id,
                    execute=False,
                    command_timeout=1.0,
                    hash_timeout=1.0,
                    capture_timeout=1.0,
                    total_timeout=30.0,
                ))
        binding.assert_not_called()
        exchange.assert_not_called()

    def test_stophud_retry_rebind_drift_blocks_second_attempt_and_identity_reads(self) -> None:
        class Frame:
            payload = b""
            transcript = (
                b"A90P1 BEGIN seq=1 cmd=stophud argc=1 flags=0x8\r\n\r\n"
                b"[busy] auto menu active; send hide/q before command\r\n"
                b"A90P1 END seq=1 cmd=stophud rc=-16 errno=16 duration_ms=0 "
                b"flags=0x8 status=busy\r\n"
            )

            def __init__(self) -> None:
                self.begin = {
                    "cmd": "stophud",
                    "seq": "1",
                    "argc": "1",
                    "flags": "0x8",
                }
                self.end = {
                    "cmd": "stophud",
                    "seq": "1",
                    "rc": "-16",
                    "errno": "16",
                    "duration_ms": "0",
                    "flags": "0x8",
                    "status": "busy",
                }

        calls: list[str] = []

        def fake_exchange(host, port, command, timeout, *, allow_error=False):
            del host, port, command, timeout, allow_error
            calls.append("stophud")
            return Frame()

        args = args_for("live-retry-drift", self.source_id)
        with mock.patch.object(live, "validate_bridge_binding", return_value=self.binding), mock.patch.object(
            live,
            "revalidate_bridge_binding",
            side_effect=[self.binding, self.binding, RuntimeError("drift before retry")],
        ) as rebind, mock.patch.object(
            live, "exchange", side_effect=fake_exchange
        ) as exchange, mock.patch.object(live, "_validate_live_identity") as identity:
            with self.assertRaises(live.LiveRecoveryError):
                live.execute(args)
        self.assertEqual(calls, ["stophud"])
        self.assertEqual(rebind.call_count, 3)
        self.assertEqual(exchange.call_count, 1)
        identity.assert_not_called()
        journal_path = self.root / "evidence" / "private" / "live-retry-drift.journal.json"
        journal = json.loads(journal_path.read_text())
        self.assertEqual(journal["status"], live.PRE_EFFECT_PREFLIGHT_INCOMPLETE)
        self.assertEqual(len(journal["stophud_attempts"]), 2)
        self.assertEqual(journal["stophud_attempts"][0]["status"], "busy")

    def test_source_path_is_fixed_and_ids_cannot_escape(self) -> None:
        expected = self.root / "evidence" / "private" / f"{self.source_id}.journal.json"
        self.assertEqual(live.source_journal_path(self.source_id), expected)
        for value in ("../escape", "", "UPPER", "a/b", "a\\b"):
            with self.subTest(value=value):
                with self.assertRaises(live.LiveRecoveryError):
                    live.source_journal_path(value)

    def test_live_cmdline_accepts_exact_known_bare_flags(self) -> None:
        payload = (
            b"skip_initramfs rootwait ro "
            b"androidboot.em.model=SM-A908N "
            b"androidboot.bootloader=A908NKSU5EWA3 "
            b"androidboot.debug_level=0x4f4c "
            b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0\n"
        )
        parsed = live.parse_cmdline(payload)
        self.assertEqual(parsed["skip_initramfs"], "")
        self.assertEqual(parsed["rootwait"], "")
        self.assertEqual(parsed["ro"], "")
        self.assertEqual(parsed["androidboot.em.model"], "SM-A908N")

    def test_live_cmdline_rejects_hostile_tokens(self) -> None:
        cases = (
            b"androidboot.em.model=SM-A908N malformed\n",
            b"ro ro androidboot.em.model=SM-A908N\n",
            b"androidboot.em.model=SM-A908N androidboot.em.model=SM-A908N\n",
            b"androidboot.em.model=\n",
            b"androidboot/em.model=SM-A908N\n",
            b"androidboot.em.model=SM-A908N\x00 ro\n",
            "androidboot.em.model=SM-A908N ☃\n".encode("utf-8"),
        )
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(live.LiveRecoveryError):
                    live.parse_cmdline(payload)

    def test_low_is_zero_write_success_and_public_binds_private(self) -> None:
        journal_path, manifest_path = self._run(self.low)
        journal = json.loads(journal_path.read_text())
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(journal["status"], live.PASS_ALREADY_LOW)
        self.assertEqual(journal["classification"], core.ALREADY_LOW)
        self.assertEqual(journal["write_count"], 0)
        self.assertFalse(journal["partition_writes"])
        self.assertEqual(manifest["status"], live.PASS_ALREADY_LOW)
        self.assertEqual(manifest["private_journal_sha256"], hashlib.sha256(journal_path.read_bytes()).hexdigest())
        self.assertEqual(manifest["preimage_sha256"], hashlib.sha256(self.low).hexdigest())
        self.assertEqual(manifest["preimage_size"], core.PARAM_PARTITION_BYTES)
        self.assertEqual(manifest["preimage_filename"], "live.preimage.bin")
        self.assertFalse(manifest["partition_writes"])
        self.assertNotIn("image", manifest)
        self.assertNotIn("cmdline_before", manifest)

    def test_real_identity_allows_apply_mid_source_with_live_mid(self) -> None:
        result, _events, exchange, _cleanup = self._run_effect(
            self.mid,
            experiment_id="identity-apply-mid-live-mid",
            live_debug_level="0x494d",
        )
        self.assertIsNotNone(result)
        assert result is not None
        journal = json.loads(result[0].read_text())
        manifest = json.loads(result[1].read_text())
        self.assertEqual(journal["classification"], core.RECOVERABLE_MID)
        self.assertEqual(journal["status"], live.PASS_RECOVERED_LOW)
        self.assertEqual(journal["source_action"], "apply-mid")
        self.assertEqual(journal["source_debug_level"], "0x4f4c")
        self.assertEqual(journal["live_debug_level"], "0x494d")
        self.assertEqual(manifest["source_debug_level"], "0x4f4c")
        self.assertEqual(manifest["live_debug_level"], "0x494d")
        self.assertEqual(exchange.call_count, 4)
        self.assertEqual(exchange.call_args_list[-1].args[2].evidence_id, "param_debug_recovery")
        self._discard_run_artifacts(result, "identity-apply-mid-live-mid")

    def test_real_identity_allows_same_boot_low_cmdline_with_mid_param_capture(self) -> None:
        result, _events, exchange, _cleanup = self._run_effect(
            self.mid,
            experiment_id="identity-same-boot-low-mid-param",
            live_debug_level="0x4f4c",
        )
        self.assertIsNotNone(result)
        assert result is not None
        journal = json.loads(result[0].read_text())
        self.assertEqual(journal["classification"], core.RECOVERABLE_MID)
        self.assertEqual(journal["source_debug_level"], "0x4f4c")
        self.assertEqual(journal["live_debug_level"], "0x4f4c")
        self.assertEqual(exchange.call_args_list[-1].args[2].evidence_id, "param_debug_recovery")
        self._discard_run_artifacts(result, "identity-same-boot-low-mid-param")

    def test_real_identity_allows_restore_source_debug_variants(self) -> None:
        for index, live_debug in enumerate(("0x4f4c", "0x494d"), 1):
            with self.subTest(live_debug=live_debug):
                self._set_source_action("restore-low")
                experiment_id = f"identity-restore-{index}"
                result, _events, exchange, _cleanup = self._run_effect(
                    self.mid,
                    experiment_id=experiment_id,
                    live_debug_level=live_debug,
                )
                self.assertIsNotNone(result)
                assert result is not None
                journal = json.loads(result[0].read_text())
                self.assertEqual(journal["source_action"], "restore-low")
                self.assertEqual(journal["source_debug_level"], "0x494d")
                self.assertEqual(journal["live_debug_level"], live_debug)
                self.assertEqual(journal["classification"], core.RECOVERABLE_MID)
                self.assertEqual(exchange.call_args_list[-1].args[2].evidence_id, "param_debug_recovery")
                self._discard_run_artifacts(result, experiment_id)
        self._set_source_action("apply-mid")

    def test_real_identity_rejects_unknown_or_high_live_debug_before_effect(self) -> None:
        self._set_source_action("apply-mid")
        for index, live_debug in enumerate(("0x4948", "0x9999"), 1):
            with self.subTest(live_debug=live_debug):
                experiment_id = f"identity-invalid-debug-{index}"
                with self.assertRaises(live.LiveRecoveryError):
                    self._run_effect(
                        self.mid,
                        experiment_id=experiment_id,
                        live_debug_level=live_debug,
                    )
                self.assertEqual(self.last_effect_exchange.call_count, 2)
                self.assertFalse(
                    any(event == "dispatch" for event in self.last_effect_events)
                )
                journal_path = self.root / "evidence" / "private" / f"{experiment_id}.journal.json"
                manifest_path = self.root / "evidence" / "manifests" / f"{experiment_id}.manifest.json"
                self.assertTrue(journal_path.exists())
                self.assertTrue(manifest_path.exists())
                journal_path.unlink()
                manifest_path.unlink()
                self._discard_run_artifacts(None, experiment_id)

    def test_mid_and_torn_recover_with_one_fixed_effect_and_low_posthash(self) -> None:
        torn = bytearray(self.low)
        torn[core.PARAM_DEBUG_OFFSET : core.PARAM_DEBUG_OFFSET + 4] = b"XXXX"
        for image, classification in ((self.mid, core.RECOVERABLE_MID), (bytes(torn), core.RECOVERABLE_TORN)):
            with self.subTest(classification=classification):
                result, events, exchange, cleanup = self._run_effect(image)
                self.assertIsNotNone(result)
                assert result is not None
                journal = json.loads(result[0].read_text())
                manifest = json.loads(result[1].read_text())
                self.assertEqual(journal["classification"], classification)
                self.assertEqual(journal["status"], live.PASS_RECOVERED_LOW)
                self.assertEqual(journal["write_count"], 1)
                self.assertTrue(journal["partition_writes"])
                self.assertFalse(journal["effect_replayed"])
                self.assertEqual(journal["current_state"], "LOW")
                self.assertEqual(manifest["status"], live.PASS_RECOVERED_LOW)
                self.assertEqual(manifest["write_count"], 1)
                self.assertTrue(manifest["partition_writes"])
                self.assertTrue(manifest["effect"]["fixed_dlow"])
                self.assertEqual(manifest["preimage_filename"], "live.preimage.bin")
                self.assertEqual(
                    manifest["private_journal_sha256"],
                    hashlib.sha256(result[0].read_bytes()).hexdigest(),
                )
                self.assertEqual(exchange.call_count, 1)
                self.assertEqual(exchange.call_args.args[2].argv, core.FIXED_EFFECT_ARGV)
                self.assertEqual(exchange.call_args.args[2].evidence_id, "param_debug_recovery")
                self.assertEqual(events.count("dispatch"), 1)
                self.assertLess(events.index("stage"), events.index("smoke"))
                self.assertLess(events.index("smoke"), events.index("dispatch"))
                self.assertLess(events.index("dispatch"), events.index("post_hash"))
                self.assertEqual(cleanup.call_count, 1)
                self.assertLess(events.index("post_hash"), events.index("cleanup"))
                claim = live._source_claim_path(
                    core.validate_source_path(
                        self.root / "evidence" / "private" / f"{self.source_id}.journal.json",
                        root=self.root,
                    )
                )
                if claim.exists():
                    claim.unlink()
                for effect_claim in (
                    self.root / "evidence" / "private" / ".param-debug-effect-consumption"
                ).glob("*.claim.json"):
                    effect_claim.unlink()
                result[0].unlink()
                result[1].unlink()
                (self.root / "evidence" / "private" / "live.preimage.bin").unlink()

    def test_capture_rebinds_immediately_before_each_remote_phase(self) -> None:
        events: list[str] = []

        def bind(label: str) -> None:
            events.append(f"bind:{label}")

        def device_hash(*args):
            phase = args[-1]
            events.append(f"remote:{phase}")
            return core.ROLLBACK_SHA256

        def binary(*args):
            events.append("remote:binary")
            return {"cmd": "cat", "rc": "0", "status": "ok"}, self.low

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(live, "device_sha256", side_effect=device_hash), \
             mock.patch.object(live, "binary_exchange", side_effect=binary):
            captured = live._capture_preimage(
                self.partition,
                Path(directory) / "preimage.bin",
                live._Budget(30.0),
                1.0,
                1.0,
                1.0,
                before_remote=bind,
            )
        self.assertEqual(captured["sha256"], core.ROLLBACK_SHA256)
        self.assertEqual(
            events,
            [
                "bind:capture_before_hash",
                "remote:recovery_before",
                "bind:capture_binary",
                "remote:binary",
                "bind:capture_after_hash",
                "remote:recovery_after",
            ],
        )

        blocked: list[str] = []

        def fail_binary_bind(label: str) -> None:
            blocked.append(label)
            if label == "capture_binary":
                raise live.BridgeBindingFailure("binding drift")

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(live, "device_sha256", side_effect=device_hash), \
             mock.patch.object(live, "binary_exchange") as binary_call:
            with self.assertRaises(live.BridgeBindingFailure):
                live._capture_preimage(
                    self.partition,
                    Path(directory) / "preimage.bin",
                    live._Budget(30.0),
                    1.0,
                    1.0,
                    1.0,
                    before_remote=fail_binary_bind,
                )
        binary_call.assert_not_called()
        self.assertEqual(blocked, ["capture_before_hash", "capture_binary"])

    def test_cleanup_binding_failure_skips_all_subsequent_remote_commands(self) -> None:
        binding = {"process_pid": 1}
        remote = mock.Mock()
        node_cleanup = mock.Mock()

        with mock.patch.object(
            live, "revalidate_bridge_binding", side_effect=RuntimeError("drift")
        ), mock.patch.object(live, "run_toybox", side_effect=remote), mock.patch.object(
            live, "remove_node", node_cleanup
        ):
            errors = live._cleanup_all(
                self.partition,
                binding,
                live._Budget(30.0),
                1.0,
                [],
            )
        self.assertTrue(errors)
        remote.assert_not_called()
        node_cleanup.assert_not_called()

    def test_effect_timeout_is_bounded_and_exposed_without_endpoint_controls(self) -> None:
        parser = live.build_parser()
        parsed = parser.parse_args(
            [
                "--experiment-id",
                "live",
                "--source-experiment-id",
                self.source_id,
                "--execute",
                "--effect-timeout",
                "12",
            ]
        )
        self.assertEqual(parsed.effect_timeout, 12.0)
        for value in (0.0, float("nan"), float("inf"), live.MAX_EFFECT_TIMEOUT + 1):
            with self.subTest(value=value):
                with self.assertRaises(live.LiveRecoveryError):
                    live._validate_timeout(value, "effect-timeout", live.MAX_EFFECT_TIMEOUT)

    def test_dispatch_failures_preserve_ambiguous_marker_and_skip_cleanup(self) -> None:
        malformed = SimpleNamespace(
            begin={"seq": "1", "cmd": "run"},
            end={"seq": "1", "cmd": "run", "rc": "not-an-int", "status": "ok"},
            payload=b"",
            transcript=b"",
        )
        failures = (
            ("dispatch-timeout", TimeoutError("dispatch timed out"), False),
            ("dispatch-malformed", malformed, False),
            ("dispatch-wrong-hash", None, True),
        )
        for experiment_id, dispatch, wrong_hash in failures:
            with self.subTest(experiment_id=experiment_id):
                with self.assertRaises(BaseException):
                    self._run_effect(
                        self.mid,
                        experiment_id=experiment_id,
                        dispatch=dispatch,
                        post_hash=core.MID_SHA256 if wrong_hash else None,
                    )
                journal_path = self.root / "evidence" / "private" / f"{experiment_id}.journal.json"
                manifest_path = self.root / "evidence" / "manifests" / f"{experiment_id}.manifest.json"
                journal = json.loads(journal_path.read_text())
                manifest = json.loads(manifest_path.read_text())
                self.assertEqual(journal["status"], core.AMBIGUOUS_STATUS)
                self.assertEqual(journal["write_count"], 1)
                self.assertTrue(journal["partition_writes"])
                self.assertFalse(journal["effect_replayed"])
                self.assertTrue(journal["cleanup"]["skipped"])
                self.assertEqual(manifest["status"], core.AMBIGUOUS_STATUS)
                self.assertEqual(manifest["write_count"], 1)
                self.assertTrue(manifest["partition_writes"])
                self.assertEqual(manifest["effect"]["write_count"], 1)
                self.assertNotIn("effect_argv", manifest)
                # No cleanup or post-hash command follows a dispatch failure;
                # the dispatch itself is the only exchange after preflight.
                self.assertEqual(self.last_effect_exchange.call_count, 1)
                self.assertEqual(self.last_effect_cleanup.call_count, 0)
                if wrong_hash:
                    self.assertEqual(self.last_effect_events.count("post_hash"), 1)
                else:
                    self.assertEqual(self.last_effect_events.count("post_hash"), 0)
                claim = live._source_claim_path(
                    core.validate_source_path(
                        self.root / "evidence" / "private" / f"{self.source_id}.journal.json",
                        root=self.root,
                    )
                )
                if claim.exists():
                    claim.unlink()
                for effect_claim in (
                    self.root / "evidence" / "private" / ".param-debug-effect-consumption"
                ).glob("*.claim.json"):
                    effect_claim.unlink()
                journal_path.unlink()
                manifest_path.unlink()
                (self.root / "evidence" / "private" / f"{experiment_id}.preimage.bin").unlink()

    def test_prearm_failures_cleanup_without_dispatch(self) -> None:
        cases = (
            ("stage-failure", {"stage_error": RuntimeError("stage")}),
            ("smoke-failure", {"smoke_error": RuntimeError("smoke")}),
            ("binding-failure", {"rebind_error": RuntimeError("binding")}),
            ("marker-persist-failure", {"persist_marker_error": RuntimeError("persist")}),
        )
        for experiment_id, kwargs in cases:
            with self.subTest(experiment_id=experiment_id):
                with self.assertRaises(BaseException):
                    self._run_effect(self.mid, experiment_id=experiment_id, **kwargs)
                journal_path = self.root / "evidence" / "private" / f"{experiment_id}.journal.json"
                manifest_path = self.root / "evidence" / "manifests" / f"{experiment_id}.manifest.json"
                journal = json.loads(journal_path.read_text())
                manifest = json.loads(manifest_path.read_text())
                if experiment_id == "marker-persist-failure":
                    # The O_EXCL source claim may already be durable when the
                    # journal marker fsync fails; preserve no-replay state and
                    # defer all cleanup conservatively.
                    self.assertEqual(journal["status"], core.AMBIGUOUS_STATUS)
                    self.assertEqual(journal["write_count"], 1)
                    self.assertTrue(journal["partition_writes"])
                    self.assertTrue(journal["effect_dispatched"])
                    self.assertTrue(journal["cleanup"]["skipped"])
                    self.assertEqual(manifest["write_count"], 1)
                    self.assertTrue(manifest["partition_writes"])
                    self.assertEqual(self.last_effect_exchange.call_count, 0)
                    self.assertEqual(self.last_effect_cleanup.call_count, 0)
                else:
                    self.assertEqual(journal["status"], live.PRE_EFFECT_PREFLIGHT_INCOMPLETE)
                    self.assertEqual(journal["write_count"], 0)
                    self.assertFalse(journal["partition_writes"])
                    self.assertFalse(journal["effect_dispatched"])
                    self.assertTrue(journal["cleanup"]["proved"])
                    self.assertEqual(manifest["write_count"], 0)
                    self.assertFalse(manifest["partition_writes"])
                    self.assertEqual(self.last_effect_exchange.call_count, 0)
                    self.assertEqual(self.last_effect_cleanup.call_count, 1)
                journal_path.unlink()
                manifest_path.unlink()
                preimage = self.root / "evidence" / "private" / f"{experiment_id}.preimage.bin"
                if preimage.exists():
                    preimage.unlink()

    def test_post_marker_node_or_payload_swap_is_ambiguous_without_dispatch(self) -> None:
        for suffix, mutation in (
            ("node-swap", "node rdev changed after smoke"),
            ("payload-swap", "staged payload bytes changed after smoke"),
        ):
            with self.subTest(suffix=suffix):
                experiment_id = f"target-{suffix}"
                with self.assertRaisesRegex(ValueError, "changed after smoke"):
                    self._run_effect(
                        self.mid,
                        experiment_id=experiment_id,
                        target_error=ValueError(mutation),
                    )
                journal_path = self.root / "evidence" / "private" / f"{experiment_id}.journal.json"
                manifest_path = self.root / "evidence" / "manifests" / f"{experiment_id}.manifest.json"
                journal = json.loads(journal_path.read_text())
                manifest = json.loads(manifest_path.read_text())
                self.assertEqual(journal["status"], core.AMBIGUOUS_STATUS)
                self.assertEqual(journal["write_count"], 1)
                self.assertTrue(journal["cleanup"]["skipped"])
                self.assertEqual(manifest["status"], core.AMBIGUOUS_STATUS)
                self.assertEqual(self.last_effect_exchange.call_count, 0)
                self.assertEqual(self.last_effect_cleanup.call_count, 0)
                claim = live._source_claim_path(
                    core.validate_source_path(
                        self.root / "evidence" / "private" / f"{self.source_id}.journal.json",
                        root=self.root,
                    )
                )
                if claim.exists():
                    claim.unlink()
                for effect_claim in (
                    self.root / "evidence" / "private" / ".param-debug-effect-consumption"
                ).glob("*.claim.json"):
                    effect_claim.unlink()
                journal_path.unlink()
                manifest_path.unlink()
                preimage = self.root / "evidence" / "private" / f"{experiment_id}.preimage.bin"
                if preimage.exists():
                    preimage.unlink()

    def test_wrong_live_gpt_and_binding_stop_before_capture(self) -> None:
        for label in ("live identity", "GPT"):
            with self.subTest(label=label):
                with mock.patch.object(live, "validate_bridge_binding", return_value=self.binding), \
                     mock.patch.object(live, "run_stophud", return_value={"accepted": True}), \
                     mock.patch.object(live, "_validate_live_identity", side_effect=live.LiveRecoveryError(label)), \
                     mock.patch.object(live, "_capture_preimage") as capture:
                    with self.assertRaises(live.LiveRecoveryError):
                        live.execute(args_for(f"bad-{label.replace(' ', '-')}", self.source_id))
                capture.assert_not_called()

        with mock.patch.object(live, "validate_bridge_binding", side_effect=live.LiveRecoveryError("binding")) as binding, \
             mock.patch.object(live, "run_stophud") as stop:
            with self.assertRaises(live.LiveRecoveryError):
                live.execute(args_for("bad-binding", self.source_id))
        binding.assert_called_once_with()
        stop.assert_not_called()

    def test_outside_field_and_capture_hash_mismatch_are_refused(self) -> None:
        changed = bytearray(self.low)
        changed[1] ^= 1
        for image, expected in ((bytes(changed), live.CAPTURE_REFUSED),):
            with mock.patch.object(live, "validate_bridge_binding", return_value=self.binding), \
                 mock.patch.object(live, "revalidate_bridge_binding", return_value=self.binding), \
                 mock.patch.object(live, "run_stophud", return_value={"accepted": True}), \
                 mock.patch.object(live, "_validate_live_identity", return_value=(
                     {}, "1", self.partition, core.PARAM_START_SECTOR, {}
                 )), \
                 mock.patch.object(live, "create_and_validate_node"), \
                 mock.patch.object(live, "_capture_preimage", return_value=self._capture(image)), \
                 mock.patch.object(live, "_cleanup_all", return_value=[]):
                with self.assertRaises(core.ParamDebugRecoveryError):
                    live.execute(args_for("outside-field", self.source_id))
            journal = json.loads((self.root / "evidence" / "private" / "outside-field.journal.json").read_text())
            self.assertEqual(journal["status"], expected)

        # The observed boot-cycle byte may differ without changing semantic
        # LOW eligibility; the full digest is retained as a forensic value.
        volatile_variant = bytearray(self.low)
        volatile_variant[0] = 0x02
        self.assertEqual(
            core.classify_live_image(bytes(volatile_variant)), core.ALREADY_LOW
        )

        with mock.patch.object(live, "validate_bridge_binding", return_value=self.binding), \
             mock.patch.object(live, "revalidate_bridge_binding", return_value=self.binding), \
             mock.patch.object(live, "run_stophud", return_value={"accepted": True}), \
             mock.patch.object(live, "_validate_live_identity", return_value=(
                 {}, "1", self.partition, core.PARAM_START_SECTOR, {}
             )), \
             mock.patch.object(live, "create_and_validate_node"), \
             mock.patch.object(live, "_capture_preimage", side_effect=live.CaptureHashMismatch("mismatch")), \
             mock.patch.object(live, "_cleanup_all", return_value=[]):
            with self.assertRaises(live.CaptureHashMismatch):
                live.execute(args_for("hash-mismatch", self.source_id))
        journal = json.loads((self.root / "evidence" / "private" / "hash-mismatch.journal.json").read_text())
        self.assertEqual(journal["status"], live.CAPTURE_HASH_MISMATCH)

    def test_cleanup_failure_does_not_claim_low_pass(self) -> None:
        with self.assertRaises(live.CleanupFailure):
            self._run(self.low, cleanup_errors=["cleanup_param_node: failed"])
        journal = json.loads((self.root / "evidence" / "private" / "live.journal.json").read_text())
        self.assertEqual(journal["status"], live.CLEANUP_FAILED)
        manifest = json.loads((self.root / "evidence" / "manifests" / "live.manifest.json").read_text())
        self.assertEqual(manifest["status"], live.CLEANUP_FAILED)
        self.assertFalse(manifest["partition_writes"])

    def test_replay_and_symlink_are_rejected_before_binding(self) -> None:
        paths = live.fixed_output_paths("replay")
        paths["journal"].touch()
        with mock.patch.object(live, "validate_bridge_binding") as binding:
            with self.assertRaises(live.LiveRecoveryError):
                live.execute(args_for("replay", self.source_id))
        binding.assert_not_called()
        paths["journal"].unlink()

        symlink_target = self.root / "symlink-target"
        symlink_target.touch()
        symlink_paths = live.fixed_output_paths("symlink")
        symlink_paths["manifest"].symlink_to(symlink_target)
        with mock.patch.object(live, "validate_bridge_binding") as binding, \
             mock.patch.object(live, "exchange") as exchange:
            with self.assertRaises(live.LiveRecoveryError):
                live.execute(args_for("symlink", self.source_id))
        binding.assert_not_called()
        exchange.assert_not_called()

    def test_same_source_new_recovery_id_is_rejected_before_device_calls(self) -> None:
        self._run(self.low)
        args = args_for("new-recovery-id", self.source_id)
        with mock.patch.object(live, "validate_bridge_binding") as binding, mock.patch.object(
            live, "exchange"
        ) as exchange:
            with self.assertRaisesRegex(live.LiveRecoveryError, "consumed"):
                live.execute(args)
        binding.assert_not_called()
        exchange.assert_not_called()

    def test_existing_semantic_effect_claim_is_rejected_before_device_calls(self) -> None:
        source_summary = core.validate_source_path(
            self.root / "evidence" / "private" / f"{self.source_id}.journal.json",
            root=self.root,
        )
        claim = live._claim_effect_consumption(
            live.CANONICAL_EFFECT_ACTION,
            source_summary["device_stable_sha256_before"],
            live._fixed_partition(),
            core.PARAM_START_SECTOR,
            "prior-owner",
            root=self.root,
        )
        claim_path = self.root / "evidence" / "private" / ".param-debug-effect-consumption" / claim["filename"]
        try:
            with mock.patch.object(live, "validate_bridge_binding") as binding, mock.patch.object(
                live, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(live.LiveRecoveryError, "effect claim"):
                    live.execute(args_for("semantic-replay", self.source_id))
            binding.assert_not_called()
            exchange.assert_not_called()
        finally:
            claim_path.unlink()

    def test_recovery_effect_claim_uses_transition_restore_low_key(self) -> None:
        before_hash = core.PARAM_STABLE_MID_SHA256
        partition = live._fixed_partition()
        recovery_path = live._effect_claim_path(
            live.CANONICAL_EFFECT_ACTION,
            before_hash,
            partition,
            core.PARAM_START_SECTOR,
            root=self.root,
        )
        transition_path = transition._effect_claim_path(
            "restore-low",
            before_hash,
            partition,
            core.PARAM_START_SECTOR,
            root=self.root,
        )
        self.assertEqual(live.CANONICAL_EFFECT_ACTION, "restore-low")
        self.assertEqual(recovery_path, transition_path)
        self.assertEqual(
            live._effect_claim_key(
                live.CANONICAL_EFFECT_ACTION,
                before_hash,
                partition,
                core.PARAM_START_SECTOR,
            ),
            transition._effect_claim_key(
                "restore-low", before_hash, partition, core.PARAM_START_SECTOR
            ),
        )
        source_summary = core.validate_source_path(
            self.root / "evidence" / "private" / f"{self.source_id}.journal.json",
            root=self.root,
        )
        self.assertEqual(source_summary["action"], "apply-mid")
        with self.assertRaisesRegex(live.LiveRecoveryError, "exact action"):
            live._ensure_effect_unclaimed({**source_summary, "action": "other"})
        self.assertNotEqual(
            transition._effect_claim_key(
                "apply-mid", before_hash, partition, core.PARAM_START_SECTOR
            ),
            transition._effect_claim_key(
                "restore-low", before_hash, partition, core.PARAM_START_SECTOR
            ),
        )

    def test_apply_mid_source_canonical_claim_collision_blocks_before_binding(self) -> None:
        source_summary = core.validate_source_path(
            self.root / "evidence" / "private" / f"{self.source_id}.journal.json",
            root=self.root,
        )
        # The source action is apply-mid, but recovery's physical effect is
        # always DLOW.  Seed the claim as a normal restore-low owner to prove
        # the opposite owner ordering cannot reach bridge/device contact.
        claim = transition._claim_effect_consumption(
            "restore-low",
            core.PARAM_STABLE_MID_SHA256,
            live._fixed_partition(),
            core.PARAM_START_SECTOR,
            "regular-transition-owner",
            root=self.root,
        )
        claim_path = self.root / "evidence" / "private" / ".param-debug-effect-consumption" / claim["filename"]
        try:
            with mock.patch.object(live, "validate_bridge_binding") as binding, mock.patch.object(
                live, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(live.LiveRecoveryError, "effect claim"):
                    live.execute(args_for("apply-mid-collision", self.source_id))
            binding.assert_not_called()
            exchange.assert_not_called()
        finally:
            claim_path.unlink()

    def test_torn_preimage_claim_keeps_exact_hash_and_canonical_action(self) -> None:
        torn = bytearray(self.low)
        torn[core.PARAM_DEBUG_OFFSET : core.PARAM_DEBUG_OFFSET + 4] = b"XXXX"
        result, _events, _exchange, _cleanup = self._run_effect(
            bytes(torn), experiment_id="torn-canonical-claim"
        )
        self.assertIsNotNone(result)
        assert result is not None
        journal_path, manifest_path = result
        try:
            journal = json.loads(journal_path.read_text())
            expected_hash = capture_contract.stable_param_sha256(bytes(torn))
            claim = journal["effect_consumption_claim"]
            self.assertEqual(claim["action"], live.CANONICAL_EFFECT_ACTION)
            self.assertEqual(claim["action"], "restore-low")
            self.assertEqual(claim["preimage_sha256"], expected_hash)
            expected_path = transition._effect_claim_path(
                "restore-low",
                expected_hash,
                self.partition,
                core.PARAM_START_SECTOR,
                root=self.root,
            )
            self.assertEqual(claim["filename"], expected_path.name)
            self.assertEqual(journal["source_action"], "apply-mid")
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["effect_consumption_claim"]["action"], "restore-low")
        finally:
            source_claim = live._source_claim_path(
                core.validate_source_path(
                    self.root / "evidence" / "private" / f"{self.source_id}.journal.json",
                    root=self.root,
                )
            )
            if source_claim.exists():
                source_claim.unlink()
            for effect_claim in (
                self.root / "evidence" / "private" / ".param-debug-effect-consumption"
            ).glob("*.claim.json"):
                effect_claim.unlink()
            journal_path.unlink()
            manifest_path.unlink()
            (self.root / "evidence" / "private" / "torn-canonical-claim.preimage.bin").unlink()

    def test_semantically_reserialized_source_cannot_bypass_claim(self) -> None:
        self._run(self.low)
        source_path = self.root / "evidence" / "private" / f"{self.source_id}.journal.json"
        source = json.loads(source_path.read_text())
        # The source validator intentionally ignores unrelated journal fields,
        # but the consumption key is the canonical source ID/path.  A changed
        # raw JSON hash must therefore remain blocked for a new recovery ID.
        source["ignored_audit_note"] = "semantically unrelated"
        source_path.write_text(json.dumps(source, separators=(",", ":")) + "\n")
        args = args_for("reserialized-source", self.source_id)
        with mock.patch.object(live, "validate_bridge_binding") as binding, mock.patch.object(
            live, "exchange"
        ) as exchange:
            with self.assertRaisesRegex(live.LiveRecoveryError, "consumed"):
                live.execute(args)
        binding.assert_not_called()
        exchange.assert_not_called()


if __name__ == "__main__":
    unittest.main()
