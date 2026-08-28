from __future__ import annotations

import struct
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from tools import a90_param_capture as capture
from tools import a90_param_debug_transition as transition
from tools.a90_partition_capture import Partition


class A90ParamCaptureTests(unittest.TestCase):
    def test_stable_mask_and_pinned_hash_contract(self) -> None:
        image = Path(
            "evidence/private/verification-006-a90-param-capture-20260825-01/param--sda10.bin"
        ).read_bytes()
        self.assertEqual(capture.PARAM_VOLATILE_RANGES, ((0, 1),))
        self.assertEqual(capture.PARAM_STABLE_RANGE, (1, capture.PARAM_PARTITION_BYTES))
        self.assertEqual(capture.PARAM_STABLE_SIZE, capture.PARAM_PARTITION_BYTES - 1)
        self.assertEqual(
            capture.stable_param_sha256(image), capture.PARAM_STABLE_LOW_SHA256
        )
        variant = bytearray(image)
        variant[0] = 0x02
        self.assertNotEqual(capture.sha256(bytes(variant)), capture.PARAM_LOW_FULL_SHA256)
        self.assertEqual(
            capture.stable_param_sha256(bytes(variant)), capture.PARAM_STABLE_LOW_SHA256
        )
        self.assertEqual(capture.classify_param_image(bytes(variant)), "LOW")
        mid = bytearray(image)
        mid[capture.PARAM_DEBUG_OFFSET : capture.PARAM_DEBUG_OFFSET + 4] = b"DMID"
        self.assertEqual(
            capture.stable_param_sha256(bytes(mid)), capture.PARAM_STABLE_MID_SHA256
        )
        self.assertEqual(capture.classify_param_image(bytes(mid)), "MID")

    def test_stable_hash_rejects_partial_or_stable_range_changes(self) -> None:
        image = bytearray(
            Path(
                "evidence/private/verification-006-a90-param-capture-20260825-01/param--sda10.bin"
            ).read_bytes()
        )
        with self.assertRaisesRegex(ValueError, "exactly"):
            capture.stable_param_sha256(bytes(image[:-1]))
        with self.assertRaisesRegex(ValueError, "bytes"):
            capture.stable_param_sha256(bytearray(image))  # type: ignore[arg-type]
        image[1] ^= 1
        with self.assertRaisesRegex(ValueError, "stable range"):
            capture.classify_param_image(bytes(image))

    def test_exact_partition_validation(self) -> None:
        partition = Partition(
            "param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096
        )
        capture.validate_param_partition(partition, 125080)
        with self.assertRaisesRegex(ValueError, "10 MiB"):
            capture.validate_param_partition(
                Partition("param", "sda10", 8, 10, 20479, 20479 * 512, 0, 4096),
                125080,
            )
        with self.assertRaisesRegex(ValueError, "read-only state"):
            capture.validate_param_partition(
                Partition("param", "sda10", 8, 10, 20480, 0xA00000, 1, 4096),
                125080,
            )
        with self.assertRaisesRegex(ValueError, "125080"):
            capture.validate_param_partition(partition, 125088)

    def test_field_offsets_and_values(self) -> None:
        data = bytearray(capture.PARAM_PARTITION_BYTES)
        values = {
            "debuglevel": capture.KERNEL_DEBUG_LOW,
            "force_upload_flag": 0,
            "FMM_lock": 0,
            "dump_sink": 0,
        }
        for name, value in values.items():
            struct.pack_into("<I", data, capture.FIELD_OFFSETS[name], value)
        decoded = capture.decode_fields(bytes(data))
        self.assertEqual(decoded["debuglevel"]["partition_offset"], "0x900000")
        self.assertEqual(decoded["force_upload_flag"]["partition_offset"], "0x9003f4")
        self.assertEqual(decoded["FMM_lock"]["partition_offset"], "0x9003fc")
        self.assertEqual(decoded["dump_sink"]["partition_offset"], "0x900400")
        self.assertEqual(decoded["debuglevel"]["label"], "LOW")
        self.assertEqual(decoded["FMM_lock"]["label"], "NOT_LOCK_MAGIC")
        self.assertEqual(decoded["dump_sink"]["label"], "USB_DEFAULT")

    def test_decoder_rejects_non_exact_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "image size"):
            capture.decode_fields(b"\0" * 4096)

    def test_cmdline_and_runtime_binding(self) -> None:
        cmdline = capture.parse_cmdline(
            b"androidboot.em.model=SM-A908N "
            b"androidboot.bootloader=A908NKSU5EWA3 "
            b"androidboot.debug_level=0x4f4c"
        )
        version = (
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        capture.validate_runtime(version, cmdline)
        cmdline["androidboot.em.model"] = "SM-S906N"
        with self.assertRaisesRegex(ValueError, "SM-A908N"):
            capture.validate_runtime(version, cmdline)

    def test_param_capture_requires_exact_low_cmdline_contract(self) -> None:
        valid = {
            "androidboot.em.model": capture.TARGET_MODEL,
            "androidboot.bootloader": capture.TARGET_BOOTLOADER,
            "androidboot.debug_level": "0x4f4c",
            "androidboot.force_upload": "0x0",
            "sec_debug.dump_sink": "0x0",
            "androidboot.upload_offset": capture.PARAM_CMDLINE_UPLOAD_OFFSET,
        }
        capture.validate_param_capture_cmdline(valid)
        for key, value in (
            ("androidboot.em.model", "SM-S906N"),
            ("androidboot.bootloader", "A908NKSU5EWA2"),
            ("androidboot.debug_level", "0x1"),
            ("androidboot.force_upload", "0x1"),
            ("sec_debug.dump_sink", "0x1"),
            ("androidboot.upload_offset", "0"),
        ):
            with self.subTest(key=key, value=value):
                bad = dict(valid)
                bad[key] = value
                with self.assertRaisesRegex(ValueError, key):
                    capture.validate_param_capture_cmdline(bad)
        for key in valid:
            with self.subTest(missing=key):
                bad = dict(valid)
                del bad[key]
                with self.assertRaisesRegex(ValueError, key):
                    capture.validate_param_capture_cmdline(bad)
        with self.assertRaises(ValueError):
            capture.validate_param_capture_cmdline(
                {**valid, "androidboot.debug_level": 0x4F4C}  # type: ignore[dict-item]
            )

    def test_cmdline_is_strict_about_bare_flags_keys_values_and_duplicates(self) -> None:
        valid = capture.parse_cmdline(
            b"skip_initramfs rootwait ro androidboot.em.model=SM-A908N"
        )
        self.assertEqual(valid["ro"], "")
        for payload in (
            b"unknown_bare_flag",
            b"ro ro",
            b"bad/key=value",
            b"key==two",
            b"key=",
            b" key=value",
            b"key=value\x00 other=x",
            "key=\N{SNOWMAN}".encode("utf-8"),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    capture.parse_cmdline(payload)

    def test_cmdline_accepts_runs_of_ascii_spaces_but_rejects_other_whitespace(self) -> None:
        canonical = (
            b"skip_initramfs rootwait ro androidboot.em.model=SM-A908N "
            b"androidboot.bootloader=A908NKSU5EWA3\n"
        )
        expected = capture.parse_cmdline(canonical)
        for count in (2, 3, 7):
            with self.subTest(space_count=count):
                spaced = canonical[:-1].replace(b" ", b" " * count) + b"\n"
                self.assertEqual(capture.parse_cmdline(spaced), expected)

        body = canonical[:-1]
        for whitespace in (b"\t", b"\v", b"\f", b"\r", b"\n"):
            with self.subTest(whitespace=whitespace):
                bad = body.replace(b" ", whitespace, 1) + b"\n"
                with self.assertRaises(ValueError):
                    capture.parse_cmdline(bad)
        with self.assertRaises(ValueError):
            capture.parse_cmdline(body.replace(b" ro ", b" ro  ro ") + b"\n")
        for bad in (
            b" " + canonical,
            canonical[:-1] + b" \n",
            canonical + b"\n",
            canonical[:-1] + b"\r\n\n",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    capture.parse_cmdline(bad)

    def test_runtime_rejects_prefix_suffix_and_duplicate_identity_lines(self) -> None:
        version = (
            b"A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)\n"
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        cmdline = {
            "androidboot.em.model": "SM-A908N",
            "androidboot.bootloader": "A908NKSU5EWA3",
        }
        capture.validate_runtime(version, cmdline)
        for bad in (
            version.replace(b"build=v2321", b"build=v2321-extra", 1),
            version + b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n",
            version.replace(b"kernel: Linux", b"prefix kernel: Linux", 1),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    capture.validate_runtime(bad, cmdline)

    def test_cmdline_accepts_embedded_equals_in_values(self) -> None:
        parsed = capture.parse_cmdline(
            b"root=PARTUUID=97d7b011-54da-4835-b3c4-917ad6e73d74 "
            b"video=vfb:640x400,bpp=32,memsize=3072000 "
            b"androidboot.em.model=SM-A908N "
            b"androidboot.bootloader=A908NKSU5EWA3\n"
        )
        self.assertEqual(parsed["root"], "PARTUUID=97d7b011-54da-4835-b3c4-917ad6e73d74")
        self.assertEqual(parsed["video"], "vfb:640x400,bpp=32,memsize=3072000")

    def test_stophud_is_first_device_command_and_double_space_reaches_next_pre_effect_stage(self) -> None:
        calls: list[str] = []
        binding_order: list[str] = []

        class Frame:
            def __init__(self, payload: bytes, command: str) -> None:
                self.payload = payload
                self.begin = {"cmd": command}
                self.end = {"cmd": command, "rc": "0", "status": "ok"}

        version = (
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        cmdline = (
            b"androidboot.em.model=SM-A908N  "
            b"androidboot.bootloader=A908NKSU5EWA3 "
            b"androidboot.debug_level=0x4f4c "
            b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0 "
            b"androidboot.upload_offset=9438196\n"
        )

        def fake_exchange(host, port, command, timeout):
            del host, port, timeout
            calls.append(command.evidence_id)
            if command.evidence_id == "version":
                return Frame(version, "version")
            if command.evidence_id == "proc_cmdline":
                return Frame(cmdline, "cat")
            if command.evidence_id == "download_mode":
                return Frame(b"1\n", "cat")
            raise AssertionError(command.evidence_id)

        def fake_stophud(host, port, timeout, exchange, *, frame_records, persist):
            del host, port, timeout, exchange, persist
            binding_order.append("stophud")
            calls.append("stophud")
            frame_records.append({"evidence_id": "stophud"})
            return {"accepted": True, "busy_retries": 0, "attempts": []}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding = {"pid": 1}
            args = Namespace(
                execute=True,
                experiment_id="param-order",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                capture_timeout=1.0,
            )
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture,
                "validate_bridge_binding",
                side_effect=lambda: (binding_order.append("initial"), binding)[1],
            ), mock.patch.object(
                capture,
                "revalidate_bridge_binding",
                side_effect=lambda value: (binding_order.append("rebind"), value)[1],
            ), mock.patch.object(
                capture, "run_stophud", side_effect=fake_stophud
            ), mock.patch.object(
                capture, "exchange", side_effect=fake_exchange
            ), mock.patch.object(
                capture, "discover_param", side_effect=RuntimeError("stop after preflight")
            ):
                with self.assertRaisesRegex(RuntimeError, "stop after preflight"):
                    capture.collect(args)
            self.assertTrue(
                (root / "evidence/private/param-order/capture-journal.json").exists()
            )
        self.assertEqual(calls[0], "stophud")
        self.assertEqual(calls[1:], ["version", "proc_cmdline", "download_mode"])
        self.assertEqual(binding_order, ["initial", "rebind", "stophud"])

    def test_param_transition_preflight_accepts_double_space_cmdline_before_write(self) -> None:
        class Frame:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload

        version = (
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        cmdline = (
            b"androidboot.em.model=SM-A908N  "
            b"androidboot.bootloader=A908NKSU5EWA3 "
            b"androidboot.debug_level=0x4f4c "
            b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0 "
            b"androidboot.upload_offset=9438196\n"
        )
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        calls: list[str] = []

        def fake_exchange(host, port, command, timeout):
            del host, port, timeout
            calls.append(command.evidence_id)
            if command.evidence_id == "version":
                return Frame(version)
            if command.evidence_id == "proc_cmdline":
                return Frame(cmdline)
            if command.evidence_id == "download_mode":
                return Frame(b"1\n")
            raise AssertionError(command.evidence_id)

        args = Namespace(
            host="127.0.0.1",
            port=54321,
            command_timeout=1.0,
        )
        with mock.patch.object(transition, "exchange", side_effect=fake_exchange), mock.patch.object(
            transition,
            "discover_param",
            return_value=(partition, 125080),
        ) as discover:
            result = transition._preflight(args)
        self.assertEqual(result[0]["androidboot.em.model"], "SM-A908N")
        self.assertEqual(result[1], "1")
        discover.assert_called_once_with("127.0.0.1", 54321, 1.0)
        self.assertEqual(calls, ["version", "proc_cmdline", "download_mode"])

    def test_bridge_binding_failure_precedes_stophud_and_exchange(self) -> None:
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="param-bind-fail",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                capture_timeout=1.0,
            )
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "validate_bridge_binding", side_effect=RuntimeError("bridge drift")
            ) as bind, mock.patch.object(
                capture, "run_stophud", side_effect=lambda *a, **k: calls.append("stophud")
            ), mock.patch.object(
                capture, "exchange", side_effect=lambda *a, **k: calls.append("exchange")
            ):
                with self.assertRaisesRegex(RuntimeError, "bridge drift"):
                    capture.collect(args)
            bind.assert_called_once_with()
        self.assertEqual(calls, [])

    def test_pre_stophud_bridge_drift_stops_before_any_stateful_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding = {"pid": 1}
            args = Namespace(
                execute=True,
                experiment_id="param-pre-stophud-drift",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                capture_timeout=1.0,
            )
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                capture, "revalidate_bridge_binding", return_value={"pid": 2}
            ) as rebind, mock.patch.object(capture, "run_stophud") as stophud, mock.patch.object(
                capture, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(RuntimeError, "drifted before mutation group"):
                    capture.collect(args)
            rebind.assert_called_once_with(binding)
            stophud.assert_not_called()
            exchange.assert_not_called()
            journal = json.loads(
                (root / "evidence/private/param-pre-stophud-drift/capture-journal.json").read_text()
            )
            self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")
            incident = root / "evidence/manifests/param-pre-stophud-drift.manifest.json"
            self.assertTrue(incident.exists())

    def test_stophud_retry_rebind_drift_allows_only_one_attempt(self) -> None:
        class Frame:
            payload = b""
            transcript = b""

            def __init__(self) -> None:
                self.begin = {"cmd": "stophud", "seq": "1"}
                self.end = {
                    "cmd": "stophud",
                    "seq": "1",
                    "rc": "-16",
                    "status": "busy",
                }

        binding = {"pid": 1}
        calls: list[str] = []

        def fake_exchange(host, port, command, timeout, *, allow_error=False):
            del host, port, timeout, allow_error
            calls.append(command.evidence_id)
            if command.evidence_id == "stophud":
                return Frame()
            raise AssertionError(command.evidence_id)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="param-retry-drift",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                capture_timeout=1.0,
            )
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                capture,
                "revalidate_bridge_binding",
                side_effect=[binding, binding, RuntimeError("drift before retry")],
            ) as rebind, mock.patch.object(
                capture, "exchange", side_effect=fake_exchange
            ) as exchange:
                with self.assertRaisesRegex(RuntimeError, "drift before retry"):
                    capture.collect(args)
            self.assertEqual(calls, ["stophud"])
            self.assertEqual(rebind.call_count, 3)
            self.assertEqual(exchange.call_count, 1)
            journal = json.loads(
                (root / "evidence/private/param-retry-drift/capture-journal.json").read_text()
            )
            self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")
            self.assertEqual(len(journal["stophud_attempts"]), 2)
            self.assertEqual(journal["stophud_attempts"][0]["status"], "busy")

    def test_nonpinned_bridge_host_or_port_fails_before_contact(self) -> None:
        for host, port in (("localhost", 54321), ("127.0.0.1", 54322)):
            with self.subTest(host=host, port=port), tempfile.TemporaryDirectory() as directory:
                args = Namespace(
                    execute=True,
                    experiment_id="param-endpoint-fail",
                    host=host,
                    port=port,
                    command_timeout=1.0,
                    capture_timeout=1.0,
                )
                with mock.patch.object(capture, "validate_bridge_binding") as bind, mock.patch.object(
                    capture, "exchange"
                ) as exchange:
                    with self.assertRaisesRegex(ValueError, "pinned"):
                        capture.collect(args)
                bind.assert_not_called()
                exchange.assert_not_called()

    def test_execute_and_timeout_gates_before_output_or_contact(self) -> None:
        parser = capture.build_parser()
        for argv in (
            ["--experiment-id", "gate"],
            ["--experiment-id", "gate", "--execute", "--command-timeout", "nan"],
            ["--experiment-id", "gate", "--execute", "--capture-timeout", "inf"],
            ["--experiment-id", "gate", "--execute", "--command-timeout", "0"],
        ):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as directory:
                args = parser.parse_args(argv)
                with mock.patch.object(capture, "REPO_ROOT", Path(directory)), mock.patch.object(
                    capture, "validate_bridge_binding"
                ) as bind:
                    with self.assertRaises(ValueError):
                        capture.collect(args)
                bind.assert_not_called()

    def test_parser_rejects_output_root_option(self) -> None:
        parser = capture.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["--experiment-id", "parser-root", "--output-root", "/tmp/other"]
            )

    def test_injected_nonfixed_output_root_fails_before_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixed_root = Path(directory) / "fixed"
            injected_root = Path(directory) / "injected"
            fixed_root.mkdir()
            args = Namespace(
                execute=True,
                experiment_id="injected-root",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                capture_timeout=1.0,
                output_root=injected_root,
            )
            with mock.patch.object(capture, "REPO_ROOT", fixed_root), mock.patch.object(
                capture, "validate_bridge_binding"
            ) as bind, mock.patch.object(capture, "exchange") as exchange:
                with self.assertRaisesRegex(ValueError, "fixed to REPO_ROOT"):
                    capture.collect(args)
            bind.assert_not_called()
            exchange.assert_not_called()

    def test_cleanup_requires_matching_binding_and_publishes_redacted_incident(self) -> None:
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 1, 4096)
        version = (
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        cmdline = (
            b"androidboot.em.model=SM-A908N "
            b"androidboot.bootloader=A908NKSU5EWA3 "
            b"androidboot.debug_level=0x4f4c "
            b"androidboot.force_upload=0x0 sec_debug.dump_sink=0x0 "
            b"androidboot.upload_offset=9438196\n"
        )
        payload = b"\0" * capture.PARAM_PARTITION_BYTES
        host_hash = capture.sha256(payload)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}

        class Frame:
            def __init__(self, payload: bytes, command: str) -> None:
                self.payload = payload
                self.begin = {"cmd": command, "seq": "1"}
                self.end = {
                    "cmd": command,
                    "seq": "1",
                    "rc": "0",
                    "status": "ok",
                }

        def fake_exchange(host, port, command, timeout):
            del host, port, timeout
            if command.evidence_id == "version":
                return Frame(version, "version")
            if command.evidence_id == "proc_cmdline":
                return Frame(cmdline, "cat")
            if command.evidence_id == "download_mode":
                return Frame(b"1\n", "cat")
            raise AssertionError(command.evidence_id)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="param-cleanup-bind-fail",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                capture_timeout=1.0,
            )
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                capture,
                "revalidate_bridge_binding",
                side_effect=[binding, RuntimeError("cleanup bridge drift")],
            ) as rebind, mock.patch.object(
                capture, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(
                capture, "exchange", side_effect=fake_exchange
            ), mock.patch.object(
                capture, "discover_param", return_value=(partition, 125080)
            ), mock.patch.object(capture, "create_and_validate_node"), mock.patch.object(
                capture, "device_sha256", return_value=host_hash
            ), mock.patch.object(
                capture, "binary_exchange", return_value=({}, payload)
            ), mock.patch.object(capture, "fsync_directory"), mock.patch.object(
                capture, "remove_node"
            ) as remove_node:
                with self.assertRaisesRegex(RuntimeError, "cleanup was not proved"):
                    capture.collect(args)
            self.assertEqual(rebind.call_args_list, [mock.call(binding), mock.call(binding)])
            remove_node.assert_not_called()
            incident = root / "evidence/manifests/param-cleanup-bind-fail.manifest.json"
            self.assertTrue(incident.exists())
            self.assertNotIn("/dev/serial", incident.read_text())
            journal = json.loads(
                (root / "evidence/private/param-cleanup-bind-fail/capture-journal.json").read_text()
            )
        self.assertEqual(journal["status"], "CLEANUP_DEFERRED_RECONCILE_REQUIRED")
        self.assertTrue(journal["cleanup_deferred"])
        self.assertTrue(journal["reconcile_required"])


if __name__ == "__main__":
    unittest.main()
