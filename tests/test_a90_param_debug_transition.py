from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from tools import a90_param_debug_transition as transition
from tools.a90_partition_capture import Partition


class A90ParamDebugTransitionTests(unittest.TestCase):
    def test_host_images_match_both_complete_hash_pins(self) -> None:
        original, modified = transition.derive_images()
        self.assertEqual(transition.sha256(original), transition.ROLLBACK_SHA256)
        self.assertEqual(transition.sha256(modified), transition.MID_SHA256)
        differences = [
            index for index, pair in enumerate(zip(original, modified)) if pair[0] != pair[1]
        ]
        self.assertEqual(
            differences,
            [
                transition.PARAM_DEBUG_OFFSET + 1,
                transition.PARAM_DEBUG_OFFSET + 2,
                transition.PARAM_DEBUG_OFFSET + 3,
            ],
        )

    def test_transitions_are_exact_inverses(self) -> None:
        original, modified = transition.derive_images()
        apply_before, apply_after = transition.transition_images(
            transition.TRANSITIONS["apply-mid"], original, modified
        )
        restore_before, restore_after = transition.transition_images(
            transition.TRANSITIONS["restore-low"], original, modified
        )
        self.assertEqual((apply_before, apply_after), (original, modified))
        self.assertEqual((restore_before, restore_after), (modified, original))

    def test_dd_target_offset_and_extent_are_fixed(self) -> None:
        args = transition.fixed_dd_args("/tmp/in", "/dev/fixed")
        self.assertIn("bs=4", args)
        self.assertIn("count=1", args)
        self.assertIn("seek=2359296", args)
        self.assertIn("conv=notrunc,fsync", args)
        self.assertEqual(transition.DD_SEEK_BLOCKS * 4, 0x900000)
        self.assertNotIn("seek=0", args)
        self.assertEqual(transition.PARAM_STABLE_LOW_SHA256, transition.LOW_STABLE_SHA256)

    def test_live_capture_contract_accepts_byte0_variant_and_rejects_stable_delta(self) -> None:
        original, _modified = transition.derive_images()
        variant = bytearray(original)
        variant[0] = 0x02
        with mock.patch.object(
            transition,
            "binary_exchange",
            return_value=({"cmd": "run", "rc": "0", "status": "ok"}, bytes(variant)),
        ):
            evidence = transition._capture_exact_param_image(
                "127.0.0.1", 54321, Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096), 1.0, "test"
            )
        self.assertEqual(evidence["stable_sha256"], transition.LOW_STABLE_SHA256)
        self.assertNotEqual(evidence["full_sha256"], transition.ROLLBACK_SHA256)
        bad = bytearray(original)
        bad[1] ^= 1
        with mock.patch.object(
            transition,
            "binary_exchange",
            return_value=({"cmd": "run", "rc": "0", "status": "ok"}, bytes(bad)),
        ):
            with self.assertRaisesRegex(ValueError, "stable"):
                # The helper computes/records the stable hash; eligibility
                # callers must reject a non-pinned value.
                result = transition._capture_exact_param_image(
                    "127.0.0.1", 54321, Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096), 1.0, "test"
                )
                if result["stable_sha256"] != transition.LOW_STABLE_SHA256:
                    raise ValueError("stable image changed")

    def test_node_stat_parser_accepts_live_crlf_without_terminal_and_closed_lf_variants(self) -> None:
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        valid = b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\n"
        parsed = transition._require_stat_rdev(valid, partition)
        self.assertEqual(parsed["raw"], valid.decode("ascii"))
        self.assertEqual(parsed["rdev"], "rdev=8:10")
        live = b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10"
        self.assertEqual(len(live), 39)
        self.assertEqual(
            hashlib.sha256(live).hexdigest(),
            "0993514304d5b15b220d3b97c687e7ebd086ec7d67c7e2543bd5da0adb39a97c",
        )
        live_parsed = transition._require_stat_rdev(live, partition)
        self.assertEqual(live_parsed["raw"], live.decode("ascii"))
        self.assertEqual(live_parsed["rdev"], "rdev=8:10")
        for retained in (
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10",
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10\r\n",
        ):
            with self.subTest(retained=retained):
                self.assertEqual(
                    transition._require_stat_rdev(retained, partition)["rdev"],
                    "rdev=8:10",
                )
        invalid = (
            b" mode=0600 uid=0 gid=0 size=0\nrdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0 \nrdev=8:10\n",
            b"mode=0600  uid=0 gid=0 size=0\nrdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\n\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\x00\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\ntrailing",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:100\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=18:10\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    transition._require_stat_rdev(payload, partition)

    def test_live_stat_parser_failure_publishes_pre_effect_journal_before_cleanup(self) -> None:
        original, modified = transition.derive_images()
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        live_stat = b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10"
        events: list[str] = []

        def fake_create(*args, **kwargs):
            del args, kwargs
            parsed = transition._require_stat_rdev(live_stat, partition)
            if parsed["rdev"] != "rdev=8:10":
                raise AssertionError(parsed)
            # Reproduce the old live r3 failure at the main pre-effect seam
            # after proving the repaired parser accepts the exact receipt.
            raise ValueError("param block-node stat contains malformed line framing")

        def fake_remove_temp(*args, **kwargs):
            del kwargs
            events.append(f"temp:{args[-1]}")

        def fake_remove_node(*args, **kwargs):
            del args, kwargs
            events.append("node")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="transition-live-stat-failure",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "revalidate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(
                transition,
                "_preflight",
                return_value=({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080),
            ), mock.patch.object(
                transition, "create_and_validate_node", side_effect=fake_create
            ), mock.patch.object(
                transition, "_remove_temp", side_effect=fake_remove_temp
            ), mock.patch.object(
                transition, "remove_node", side_effect=fake_remove_node
            ), mock.patch.object(transition, "exchange") as exchange:
                with self.assertRaisesRegex(ValueError, "stat contains malformed line framing"):
                    with mock.patch.object(transition, "REPO_ROOT", root):
                        transition.execute(args)
            journal = json.loads(
                (root / "evidence/private/transition-live-stat-failure.journal.json").read_text()
            )

        self.assertEqual(events, ["temp:payload_cleanup_after", "temp:smoke_cleanup_final", "node"])
        self.assertFalse(exchange.called)
        self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")
        self.assertIn("ValueError: param block-node stat contains malformed line framing", journal["error"])
        self.assertFalse(journal["effect_dispatched"])
        self.assertEqual(journal["effect_dispatched_count"], 0)
        self.assertEqual(journal["write_count"], 0)
        self.assertFalse(journal["partition_writes"])
        self.assertTrue(journal["cleanup_attempted"])
        self.assertTrue(journal["cleanup_completed"])
        self.assertTrue(journal["node_cleanup_verified"])
        self.assertFalse(journal["cleanup_deferred"])
        self.assertFalse(journal["reconcile_required"])

    def test_cli_has_no_partition_offset_or_value_inputs(self) -> None:
        parser = transition.build_parser()
        parsed = parser.parse_args(
            ["--experiment-id", "test", "--action", "apply-mid", "--execute"]
        )
        self.assertTrue(parsed.execute)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "--experiment-id",
                        "test",
                        "--action",
                        "apply-mid",
                        "--offset",
                        "0",
                    ]
                )

    def test_cli_has_no_output_root_namespace(self) -> None:
        parser = transition.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "--experiment-id",
                        "test",
                        "--action",
                        "apply-mid",
                        "--execute",
                        "--output-root",
                        "/tmp/other",
                    ]
                )

    def test_initial_journal_and_semantic_effect_claim_are_single_owner(self) -> None:
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / "evidence" / "private" / "first.journal.json"
            transition._write_initial_json(journal, {"owner": "first"})
            with self.assertRaises(FileExistsError):
                transition._write_initial_json(journal, {"owner": "second"})
            with mock.patch.object(transition, "REPO_ROOT", root):
                first_claim = transition._claim_effect_consumption(
                    "apply-mid",
                    transition.ROLLBACK_SHA256,
                    partition,
                    125080,
                    "owner-one",
                )
                self.assertTrue(first_claim["filename"].endswith(".claim.json"))
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    transition._claim_effect_consumption(
                        "apply-mid",
                        transition.ROLLBACK_SHA256,
                        partition,
                        125080,
                        "owner-two",
                    )

    def test_timeout_rejects_nonfinite_nonpositive_and_out_of_range_before_binding(self) -> None:
        original, modified = transition.derive_images()
        for name, value in (
            ("command_timeout", float("nan")),
            ("hash_timeout", float("inf")),
            ("effect_timeout", 0.0),
        ):
            with self.subTest(name=name):
                args = Namespace(
                    execute=True,
                    experiment_id="transition-timeout-gate",
                    action="apply-mid",
                    host="127.0.0.1",
                    port=54321,
                    command_timeout=1.0,
                    hash_timeout=1.0,
                    effect_timeout=1.0,
                )
                setattr(args, name, value)
                with mock.patch.object(
                    transition, "derive_images", return_value=(original, modified)
                ), mock.patch.object(transition, "validate_bridge_binding") as bind:
                    with self.assertRaises(ValueError):
                        transition.execute(args)
                bind.assert_not_called()

    def test_stophud_is_first_device_command_and_journaled_before_param_write(self) -> None:
        original, modified = transition.derive_images()
        events: list[str] = []
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)

        def fake_stophud(host, port, timeout, exchange, *, frame_records, persist):
            del host, port, timeout, exchange
            events.append("stophud")
            frame_records.append({"evidence_id": "stophud", "rc": 0, "status": "ok"})
            result = {
                "accepted": True,
                "busy_retries": 0,
                "attempts": [{"attempt": 1, "rc": 0, "status": "ok"}],
            }
            persist(result["attempts"])
            return result

        def fake_preflight(args):
            del args
            events.append("preflight")
            return ({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080)

        def fake_create(*args):
            del args
            events.append("create_node")
            raise RuntimeError("stop before param write")

        def fake_remove_temp(*args):
            events.append(args[-1])

        def fake_remove_node(*args):
            events.append("remove_node")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
            args = Namespace(
                execute=True,
                experiment_id="transition-order",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition,
                "validate_bridge_binding",
                side_effect=lambda: (events.append("initial_bind"), binding)[1],
            ), mock.patch.object(
                transition,
                "revalidate_bridge_binding",
                side_effect=lambda value: (events.append("rebind"), value)[1],
            ), mock.patch.object(
                transition, "run_stophud", side_effect=fake_stophud
            ), mock.patch.object(
                transition, "_preflight", side_effect=fake_preflight
            ), mock.patch.object(
                transition, "create_and_validate_node", side_effect=fake_create
            ), mock.patch.object(
                transition, "_remove_temp", side_effect=fake_remove_temp
            ), mock.patch.object(
                transition, "remove_node", side_effect=fake_remove_node
            ):
                with self.assertRaisesRegex(RuntimeError, "stop before param write"):
                    with mock.patch.object(transition, "REPO_ROOT", root):
                        transition.execute(args)
            journal_path = root / "evidence/private/transition-order.journal.json"
            journal = json.loads(journal_path.read_text())
        self.assertEqual(events[:4], ["initial_bind", "rebind", "stophud", "preflight"])
        self.assertEqual(events[4:6], ["rebind", "create_node"])
        self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")
        self.assertFalse(journal["effect_dispatched"])
        self.assertEqual(journal["effect_dispatched_count"], 0)
        self.assertEqual(journal["write_count"], 0)
        self.assertFalse(journal["partition_writes"])
        self.assertTrue(journal["cleanup_attempted"])
        self.assertTrue(journal["cleanup_completed"])
        self.assertTrue(journal["node_cleanup_verified"])
        self.assertFalse(journal["cleanup_deferred"])
        self.assertFalse(journal["reconcile_required"])
        self.assertEqual(journal["stophud"]["accepted"], True)
        self.assertEqual(journal["stophud_frames"][0]["evidence_id"], "stophud")
        self.assertNotIn("effect_argv", journal)

    def test_bridge_binding_failure_precedes_stophud_and_device_contact(self) -> None:
        original, modified = transition.derive_images()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="transition-bind-fail",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", side_effect=RuntimeError("bridge drift")
            ) as bind, mock.patch.object(transition, "run_stophud") as stophud, mock.patch.object(
                transition, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(RuntimeError, "bridge drift"):
                    with mock.patch.object(transition, "REPO_ROOT", root):
                        transition.execute(args)
            bind.assert_called_once_with()
            stophud.assert_not_called()
            exchange.assert_not_called()

    def test_pre_stophud_bridge_drift_refuses_before_stophud_or_reads(self) -> None:
        original, modified = transition.derive_images()
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="transition-pre-stophud-drift",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "revalidate_bridge_binding", return_value={"process_pid": 999}
            ) as rebind, mock.patch.object(transition, "run_stophud") as stophud, mock.patch.object(
                transition, "exchange"
            ) as exchange:
                with self.assertRaisesRegex(RuntimeError, "immediately before stophud"):
                    with mock.patch.object(transition, "REPO_ROOT", root):
                        transition.execute(args)
            rebind.assert_called_once_with(binding)
            stophud.assert_not_called()
            exchange.assert_not_called()
            journal = json.loads(
                (root / "evidence/private/transition-pre-stophud-drift.journal.json").read_text()
            )
            self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")

    def test_stophud_retry_rebind_drift_prevents_second_attempt_and_reads(self) -> None:
        original, modified = transition.derive_images()
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}

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
            del host, port, timeout, allow_error
            calls.append(command.evidence_id)
            if command.evidence_id == "stophud":
                return Frame()
            raise AssertionError(f"unexpected substantive command: {command.evidence_id}")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                execute=True,
                experiment_id="transition-retry-drift",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition,
                "revalidate_bridge_binding",
                side_effect=[binding, binding, RuntimeError("drift before retry")],
            ) as rebind, mock.patch.object(
                transition, "exchange", side_effect=fake_exchange
            ) as exchange, mock.patch.object(transition, "_preflight") as preflight:
                with self.assertRaisesRegex(RuntimeError, "drift before retry"):
                    with mock.patch.object(transition, "REPO_ROOT", root):
                        transition.execute(args)
            self.assertEqual(calls, ["stophud"])
            self.assertEqual(rebind.call_count, 3)
            self.assertEqual(exchange.call_count, 1)
            preflight.assert_not_called()
            journal = json.loads(
                (root / "evidence/private/transition-retry-drift.journal.json").read_text()
            )
            self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")
            self.assertEqual(len(journal["stophud_attempts"]), 2)

    def test_nonpinned_bridge_host_or_port_fails_before_contact(self) -> None:
        original, modified = transition.derive_images()
        for host, port in (("localhost", 54321), ("127.0.0.1", 54322)):
            with self.subTest(host=host, port=port), tempfile.TemporaryDirectory() as directory:
                args = Namespace(
                    execute=True,
                    experiment_id="transition-endpoint-fail",
                    action="apply-mid",
                    host=host,
                    port=port,
                    command_timeout=1.0,
                    hash_timeout=1.0,
                    effect_timeout=1.0,
                )
                with mock.patch.object(
                    transition, "derive_images", return_value=(original, modified)
                ), mock.patch.object(
                    transition, "validate_bridge_binding"
                ) as bind, mock.patch.object(transition, "exchange") as exchange:
                    with self.assertRaisesRegex(ValueError, "pinned"):
                        transition.execute(args)
                bind.assert_not_called()
                exchange.assert_not_called()

    def test_final_bridge_drift_refuses_before_effect_arm(self) -> None:
        original, modified = transition.derive_images()
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        with tempfile.TemporaryDirectory() as directory:
            args = Namespace(
                execute=True,
                experiment_id="transition-final-bind-fail",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition,
                "revalidate_bridge_binding",
                side_effect=[binding, RuntimeError("bridge drift")],
            ) as rebind, mock.patch.object(
                transition, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(
                transition,
                "_preflight",
                return_value=({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080),
            ), mock.patch.object(
                transition, "create_and_validate_node"
            ), mock.patch.object(
                transition,
                "binary_exchange",
                return_value=({"cmd": "run", "rc": "0", "status": "ok"}, original),
            ), mock.patch.object(
                transition, "device_sha256", return_value=transition.ROLLBACK_SHA256
            ), mock.patch.object(
                transition, "_write_ascii_payload", return_value={"size": 4, "sha256": "x"}
            ), mock.patch.object(
                transition, "verify_regular_file_dd", return_value={"passed": True}
            ), mock.patch.object(transition, "exchange") as exchange, mock.patch.object(
                transition, "_remove_temp"
            ) as remove_temp, mock.patch.object(transition, "remove_node") as remove_node:
                with self.assertRaisesRegex(RuntimeError, "bridge drift"):
                    with mock.patch.object(transition, "REPO_ROOT", Path(directory)):
                        transition.execute(args)
            exchange.assert_not_called()
            self.assertEqual(rebind.call_args_list, [mock.call(binding), mock.call(binding)])
            remove_temp.assert_not_called()
            remove_node.assert_not_called()
            journal = json.loads(
                (Path(directory) / "evidence/private/transition-final-bind-fail.journal.json").read_text()
            )
        self.assertFalse(journal["effect_dispatched"])
        self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")
        self.assertTrue(journal["cleanup_deferred"])
        self.assertTrue(journal["reconcile_required"])

    def test_pre_effect_failure_with_cleanup_binding_drift_defers_without_cleanup(self) -> None:
        original, modified = transition.derive_images()
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        with tempfile.TemporaryDirectory() as directory:
            args = Namespace(
                execute=True,
                experiment_id="transition-cleanup-bind-fail",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition,
                "revalidate_bridge_binding",
                side_effect=[binding, RuntimeError("cleanup bridge drift")],
            ) as rebind, mock.patch.object(
                transition, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(
                transition,
                "_preflight",
                return_value=({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080),
            ), mock.patch.object(
                transition, "create_and_validate_node", side_effect=RuntimeError("prepare failed")
            ), mock.patch.object(transition, "_remove_temp") as remove_temp, mock.patch.object(
                transition, "remove_node"
            ) as remove_node:
                with self.assertRaisesRegex(RuntimeError, "prepare failed"):
                    with mock.patch.object(transition, "REPO_ROOT", Path(directory)):
                        transition.execute(args)
            self.assertEqual(rebind.call_args_list, [mock.call(binding), mock.call(binding)])
            remove_temp.assert_not_called()
            remove_node.assert_not_called()
            journal = json.loads(
                (Path(directory) / "evidence/private/transition-cleanup-bind-fail.journal.json").read_text()
            )
        self.assertEqual(journal["status"], "PRE_EFFECT_PREFLIGHT_INCOMPLETE")
        self.assertFalse(journal["effect_dispatched"])
        self.assertEqual(journal["effect_dispatched_count"], 0)
        self.assertEqual(journal["write_count"], 0)
        self.assertFalse(journal["partition_writes"])
        self.assertFalse(journal["cleanup_attempted"])
        self.assertFalse(journal["cleanup_completed"])
        self.assertFalse(journal["node_cleanup_verified"])
        self.assertTrue(journal["cleanup_deferred"])
        self.assertTrue(journal["reconcile_required"])

    def test_pre_effect_incident_publication_is_idempotent_if_cleanup_then_fails(self) -> None:
        original, modified = transition.derive_images()
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        with tempfile.TemporaryDirectory() as directory:
            args = Namespace(
                execute=True,
                experiment_id="transition-incident-idempotent",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )

            def fail_create(*args):
                del args
                raise RuntimeError("prepare failed")

            def fail_cleanup(*args):
                del args
                raise RuntimeError("cleanup failed")

            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "revalidate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(
                transition,
                "_preflight",
                return_value=({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080),
            ), mock.patch.object(
                transition, "create_and_validate_node", side_effect=fail_create
            ), mock.patch.object(
                transition, "_remove_temp", side_effect=fail_cleanup
            ), mock.patch.object(transition, "remove_node"):
                with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                    with mock.patch.object(transition, "REPO_ROOT", Path(directory)):
                        transition.execute(args)
            manifest_path = Path(directory) / "evidence/manifests/transition-incident-idempotent.manifest.json"
            self.assertTrue(manifest_path.exists())
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["effect_dispatched_count"], 0)
            self.assertFalse("FileExistsError" in manifest.get("error", ""))

    def test_effect_timeout_defers_cleanup_and_sends_no_post_effect_command(self) -> None:
        original, modified = transition.derive_images()
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        with tempfile.TemporaryDirectory() as directory:
            args = Namespace(
                execute=True,
                experiment_id="transition-effect-timeout",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            def effect_exchange(*args, **kwargs):
                del kwargs
                command = args[2]
                if command.evidence_id == "param_debug_transition":
                    raise TimeoutError("effect transport timeout")
                raise AssertionError(command.evidence_id)

            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "revalidate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(
                transition,
                "_preflight",
                return_value=({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080),
            ), mock.patch.object(transition, "create_and_validate_node"), mock.patch.object(
                transition,
                "binary_exchange",
                return_value=({"cmd": "run", "rc": "0", "status": "ok"}, original),
            ), mock.patch.object(
                transition, "device_sha256", return_value=transition.ROLLBACK_SHA256
            ), mock.patch.object(
                transition, "_write_ascii_payload", return_value={"size": 4, "sha256": "x"}
            ), mock.patch.object(
                transition, "verify_regular_file_dd", return_value={"passed": True}
            ), mock.patch.object(
                transition, "verify_exact_param_target", return_value={"ok": True}
            ), mock.patch.object(
                transition, "exchange", side_effect=effect_exchange
            ), mock.patch.object(transition, "_remove_temp") as remove_temp, mock.patch.object(
                transition, "remove_node"
            ) as remove_node:
                with self.assertRaises(TimeoutError):
                    with mock.patch.object(transition, "REPO_ROOT", Path(directory)):
                        transition.execute(args)
            remove_temp.assert_not_called()
            remove_node.assert_not_called()
            journal = json.loads(
                (Path(directory) / "evidence/private/transition-effect-timeout.journal.json").read_text()
            )
        self.assertEqual(journal["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED")
        self.assertTrue(journal["cleanup_deferred"])

    def test_post_effect_hash_failure_defers_cleanup_without_device_commands(self) -> None:
        original, modified = transition.derive_images()
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}

        class ReturnedFrame:
            payload = b""
            transcript = b"A90P1 effect"
            begin = {"cmd": "run", "seq": "1"}
            end = {"cmd": "run", "seq": "1", "rc": "0", "status": "ok"}

        with tempfile.TemporaryDirectory() as directory:
            args = Namespace(
                execute=True,
                experiment_id="transition-post-hash-fail",
                action="apply-mid",
                host="127.0.0.1",
                port=54321,
                command_timeout=1.0,
                hash_timeout=1.0,
                effect_timeout=1.0,
            )
            hash_calls = 0

            def fake_hash(*args, **kwargs):
                nonlocal hash_calls
                del args, kwargs
                hash_calls += 1
                if hash_calls == 1:
                    return transition.ROLLBACK_SHA256
                raise TimeoutError("post-effect hash unavailable")

            def fake_exchange(*args, **kwargs):
                del kwargs
                command = args[2]
                if command.evidence_id == "param_debug_transition":
                    return ReturnedFrame()
                raise AssertionError(command.evidence_id)

            with mock.patch.object(
                transition, "derive_images", return_value=(original, modified)
            ), mock.patch.object(
                transition, "validate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "revalidate_bridge_binding", return_value=binding
            ), mock.patch.object(
                transition, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
            ), mock.patch.object(
                transition,
                "_preflight",
                return_value=({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080),
            ), mock.patch.object(transition, "create_and_validate_node"), mock.patch.object(
                transition,
                "binary_exchange",
                side_effect=[
                    ({"cmd": "run", "rc": "0", "status": "ok"}, original),
                    TimeoutError("post-effect capture unavailable"),
                ],
            ), mock.patch.object(
                transition, "device_sha256", side_effect=fake_hash
            ), mock.patch.object(
                transition, "_write_ascii_payload", return_value={"size": 4, "sha256": "x"}
            ), mock.patch.object(
                transition, "verify_regular_file_dd", return_value={"passed": True}
            ), mock.patch.object(
                transition, "verify_exact_param_target", return_value={"ok": True}
            ), mock.patch.object(
                transition, "exchange", side_effect=fake_exchange
            ), mock.patch.object(transition, "_remove_temp") as remove_temp, mock.patch.object(
                transition, "remove_node"
            ) as remove_node:
                with self.assertRaises(TimeoutError):
                    with mock.patch.object(transition, "REPO_ROOT", Path(directory)):
                        transition.execute(args)
            remove_temp.assert_not_called()
            remove_node.assert_not_called()
            journal = json.loads(
                (Path(directory) / "evidence/private/transition-post-hash-fail.journal.json").read_text()
            )
        self.assertEqual(journal["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED")
        self.assertTrue(journal["cleanup_deferred"])

    def test_post_marker_node_or_payload_swap_is_ambiguous_without_replay(self) -> None:
        original, modified = transition.derive_images()
        partition = Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        for suffix, mutation in (
            ("node-swap", "node rdev changed after smoke"),
            ("payload-swap", "staged payload bytes changed after smoke"),
        ):
            with self.subTest(suffix=suffix):
                with tempfile.TemporaryDirectory() as directory:
                    args = Namespace(
                        execute=True,
                        experiment_id=f"transition-{suffix}",
                        action="apply-mid",
                        host="127.0.0.1",
                        port=54321,
                        command_timeout=1.0,
                        hash_timeout=1.0,
                        effect_timeout=1.0,
                    )
                    target_calls = 0

                    def target_verify(*_args, **_kwargs):
                        nonlocal target_calls
                        target_calls += 1
                        if target_calls == 2:
                            raise ValueError(mutation)
                        return {"ok": True}

                    with mock.patch.object(
                        transition, "derive_images", return_value=(original, modified)
                    ), mock.patch.object(
                        transition, "validate_bridge_binding", return_value=binding
                    ), mock.patch.object(
                        transition, "revalidate_bridge_binding", return_value=binding
                    ), mock.patch.object(
                        transition, "run_stophud", return_value={"accepted": True, "busy_retries": 0}
                    ), mock.patch.object(
                        transition,
                        "_preflight",
                        return_value=({"androidboot.debug_level": "0x4f4c"}, "1", partition, 125080),
                    ), mock.patch.object(
                        transition, "create_and_validate_node"
                    ), mock.patch.object(
                        transition,
                        "binary_exchange",
                        return_value=({"cmd": "run", "rc": "0", "status": "ok"}, original),
                    ), mock.patch.object(
                        transition, "device_sha256", return_value=transition.ROLLBACK_SHA256
                    ), mock.patch.object(
                        transition, "_write_ascii_payload", return_value={"size": 4, "sha256": "x"}
                    ), mock.patch.object(
                        transition, "verify_regular_file_dd", return_value={"passed": True}
                    ), mock.patch.object(
                        transition, "verify_exact_param_target", side_effect=target_verify
                    ), mock.patch.object(transition, "exchange") as exchange, mock.patch.object(
                        transition, "_remove_temp"
                    ) as remove_temp, mock.patch.object(
                        transition, "remove_node"
                    ) as remove_node:
                        with self.assertRaisesRegex(ValueError, "changed after smoke"):
                            with mock.patch.object(transition, "REPO_ROOT", Path(directory)):
                                transition.execute(args)
                    exchange.assert_not_called()
                    remove_temp.assert_not_called()
                    remove_node.assert_not_called()
                    journal = json.loads(
                        (
                            Path(directory)
                            / f"evidence/private/transition-{suffix}.journal.json"
                        ).read_text()
                    )
                    self.assertEqual(
                        journal["status"], "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
                    )
                    self.assertEqual(journal["write_count"], 1)
                    self.assertTrue(journal["cleanup_deferred"])


if __name__ == "__main__":
    unittest.main()
