from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools import a90_partition_capture as capture


def binary_frame(payload: bytes, *, seq: int = 11) -> bytes:
    return (
        b"a90:/# cmdv1 cat /dev/test\r\n"
        + f"A90P1 BEGIN seq={seq} cmd=cat argc=2 flags=0x0\r\n".encode()
        + payload
        + b"\r\n[done] cat (9ms)\r\n"
        + (
            f"A90P1 END seq={seq} cmd=cat rc=0 errno=0 duration_ms=9 "
            "flags=0x0 status=ok\r\n"
        ).encode()
        + b"a90:/# "
    )


class PartitionCaptureTests(unittest.TestCase):
    def test_binary_parser_uses_advertised_size_not_embedded_marker(self) -> None:
        payload = b"\x00firmware\r\nA90P1 END fake\r\n\xfftail"
        fields, parsed = capture.parse_binary_frame(binary_frame(payload), len(payload))
        self.assertEqual(parsed, payload)
        self.assertEqual(fields["status"], "ok")

    def test_binary_parser_rejects_wrong_size_or_trailer(self) -> None:
        payload = b"abcd"
        with self.assertRaisesRegex(ValueError, "trailer"):
            capture.parse_binary_frame(binary_frame(payload), len(payload) - 1)
        bad = binary_frame(payload).replace(b"[done] cat", b"[done] write")
        with self.assertRaisesRegex(ValueError, "trailer"):
            capture.parse_binary_frame(bad, len(payload))

    def test_binary_receive_refuses_overrun_at_fixed_bound(self) -> None:
        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def settimeout(self, value):
                del value

            def sendall(self, value):
                del value

            def recv(self, value):
                return b"x" * (value + 1)

        with mock.patch.object(capture.socket, "create_connection", return_value=FakeSocket()):
            with self.assertRaisesRegex(ValueError, "overrun"):
                capture.binary_exchange(
                    "127.0.0.1",
                    54321,
                    "/dev/sdm855_mblab_sda10",
                    100,
                    1.0,
                )

    def test_parse_uevent(self) -> None:
        parsed = capture.parse_uevent(
            b"MAJOR=8\nMINOR=17\nDEVNAME=sdb1\nDEVTYPE=partition\nPARTNAME=xbl\n"
        )
        self.assertEqual(parsed["PARTNAME"], "xbl")
        with self.assertRaises(ValueError):
            capture.parse_uevent(b"MAJOR=8\nMAJOR=9\n")

    def test_partition_validation_and_selection(self) -> None:
        xbl = capture.Partition("xbl", "sdb1", 8, 17, 8192, 4194304, 1, 4096)
        capture.validate_partition(xbl)
        self.assertEqual(capture.select_partitions([xbl], ["xbl"]), [xbl])
        with self.assertRaisesRegex(ValueError, "not found"):
            capture.select_partitions([xbl], ["hyp"])
        with self.assertRaisesRegex(ValueError, "not sysfs read-only"):
            capture.validate_partition(
                capture.Partition("xbl", "sdb1", 8, 17, 8192, 4194304, 0, 4096)
            )
        param = capture.Partition(
            "param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096
        )
        capture.validate_partition(param)
        with self.assertRaises(ValueError):
            capture.validate_param_partition(param, 125088)

    def test_cli_does_not_accept_arbitrary_partition(self) -> None:
        parser = capture.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    ["--experiment-id", "x", "--partname", "userdata"]
                )

    def test_cli_requires_execute_and_has_no_output_or_endpoint_namespace(self) -> None:
        parser = capture.build_parser()
        parsed = parser.parse_args(["--experiment-id", "x", "--execute"])
        self.assertTrue(parsed.execute)
        for option in ("--output-root", "--host", "--port"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(["--experiment-id", "x", option, "x"])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--experiment-id", "x", "--discover-only"])

    def test_strict_toybox_payload_and_fixed_node_path(self) -> None:
        payload = b"run: pid=123, q/Ctrl-C cancels\n[exit 0]\n"
        self.assertEqual(capture.parse_toybox_payload(payload), b"")
        with self.assertRaises(ValueError):
            capture.parse_toybox_payload(
                b"run: pid=123, q/Ctrl-C cancels\n[exit 1]\n"
            )
        with self.assertRaisesRegex(ValueError, "terminal"):
            capture.parse_toybox_payload(
                b"body\nrun: pid=123, q/Ctrl-C cancels\n[exit 0]\n"
            )
        with self.assertRaisesRegex(ValueError, "terminal"):
            capture.parse_toybox_payload(
                b"run: pid=123, q/Ctrl-C cancels\n[exit 0]\ntrailing\n"
            )
        with self.assertRaises(ValueError):
            capture._validate_node_path("/tmp/not-a-node")
        capture._validate_node_path("/dev/sdm855_mblab_sda10")

    def test_node_stat_rdev_is_an_exact_anchored_record(self) -> None:
        partition = capture.Partition("param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096)
        valid = b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\n"
        parsed = capture._parse_node_stat_identity(valid, partition)
        self.assertEqual(parsed["rdev"], "8:10")
        live = b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10"
        self.assertEqual(len(live), 39)
        self.assertEqual(
            hashlib.sha256(live).hexdigest(),
            "0993514304d5b15b220d3b97c687e7ebd086ec7d67c7e2543bd5da0adb39a97c",
        )
        self.assertEqual(capture._parse_node_stat_identity(live, partition)["rdev"], "8:10")
        for retained in (
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10",
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10\r\n",
        ):
            with self.subTest(retained=retained):
                self.assertEqual(
                    capture._parse_node_stat_identity(retained, partition)["rdev"],
                    "8:10",
                )
        invalid = (
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:100\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=18:10\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\nrdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\nrdev=8:11\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10 trailing\n",
            b"mode=0600 uid=0 gid=0 size=0 rdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\ntrailing\n",
            b" mode=0600 uid=0 gid=0 size=0\nrdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0 \nrdev=8:10\n",
            b"mode=0600  uid=0 gid=0 size=0\nrdev=8:10\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\n\n",
            b"mode=0600 uid=0 gid=0 size=0\nrdev=8:10\x00\n",
            b"mode=0600 uid=0 gid=0 size=0\rrdev=8:10",
            b"mode=0600 uid=0 gid=0 size=0\r\nrdev=8:10\r",
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    capture._parse_node_stat_identity(payload, partition)

    def test_initial_arbitration_journal_is_single_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "capture-journal.json"
            capture._write_initial_json(journal, {"owner": "first"})
            with self.assertRaises(FileExistsError):
                capture._write_initial_json(journal, {"owner": "second"})
            self.assertEqual(json.loads(journal.read_text())["owner"], "first")

    def test_timeout_rejects_nonfinite_nonpositive_and_out_of_range(self) -> None:
        for value in (float("nan"), float("inf"), 0.0, -1.0, 121.0):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    capture.validate_timeout(value, "command-timeout", 120.0)

    def test_stophud_busy_is_bounded_and_already_stopped_is_terminal(self) -> None:
        class Frame:
            def __init__(self, sequence: int, rc: int, status: str) -> None:
                self.payload = b""
                self.transcript = b""
                self.begin = {"cmd": "stophud", "seq": str(sequence)}
                self.end = {
                    "cmd": "stophud",
                    "seq": str(sequence),
                    "rc": str(rc),
                    "status": status,
                }

        for responses, expected_calls, expected_retries in (
            ([(-16, "busy"), (-16, "busy"), (0, "ok")], 3, 2),
            ([(0, "ok")], 1, 0),
        ):
            with self.subTest(responses=responses):
                calls: list[str] = []
                persisted: list[list[dict[str, object]]] = []
                frames: list[dict[str, object]] = []
                response_iter = iter(responses)

                def exchange(host, port, command, timeout, *, allow_error=False):
                    del host, port, command, timeout, allow_error
                    calls.append("stophud")
                    rc, status = next(response_iter)
                    return Frame(len(calls), rc, status)

                result = capture.run_stophud(
                    "127.0.0.1",
                    54321,
                    1.0,
                    exchange,
                    frame_records=frames,
                    persist=lambda attempts: persisted.append(attempts),
                    sleep_fn=lambda delay: None,
                )
                self.assertTrue(result["accepted"])
                self.assertEqual(len(calls), expected_calls)
                self.assertEqual(result["busy_retries"], expected_retries)
                self.assertEqual(len(persisted), expected_calls)
                self.assertEqual(len(frames), expected_calls)

    def test_collect_journals_before_rebind_stophud_and_version(self) -> None:
        events: list[str] = []
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}

        def fake_initial(path, value, mode=0o600):
            events.append("journal")
            return real_initial(path, value, mode)

        def fake_bind():
            events.append("initial_bind")
            return binding

        def fake_rebind(value):
            events.append("rebind")
            return value

        def fake_stophud(
            host, port, timeout, exchange, *, frame_records, persist
        ):
            del host, port, timeout, exchange
            events.append("stophud")
            record = {"evidence_id": "stophud_1", "attempt": 1, "rc": 0, "status": "ok"}
            frame_records.append(record)
            persist([record])
            return {"accepted": True, "busy_retries": 0, "attempts": [record]}

        def fail_version(host, port, evidence_id, argv, timeout):
            del host, port, argv, timeout
            events.append(evidence_id)
            raise RuntimeError("stop after arbitration")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(
                experiment_id="arbitration-order",
                execute=True,
                command_timeout=1.0,
                capture_timeout=1.0,
                partname=[],
            )
            real_initial = capture._write_initial_json
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "_write_initial_json", side_effect=fake_initial
            ), mock.patch.object(
                capture, "_bind_fixed_bridge", side_effect=fake_bind
            ), mock.patch.object(
                capture, "revalidate_bridge_binding", side_effect=fake_rebind
            ), mock.patch.object(
                capture, "run_stophud", side_effect=fake_stophud
            ), mock.patch.object(
                capture, "text_exchange", side_effect=fail_version
            ) as text, mock.patch.object(capture, "discover_partitions") as discover:
                with self.assertRaisesRegex(RuntimeError, "stop after arbitration"):
                    capture.collect(args)
            self.assertEqual(events, ["journal", "initial_bind", "rebind", "stophud", "version"])
            text.assert_called_once()
            discover.assert_not_called()
            journal = json.loads(
                (root / "evidence/private/arbitration-order/capture-journal.json").read_text()
            )
            self.assertEqual(journal["status"], "PREFLIGHT")
            self.assertEqual(journal["stophud_attempts"][0]["status"], "ok")
            self.assertEqual(journal["stophud_frames"][0]["evidence_id"], "stophud_1")

    def test_collect_arbitration_drift_is_incident_without_stophud_or_reads(self) -> None:
        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(
                experiment_id="arbitration-drift",
                execute=True,
                command_timeout=1.0,
                capture_timeout=1.0,
                partname=[],
            )
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "_bind_fixed_bridge", return_value=binding
            ), mock.patch.object(
                capture, "revalidate_bridge_binding", return_value={"process_pid": 999}
            ) as rebind, mock.patch.object(capture, "run_stophud") as stophud, mock.patch.object(
                capture, "text_exchange"
            ) as exchange:
                with self.assertRaisesRegex(RuntimeError, "drifted before stophud"):
                    capture.collect(args)
            rebind.assert_called_once_with(binding)
            stophud.assert_not_called()
            exchange.assert_not_called()
            journal = json.loads(
                (root / "evidence/private/arbitration-drift/capture-journal.json").read_text()
            )
            self.assertEqual(journal["status"], "ARBITRATION_FAILED")
            self.assertEqual(journal["stophud_attempts"], [])
            incident = root / "evidence/manifests/arbitration-drift.manifest.json"
            self.assertTrue(incident.exists())

    def test_collect_rebinds_before_each_stophud_retry_and_stops_on_drift(self) -> None:
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

        binding = {"process_pid": 123, "serial_device": "/dev/ttyACM0"}
        calls: list[str] = []

        def fake_exchange(host, port, command, timeout, *, allow_error=False):
            del host, port, timeout, allow_error
            calls.append(command.evidence_id)
            if command.evidence_id == "stophud":
                return Frame()
            raise AssertionError(f"unexpected substantive command: {command.evidence_id}")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(
                experiment_id="arbitration-retry-drift",
                execute=True,
                command_timeout=1.0,
                capture_timeout=1.0,
                partname=[],
            )
            with mock.patch.object(capture, "REPO_ROOT", root), mock.patch.object(
                capture, "_bind_fixed_bridge", return_value=binding
            ), mock.patch.object(
                capture,
                "revalidate_bridge_binding",
                side_effect=[binding, binding, RuntimeError("drift before retry")],
            ) as rebind, mock.patch.object(
                capture, "exchange", side_effect=fake_exchange
            ), mock.patch.object(capture, "discover_partitions") as discover:
                with self.assertRaisesRegex(RuntimeError, "drift before retry"):
                    capture.collect(args)
            self.assertEqual(calls, ["stophud"])
            self.assertEqual(rebind.call_count, 3)
            discover.assert_not_called()
            journal = json.loads(
                (root / "evidence/private/arbitration-retry-drift/capture-journal.json").read_text()
            )
            self.assertEqual(journal["status"], "ARBITRATION_FAILED")
            self.assertEqual(len(journal["stophud_attempts"]), 2)
            self.assertEqual(journal["stophud_attempts"][0]["status"], "busy")
            self.assertIn("transport_error", journal["stophud_attempts"][1])


if __name__ == "__main__":
    unittest.main()
