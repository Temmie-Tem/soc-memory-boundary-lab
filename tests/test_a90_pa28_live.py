from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from tools import a90_pa28_live as live
from tools import a90_pa28_live_analysis as analysis


def fake_frame(
    command: str,
    payload: bytes = b"",
    *,
    rc: int = 0,
    status: str = "ok",
    seq: int = 1,
) -> live.Frame:
    begin = {"seq": str(seq), "cmd": command}
    end = {**begin, "rc": str(rc), "status": status}
    return live.Frame(begin, end, payload, b"A90P1 " + command.encode())


def child_payload(*lines: bytes, code: int = 0) -> bytes:
    return (
        b"run: pid=123, q/Ctrl-C cancels\n"
        + b"\n".join(lines)
        + (b"\n" if lines else b"")
        + f"[exit {code}]\n".encode()
    )


def target_version() -> bytes:
    return (
        f"{live.EXPECTED_VERSION} ({live.EXPECTED_RUNTIME_BUILD})\n"
        f"version: {live.EXPECTED_RUNTIME} {live.EXPECTED_BUILD}\n"
        f"kernel: {live.EXPECTED_KERNEL}\n"
    ).encode()


def target_cmdline() -> bytes:
    return child_payload(" ".join(sorted(live.EXPECTED_CMDLINE_TOKENS)).encode())


def probe_records() -> list[dict[str, object]]:
    context = {
        "schema": live.PROBE_SCHEMA,
        "type": "context",
        "cpu": live.EXPECTED_CPU,
        "cntfrq": live.EXPECTED_CNTFRQ,
        "heap": live.EXPECTED_HEAP,
        "mib": live.EXPECTED_MIB,
        "repetitions": live.EXPECTED_REPETITIONS,
        "pairs": live.EXPECTED_PAIRS,
        "warmups": live.EXPECTED_WARMUPS,
        "order": live.EXPECTED_ORDER,
        "barrier": live.EXPECTED_BARRIER,
        "divisor": live.EXPECTED_DIVISOR,
        "offset_mode": live.EXPECTED_OFFSET_MODE,
        "declared_base": live.EXPECTED_BASE_TEXT,
    }
    heap = {
        "schema": live.PROBE_SCHEMA,
        "type": "ion_heap",
        "name": live.EXPECTED_HEAP,
        "heap_type": 10,
        "heap_id": 30,
    }
    provenance = {
        "schema": live.PROBE_SCHEMA,
        "type": "pa_provenance",
        "source": "pagemap",
        "pages": live.EXPECTED_PAGE_COUNT,
        "present": 0,
        "nonzero_pfn": 0,
        "first_pfn": "0x0",
        "last_pfn": "0x0",
        "contiguous": True,
        "status": "BLIND",
    }
    rows: list[dict[str, object]] = [context, heap, provenance]
    for index, difference_text in enumerate(live.FIXED_DIFFERENCES):
        difference = int(difference_text, 16)
        offset = 0
        other = offset ^ difference
        pa_a = live.EXPECTED_BASE + offset
        pa_b = live.EXPECTED_BASE + other
        rows.append(
            {
                "schema": live.PROBE_SCHEMA,
                "type": "pair",
                "value": difference_text,
                "offset": "0x0",
                "pa_a": hex(pa_a),
                "pa_b": hex(pa_b),
                "pa_xor": hex(pa_a ^ pa_b),
                "delta": index,
            }
        )
        rows.append(
            {
                "schema": live.PROBE_SCHEMA,
                "type": "difference",
                "value": difference_text,
                "pairs": 1,
                "rejected_range": live.EXPECTED_PAIRS - 1,
                "rejected_carry": 0,
                "p10": index,
                "median": index,
                "p90": index,
            }
        )
    rows.append(
        {
            "schema": live.PROBE_SCHEMA,
            "type": "cleanup",
            "attempted": True,
            "released": True,
            "ion_fd_closed": True,
            "allocation_fd_closed": True,
            "map_unmapped": True,
            "eviction_unmapped": True,
            "heaps_freed": True,
            "sample_buffers_freed": True,
            "status": "PASS",
        }
    )
    return rows


def probe_payload(*, code: int = 0, mutate: str | None = None) -> bytes:
    rows = probe_records()
    if mutate == "schema":
        rows[0]["schema"] = "foreign"
    if mutate == "duplicate":
        first = json.dumps(rows[0], sort_keys=True)
        first = first[:-1] + ',"heap": "wrong"}'
        lines = [first] + [json.dumps(row, sort_keys=True) for row in rows[1:]]
        return child_payload(*(line.encode() for line in lines), code=code)
    return child_payload(
        *(json.dumps(row, sort_keys=True).encode() for row in rows), code=code
    )


class PartialTransportTimeout(TimeoutError):
    def __init__(self) -> None:
        super().__init__("fixture transport timeout")
        self.partial_payload = (
            b"run: pid=456, q/Ctrl-C cancels\n"
            b'{"schema":"a90_pa28_probe_v022r_v1","type":"context"}\n'
        )
        self.partial_transcript = b"partial A90P1 BEGIN/child banner\n"


class FakeBridge:
    def __init__(
        self,
        binary: bytes,
        *,
        target_drift: bool = False,
        remote_hash: str | None = None,
        probe_code: int = 0,
        probe_mutation: str | None = None,
        final_selftest_fail: int = 0,
        probe_timeout: bool = False,
    ) -> None:
        self.binary_hash = hashlib.sha256(binary).hexdigest()
        self.target_drift = target_drift
        self.remote_hash = remote_hash or self.binary_hash
        self.probe_code = probe_code
        self.probe_mutation = probe_mutation
        self.final_selftest_fail = final_selftest_fail
        self.probe_timeout = probe_timeout
        self.calls: list[tuple[str, tuple[str, ...], bool]] = []

    def __call__(
        self,
        host: str,
        port: int,
        command: live.Command | live.ExtendedCommand,
        timeout: float,
        *,
        allow_error: bool = False,
    ) -> live.Frame:
        del host, port, timeout
        evidence_id = command.evidence_id
        argv = tuple(command.argv)
        self.calls.append((evidence_id, argv, allow_error))
        if evidence_id == "version":
            payload = (
                b"version: 0.9.286 build=wrong\n"
                b"kernel: wrong\n"
                if self.target_drift
                else target_version()
            )
            return fake_frame("version", payload)
        if evidence_id in {"final_version"}:
            return fake_frame("version", target_version())
        if evidence_id in {"cmdline", "final_cmdline"}:
            return fake_frame("run", target_cmdline())
        if evidence_id == "ion_dev":
            return fake_frame("run", child_payload(b"10:94"))
        if evidence_id == "probe":
            if self.probe_timeout:
                raise PartialTransportTimeout()
            return fake_frame(
                "run",
                probe_payload(code=self.probe_code, mutate=self.probe_mutation),
                rc=0 if self.probe_code == 0 else 1,
                status="ok" if self.probe_code == 0 else "error",
            )
        if evidence_id == "probe_terminate":
            return fake_frame("run", child_payload())
        if evidence_id.startswith("probe_termination_check_"):
            return fake_frame("run", child_payload(code=1))
        if evidence_id in {"remote_hash_before_run", "remote_hash_after_run"}:
            return fake_frame(
                "run",
                child_payload(
                    f"{self.remote_hash}  {live.REMOTE_BINARY}".encode()
                ),
            )
        if evidence_id == "final_selftest":
            payload = (
                f"selftest: pass=11 warn=1 fail={self.final_selftest_fail} "
                "duration=1ms entries=12\n"
            ).encode()
            return fake_frame("selftest", payload)
        if argv and argv[0] == "appendfile":
            return fake_frame("appendfile")
        if argv and argv[0] == "run":
            return fake_frame("run", child_payload())
        return fake_frame(argv[0] if argv else "unknown")


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "evidence" / "private").mkdir(parents=True)
        self.binary = self.root / live.EXPECTED_PROBE_BINARY_BASENAME
        self.binary.write_bytes(b"fixture-pa28-probe")
        source = live.REPO_ROOT / "tools" / live.EXPECTED_PROBE_SOURCE_BASENAME
        source_bytes = source.read_bytes()
        binary_bytes = self.binary.read_bytes()
        self.build_receipt = self.root / "build-receipt.json"
        self.build_receipt.write_text(
            json.dumps(
                {
                    "schema": live.BUILD_SCHEMA,
                    "source": {
                        "basename": source.name,
                        "size_bytes": len(source_bytes),
                        "sha256": hashlib.sha256(source_bytes).hexdigest(),
                    },
                    "binary": {
                        "basename": self.binary.name,
                        "size_bytes": len(binary_bytes),
                        "sha256": hashlib.sha256(binary_bytes).hexdigest(),
                    },
                    "compiler": {
                        "triple": "aarch64-linux-gnu",
                        "version": live.EXPECTED_COMPILER_VERSION,
                        "command": [
                            "aarch64-linux-gnu-gcc", "-O2", "-static", "-Wall",
                            "-Wextra", "-Werror", "-o",
                            str(self.binary),
                            "tools/" + live.EXPECTED_PROBE_SOURCE_BASENAME,
                        ],
                        "static": True,
                    },
                    "reproducible_byte_identical": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def args(self, name: str = "run") -> argparse.Namespace:
        return argparse.Namespace(
            experiment_id="verification-022r-fixture",
            binary=self.binary,
            source=live.REPO_ROOT / "tools" / live.EXPECTED_PROBE_SOURCE_BASENAME,
            build_receipt=self.build_receipt,
            output_dir=self.root / "evidence" / "private" / name,
            host=live.BRIDGE_HOST,
            port=live.BRIDGE_PORT,
            timeout=1.0,
            probe_timeout=2.0,
            total_timeout=330.0,
        )

    def run_with(
        self,
        bridge: FakeBridge,
        args: argparse.Namespace | None = None,
        *,
        rebind: bool = False,
        fail_after_footer: bool = False,
    ):
        source = live.REPO_ROOT / "tools" / live.EXPECTED_PROBE_SOURCE_BASENAME
        source_bytes = source.read_bytes()
        binary_bytes = self.binary.read_bytes()
        binding = {
            "listener": {"host": live.BRIDGE_HOST, "port": live.BRIDGE_PORT},
            "serial_device": live.BRIDGE_SERIAL_DEVICE,
            "serial_identity": live.BRIDGE_SERIAL_ID,
            "serial_realpath": live.BRIDGE_SERIAL_DEVICE,
            "serial_stat": {
                "st_dev": 1,
                "st_ino": 2,
                "st_rdev": 3,
                "mode": 0o600,
                "character_device": True,
            },
            "validated_utc": live.utc_now(),
            "process_pid": 123,
            "process_argv": [
                "python3", str(live.BRIDGE_PROCESS_SCRIPT_PATH), "--host",
                live.BRIDGE_HOST, "--port", str(live.BRIDGE_PORT), "--device",
                live.BRIDGE_SERIAL_DEVICE, "--expect-realpath",
                live.BRIDGE_SERIAL_DEVICE, "--device-glob",
                live.BRIDGE_SERIAL_GLOB_TOKEN,
            ],
            "bridge_process_script": live.BRIDGE_PROCESS_SCRIPT,
            "bridge_process_script_path": str(live.BRIDGE_PROCESS_SCRIPT_PATH),
            "bridge_process_script_descriptor": {
                "basename": live.EXPECTED_BRIDGE_SCRIPT_BASENAME,
                "size_bytes": live.EXPECTED_BRIDGE_SCRIPT_SIZE,
                "sha256": live.EXPECTED_BRIDGE_SCRIPT_SHA256,
            },
            "unique_process": True,
        }
        second_binding = dict(binding)
        if rebind:
            second_binding["process_pid"] = 999
        binding_values = [binding, second_binding]
        if bridge.probe_timeout and not rebind:
            binding_values.append(second_binding)
        cancel_result = {
            "proved": True,
            "method": "raw_ctrl_c_reconnect",
            "pid": 456,
            "child_exit_code": None,
            "termination_rc": -125,
            "channel_ready": True,
            "errors": [],
            "cancel": {
                "method": "raw_ctrl_c_reconnect",
                "byte_hex": "03",
                "send_size": 1,
                "send_sha256": live.sha256(b"\x03"),
                "started_utc": live.utc_now(),
                "sent_utc": live.utc_now(),
                "completed_utc": live.utc_now(),
                "sent": True,
                "remainder_size": 1,
                "remainder_sha256": live.sha256(b"x"),
                "combined_size": 1,
                "combined_sha256": live.sha256(b"x"),
                "original_begin": {"seq": "1", "cmd": "run"},
                "original_pid": 456,
                "terminal": True,
                "prompt": True,
                "termination_rc": -125,
                "cancelled": True,
                "child_terminated": True,
                "errors": [],
            },
            "terminal_payload": None,
        }
        real_upload = live.upload_binary

        def upload_side_effect(
            session: live._Session,
            binary_data: bytes,
            timeout: float | None = None,
            *,
            lifecycle: dict[str, object] | None = None,
        ):
            if not fail_after_footer:
                return real_upload(
                    session, binary_data, timeout, lifecycle=lifecycle
                )
            header, body, footer = live.make_envelope(binary_data)
            header_frame = session.invoke(
                "envelope_header", ("appendfile", live.REMOTE_ENVELOPE, header),
                extended=True, allow_error=True,
            )
            live.require_frame_ok(header_frame, "envelope header")
            for index in range(0, len(body), live.MAX_LEGACY_CHUNK):
                chunk = body[index : index + live.MAX_LEGACY_CHUNK]
                chunk_frame = session.invoke(
                    f"payload_{index // live.MAX_LEGACY_CHUNK:04d}",
                    ("appendfile", live.REMOTE_ENVELOPE, chunk),
                    allow_error=True,
                )
                live.require_frame_ok(chunk_frame, "envelope payload")
            footer_frame = session.invoke(
                "envelope_footer", ("appendfile", live.REMOTE_ENVELOPE, footer),
                extended=True, allow_error=True,
            )
            live.require_frame_ok(footer_frame, "envelope footer")
            # Reproduce a local deadline check before decode.  No bytes are
            # sent for decode, so the completed footer frame remains prompt
            # evidence for the host-only revalidation/cleanup path.
            session.deadline = time.monotonic() - 1.0
            session.invoke(
                "decode",
                ("run", live.TOYBOX, "uudecode", "-o", live.REMOTE_BINARY, live.REMOTE_ENVELOPE),
                allow_error=True,
            )

        with mock.patch.object(live, "exchange", side_effect=bridge), \
             mock.patch.object(
                 live, "validate_bridge_binding", side_effect=binding_values
             ), \
             mock.patch.object(
                 live, "cancel_probe_raw", return_value=cancel_result
             ), \
             mock.patch.object(live, "upload_binary", side_effect=upload_side_effect), \
             mock.patch.multiple(
                 live,
                 EXPECTED_PROBE_SOURCE_SIZE=len(source_bytes),
                 EXPECTED_PROBE_SOURCE_SHA256=hashlib.sha256(source_bytes).hexdigest(),
                 EXPECTED_PROBE_BINARY_SIZE=len(binary_bytes),
                 EXPECTED_PROBE_BINARY_SHA256=hashlib.sha256(binary_bytes).hexdigest(),
             ):
            return live.run(args or self.args())

    def test_fixed_invocation_and_full_post_binding_sequence(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        output = self.run_with(bridge)
        ids = [call[0] for call in bridge.calls]
        self.assertEqual(ids[:4], ["version", "cmdline", "ion_dev", "preclean"])
        self.assertEqual(ids[-8:], [
            "cleanup_node", "cleanup_files", "absence_node", "absence_envelope",
            "absence_binary", "final_version", "final_cmdline", "final_selftest",
        ])
        by_id = {evidence_id: argv for evidence_id, argv, _ in bridge.calls}
        self.assertEqual(by_id["probe"], live.PROBE_ARGV)
        self.assertEqual(
            by_id["ion_node_create"],
            ("run", live.TOYBOX, "mknod", live.REMOTE_ION, "c", "10", "94"),
        )
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["ion_device"]["sysfs_identity"], "10:94")
        self.assertTrue(receipt["cleanup"]["absence_proved"])
        self.assertEqual(receipt["dispatch_count"], 1)
        self.assertEqual(receipt["final_health"]["selftest"]["entries"], 12)
        self.assertTrue(receipt["lifecycle"]["probe_dispatch_utc"])
        self.assertTrue(receipt["lifecycle"]["probe_child_exit_utc"])
        pre_dispatch = receipt["pre_dispatch_revalidation"]
        self.assertEqual(
            set(pre_dispatch),
            {"status", "validated_utc", "bridge_binding", "target", "ion_identity", "command_argv"},
        )
        self.assertEqual(pre_dispatch["status"], "PASS")
        self.assertEqual(pre_dispatch["bridge_binding"], receipt["bridge_binding"])
        self.assertEqual(pre_dispatch["target"], receipt["target"])
        self.assertEqual(pre_dispatch["ion_identity"], "10:94")
        self.assertEqual(pre_dispatch["command_argv"], list(live.PROBE_ARGV))

    def test_fixed_probe_constants_and_no_caller_surface(self) -> None:
        self.assertEqual(
            live.PROBE_ARGV,
            (
                "run", live.REMOTE_BINARY, "camera_preview", "320", "201", "256", "7",
                "spread", "0xc2000000", live.REMOTE_ION,
                "0x16000", "0x2000", "0x10002000", "0x10004000", "0x10006000",
                "0x10008000", "0x1000a000", "0x1000c000", "0x1000e000",
                "0x16000", "0x2000",
            ),
        )
        self.assertFalse(any(name in live.PROBE_ARGV for name in ("adb", "fastboot")))
        for pin_name in (
            "EXPECTED_BRIDGE_SCRIPT_SHA256",
            "EXPECTED_PROBE_SOURCE_SHA256",
            "EXPECTED_PROBE_BINARY_SHA256",
        ):
            pin = getattr(live, pin_name)
            self.assertRegex(pin, r"\A[0-9a-f]{64}\Z", pin_name)
        self.assertEqual(
            live.EXPECTED_PROBE_BINARY_SHA256,
            "ed826cc75dee1eafad3b1b1ea4b0b779147364a330201e284b9e24c92adf1b92",
        )
        self.assertEqual(live.DEFAULT_TOTAL_TIMEOUT, 1800.0)
        self.assertGreaterEqual(
            live.DEFAULT_TOTAL_TIMEOUT
            - live.DEFAULT_PROBE_TIMEOUT
            - live.cleanup_health_reserve(live.DEFAULT_PROBE_TIMEOUT),
            live.MIN_PRE_DISPATCH_BUDGET,
        )
        with self.assertRaises(live.LiveError):
            args = self.args("bad-host")
            args.host = "localhost"
            live.run(args)

    def test_probe_jsonl_arithmetic_and_shape_are_strict(self) -> None:
        payload = probe_payload()
        jsonl, records = live.validate_probe_payload(payload)
        self.assertEqual(len(records), 26)
        self.assertEqual(json.loads(jsonl.splitlines()[0])["declared_base"], "0xc2000000")
        with self.assertRaises(live.LiveError):
            live.validate_probe_payload(probe_payload(mutate="schema"))
        with self.assertRaises(live.LiveError):
            live.validate_probe_payload(probe_payload(mutate="duplicate"))
        malformed = payload.replace(b'"pa_xor": "0x16000"', b'"pa_xor": "0x0"', 1)
        with self.assertRaises(live.LiveError):
            live.validate_probe_payload(malformed)

    def test_target_drift_fails_closed_without_cleanup(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), target_drift=True)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        self.assertEqual([call[0] for call in bridge.calls], ["version", "cmdline"])
        output = self.root / "evidence" / "private" / "run"
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertFalse(receipt["target_bound"])

    def test_probe_failure_retains_payload_and_runs_hash_cleanup_health(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), probe_code=1)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        output = self.root / "evidence" / "private" / "run"
        self.assertIn(b"[exit 1]", (output / live.RAW_PAYLOAD_BASENAME).read_bytes())
        ids = [call[0] for call in bridge.calls]
        self.assertIn("remote_hash_after_run", ids)
        self.assertIn("final_selftest", ids)
        self.assertEqual(json.loads((output / live.RECEIPT_BASENAME).read_text())["status"], "INCIDENT")

    def test_transport_timeout_keeps_partial_pid_and_never_replays(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), probe_timeout=True)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        output = self.root / "evidence" / "private" / "run"
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        ids = [call[0] for call in bridge.calls]
        self.assertEqual(ids.count("probe"), 1)
        self.assertNotIn("probe_terminate", ids)
        self.assertNotIn("probe_termination_check_0", ids)
        self.assertIn("cleanup_node", ids)
        self.assertIn("final_selftest", ids)
        self.assertEqual(receipt["dispatch_count"], 1)
        self.assertEqual(receipt["probe_completion"]["pid"], 456)
        self.assertTrue(receipt["probe_completion"]["proved"])
        self.assertIn(b"pid=456", (output / live.RAW_PAYLOAD_BASENAME).read_bytes())
        probe_entry = next(item for item in receipt["commands"] if item["evidence_id"] == "probe")
        self.assertEqual(probe_entry["partial_pid"], 456)
        self.assertTrue(probe_entry["partial_transcript_size"] > 0)
        self.assertEqual(receipt["probe_completion"]["cancel"]["byte_hex"], "03")

    def test_socket_timeout_retains_real_partial_pid(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((live.BRIDGE_HOST, 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_partial() -> None:
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.recv(4096)
                    connection.sendall(
                        b"A90P1 BEGIN seq=9 cmd=run argc=1 flags=0x0\r\n"
                        b"run: pid=987, q/Ctrl-C cancels\r\n"
                    )
                    time.sleep(0.20)
            finally:
                listener.close()

        worker = threading.Thread(target=serve_partial)
        worker.start()
        try:
            with self.assertRaises(live.TransportFailure) as raised:
                live.call(
                    live.BRIDGE_HOST,
                    port,
                    "probe",
                    live.PROBE_ARGV,
                    0.08,
                    allow_error=True,
                )
        finally:
            worker.join(1.0)
        partial = raised.exception.partial
        self.assertIsNotNone(partial)
        assert partial is not None
        self.assertIn(b"pid=987", partial.transcript or b"")
        self.assertEqual(live.child_pid(partial.payload or partial.transcript or b""), 987)
        self.assertIsNotNone(partial.payload)

    def test_raw_cancel_reconnect_accepts_only_ctrl_c_for_active_probe(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((live.BRIDGE_HOST, 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        observed: list[bytes] = []
        server_errors: list[BaseException] = []

        def serve_active() -> None:
            try:
                first, _ = listener.accept()
                with first:
                    observed.append(first.recv(4096))
                    first.sendall(
                        b"A90P1 BEGIN seq=11 cmd=run argc=5 flags=0x0\r\n"
                        b"run: pid=987, q/Ctrl-C cancels\r\n"
                    )
                    first.settimeout(1.0)
                    while first.recv(4096):
                        pass
                second, _ = listener.accept()
                with second:
                    cancel = second.recv(4096)
                    observed.append(cancel)
                    if cancel.startswith(b"cmdv1") or cancel.startswith(b"cmdv1x"):
                        second.sendall(b"[bridge] framed command rejected while run is active\r\n")
                    elif cancel == b"\x03":
                        second.sendall(
                            b"\r\nrun: terminating pid=987\r\n"
                            b"run: cancelled by Ctrl-C\r\n"
                            b"[err] run rc=-125 errno=125 (Operation canceled) (3ms)\r\n"
                            b"A90P1 END seq=11 cmd=run rc=-125 errno=125 duration_ms=3 "
                            b"flags=0x0 status=error\r\n"
                            b"a90:/# "
                        )
            except BaseException as exc:
                server_errors.append(exc)
            finally:
                listener.close()

        worker = threading.Thread(target=serve_active)
        worker.start()
        try:
            with self.assertRaises(live.TransportFailure) as raised:
                live.call(
                    live.BRIDGE_HOST,
                    port,
                    "probe",
                    live.PROBE_ARGV,
                    0.08,
                    allow_error=True,
                )
            partial = raised.exception.partial
            self.assertIsNotNone(partial)
            assert partial is not None
            session = live._Session(live.BRIDGE_HOST, port, 0.2)
            with mock.patch.object(
                live, "revalidate_bridge_binding", return_value={}
            ), mock.patch.object(
                live, "BRIDGE_CLIENT_OBSERVATION_WINDOW", 0.02
            ):
                completion = live.cancel_probe_raw(
                    session,
                    partial.transcript,
                    expected_binding={},
                    timeout=0.5,
                )
        finally:
            worker.join(1.0)
        self.assertEqual(server_errors, [])
        self.assertEqual(len(observed), 2)
        self.assertIn(b"cmdv1", observed[0])
        self.assertEqual(observed[1], b"\x03")
        self.assertTrue(completion["proved"])
        self.assertTrue(completion["channel_ready"])
        self.assertEqual(completion["pid"], 987)
        self.assertEqual(completion["cancel"]["send_sha256"], live.sha256(b"\x03"))
        self.assertEqual(session.commands, [])

    def test_raw_cancel_retries_busy_before_one_ctrl_c(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((live.BRIDGE_HOST, 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        observed: list[bytes] = []
        first_observed: list[bytes] = []
        server_errors: list[BaseException] = []
        terminal = (
            b"\r\nrun: terminating pid=987\r\n"
            b"run: cancelled by Ctrl-C\r\n"
            b"[err] run rc=-125 errno=125 (Operation canceled) (3ms)\r\n"
            b"A90P1 END seq=12 cmd=run rc=-125 errno=125 duration_ms=3 "
            b"flags=0x0 status=error\r\n"
            b"a90:/# "
        )

        def serve_busy_then_quiet() -> None:
            try:
                busy, _ = listener.accept()
                with busy:
                    # Deliberately exceed the old 0.05s peek interval.  The
                    # runner must not send Ctrl-C before this delayed busy
                    # greeting is observed.
                    time.sleep(0.08)
                    busy.sendall(live.CANCEL_BUSY_TEXT)
                    busy.settimeout(0.2)
                    try:
                        first_observed.append(busy.recv(1))
                    except (socket.timeout, ConnectionResetError):
                        first_observed.append(b"")
                quiet, _ = listener.accept()
                with quiet:
                    observed.append(quiet.recv(1))
                    quiet.sendall(terminal)
            except BaseException as exc:
                server_errors.append(exc)
            finally:
                listener.close()

        worker = threading.Thread(target=serve_busy_then_quiet)
        worker.start()
        original = (
            b"A90P1 BEGIN seq=12 cmd=run argc=5 flags=0x0\r\n"
            b"run: pid=987, q/Ctrl-C cancels\r\n"
        )
        session = live._Session(live.BRIDGE_HOST, port, 0.2)
        try:
            with mock.patch.object(
                live, "revalidate_bridge_binding", side_effect=[{}, {}, {}]
            ), mock.patch.object(
                live, "BRIDGE_CLIENT_OBSERVATION_WINDOW", 0.12
            ):
                completion = live.cancel_probe_raw(
                    session, original, expected_binding={}, timeout=0.8
                )
        finally:
            worker.join(1.0)
        self.assertEqual(server_errors, [])
        self.assertEqual(first_observed, [b""])
        self.assertEqual(observed, [b"\x03"])
        self.assertTrue(completion["proved"])
        self.assertEqual(completion["cancel"]["send_count"], 1)
        self.assertEqual(len(completion["cancel"]["attempts"]), 2)
        self.assertTrue(completion["cancel"]["attempts"][0]["busy"])
        self.assertTrue(completion["cancel"]["attempts"][1]["sent"])

    def test_raw_cancel_rebind_sends_zero_bytes(self) -> None:
        original = (
            b"A90P1 BEGIN seq=13 cmd=run argc=5 flags=0x0\r\n"
            b"run: pid=988, q/Ctrl-C cancels\r\n"
        )
        session = live._Session(live.BRIDGE_HOST, 9, 0.2)
        with mock.patch.object(
            live,
            "revalidate_bridge_binding",
            side_effect=live.LiveError("bridge PID drifted"),
        ):
            completion = live.cancel_probe_raw(
                session, original, expected_binding={}, timeout=0.8
            )
        self.assertFalse(completion["proved"])
        self.assertTrue(completion["binding_lost"])
        self.assertEqual(completion["cancel"]["send_count"], 0)
        self.assertEqual(completion["cancel"]["attempts"], [])

    def test_bridge_rebind_before_probe_is_incident_without_dispatch(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        with self.assertRaises(live.LiveError):
            self.run_with(bridge, rebind=True)
        ids = [call[0] for call in bridge.calls]
        self.assertNotIn("probe", ids)
        self.assertNotIn("cleanup_node", ids)
        self.assertNotIn("cleanup_files", ids)
        self.assertNotIn("final_version", ids)
        self.assertNotIn("final_cmdline", ids)
        self.assertNotIn("final_selftest", ids)
        receipt = json.loads(
            (self.root / "evidence/private/run/receipt.json").read_text()
        )
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertEqual(receipt["dispatch_count"], 0)
        self.assertFalse(receipt["command_sequence_validated"])
        self.assertIsNone(receipt["pre_dispatch_revalidation"])

    def test_preprobe_deadline_revalidates_before_safe_cleanup(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        with self.assertRaises(live.LiveError):
            self.run_with(bridge, fail_after_footer=True)
        ids = [call[0] for call in bridge.calls]
        self.assertEqual(ids.count("probe"), 0)
        self.assertNotIn("decode", ids)
        footer_index = ids.index("envelope_footer")
        cleanup_index = ids.index("cleanup_node")
        self.assertGreater(cleanup_index, footer_index)
        self.assertIn("final_selftest", ids)
        receipt = json.loads(
            (self.root / "evidence/private/run/receipt.json").read_text()
        )
        self.assertEqual(receipt["dispatch_count"], 0)
        self.assertTrue(receipt["cleanup"]["attempted"])
        self.assertEqual(receipt["pre_dispatch_revalidation"]["status"], "PASS")

        rebound = FakeBridge(self.binary.read_bytes())
        with self.assertRaises(live.LiveError):
            self.run_with(
                rebound,
                self.args("footer-rebind"),
                rebind=True,
                fail_after_footer=True,
            )
        rebound_ids = [call[0] for call in rebound.calls]
        self.assertEqual(rebound_ids.count("probe"), 0)
        self.assertNotIn("cleanup_node", rebound_ids)
        self.assertNotIn("final_selftest", rebound_ids)

    def test_hash_and_final_health_failures_are_incidents(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), remote_hash="0" * 64)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        receipt = json.loads(
            (self.root / "evidence/private/run/receipt.json").read_text()
        )
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertTrue(receipt["cleanup"]["attempted"])
        bridge = FakeBridge(self.binary.read_bytes(), final_selftest_fail=1)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge, self.args("selftest-fail"))
        receipt = json.loads(
            (self.root / "evidence/private/selftest-fail/receipt.json").read_text()
        )
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertFalse(receipt["final_health"]["ok"])

    def test_private_sidecar_hashes_and_public_redaction(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        output = self.run_with(bridge)
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        for key, filename in (
            ("raw", live.RAW_BASENAME),
            ("payload", live.RAW_PAYLOAD_BASENAME),
        ):
            metadata = receipt["probe"][key]
            data = (output / filename).read_bytes()
            self.assertEqual(metadata["basename"], filename)
            self.assertEqual(metadata["size_bytes"], len(data))
            self.assertEqual(metadata["sha256"], live.sha256(data))
        transcript = (output / live.TRANSCRIPT_BASENAME).read_bytes()
        self.assertEqual(receipt["transcript"]["sha256"], live.sha256(transcript))
        # A receipt mapping is never sufficient for publication.  The sole
        # public authority must reopen the private directory and all sidecars.
        with self.assertRaises(live.LiveError):
            live.make_public_manifest(receipt)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "public.json"
            with self.assertRaises(live.LiveError):
                live.write_public_manifest(Path(temporary) / "evidence/private/x.json", receipt)
            with mock.patch.object(
                analysis,
                "make_public_manifest",
                return_value={"status": "DEVICE_ACQUISITION_VALIDATED"},
            ) as delegated_make:
                public = live.make_public_manifest(output)
            delegated_make.assert_called_once_with(
                output, dependency_020m=None, dependency_021=None
            )
            self.assertEqual(public["status"], "DEVICE_ACQUISITION_VALIDATED")
            with mock.patch.object(
                analysis,
                "write_public_manifest",
                return_value=path,
            ) as delegated_write:
                self.assertEqual(live.write_public_manifest(path, output), path)
            delegated_write.assert_called_once_with(
                path,
                output,
                dependency_020m=None,
                dependency_021=None,
            )

        (output / live.RAW_PAYLOAD_BASENAME).unlink()
        with self.assertRaises(live.LiveError):
            live.make_public_manifest(output)

    def test_public_generation_rejects_incident_and_forged_pass_gates(self) -> None:
        incident_bridge = FakeBridge(self.binary.read_bytes(), target_drift=True)
        with self.assertRaises(live.LiveError):
            self.run_with(incident_bridge)
        incident = json.loads(
            (self.root / "evidence/private/run/receipt.json").read_text()
        )
        with self.assertRaises(live.LiveError):
            live.make_public_manifest(incident)

        output = self.run_with(FakeBridge(self.binary.read_bytes()), self.args("pass"))
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        receipt["dispatch_count"] = 2
        (output / live.RECEIPT_BASENAME).write_text(
            json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaises(live.LiveError):
            live.make_public_manifest(output)

    def test_no_clobber_and_no_retry(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        self.run_with(bridge)
        count = len(bridge.calls)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        self.assertEqual(len(bridge.calls), count)

    def test_repeated_groups_interleaving_and_percentiles_are_recomputed(self) -> None:
        rows = probe_records()
        # Group 0 is pair/summary at rows 3/4 and group 1 at rows 5/6.
        rows[4]["p90"] = 99
        with self.assertRaises(live.LiveError):
            live.validate_probe_records(rows)
        rows = probe_records()
        rows[3], rows[5] = rows[5], rows[3]
        with self.assertRaises(live.LiveError):
            live.validate_probe_records(rows)
        rows = probe_records()
        rows[6]["pairs"] = 2
        rows[6]["rejected_range"] = live.EXPECTED_PAIRS - 2
        with self.assertRaises(live.LiveError):
            live.validate_probe_records(rows)


class LocalSafetyTests(unittest.TestCase):
    def test_bridge_binding_skips_empty_proc_cmdline(self) -> None:
        bridge_argv = [
            "python3", str(live.BRIDGE_PROCESS_SCRIPT_PATH), "--host",
            live.BRIDGE_HOST, "--port", str(live.BRIDGE_PORT), "--device",
            live.BRIDGE_SERIAL_DEVICE, "--expect-realpath",
            live.BRIDGE_SERIAL_DEVICE, "--device-glob",
            live.BRIDGE_SERIAL_GLOB_TOKEN,
        ]
        descriptor = {
            "basename": live.EXPECTED_BRIDGE_SCRIPT_BASENAME,
            "size_bytes": live.EXPECTED_BRIDGE_SCRIPT_SIZE,
            "sha256": live.EXPECTED_BRIDGE_SCRIPT_SHA256,
        }
        serial_stat = mock.Mock(
            st_mode=live.stat.S_IFCHR | 0o600,
            st_dev=1,
            st_ino=2,
            st_rdev=3,
        )
        with mock.patch.object(
            live, "_bridge_script_descriptor", return_value=descriptor
        ), mock.patch.object(
            live.os.path, "realpath", return_value=live.BRIDGE_SERIAL_DEVICE
        ), mock.patch.object(
            live.os, "stat", return_value=serial_stat
        ), mock.patch.object(
            live.Path, "iterdir", return_value=[Path("/proc/111"), Path("/proc/222")]
        ), mock.patch.object(
            live, "_proc_cmdline", side_effect=[None, bridge_argv]
        ), mock.patch.object(
            live, "_bridge_listener_owned", return_value=True
        ):
            binding = live.validate_bridge_binding()
        self.assertEqual(binding["process_pid"], 222)

    def test_stable_read_and_write_are_no_follow_no_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_bytes(b"x")
            link = root / "link"
            link.symlink_to(real)
            with self.assertRaises(live.LiveError):
                live.read_stable(link, "linked")
            destination = root / "new"
            live.write_new(destination, b"x")
            with self.assertRaises(live.LiveError):
                live.write_new(destination, b"y")


if __name__ == "__main__":
    unittest.main()
