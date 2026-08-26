from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import a90_alias_marker_live as live
from tools import a90_alias_marker_analysis as marker_analysis


def fake_frame(command: str, payload: bytes = b"", *, rc: int = 0,
               status: str = "ok", seq: int = 1) -> live.Frame:
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
        f"{live.EXPECTED_VERSION} ({live.EXPECTED_RUNTIME_BUILD})".encode()
        + b"\n"
        + f"version: {live.EXPECTED_RUNTIME} {live.EXPECTED_BUILD}".encode()
        + b"\n"
        + f"kernel: {live.EXPECTED_KERNEL}".encode()
        + b"\n"
    )


def target_cmdline(*, drift: str | None = None) -> bytes:
    tokens = set(live.EXPECTED_CMDLINE_TOKENS)
    if drift is not None:
        tokens = {
            token for token in tokens
            if not token.startswith("androidboot.em.model=")
        }
        tokens.add(f"androidboot.em.model={drift}")
    return child_payload(" ".join(sorted(tokens)).encode())


def probe_payload() -> bytes:
    lines = marker_analysis.simulate(marker_analysis.SyntheticMemory()).splitlines()
    context = json.loads(lines[0])
    context["mapping"] = "write_combine"
    context["ion_node"] = live.REMOTE_ION
    lines[0] = json.dumps(context, sort_keys=True)
    return child_payload(*(line.encode() for line in lines))


class FakeBridge:
    def __init__(
        self,
        binary: bytes,
        *,
        target_drift: bool = False,
        remote_hash: str | None = None,
        probe_code: int = 0,
        cleanup_node_error: bool = False,
        final_selftest_fail: int = 0,
    ) -> None:
        self.binary_hash = hashlib.sha256(binary).hexdigest()
        self.target_drift = target_drift
        self.remote_hash = remote_hash or self.binary_hash
        self.probe_code = probe_code
        self.cleanup_node_error = cleanup_node_error
        self.final_selftest_fail = final_selftest_fail
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
        del timeout
        evidence_id = command.evidence_id
        argv = tuple(command.argv)
        self.calls.append((evidence_id, argv, allow_error))
        if evidence_id == "version":
            payload = (
                b"version: 0.9.286 build=wrong\n"
                b"kernel: wrong\n"
                if self.target_drift else target_version()
            )
            return fake_frame("version", payload)
        if evidence_id == "cmdline":
            return fake_frame("run", target_cmdline())
        if evidence_id in {"final_version"}:
            return fake_frame("version", target_version())
        if evidence_id == "final_cmdline":
            return fake_frame("run", target_cmdline())
        if evidence_id == "ion_dev":
            return fake_frame("run", child_payload(b"10:94"))
        if evidence_id == "probe":
            return fake_frame(
                "run",
                child_payload(probe_payload().split(b"\n", 1)[1].rsplit(
                    b"\n[exit 0]\n", 1
                )[0], code=self.probe_code),
            )
        if evidence_id in {"remote_hash_before_run", "remote_hash_after_run"}:
            payload = child_payload(
                f"{self.remote_hash}  {live.REMOTE_BINARY}".encode()
            )
            return fake_frame("run", payload)
        if evidence_id == "final_selftest":
            payload = (
                f"selftest: pass=11 warn=1 fail={self.final_selftest_fail} "
                "duration=1ms entries=2\n"
            ).encode()
            return fake_frame("selftest", payload)
        if evidence_id == "cleanup_node" and self.cleanup_node_error:
            return fake_frame("run", child_payload(code=1), rc=1, status="error")
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
        self.binary = self.root / "v018-alias-probe"
        self.source = live.REPO_ROOT / "tools" / live.EXPECTED_PROBE_SOURCE_BASENAME
        self.binary.write_bytes(b"already-built-probe")
        source_bytes = self.source.read_bytes()
        binary_bytes = self.binary.read_bytes()
        self.build_receipt = self.root / "build-receipt.json"
        self.build_receipt.write_text(
            json.dumps(
                {
                    "schema": live.BUILD_SCHEMA,
                    "source": {
                        "basename": self.source.name,
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
                        "version": "fixture compiler",
                        "command": ["fixture-build"],
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
            experiment_id="verification-018-fixture",
            binary=self.binary,
            source=self.source,
            build_receipt=self.build_receipt,
            output_dir=self.root / "evidence" / "private" / name,
            host=live.BRIDGE_HOST,
            port=live.BRIDGE_PORT,
            timeout=1.0,
            probe_timeout=2.0,
            total_timeout=30.0,
        )

    def run_with(self, bridge: FakeBridge, args: argparse.Namespace | None = None):
        source_bytes = self.source.read_bytes()
        binary_bytes = self.binary.read_bytes()
        with mock.patch.object(live, "exchange", side_effect=bridge), \
             mock.patch.object(live, "validate_bridge_binding", return_value={
                 "listener": {"host": live.BRIDGE_HOST, "port": live.BRIDGE_PORT},
                 "serial_device": live.BRIDGE_SERIAL_DEVICE,
                 "serial_identity_resolved": True,
                 "bridge_process_script": live.BRIDGE_PROCESS_SCRIPT,
                 "unique_process": True,
             }), \
             mock.patch.multiple(
                 live,
                 EXPECTED_PROBE_SOURCE_SIZE=len(source_bytes),
                 EXPECTED_PROBE_SOURCE_SHA256=hashlib.sha256(source_bytes).hexdigest(),
                 EXPECTED_PROBE_BINARY_SIZE=len(binary_bytes),
                 EXPECTED_PROBE_BINARY_SHA256=hashlib.sha256(binary_bytes).hexdigest(),
             ):
            return live.run(args or self.args())

    def test_fixed_protocol_sequence_and_command_surface(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        output = self.run_with(bridge)
        self.assertEqual(
            [call[0] for call in bridge.calls],
            [
                "version", "cmdline", "ion_dev", "preclean",
                "envelope_header", "payload_0000", "envelope_footer",
                "decode", "chmod_binary", "remote_hash_before_run",
                "ion_node_create", "ion_node_chmod", "probe",
                "remote_hash_after_run", "cleanup_node", "cleanup_files",
                "absence_node", "absence_envelope", "absence_binary",
                "final_version", "final_cmdline", "final_selftest",
            ],
        )
        by_id = {evidence_id: argv for evidence_id, argv, _ in bridge.calls}
        self.assertEqual(by_id["preclean"], (
            "run", live.TOYBOX, "rm", "-f",
            live.REMOTE_ENVELOPE, live.REMOTE_BINARY, live.REMOTE_ION,
        ))
        self.assertEqual(by_id["probe"], live.PROBE_ARGV)
        self.assertEqual(by_id["ion_dev"], (
            "run", live.TOYBOX, "cat", live.ION_DEV_PATH
        ))
        self.assertEqual(by_id["ion_node_create"], (
            "run", live.TOYBOX, "mknod", live.REMOTE_ION, "c", "10", "94"
        ))
        for _, argv, _ in bridge.calls:
            flattened = " ".join(argv).lower()
            for forbidden in ("adb", "fastboot", "smc", "mmio", "dev/mem",
                              "partition", "flash"):
                self.assertNotIn(forbidden, flattened)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_probe_cli_constant_binds_all_fixed_parameters(self) -> None:
        self.assertEqual(live.PROBE_ARGV[0:2], ("run", live.REMOTE_BINARY))
        self.assertEqual(live.PROBE_CLI_ARGS, (
            "--ion-node", live.REMOTE_ION, "--seed", live.EXPECTED_SEED
        ))
        self.assertEqual(
            (live.EXPECTED_HEAP, live.EXPECTED_MIB,
             live.EXPECTED_ANCHORS, live.EXPECTED_TRIALS),
            ("camera_preview", 256, 4, 2),
        )

    def test_receipt_and_raw_hashes_bind_exact_files(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        output = self.run_with(bridge)
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        self.assertEqual(receipt["status"], "PASS")
        for key, name in (
            ("raw", live.RAW_BASENAME),
            ("payload", live.RAW_PAYLOAD_BASENAME),
        ):
            metadata = receipt["probe"][key]
            data = (output / name).read_bytes()
            self.assertEqual(metadata["basename"], name)
            self.assertEqual(metadata["size_bytes"], len(data))
            self.assertEqual(metadata["sha256"], live.sha256(data))
        transcript = (output / live.TRANSCRIPT_BASENAME).read_bytes()
        self.assertEqual(receipt["transcript"]["sha256"], live.sha256(transcript))
        self.assertEqual(receipt["remote_binary"]["before_run_sha256"],
                         receipt["remote_binary"]["after_run_sha256"])
        self.assertEqual(receipt["final_health"]["selftest"]["fail"], 0)
        self.assertNotIn(str(output), (output / live.RECEIPT_BASENAME).read_text())

    def test_target_drift_fails_closed_before_cleanup_or_replay(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), target_drift=True)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        self.assertEqual([call[0] for call in bridge.calls],
                         ["version", "cmdline"])
        output = self.root / "evidence" / "private" / "run"
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertFalse(receipt["target_bound"])
        self.assertNotIn("PASS", receipt["status"])

    def test_remote_hash_mismatch_is_incident_and_cleanup_runs(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), remote_hash="0" * 64)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        ids = [call[0] for call in bridge.calls]
        self.assertIn("cleanup_node", ids)
        self.assertIn("final_selftest", ids)
        receipt = json.loads(
            (self.root / "evidence/private/run/receipt.json").read_text()
        )
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertFalse(receipt["cleanup"]["absence_proved"] is False)
        self.assertIsNone(receipt["remote_binary"]["after_run_sha256"])

    def test_probe_failure_preserves_exact_payload_and_does_not_pass(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), probe_code=1)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        output = self.root / "evidence/private/run"
        self.assertTrue((output / live.RAW_PAYLOAD_BASENAME).is_file())
        self.assertIn(b"[exit 1]", (output / live.RAW_PAYLOAD_BASENAME).read_bytes())
        receipt = json.loads((output / live.RECEIPT_BASENAME).read_text())
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertIn("remote_hash_after_run", [call[0] for call in bridge.calls])

    def test_cleanup_failure_is_recorded_without_pass_claim(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), cleanup_node_error=True)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        receipt = json.loads(
            (self.root / "evidence/private/run/receipt.json").read_text()
        )
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertTrue(receipt["cleanup"]["files_removed"])
        self.assertFalse(receipt["cleanup"]["node_removed"])
        self.assertTrue(receipt["cleanup"]["errors"])

    def test_final_health_failure_is_recorded_without_pass_claim(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes(), final_selftest_fail=1)
        with self.assertRaises(live.LiveError):
            self.run_with(bridge)
        receipt = json.loads(
            (self.root / "evidence/private/run/receipt.json").read_text()
        )
        self.assertEqual(receipt["status"], "INCIDENT")
        self.assertFalse(receipt["final_health"]["ok"])

    def test_no_replay_and_output_no_clobber(self) -> None:
        bridge = FakeBridge(self.binary.read_bytes())
        self.run_with(bridge)
        first_count = len(bridge.calls)
        with mock.patch.object(live, "exchange", side_effect=bridge):
            with self.assertRaises(live.LiveError):
                live.run(self.args())
        self.assertEqual(len(bridge.calls), first_count)
        receipt = self.root / "evidence/private/run/receipt.json"
        original = receipt.read_bytes()
        self.assertEqual(receipt.read_bytes(), original)

    def test_loopback_and_fixed_port_are_enforced(self) -> None:
        for host, port in (("localhost", live.BRIDGE_PORT),
                           ("::1", live.BRIDGE_PORT),
                           (live.BRIDGE_HOST, 54322)):
            args = self.args(name=f"bad-{len(host)}-{port}")
            args.host, args.port = host, port
            with self.assertRaises(live.LiveError):
                live.run(args)


class ParserAndSafetyTests(unittest.TestCase):
    def test_target_identity_rejects_conflicting_or_duplicate_fields(self) -> None:
        with self.assertRaises(live.LiveError):
            live.validate_target(
                target_version().replace(
                    live.EXPECTED_BUILD.encode(), b"build=v2321-drift", 1
                ),
                target_cmdline(),
            )
        duplicate = target_cmdline()[:-1] + b" androidboot.debug_level=0x4f4c\n[exit 0]\n"
        with self.assertRaises(live.LiveError):
            live.validate_target(target_version(), duplicate)

    def test_probe_payload_requires_fixed_context_and_structured_summary(self) -> None:
        payload = probe_payload()
        jsonl, records = live.validate_probe_payload(payload)
        self.assertEqual(len(records), 190)
        self.assertEqual(json.loads(jsonl.splitlines()[0])["trials"], 2)
        with self.assertRaises(live.LiveError):
            live.validate_probe_payload(
                payload.replace(b'"camera_preview"', b'"wrong_heap"', 1)
            )
        with self.assertRaises(live.LiveError):
            live.validate_probe_payload(payload.replace(b"\n{", b"\n\n{", 1))

    def test_probe_payload_rejects_foreign_or_malformed_records(self) -> None:
        bad = child_payload(b'{"schema":"foreign","type":"summary"}')
        with self.assertRaises(live.LiveError):
            live.validate_probe_payload(bad)
        bad = child_payload(b"not-json")
        with self.assertRaises(live.LiveError):
            live.validate_probe_payload(bad)

    def test_envelope_is_bounded_base64_and_extended_wire_is_safe(self) -> None:
        binary = bytes(range(256)) * 32
        header, body, footer = live.make_envelope(binary)
        self.assertEqual(base64_decode(body), binary)
        self.assertEqual(header, "begin-base64 700 v018-alias-probe\n")
        self.assertEqual(footer, "\n====\n")
        command = live.ExtendedCommand(
            "header", ("appendfile", live.REMOTE_ENVELOPE, header)
        )
        self.assertLess(len(command.wire), 4096)

    def test_no_follow_and_no_clobber_local_io(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            link = root / "link"
            real.write_bytes(b"x")
            link.symlink_to(real)
            with self.assertRaises(live.LiveError):
                live.read_stable(link, "linked")
            destination = root / "new"
            live.write_new(destination, b"x")
            with self.assertRaises(live.LiveError):
                live.write_new(destination, b"y")


def base64_decode(value: str) -> bytes:
    import base64
    return base64.b64decode(value, validate=True)


if __name__ == "__main__":
    unittest.main()
