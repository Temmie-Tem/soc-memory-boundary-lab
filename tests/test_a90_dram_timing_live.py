from __future__ import annotations

import base64
import hashlib
import json
import unittest
from types import SimpleNamespace

from tools import a90_dram_timing_live as live


class ExtendedCommandTests(unittest.TestCase):
    def test_newline_argument_is_length_prefixed_hex(self) -> None:
        command = live.ExtendedCommand(
            "header", ("appendfile", live.REMOTE_ENVELOPE, "head\n")
        )
        wire = command.wire
        self.assertTrue(wire.startswith(b"cmdv1x "))
        self.assertTrue(wire.endswith(b"\n"))
        self.assertIn(b"5:686561640a", wire)

    def test_nul_is_rejected(self) -> None:
        command = live.ExtendedCommand("bad", ("appendfile", "x\0y"))
        with self.assertRaises(live.LiveError):
            _ = command.wire


class EnvelopeTests(unittest.TestCase):
    def test_envelope_is_toybox_begin_base64_shape(self) -> None:
        payload = bytes(range(256))
        header, body, footer = live.make_envelope(payload)
        self.assertEqual(header, "begin-base64 700 exp014-dram-probe\n")
        self.assertEqual(base64.b64decode(body, validate=True), payload)
        self.assertEqual(footer, "\n====\n")
        self.assertNotIn("\n", body)

    def test_chunk_size_stays_inside_legacy_frame(self) -> None:
        chunk = "A" * live.MAX_LEGACY_CHUNK
        wire = live.Command(
            "chunk", ("appendfile", live.REMOTE_ENVELOPE, chunk)
        ).wire
        self.assertLess(len(wire), 4096)


class ProbeArgvTests(unittest.TestCase):
    def test_ion_smoke_uses_fixed_ion_mode(self) -> None:
        args = SimpleNamespace(
            mode="smoke", backing="ion", cpu=7, mib=1, pairs=64,
            repetitions=201, difference=None, ion_heap="user_contig",
        )
        self.assertEqual(
            live.probe_argv(args),
            ("run", live.REMOTE_BINARY, "ion-smoke", "7"),
        )

    def test_anonymous_measure_preserves_supplied_differences(self) -> None:
        args = SimpleNamespace(
            mode="measure", backing="anonymous", cpu=7, mib=256, pairs=64,
            repetitions=201, difference=["0x100000"], ion_heap="user_contig",
        )
        self.assertEqual(live.probe_argv(args)[2], "measure")
        self.assertEqual(live.probe_argv(args)[-1], "0x100000")

    def test_ion_scan_binds_heap_name(self) -> None:
        args = SimpleNamespace(
            mode="scan", backing="ion", cpu=7, mib=1, pairs=64,
            repetitions=201, difference=None, ion_heap="user_contig",
        )
        self.assertEqual(
            live.probe_argv(args),
            ("run", live.REMOTE_BINARY, "ion-scan", "1", "user_contig"),
        )

    def test_explicit_difference_limit_matches_a90p1_argv_budget(self) -> None:
        self.assertEqual(live.MAX_DEVICE_DIFFERENCES, 23)


class TargetValidationTests(unittest.TestCase):
    def test_exact_a90_v2321_low_target_passes(self) -> None:
        version = (
            live.EXPECTED_VERSION + "\n" + live.EXPECTED_BUILD + "\n" +
            "kernel: " + live.EXPECTED_KERNEL
        ).encode()
        cmdline = (" ".join(sorted(live.EXPECTED_CMDLINE_TOKENS)) + "\n[exit 0]").encode()
        target = live.validate_target(version, cmdline)
        self.assertEqual(target["model"], "SM-A908N")
        self.assertEqual(target["debug_level"], "0x4f4c")

    def test_wrong_debug_level_fails_closed(self) -> None:
        version = (
            live.EXPECTED_VERSION + "\n" + live.EXPECTED_BUILD + "\n" +
            live.EXPECTED_KERNEL
        ).encode()
        tokens = set(live.EXPECTED_CMDLINE_TOKENS)
        tokens.remove("androidboot.debug_level=0x4f4c")
        tokens.add("androidboot.debug_level=0x494d")
        with self.assertRaises(live.LiveError):
            live.validate_target(version, " ".join(tokens).encode())


class ProbeRecordTests(unittest.TestCase):
    def test_structured_output_and_stability_are_required(self) -> None:
        records = [
            {"schema": live.PROBE_SCHEMA, "type": "header"},
            {
                "schema": live.PROBE_SCHEMA,
                "type": "stability",
                "changed_pages": 0,
                "lost_pages": 0,
            },
        ]
        payload = b"run header\r\n" + b"\r\n".join(
            json.dumps(record).encode() for record in records
        ) + b"\r\n[exit 0]"
        self.assertEqual(live.parse_probe_records(payload), records)

    def test_missing_stability_fails(self) -> None:
        payload = json.dumps(
            {"schema": live.PROBE_SCHEMA, "type": "header"}
        ).encode()
        with self.assertRaises(live.LiveError):
            live.parse_probe_records(payload)

    def test_scan_can_require_its_own_terminal_record(self) -> None:
        payload = json.dumps(
            {"schema": live.PROBE_SCHEMA, "type": "scan_complete"}
        ).encode()
        records = live.parse_probe_records(payload, require_stability=False)
        self.assertEqual(records[0]["type"], "scan_complete")

    def test_hash_helper_is_sha256(self) -> None:
        self.assertEqual(live.sha256(b"x"), hashlib.sha256(b"x").hexdigest())

    def test_run_value_removes_protocol_lines(self) -> None:
        payload = b"run: pid=42, q/Ctrl-C cancels\r\nperformance\r\n[exit 0]"
        self.assertEqual(live.parse_run_value(payload, "governor"), "performance")

    def test_run_value_rejects_nonzero_child(self) -> None:
        with self.assertRaises(live.LiveError):
            live.parse_run_value(b"run: pid=42, q/Ctrl-C cancels\r\n[exit 1]", "x")


if __name__ == "__main__":
    unittest.main()
