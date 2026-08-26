"""Focused host-only tests for the Verification-018 marker analyzer.

These tests deliberately construct transcripts through the analyzer's
synthetic probe model.  They never open a device or invoke the live runner.
The transcript is a fixed contract: 190 records, with every marker, sentinel,
verdict, and summary field recomputed by the analyzer before a result can be
used.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tools import a90_alias_marker_analysis as marker


EXPECTED_RECORDS = 190


def transcript_rows(*, memory: marker.SyntheticMemory | None = None) -> list[dict]:
    """Return one complete transcript as mutable JSON-like records."""

    text = marker.simulate(memory or marker.SyntheticMemory())
    return [json.loads(line) for line in text.splitlines()]


def render_rows(rows: list[dict]) -> str:
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"


def first_index(rows: list[dict], kind: str) -> int:
    return next(index for index, row in enumerate(rows) if row.get("type") == kind)


def candidate_index(rows: list[dict], *, bit: int = 6, trial: int = 0) -> int:
    return next(
        index
        for index, row in enumerate(rows)
        if row.get("type") == "candidate"
        and row.get("bit") == bit
        and row.get("trial") == trial
        and row.get("anchor") == "0x0"
    )


def changed_uint(value: object) -> str:
    """Change an integer or hexadecimal integer without changing its shape."""

    if isinstance(value, int):
        return f"0x{value ^ 1:x}"
    return f"0x{int(str(value), 0) ^ 1:x}"


class TranscriptShapeTests(unittest.TestCase):
    def test_valid_transcript_has_exactly_190_records(self):
        rows = marker.parse(marker.simulate(marker.SyntheticMemory()), "valid")
        self.assertEqual(len(rows), EXPECTED_RECORDS)
        self.assertEqual(sum(row["type"] == "candidate" for row in rows), 176)
        self.assertEqual(sum(row["type"] == "anchor" for row in rows), 8)
        self.assertEqual(rows[-1]["type"], "summary")

    def test_malformed_blank_foreign_and_duplicate_key_records_fail_closed(self):
        valid = marker.simulate(marker.SyntheticMemory())

        with self.assertRaises(marker.MarkerError):
            marker.parse(valid + "not-json\n", "malformed")

        lines = valid.splitlines()
        lines.insert(1, "")
        with self.assertRaises(marker.MarkerError):
            marker.parse("\n".join(lines) + "\n", "blank")

        rows = transcript_rows()
        rows[0]["schema"] = "foreign_schema"
        with self.assertRaises(marker.MarkerError):
            marker.parse(render_rows(rows), "foreign")

        first = valid.splitlines()[0]
        duplicate_key = first.replace(
            '"schema": "a90_alias_marker_v1"',
            '"schema": "a90_alias_marker_v1", "schema": "a90_alias_marker_v1"',
            1,
        )
        self.assertNotEqual(first, duplicate_key)
        with self.assertRaises(marker.MarkerError):
            marker.parse("\n".join([duplicate_key, *valid.splitlines()[1:]]) + "\n", "duplicate-key")

    def test_out_of_order_trailing_missing_and_duplicate_candidate_records_fail(self):
        rows = transcript_rows()
        rows[1], rows[2] = rows[2], rows[1]
        with self.assertRaises(marker.MarkerError):
            marker.parse(render_rows(rows), "out-of-order")

        rows = transcript_rows()
        rows.append(copy.deepcopy(rows[-1]))
        with self.assertRaises(marker.MarkerError):
            marker.parse(render_rows(rows), "trailing")

        rows = transcript_rows()
        rows.pop(candidate_index(rows))
        with self.assertRaises(marker.MarkerError):
            marker.parse(render_rows(rows), "missing")

        rows = transcript_rows()
        duplicate = copy.deepcopy(rows[candidate_index(rows, bit=6)])
        rows[candidate_index(rows, bit=7)] = duplicate
        parsed = marker.parse(render_rows(rows), "duplicate-candidate")
        with self.assertRaises(marker.MarkerError):
            marker.analyse(parsed, "duplicate-candidate")


class SyntheticOutcomeTests(unittest.TestCase):
    def test_dropped_bit_positives_name_each_synthetic_line(self):
        for bit in (6, 12, 13, 19, 27):
            with self.subTest(bit=bit):
                result = marker.analyse(
                    marker.parse(
                        marker.simulate(marker.SyntheticMemory(drop_bit=bit)),
                        f"drop-bit-{bit}",
                    ),
                    f"drop-bit-{bit}",
                )
                self.assertEqual(result["verdict"], "ALIAS_DETECTED")
                self.assertEqual(result["aliased_bits"], [bit])
                self.assertFalse(result["negative_is_admissible"])

    def test_injective_synthetic_negative_is_admissible_only_in_its_declared_scope(self):
        result = marker.analyse(
            marker.parse(marker.simulate(marker.SyntheticMemory()), "injective"),
            "injective",
        )
        self.assertEqual(result["verdict"], "NO_ALIAS")
        self.assertEqual(result["aliased_bits"], [])
        self.assertTrue(result["negative_is_admissible"])
        self.assertEqual(result["scope"]["state"], "ONE_TESTED_STATE")
        self.assertEqual(
            result["scope"]["cross_state_skitter_permutation"], "NOT_TESTED"
        )

    def test_skitter_permutation_remains_blind_to_cross_state_aliases(self):
        result = marker.analyse(
            marker.parse(marker.simulate(marker.SkitterPermutation()), "skitter"),
            "skitter",
        )
        self.assertEqual(result["verdict"], "NO_ALIAS")
        self.assertTrue(result["negative_is_admissible"])
        self.assertEqual(result["scope"]["state"], "ONE_TESTED_STATE")
        self.assertEqual(
            result["scope"]["cross_state_skitter_permutation"], "NOT_TESTED"
        )
        self.assertEqual(
            result["scope"]["storage_identity"], "SINGLE_STATE_NONINJECTIVE_TEST"
        )


class RecomputedFieldTests(unittest.TestCase):
    def _assert_analysis_rejects(self, rows: list[dict], label: str) -> None:
        parsed = marker.parse(render_rows(rows), label)
        with self.assertRaises(marker.MarkerError):
            marker.analyse(parsed, label)

    def test_marker_sentinel_verdict_and_summary_are_recomputed(self):
        rows = transcript_rows()
        rows[first_index(rows, "ion_heap")]["heap_type"] = 9
        self._assert_analysis_rejects(rows, "heap-identity-drift")

        rows = transcript_rows()
        rows[first_index(rows, "anchor")]["marker"] = changed_uint(
            rows[first_index(rows, "anchor")]["marker"]
        )
        self._assert_analysis_rejects(rows, "bad-marker")

        rows = transcript_rows()
        index = candidate_index(rows)
        rows[index]["expected"] = changed_uint(rows[index]["expected"])
        self._assert_analysis_rejects(rows, "bad-sentinel")

        rows = transcript_rows()
        index = candidate_index(rows)
        rows[index]["verdict"] = "ALIAS"
        self._assert_analysis_rejects(rows, "bad-verdict")

        rows = transcript_rows()
        rows[-1]["candidates"] += 1
        self._assert_analysis_rejects(rows, "bad-summary")

        rows = transcript_rows()
        rows[first_index(rows, "anchor")]["trial"] = False
        self._assert_analysis_rejects(rows, "boolean-anchor-trial")

        rows = transcript_rows()
        rows[-1]["aliases"] = False
        self._assert_analysis_rejects(rows, "boolean-summary-count")

    def test_collision_gate_rejects_marker_sentinel_collisions(self):
        seed = marker.DEFAULT_SEED
        values = marker._layout_values(seed)
        self.assertEqual(len(values), len({value for _, value in values}))
        with mock.patch.object(
            marker, "control_distinct_marker", return_value=marker.control_same_marker(seed)
        ):
            with self.assertRaises(marker.MarkerError):
                marker._layout_values(seed)


class PinAndArtifactTests(unittest.TestCase):
    def test_pin_validation_normalizes_aliases_and_rejects_unsafe_shapes(self):
        checked = marker.validate_pin(
            {
                "basename": "probe.bin",
                "size_bytes": 3,
                "sha256": "AB" * 32,
            },
            "probe-source",
        )
        self.assertEqual(checked, {
            "basename": "probe.bin",
            "size_bytes": 3,
            "sha256": "ab" * 32,
        })

        invalid = (
            ({"size_bytes": 1, "sha256": "0" * 64, "extra": True}, "raw"),
            ({"size_bytes": 1, "sha256": "0" * 63}, "raw"),
            ({"size_bytes": True, "sha256": "0" * 64}, "raw"),
            ({"size_bytes": -1, "sha256": "0" * 64}, "raw"),
            ({"basename": "../probe", "size_bytes": 1, "sha256": "0" * 64}, "raw"),
            ({"size_bytes": 1, "sha256": "0" * 64}, "unknown-kind"),
        )
        for pin, kind in invalid:
            with self.subTest(pin=pin, kind=kind), self.assertRaises(marker.MarkerError):
                marker.validate_pin(pin, kind)

        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw.jsonl"
            raw.write_text(marker.simulate(marker.SyntheticMemory()), encoding="utf-8")
            with self.assertRaises(marker.MarkerError):
                marker.analyse_raw(
                    raw,
                    pins={
                        "probe_source": {
                            "size_bytes": 1,
                            "sha256": "0" * 64,
                        }
                    },
                )

    def test_raw_source_binary_and_receipt_hashes_are_stable_and_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "raw": root / "alias-marker.jsonl",
                "probe_source": marker.V018_RUNNER_PATH.with_name("a90_alias_marker_probe.c"),
                "probe_binary": root / "v018-alias-probe",
                "acquisition_receipt": root / "receipt.json",
                "build_receipt": root / "build-receipt.json",
                "raw_payload": root / "probe-output.bin",
                "transcript": root / "transcript.bin",
            }
            live_rows = transcript_rows()
            live_rows[0]["mapping"] = "write_combine"
            live_rows[0]["ion_node"] = "/tmp/a90-native/v018-ion"
            paths["raw"].write_text(render_rows(live_rows), encoding="utf-8")
            paths["probe_binary"].write_bytes(b"synthetic probe binary\x00")
            raw_bytes = paths["raw"].read_bytes()
            paths["raw_payload"].write_bytes(
                b"run: pid=123, q/Ctrl-C cancels\n" + raw_bytes + b"[exit 0]\n"
            )

            def metadata(path: Path) -> dict:
                data = path.read_bytes()
                return {
                    "basename": path.name,
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            # When all three future artifacts are supplied, the analyzer also
            # validates the live runner's exact receipt envelope.  This stays
            # synthetic and does not imply that any device acquisition ran.
            raw_meta = metadata(paths["raw"])
            source_meta = metadata(paths["probe_source"])
            binary_meta = metadata(paths["probe_binary"])
            payload_meta = metadata(paths["raw_payload"])
            build_receipt = {
                "schema": marker.BUILD_SCHEMA,
                "source": source_meta,
                "binary": binary_meta,
                "compiler": {
                    "triple": "aarch64-linux-gnu",
                    "version": "fixture compiler",
                    "command": ["fixture-build"],
                    "static": True,
                },
                "reproducible_byte_identical": True,
            }
            paths["build_receipt"].write_text(
                json.dumps(build_receipt, sort_keys=True) + "\n", encoding="utf-8"
            )
            build_meta = metadata(paths["build_receipt"])
            runner_meta = metadata(marker.V018_RUNNER_PATH)
            bridge_meta = metadata(marker.V018_BRIDGE_PATH)
            command_ids = marker._expected_live_command_ids(1)
            commands = []
            for index, evidence_id in enumerate(command_ids):
                argv = [evidence_id]
                frame_bytes = (
                    f"\r\na90:/# cmdv1 {evidence_id}\n"
                    f"A90P1 BEGIN seq={index + 1} cmd={evidence_id} argc=1 flags=0x0\n"
                    f"[done] {evidence_id} (0ms)\n"
                    f"A90P1 END seq={index + 1} cmd={evidence_id} rc=0 errno=0 "
                    "duration_ms=0 flags=0x0 status=ok\r\n"
                    "a90:/# "
                ).encode()
                commands.append({
                    "evidence_id": evidence_id,
                    "argv": argv,
                    "extended": False,
                    "begin": {"cmd": evidence_id, "seq": str(index + 1)},
                    "end": {"cmd": evidence_id, "seq": str(index + 1)},
                    "transcript_sha256": hashlib.sha256(frame_bytes).hexdigest(),
                    "transcript_size": len(frame_bytes),
                })
            transcript_bytes = b"".join(
                (
                    f"\n===== {entry['evidence_id']} =====\n".encode()
                    + (
                        f"\r\na90:/# cmdv1 {entry['evidence_id']}\n"
                        f"A90P1 BEGIN seq={index + 1} cmd={entry['evidence_id']} argc=1 flags=0x0\n"
                        f"[done] {entry['evidence_id']} (0ms)\n"
                        f"A90P1 END seq={index + 1} cmd={entry['evidence_id']} rc=0 errno=0 "
                        "duration_ms=0 flags=0x0 status=ok\r\n"
                        "a90:/# "
                    ).encode()
                )
                for index, entry in enumerate(commands)
            )
            paths["transcript"].write_bytes(transcript_bytes)
            transcript_meta = metadata(paths["transcript"])
            receipt = {
                "schema": marker.LIVE_SCHEMA,
                "status": "PASS",
                "experiment_id": "synthetic-v018",
                "started_utc": "2026-08-27T00:00:00+00:00",
                "completed_utc": "2026-08-27T00:00:01+00:00",
                "target_bound": True,
                "target": marker._LIVE_TARGET,
                "target_frames": {
                    "version": {
                        "begin": {"cmd": "version", "seq": "1"},
                        "end": {"cmd": "version", "seq": "1"},
                        "payload_size": 1,
                        "payload_sha256": "0" * 64,
                        "transcript_size": 1,
                        "transcript_sha256": "1" * 64,
                    },
                    "cmdline": {
                        "begin": {"cmd": "run", "seq": "2"},
                        "end": {"cmd": "run", "seq": "2"},
                        "payload_size": 1,
                        "payload_sha256": "2" * 64,
                        "transcript_size": 1,
                        "transcript_sha256": "3" * 64,
                    },
                },
                "bridge": {"host": "127.0.0.1", "port": 54321},
                "bridge_binding": {
                    "listener": {"host": "127.0.0.1", "port": 54321},
                    "serial_device": "/dev/ttyACM0",
                    "serial_identity_resolved": True,
                    "bridge_process_script": "serial_tcp_bridge.py",
                    "unique_process": True,
                },
                "command_argv": marker._LIVE_COMMAND_ARGV,
                "probe_argv": marker._LIVE_PROBE_ARGV,
                "command_sequence_validated": True,
                "probe": {
                    "schema": marker.PROBE_SCHEMA,
                    "records": 190,
                    "child_pid": 123,
                    "child_exit_proved": True,
                    "raw": raw_meta,
                    "payload": payload_meta,
                },
                "artifacts": {
                    "source": source_meta,
                    "binary": binary_meta,
                    "runner": runner_meta,
                    "bridge_script": bridge_meta,
                    "build_receipt": build_meta,
                },
                "source": source_meta,
                "binary": binary_meta,
                "runner": runner_meta,
                "bridge_script": bridge_meta,
                "build_receipt": build_meta,
                "build": {
                    "schema": marker.BUILD_SCHEMA,
                    "compiler_triple": "aarch64-linux-gnu",
                    "compiler_version": "fixture compiler",
                    "static": True,
                    "reproducible_byte_identical": True,
                },
                "upload": {
                    "binary_size": binary_meta["size_bytes"],
                    "binary_sha256": binary_meta["sha256"],
                    "remote_sha256_verified": True,
                    "remote_before_run_sha256": binary_meta["sha256"],
                },
                "remote_binary": {
                    "before_run_sha256": binary_meta["sha256"],
                    "after_run_sha256": binary_meta["sha256"],
                    "unchanged": True,
                },
                "ion_device": {
                    "sysfs_identity": "10:94",
                    "expected_identity": "10:94",
                    "node_created": True,
                },
                "cleanup": {
                    "attempted": True,
                    "node_removed": True,
                    "files_removed": True,
                    "absence_proved": True,
                    "errors": [],
                },
                "final_health": {
                    "attempted": True,
                    "ok": True,
                    "errors": [],
                    "target": marker._LIVE_TARGET,
                    "selftest": {
                        "passed": 11,
                        "warn": 1,
                        "fail": 0,
                        "duration": 1,
                        "entries": 12,
                    },
                },
                "transcript": transcript_meta,
                "commands": commands,
                "failures": [],
                "claims": {"interpretation": "DEFERRED_TO_HOST_ANALYZER"},
                "probe_completion": {
                    "proved": True,
                    "method": "child_exit_receipt",
                    "pid": 123,
                    "errors": [],
                },
            }
            paths["acquisition_receipt"].write_text(
                json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8"
            )

            pins: dict[str, dict] = {}
            for kind in (
                "raw", "probe_source", "probe_binary", "acquisition_receipt",
                "build_receipt",
            ):
                path = paths[kind]
                data = path.read_bytes()
                pins[kind] = {
                    "basename": path.name,
                    "size_bytes": len(data),
                    # Uppercase exercises normalization while the resulting
                    # public metadata remains a canonical lowercase digest.
                    "sha256": hashlib.sha256(data).hexdigest().upper(),
                }

            result = marker.analyse_raw(
                paths["raw"],
                pins={"raw": pins["raw"], "probe-source": pins["probe_source"],
                      "probe_binary": pins["probe_binary"],
                      "acquisition-receipt": pins["acquisition_receipt"],
                      "build-receipt": pins["build_receipt"]},
                artifacts={
                    "probe-source": paths["probe_source"],
                    "probe_binary": paths["probe_binary"],
                    "acquisition-receipt": paths["acquisition_receipt"],
                    "build-receipt": paths["build_receipt"],
                },
            )
            self.assertEqual(set(result["inputs"]), {
                "raw", "probe_source", "probe_binary", "acquisition_receipt",
                "build_receipt", "raw_payload", "transcript", "runner",
                "bridge_script",
            })
            for kind, path in {
                **{key: paths[key] for key in (
                    "raw", "probe_source", "probe_binary", "acquisition_receipt",
                    "build_receipt", "raw_payload", "transcript",
                )},
                "runner": marker.V018_RUNNER_PATH,
                "bridge_script": marker.V018_BRIDGE_PATH,
            }.items():
                data = path.read_bytes()
                expected_digest = hashlib.sha256(data).hexdigest()
                self.assertEqual(result["inputs"][kind], {
                    "basename": path.name,
                    "size_bytes": len(data),
                    "sha256": expected_digest,
                })
                if kind in pins:
                    self.assertEqual(result["declared_pins"][kind]["sha256"], expected_digest)
            self.assertEqual(result["mode"], "RAW_TRANSCRIPT_ANALYSIS")
            self.assertNotIn(str(root), json.dumps(result, sort_keys=True))


class PublicationAndControlGateTests(unittest.TestCase):
    def test_public_safe_output_is_deterministic_and_never_clobbers(self):
        result = marker.build_host_selftest()
        encoded = marker.encode_output(result)
        rendered = encoded.decode("utf-8")
        self.assertNotIn("/home/", rendered)
        self.assertNotIn("evidence/private", rendered)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "public.json"
            publication = marker.write_public_output(output, result)
            self.assertEqual(publication["observed_mode"], "0644")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            self.assertEqual(output.read_bytes(), encoded)
            original = output.read_bytes()
            with self.assertRaises(marker.MarkerError):
                marker.write_public_output(output, result)
            self.assertEqual(output.read_bytes(), original)

        with self.assertRaises(marker.MarkerError):
            marker.encode_output({"private_path": "/home/temmie/private.json"})

    def _assert_control_failure_is_closed(self, rows: list[dict], label: str) -> None:
        try:
            result = marker.analyse(marker.parse(render_rows(rows), label), label)
        except marker.MarkerError:
            # A stale NO_ALIAS summary may be rejected before the analyzer can
            # publish its repaired INSTRUMENT_FAILED verdict.  Both outcomes
            # are fail-closed and therefore safe for this gate.
            return
        self.assertFalse(result.get("negative_is_admissible", True))
        self.assertFalse(result.get("instrument_ok", True))
        self.assertNotEqual(result.get("verdict"), "NO_ALIAS")

    def test_failed_same_storage_control_never_yields_admissible_negative(self):
        rows = transcript_rows()
        index = first_index(rows, "control")
        self.assertEqual(rows[index]["name"], "same_storage_two_mappings")
        rows[index]["observed"] = changed_uint(rows[index]["observed"])
        rows[index]["verdict"] = "MISSED"
        self._assert_control_failure_is_closed(rows, "same-control-failure")

    def test_failed_distinct_control_never_yields_admissible_negative(self):
        rows = transcript_rows()
        index = next(
            index
            for index, row in enumerate(rows)
            if row.get("type") == "control" and row.get("name") == "distinct"
        )
        rows[index]["observed"] = rows[index]["marker"]
        rows[index]["verdict"] = "ALIAS"
        self._assert_control_failure_is_closed(rows, "distinct-control-failure")


if __name__ == "__main__":
    unittest.main()
