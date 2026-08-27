from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import a90_pa28_live_analysis as analysis


def _cleanup() -> dict[str, object]:
    return {
        "schema": analysis.PROBE_SCHEMA,
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


def _records() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = [
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "context",
            "cpu": analysis.EXPECTED_CPU,
            "cntfrq": analysis.EXPECTED_CNTFRQ,
            "heap": analysis.EXPECTED_HEAP,
            "mib": analysis.EXPECTED_MIB,
            "repetitions": analysis.EXPECTED_REPETITIONS,
            "pairs": analysis.EXPECTED_PAIRS,
            "warmups": analysis.EXPECTED_WARMUPS,
            "order": analysis.EXPECTED_ORDER,
            "barrier": analysis.EXPECTED_BARRIER,
            "divisor": analysis.EXPECTED_DIVISOR,
            "offset_mode": analysis.EXPECTED_OFFSET_MODE,
            "declared_base": analysis.EXPECTED_BASE_TEXT,
        },
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "ion_heap",
            "name": analysis.EXPECTED_HEAP,
            "heap_type": analysis.EXPECTED_HEAP_TYPE,
            "heap_id": analysis.EXPECTED_HEAP_ID,
        },
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "pa_provenance",
            "source": "pagemap",
            "pages": analysis.EXPECTED_PAGE_COUNT,
            "present": 0,
            "nonzero_pfn": 0,
            "first_pfn": "0x0",
            "last_pfn": "0x0",
            "contiguous": True,
            "status": "BLIND",
        },
    ]
    # Leading controls, seven candidates, and trailing controls.  The same
    # offset is safe for every fixed difference and keeps test arithmetic
    # independent of timing classification.
    medians = {
        analysis.CONTROL_CONFLICT: [110, 111],
        analysis.CONTROL_NON_CONFLICT: [10, 11],
        analysis.CANDIDATE_VALUES[0]: [12, 12],
        analysis.CANDIDATE_VALUES[1]: [100, 100],
        analysis.CANDIDATE_VALUES[2]: [13, 13],
        analysis.CANDIDATE_VALUES[3]: [14, 14],
        analysis.CANDIDATE_VALUES[4]: [15, 15],
        analysis.CANDIDATE_VALUES[5]: [16, 16],
        analysis.CANDIDATE_VALUES[6]: [17, 17],
    }
    for occurrence, value in enumerate(analysis.FIXED_DIFFERENCES):
        delta = medians[value][0 if occurrence < 2 else 1 if occurrence >= 9 else 0]
        other = value
        for _ in range(analysis.EXPECTED_PAIRS):
            rows.append({
                "schema": analysis.PROBE_SCHEMA,
                "type": "pair",
                "value": hex(value),
                "offset": "0x0",
                "pa_a": hex(analysis.EXPECTED_BASE),
                "pa_b": hex(analysis.EXPECTED_BASE + other),
                "pa_xor": hex(value),
                "delta": delta,
            })
        rows.append({
            "schema": analysis.PROBE_SCHEMA,
            "type": "difference",
            "value": hex(value),
            "pairs": analysis.EXPECTED_PAIRS,
            "rejected_range": 0,
            "rejected_carry": 0,
            "p10": delta,
            "median": delta,
            "p90": delta,
        })
    rows.append(_cleanup())
    return rows


def _raw_bytes(rows: list[dict[str, object]] | None = None) -> bytes:
    return "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in (rows or _records())).encode()


def _descriptor(name: str, size: int = 1, digest: str | None = None) -> dict[str, object]:
    return {"basename": name, "size_bytes": size, "sha256": digest or "a" * 64}


def _build_receipt_bytes() -> bytes:
    return (
        json.dumps(
            {
                "schema": analysis.BUILD_SCHEMA,
                "source": _descriptor(analysis.EXPECTED_SOURCE_BASENAME, analysis.EXPECTED_SOURCE_SIZE, analysis.EXPECTED_SOURCE_SHA256),
                "binary": _descriptor(analysis.EXPECTED_BINARY_BASENAME, analysis.EXPECTED_BINARY_SIZE, analysis.EXPECTED_BINARY_SHA256),
                "compiler": {
                    "triple": analysis.EXPECTED_COMPILER_TRIPLE,
                    "version": analysis.EXPECTED_COMPILER_VERSION,
                    "command": ["aarch64-linux-gnu-gcc", "-O2", "-static", "-Wall", "-Wextra", "-Werror", "-o", analysis.EXPECTED_BINARY_BASENAME, analysis.EXPECTED_SOURCE_BASENAME],
                    "static": True,
                },
                "reproducible_byte_identical": True,
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _commands() -> list[dict[str, object]]:
    binary_b64 = ((analysis.EXPECTED_BINARY_SIZE + 2) // 3) * 4
    chunk_count = (binary_b64 + analysis.MAX_LEGACY_CHUNK - 1) // analysis.MAX_LEGACY_CHUNK
    ids = analysis._expected_command_ids(chunk_count)
    commands: list[dict[str, object]] = []
    for index, evidence_id in enumerate(ids):
        if evidence_id in {"version", "final_version"}:
            argv = ["version"]
        elif evidence_id in {"cmdline", "final_cmdline"}:
            argv = ["run", analysis.TOYBOX, "cat", "/proc/cmdline"]
        elif evidence_id == "ion_dev":
            argv = ["run", analysis.TOYBOX, "cat", analysis.ION_DEV_PATH]
        elif evidence_id == "preclean":
            argv = ["run", analysis.TOYBOX, "rm", "-f", analysis.REMOTE_ENVELOPE, analysis.REMOTE_BINARY, analysis.REMOTE_ION]
        elif evidence_id == "envelope_header":
            argv = ["appendfile", analysis.REMOTE_ENVELOPE, "begin-base64 700 v022r-pa28-probe\n"]
        elif evidence_id.startswith("payload_"):
            argv = ["appendfile", analysis.REMOTE_ENVELOPE, "A" * min(analysis.MAX_LEGACY_CHUNK, 32)]
        elif evidence_id == "envelope_footer":
            argv = ["appendfile", analysis.REMOTE_ENVELOPE, "\n====\n"]
        elif evidence_id == "decode":
            argv = ["run", analysis.TOYBOX, "uudecode", "-o", analysis.REMOTE_BINARY, analysis.REMOTE_ENVELOPE]
        elif evidence_id == "chmod_binary":
            argv = ["run", analysis.TOYBOX, "chmod", "700", analysis.REMOTE_BINARY]
        elif evidence_id in {"remote_hash_before_run", "remote_hash_after_run"}:
            argv = ["run", analysis.TOYBOX, "sha256sum", analysis.REMOTE_BINARY]
        elif evidence_id == "ion_node_create":
            argv = ["run", analysis.TOYBOX, "mknod", analysis.REMOTE_ION, "c", "10", "94"]
        elif evidence_id == "ion_node_chmod":
            argv = ["run", analysis.TOYBOX, "chmod", "600", analysis.REMOTE_ION]
        elif evidence_id == "probe":
            argv = list(analysis.PROBE_ARGV)
        elif evidence_id == "cleanup_node":
            argv = ["run", analysis.TOYBOX, "rm", "-f", analysis.REMOTE_ION]
        elif evidence_id == "cleanup_files":
            argv = ["run", analysis.TOYBOX, "rm", "-f", analysis.REMOTE_ENVELOPE, analysis.REMOTE_BINARY]
        elif evidence_id.startswith("absence_"):
            wanted = {"absence_node": analysis.REMOTE_ION, "absence_envelope": analysis.REMOTE_ENVELOPE, "absence_binary": analysis.REMOTE_BINARY}[evidence_id]
            argv = ["run", analysis.TOYBOX, "test", "!", "-e", wanted]
        else:
            argv = ["selftest", "status"]
        seq = str(index + 1)
        commands.append({
            "evidence_id": evidence_id,
            "argv": argv,
            "extended": evidence_id in {"envelope_header", "envelope_footer"},
            "started_utc": "2026-08-27T09:00:00.000000+00:00",
            "completed_utc": "2026-08-27T09:00:00.100000+00:00",
            "duration_monotonic_s": 0.1,
            "child_exit_code": 0 if argv[0] == "run" else "NOT_APPLICABLE",
            "begin": {"seq": seq, "cmd": argv[0]},
            "end": {"seq": seq, "cmd": argv[0], "rc": "0", "status": "ok"},
            "transcript_sha256": "b" * 64,
            "transcript_size": 10,
        })
    return commands


def _receipt(raw: bytes) -> dict[str, object]:
    raw_hash = hashlib.sha256(raw).hexdigest()
    artifacts = {
        "source": _descriptor(analysis.EXPECTED_SOURCE_BASENAME, analysis.EXPECTED_SOURCE_SIZE, analysis.EXPECTED_SOURCE_SHA256),
        "binary": _descriptor(analysis.EXPECTED_BINARY_BASENAME, analysis.EXPECTED_BINARY_SIZE, analysis.EXPECTED_BINARY_SHA256),
        "runner": _descriptor(analysis.EXPECTED_RUNNER_BASENAME, analysis.EXPECTED_RUNNER_SIZE, analysis.EXPECTED_RUNNER_SHA256),
        "bridge_script": _descriptor(analysis.EXPECTED_BRIDGE_BASENAME, analysis.EXPECTED_BRIDGE_SIZE, analysis.EXPECTED_BRIDGE_SHA256),
        "build_receipt": _descriptor(analysis.EXPECTED_BUILD_BASENAME, 10, "e" * 64),
    }
    binding = {
        "listener": {"host": analysis.BRIDGE_HOST, "port": analysis.BRIDGE_PORT},
        "serial_device": analysis.BRIDGE_SERIAL_DEVICE,
        "serial_identity": analysis.BRIDGE_SERIAL_ID,
        "serial_realpath": analysis.BRIDGE_SERIAL_DEVICE,
        "serial_stat": {"st_dev": 1, "st_ino": 2, "st_rdev": 3, "mode": 0o600, "character_device": True},
        "validated_utc": "2026-08-27T09:00:00.000000+00:00",
        "process_pid": 123,
        "process_argv": [
            "python3", "serial_tcp_bridge.py", "--host", analysis.BRIDGE_HOST,
            "--port", str(analysis.BRIDGE_PORT), "--device", analysis.BRIDGE_SERIAL_DEVICE,
            "--expect-realpath", analysis.BRIDGE_SERIAL_DEVICE,
            "--device-glob", f"*{analysis.BRIDGE_SERIAL_GLOB_TOKEN}*",
        ],
        "bridge_process_script": analysis.BRIDGE_PROCESS_SCRIPT,
        "bridge_process_script_path": str(analysis.BRIDGE_SCRIPT_PATH),
        "bridge_process_script_descriptor": _descriptor(analysis.EXPECTED_BRIDGE_BASENAME, analysis.EXPECTED_BRIDGE_SIZE, analysis.EXPECTED_BRIDGE_SHA256),
        "unique_process": True,
    }
    lifecycle_keys = (
        "acquisition_started_utc", "bridge_validation_started_utc", "bridge_validation_completed_utc",
        "target_preflight_started_utc", "target_preflight_completed_utc", "ion_identity_started_utc",
        "ion_identity_completed_utc", "preclean_started_utc", "preclean_completed_utc", "upload_started_utc",
        "upload_completed_utc", "remote_hash_before_started_utc", "remote_hash_before_completed_utc",
        "ion_node_creation_started_utc", "ion_node_creation_completed_utc", "probe_dispatch_utc",
        "probe_child_exit_utc", "remote_hash_after_started_utc", "remote_hash_after_completed_utc",
        "cleanup_started_utc", "cleanup_completed_utc", "final_health_started_utc", "final_health_completed_utc",
        "acquisition_completed_utc", "receipt_publication_prewrite_utc",
    )
    timestamp = "2026-08-27T09:00:00.000000+00:00"
    lifecycle = {key: timestamp for key in lifecycle_keys}
    lifecycle["duration_monotonic_s"] = 1.0
    lifecycle["absence_checks"] = {name: {"started_utc": timestamp, "completed_utc": timestamp, "ok": True} for name in ("absence_node", "absence_envelope", "absence_binary")}
    commands = _commands()
    return {
        "schema": analysis.RECEIPT_SCHEMA,
        "status": "PASS",
        "experiment_id": analysis.EXPERIMENT_ID,
        "started_utc": timestamp,
        "completed_utc": timestamp,
        "target_bound": True,
        "dispatch_count": 1,
        "target": dict(analysis.EXPECTED_TARGET),
        "target_frames": {
            "version": {"begin": {"cmd": "version", "seq": "1"}, "end": {"cmd": "version", "seq": "1", "rc": "0", "status": "ok"}, "payload_size": 1, "payload_sha256": "f" * 64, "transcript_size": 1, "transcript_sha256": "f" * 64},
            "cmdline": {"begin": {"cmd": "run", "seq": "2"}, "end": {"cmd": "run", "seq": "2", "rc": "0", "status": "ok"}, "payload_size": 1, "payload_sha256": "f" * 64, "transcript_size": 1, "transcript_sha256": "f" * 64},
        },
        "bridge": {"host": analysis.BRIDGE_HOST, "port": analysis.BRIDGE_PORT},
        "bridge_binding": binding,
        "pre_dispatch_revalidation": {
            "status": "PASS",
            "validated_utc": timestamp,
            "bridge_binding": binding,
            "target": dict(analysis.EXPECTED_TARGET),
            "ion_identity": analysis.EXPECTED_ION_DEV,
            "command_argv": list(analysis.PROBE_ARGV),
        },
        "command_argv": list(analysis.PROBE_ARGV),
        "probe_argv": list(analysis.PROBE_CLI_ARGS),
        "probe": {"schema": analysis.PROBE_SCHEMA, "records": len(_records()), "child_pid": 456, "child_exit_proved": True, "cleanup": _cleanup(), "raw": {"basename": analysis.RAW_BASENAME, "size_bytes": len(raw), "sha256": raw_hash}, "payload": _descriptor(analysis.RAW_PAYLOAD_BASENAME, 7, "9" * 64)},
        "probe_completion": {"proved": True, "method": "child_exit_receipt", "pid": 456, "child_exit_code": 0, "errors": []},
        "artifacts": artifacts,
        "source": artifacts["source"], "binary": artifacts["binary"], "runner": artifacts["runner"], "bridge_script": artifacts["bridge_script"], "build_receipt": artifacts["build_receipt"], "build_receipt_copy": artifacts["build_receipt"],
        "build": {"schema": analysis.BUILD_SCHEMA, "compiler_triple": analysis.EXPECTED_COMPILER_TRIPLE, "compiler_version": analysis.EXPECTED_COMPILER_VERSION, "compiler_command": ["aarch64-linux-gnu-gcc", "-O2", "-static", "-Wall", "-Wextra", "-Werror", "-o", analysis.EXPECTED_BINARY_BASENAME, analysis.EXPECTED_SOURCE_BASENAME], "static": True, "reproducible_byte_identical": True},
        "upload": {"binary_size": analysis.EXPECTED_BINARY_SIZE, "binary_sha256": analysis.EXPECTED_BINARY_SHA256, "base64_bytes": ((analysis.EXPECTED_BINARY_SIZE + 2) // 3) * 4, "chunk_bytes": analysis.MAX_LEGACY_CHUNK, "chunk_count": len([x for x in commands if x["evidence_id"].startswith("payload_")]), "remote_path": analysis.REMOTE_BINARY, "remote_sha256_verified": True, "remote_before_run_sha256": analysis.EXPECTED_BINARY_SHA256},
        "remote_binary": {"path": analysis.REMOTE_BINARY, "before_run_sha256": analysis.EXPECTED_BINARY_SHA256, "after_run_sha256": analysis.EXPECTED_BINARY_SHA256, "unchanged": True},
        "ion_device": {"sysfs_path": analysis.ION_DEV_PATH, "sysfs_identity": analysis.EXPECTED_ION_DEV, "expected_identity": analysis.EXPECTED_ION_DEV, "temporary_node": analysis.REMOTE_ION, "node_created": True},
        "cleanup": {"attempted": True, "node_removed": True, "files_removed": True, "absence_proved": True, "errors": []},
        "final_health": {"attempted": True, "ok": True, "errors": [], "target": dict(analysis.EXPECTED_TARGET), "selftest": {"passed": 11, "warn": 1, "fail": 0, "duration": 1, "entries": 12}},
        "transcript": _descriptor(analysis.TRANSCRIPT_BASENAME, 10, "1" * 64),
        "commands": commands,
        "command_sequence_validated": True,
        "failures": [],
        "claims": {"interpretation": "DEFERRED_TO_HOST_ANALYZER", "physical_alias": "NOT_ESTABLISHED"},
        "scope": {"normal_ram_only": True, "write_combine_mapping": True, "mmio": False, "smc": False, "protected_memory": False, "partition_write": False, "automatic_retries": False},
        "lifecycle": lifecycle,
    }


class ProbeReducerTests(unittest.TestCase):
    def test_valid_probe_reduces_unique_vector_and_cleanup(self) -> None:
        rows = _records()
        parsed = analysis.validate_probe_records(rows)
        reduced = analysis.reduce_measurements(parsed)
        self.assertEqual(reduced["status"], "SUPPORTED_MODEL_EXTENSION")
        self.assertEqual(reduced["f_pa28"], "010")
        self.assertEqual(parsed["cleanup"]["released"], True)

    def test_summary_forgery_interleaving_and_cleanup_fail_closed(self) -> None:
        rows = _records()
        rows[3 + analysis.EXPECTED_PAIRS]["median"] = 999
        with self.assertRaises(analysis.AnalysisError):
            analysis.validate_probe_records(rows)
        rows = _records()
        rows[3], rows[259] = rows[259], rows[3]
        with self.assertRaises(analysis.AnalysisError):
            analysis.validate_probe_records(rows)
        rows = _records()
        rows[-1]["released"] = False
        with self.assertRaises(analysis.AnalysisError):
            analysis.validate_probe_records(rows)

    def test_repeated_control_disagreement_and_non_unique_winner_are_inconclusive(self) -> None:
        rows = _records()
        # Move the trailing conflict control into the non-conflict cluster.
        summary_index = 3 + 9 * (analysis.EXPECTED_PAIRS + 1) + analysis.EXPECTED_PAIRS
        rows[summary_index]["median"] = 20
        rows[summary_index]["p10"] = 20
        rows[summary_index]["p90"] = 20
        for row in rows[3 + 9 * (analysis.EXPECTED_PAIRS + 1):summary_index]:
            if row.get("type") == "pair":
                row["delta"] = 20
        parsed = analysis.validate_probe_records(rows)
        result = analysis.reduce_measurements(parsed)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        rows = _records()
        for row in rows:
            if row.get("type") == "pair" and row.get("value") == hex(analysis.CANDIDATE_VALUES[2]):
                row["delta"] = 100
        # Update the forged-but-arithmetically-consistent summary for the second candidate.
        for row in rows:
            if row.get("type") == "difference" and row.get("value") == hex(analysis.CANDIDATE_VALUES[2]):
                row.update({"median": 100, "p10": 100, "p90": 100})
        parsed = analysis.validate_probe_records(rows)
        self.assertEqual(analysis.reduce_measurements(parsed)["status"], "INCONCLUSIVE")

    def test_alternate_cleanup_field_variant_is_rejected(self) -> None:
        rows = _records()
        rows[-1].pop("sample_buffers_freed")
        rows[-1]["samples_freed"] = True
        with self.assertRaises(analysis.AnalysisError):
            analysis.validate_probe_records(rows)


class AcquisitionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner_pin_patch = mock.patch.multiple(
            analysis,
            EXPECTED_RUNNER_SIZE=150104,
            EXPECTED_RUNNER_SHA256="0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66",
        )
        self.runner_pin_patch.start()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.directory = self.root / "evidence" / "private" / "run"
        self.directory.mkdir(parents=True)
        self.directory.chmod(0o700)
        self.raw = _raw_bytes()
        (self.directory / analysis.RAW_BASENAME).write_bytes(self.raw)
        payload = b"payload"
        transcript = b"transcript"
        build = _build_receipt_bytes()
        (self.directory / analysis.RAW_PAYLOAD_BASENAME).write_bytes(payload)
        (self.directory / analysis.TRANSCRIPT_BASENAME).write_bytes(transcript)
        (self.directory / analysis.EXPECTED_BUILD_BASENAME).write_bytes(build)
        receipt = _receipt(self.raw)
        receipt["probe"]["payload"] = _descriptor(analysis.RAW_PAYLOAD_BASENAME, len(payload), hashlib.sha256(payload).hexdigest())
        receipt["transcript"] = _descriptor(analysis.TRANSCRIPT_BASENAME, len(transcript), hashlib.sha256(transcript).hexdigest())
        receipt["build_receipt"] = _descriptor(analysis.EXPECTED_BUILD_BASENAME, len(build), hashlib.sha256(build).hexdigest())
        receipt["build_receipt_copy"] = receipt["build_receipt"]
        receipt["artifacts"]["build_receipt"] = receipt["build_receipt"]
        receipt["source"] = receipt["artifacts"]["source"]
        receipt["binary"] = receipt["artifacts"]["binary"]
        receipt["runner"] = receipt["artifacts"]["runner"]
        receipt["bridge_script"] = receipt["artifacts"]["bridge_script"]
        (self.directory / analysis.RECEIPT_BASENAME).write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.runner_pin_patch.stop()

    def test_valid_private_run_and_redacted_no_clobber(self) -> None:
        result = analysis.reduce_directory(self.directory)
        manifest = analysis.make_public_manifest(self.directory)
        rendered = json.dumps(manifest, sort_keys=True)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertNotIn(str(self.directory), rendered)
        self.assertNotIn("/tmp/a90-native", rendered)
        output = self.root / "public.json"
        analysis.write_public_manifest(output, self.directory)
        with self.assertRaises(analysis.AnalysisError):
            analysis.write_public_manifest(output, self.directory)

    def test_dependency_mutation_forged_receipt_and_raw_hash_fail(self) -> None:
        receipt_path = self.directory / analysis.RECEIPT_BASENAME
        document = json.loads(receipt_path.read_text())
        document["status"] = "INCIDENT"
        receipt_path.write_text(json.dumps(document) + "\n")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)
        receipt_path.write_text(json.dumps(_receipt(self.raw), sort_keys=True) + "\n")
        document = json.loads(receipt_path.read_text())
        document["probe"]["raw"]["sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(document) + "\n")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)
        with tempfile.TemporaryDirectory() as temporary:
            mutated = Path(temporary) / "020m.json"
            source = analysis.DEPENDENCY_020M_PATH.read_bytes()
            mutated.write_bytes(source.replace(b'"SM-A908N"', b'"SM-S918N"', 1))
            with self.assertRaises(analysis.AnalysisError):
                analysis.reduce_directory(self.directory, dependency_020m=mutated)

    def test_symlink_inputs_and_public_destination_fail_closed(self) -> None:
        raw_path = self.directory / analysis.RAW_BASENAME
        raw_path.unlink()
        raw_path.symlink_to(self.root / "real-raw")
        (self.root / "real-raw").write_bytes(self.raw)
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)
        raw_path.unlink()
        raw_path.write_bytes(self.raw)
        with self.assertRaises(analysis.AnalysisError):
            analysis.write_public_manifest(self.root / "evidence" / "private" / "bad.json", {})

    def test_arbitrary_manifest_and_pre_dispatch_mutations_fail(self) -> None:
        valid_result = analysis.reduce_directory(self.directory)
        forged_result = copy.deepcopy(valid_result)
        forged_result["reduction"]["candidate_winner"] = {
            "difference": "0xdeadbeef", "vector": "111", "f_pa28": "111",
        }
        with self.assertRaises(analysis.AnalysisError):
            analysis.make_public_manifest(forged_result)
        with self.assertRaises(analysis.AnalysisError):
            analysis.write_public_manifest(self.root / "forged.json", forged_result)
        with self.assertRaises(analysis.AnalysisError):
            analysis.make_public_manifest(
                {"schema": analysis.ANALYSIS_SCHEMA, "classification": "CLASS C (TRANSFORM ONLY)", "eligibility": "NOT_ELIGIBLE"},
            )
        with self.assertRaises(analysis.AnalysisError):
            analysis.write_public_manifest(
                self.root / "public.json",
                {"schema": analysis.ANALYSIS_SCHEMA, "classification": "CLASS C (TRANSFORM ONLY)", "eligibility": "NOT_ELIGIBLE"},
            )
        receipt_path = self.directory / analysis.RECEIPT_BASENAME
        receipt = json.loads(receipt_path.read_text())
        del receipt["pre_dispatch_revalidation"]
        receipt_path.write_text(json.dumps(receipt) + "\n")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)
        receipt = _receipt(self.raw)
        payload = (self.directory / analysis.RAW_PAYLOAD_BASENAME).read_bytes()
        transcript = (self.directory / analysis.TRANSCRIPT_BASENAME).read_bytes()
        build = (self.directory / analysis.EXPECTED_BUILD_BASENAME).read_bytes()
        receipt["probe"]["payload"] = _descriptor(analysis.RAW_PAYLOAD_BASENAME, len(payload), hashlib.sha256(payload).hexdigest())
        receipt["transcript"] = _descriptor(analysis.TRANSCRIPT_BASENAME, len(transcript), hashlib.sha256(transcript).hexdigest())
        receipt["build_receipt"] = _descriptor(analysis.EXPECTED_BUILD_BASENAME, len(build), hashlib.sha256(build).hexdigest())
        receipt["build_receipt_copy"] = receipt["build_receipt"]
        receipt["artifacts"]["build_receipt"] = receipt["build_receipt"]
        receipt["pre_dispatch_revalidation"]["status"] = "FAIL"
        receipt_path.write_text(json.dumps(receipt) + "\n")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)

    def test_build_transcript_payload_and_runner_sidecar_mutations_fail(self) -> None:
        receipt_path = self.directory / analysis.RECEIPT_BASENAME
        original = receipt_path.read_text()
        payload_path = self.directory / analysis.RAW_PAYLOAD_BASENAME
        payload_path.write_bytes(payload_path.read_bytes() + b"x")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)
        payload_path.write_bytes(b"payload")
        transcript_path = self.directory / analysis.TRANSCRIPT_BASENAME
        transcript_path.write_bytes(transcript_path.read_bytes() + b"x")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)
        transcript_path.write_bytes(b"transcript")
        build_path = self.directory / analysis.EXPECTED_BUILD_BASENAME
        build_path.write_bytes(build_path.read_bytes().replace(b"aarch64-linux-gnu", b"wrong", 1))
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)
        build_path.write_bytes(_build_receipt_bytes())
        receipt = json.loads(original)
        receipt["artifacts"]["runner"]["sha256"] = "0" * 64
        receipt["runner"] = receipt["artifacts"]["runner"]
        receipt_path.write_text(json.dumps(receipt) + "\n")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)

    def test_pre_dispatch_bridge_identity_drift_is_rejected(self) -> None:
        receipt_path = self.directory / analysis.RECEIPT_BASENAME
        original = json.loads(receipt_path.read_text())
        mutations = (
            ("process_pid", 999),
            ("process_argv", ["python3", "serial_tcp_bridge.py", "--host", "127.0.0.1"]),
            ("serial_stat", {"st_dev": 1, "st_ino": 999, "st_rdev": 3, "mode": 0o600, "character_device": True}),
            ("bridge_process_script", "other_bridge.py"),
        )
        for field, value in mutations:
            receipt = json.loads(json.dumps(original))
            receipt["pre_dispatch_revalidation"]["bridge_binding"][field] = value
            receipt_path.write_text(json.dumps(receipt) + "\n")
            with self.assertRaises(analysis.AnalysisError):
                analysis.reduce_directory(self.directory)
        receipt = json.loads(json.dumps(original))
        receipt["pre_dispatch_revalidation"]["bridge_binding"]["listener"]["port"] = 12345
        receipt_path.write_text(json.dumps(receipt) + "\n")
        with self.assertRaises(analysis.AnalysisError):
            analysis.reduce_directory(self.directory)


if __name__ == "__main__":
    unittest.main()
