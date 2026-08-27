from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import a90_pa28_timing_analysis as analysis


def _measurement(name: str, difference: int, p10: int, median: int, p90: int) -> dict[str, object]:
    return {
        "schema": analysis.PROBE_SCHEMA,
        "type": "measurement",
        "name": name,
        "difference": f"0x{difference:x}",
        "pairs": analysis.EXPECTED_PAIRS,
        "repetitions_per_pair": analysis.EXPECTED_REPETITIONS,
        "warmups_per_pair": analysis.EXPECTED_WARMUPS,
        "trim_percent": 10,
        "p10": p10,
        "median": median,
        "p90": p90,
        "status": "OK",
    }


def _raw_rows() -> list[dict[str, object]]:
    return [
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "context",
            "heap_name": analysis.EXPECTED_HEAP_NAME,
            "heap_id": analysis.EXPECTED_HEAP_ID,
            "heap_type": analysis.EXPECTED_HEAP_TYPE,
            "allocation_mib": analysis.EXPECTED_ALLOCATION_MIB,
            "allocation_bytes": analysis.EXPECTED_ALLOCATION_BYTES,
            "pa28_difference": "0x10000000",
            "negative_differences": ["0x10002000", "0x10004000"],
            "cpu": analysis.EXPECTED_CPU,
            "repetitions_per_pair": analysis.EXPECTED_REPETITIONS,
            "warmups_per_pair": analysis.EXPECTED_WARMUPS,
            "mapping": "ion_uncached_writecombine",
            "barrier": "dsb_ld",
            "order": "alternating",
            "pagemap": "NOT_USED",
            "physical_address_provenance": "NOT_COLLECTED",
            "device_writes": False,
            "mmio": False,
            "smc": False,
            "protected_memory": False,
        },
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "ion_heap",
            "name": analysis.EXPECTED_HEAP_NAME,
            "heap_type": analysis.EXPECTED_HEAP_TYPE,
            "heap_id": analysis.EXPECTED_HEAP_ID,
        },
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "allocation",
            "heap_id": analysis.EXPECTED_HEAP_ID,
            "heap_type": analysis.EXPECTED_HEAP_TYPE,
            "heap_name": analysis.EXPECTED_HEAP_NAME,
            "flags": 0,
            "requested_mib": analysis.EXPECTED_ALLOCATION_MIB,
            "mapped_bytes": analysis.EXPECTED_ALLOCATION_BYTES,
            "status": "OK",
        },
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "control",
            "name": "cache_maintenance",
            "mapping": "anonymous_cached",
            "cache_maintenance": "dc_civac",
            "samples": analysis.EXPECTED_CACHE_SAMPLES,
            "min": 1,
            "median": 5,
            "p90": 10,
            "status": "OK",
        },
        _measurement("same_offset", 0, -5, 0, 5),
        _measurement("pa28_candidate", analysis.EXPECTED_PA28_DIFFERENCE, 400, 500, 600),
        _measurement("negative_bank_bit13", analysis.EXPECTED_NEGATIVE_DIFFERENCES[0], -50, 0, 50),
        _measurement("negative_bank_bit14", analysis.EXPECTED_NEGATIVE_DIFFERENCES[1], -40, 10, 60),
        {
            "schema": analysis.PROBE_SCHEMA,
            "type": "summary",
            "candidate": "pa28_candidate",
            "same_offset": "same_offset",
            "negative_controls": ["negative_bank_bit13", "negative_bank_bit14"],
            "cache_control": "cache_maintenance",
            "pagemap": "NOT_USED",
            "physical_address_claim": "NONE",
            "interpretation": "HOST_ANALYZER_REQUIRED",
            "status": "OK",
            "load_sink": 123,
        },
    ]


def _precondition() -> dict[str, object]:
    return {
        "schema": analysis.PRECONDITION_SCHEMA,
        "target": {
            "model": "SM-A908N",
            "soc": "SM8150",
            "version": "A90 Linux init 0.9.285",
            "build": "build=v2321-usb-clean-identity-rodata",
            "kernel": "Linux 4.14.190-25818860-abA908NKSUEWA3 aarch64".replace(
                "A908NKSUEWA3", "A908NKSU5EWA3"
            ),
        },
        "raw_receipt": dict(analysis.EXPECTED_020M_RAW_RECEIPT),
        "semantic": {
            "ion_heap30": {
                "reg": "0x1e",
                "memory_region_phandle": "0x67a",
                "name": "qcom,ion-heap",
            },
            "camera_mem_region": {
                "name": "camera_mem_region",
                "phandle": "0x67a",
                "reg": {
                    "base": "0xc2000000",
                    "size": "0x14000000",
                    "end_exclusive": "0xd6000000",
                },
                "ion_recyclable": {"present": True, "errno": 0},
                "optional_properties": {
                    "camera_no_map": {"present": False, "errno": 2, "status": "error"},
                    "camera_reusable": {"present": False, "errno": 2, "status": "error"},
                },
            },
        },
    }


def _extent() -> dict[str, object]:
    return {
        "schema": analysis.EXTENT_SCHEMA,
        "heap": {
            "name": analysis.EXPECTED_HEAP_NAME,
            "heap_type": analysis.EXPECTED_HEAP_TYPE,
            "heap_id": analysis.EXPECTED_HEAP_ID,
        },
        "device_tree_region": {
            "heap_name": analysis.EXPECTED_HEAP_NAME,
            "heap_id": analysis.EXPECTED_HEAP_ID,
            "memory_region_phandle": "0x67a",
            "base": "0xc2000000",
            "size": "0x14000000",
        },
        "hold_bytes": analysis.EXPECTED_ALLOCATION_BYTES,
        "hold_equals_declared_region_size": True,
        "instrument_ok": True,
        "pool_exhausted": True,
        "controls_fired": True,
        "control_before_ok": 5,
        "under_hold_ok": 0,
        "control_after_ok": 5,
        "verdict": "HOLD_CONSUMES_POOL",
        "implied_physical_span": ["0xc2000000", "0xd6000000"],
    }


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


class ProbeParserTests(unittest.TestCase):
    def test_valid_fixed_receipt_is_reduced_to_a_candidate(self) -> None:
        parsed = analysis._parse_probe_records(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in _raw_rows()).encode()
        )
        reduced = analysis.reduce_measurements(parsed)
        self.assertTrue(reduced["controls_pass"])
        self.assertEqual(reduced["candidate_verdict"], "PA28_TIMING_CANDIDATE")
        self.assertEqual(reduced["pa28_candidate"]["separation_milli_ticks"], 340)

    def test_target_and_heap_drift_fail_closed(self) -> None:
        rows = _raw_rows()
        rows[0]["heap_id"] = 29
        with self.assertRaisesRegex(analysis.AnalysisError, "context"):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )
        rows = _raw_rows()
        rows[1]["heap_type"] = 4
        with self.assertRaisesRegex(analysis.AnalysisError, "heap identity"):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )

    def test_command_surface_and_pagemap_overclaim_fail_closed(self) -> None:
        rows = _raw_rows()
        rows[0]["pagemap"] = "RESOLVED"
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )
        rows = _raw_rows()
        rows[3]["name"] = "unexpected_control"
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )

    def test_property_and_candidate_errors_are_not_rewritten(self) -> None:
        rows = _raw_rows()
        rows[5]["difference"] = "0x10000001"
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )
        rows = _raw_rows()
        rows[4]["p90"] = -10
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )

    def test_missing_control_and_duplicate_record_fail_closed(self) -> None:
        rows = [row for row in _raw_rows() if row.get("name") != "negative_bank_bit14"]
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )

    def test_malformed_blank_and_duplicate_json_keys_fail_closed(self) -> None:
        valid = "".join(json.dumps(row, sort_keys=True) + "\n" for row in _raw_rows())
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records((valid + "\n").encode())
        first = json.dumps(_raw_rows()[0], sort_keys=True)
        duplicate = first[:-1] + ',"heap_id":30}'
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records((duplicate + "\n").encode())

    def test_overlapping_candidate_and_negative_controls_stay_unresolved(self) -> None:
        rows = _raw_rows()
        candidate = rows[5]
        candidate["p10"] = 50
        candidate["median"] = 60
        candidate["p90"] = 70
        parsed = analysis._parse_probe_records(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
        )
        reduced = analysis.reduce_measurements(parsed)
        self.assertFalse(reduced["controls_pass"])
        self.assertEqual(reduced["candidate_verdict"], "PA28_UNRESOLVED")
        rows = _raw_rows()
        rows.append(dict(rows[4]))
        with self.assertRaises(analysis.AnalysisError):
            analysis._parse_probe_records(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
            )


class DependencyTests(unittest.TestCase):
    def test_020m_target_and_property_errors_fail_closed(self) -> None:
        document = _precondition()
        document["target"]["model"] = "SM-S918N"
        with self.assertRaises(analysis.AnalysisError):
            analysis._validate_020m(document)
        document = _precondition()
        document["semantic"]["camera_mem_region"]["optional_properties"]["camera_reusable"]["errno"] = 0
        with self.assertRaises(analysis.AnalysisError):
            analysis._validate_020m(document)

    def test_021_successful_full_size_gate_is_required(self) -> None:
        document = _extent()
        self.assertEqual(analysis._validate_021(document)["hold_bytes"], analysis.EXPECTED_ALLOCATION_BYTES)
        document["pool_exhausted"] = False
        with self.assertRaises(analysis.AnalysisError):
            analysis._validate_021(document)


class ArtifactTests(unittest.TestCase):
    def test_analyze_binds_dependencies_source_and_raw_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.jsonl"
            pre = root / "pre.json"
            extent = root / "extent.json"
            _write_jsonl(raw, _raw_rows())
            pre.write_text(json.dumps(_precondition(), sort_keys=True) + "\n", encoding="utf-8")
            extent.write_text(json.dumps(_extent(), sort_keys=True) + "\n", encoding="utf-8")
            source = analysis.PROBE_SOURCE_PATH
            pins = {}
            for path in (pre, extent, source):
                data = path.read_bytes()
                pins[path] = {"basename": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            with mock.patch.multiple(
                analysis,
                EXPECTED_020M_MANIFEST=pins[pre],
                EXPECTED_021_MANIFEST=pins[extent],
                EXPECTED_PROBE_SOURCE_SIZE=pins[source]["size"],
                EXPECTED_PROBE_SOURCE_SHA256=pins[source]["sha256"],
            ):
                result = analysis.analyze(raw, pre, extent, source)
            self.assertEqual(result["status"], "PA28_TIMING_CANDIDATE")
            self.assertEqual(result["classification"], "CLASS C (TRANSFORM ONLY)")
            rendered = json.dumps(result, sort_keys=True)
            self.assertNotIn(str(root), rendered)
            self.assertEqual(result["probe"]["pagemap"], "NOT_USED")

    def test_dependency_hash_drift_and_output_no_clobber_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pre = root / "pre.json"
            extent = root / "extent.json"
            raw = root / "raw.jsonl"
            _write_jsonl(raw, _raw_rows())
            pre.write_text(json.dumps(_precondition(), sort_keys=True) + "\n", encoding="utf-8")
            extent.write_text(json.dumps(_extent(), sort_keys=True) + "\n", encoding="utf-8")
            pins = {}
            for path in (pre, extent):
                data = path.read_bytes()
                pins[path] = {"basename": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            source = analysis.PROBE_SOURCE_PATH
            source_data = source.read_bytes()
            with mock.patch.multiple(
                analysis,
                EXPECTED_020M_MANIFEST=pins[pre],
                EXPECTED_021_MANIFEST=pins[extent],
                EXPECTED_PROBE_SOURCE_SIZE=len(source_data),
                EXPECTED_PROBE_SOURCE_SHA256=hashlib.sha256(source_data).hexdigest(),
            ):
                extent.write_text(extent.read_text() + " ", encoding="utf-8")
                with self.assertRaisesRegex(analysis.AnalysisError, "021 manifest"):
                    analysis.analyze(raw, pre, extent, source)
            output = root / "manifest.json"
            analysis.write_new(output, b"x")
            with self.assertRaises(FileExistsError):
                analysis.write_new(output, b"y")

    def test_symlinked_input_component_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_bytes(b"x")
            link = root / "link"
            link.symlink_to(real)
            with self.assertRaises(analysis.AnalysisError):
                analysis.read_stable(link, "linked")

    def test_symlinked_output_and_existing_output_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_bytes(b"old")
            link = root / "link"
            link.symlink_to(real)
            with self.assertRaises(analysis.AnalysisError):
                analysis.write_new(link, b"new")
            output = root / "output"
            analysis.write_new(output, b"first", 0o644)
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                analysis.write_new(output, b"second")


class ProbeSourceTests(unittest.TestCase):
    def test_probe_is_fixed_and_has_no_pagemap_or_external_command_surface(self) -> None:
        source = analysis.PROBE_SOURCE_PATH.read_text(encoding="utf-8")
        self.assertIn("if (argc != 1)", source)
        self.assertNotIn("strtoull", source)
        self.assertNotIn("/proc/self/pagemap", source)
        self.assertNotIn("/dev/mem", source)
        self.assertNotIn("system(", source)
        self.assertIn('"/dev/ion"', source)
        self.assertIn("PA28_DIFFERENCE", source)
        self.assertIn("NEGATIVE_BANK13", source)
        self.assertIn("cache_maintenance", source)


if __name__ == "__main__":
    unittest.main()
