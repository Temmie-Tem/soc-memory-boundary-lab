"""Tests for the ION heap-capacity ladder reduction.

The load-bearing claims are that no non-secure heap reaches the 512 MiB reopen
threshold, and that `camera_preview`'s ceiling is 320 MiB rather than the 256
MiB asserted without evidence in `docs/REMAINING_ROUTES_2026-08-27.md`.  Both
are only admissible if the ladder is monotone, so the monotonicity gate gets a
negative control.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import a90_heap_capacity_analysis as cap

RAW_DIR = REPO_ROOT / "evidence" / "private" / "verification-020-heap-capacity-20260827-01"
FINE = RAW_DIR / "heap-capacity-fine.jsonl"
MANIFEST = REPO_ROOT / "evidence" / "manifests" / "verification-020-heap-capacity-20260827-01.manifest.json"


def _ladder(name: str, rungs: list[tuple[int, bool]], heap_type: int = 10) -> list[dict]:
    records = [{"schema": cap.SCHEMA, "type": "heap", "name": name,
                "heap_type": heap_type, "heap_id": 30, "attempted": True}]
    for mib, ok in rungs:
        records.append({"schema": cap.SCHEMA, "type": "attempt", "name": name,
                        "mib": mib, "ok": ok, "errno": 0 if ok else 12})
    return records


class MaxXorBit(unittest.TestCase):
    def test_bit_needs_span_strictly_greater_than_two_to_the_k(self) -> None:
        """A span of exactly 2**k cannot hold a pair differing in bit k."""
        self.assertEqual(cap.max_xor_bit(1 << 28), 27)
        self.assertEqual(cap.max_xor_bit((1 << 28) + 1), 28)

    def test_320_mib_admits_bit_28_and_not_bit_29(self) -> None:
        self.assertEqual(cap.max_xor_bit(320 * cap.MIB), 28)
        self.assertLess(320 * cap.MIB, 1 << 29)

    def test_256_mib_stops_one_bit_short_of_28(self) -> None:
        """The number the unbacked prose asserted would not have reached PA28."""
        self.assertEqual(cap.max_xor_bit(256 * cap.MIB), 27)

    def test_degenerate_spans(self) -> None:
        self.assertIsNone(cap.max_xor_bit(0))
        self.assertIsNone(cap.max_xor_bit(1))


class MonotonicityGate(unittest.TestCase):
    def test_monotone_ladder_yields_a_ceiling(self) -> None:
        result = cap.analyse(_ladder("h", [(512, False), (384, False), (320, True), (256, True)]))
        self.assertTrue(result["instrument_ok"])
        self.assertEqual(result["heaps"]["h"]["ceiling_mib"], 320)
        self.assertEqual(result["heaps"]["h"]["ceiling_bracket_mib"], [320, 384])

    def test_non_monotone_ladder_refuses_a_ceiling(self) -> None:
        """A success above a failure is memory pressure, not a capacity bound."""
        result = cap.analyse(_ladder("h", [(512, True), (384, False), (256, True)]))
        self.assertFalse(result["instrument_ok"])
        self.assertFalse(result["heaps"]["h"]["monotone"])
        self.assertIsNone(result["heaps"]["h"]["ceiling_mib"])
        self.assertEqual(result["reopen_condition_2"], "INSTRUMENT_FAILED")

    def test_non_monotone_cannot_report_condition_met(self) -> None:
        """The 512 MiB success must not flip the condition while the gate is down."""
        result = cap.analyse(_ladder("h", [(512, True), (384, False), (256, True)]))
        self.assertNotEqual(result["reopen_condition_2"], "MET")
        self.assertFalse(result["heaps"]["h"]["meets_reopen_condition_2"])

    def test_a_genuine_512_success_would_flip_the_condition(self) -> None:
        """The negative result is not hardcoded."""
        result = cap.analyse(_ladder("h", [(512, True), (384, True), (256, True)]))
        self.assertTrue(result["instrument_ok"])
        self.assertEqual(result["reopen_condition_2"], "MET")
        self.assertEqual(result["max_xor_bit_upper_bound"], 28)


class RecordValidation(unittest.TestCase):
    def test_foreign_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.jsonl"
            p.write_text(json.dumps({"schema": "something_else", "type": "heap"}) + "\n")
            with self.assertRaises(ValueError):
                cap.load_records(p)

    def test_duplicate_heap_record_is_rejected(self) -> None:
        records = _ladder("h", [(256, True)]) + _ladder("h", [(256, True)])
        with self.assertRaises(ValueError):
            cap.analyse(records)

    def test_attempt_on_a_withheld_heap_is_rejected(self) -> None:
        records = [{"schema": cap.SCHEMA, "type": "heap", "name": "secure_heap",
                    "heap_type": 7, "heap_id": 9, "attempted": False},
                   {"schema": cap.SCHEMA, "type": "attempt", "name": "secure_heap",
                    "mib": 256, "ok": True, "errno": 0}]
        with self.assertRaises(ValueError):
            cap.analyse(records)

    def test_symlinked_receipt_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.jsonl"
            real.write_text(json.dumps(_ladder("h", [(256, True)])[0]) + "\n")
            link = Path(tmp) / "link.jsonl"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                cap.load_records(link)

    def test_load_records_with_pin_reports_exact_receipt_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "receipt.jsonl"
            p.write_text(json.dumps(_ladder("h", [(256, True)])[0]) + "\n")
            records, pin = cap.load_records_with_pin(p)
            self.assertEqual(len(records), 1)
            self.assertEqual(pin["filename"], p.name)
            self.assertEqual(pin["size"], p.stat().st_size)
            self.assertEqual(pin["sha256"], hashlib.sha256(p.read_bytes()).hexdigest())

    def test_probe_source_pin_fails_closed_on_expected_hash_drift(self) -> None:
        original = cap.PROBE_SOURCE_SHA256
        cap.PROBE_SOURCE_SHA256 = "0" * 64
        try:
            with self.assertRaises(ValueError):
                cap.probe_provenance()
        finally:
            cap.PROBE_SOURCE_SHA256 = original


class RetainedResult(unittest.TestCase):
    def setUp(self) -> None:
        if not FINE.exists():
            self.skipTest("retained heap-capacity receipt is absent on this host")

    def test_retained_ladder_is_monotone(self) -> None:
        result = cap.analyse(cap.load_records(FINE))
        self.assertTrue(result["instrument_ok"])

    def test_camera_preview_ceiling_is_320_not_256(self) -> None:
        result = cap.analyse(cap.load_records(FINE))
        self.assertEqual(result["heaps"]["camera_preview"]["ceiling_mib"], 320)

    def test_no_non_secure_heap_meets_the_reopen_threshold(self) -> None:
        result = cap.analyse(cap.load_records(FINE))
        self.assertEqual(result["reopen_condition_2"], "NOT_MET")
        for name, entry in result["heaps"].items():
            if entry["attempted"]:
                self.assertFalse(entry["meets_reopen_condition_2"], name)

    def test_secure_heaps_were_enumerated_but_never_allocated_from(self) -> None:
        result = cap.analyse(cap.load_records(FINE))
        for name in ("secure_heap", "secure_display", "secure_carveout",
                     "spss", "qsecom_ta", "adsp"):
            self.assertFalse(result["heaps"][name]["attempted"], name)
            self.assertIsNone(result["heaps"][name]["ceiling_mib"], name)

    def test_system_heap_is_withheld_as_page_based_not_as_secure(self) -> None:
        result = cap.analyse(cap.load_records(FINE))
        entry = result["heaps"]["system"]
        self.assertFalse(entry["attempted"])
        self.assertIn("page-based", entry["reason_not_attempted"])
        self.assertFalse(entry["contiguity_possible"])

    def test_manifest_matches_the_retained_receipt(self) -> None:
        if not MANIFEST.exists():
            self.skipTest("manifest absent")
        published = json.loads(MANIFEST.read_text())
        recomputed = cap.analyse(cap.load_records(FINE))
        for key in ("reopen_condition_2", "largest_non_secure_ceiling_mib",
                    "max_xor_bit_upper_bound", "instrument_ok"):
            self.assertEqual(published[key], recomputed[key], key)

    def test_manifest_pins_receipts_and_probe_provenance(self) -> None:
        if not MANIFEST.exists():
            self.skipTest("manifest absent")
        published = json.loads(MANIFEST.read_text())
        inputs = published["inputs"]
        self.assertEqual(
            {item["filename"] for item in inputs["raw_ladders"]},
            {"heap-capacity-coarse.jsonl", "heap-capacity-fine.jsonl"},
        )
        self.assertEqual(inputs["probe"]["source"]["sha256"], cap.PROBE_SOURCE_SHA256)
        self.assertFalse(inputs["probe"]["executed_binary"]["retained"])
        self.assertEqual(inputs["probe"]["executed_binary"]["sha256"], cap.EXECUTED_PROBE["sha256"])


if __name__ == "__main__":
    unittest.main()
