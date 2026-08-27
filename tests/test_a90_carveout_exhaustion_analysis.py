"""Tests for the carveout-exhaustion reduction.

The load-bearing claim is that a 320 MiB allocation leaves nothing allocatable
in `camera_preview`, which is only admissible when both controls fire.  The
gate therefore gets negative controls in both directions: a missing control
must not be reported as exhaustion, and a genuine leftover must not be reported
as exhaustion either.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import a90_carveout_exhaustion_analysis as cx

RAW = (REPO_ROOT / "evidence" / "private"
       / "verification-021-carveout-exhaustion-20260827-01"
       / "carveout-exhaustion.jsonl")
MANIFEST = (REPO_ROOT / "evidence" / "manifests"
            / "verification-021-carveout-exhaustion-20260827-01.manifest.json")

SIZES = [16 << 20, 4 << 20, 1 << 20, 64 << 10, 4 << 10]


def _receipt(before: list[bool], under: list[bool], after: list[bool],
             hold_ok: bool = True, hold_bytes: int = 0x14000000) -> list[dict]:
    out = [{"schema": cx.SCHEMA, "type": "context", "heap": "camera_preview",
            "heap_type": 10, "heap_id": 30, "hold_mib": 320, "probe_count": len(SIZES)}]
    def phase(name, oks):
        for size, ok in zip(SIZES, oks):
            out.append({"schema": cx.SCHEMA, "type": "probe", "phase": name,
                        "bytes": size, "ok": ok, "errno": 0 if ok else 12,
                        "error": "" if ok else "Cannot allocate memory"})
    phase("control_before", before)
    out.append({"schema": cx.SCHEMA, "type": "hold", "bytes": hold_bytes,
                "ok": hold_ok, "errno": 0, "error": ""})
    phase("under_hold", under)
    phase("control_after", after)
    return out


ALL = [True] * len(SIZES)
NONE = [False] * len(SIZES)


class Gate(unittest.TestCase):
    def test_exhaustion_requires_both_controls(self) -> None:
        r = cx.analyse(_receipt(ALL, NONE, ALL))
        self.assertTrue(r["controls_fired"])
        self.assertEqual(r["verdict"], "HOLD_CONSUMES_POOL")
        self.assertTrue(r["pool_exhausted"])

    def test_missing_leading_control_is_instrument_failure(self) -> None:
        """Without it, an ENOMEM under hold could be any unrelated condition."""
        r = cx.analyse(_receipt([True, True, True, True, False], NONE, ALL))
        self.assertEqual(r["verdict"], "INSTRUMENT_FAILED")
        self.assertFalse(r["pool_exhausted"])
        self.assertIsNone(r["implied_physical_span"])

    def test_unrestored_trailing_control_is_instrument_failure(self) -> None:
        """If the pool never comes back, the hold was not what emptied it."""
        r = cx.analyse(_receipt(ALL, NONE, [True, True, False, True, True]))
        self.assertEqual(r["verdict"], "INSTRUMENT_FAILED")
        self.assertFalse(r["pool_exhausted"])

    def test_a_single_surviving_page_defeats_exhaustion(self) -> None:
        """One 4 KiB success means the hold did not take the whole pool."""
        r = cx.analyse(_receipt(ALL, [False, False, False, False, True], ALL))
        self.assertEqual(r["verdict"], "HOLD_LEAVES_ROOM")
        self.assertFalse(r["pool_exhausted"])
        self.assertIsNone(r["implied_physical_span"])

    def test_span_is_withheld_when_hold_size_differs_from_the_region(self) -> None:
        r = cx.analyse(_receipt(ALL, NONE, ALL, hold_bytes=256 << 20))
        self.assertTrue(r["pool_exhausted"])
        self.assertFalse(r["hold_equals_declared_region_size"])
        self.assertIsNone(r["implied_physical_span"])

    def test_failed_hold_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            cx.analyse(_receipt(ALL, NONE, ALL, hold_ok=False))


class Validation(unittest.TestCase):
    def test_foreign_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.jsonl"
            p.write_text(json.dumps({"schema": "other", "type": "context"}) + "\n")
            with self.assertRaises(ValueError):
                cx.load_records(p)

    def test_symlinked_receipt_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.jsonl"
            real.write_text(json.dumps(_receipt(ALL, NONE, ALL)[0]) + "\n")
            link = Path(tmp) / "link.jsonl"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                cx.load_records(link)

    def test_mismatched_probe_sets_are_rejected(self) -> None:
        records = _receipt(ALL, NONE, ALL)
        for r in records:
            if r["type"] == "probe" and r["phase"] == "under_hold" and r["bytes"] == 4 << 10:
                r["bytes"] = 8 << 10
        with self.assertRaises(ValueError):
            cx.analyse(records)

    def test_missing_phase_is_rejected(self) -> None:
        records = [r for r in _receipt(ALL, NONE, ALL)
                   if not (r["type"] == "probe" and r["phase"] == "control_after")]
        with self.assertRaises(ValueError):
            cx.analyse(records)


class RetainedResult(unittest.TestCase):
    def setUp(self) -> None:
        if not RAW.exists():
            self.skipTest("retained carveout-exhaustion receipt is absent on this host")

    def test_retained_receipt_reports_exhaustion_with_controls(self) -> None:
        records, _ = cx.load_records(RAW)
        r = cx.analyse(records)
        self.assertTrue(r["controls_fired"])
        self.assertEqual(r["under_hold_ok"], 0)
        self.assertEqual(r["verdict"], "HOLD_CONSUMES_POOL")

    def test_not_even_one_page_survived(self) -> None:
        records, _ = cx.load_records(RAW)
        r = cx.analyse(records)
        self.assertEqual(r["smallest_probe_bytes"], 4096)

    def test_implied_span_matches_the_device_tree_region(self) -> None:
        records, _ = cx.load_records(RAW)
        r = cx.analyse(records)
        self.assertEqual(r["implied_physical_span"], ["0xc2000000", "0xd6000000"])

    def test_span_holds_a_single_bit_28_pair_across_its_whole_window(self) -> None:
        """The reason this experiment was run at all."""
        records, _ = cx.load_records(RAW)
        r = cx.analyse(records)
        lo, hi = (int(v, 16) for v in r["implied_physical_span"])
        for x in (lo, lo + (1 << 24), hi - (1 << 28) - 0x1000):
            self.assertLess(x, hi - (1 << 28) + 1)
            self.assertEqual(x ^ (x + (1 << 28)), 1 << 28)

    def test_manifest_matches_the_retained_receipt(self) -> None:
        if not MANIFEST.exists():
            self.skipTest("manifest absent")
        published = json.loads(MANIFEST.read_text())
        records, _ = cx.load_records(RAW)
        recomputed = cx.analyse(records)
        for key in ("verdict", "pool_exhausted", "controls_fired",
                    "under_hold_ok", "implied_physical_span"):
            self.assertEqual(published[key], recomputed[key], key)


if __name__ == "__main__":
    unittest.main()
