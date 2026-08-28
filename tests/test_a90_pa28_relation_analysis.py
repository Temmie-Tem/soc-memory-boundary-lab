"""Tests for the f(PA28) reduction.

The claim is that exactly one of seven candidate differences conflicts, and
that which one names f(PA28).  A single conflicting candidate is only meaningful
if the same-phase controls fired and if every measured pair really isolated the
bit its difference names, so both gates get negative controls, and the resolved
value is shown not to be hardcoded.
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

from tools import a90_pa28_relation_analysis as pa

RAW_DIR = REPO_ROOT / "evidence" / "private" / "verification-022-pa28-relation-20260827-01"
EXISTENCE = RAW_DIR / "pa28-existence.jsonl"
IDENTIFICATION = RAW_DIR / "pa28-identification.jsonl"
MANIFEST = (REPO_ROOT / "evidence" / "manifests"
            / "verification-022-pa28-relation-20260827-01.manifest.json")

CONFLICT_DELTA = 540
NEGATIVE_DELTA = 145


def _synthetic(winner: int | None, *, controls_fire: bool = True,
               break_isolation: bool = False, extra_winner: int | None = None) -> list[dict]:
    """Build a phase where `winner` (a candidate difference) conflicts."""
    records = [{"schema": pa.SCHEMA, "type": "context", "heap": "camera_preview",
                "mib": 320, "repetitions": 201, "pairs": 256, "cpu": 7, "warmups": 17,
                "order": "alternating", "barrier": "dsb_ld", "divisor": "kept_times_two",
                "offset_mode": "spread", "declared_base": "0xc2000000"},
               {"schema": pa.SCHEMA, "type": "pa_provenance", "source": "pagemap",
                "status": "BLIND"}]

    def emit(difference: int, delta: int, isolate: bool = True) -> None:
        for index in range(8):
            offset = 0x1000 * (index + 1)
            pa_a = pa.EXPECTED_BASE + offset
            pa_b = pa.EXPECTED_BASE + (offset ^ difference)
            records.append({
                "schema": pa.SCHEMA, "type": "pair", "value": hex(difference),
                "offset": hex(offset),
                "pa_a": hex(pa_a), "pa_b": hex(pa_b),
                "pa_xor": hex(difference) if isolate else hex(difference ^ 0x40),
                "delta": delta})
        records.append({"schema": pa.SCHEMA, "type": "difference",
                        "value": hex(difference), "pairs": 8, "rejected_range": 0,
                        "rejected_carry": 0, "p10": delta, "median": delta, "p90": delta})

    emit(pa.CONTROL_CONFLICT, CONFLICT_DELTA if controls_fire else NEGATIVE_DELTA)
    emit(pa.CONTROL_NEGATIVE, NEGATIVE_DELTA)
    for mask in range(8):
        difference = pa.PA28
        for bit, value in pa.BASIS.items():
            if mask & value:
                difference ^= bit
        hot = difference in (winner, extra_winner)
        emit(difference, CONFLICT_DELTA if hot else NEGATIVE_DELTA,
             isolate=not (break_isolation and difference == pa.PA28))
    return records


class Resolution(unittest.TestCase):
    def test_the_conflicting_candidate_names_f_pa28(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000))
        self.assertEqual(result["verdict"], "RESOLVED")
        self.assertEqual(result["f_pa28"], "010")

    def test_a_different_winner_resolves_differently(self) -> None:
        """The answer is read off the data, not baked in."""
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x8000))
        self.assertEqual(result["verdict"], "RESOLVED")
        self.assertEqual(result["f_pa28"], "100")

    def test_a_compound_winner_resolves_to_a_compound_vector(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x2000 ^ 0x8000))
        self.assertEqual(result["f_pa28"], "101")

    def test_no_conflicting_candidate_is_outside_the_space_not_resolved(self) -> None:
        result = pa.analyse(_synthetic(None))
        self.assertEqual(result["verdict"], "OUTSIDE_RANK_3_SPACE")
        self.assertIsNone(result["f_pa28"])

    def test_two_conflicting_candidates_are_ambiguous_not_resolved(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000, extra_winner=pa.PA28 ^ 0x8000))
        self.assertEqual(result["verdict"], "AMBIGUOUS_MULTIPLE_CONFLICTS")
        self.assertIsNone(result["f_pa28"])


class Gates(unittest.TestCase):
    def test_a_control_that_did_not_fire_blocks_resolution(self) -> None:
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000, controls_fire=False))
        self.assertEqual(result["verdict"], "INSTRUMENT_FAILED")
        self.assertIsNone(result["f_pa28"])

    def test_a_pair_that_did_not_isolate_its_bit_blocks_resolution(self) -> None:
        """A carried pair would be scored against a bit it does not name."""
        result = pa.analyse(_synthetic(pa.PA28 ^ 0x4000, break_isolation=True))
        self.assertFalse(result["pair_verification"]["all_pairs_isolate_their_difference"])
        self.assertEqual(result["verdict"], "INSTRUMENT_FAILED")

    def test_foreign_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.jsonl"
            p.write_text(json.dumps({"schema": "other", "type": "context"}) + "\n")
            with self.assertRaises(ValueError):
                pa.load(p)

    def test_symlinked_receipt_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.jsonl"
            real.write_text(json.dumps(_synthetic(pa.PA28 ^ 0x4000)[0]) + "\n")
            link = Path(tmp) / "link.jsonl"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                pa.load(link)

    def test_non_regular_receipt_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                pa.load(Path(tmp))

    def test_same_size_pa_xor_mutations_fail_closed(self) -> None:
        rows = _synthetic(pa.PA28 ^ 0x4000)
        pair = next(row for row in rows if row["type"] == "pair")
        pair["pa_a"] = hex(int(pair["pa_a"], 16) ^ 0x1000)
        self.assertFalse(pa.verify_pairs(rows)["all_pairs_isolate_their_difference"])


class ProbeSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (REPO_ROOT / "tools" / "a90_pa28_probe.c").read_text()

    def test_pointer_formation_follows_range_and_carry_gates(self) -> None:
        range_check = self.source.index("if (a > bytes - PAGE_BYTES")
        carry_check = self.source.index("if (base > UINT64_MAX - a")
        pointer_formation = self.source.index("const uint8_t *pa = map + a;")
        self.assertLess(range_check, pointer_formation)
        self.assertLess(carry_check, pointer_formation)
        self.assertEqual(self.source.count("const uint8_t *pa = map + a;"), 1)

    def test_probe_surface_is_fixed_and_ion_path_is_bounded(self) -> None:
        for snippet in (
            '#define EXPECTED_HEAP_NAME "camera_preview"',
            "#define EXPECTED_MIB UINT64_C(320)",
            "#define EXPECTED_REPETITIONS 201U",
            "#define EXPECTED_PAIRS 256U",
            "#define EXPECTED_CPU 7U",
            '#define EXPECTED_BASE UINT64_C(0xc2000000)',
            'strcmp(offset_mode, "spread") != 0',
            "static int safe_ion_path(const char *path)",
            'strcmp(path + sizeof(prefix) - 1U, "..") == 0',
            "O_NOFOLLOW",
            'selected->type != EXPECTED_HEAP_TYPE',
            'selected->heap_id != EXPECTED_HEAP_ID',
            'allocation.heap_id_mask = UINT32_C(1) << EXPECTED_HEAP_ID',
            "static int allowed_difference(uint64_t difference)",
        ):
            self.assertIn(snippet, self.source)

    def test_difference_list_is_bounded_before_device_open(self) -> None:
        allowlist = self.source.index("static int allowed_difference")
        validation = self.source.index("difference is outside the fixed 022 allowlist")
        device_open = self.source.index("ion_fd = open(ion_path")
        self.assertLess(allowlist, validation)
        self.assertLess(validation, device_open)


class CanonicalHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not (EXISTENCE.exists() and IDENTIFICATION.exists()):
            raise unittest.SkipTest("retained PA28 receipts are absent on this host")
        cls.existence, cls.existence_pin = pa.load(
            EXISTENCE, phase="existence", canonical=True
        )
        cls.identification, cls.identification_pin = pa.load(
            IDENTIFICATION, phase="identification", canonical=True
        )

    def test_canonical_phase_cardinality_and_target_controls_pass(self) -> None:
        pa.validate_phase_records(self.existence, "existence")
        pa.validate_phase_records(self.identification, "identification")
        self.assertEqual(self.existence_pin["size_bytes"], 194481)
        self.assertEqual(self.identification_pin["size_bytes"], 283197)

    def test_missing_candidate_or_control_phase_fails_closed(self) -> None:
        missing_candidate = [
            row for row in self.identification
            if not (row["type"] == "difference" and row["value"] == "0x10004000")
        ]
        with self.assertRaisesRegex(ValueError, "cardinality"):
            pa.validate_phase_records(missing_candidate, "identification")
        missing_control = [
            row for row in self.existence
            if not (row["type"] == "difference" and row["value"] == "0x2000")
        ]
        with self.assertRaisesRegex(ValueError, "cardinality"):
            pa.validate_phase_records(missing_control, "existence")

    def test_base_plus_offset_and_second_pointer_are_recomputed(self) -> None:
        rows = [dict(row) for row in self.existence]
        pair = next(row for row in rows if row["type"] == "pair")
        pair["pa_b"] = hex(int(pair["pa_b"], 16) ^ 0x1000)
        with self.assertRaisesRegex(ValueError, "pa_b"):
            pa.validate_phase_records(rows, "existence")
        rows = [dict(row) for row in self.existence]
        pair = next(row for row in rows if row["type"] == "pair")
        pair["offset"] = hex(int(pair["offset"], 16) ^ 0x1000)
        with self.assertRaisesRegex(ValueError, "pa_a"):
            pa.validate_phase_records(rows, "existence")
        rows = [dict(row) for row in self.existence]
        pair = next(row for row in rows if row["type"] == "pair")
        pair["offset"] = hex(pa.EXPECTED_ALLOCATION_BYTES)
        with self.assertRaisesRegex(ValueError, "outside allocation"):
            pa.validate_phase_records(rows, "existence")

    def test_canonical_raw_pin_and_dependency_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / EXISTENCE.name
            raw.write_bytes(EXISTENCE.read_bytes() + b" ")
            with self.assertRaises(ValueError):
                pa.load(raw, phase="existence", canonical=True)
            dep = root / pa.DEPENDENCY_020M_PATH.name
            dep.write_bytes(pa.DEPENDENCY_020M_PATH.read_bytes()[:-2] + b"  \n")
            with self.assertRaises(ValueError):
                pa.load_dependency(dep, pa.DEPENDENCY_020M_PIN, "020M")
            dep021 = root / pa.DEPENDENCY_021_PATH.name
            original021 = pa.DEPENDENCY_021_PATH.read_bytes()
            dep021.write_bytes(original021[:-1] + (b" " if original021[-1:] != b" " else b"\n"))
            with self.assertRaises(ValueError):
                pa.load_dependency(dep021, pa.DEPENDENCY_021_PIN, "021")

    def test_redacted_regeneration_keeps_provenance_unknown_and_model_supported(self) -> None:
        result = pa.build_public_manifest([EXISTENCE, IDENTIFICATION])
        self.assertEqual(result["result_disposition"], "SUPPORTED_MODEL_EXTENSION")
        self.assertEqual(result["claim_disposition"]["model_extension"], "SUPPORTED")
        self.assertEqual(result["claim_disposition"]["alias"], "UNKNOWN_NOT_TESTED")
        self.assertEqual(result["provenance"]["target"]["status"], "UNKNOWN_UNRETAINED")
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(REPO_ROOT / "evidence/private"), rendered)
        self.assertNotIn("payload_base64", rendered)

    def test_manifest_dependencies_include_exact_probe_provenance_pins(self) -> None:
        result = pa.build_public_manifest([EXISTENCE, IDENTIFICATION])
        self.assertEqual(
            result["inputs"]["probe_source"]["sha256"],
            pa.PROBE_SOURCE_PIN["sha256"],
        )
        self.assertEqual(
            result["inputs"]["probe_binary"]["status"], "NOT_RETAINED"
        )
        self.assertEqual(
            result["inputs"]["dependency_021"]["sha256"],
            pa.DEPENDENCY_021_PIN["sha256"],
        )
        self.assertEqual(
            result["inputs"]["dependency_020m"]["sha256"],
            pa.DEPENDENCY_020M_PIN["sha256"],
        )


class RetainedResult(unittest.TestCase):
    def setUp(self) -> None:
        if not (EXISTENCE.exists() and IDENTIFICATION.exists()):
            self.skipTest("retained PA28 receipts are absent on this host")
        merged = []
        for path in (EXISTENCE, IDENTIFICATION):
            records, _ = pa.load(path)
            merged.extend(records)
        self.result = pa.analyse(merged)

    def test_every_measured_pair_isolated_its_bit(self) -> None:
        verification = self.result["pair_verification"]
        self.assertEqual(verification["mismatched"], [])
        self.assertGreater(verification["pairs_checked"], 3000)

    def test_controls_fired(self) -> None:
        self.assertTrue(self.result["controls"]["controls_fired"])

    def test_exactly_one_candidate_conflicts(self) -> None:
        self.assertEqual(len(self.result["conflicting_candidates"]), 1)

    def test_the_split_is_not_marginal(self) -> None:
        """The gap that sets the threshold must dominate the next one."""
        split = self.result["phase_split"]
        self.assertGreater(split["gap"], 10 * split["runner_up_gap"])

    def test_f_pa28_is_f_pa14(self) -> None:
        self.assertEqual(self.result["verdict"], "RESOLVED")
        self.assertEqual(self.result["f_pa28"], "010")
        self.assertEqual(self.result["f_pa28_equals"], "f(PA14)")

    def test_pa28_alone_is_negative_as_the_resolved_value_requires(self) -> None:
        """f(2^28) = 010 is nonzero, so 2^28 on its own must not conflict."""
        self.assertNotIn(hex(pa.PA28), self.result["conflicting_candidates"])

    def test_pagemap_was_blind_so_the_base_came_from_the_device_tree(self) -> None:
        self.assertEqual(self.result["pagemap_status"], "BLIND")

    def test_manifest_matches_the_retained_receipts(self) -> None:
        if not MANIFEST.exists():
            self.skipTest("manifest absent")
        published = json.loads(MANIFEST.read_text())
        for key in ("verdict", "f_pa28", "f_pa28_equals", "conflicting_candidates"):
            self.assertEqual(published[key], self.result[key], key)


if __name__ == "__main__":
    unittest.main()
