"""Focused tests for the repaired Verification-016 host-only analysis."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import a90_high_bit_relation_analysis as high


def context(*, pairs: int = 2, mib: int = 1) -> dict:
    return {
        "schema": high.PROBE_SCHEMA,
        "type": "context",
        "cpu": 7,
        "cntfrq": 19_200_000,
        "heap": "camera_preview",
        "mib": mib,
        "repetitions": 201,
        "pairs": pairs,
        "warmups": 17,
        "order": "alternating",
        "barrier": "dsb_ld",
        "divisor": "kept_times_two",
        "offset_mode": "spread",
    }


def section_text(
    medians: dict[int, tuple[int, ...]],
    *,
    ctx: dict | None = None,
    heap_id: int = 30,
    pa_status: str = "BLIND",
) -> str:
    """Render a small valid section, including the C qsort-index statistics."""

    ctx = dict(ctx or context())
    rows: list[dict] = [ctx]
    rows.append(
        {
            "schema": high.PROBE_SCHEMA,
            "type": "ion_heap",
            "name": "camera_preview",
            "heap_type": 10,
            "heap_id": heap_id,
        }
    )
    rows.append(
        {
            "schema": high.PROBE_SCHEMA,
            "type": "pa_provenance",
            "source": "pagemap",
            "pages": 1,
            "present": 0,
            "nonzero_pfn": 0,
            "first_pfn": "0x0",
            "last_pfn": "0x0",
            "contiguous": True,
            "status": pa_status,
        }
    )
    pairs = int(ctx["pairs"])
    for difference, values in medians.items():
        if len(values) != pairs:
            raise AssertionError("test transcript values must match context pairs")
        for index, delta in enumerate(values):
            rows.append(
                {
                    "schema": high.PROBE_SCHEMA,
                    "type": "pair",
                    "value": f"0x{difference:x}",
                    "offset": f"0x{index * 0x1000:x}",
                    "delta": delta,
                }
            )
        ordered = sorted(values)
        tenth = len(ordered) // 10
        rows.append(
            {
                "schema": high.PROBE_SCHEMA,
                "type": "difference",
                "value": f"0x{difference:x}",
                "pairs": pairs,
                "p10": ordered[tenth],
                "median": ordered[len(ordered) // 2],
                "p90": ordered[len(ordered) - 1 - tenth],
            }
        )
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"


class ParserTests(unittest.TestCase):
    def test_sections_are_retained_when_keys_overlap(self):
        first = section_text({high.KERNEL_REFERENCE: (10, 20)})
        second = section_text({high.KERNEL_REFERENCE: (30, 40)})
        parsed = high.parse_probe_transcript(first + second)
        self.assertEqual(len(parsed["sections"]), 2)
        self.assertEqual(parsed["sections"][0]["medians"], {high.KERNEL_REFERENCE: 20})
        self.assertEqual(parsed["sections"][1]["medians"], {high.KERNEL_REFERENCE: 40})
        with self.assertRaises(high.HighBitError):
            high.load_medians(first + second)

    def test_blind_contiguity_is_reported_but_not_promoted(self):
        parsed = high.parse_probe_transcript(section_text({1: (10, 20)}))
        record = parsed["pa_provenance"]
        self.assertNotIn("contiguous", record)
        self.assertTrue(record["reported_contiguous"])
        self.assertEqual(record["effective_contiguity"], "UNKNOWN")
        self.assertNotIn("contiguous", parsed["sections"][0]["pa_records"][0])

    def test_pair_after_summary_is_rejected(self):
        rows = json.loads("[" + ",".join(section_text({1: (10, 20)}).splitlines()) + "]")
        rows.insert(
            -1,
            {
                "schema": high.PROBE_SCHEMA,
                "type": "pair",
                "value": "0x1",
                "offset": "0x8000",
                "delta": 10,
            },
        )
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(json.dumps(row) for row in rows))

    def test_qsort_statistics_and_pair_counts_are_checked(self):
        rows = section_text({1: (10, 20)}).splitlines()
        rows[-1] = rows[-1].replace('"p90": 20', '"p90": 21')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

        rows = section_text({1: (10, 20)}).splitlines()
        rows[-1] = rows[-1].replace('"pairs": 2', '"pairs": 1')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

    def test_offsets_are_unique_bounded_and_require_metadata_first(self):
        rows = section_text({1: (10, 20)}).splitlines()
        rows[4] = rows[4].replace('"offset": "0x1000"', '"offset": "0x0"')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

    def test_pair_page_contract_rejects_zero_non_aligned_and_page_end_values(self):
        rows = section_text({1: (10, 20)}).splitlines()
        rows[3] = rows[3].replace('"value": "0x1"', '"value": "0x0"')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

        rows = section_text({1: (10, 20)}).splitlines()
        rows[3] = rows[3].replace('"offset": "0x0"', '"offset": "0x1"')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

        rows = section_text({1: (10, 20)}, ctx=context(pairs=2, mib=1)).splitlines()
        rows[3] = rows[3].replace('"offset": "0x0"', '"offset": "0x100000"')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

        rows = section_text({1: (10, 20)}, ctx=context(pairs=2, mib=1)).splitlines()
        rows[3] = rows[3].replace('"offset": "0x0"', '"offset": "0xff000"')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

        rows = section_text({1: (10, 20)}).splitlines()
        rows[-1] = rows[-1].replace('"value": "0x1"', '"value": "0x0"')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

        rows = section_text({1: (10, 20)}).splitlines()
        rows[3] = rows[3].replace('"offset": "0x0"', '"offset": "0x100000"')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

        rows = section_text({1: (10, 20)}).splitlines()
        heap = rows.pop(1)
        rows.insert(4, heap)
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript("\n".join(rows))

    def test_invalid_json_and_nonblind_pa_are_rejected(self):
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript('{"type":"context"}\nnot-json\n')
        with self.assertRaises(high.HighBitError):
            high.parse_probe_transcript(section_text({1: (10, 20)}, pa_status="RESOLVED"))

    def test_nonfinite_json_constants_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(high.HighBitError):
                high.parse_probe_transcript(constant + "\n")

    def test_discrimination_phase_reordering_is_rejected_by_expected_key_mapping(self):
        parsed = high.parse_probe_file(
            high.PRIVATE_ROOT / "pa25-27-discriminate.jsonl"
        )
        swapped = copy.deepcopy(list(reversed(parsed["sections"])))
        with self.assertRaises(high.HighBitError):
            for bit, section in zip(high.HIGH_BITS, swapped):
                expected = {high.KERNEL_REFERENCE, high.NEGATIVE_REFERENCE}
                expected.update((1 << bit) ^ (1 << lower) for lower in high.LOWER_BITS)
                high._validate_difference_shape(section, expected, f"bit{bit}")


class ArithmeticTests(unittest.TestCase):
    def test_reference_control_assertion_is_explicit_and_rejects_flip(self):
        split = {"threshold": 50}
        self.assertEqual(
            high.assert_reference_labels(
                {high.KERNEL_REFERENCE: 100, high.NEGATIVE_REFERENCE: 10},
                split,
                "synthetic",
            ),
            {"0x16000": "CONFLICT", "0x2000": "NEGATIVE"},
        )
        with self.assertRaises(high.HighBitError):
            high.assert_reference_labels(
                {high.KERNEL_REFERENCE: 10, high.NEGATIVE_REFERENCE: 100},
                split,
                "synthetic",
            )

    def test_widest_gap_split_is_deterministic(self):
        split = high.separation({1: 192, 2: 487, 3: 170})
        self.assertEqual(split["threshold"], 339)
        self.assertEqual(split["gap"], 295)
        self.assertEqual(split["runner_up_gap"], 22)
        self.assertEqual(split["band_low"], 192)
        self.assertEqual(split["band_high"], 487)

    def test_three_column_passes_require_equal_keys_and_use_floor_mean(self):
        first = {"medians": {1: 5, 2: 8}}
        second = {"medians": {1: 6, 2: 7}}
        combined, dispersion = high.combine_three_column_passes([first, second])
        self.assertEqual(combined, {1: 5, 2: 7})
        self.assertEqual(dispersion[1]["values"], [5, 6])
        self.assertEqual(dispersion[1]["mean"], 5.5)
        self.assertEqual(dispersion[2]["spread"], 1)
        with self.assertRaises(high.HighBitError):
            high.combine_three_column_passes([first, {"medians": {1: 6, 3: 7}}])

    def test_selector_and_cancellation_directions_are_distinct(self):
        self.assertEqual(
            high.direction(152, 133, 206, 358, 527), "SELECTOR"
        )
        self.assertEqual(
            high.direction(131, 148, 510, 358, 527),
            "SELECTOR_CANCELS_NEGATIVE_WITNESS",
        )
        self.assertEqual(high.direction(717, 702, 702, 500, 527), "SATURATING")

    def test_three_column_verdict_gate_rejects_hidden_pass_disagreement(self):
        good = [[
            {"bit": 25, "verdict": "SELECTOR"},
            {"bit": 26, "verdict": "SELECTOR"},
            {"bit": 27, "verdict": "SELECTOR_CANCELS_NEGATIVE_WITNESS"},
        ]] * 2
        combined = list(good[0])
        result = high.assert_three_column_verdict_consistency(good, combined)
        self.assertTrue(result["all_consistent"])
        self.assertEqual(result["by_bit"]["25"]["pass_verdicts"], ["SELECTOR", "SELECTOR"])
        bad = [list(good[0]), list(good[1])]
        bad[1][0] = {"bit": 25, "verdict": "SATURATING"}
        with self.assertRaises(high.HighBitError):
            high.assert_three_column_verdict_consistency(bad, combined)


@unittest.skipUnless(high.PRIVATE_ROOT.exists(), "canonical V016 inputs unavailable")
class CanonicalIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = high.analyse_canonical()
        cls.encoded = high.encode_manifest(cls.manifest)

    def test_exact_input_pins_and_dependency_semantics(self):
        self.assertEqual(
            {item["basename"]: (item["size_bytes"], item["sha256"])
             for item in self.manifest["inputs"]["raw"]},
            {name: high.RAW_PINS[name] for name in high.RAW_BASENAMES},
        )
        self.assertEqual(
            self.manifest["inputs"]["probe_source"]["sha256"],
            high.PROBE_SOURCE_SHA256,
        )
        self.assertEqual(
            self.manifest["inputs"]["dependency_manifest"]["sha256"],
            high.DEPENDENCY_MANIFEST_SHA256,
        )
        self.assertEqual(
            self.manifest["inputs"]["v015_helper"]["sha256"],
            high.V015_HELPER_SHA256,
        )
        semantics = self.manifest["dependency_cross_check"]
        self.assertEqual(semantics["rank"], 3)
        self.assertEqual(semantics["new_bit"], 24)
        self.assertEqual(semantics["new_bit_contribution"], "0b110")
        self.assertEqual(semantics["kernel_span_dimension"], 9)
        self.assertEqual(semantics["kernel_consistent_count"], 1)
        self.assertTrue(all(
            row["pairwise_equalities"][0]["present_in_023R_kernel_or_differences"]
            for row in semantics["lower_kernel_equalities"]
            if row["pairwise_equalities"]
        ))

    def test_phase_splits_and_discrimination_matches_are_pinned(self):
        expected = {
            "bit25": (339, 295, 22, 192, 487, 3),
            "bit26": (325, 273, 75, 189, 462, 2),
            "bit27": (355, 302, 25, 204, 506, 3),
        }
        for name, values in expected.items():
            split = self.manifest["phase_results"][name]["separation"]
            self.assertEqual(
                tuple(split[key] for key in (
                    "threshold", "gap", "runner_up_gap", "band_low",
                    "band_high", "conflict_count"
                )),
                values,
            )
        self.assertEqual(self.manifest["matches"], {
            "PA25": [14, 21], "PA26": [19], "PA27": [13, 20]
        })
        self.assertEqual(
            [item["equal_contribution_bits"] for item in self.manifest["discrimination"]],
            [[14, 21], [19], [13, 20]],
        )

    def test_three_column_mean_dispersion_triplets_and_heldout_are_pinned(self):
        result = self.manifest["three_column"]
        self.assertEqual(result["pass_count"], 2)
        self.assertEqual(result["difference_count"], 14)
        self.assertEqual(
            tuple(result["separation"][key] for key in (
                "threshold", "gap", "runner_up_gap", "band_low",
                "band_high", "conflict_count"
            )),
            (358, 304, 136, 206, 510, 2),
        )
        self.assertEqual(
            [(item["bit"], item["alone"], item["with_conflict"],
              item["with_negative"], item["verdict"])
             for item in result["triplets"]],
            [
                (25, 152, 133, 206, "SELECTOR"),
                (26, 150, 141, 136, "SELECTOR"),
                (27, 131, 148, 510, "SELECTOR_CANCELS_NEGATIVE_WITNESS"),
            ],
        )
        self.assertEqual(
            [[(item["bit"], item["alone"], item["with_conflict"],
               item["with_negative"], item["verdict"])
              for item in passed["triplets"]]
             for passed in result["passes"]],
            [
                [
                    (25, 186, 161, 226, "SELECTOR"),
                    (26, 161, 161, 149, "SELECTOR"),
                    (27, 145, 158, 527, "SELECTOR_CANCELS_NEGATIVE_WITNESS"),
                ],
                [
                    (25, 118, 105, 186, "SELECTOR"),
                    (26, 139, 121, 124, "SELECTOR"),
                    (27, 118, 139, 493, "SELECTOR_CANCELS_NEGATIVE_WITNESS"),
                ],
            ],
        )
        consistency = result["verdict_consistency"]
        self.assertTrue(consistency["all_consistent"])
        for bit in ("25", "26", "27"):
            self.assertEqual(
                len(set(consistency["by_bit"][bit]["pass_verdicts"] +
                        [consistency["by_bit"][bit]["combined_verdict"]])),
                1,
            )
        self.assertEqual(self.manifest["heldout"]["predictions"]["agreements"], 7)
        self.assertEqual(self.manifest["heldout"]["predictions"]["total"], 7)
        self.assertTrue(self.manifest["heldout"]["predictions"]["all_agree"])
        self.assertEqual(
            self.manifest["heldout"]["agreement_scope"],
            "OUT_OF_SAMPLE_MODEL_DERIVED_AGREEMENT",
        )
        self.assertEqual(
            self.manifest["heldout"]["preregistration_status"],
            "UNKNOWN_UNRETAINED",
        )
        self.assertEqual(
            self.manifest["heldout"]["acquisition_order_timestamp_status"],
            "UNKNOWN_UNRETAINED",
        )
        self.assertEqual(
            [row["expected"] for row in self.manifest["heldout"]["predictions"]["checked"]],
            ["CONFLICT", "CONFLICT", "CONFLICT", "CONFLICT",
             "NEGATIVE", "NEGATIVE", "NEGATIVE"],
        )

    def test_only_two_references_and_no_cross_phase_merge(self):
        self.assertEqual(self.manifest["raw_structure"]["reference_count"], 2)
        self.assertEqual(
            self.manifest["raw_structure"]["unique_reference_differences_per_section"],
            ["0x16000", "0x2000"],
        )
        for phase in self.manifest["phase_results"].values():
            self.assertEqual(
                phase["reference_labels"],
                {"0x16000": "CONFLICT", "0x2000": "NEGATIVE"},
            )
        self.assertEqual(
            self.manifest["heldout"]["reference_labels"],
            {"0x16000": "CONFLICT", "0x2000": "NEGATIVE"},
        )
        for passed in self.manifest["three_column"]["passes"]:
            self.assertEqual(
                passed["reference_labels"],
                {"0x16000": "CONFLICT", "0x2000": "NEGATIVE"},
            )
        self.assertEqual(
            self.manifest["three_column"]["reference_labels"],
            {"0x16000": "CONFLICT", "0x2000": "NEGATIVE"},
        )
        discr = high.parse_probe_file(high.PRIVATE_ROOT / "pa25-27-discriminate.jsonl")
        self.assertEqual(len(discr["sections"]), 3)
        self.assertNotEqual(
            discr["sections"][0]["medians"][high.KERNEL_REFERENCE],
            discr["sections"][1]["medians"][high.KERNEL_REFERENCE],
        )

    def test_model_scope_does_not_promote_physical_or_device_claims(self):
        self.assertEqual(self.manifest["coordinate_scope"], high.PUBLIC_COORDINATE_SCOPE)
        self.assertEqual(self.manifest["class_c"], "TRANSFORM ONLY")
        self.assertEqual(self.manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(
            self.manifest["dispositions"]["numbered_experiments_015_and_016"],
            "NOT_ELIGIBLE",
        )
        self.assertEqual(
            self.manifest["dispositions"]["verification_017"],
            "UNBLOCKED_FOR_SEPARATE_AUDIT_NOT_PROMOTED",
        )
        physical = self.manifest["physical_provenance"]
        self.assertEqual(physical["pagemap_status"], "BLIND")
        self.assertEqual(physical["effective_contiguity"], "UNKNOWN")
        self.assertEqual(physical["physical_pa_mapping"], "UNKNOWN")
        self.assertEqual(physical["allocation_base"], "UNKNOWN")
        self.assertEqual(physical["allocation_alignment"], "UNKNOWN")
        self.assertNotIn("contiguous", self.manifest["acquisition_context"]["pa_provenance"])
        self.assertTrue(self.manifest["acquisition_context"]["pa_provenance"]["reported_contiguous"])
        self.assertEqual(
            self.manifest["acquisition_context"]["pa_provenance"]["effective_contiguity"],
            "UNKNOWN",
        )
        self.assertEqual(
            self.manifest["provenance_identity"]["target"]["status"],
            "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
        )
        self.assertEqual(
            self.manifest["provenance_identity"]["historical_action"]["status"],
            "UNKNOWN_INCOMPLETE_RECEIPT",
        )
        self.assertEqual(
            self.manifest["historical_17_of_17"]["retained_evidence_status"],
            "REFUTED_AS_RETAINED_EVIDENCE",
        )
        self.assertEqual(
            self.manifest["historical_17_of_17"]["separate_unretained_run_occurrence"],
            "UNKNOWN",
        )
        refuted = " ".join(self.manifest["claims"]["REFUTED"])
        self.assertIn("REFUTED_AS_RETAINED_EVIDENCE", refuted)
        self.assertNotIn("came from cross-phase filename-order mixing", refuted)
        self.assertEqual(
            self.manifest["input_identity_scope"]["filesystem_inode_provenance"],
            "UNKNOWN_NOT_CLAIMED",
        )

    def test_manifest_is_deterministic_and_public_safe(self):
        self.assertEqual(self.encoded, high.encode_manifest(high.analyse_canonical()))
        rendered = self.encoded.decode("utf-8")
        self.assertNotIn("evidence/private/verification-016", rendered)
        self.assertNotIn("/home/", rendered)
        self.assertFalse(self.manifest["public_private_separation"]["raw_transcript_bytes_in_manifest"])
        with self.assertRaises(high.HighBitError):
            high.encode_manifest({"unsafe": "/home/temmie/private.json"})

    def test_hash_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_copy = Path(directory) / "raw"
            raw_copy.mkdir()
            for name in high.RAW_BASENAMES:
                source = high.PRIVATE_ROOT / name
                (raw_copy / name).write_bytes(source.read_bytes())
            path = raw_copy / high.RAW_BASENAMES[0]
            path.write_bytes(path.read_bytes() + b"drift")
            with self.assertRaises(high.HighBitError):
                high.analyse_canonical(raw_copy)

            dependency = Path(directory) / "dependency.json"
            dependency.write_bytes(high.DEPENDENCY_MANIFEST_PATH.read_bytes() + b"\n")
            with self.assertRaises(high.HighBitError):
                high.analyse_canonical(
                    high.PRIVATE_ROOT,
                    dependency_manifest_path=dependency,
                )

    def test_canonical_raw_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_copy = Path(directory) / "raw"
            raw_copy.mkdir()
            for name in high.RAW_BASENAMES:
                shutil.copyfile(
                    high.PRIVATE_ROOT / name,
                    raw_copy / name,
                )
            path = raw_copy / high.RAW_BASENAMES[0]
            path.unlink()
            path.symlink_to(high.PRIVATE_ROOT / high.RAW_BASENAMES[0])
            with self.assertRaises(high.HighBitError):
                high.analyse_canonical(raw_copy)

    def test_no_clobber_atomic_publication_and_fresh_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            publication = high.write_manifest(output, self.manifest)
            self.assertEqual(publication["observed_mode"], "0644")
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            self.assertEqual(output.read_bytes(), self.encoded)
            with self.assertRaises(high.HighBitError):
                high.write_manifest(output, self.manifest)
            link = Path(directory) / "link.json"
            link.symlink_to(output)
            with self.assertRaises(high.HighBitError):
                high.write_manifest(link, self.manifest)


if __name__ == "__main__":
    unittest.main()
