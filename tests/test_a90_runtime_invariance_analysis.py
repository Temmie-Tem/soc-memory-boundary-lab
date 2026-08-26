"""Focused tests for the repaired Verification-015 host-side integration."""

from __future__ import annotations

import json
import os
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import a90_runtime_invariance_analysis as inv


def context(*, pairs: int = 1, cpu: int = 7) -> dict:
    return {
        "schema": inv.PROBE_SCHEMA,
        "type": "context",
        "cpu": cpu,
        "cntfrq": 19_200_000,
        "heap": "qsecom",
        "mib": 1,
        "repetitions": 3,
        "pairs": pairs,
        "warmups": 1,
        "order": "alternating",
        "barrier": "dsb_ld",
        "divisor": "kept_times_two",
        "offset_mode": "spread",
    }


def strict_transcript(medians: dict[int, int], *, ctx: dict | None = None) -> str:
    """Build a complete small probe section accepted by the strict parser."""

    ctx = dict(ctx or context())
    rows = [ctx]
    rows.append(
        {
            "schema": inv.PROBE_SCHEMA,
            "type": "ion_heap",
            "name": "qsecom",
            "heap_type": 4,
            "heap_id": 27,
        }
    )
    rows.append(
        {
            "schema": inv.PROBE_SCHEMA,
            "type": "pa_provenance",
            "source": "pagemap",
            "pages": 1,
            "present": 0,
            "nonzero_pfn": 0,
            "first_pfn": "0x0",
            "last_pfn": "0x0",
            "contiguous": True,
            "status": "BLIND",
        }
    )
    for difference, median in medians.items():
        for pair in range(int(ctx["pairs"])):
            rows.append(
                {
                    "schema": inv.PROBE_SCHEMA,
                    "type": "pair",
                    "value": f"0x{difference:x}",
                    "offset": f"0x{pair * 0x1000:x}",
                    "delta": median,
                }
            )
        rows.append(
            {
                "schema": inv.PROBE_SCHEMA,
                "type": "difference",
                "value": f"0x{difference:x}",
                "pairs": int(ctx["pairs"]),
                "p10": median,
                "median": median,
                "p90": median,
            }
        )
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"


class StrictTranscriptTests(unittest.TestCase):
    def test_contexts_must_be_identical(self):
        changed = context(cpu=6)
        text = strict_transcript({0x1: 10}, ctx=context())
        text += strict_transcript({0x2: 20}, ctx=changed)
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_context_numeric_strings_are_rejected_before_bounds_math(self):
        changed = context()
        changed["mib"] = "32"
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(strict_transcript({0x1: 10}, ctx=changed))

    def test_each_section_heap_and_pa_records_must_match(self):
        rows = [json.loads(line) for line in strict_transcript({0x1: 10}).splitlines()]
        second = [json.loads(line) for line in strict_transcript({0x2: 20}).splitlines()]
        for row in second:
            if row.get("type") == "ion_heap":
                row["heap_id"] = 28
            if row.get("type") == "pa_provenance":
                row["status"] = "NOT_BLIND"
        text = "\n".join(json.dumps(row) for row in rows + second)
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_duplicate_difference_records_are_rejected(self):
        text = strict_transcript({0x1: 10})
        text += json.dumps(
            {
                "schema": inv.PROBE_SCHEMA,
                "type": "difference",
                "value": "0x1",
                "pairs": 1,
                "p10": 10,
                "median": 10,
                "p90": 10,
            }
        )
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_each_context_section_requires_one_heap_and_pa_record(self):
        text = "\n".join(
            line
            for line in strict_transcript({0x1: 10}).splitlines()
            if json.loads(line).get("type") != "ion_heap"
        )
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_summary_without_preceding_pairs_is_rejected(self):
        rows = [context(), {
            "schema": inv.PROBE_SCHEMA,
            "type": "ion_heap",
            "name": "qsecom",
            "heap_type": 4,
            "heap_id": 27,
        }, {
            "schema": inv.PROBE_SCHEMA,
            "type": "pa_provenance",
            "source": "pagemap",
            "pages": 1,
            "present": 0,
            "nonzero_pfn": 0,
            "first_pfn": "0x0",
            "last_pfn": "0x0",
            "contiguous": True,
            "status": "BLIND",
        }, {
            "schema": inv.PROBE_SCHEMA,
            "type": "difference",
            "value": "0x1",
            "pairs": 1,
            "p10": 10,
            "median": 10,
            "p90": 10,
        }]
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript("\n".join(json.dumps(row) for row in rows))

    def test_duplicate_pair_offsets_are_rejected(self):
        text = strict_transcript({0x1: 10}, ctx=context(pairs=2))
        text = text.replace('"offset": "0x1000"', '"offset": "0x0"')
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_pair_after_its_summary_is_rejected(self):
        text = strict_transcript({0x1: 10})
        pair = {
            "schema": inv.PROBE_SCHEMA,
            "type": "pair",
            "value": "0x1",
            "offset": "0x1000",
            "delta": 10,
        }
        text += json.dumps(pair) + "\n"
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_qsort_statistics_are_recomputed_from_pair_deltas(self):
        text = strict_transcript({0x1: 10})
        text = text.replace('"p10": 10', '"p10": 11')
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_offsets_and_xor_offsets_must_fit_context_allocation(self):
        text = strict_transcript({0x1: 10})
        text = text.replace('"offset": "0x0"', '"offset": "0x100000"')
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)
        text = strict_transcript({0x100000: 10}, ctx=context())
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript(text)

    def test_malformed_json_is_rejected_instead_of_skipped(self):
        with self.assertRaises(inv.InvarianceError):
            inv.parse_probe_transcript('{"type":"context"}\nnot-json\n')

    def test_legacy_loader_rejects_equal_duplicate_medians(self):
        text = (
            '{"schema":"x","type":"difference","value":"0x1",'
            '"median":10}\n'
            '{"schema":"x","type":"difference","value":"0x1",'
            '"median":10}\n'
        )
        with self.assertRaises(inv.InvarianceError):
            inv.load_medians(text)


class AnalysisContractTests(unittest.TestCase):
    def test_unequal_final_keysets_are_rejected(self):
        with self.assertRaises(inv.InvarianceError):
            inv.analyse(
                {
                    "a": [{1: 10, 2: 10, 3: 100}],
                    "b": [{1: 10, 2: 100, 4: 100}],
                },
                "a",
            )

    def test_cross_condition_contexts_must_be_identical_when_bound(self):
        values = {1: 10, 2: 100}
        with self.assertRaises(inv.InvarianceError):
            inv.analyse(
                {"a": [values], "b": [values]},
                "a",
                contexts={"a": context(), "b": context(cpu=6)},
            )

    def test_compare_does_not_use_cross_condition_gap_magnitudes(self):
        values = {1: 10, 2: 11, 3: 12, 4: 100, 5: 101, 6: 102}
        base = inv.analyse_condition("base", [values])
        other = inv.analyse_condition("other", [values])
        comparison = inv.compare([base, other], "base")
        self.assertNotIn("widest_gap", comparison)
        self.assertNotIn("runner_up_gap", comparison)
        self.assertIn("weak_separation_runner_up_ratio", comparison)

    def test_dispersion_and_runner_up_gap_are_published(self):
        result = inv.analyse_condition("a", [{1: 10, 2: 11}, {1: 12, 2: 13}])
        self.assertEqual(result["dispersion"]["0x1"]["observations"], 2)
        self.assertEqual(result["dispersion"]["0x1"]["values"], [10, 12])
        self.assertEqual(result["dispersion"]["0x1"]["spread"], 2)
        self.assertIn("runner_up_gap", result["separation"])

    def test_weak_separation_is_scale_invariant_between_conditions(self):
        base_values = {1: 10, 2: 11, 3: 12, 4: 100, 5: 101, 6: 102}
        shifted_values = {difference: value * 100 + 37 for difference, value in base_values.items()}
        first = inv.compare(
            [
                inv.analyse_condition("base", [base_values]),
                inv.analyse_condition("other", [base_values]),
            ],
            "base",
        )
        second = inv.compare(
            [
                inv.analyse_condition("base", [shifted_values]),
                inv.analyse_condition("other", [shifted_values]),
            ],
            "base",
        )
        self.assertEqual(first["weak_separation_conditions"], second["weak_separation_conditions"])
        self.assertEqual(
            [entry["status"] for entry in first["comparisons"]],
            [entry["status"] for entry in second["comparisons"]],
        )
        self.assertNotIn("widest_gap", first)
        self.assertNotIn("runner_up_gap", first)

    def test_l762_is_a_canonical_repeat_gate(self):
        values = {1: 10, 2: 11, 3: 100, 4: 101}
        result = inv.analyse(
            {"v2321-L7980": [values], "v2321-L762": [values]},
            "v2321-L7980",
        )
        self.assertFalse(result["comparison"]["all_invariant"])
        entry = result["comparison"]["comparisons"][0]
        self.assertEqual(entry["status"], "REPEAT_REQUIRED")

    def test_empty_glob_is_rejected(self):
        with self.assertRaises(inv.InvarianceError):
            inv._parse_condition("empty=this-pattern-cannot-match-anything-*.jsonl")

    def test_public_condition_ids_reject_path_fragments(self):
        with self.assertRaises(inv.InvarianceError):
            inv._parse_condition("/home/temmie/private-label=*.jsonl")

    def test_public_safety_checks_mapping_keys(self):
        with self.assertRaises(inv.InvarianceError):
            inv._assert_public_safety({"/home/temmie/private-key": True})

    def test_cli_exposes_auxiliary_provenance_bindings(self):
        parser = inv.build_parser()
        args = parser.parse_args(
            [
                "--condition", "a=one.jsonl",
                "--baseline", "a",
                "--output", "manifest.json",
                "--repeat", "repeat.jsonl",
                "--sweep", "sweep.jsonl",
                "--journal", "journal.txt",
                "--dependency-manifest", "dependency.json",
                "--probe", "probe.c",
            ]
        )
        self.assertEqual(args.level_sweep, Path("sweep.jsonl"))
        self.assertEqual(args.dependency, Path("dependency.json"))
        self.assertEqual(args.probe_source, Path("probe.c"))

    def test_duplicate_paths_and_content_hashes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.jsonl"
            second = root / "second.jsonl"
            first.write_text("same", encoding="utf-8")
            second.write_text("same", encoding="utf-8")
            with self.assertRaises(inv.InvarianceError):
                inv._validate_input_identity({"a": [first], "b": [first]})
            with self.assertRaises(inv.InvarianceError):
                inv._validate_input_identity({"a": [first], "b": [second]})

    def test_validate_then_swap_is_rejected_before_new_medians_can_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input.jsonl"
            path.write_text(strict_transcript({0x1: 10}), encoding="utf-8")
            parsed_old = inv.parse_probe_file(path)
            identity = inv._path_identity(path)
            known = {identity: parsed_old["artifact"]}
            path.write_text(strict_transcript({0x1: 20}), encoding="utf-8")
            with self.assertRaises(inv.InvarianceError):
                inv._validate_input_identity({"a": [path]}, known_metadata=known)


@unittest.skipUnless(
    inv.PRIVATE_ROOT.exists(), "canonical Verification-015 private inputs are unavailable"
)
class CanonicalIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = inv.build_manifest()
        cls.encoded = inv.encode_manifest(cls.manifest)

    def test_canonical_reproduction_has_six_51_key_conditions(self):
        self.assertEqual(len(self.manifest["conditions"]), 6)
        self.assertTrue(
            all(condition["difference_count"] == 51 for condition in self.manifest["conditions"])
        )
        self.assertEqual(
            {
                condition["name"] for condition in self.manifest["conditions"]
            },
            set(inv.CANONICAL_CONDITION_BASENAMES),
        )
        self.assertEqual(
            {condition["difference_count"] for condition in self.manifest["conditions"]},
            {51},
        )

    def test_canonical_repeat_binding_and_six_level_scope(self):
        self.assertEqual(self.manifest["repeat_evidence"]["difference_count"], 6)
        self.assertEqual(self.manifest["repeat_evidence"]["surviving_flip_count"], 0)
        self.assertTrue(self.manifest["repeat_evidence"]["zero_surviving_repeated_flips"])
        groups = self.manifest["repeat_evidence"]["group_analyses"]
        self.assertEqual(len(groups), 6)
        self.assertTrue(all("separation" in group and "labels" in group for group in groups))
        sweep = self.manifest["level_sweep"]
        self.assertEqual(sweep["requested_levels"], list(inv.EXPECTED_SWEEP_LEVELS))
        self.assertEqual(sweep["requested_level_count"], 6)
        self.assertEqual(sweep["replicates_per_level"], 2)
        self.assertEqual(len(sweep["rows"]), 12)
        self.assertEqual(
            self.manifest["repeat_evidence"]["acquisition_scope"]["main_context_binding"],
            "MAIN_CONTEXT_EXCEPT_DECLARED_PAIRS_32",
        )
        self.assertEqual(
            self.manifest["level_sweep"]["acquisition_scope"]["main_context_binding"],
            "EXACT_MAIN_CONTEXT_PAIRS_16",
        )

    def test_repeat_labels_do_not_bind_to_baseline_absolute_scale(self):
        repeat_path = inv.PRIVATE_ROOT / inv.REPEAT_BASENAME
        repeat = inv.parse_level_repeat(repeat_path)
        baseline = next(
            condition
            for condition in self.manifest["conditions"]
            if condition["name"] == "v2321-L7980"
        )
        shifted = copy.deepcopy(baseline)
        shifted["separation"]["threshold"] += 100000
        self.assertEqual(
            inv.bind_repeat_evidence(repeat, baseline),
            inv.bind_repeat_evidence(repeat, shifted),
        )

    def test_one_repeat_flip_is_not_voted_away(self):
        repeat = copy.deepcopy(
            inv.parse_level_repeat(inv.PRIVATE_ROOT / inv.REPEAT_BASENAME)
        )
        group = next(
            item
            for item in repeat["groups"]
            if item["rep"] == 0 and item["level"] == 7980
        )
        group["parsed"]["medians"][0x100E000] = 600
        baseline = next(
            condition
            for condition in self.manifest["conditions"]
            if condition["name"] == "v2321-L7980"
        )
        bound = inv.bind_repeat_evidence(repeat, baseline)
        self.assertIn("0x100e000", bound["surviving_flips"])
        self.assertEqual(
            bound["per_difference"]["0x100e000"]["flip_repetitions"], 1
        )

    def test_canonical_comparison_keeps_l762_repeat_required(self):
        comparison = self.manifest["comparison"]
        self.assertFalse(comparison["all_invariant"])
        l762 = next(
            item for item in comparison["comparisons"] if item["condition"] == "v2321-L762"
        )
        self.assertEqual(l762["status"], "REPEAT_REQUIRED")

    def test_canonical_load_bearing_splits_are_pinned(self):
        expected = {
            "twrp-pre-L7980": (371, 344, 7, 25),
            "twrp-pre-L6881": (573, 396, 3, 25),
            "twrp-post-L7980": (365, 346, 13, 25),
            "v2321-L7980": (351, 339, 8, 25),
            "v2321-L762": (274, 165, 140, 27),
            "v2321-coldboot-L7980": (350, 338, 8, 25),
        }
        for condition in self.manifest["conditions"]:
            split = condition["separation"]
            actual = (
                split["threshold"],
                split["gap"],
                split["runner_up_gap"],
                condition["conflict_count"],
            )
            self.assertEqual(actual, expected[condition["name"]])
        l762 = next(
            item
            for item in self.manifest["comparison"]["comparisons"]
            if item["condition"] == "v2321-L762"
        )
        self.assertEqual(
            {item["difference"] for item in l762["disagreements"]},
            {"0x100e000", "0x1012000"},
        )

    def test_repeat_covers_the_actual_primary_disagreements(self):
        coverage = self.manifest["repeat_evidence"]["primary_comparison_coverage"]
        self.assertEqual(coverage["original_disagreement_count"], 2)
        self.assertEqual(
            set(coverage["original_disagreements"]),
            {"0x100e000", "0x1012000"},
        )
        self.assertTrue(coverage["coverage_complete"])

    def test_missing_repeat_coverage_is_rejected(self):
        repeat_summary = {"per_difference": {"0x100e000": {}}}
        comparison = {
            "baseline": "v2321-L7980",
            "comparisons": [
                {
                    "condition": "v2321-L762",
                    "disagreements": [
                        {"difference": "0x100e000"},
                        {"difference": "0x1012000"},
                    ],
                }
            ],
        }
        with self.assertRaises(inv.InvarianceError):
            inv.validate_repeat_coverage(comparison, repeat_summary)

    def test_all_repeat_group_splits_are_pinned(self):
        expected = {
            (0, 762): (342, 345, 12),
            (0, 7980): (345, 363, 10),
            (1, 762): (367, 345, 208),
            (1, 7980): (358, 357, 22),
            (2, 762): (353, 361, 34),
            (2, 7980): (350, 361, 19),
        }
        for group in self.manifest["repeat_evidence"]["group_analyses"]:
            split = group["separation"]
            self.assertEqual(
                (split["threshold"], split["gap"], split["runner_up_gap"]),
                expected[(group["rep"], group["level"])],
            )
        self.assertEqual(
            sum(
                info["flip_repetitions"]
                for info in self.manifest["repeat_evidence"]["per_difference"].values()
            ),
            0,
        )

    def test_common_acquisition_context_does_not_promote_contiguity(self):
        acquisition = self.manifest["acquisition_context"]
        self.assertTrue(acquisition["common_across_conditions"])
        self.assertEqual(acquisition["ion_heap"]["name"], "qsecom")
        self.assertTrue(acquisition["pa_provenance"]["reported_contiguous"])
        self.assertEqual(acquisition["pa_provenance"]["status"], "BLIND")
        self.assertEqual(acquisition["pa_provenance"]["effective_contiguity"], "UNKNOWN")

    def test_auxiliary_context_binding_allows_only_declared_pairs_difference(self):
        repeat = inv.parse_level_repeat(inv.PRIVATE_ROOT / inv.REPEAT_BASENAME)
        sweep = inv.parse_level_sweep(inv.PRIVATE_ROOT / inv.SWEEP_BASENAME)
        main_context = next(
            condition["context"]
            for condition in self.manifest["conditions"]
            if condition["name"] == "v2321-L7980"
        )
        main_entry = inv.parse_probe_file(
            inv.PRIVATE_ROOT / "v2321-L7980-pass0.jsonl"
        )
        main_records = {
            "ion_heap": main_entry["ion_heap"],
            "pa_provenance": main_entry["pa_provenance"],
        }
        inv._validate_auxiliary_context_binding(
            main_context, repeat, sweep, main_records=main_records
        )
        bad_repeat = copy.deepcopy(repeat)
        bad_repeat["context"]["barrier"] = "changed"
        with self.assertRaises(inv.InvarianceError):
            inv._validate_auxiliary_context_binding(
                main_context, bad_repeat, sweep, main_records=main_records
            )
        bad_repeat = copy.deepcopy(repeat)
        bad_repeat["ion_heap"]["heap_id"] = 999
        with self.assertRaises(inv.InvarianceError):
            inv._validate_auxiliary_context_binding(
                main_context, bad_repeat, sweep, main_records=main_records
            )

    def test_claims_use_only_evidence_disposition_keys(self):
        self.assertEqual(
            set(self.manifest["claims"]),
            {"PROVED", "SUPPORTED", "HYPOTHESIS", "UNKNOWN", "REFUTED"},
        )
        self.assertEqual(
            self.manifest["dispositions"]["alias_or_mutation_scope"],
            "NO_ALIAS_OR_MUTATION_OBSERVED_OR_TESTED",
        )

    def test_identity_and_transition_statuses_cannot_promote_from_transcripts(self):
        identity = self.manifest["provenance_identity"]
        self.assertEqual(identity["target"]["model"], "SM-A908N")
        self.assertEqual(identity["target"]["soc"], "SM8150")
        self.assertEqual(
            identity["target"]["status"],
            "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT",
        )
        self.assertFalse(identity["target"]["transcript_attests_identity"])
        self.assertEqual(identity["timestamp"]["status"], "UNKNOWN_UNRETAINED")
        self.assertEqual(
            identity["commands"]["status"],
            "REDACTED_REPRODUCTION_TEMPLATE",
        )
        self.assertIn("<private-root>", identity["commands"]["template"])
        self.assertEqual(identity["commands"]["executed_receipt"], "NOT_RETAINED")
        self.assertEqual(identity["final_state"]["status"], "UNKNOWN_INCOMPLETE_RECEIPT")

    def test_canonical_input_metadata_is_sanitized_and_complete(self):
        all_inputs = []
        for entries in self.manifest["inputs"]["conditions"].values():
            all_inputs.extend(entries)
        all_inputs.extend(
            [self.manifest["inputs"]["repeat"], self.manifest["inputs"]["level_sweep"]]
        )
        all_inputs.extend(self.manifest["inputs"]["journals"])
        self.assertEqual(len(all_inputs), 19)
        self.assertEqual(
            sum(len(entries) for entries in self.manifest["inputs"]["conditions"].values()),
            15,
        )
        for item in all_inputs:
            self.assertNotIn("/", item["basename"])
            self.assertEqual(len(item["sha256"]), 64)
            self.assertGreater(item["size_bytes"], 0)
        dependencies = self.manifest["dependencies"]
        self.assertEqual(dependencies["probe_source"]["sha256"], inv.PROBE_SOURCE_SHA256)
        self.assertEqual(
            dependencies["dependency_manifest"]["sha256"], inv.DEPENDENCY_MANIFEST_SHA256
        )
        self.assertEqual(
            dependencies["historical_probe_binary"]["status"],
            "UNKNOWN_NO_RETAINED_BUILD_OR_TRANSFER_RECEIPT",
        )

    def test_canonical_artifact_size_and_hash_drift_is_rejected(self):
        source = inv.PRIVATE_ROOT / "v2321-L762-pass0.jsonl"
        with tempfile.TemporaryDirectory() as directory:
            copy_path = Path(directory) / source.name
            copy_path.write_bytes(source.read_bytes() + b"drift")
            with self.assertRaises(inv.InvarianceError):
                inv._validate_input_identity(
                    {"v2321-L762": [copy_path]},
                    pins=inv.CANONICAL_ARTIFACT_PINS,
                )

    def test_canonical_public_safety_and_determinism(self):
        self.assertEqual(self.encoded, inv.encode_manifest(inv.build_manifest()))
        rendered = self.encoded.decode("utf-8")
        self.assertNotIn("evidence/private", rendered)
        self.assertNotIn("/home/", rendered)
        self.assertFalse(self.manifest["public_private_separation"]["raw_transcript_bytes_in_manifest"])
        self.assertFalse(self.manifest["public_private_separation"]["raw_sensitive_bytes_in_manifest"])
        self.assertEqual(self.manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(self.manifest["class_c"], "TRANSFORM ONLY")
        self.assertEqual(
            self.manifest["coordinate_scope"],
            "ALLOCATION_OFFSET_MODEL_COORDINATES",
        )
        self.assertEqual(
            self.manifest["alias_and_mutation"]["status"],
            "NO_ALIAS_OR_MUTATION_OBSERVED_OR_TESTED",
        )
        self.assertEqual(self.manifest["publication"]["requested_mode"], "0644")
        self.assertIn("lstat", self.manifest["publication"]["mode_policy"])

    def test_no_clobber_atomic_publication_and_fresh_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            publication = inv.write_manifest(output, self.manifest)
            self.assertEqual(publication["requested_mode"], "0644")
            self.assertEqual(publication["observed_mode"], "0644")
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            self.assertEqual(output.read_bytes(), self.encoded)
            with self.assertRaises(inv.InvarianceError):
                inv.write_manifest(output, self.manifest)
            link = Path(directory) / "link.json"
            link.symlink_to(output)
            with self.assertRaises(inv.InvarianceError):
                inv.write_manifest(link, self.manifest)

    def test_temp_path_substitution_race_is_detected_without_unlinking_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            original_link = inv.os.link

            def substitute(source, target, *args, **kwargs):
                source_path = Path(source)
                source_path.unlink()
                source_path.write_bytes(b"replacement")
                return original_link(source, target, *args, **kwargs)

            with mock.patch.object(inv.os, "link", side_effect=substitute):
                with self.assertRaises(inv.InvarianceError):
                    inv.write_manifest(output, {"race": True})
            # The path is now an untrusted replacement inode; the publisher
            # must not unlink it while cleaning up its own abandoned temp inode.
            self.assertEqual(output.read_bytes(), b"replacement")

    def test_post_link_mutation_of_our_inode_is_removed_on_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            original_link = inv.os.link

            def link_then_mutate(source, target, *args, **kwargs):
                result = original_link(source, target, *args, **kwargs)
                Path(target).write_bytes(b"mutated")
                return result

            with mock.patch.object(inv.os, "link", side_effect=link_then_mutate):
                with self.assertRaises(inv.InvarianceError):
                    inv.write_manifest(output, {"race": True})
            self.assertFalse(output.exists())

    def test_directory_fsync_same_size_mutation_is_removed_on_final_check(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            original_fsync = inv.os.fsync
            calls = 0

            def fsync_then_mutate(descriptor):
                nonlocal calls
                calls += 1
                result = original_fsync(descriptor)
                if calls == 2:
                    output.write_bytes(b"x" * len(inv.encode_manifest({"race": True})))
                return result

            with mock.patch.object(inv.os, "fsync", side_effect=fsync_then_mutate):
                with self.assertRaises(inv.InvarianceError):
                    inv.write_manifest(output, {"race": True})
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
