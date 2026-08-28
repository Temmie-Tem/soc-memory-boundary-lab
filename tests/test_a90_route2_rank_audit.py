"""Focused tests for the bounded Route-2 manifest audit."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tools import a90_route2_rank_audit as audit


class Route2AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = audit.load_inputs()
        cls.result = audit.audit(cls.documents)

    def test_all_exact_inputs_are_pinned(self):
        self.assertEqual(
            set(self.documents),
            set(audit.MANIFEST_PINS),
        )
        for key, pin in audit.MANIFEST_PINS.items():
            path = Path("evidence/manifests") / pin["basename"]
            data = path.read_bytes()
            self.assertEqual(len(data), pin["size_bytes"], key)
            self.assertEqual(hashlib.sha256(data).hexdigest(), pin["sha256"], key)

    def test_q1_is_bounded_and_global_unknown(self):
        q1 = self.result["q1_writer_route"]
        self.assertEqual(q1["status"], "SUPPORTED_BOUNDED_CLOSURE_UNKNOWN_GLOBAL")
        self.assertFalse(q1["baseline_027"]["writer_absence_claim"])
        self.assertTrue(q1["site_identity_stable_031_to_034"])
        self.assertEqual(q1["global_writer_or_consumer_absence"], "UNKNOWN")

    def test_q1_counts_and_paths_are_exact(self):
        rows = {row["manifest"]: row for row in self.result["q1_writer_route"]["extensions"]}
        self.assertEqual(rows["031-dcb-scalar-frontier-extension-20260826-01.manifest.json"]["no_target_within_model"], 51)
        self.assertEqual(rows["032-dcb-arithmetic-frontier-20260826-01.manifest.json"]["indirect_or_unsupported"], 16)
        self.assertEqual(rows["033-dcb-residual-memory-frontier-20260826-01.manifest.json"]["no_target_within_model"], 70)
        self.assertEqual(rows["034-dcb-site35-jump-table-20260826-01.manifest.json"]["no_target_within_model"], 71)
        self.assertTrue(all(row["dcb_consumer_paths"] == 0 and row["mc_or_shrm_symbolic_target"] == 0 for row in rows.values()))

    def test_q4_stays_unknown_without_complete_rows(self):
        q4 = self.result["q4_rank3_contradiction"]
        self.assertEqual(q4["status"], "UNKNOWN_NO_COMPLETE_029_034_RELATION_ROW_SET")
        self.assertEqual(q4["contradiction_status"], "UNKNOWN_NOT_AUDITED_FROM_COMPLETE_RAW_ROW_SET")
        self.assertEqual(q4["source_rank3"]["rank"], 3)
        self.assertEqual(q4["030_inherited_relation"]["contribution"], "0b110")
        self.assertEqual(q4["explicit_relation_rows_in_029_031_034"], 0)

    def test_029_rank_fields_are_not_relation_rows(self):
        q4 = self.result["q4_rank3_contradiction"]
        self.assertEqual(q4["decoder_ordering_metadata_count_029"], 4)
        fields = q4["rank_relation_field_inventory"]
        self.assertEqual(fields["frontier_031"], [])
        self.assertEqual(fields["frontier_032"], [])
        self.assertEqual(fields["frontier_033"], [])
        self.assertEqual(fields["frontier_034"], [])

    def test_scope_and_claim_labels_preserve_unknowns(self):
        self.assertEqual(self.result["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(self.result["scope"]["global_writer_absence"], "UNKNOWN")
        self.assertFalse(self.result["device_access"]["device_contact"])
        claims = self.result["claims"]
        self.assertTrue(any("Q4 contradiction" in item for item in claims["UNKNOWN"]))
        self.assertFalse(claims["REFUTED"])

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(audit.Route2AuditError):
            audit._decode_json_object(b'{"x": 1, "x": 2}', "fixture")

    def test_changed_manifest_bytes_are_rejected_by_pin(self):
        key = "low_bit_030"
        pin = dict(audit.MANIFEST_PINS[key])
        original = audit._read_pinned

        def changed(path, current_pin, label):
            data = original(path, current_pin, label)
            if label == key:
                return data.replace(b"0b110", b"0b111", 1)
            return data

        with mock.patch.object(audit, "_read_pinned", side_effect=changed):
            with self.assertRaises(audit.Route2AuditError):
                audit.audit()

    def test_changed_semantics_are_rejected_even_if_hash_reader_is_bypassed(self):
        original = audit._read_pinned

        def changed(path, pin, label):
            data = original(path, pin, label)
            if label == "frontier_034":
                value = json.loads(data)
                value["analysis"]["discriminator_counts"]["NO_TARGET_WITHIN_MODEL"] = 70
                return json.dumps(value).encode()
            return data

        with mock.patch.object(audit, "_read_pinned", side_effect=changed):
            with self.assertRaises(audit.Route2AuditError):
                audit.audit()

    def test_031_transition_identity_is_required(self):
        documents = copy.deepcopy(self.documents)
        documents["frontier_031"]["analysis"]["actual_delta_vs_027"]["transition_identity"] = False
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_transition_quadrant_counts_are_not_trusted_from_booleans(self):
        documents = copy.deepcopy(self.documents)
        documents["frontier_032"]["analysis"]["transition_quadrants"]["counts"][
            "031_INDIRECT_OR_UNSUPPORTED_TO_032_NO_TARGET_WITHIN_MODEL"
        ] = 5
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_transition_counts_must_match_independent_q1_labels(self):
        documents = copy.deepcopy(self.documents)
        delta = documents["frontier_031"]["analysis"]["actual_delta_vs_027"]
        delta["sites_transitioned_to_no_target_within_v2_model"] = 50
        delta["sites_remaining_fail_closed"] = 21
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_quadrant_expected_counts_cannot_be_mutated_with_declared_counts(self):
        documents = copy.deepcopy(self.documents)
        transition = documents["frontier_033"]["analysis"]["transition_quadrants"]
        key = "032_INDIRECT_OR_UNSUPPORTED_TO_033_NO_TARGET_WITHIN_MODEL"
        transition["counts"][key] += 1
        transition["expected_counts"][key] += 1
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_034_final_projection_requires_inherited_site35_blocker(self):
        documents = copy.deepcopy(self.documents)
        documents["frontier_034"]["sites"][35]["discriminators"] = ["NO_TARGET_WITHIN_MODEL"]
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_row_transition_flags_are_not_trusted(self):
        documents = copy.deepcopy(self.documents)
        documents["frontier_032"]["sites"][1]["delta_vs_031"][
            "transitioned_to_no_target_within_v3_model"
        ] = False
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_quadrant_regressions_are_not_hidden_by_boolean_flags(self):
        documents = copy.deepcopy(self.documents)
        documents["frontier_034"]["analysis"]["combined_transition_quadrants"][
            "regression_count"
        ] = 1
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_031_row_transition_labels_are_checked(self):
        documents = copy.deepcopy(self.documents)
        documents["frontier_031"]["sites"][0]["delta_vs_027"][
            "transition"
        ] = "027_INDIRECT_OR_UNSUPPORTED_TO_031_INDIRECT_OR_UNSUPPORTED"
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_actual_delta_aggregate_is_recomputed_from_rows(self):
        documents = copy.deepcopy(self.documents)
        row = documents["frontier_031"]["sites"][0]
        row["discriminators"] = ["INDIRECT_OR_UNSUPPORTED"]
        delta = row["delta_vs_027"]
        delta["transition"] = "027_INDIRECT_OR_UNSUPPORTED_TO_031_INDIRECT_OR_UNSUPPORTED"
        delta["is_fail_closed"] = True
        delta["transitioned_to_no_target_within_v2_model"] = False
        with self.assertRaises(audit.Route2AuditError):
            audit.audit(documents)

    def test_public_manifest_is_canonical_and_no_clobber(self):
        encoded = audit.encode_public(self.result)
        self.assertNotIn(b"/home/", encoded)
        self.assertIn(b"UNKNOWN_NO_COMPLETE_029_034_RELATION_ROW_SET", encoded)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            publication = audit.write_public(path, self.result)
            self.assertEqual(path.read_bytes(), encoded)
            self.assertEqual(publication["mode"], "0644")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(audit.Route2AuditError):
                audit.write_public(path, self.result)
            sentinel = Path(directory) / "sentinel"
            sentinel.write_bytes(b"keep")
            link = Path(directory) / "link.json"
            link.symlink_to(sentinel)
            with self.assertRaises(audit.Route2AuditError):
                audit.write_public(link, self.result)
            self.assertEqual(sentinel.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
