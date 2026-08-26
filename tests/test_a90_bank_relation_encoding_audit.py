"""Tests for the Experiment 028 bank-relation encoding audit.

Every test builds its own synthetic input, so none needs firmware or device
output.  Several exist to hold the two repairs this audit makes over
`a90_bank_hash_literal_audit`: that the target set is the corrected,
basis-independent row space, and that a negative is reported against a
measured chance rate instead of on its own.
"""

from __future__ import annotations

import itertools
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools import a90_bank_relation_encoding_audit as audit


def register(address: str, value: int, topology: list[str] | None = None) -> dict:
    return {"register": address, "value": f"0x{value:08x}",
            "topology": topology or []}


def invertible_matrices():
    """Every invertible 3x3 matrix over GF(2), as row triples of bitmasks."""
    for rows in itertools.product(range(8), repeat=3):
        span = {0}
        for row in rows:
            span |= {other ^ row for other in span}
        if len(span) == 8:
            yield rows


class RowSpaceTest(unittest.TestCase):
    def test_three_independent_rows_give_seven_covectors(self):
        self.assertEqual(len(audit.row_space(audit.BANK_ROWS)), 7)

    def test_row_space_is_the_same_for_every_basis_of_the_kernel(self):
        # The audit searches the row space precisely because it does not
        # depend on which of the 168 bases the relation was written in.
        reference = audit.row_space(audit.BANK_ROWS)
        count = 0
        for matrix in invertible_matrices():
            rows = []
            for selector in matrix:
                value = 0
                for index, row in enumerate(audit.BANK_ROWS):
                    if (selector >> index) & 1:
                        value ^= row
                rows.append(value)
            self.assertEqual(audit.row_space(tuple(rows)), reference)
            count += 1
        self.assertEqual(count, 168)

    def test_pa24_is_present_in_two_rows(self):
        in_row = [bool((row >> 24) & 1) for row in audit.BANK_ROWS]
        self.assertEqual(in_row, [False, True, True])

    def test_legacy_rows_differ_only_by_pa24(self):
        for row, legacy in zip(audit.BANK_ROWS, audit.LEGACY_BANK_ROWS):
            self.assertEqual(row & ~(1 << 24), legacy)


class LegacyComparisonTest(unittest.TestCase):
    def test_four_legacy_targets_were_never_in_the_relation(self):
        result = audit.legacy_comparison(audit.LEGACY_BANK_ROWS, audit.BANK_ROWS)
        self.assertEqual(len(result["shared"]), 3)
        self.assertEqual(len(result["legacy_only_never_in_relation"]), 4)
        self.assertEqual(len(result["current_only_never_searched"]), 4)

    def test_an_identical_basis_compares_as_fully_shared(self):
        result = audit.legacy_comparison(audit.BANK_ROWS, audit.BANK_ROWS)
        self.assertEqual(result["legacy_only_never_in_relation"], [])
        self.assertEqual(result["current_only_never_searched"], [])


class LiteralAuditTest(unittest.TestCase):
    def test_planted_mask_is_found(self):
        mask = audit.row_space(audit.BANK_ROWS)[0]
        data = b"\x00" * 16 + mask.to_bytes(4, "little") + b"\x00" * 16
        hits = audit.literal_audit({"blob": data}, [mask])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["file_offset"], "0x10")
        self.assertTrue(hits[0]["aligned_u32"])

    def test_misalignment_is_recorded_not_dropped(self):
        mask = audit.row_space(audit.BANK_ROWS)[0]
        data = b"\x00" * 17 + mask.to_bytes(4, "little") + b"\x00" * 16
        hits = audit.literal_audit({"blob": data}, [mask])
        self.assertEqual(len(hits), 1)
        self.assertFalse(hits[0]["aligned_u32"])

    def test_absent_mask_yields_nothing(self):
        self.assertEqual(audit.literal_audit({"blob": b"\x00" * 64},
                                             [0x009D2000]), [])


class ChanceBaselineTest(unittest.TestCase):
    def test_decoys_never_include_a_real_mask(self):
        masks = audit.row_space(audit.BANK_ROWS)
        blob = b"".join(m.to_bytes(4, "little") for m in masks)
        result = audit.chance_baseline({"blob": blob}, masks, trials=50)
        # Every real mask sits in the blob; if a decoy could equal one, the
        # baseline would absorb the very signal it is meant to calibrate.
        self.assertEqual(result["decoy_hits"], 0)

    def test_baseline_is_deterministic_for_a_seed(self):
        masks = audit.row_space(audit.BANK_ROWS)
        first = audit.chance_baseline({"blob": b"\x00" * 4096}, masks, trials=20)
        second = audit.chance_baseline({"blob": b"\x00" * 4096}, masks, trials=20)
        self.assertEqual(first, second)

    def test_expected_count_scales_with_the_number_of_real_masks(self):
        masks = audit.row_space(audit.BANK_ROWS)
        result = audit.chance_baseline({"blob": b"\x00" * 4096}, masks, trials=20)
        self.assertAlmostEqual(result["expected_for_real_masks"],
                               result["hits_per_mask"] * len(masks))


class RegisterAuditTest(unittest.TestCase):
    def test_every_shift_is_covered(self):
        mask = audit.row_space(audit.BANK_ROWS)[0]
        packed = mask >> 13
        for shift in range(0, 19):
            if (packed << shift) >> 32:
                continue
            matches = audit.register_audit(
                [register("0x09260400", packed << shift)], [mask])
            self.assertTrue(matches, shift)
            self.assertEqual(matches[0]["shift"], shift)

    def test_enable_bit_form_is_recognised(self):
        mask = audit.row_space(audit.BANK_ROWS)[0]
        value = ((mask >> 13) << 1) | 1
        matches = audit.register_audit([register("0x09260404", value)], [mask])
        self.assertEqual(matches[0]["form"], "enable_bit")

    def test_zero_registers_are_ignored(self):
        masks = audit.row_space(audit.BANK_ROWS)
        self.assertEqual(audit.register_audit([register("0x0", 0)], masks), [])

    def test_unrelated_value_does_not_match(self):
        masks = audit.row_space(audit.BANK_ROWS)
        self.assertEqual(
            audit.register_audit([register("0x09260400", 0xC003FFFF)], masks), [])


class IndexEncodingTest(unittest.TestCase):
    def test_planted_index_list_is_found(self):
        mask = audit.row_space(audit.BANK_ROWS)[1]   # popcount 6, fits 8 nibbles
        bits = [b for b in audit.RELATION_BITS if (mask >> b) & 1]
        value = 0
        for slot, bit in enumerate(bits):
            value |= (bit - 13) << (slot * 4)
        matches = audit.index_encoding_audit([register("0x09260404", value)],
                                             [mask])
        self.assertTrue(matches)
        self.assertEqual(matches[0]["index_base"], 13)

    def test_repeating_nibble_value_is_not_a_match(self):
        masks = audit.row_space(audit.BANK_ROWS)
        self.assertEqual(
            audit.index_encoding_audit([register("0x09260404", 0x00003333)],
                                       masks), [])


class AdjacentTripleTest(unittest.TestCase):
    def _blob(self, values: list[int], stride: int) -> bytes:
        data = bytearray(b"\x00" * (stride * 3))
        for index, value in enumerate(values):
            data[index * stride:index * stride + 4] = value.to_bytes(4, "little")
        return bytes(data)

    def test_planted_spanning_triple_is_found(self):
        masks = audit.row_space(audit.BANK_ROWS)
        rows = [row >> 13 for row in audit.BANK_ROWS]
        matches = audit.adjacent_triple_audit({"blob": self._blob(rows, 4)}, masks)
        self.assertTrue(matches)
        self.assertEqual(matches[0]["shift"], 0)

    def test_stride_eight_is_covered(self):
        masks = audit.row_space(audit.BANK_ROWS)
        rows = [row >> 13 for row in audit.BANK_ROWS]
        matches = audit.adjacent_triple_audit({"blob": self._blob(rows, 8)}, masks)
        self.assertTrue(any(m["stride"] == 8 for m in matches))

    def test_three_dependent_covectors_do_not_span_and_are_rejected(self):
        # a, b and a^b lie in the row space but span only four values, so they
        # are not a hash block; requiring the full span is what keeps the
        # signature strong.
        masks = audit.row_space(audit.BANK_ROWS)
        a, b = audit.BANK_ROWS[0] >> 13, audit.BANK_ROWS[1] >> 13
        matches = audit.adjacent_triple_audit(
            {"blob": self._blob([a, b, a ^ b], 4)}, masks)
        self.assertEqual(matches, [])

    def test_empty_blob_is_handled(self):
        masks = audit.row_space(audit.BANK_ROWS)
        self.assertEqual(audit.adjacent_triple_audit({"blob": b"\x00"}, masks), [])


class AuditTest(unittest.TestCase):
    def test_negative_scope_is_observed_set_not_global_absence(self):
        result = audit.audit({"blob": b"\x00" * 32}, [])
        scope = result["register_observation_scope"]
        self.assertEqual(result["experiment_id"], audit.EXPERIMENT_ID)
        self.assertEqual(scope["status"], "NOT_APPLICABLE")
        self.assertEqual(scope["observed_register_count"], 0)
        self.assertIsNone(scope["ranked_instance_observed_address_count"])
        self.assertIsNone(scope["observed_span_word_slots"])
        self.assertIsNone(scope["observed_span_address_density_percent"])
        self.assertIn("NOT_APPLICABLE", result["claim_scope"])
        self.assertIn("SUPPORTED_WITHIN_MODEL", " ".join(result["claims"]["SUPPORTED"]))
        self.assertNotIn("register", " ".join(result["claims"]["REFUTED"]).lower())
        self.assertEqual(scope["negative_claim_status"], "NOT_APPLICABLE")
        self.assertTrue(result["relation_dependency"]["validated"])
        self.assertEqual(result["definition_of_done"]["build"]["status"], "NOT_APPLICABLE")
        for field in ("timestamp", "repetitions", "rollback",
                      "recovery", "device_binding"):
            self.assertEqual(result["definition_of_done"][field]["status"], "NOT_APPLICABLE")
        self.assertEqual(
            result["definition_of_done"]["commands"]["status"],
            "REDACTED_REPRODUCTION_TEMPLATE",
        )

    def test_below_chance_verdict_when_nothing_is_planted(self):
        result = audit.audit({"blob": b"\x00" * 65536}, [register("0x0", 0)])
        self.assertEqual(result["literal"]["count"], 0)
        self.assertEqual(result["literal_verdict"], "BELOW_CHANCE")
        self.assertEqual(result["register_mask"], [])
        self.assertEqual(result["adjacent_triple"], [])

    def test_planted_relation_is_reported_above_chance(self):
        masks = audit.row_space(audit.BANK_ROWS)
        blob = b"\x00" * 4096 + b"".join(
            m.to_bytes(4, "little") for m in masks) + b"\x00" * 4096
        result = audit.audit({"blob": blob}, [])
        self.assertEqual(result["literal"]["count"], len(masks))
        self.assertEqual(result["literal_verdict"], "ABOVE_CHANCE")

    def test_manifest_records_target_digests(self):
        result = audit.audit({"blob": b"\x00" * 32}, [])
        self.assertIn("sha256", result["targets"]["blob"])
        self.assertEqual(result["targets"]["blob"]["bytes"], 32)

    def test_reused_audit_can_publish_a_distinct_experiment_id(self):
        result = audit.audit(
            {"blob": b"\x00" * 32}, [],
            experiment_id="029A-bank-relation-audit-over-abl",
        )
        self.assertEqual(result["experiment_id"],
                         "029A-bank-relation-audit-over-abl")

    def test_source_manifest_pins_scratch_names_sizes_and_hashes(self):
        payload = b"scratch payload"
        digest = hashlib.sha256(payload).hexdigest()
        source = {
            "schema": "abl-uefi-extract-v2",
            "experiment_id": "029A-abl-uefi-searchability",
            "extracted": {
                "logical/blob": {
                    "dump_name": "blob.bin",
                    "bytes": len(payload),
                    "sha256": digest,
                }
            },
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "extraction.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            result = audit.audit(
                {"blob.bin": payload}, [], source_manifest=path
            )
            self.assertTrue(result["source_manifest_dependency"]["validated"])
            self.assertEqual(
                result["source_manifest_dependency"]["experiment_id"],
                "029A-abl-uefi-searchability",
            )
            with self.assertRaises(ValueError):
                audit.audit({"blob.bin": payload + b"!"}, [], source_manifest=path)


class PublishedScopeTest(unittest.TestCase):
    def test_published_manifest_pins_the_observed_negative_scope(self):
        import json
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / (
            "evidence/manifests/028-bank-relation-encoding-audit-20260826-01.manifest.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["experiment_id"], audit.EXPERIMENT_ID)
        scope = document["register_observation_scope"]
        self.assertEqual(scope["observed_register_count"], 494)
        self.assertEqual(scope["observed_nonzero_register_count"], 274)
        self.assertEqual(scope["observed_span_address_density_percent"], 0.4514)
        self.assertIn("not global", document["claim_scope"])
        self.assertEqual(document["relation_dependency"]["manifest"],
                         audit.RELATION_MANIFEST_NAME)
        self.assertEqual(document["relation_dependency"]["sha256"],
                         audit.RELATION_MANIFEST_SHA256)
        self.assertEqual(document["relation_dependency"]["new_bit"], 24)
        self.assertEqual(document["relation_dependency"]["contribution"], "0b110")
        self.assertEqual(document["relation_dependency"]["rank"], 3)
        self.assertEqual(document["relation_dependency"]["coordinate_scope"],
                         "allocation-offset/model coordinates")
        self.assertEqual(document["relation_dependency"]["physical_classification"],
                         "SUPPORTED_WITHIN_MODEL")
        relation = json.loads(
            (path.parent / audit.RELATION_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        for section in ("new_bit", "rank", "kernel"):
            self.assertEqual(
                relation[section]["physical_mapping_classification"],
                "SUPPORTED_WITHIN_MODEL",
            )
        self.assertEqual(document["register_observation_scope"]["negative_claim_status"],
                         "OBSERVED_BOUNDED")
        self.assertEqual(
            document["definition_of_done"]["commands"]["status"],
            "REDACTED_REPRODUCTION_TEMPLATE",
        )


if __name__ == "__main__":
    unittest.main()
