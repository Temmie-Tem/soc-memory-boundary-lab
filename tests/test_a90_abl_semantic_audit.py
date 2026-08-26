"""Focused tests for the bounded 029A ABL semantic audit.

These tests use tiny synthetic payloads (and the existing extractor fixture)
only.  They exercise exact-byte negatives, the adjacent-triple detector, the
runtime/DT unknown boundaries, and deterministic public-manifest shaping;
they do not load the retained multi-megabyte private capture.
"""
from __future__ import annotations

import json
import struct
import unittest

from tools import a90_abl_semantic_audit as audit
from tests import test_abl_uefi_extract as extract_test


class LiteralSearchTest(unittest.TestCase):
    def test_find_all_includes_unaligned_overlapping_offsets(self):
        self.assertEqual(audit.find_all(b"aaaaa", b"aa"), [0, 1, 2, 3])

    def test_unrelated_payload_has_no_controller_or_row_literals(self):
        result = audit.analyse_targets({"payload": b"unrelated bytes"})
        self.assertEqual(
            result["controller_base_literals"]["total_count"], 0
        )
        self.assertEqual(result["bank_row_space_literals"]["total_count"], 0)
        self.assertEqual(result["adjacent_triples"]["count"], 0)

    def test_named_ddr_strings_are_counted_without_runtime_inference(self):
        text = audit.DDR_STRINGS[0][1].encode("ascii")
        result = audit.analyse_targets({"payload": text + text})
        record = result["named_ddr_strings"]["strings"][
            "error_getting_ddr_info"
        ]
        self.assertEqual(record["count"], 2)
        self.assertEqual(record["per_target"], {"payload": 2})


class AdjacentTripleTest(unittest.TestCase):
    def test_three_independent_packed_rows_are_detected(self):
        words = [row >> audit.RELATION_BITS[0] for row in audit.BANK_ROWS]
        payload = b"pref" + struct.pack("<III", *words) + b"suffix"
        matches = audit.adjacent_triple_audit(
            {"payload": payload}, audit.row_space()
        )
        self.assertTrue(matches)
        self.assertEqual(matches[0]["stride"], 4)
        self.assertEqual(matches[0]["shift"], 0)

    def test_two_words_do_not_count_as_a_spanning_triple(self):
        words = [row >> audit.RELATION_BITS[0] for row in audit.BANK_ROWS[:2]]
        payload = struct.pack("<II", *words)
        self.assertEqual(
            audit.adjacent_triple_audit({"payload": payload}, audit.row_space()),
            [],
        )


class BoundaryTest(unittest.TestCase):
    def test_claims_keep_runtime_participation_and_disassembly_unknown(self):
        semantic = audit.analyse_targets({"payload": b"static names only"})
        claims = audit._claims(semantic)
        unknown = " ".join(claims["UNKNOWN"])
        self.assertIn("runtime", unknown)
        self.assertIn("not disassembled", unknown)
        self.assertEqual(len(claims["REFUTED"]), 3)

    def test_synthetic_public_manifest_marks_live_dt_unretained_unknown(self):
        image = extract_test.ExtractTest()._image()
        manifest = audit.audit_image(image, "/private/abl--sdd8.bin")
        self.assertEqual(
            manifest["live_device_tree"]["status"], "UNRETAINED_UNKNOWN"
        )
        self.assertFalse(manifest["live_device_tree"]["retained_evidence"])
        self.assertEqual(manifest["device_binding"]["status"], "NOT_APPLICABLE")
        self.assertEqual(
            manifest["build"]["kernel"],
            "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
        )
        self.assertEqual(
            manifest["build"]["capture_manifest_sha256"],
            audit.CAPTURE_MANIFEST_SHA256,
        )
        self.assertEqual(manifest["rollback"]["status"], "NOT_APPLICABLE")
        self.assertEqual(manifest["recovery"]["status"], "NOT_APPLICABLE")
        self.assertFalse(manifest["public_private_separation"]["raw_bytes_in_manifest"])
        self.assertFalse(
            manifest["public_private_separation"]["private_absolute_paths_in_manifest"]
        )
        rendered = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("/private/", rendered)
        self.assertNotIn("/home/", rendered)
        self.assertTrue(manifest["relation_dependency"]["validated"])
        self.assertEqual(manifest["relation_dependency"]["new_bit"], 24)
        self.assertEqual(manifest["relation_dependency"]["contribution"], "0b110")
        self.assertEqual(
            manifest["definition_of_done"]["commands"]["status"],
            "REDACTED_REPRODUCTION_TEMPLATE",
        )

    def test_audit_output_is_deterministic_for_same_input(self):
        image = extract_test.ExtractTest()._image()
        first = audit.audit_image(image, "abl--sdd8.bin")
        second = audit.audit_image(image, "abl--sdd8.bin")
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )


if __name__ == "__main__":
    unittest.main()
