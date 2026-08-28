"""Focused tests for the host-only Verification-015 bus-vote amendment."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import a90_v015_bus_vote_amendment as amendment


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = (amendment.PRIVATE_ROOT / amendment.CLIENT_LIST_NAME).read_bytes()
        self.ebi = (amendment.PRIVATE_ROOT / amendment.EBI_NAME).read_bytes()

    def test_client_list_is_exactly_declared_and_contains_ebi(self) -> None:
        result = amendment.parse_client_list(self.client)
        self.assertEqual(result["declared_client_count"], 66)
        self.assertEqual(result["listed_client_count"], 4)
        self.assertEqual(result["listed_client_names"], list(amendment.EXPECTED_CLIENT_NAMES))
        self.assertTrue(result["required_client_present"])

    def test_client_list_regex_and_semantic_mutations_fail_closed(self) -> None:
        for mutated in (
            self.client.replace(b"66\n", b"65\n", 1),
            self.client.replace(b"disp_rsc_ebi", b"disp_rsc_other", 1),
            self.client + b"\n",
            b"66\n\n\nclk_dispcc_debugfs\n",
        ):
            with self.subTest(mutated=mutated[:20]):
                with self.assertRaises(amendment.BusVoteError):
                    amendment.parse_client_list(mutated)

    def test_ebi_entries_are_classified_and_restored(self) -> None:
        result = amendment.parse_ebi_entries(self.ebi)
        self.assertEqual(result["entry_count"], 6)
        self.assertEqual(result["phase_counts"], {"INITIAL_STATIC_VOTE": 1, "TRANSIENT_LOW_VOTE": 2, "RESTORED_STATIC_VOTE": 3})
        self.assertEqual(result["initial_vote_bytes_per_sec"], {"ab": 12_800_000_000, "ib": 12_800_000_000})
        self.assertEqual(result["transient_vote_bytes_per_sec"], {"ab": 0, "ib": 400_000_000})
        self.assertEqual(result["restored_vote_bytes_per_sec"], {"ab": 12_800_000_000, "ib": 12_800_000_000})
        self.assertTrue(result["restored_matches_initial"])
        self.assertEqual([row["phase"] for row in result["entries"]], [
            "INITIAL_STATIC_VOTE",
            "TRANSIENT_LOW_VOTE",
            "TRANSIENT_LOW_VOTE",
            "RESTORED_STATIC_VOTE",
            "RESTORED_STATIC_VOTE",
            "RESTORED_STATIC_VOTE",
        ])

    def test_ebi_regex_cardinality_and_semantic_mutations_fail_closed(self) -> None:
        mutations = (
            self.ebi.replace(b"400000000", b"401000000", 1),
            self.ebi.replace(b"12800000000", b"12801000000", 1),
            self.ebi + b"\n",
            self.ebi.replace(b"masters: 20000", b"masters : 20000", 1),
            self.ebi.replace(b"\n\n", b"\n", 1),
        )
        for mutated in mutations:
            with self.subTest(mutated=mutated[:25]):
                with self.assertRaises(amendment.BusVoteError):
                    amendment.parse_ebi_entries(mutated)


class InputAndPublicationTests(unittest.TestCase):
    def test_exact_manifest_is_class_c_and_public_safe(self) -> None:
        manifest = amendment.build_manifest()
        text = json.dumps(manifest, sort_keys=True)
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["device_access"], "none")
        self.assertEqual(manifest["bus_vote"]["declared_client_count"], 66)
        self.assertEqual(manifest["bus_vote"]["entry_count"], 6)
        self.assertNotIn("evidence/private", text)
        self.assertNotIn(str(amendment.PRIVATE_ROOT), text)
        self.assertNotIn("12800000000\n", text)

    def test_input_hash_drift_fails_closed(self) -> None:
        with mock.patch.object(amendment, "CLIENT_LIST_SHA256", "0" * 64):
            with self.assertRaises(amendment.BusVoteError):
                amendment.build_manifest()
        with mock.patch.object(amendment, "EBI_SHA256", "0" * 64):
            with self.assertRaises(amendment.BusVoteError):
                amendment.build_manifest()

    def test_no_follow_and_regular_file_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = (amendment.PRIVATE_ROOT / amendment.CLIENT_LIST_NAME).read_bytes()
            target = root / "target.txt"
            target.write_bytes(client)
            link = root / "link.txt"
            os.symlink(target, link)
            with self.assertRaises(amendment.BusVoteError):
                amendment._read_exact(link, len(client), amendment._sha256(client), "symlink")
            directory_path = root / "directory"
            directory_path.mkdir()
            with self.assertRaises(amendment.BusVoteError):
                amendment._read_exact(directory_path, len(client), amendment._sha256(client), "directory")

    def test_manifest_encoding_is_deterministic(self) -> None:
        first = amendment.encode_manifest(amendment.build_manifest())
        second = amendment.encode_manifest(amendment.build_manifest())
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))

    def test_no_clobber_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            payload = amendment.encode_manifest(amendment.build_manifest())
            publication = amendment.write_no_clobber(path, payload)
            self.assertEqual(publication["size_bytes"], len(payload))
            self.assertEqual(publication["mode"], "0644")
            with self.assertRaises(amendment.BusVoteError):
                amendment.write_no_clobber(path, payload)


if __name__ == "__main__":
    unittest.main()
