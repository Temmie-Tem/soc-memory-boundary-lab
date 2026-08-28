"""Focused tests for the bounded 1b known-aperture checkpoint."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_1b_reachability_checkpoint as checkpoint


class SourceParserTests(unittest.TestCase):
    def test_memory_map_anchors_are_present(self) -> None:
        payload = (checkpoint.REPO_ROOT / "docs" / checkpoint.MEMORY_MAP_NAME).read_bytes()
        result = checkpoint._parse_memory_map(payload)
        self.assertEqual(result["required_row_count"], 11)
        self.assertEqual(result["rows"][0]["name"], "MEMNOC_MS_MPU")
        self.assertEqual(result["rows"][1]["name"], "CNOC_SNOC_MS_MPU")
        self.assertIn("BIMC_MPU3", {row["name"] for row in result["rows"]})

    def test_memory_map_semantic_mutation_fails_closed(self) -> None:
        payload = (checkpoint.REPO_ROOT / "docs" / checkpoint.MEMORY_MAP_NAME).read_bytes()
        mutated = payload.replace(b"Raw client-vector meaning", b"Effective HLOS denial", 1)
        with self.assertRaises(checkpoint.ReachabilityError):
            checkpoint._parse_memory_map(mutated)

    def test_policy_and_initializer_extract_exact_eight_addresses(self) -> None:
        policy = json.loads((checkpoint.REPO_ROOT / "evidence/manifests" / checkpoint.POLICY_009_NAME).read_bytes())
        initializer = json.loads((checkpoint.REPO_ROOT / "evidence/manifests" / checkpoint.INITIALIZER_010_NAME).read_bytes())
        policy_result = checkpoint._parse_policy_009(policy)
        initializer_result = checkpoint._parse_initializer_010(initializer)
        self.assertTrue(policy_result["selector_branch_invariant"])
        self.assertEqual(initializer_result["known_candidate_count"], 8)
        for branch in initializer_result["selector_branches"].values():
            self.assertEqual(branch["address_count"], 8)
            self.assertTrue(all(item["tz_owned"] for item in branch["addresses"]))
            self.assertTrue(all(not item["legacy_bit3_read_marker"] for item in branch["addresses"]))
            self.assertTrue(all(not item["legacy_bit3_write_marker"] for item in branch["addresses"]))
            self.assertTrue(all(item["effective_hlos_access"] == "UNKNOWN" for item in branch["addresses"]))

    def test_initializer_address_and_legacy_marker_mutations_fail_closed(self) -> None:
        manifest = json.loads((checkpoint.REPO_ROOT / "evidence/manifests" / checkpoint.INITIALIZER_010_NAME).read_bytes())
        changed_address = copy.deepcopy(manifest)
        changed_address["controller_aperture_policy"]["selector_branches"]["selector_result_ge_2"]["addresses"][0]["address"] = "0x09248084"
        with self.assertRaises(checkpoint.ReachabilityError):
            checkpoint._parse_initializer_010(changed_address)
        changed_hlos = copy.deepcopy(manifest)
        changed_hlos["controller_aperture_policy"]["selector_branches"]["selector_result_lt_2"]["addresses"][0]["hits"][1]["hlos_read"] = True
        with self.assertRaises(checkpoint.ReachabilityError):
            checkpoint._parse_initializer_010(changed_hlos)

    def test_watchdog_and_devmem_evidence_is_fail_closed(self) -> None:
        watchdog = json.loads((checkpoint.REPO_ROOT / "evidence/manifests" / checkpoint.WATCHDOG_007_NAME).read_bytes())
        devmem = json.loads((checkpoint.REPO_ROOT / "evidence/manifests" / checkpoint.DEVMEM_005_NAME).read_bytes())
        self.assertEqual(checkpoint._parse_watchdog_007(watchdog)["watchdog_cause"], "Non Secure Watchdog Bark")
        self.assertEqual(checkpoint._parse_devmem_005(devmem)["read_success_count"], 0)
        changed = copy.deepcopy(watchdog)
        changed["read"]["operation_count"] = 2
        with self.assertRaises(checkpoint.ReachabilityError):
            checkpoint._parse_watchdog_007(changed)
        changed = copy.deepcopy(devmem)
        changed["memory_or_mmio_writes"] = True
        with self.assertRaises(checkpoint.ReachabilityError):
            checkpoint._parse_devmem_005(changed)


class CheckpointTests(unittest.TestCase):
    def test_exact_checkpoint_is_class_c_with_global_unknown(self) -> None:
        manifest = checkpoint.build_manifest()
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        self.assertEqual(manifest["device_access"], "none")
        self.assertEqual(manifest["known_apertures"]["candidate_count"], 8)
        self.assertEqual(len(manifest["known_apertures"]["candidates"]), 8)
        self.assertTrue(manifest["known_apertures"]["all_branches_cover_all_candidates"])
        self.assertTrue(manifest["known_apertures"]["all_hits_tz_owned"])
        self.assertFalse(manifest["known_apertures"]["bit3_predicate_discriminating"])
        self.assertEqual(manifest["known_apertures"]["effective_hlos_access"], "UNKNOWN")
        self.assertEqual(manifest["reachability"]["refusing_agent"], "UNDECIDABLE")
        self.assertEqual(manifest["reachability"]["global_normal_world_reachability"], "UNKNOWN")
        self.assertEqual(manifest["reachability"]["fixed_el1_watchdog"]["fixed_address"], "0x09248080")
        encoded = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("PROVED_BROAD_TZ_OWNED_NO_HLOS_STATIC_COVERAGE", encoded)
        self.assertNotIn("SUPPORTED_BLOCKED_FOR_TESTED_STATIC_POLICY", encoded)
        self.assertNotIn("evidence/private", encoded)
        self.assertNotIn(str(checkpoint.REPO_ROOT), encoded)

    def test_all_public_input_hash_drift_is_rejected(self) -> None:
        for constant in (
            "MEMORY_MAP_SHA256",
            "POLICY_009_SHA256",
            "INITIALIZER_010_SHA256",
            "WATCHDOG_007_SHA256",
            "DEVMEM_005_SHA256",
        ):
            with self.subTest(constant=constant), mock.patch.object(checkpoint, constant, "0" * 64):
                with self.assertRaises(checkpoint.ReachabilityError):
                    checkpoint.build_manifest()

    def test_no_follow_and_regular_file_checks(self) -> None:
        source = checkpoint.REPO_ROOT / "docs" / checkpoint.MEMORY_MAP_NAME
        payload = source.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(payload)
            link = root / "link"
            os.symlink(target, link)
            with self.assertRaises(checkpoint.ReachabilityError):
                checkpoint._read_pinned(link, len(payload), checkpoint._sha256(payload), "symlink")
            folder = root / "folder"
            folder.mkdir()
            with self.assertRaises(checkpoint.ReachabilityError):
                checkpoint._read_pinned(folder, len(payload), checkpoint._sha256(payload), "directory")

    def test_deterministic_encoding_and_no_clobber(self) -> None:
        first = checkpoint.encode_manifest(checkpoint.build_manifest())
        second = checkpoint.encode_manifest(checkpoint.build_manifest())
        self.assertEqual(first, second)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            publication = checkpoint.write_no_clobber(path, first)
            self.assertEqual(publication["size_bytes"], len(first))
            self.assertEqual(publication["mode"], "0644")
            with self.assertRaises(checkpoint.ReachabilityError):
                checkpoint.write_no_clobber(path, first)


if __name__ == "__main__":
    unittest.main()
