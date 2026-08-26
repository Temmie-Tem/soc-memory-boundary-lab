"""Focused tests for the host-only Experiment 029 frontier inventory.

These tests intentionally treat the checked public manifest as an exact
deterministic artifact while independently recomputing its range and
occurrence accounting.  They never expose or write the private XBL outside a
temporary test directory.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import sm8150_dcb_unsupported_frontier as frontier


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "sm8150_dcb_unsupported_frontier.py"
MANIFEST_PATH = ROOT / "evidence/manifests/029-dcb-unsupported-frontier-20260826-01.manifest.json"
DEPENDENCY_MANIFEST_PATH = ROOT / "evidence/manifests/027-dcb-consumer-writer-complement-20260826-01.manifest.json"
FIRMWARE_PATH = ROOT / "evidence/private/004-live-firmware-readonly-20260825-01/xbl--sdb1.bin"

EXPECTED_MANIFEST_SIZE = 628_525
EXPECTED_MANIFEST_SHA256 = "c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634"
EXPECTED_TOOL_SIZE = 43_950
EXPECTED_TOOL_SHA256 = "e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0"


def load_checked_manifest() -> tuple[bytes, dict[str, object]]:
    data = MANIFEST_PATH.read_bytes()
    return data, json.loads(data)


def _hex_int(value: str) -> int:
    return int(value, 16)


class ExactPinAndImportTests(unittest.TestCase):
    def test_frozen_tool_identity_and_private_input_pin_are_exact(self):
        self.assertEqual(TOOL_PATH.stat().st_size, EXPECTED_TOOL_SIZE)
        self.assertEqual(hashlib.sha256(TOOL_PATH.read_bytes()).hexdigest(), EXPECTED_TOOL_SHA256)
        self.assertEqual(FIRMWARE_PATH.stat().st_size, frontier.XBL_SIZE)
        self.assertEqual(hashlib.sha256(FIRMWARE_PATH.read_bytes()).hexdigest(), frontier.XBL_SHA256)

    def test_tool_hash_mutation_is_rejected_before_dependency_import(self):
        tool_data = TOOL_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            mutated_tool = Path(temp) / TOOL_PATH.name
            mutated_tool.write_bytes(tool_data[:-1] + bytes((tool_data[-1] ^ 1,)))
            imported = False

            def unexpected_import(*_args, **_kwargs):
                nonlocal imported
                imported = True
                raise AssertionError("mutated dependency was imported")

            with mock.patch.object(
                frontier.importlib.util,
                "spec_from_file_location",
                side_effect=unexpected_import,
            ):
                with self.assertRaises(frontier.FrontierError):
                    frontier.load_pinned_027(tool_path=mutated_tool, manifest_path=DEPENDENCY_MANIFEST_PATH)
            self.assertFalse(imported)

    def test_firmware_hash_mutation_is_rejected(self):
        firmware_data = FIRMWARE_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            mutated = Path(temp) / frontier.XBL_NAME
            mutated.write_bytes(firmware_data[:-1] + bytes((firmware_data[-1] ^ 1,)))
            with self.assertRaises(frontier.FrontierError):
                frontier.load_exact(mutated, frontier.XBL_SIZE, frontier.XBL_SHA256, frontier.XBL_NAME)

    def test_semantic_mutation_is_rejected_before_dependency_import(self):
        original = DEPENDENCY_MANIFEST_PATH.read_bytes()
        needle = b'"site_count": 73'
        self.assertIn(needle, original)
        mutated = original.replace(needle, b'"site_count": 72', 1)
        self.assertEqual(len(mutated), len(original))
        mutated_sha256 = hashlib.sha256(mutated).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            mutated_manifest = Path(temp) / DEPENDENCY_MANIFEST_PATH.name
            mutated_manifest.write_bytes(mutated)
            imported = False

            def unexpected_import(*_args, **_kwargs):
                nonlocal imported
                imported = True
                raise AssertionError("semantically mutated dependency was imported")

            with mock.patch.object(
                frontier,
                "EXPERIMENT_027_MANIFEST_SIZE",
                len(mutated),
            ), mock.patch.object(
                frontier,
                "EXPERIMENT_027_MANIFEST_SHA256",
                mutated_sha256,
            ), mock.patch.object(
                frontier.importlib.util,
                "spec_from_file_location",
                side_effect=unexpected_import,
            ):
                with self.assertRaises(frontier.FrontierError):
                    frontier.load_pinned_027(
                        tool_path=TOOL_PATH,
                        manifest_path=mutated_manifest,
                    )
            self.assertFalse(imported)


class ManifestAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes, cls.manifest = load_checked_manifest()

    def test_checked_manifest_identity_and_top_level_boundary(self):
        self.assertEqual(len(self.manifest_bytes), EXPECTED_MANIFEST_SIZE)
        self.assertEqual(hashlib.sha256(self.manifest_bytes).hexdigest(), EXPECTED_MANIFEST_SHA256)
        # Git does not preserve the exact non-executable permission bits.  The
        # publisher's 0644 contract is exercised on fresh outputs below; the
        # checked-in artifact identity is its pinned bytes.
        self.assertEqual(self.manifest["schema"], "sm8150-dcb-unsupported-frontier-v1")
        self.assertEqual(self.manifest["experiment_id"], "029-dcb-unsupported-frontier")
        self.assertEqual(self.manifest["mode"], "HOST_ONLY_READ_ONLY")
        self.assertEqual(self.manifest["device_access"], "none")
        self.assertEqual(self.manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(self.manifest["eligibility"], "NOT_ELIGIBLE")

    def test_exact_71_scope_and_recognized_frontier_separation(self):
        scope = self.manifest["scope"]
        dependency = self.manifest["dependency_027_semantics"]
        ranges = self.manifest["site_ranges"]
        accounting = self.manifest["accounting"]
        self.assertEqual(len(ranges), 71)
        self.assertEqual(scope["fail_closed_site_count"], 71)
        self.assertEqual(scope["source_label"], "INDIRECT_OR_UNSUPPORTED")
        self.assertEqual(scope["register_offset_sites"], 65)
        self.assertEqual(scope["computed_address_sites"], 8)
        self.assertFalse(scope["arbitrary_range_scan"])
        self.assertEqual(scope["scan_mode"], "SYNTACTIC_RANGE_MEMBERSHIP_ONLY")
        self.assertEqual(scope["cfg_reachability"], "UNKNOWN_NOT_ANALYZED")
        self.assertEqual(dependency["site_count"], 73)
        self.assertEqual(dependency["register_offset_site_count"], 65)
        self.assertEqual(dependency["computed_address_site_count"], 8)
        self.assertEqual(dependency["indirect_or_unsupported"], 71)

        scanned = sum(row["scanned_word_occurrences"] for row in ranges)
        recognized = sum(row["recognized_word_occurrences"] for row in ranges)
        frontier_occurrences = sum(row["frontier_occurrences"] for row in ranges)
        self.assertEqual(scanned, 1_992)
        self.assertEqual(recognized, 1_640)
        self.assertEqual(frontier_occurrences, 352)
        self.assertEqual(recognized + frontier_occurrences, scanned)
        self.assertEqual(accounting["scanned_word_occurrence_count"], scanned)
        self.assertEqual(accounting["recognized_word_occurrence_count"], recognized)
        self.assertEqual(accounting["frontier_occurrence_count"], frontier_occurrences)

    def test_all_accounting_identities_and_overlap_deduplication(self):
        accounting = self.manifest["accounting"]
        frontier_data = self.manifest["frontier"]
        occurrences = frontier_data["occurrences"]
        unique_vas = frontier_data["unique_vas"]
        unique_va_records = frontier_data["unique_va_records"]
        unique_words = frontier_data["unique_raw_words"]
        self.assertEqual(len(occurrences), 352)
        self.assertEqual(len(unique_vas), 219)
        self.assertEqual(len(unique_va_records), 219)
        self.assertEqual(len(unique_words), 197)
        self.assertEqual(accounting["scanned_unique_va_count"], 1_180)
        self.assertEqual(accounting["recognized_unique_va_count"], 961)
        self.assertEqual(accounting["frontier_unique_va_count"], 219)
        self.assertEqual(accounting["frontier_unique_raw_word_count"], 197)
        self.assertEqual(accounting["recognized_unique_va_count"] + accounting["frontier_unique_va_count"], accounting["scanned_unique_va_count"])

        by_va: dict[str, list[dict[str, object]]] = defaultdict(list)
        for occurrence in occurrences:
            by_va[occurrence["va"]].append(occurrence)
        self.assertEqual(set(by_va), set(unique_vas))
        overlap_vas = {va for va, members in by_va.items() if len(members) > 1}
        nonoverlap_vas = {va for va, members in by_va.items() if len(members) == 1}
        overlap_occurrences = sum(len(members) for members in by_va.values() if len(members) > 1)
        nonoverlap_occurrences = sum(len(members) for members in by_va.values() if len(members) == 1)
        self.assertEqual(len(overlap_vas), 58)
        self.assertEqual(len(nonoverlap_vas), 161)
        self.assertEqual(overlap_occurrences, 191)
        self.assertEqual(nonoverlap_occurrences, 161)
        self.assertEqual(overlap_occurrences + nonoverlap_occurrences, len(occurrences))
        self.assertEqual(accounting["frontier_overlap_unique_va_count"], len(overlap_vas))
        self.assertEqual(accounting["frontier_nonoverlap_unique_va_count"], len(nonoverlap_vas))
        self.assertEqual(accounting["frontier_overlap_occurrence_count"], overlap_occurrences)
        self.assertEqual(accounting["frontier_nonoverlap_occurrence_count"], nonoverlap_occurrences)
        self.assertEqual(accounting["overlap_multiplicity"], len(occurrences) - len(unique_vas))
        self.assertEqual(accounting["overlap_multiplicity"], overlap_occurrences - len(overlap_vas))
        self.assertTrue(accounting["frontier_occurrence_identity_check"])
        self.assertTrue(accounting["frontier_unique_va_identity_check"])

        for record in unique_va_records:
            members = by_va[record["va"]]
            self.assertEqual(len({member["raw_word"] for member in members}), 1)
            self.assertEqual(record["raw_word"], members[0]["raw_word"])
            self.assertEqual(record["membership_count"], len(members))
            self.assertEqual(record["site_indices"], sorted({member["site_index"] for member in members}))
            self.assertEqual(record["classification"], members[0]["classification"])

        all_range_membership: Counter[int] = Counter()
        for row in self.manifest["site_ranges"]:
            start = _hex_int(row["site_range"]["start"])
            end = _hex_int(row["site_range"]["end_exclusive"])
            all_range_membership.update(range(start, end, 4))
        self.assertEqual(sum(all_range_membership.values()), 1_992)
        all_range_overlap_multiplicity = sum(max(0, count - 1) for count in all_range_membership.values())
        self.assertEqual(all_range_overlap_multiplicity, 812)
        self.assertEqual(accounting["range_overlap_multiplicity"], all_range_overlap_multiplicity)
        for occurrence in occurrences:
            va = _hex_int(occurrence["va"])
            self.assertEqual(occurrence["range_membership_count"], all_range_membership[va])
            expected_overlap = all_range_membership[va] > 1
            self.assertEqual(occurrence["overlap_status"], "OVERLAPPING" if expected_overlap else "NON_OVERLAPPING")

    def test_primary_classes_are_separate_from_orthogonal_overlap_class(self):
        primary_classes = {
            frontier.DECODER_EXTENSION_CANDIDATE,
            frontier.FLAG_ONLY_NO_GPR_DEF,
            frontier.TAINT_KILL_REQUIRED,
            frontier.CONTROL_OR_MEMORY_UNSUPPORTED,
            frontier.UNKNOWN,
        }
        class_counts = self.manifest["frontier"]["class_counts"]
        self.assertEqual(set(class_counts), primary_classes)
        self.assertNotIn(frontier.UNREACHABLE_OR_OVERLAP_UNKNOWN, class_counts)
        self.assertEqual(
            class_counts,
            {
                frontier.DECODER_EXTENSION_CANDIDATE: 161,
                frontier.FLAG_ONLY_NO_GPR_DEF: 99,
                frontier.TAINT_KILL_REQUIRED: 27,
                frontier.CONTROL_OR_MEMORY_UNSUPPORTED: 54,
                frontier.UNKNOWN: 11,
            },
        )
        self.assertEqual(
            self.manifest["frontier"]["range_membership_label_counts"],
            {"UNIQUE_RANGE_MEMBERSHIP": 161, frontier.UNREACHABLE_OR_OVERLAP_UNKNOWN: 191},
        )
        for occurrence in self.manifest["frontier"]["occurrences"]:
            self.assertIn(occurrence["classification"]["label"], primary_classes)
            self.assertIn(
                occurrence["range_membership_label"],
                {"UNIQUE_RANGE_MEMBERSHIP", frontier.UNREACHABLE_OR_OVERLAP_UNKNOWN},
            )

    def test_candidate_rank_is_by_unique_va_and_provenance_is_unknown(self):
        candidates = self.manifest["decoder_extension_candidates"]
        expected = [
            ("BITFIELD_IMM", 56, 54, 120),
            ("AND_SHIFT", 14, 14, 37),
            ("EOR_SHIFT", 2, 2, 2),
            ("BIC_SHIFT", 2, 1, 2),
        ]
        self.assertEqual(
            [(row["family"], row["unique_va_count"], row["unique_raw_word_count"], row["occurrence_count"]) for row in candidates],
            expected,
        )
        sort_keys = [
            (-row["unique_va_count"], -row["unique_raw_word_count"], -row["occurrence_count"], row["family"])
            for row in candidates
        ]
        self.assertEqual(sort_keys, sorted(sort_keys))
        self.assertEqual(
            self.manifest["decoder_extension_rank_basis"],
            "unique_va_count_desc,unique_raw_word_count_desc,occurrence_count_desc,family_asc",
        )
        for rank, row in enumerate(candidates, 1):
            self.assertEqual(row["rank"], rank)
            self.assertEqual(row["claim_status"], "HYPOTHESIS")
            self.assertTrue(row["encoding_mask_match"])
            self.assertEqual(row["source_provenance"], "UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW")
            self.assertEqual(row["label"], frontier.DECODER_EXTENSION_CANDIDATE)


class MaskClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.decoder, _manifest, _hashes = frontier.load_pinned_027()

    def assert_classification(self, word: int, label: str, family: str, *, match: bool = True):
        result = frontier.classify_unrecognized_word(word, self.decoder)
        self.assertEqual(result["label"], label)
        self.assertEqual(result["family"], family)
        self.assertEqual(result["encoding_mask_match"], match)
        self.assertEqual(result["source_provenance"], "UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW")
        self.assertEqual(result["reachability"], "UNKNOWN_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY")
        self.assertEqual(result["decoder_safety"], "NOT_CLAIMED")

    def test_positive_exact_mask_families_and_primary_classes(self):
        cases = (
            (0x8A000000 | (1 << 16) | (2 << 5) | 3, frontier.DECODER_EXTENSION_CANDIDATE, "AND_SHIFT"),
            (0x8A000000 | (3 << 22) | (1 << 16) | (2 << 5) | 3, frontier.DECODER_EXTENSION_CANDIDATE, "AND_SHIFT"),  # ROR
            (0x924003E0, frontier.DECODER_EXTENSION_CANDIDATE, "AND_IMM"),
            (0x93400000 | (1 << 16) | (2 << 5) | 3, frontier.DECODER_EXTENSION_CANDIDATE, "BITFIELD_IMM"),
            (0x1AC02000, frontier.TAINT_KILL_REQUIRED, "VARIABLE_SHIFT"),
            (0x1AC00800, frontier.TAINT_KILL_REQUIRED, "DIVIDE"),
            (0x1A800000, frontier.TAINT_KILL_REQUIRED, "CONDITIONAL_SELECT"),
            (0x1A400000, frontier.FLAG_ONLY_NO_GPR_DEF, "CCMP_CCMN"),
            (0xA9000000, frontier.CONTROL_OR_MEMORY_UNSUPPORTED, "PAIR_MEMORY"),
            (0x39800000, frontier.CONTROL_OR_MEMORY_UNSUPPORTED, "SIGN_EXTENDING_MEMORY"),
            (0xD5000000, frontier.CONTROL_OR_MEMORY_UNSUPPORTED, "SYSTEM_CONTROL"),
        )
        for word, label, family in cases:
            with self.subTest(word=hex(word)):
                self.assert_classification(word, label, family)

    def test_negative_and_reserved_masks_remain_unknown(self):
        cases = (
            (0x00000000, "UNKNOWN_FORM", "NO_EXACT_ENCODING_MASK_FAMILY"),
            (0x0A000000 | (32 << 10) | (1 << 16) | (2 << 5) | 3, "AND_SHIFT", "invalid logical-shifted width/amount encoding"),
            (0x12007C00, "AND_IMM", "reserved logical-immediate encoding"),
            (0xF3410043, "UNKNOWN_FORM", "NO_EXACT_ENCODING_MASK_FAMILY"),  # bitfield opc=3
            (0x91800000, "ADD_SUB_IMM_TAGGED_OR_RESERVED", "reserved add/sub immediate encoding"),
            (0x0B000000 | (3 << 22), "ADDS_SUBS_REG", "reserved add/sub register encoding"),
            (0x0B200000 | (3 << 13), "ADDS_SUBS_EXT", "reserved add/sub register encoding"),
            (0x0B200000 | (7 << 13), "ADDS_SUBS_EXT", "reserved add/sub register encoding"),
            (0x1A800800, "UNKNOWN_FORM", "NO_EXACT_ENCODING_MASK_FAMILY"),  # CSEL reserved bit 11
            (0x1A800C00, "UNKNOWN_FORM", "NO_EXACT_ENCODING_MASK_FAMILY"),  # CSEL reserved bits 11:10
            (0x1B200000, "THREE_SOURCE_UNVALIDATED", "primary allocation fields (sf/op54/op31/o0/Ra) not validated"),
            (0x9B096349, "THREE_SOURCE_UNVALIDATED", "primary allocation fields (sf/op54/op31/o0/Ra) not validated"),
        )
        for word, family, reason in cases:
            with self.subTest(word=hex(word)):
                result = frontier.classify_unrecognized_word(word, self.decoder)
                self.assertEqual(result["label"], frontier.UNKNOWN)
                self.assertEqual(result["family"], family)
                self.assertFalse(result["encoding_mask_match"])
                self.assertEqual(result["reason"], reason)

    def test_add_sub_s_and_rd_semantics_are_distinguished(self):
        add_s0_rd31 = 0x91000000 | (1 << 10) | (2 << 5) | 31
        add_s1_rd31 = 0xB1000000 | (1 << 10) | (2 << 5) | 31
        add_s1_rd3 = 0xB1000000 | (1 << 10) | (2 << 5) | 3
        add_reg_s0_rd31 = 0x8B000000 | (1 << 16) | (2 << 5) | 31
        add_ext_s0_rd31 = 0x8B200000 | (1 << 16) | (2 << 5) | 31
        add_reg_s1_rd31 = 0xAB000000 | (1 << 16) | (2 << 5) | 31
        add_reg_s1_rd3 = 0xAB000000 | (1 << 16) | (2 << 5) | 3
        self.assert_classification(add_s0_rd31, frontier.TAINT_KILL_REQUIRED, "ADD_SUB_IMM_SP")
        self.assert_classification(add_s1_rd31, frontier.FLAG_ONLY_NO_GPR_DEF, "ADDS_SUBS_IMM_FLAG")
        self.assert_classification(add_s1_rd3, frontier.TAINT_KILL_REQUIRED, "ADDS_SUBS_IMM")
        self.assert_classification(add_reg_s0_rd31, frontier.UNKNOWN, "ADD_SUB_REG_ZR_DISCARD")
        self.assert_classification(add_ext_s0_rd31, frontier.TAINT_KILL_REQUIRED, "ADD_SUB_EXT_SP")
        self.assert_classification(add_reg_s1_rd31, frontier.FLAG_ONLY_NO_GPR_DEF, "ADDS_SUBS_REG_FLAG")
        self.assert_classification(add_reg_s1_rd3, frontier.TAINT_KILL_REQUIRED, "ADDS_SUBS_REG")

        # These exact W-register CMP controls were the four former UNKNOWN
        # frontier occurrences.  S=1 and Rd=31 writes NZCV only.
        for word in (0x6B28001F, 0x6B2A01DF, 0x6B2A023F):
            with self.subTest(word=hex(word)):
                self.assert_classification(word, frontier.FLAG_ONLY_NO_GPR_DEF, "ADDS_SUBS_EXT_FLAG")

    def test_w_extended_register_options_match_the_pinned_decoder(self):
        # W extended-register ADD/SUB permits UXTW/UXTX/SXTW/SXTX options
        # 0/1/2/4/5/6; option 3/7 are reserved for this width.
        for option in (0, 1, 2, 4, 5, 6):
            word = 0x0B200000 | (option << 13) | 3
            with self.subTest(option=option):
                self.assertIsNotNone(self.decoder.is_add_sub_ext(word))
        for option in (3, 7):
            word = 0x0B200000 | (option << 13) | 3
            with self.subTest(option=option):
                self.assertIsNone(self.decoder.is_add_sub_ext(word))


class SafetyAndPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes, cls.manifest = load_checked_manifest()

    def test_public_manifest_has_no_private_paths_or_firmware_bytes(self):
        self.assertNotIn(b"evidence/private", self.manifest_bytes)
        self.assertNotIn(b"/home/", self.manifest_bytes)
        self.assertNotIn(b"raw_bytes", self.manifest_bytes)
        self.assertNotIn(b"firmware_bytes", self.manifest_bytes)
        self.assertNotIn(b"private_path", self.manifest_bytes)
        self.assertNotIn("xbl_config--sdb2.bin", self.manifest_bytes.decode())
        self.assertEqual(self.manifest["boundary_bypass"], {
            "device": "none",
            "mmio": "none",
            "reason": "Host-only syntactic inventory; no activation or live authority.",
            "status": "NOT_AUTHORIZED",
            "write": "none",
        })
        claims = self.manifest["claims"]
        unknown = " ".join(claims["UNKNOWN"])
        self.assertIn("Range membership is not CFG reachability", unknown)
        self.assertIn("global consumer or writer absence", unknown)
        self.assertIn("writer presence remain UNKNOWN", unknown)
        for occurrence in self.manifest["frontier"]["occurrences"]:
            classification = occurrence["classification"]
            self.assertEqual(classification["reachability"], "UNKNOWN_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY")
            self.assertEqual(classification["decoder_safety"], "NOT_CLAIMED")
            self.assertEqual(classification["source_provenance"], "UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW")

    def test_retained_runtime_alias_and_unknown_boundaries_are_explicit(self):
        alias = self.manifest["indirect_runtime_alias_site"]
        self.assertEqual(alias["site_index"], 35)
        self.assertEqual(alias["reason"], "027 recorded INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS; retained separately; no reachability claim")
        self.assertEqual(self.manifest["dependency_027_semantics"]["writer_absence"], "UNKNOWN")
        self.assertFalse(self.manifest["dependency_027_semantics"]["writer_absence_claim"])
        self.assertEqual(self.manifest["definition_of_done"]["result"]["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(self.manifest["definition_of_done"]["result"]["status"], "BOUNDED_UNSUPPORTED_FRONTIER_INVENTORY_UNKNOWN")

    def test_two_fresh_cli_generations_equal_checked_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            outputs = [directory / "generation-1.json", directory / "generation-2.json"]
            for output in outputs:
                subprocess.run(
                    [sys.executable, str(TOOL_PATH), "--output", str(output)],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
                self.assertEqual(output.read_bytes(), self.manifest_bytes)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())

    def test_o_excl_nofollow_no_clobber_and_mode0644(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            output = directory / "manifest.json"
            first = b'{"first":true}\n'
            frontier.write_no_clobber(output, first)
            self.assertEqual(output.read_bytes(), first)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                frontier.write_no_clobber(output, b'{"second":true}\n')
            self.assertEqual(output.read_bytes(), first)

            target = directory / "target.json"
            target.write_bytes(b"target")
            link = directory / "symlink.json"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                frontier.write_no_clobber(link, b"clobber")
            self.assertEqual(target.read_bytes(), b"target")


if __name__ == "__main__":
    unittest.main()
