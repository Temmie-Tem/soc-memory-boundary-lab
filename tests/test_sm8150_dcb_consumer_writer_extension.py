"""Focused tests for the host-only Experiment 031 scalar frontier extension."""

from __future__ import annotations

import hashlib
import json
import stat
import struct
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from tools import sm8150_dcb_consumer_writer_extension as extension
from tools import sm8150_dcb_consumer_writer_complement as complement_027


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "evidence/manifests/031-dcb-scalar-frontier-extension-20260826-01.manifest.json"


def build_elf(base: int, words: list[int], flags: int = 5) -> object:
    payload = b"".join(struct.pack("<I", word) for word in words)
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:7] = b"\x02\x01\x01"
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<H", header, 54, 56)
    struct.pack_into("<H", header, 56, 1)
    phoff = 120
    phdr = struct.pack("<IIQQQQQQ", 1, flags, phoff, base, base, len(payload), len(payload), 0x1000)
    # The PT_LOAD begins immediately after the one program header.
    return _DECODER.Image(bytes(header) + phdr + payload)


def str_w(rt: int, rn: int, offset: int = 0) -> int:
    return 0xB9000000 | ((offset // 4) << 10) | (rn << 5) | rt


def ands_shift(rd: int, rn: int, rm: int, *, width64: bool = True, shift: int = 0, amount: int = 0) -> int:
    return (0xEA000000 if width64 else 0x6A000000) | (shift << 22) | (rm << 16) | (amount << 10) | (rn << 5) | rd


def ubfm_x(rd: int, rn: int, immr: int, imms: int) -> int:
    return 0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd


def variable_lsl(rd: int, rn: int, rm: int) -> int:
    return 0x1AC02000 | (rm << 16) | (rn << 5) | rd


_DECODER, _MANIFEST_027, _MANIFEST_029, _HASHES = extension.load_pinned_dependencies()


class PinAndSourceTests(unittest.TestCase):
    def test_exact_dependency_pins_and_source_identity(self):
        self.assertEqual(_HASHES["experiment_027_tool"]["size"], extension.EXPERIMENT_027_TOOL_SIZE)
        self.assertEqual(_HASHES["experiment_029_manifest"]["sha256"], extension.EXPERIMENT_029_MANIFEST_SHA256)
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["document_identifier"], "DDI0602 (ID092025)")
        self.assertTrue(extension.ARM_PRIMARY_SOURCE["canonical_url"].startswith("https://developer.arm.com/"))
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["sha256"], "683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f")

    def test_source_coverage_covers_promoted_add_sub_and_csinc_families(self):
        flag_pages = set(extension.ARM_FORM_SOURCES["FLAG_ONLY_NO_GPR_DEF"]["pages"])
        taint_pages = set(extension.ARM_FORM_SOURCES["TAINT_KILL_REQUIRED"]["pages"])
        self.assertTrue({25, 27, 28, 34, 35, 113, 114, 116, 117, 827, 829, 830, 831} <= flag_pages)
        self.assertTrue({21, 27, 325, 331, 39, 535, 538, 640, 650, 820, 829, 872} <= taint_pages)
        self.assertIn("CSINC", extension.ARM_FORM_SOURCES["TAINT_KILL_REQUIRED"]["sections"])
        self.assertEqual(set(extension.ARM_FORM_SOURCES["DIRECT_CONTROL_DISPATCH_REPAIR"]["pages"]), {54, 55, 111, 112, 849, 850})
        for source in extension.ARM_FORM_SOURCES.values():
            self.assertEqual(source["document_identifier"], "DDI0602 (ID092025)")
            self.assertEqual(source["source_access_status"], "AVAILABLE_AND_HASH_PINNED")

    def test_semantic_dependency_mutation_is_rejected(self):
        mutated = json.loads(json.dumps(_MANIFEST_027))
        mutated["site_summary"]["site_count"] = 72
        with self.assertRaises(extension.ExtensionError):
            extension.validate_pinned_dependencies(mutated, _MANIFEST_029)

    def test_qualified_and_preserved_masks(self):
        self.assertEqual(extension.classify_v2_word(0x8A000000 | (1 << 16) | (2 << 5) | 3, _DECODER)["family"], "AND_SHIFT")
        self.assertTrue(extension.classify_v2_word(0x8A000000 | (3 << 22) | (1 << 16) | (2 << 5) | 3, _DECODER)["supported"])
        self.assertEqual(extension.classify_v2_word(0x8A200000 | (1 << 16) | (2 << 5) | 3, _DECODER)["supported"], False)
        self.assertEqual(extension.classify_v2_word(0xCA000000 | (1 << 16) | (2 << 5) | 3, _DECODER)["family"], "EOR_SHIFT")

    def test_source_unavailable_does_not_promote_a_form(self):
        with mock.patch.dict(extension.ARM_PRIMARY_SOURCE, {"access_status": "UNKNOWN"}):
            result = extension.classify_v2_word(0x8A000000 | (1 << 16) | (2 << 5) | 3, _DECODER)
            self.assertFalse(result["supported"])
            self.assertEqual(result["label"], extension.UNKNOWN)
            self.assertEqual(result["source_access_status"], "UNKNOWN_SOURCE_UNAVAILABLE")

    def test_reached_event_requires_exact_029_selected_identity(self):
        lookup = extension._selected_029_admission_lookup(_MANIFEST_029)
        key, expected = next((key, value) for key, value in lookup.items() if value["family"] == "CONDITIONAL_SELECT")
        event = {"site_index": key[0], "va": key[1], "word": key[2], "family": "CSEL", "label": expected["label"], "effect": "DESTINATION_LOCAL_KILL"}
        stats = extension._admit_reached_extension_events([event], lookup)
        self.assertEqual(stats, {"events_outside_selected": 0, "family_mismatch_count": 0, "label_mismatch_count": 0})
        self.assertEqual(event["family"], "CONDITIONAL_SELECT")
        bad = dict(event, family="EOR_SHIFT")
        with self.assertRaises(extension.ExtensionError):
            extension._admit_reached_extension_events([bad], lookup)

    def test_negative_width_and_bitfield_encodings_fail_closed(self):
        # W shifted-register amount 32, bitfield opc=3, N/sf mismatch, and
        # out-of-range W immediates are all reserved/invalid.
        self.assertFalse(extension.classify_v2_word(0x0A000000 | (32 << 10), _DECODER)["supported"])
        self.assertFalse(extension.classify_v2_word(0xF3410043, _DECODER)["supported"])
        self.assertFalse(extension.classify_v2_word(0x13000000 | (1 << 22), _DECODER)["supported"])
        self.assertFalse(extension.classify_v2_word(0x13000000 | (32 << 16), _DECODER)["supported"])
        self.assertFalse(extension.classify_v2_word(0x0B200000 | (1 << 22), _DECODER)["supported"])
        self.assertFalse(extension.classify_v2_word(0x0B200000 | (1 << 23), _DECODER)["supported"])


class PureSemanticsTests(unittest.TestCase):
    def test_official_bitfield_and_and_evaluators(self):
        bitfield = extension.decode_bitfield(0x53017E11)
        self.assertIsNotNone(bitfield)
        assert bitfield is not None
        self.assertEqual(extension.evaluate_bitfield(0x1032547698BADCFF, 0, bitfield["width"], bitfield["opc"], bitfield["n"], bitfield["immr"], bitfield["imms"]), 0x4C5D6E7F)
        self.assertEqual(extension.evaluate_and_shift(0xF0, 0x3, 64, 0, 4), 0x30)
        self.assertEqual(extension.evaluate_and_shift(0xFFFFFFFF, 0x80000000, 32, 2, 1), 0xC0000000)

    def test_bfm_old_rd_tmask_ubfm_tmask_and_sbfm_signfill(self):
        # BFM must retain old Rd bits outside tmask; UBFM must apply tmask;
        # SBFM must fill above the selected sign bit.
        self.assertEqual(extension.evaluate_bitfield(0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA, 64, 1, 1, 8, 15), 0xAAAAAAAAAAAAAADE)
        self.assertEqual(extension.evaluate_bitfield(0x98BADCFF, 0, 32, 2, 0, 1, 31), 0x4C5D6E7F)
        self.assertEqual(extension.evaluate_bitfield(0x80, 0, 32, 0, 0, 0, 7), 0xFFFFFF80)

    def test_analyzer_bitfield_operation_preserves_tmask_and_signfill(self):
        state = extension.V2State(
            {
                1: _DECODER.constant(0x123456789ABCDEF0),
                2: _DECODER.constant(0xAAAAAAAAAAAAAAAA),
            },
            _DECODER.UNKNOWN,
        )
        bfm = extension.classify_v2_word(0xB3400000 | (8 << 16) | (15 << 10) | (1 << 5) | 2, _DECODER)
        self.assertEqual(bfm["operation"], "BFM")
        self.assertEqual(
            extension._bitfield_origin(_DECODER, state, bfm, 0).value,
            extension.evaluate_bitfield(0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA, 64, 1, 1, 8, 15),
        )
        ubfm = extension.classify_v2_word(0xD3400000 | (1 << 16) | (31 << 10) | (1 << 5) | 2, _DECODER)
        self.assertEqual(ubfm["operation"], "UBFM")
        self.assertEqual(
            extension._bitfield_origin(_DECODER, state, ubfm, 0).value,
            extension.evaluate_bitfield(0x123456789ABCDEF0, 0, 64, 2, 1, 1, 31),
        )
        sbfm = extension.classify_v2_word(0x13000000 | (0 << 16) | (7 << 10) | (1 << 5) | 2, _DECODER)
        self.assertEqual(sbfm["operation"], "SBFM")
        sbfm_state = extension.V2State({1: _DECODER.constant(0x80)}, _DECODER.UNKNOWN)
        self.assertEqual(
            extension._bitfield_origin(_DECODER, sbfm_state, sbfm, 0).value,
            extension.evaluate_bitfield(0x80, 0, 32, 0, 0, 0, 7),
        )

    def test_w_width_does_not_preserve_x_origin(self):
        origin = _DECODER.symbolic("X_PTR", kind="BASE")
        self.assertEqual(extension.evaluate_bitfield(1, 0, 32, 2, 0, 0, 31), 1)
        image = build_elf(0x1000, [0x53007C22, str_w(0, 2)])  # UBFM W2,W1,#0,#31
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={1: origin})
        self.assertEqual(result["usable_target_observations"][0]["target_kind"], "UNKNOWN")
        image = build_elf(0x1000, [0x0A010022, str_w(0, 2)])  # AND W2,W1,W1
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={1: origin})
        self.assertEqual(result["usable_target_observations"][0]["target_kind"], "UNKNOWN")


class BoundedFlowTests(unittest.TestCase):
    def test_direct_branch_dispatch_repair_removes_027_fallthrough_false_block(self):
        # CBZ W0,+8 reaches the store target and falls through conservatively.
        # Frozen 027 dispatches the edge but then incorrectly sends the branch
        # word through its scalar fallback; v2 records the bounded repair.
        image = build_elf(0x1000, [0x34000040, 0xD503201F, str_w(0, 1)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008"}
        old = complement_027.analyze_bounded_site(image, site, seed_origins={1: complement_027.constant(0x9000)})
        new = extension.analyze_site_bound(image, _DECODER, site, seed_origins={1: _DECODER.constant(0x9000)})
        self.assertIn("INDIRECT_OR_UNSUPPORTED", old["discriminators"])
        self.assertIn("UNRECOGNIZED_AARCH64_INSTRUCTION_OR_MEMORY_FORM", old["unsupported_forms"])
        self.assertEqual(new["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertEqual(new["unsupported_forms"], [])
        self.assertEqual(new["control_flow_events"][0]["family"], "DIRECT_CONTROL_DISPATCH_REPAIR")
        self.assertEqual(new["control_flow_events"][0]["control_family"], "CBZ_CBNZ")

    def test_flag_only_preserves_other_gpr_and_models_flags(self):
        image = build_elf(0x1000, [ands_shift(31, 1, 2), str_w(0, 3)])
        target = _DECODER.constant(0x9000)
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={1: _DECODER.constant(7), 2: _DECODER.constant(3), 3: target})
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertEqual(result["usable_target_observations"][0]["target_origin"], "0x00009000")
        self.assertEqual(result["flags_model"]["state"], "UNKNOWN")
        self.assertTrue(result["v2_handled_forms"])

    def test_destination_local_kill_keeps_unrelated_origin(self):
        image = build_elf(0x1000, [variable_lsl(1, 2, 3), str_w(0, 4)])
        target = _DECODER.constant(0xA000)
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={1: _DECODER.constant(0xBAD), 4: target})
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertEqual(result["usable_target_observations"][0]["target_origin"], "0x0000a000")
        self.assertEqual(result["taint_kills"][0]["destination"], "X1")

    def test_rd31_is_zr_discard_for_bitfield_and_immediate_add_rd31_kills_sp_locally(self):
        image = build_elf(0x1000, [ubfm_x(31, 1, 0, 63), str_w(0, 2)])
        target = _DECODER.constant(0xA000)
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={1: _DECODER.constant(0x1234), 2: target})
        self.assertEqual(result["usable_target_observations"][0]["target_origin"], "0x0000a000")
        self.assertEqual(result["v2_handled_forms"][0]["effect"], "BITFIELD_RESULT_OR_ZR_DISCARD")

        add_sp = 0x91000000 | (1 << 10) | (31 << 5) | 31
        image = build_elf(0x1000, [add_sp, str_w(0, 31)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_sp=_DECODER.symbolic("SP_PTR", kind="BASE"))
        self.assertEqual(result["taint_kills"][0]["destination"], "SP")
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])

    def test_extended_rd31_form_stays_fail_closed(self):
        extended_rd31 = 0x0B200000 | (2 << 16) | (1 << 5) | 31
        classified = extension.classify_v2_word(extended_rd31, _DECODER)
        self.assertFalse(classified["supported"])
        self.assertEqual(classified["family"], "ADD_SUB_EXT_SP")
        image = build_elf(0x1000, [extended_rd31, str_w(0, 1)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_sp=_DECODER.symbolic("MC_STALE_SP", kind="MC_BASE"))
        self.assertIn("INDIRECT_OR_UNSUPPORTED", result["discriminators"])

    def test_pair_memory_remains_fail_closed(self):
        image = build_elf(0x1000, [0xA9000000, str_w(0, 1)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"})
        self.assertIn("INDIRECT_OR_UNSUPPORTED", result["discriminators"])
        self.assertTrue(result["reached_blocker_events"])


class ExactArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes = MANIFEST_PATH.read_bytes()
        cls.manifest = json.loads(cls.manifest_bytes)

    def test_exact_transition_and_syntactic_accounting(self):
        self.assertEqual(self.manifest["experiment_id"], extension.EXPERIMENT_ID)
        self.assertEqual(self.manifest["analysis"]["selected_syntactic_frontier"]["occurrence_count"], 283)
        self.assertEqual(self.manifest["analysis"]["selected_syntactic_frontier"]["unique_va_count"], 160)
        self.assertEqual(self.manifest["analysis"]["selected_syntactic_frontier"]["unique_raw_word_count"], 148)
        self.assertEqual(self.manifest["analysis"]["remaining_syntactic_frontier"]["occurrence_count"], 69)
        self.assertEqual(self.manifest["analysis"]["remaining_syntactic_frontier"]["unique_va_count"], 59)
        self.assertEqual(self.manifest["analysis"]["remaining_syntactic_frontier"]["unique_raw_word_count"], 49)
        self.assertEqual(self.manifest["analysis"]["all_range_forms_selected"]["ratio"], "51/71")
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_027"]["sites_transitioned_to_no_target_within_v2_model"], 51)
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_027"]["v2_fail_closed_sites"], 20)
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_027"]["transition_scope"], "V2_MODEL_ONLY")
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_027"]["absence_claim"], "NO_ABSENCE_CLAIM")
        dispatch = self.manifest["analysis"]["direct_control_dispatch_repair"]
        self.assertTrue(dispatch["identity_check"])
        self.assertEqual(dispatch["event_count"], 143)
        self.assertEqual(dispatch["site_count"], 62)
        self.assertEqual(dispatch["family_counts"], {"B": 15, "B.cond": 87, "CBZ_CBNZ": 28, "TBZ_TBNZ": 13})
        self.assertEqual(dispatch["outcome_split"]["with_direct_control_repair"], {"fail_closed": 14, "no_target_within_v2_model": 48, "site_count": 62})
        self.assertEqual(dispatch["outcome_split"]["without_direct_control_repair"], {"fail_closed": 6, "no_target_within_v2_model": 3, "site_count": 9})
        admission = self.manifest["analysis"]["extension_admission"]
        self.assertEqual(admission["reached_unique_event_count"], 250)
        self.assertEqual(admission["selected_029_occurrence_count"], 283)
        self.assertEqual(admission["selected_not_reached_count"], 33)
        self.assertEqual(admission["events_outside_selected"], 0)
        self.assertEqual(admission["family_mismatch_count"], 0)
        self.assertEqual(admission["label_mismatch_count"], 0)
        self.assertTrue(admission["all_reached_events_admitted"])
        events = self.manifest["analysis"]["reached_extension_events"]
        self.assertEqual(len(events), 250)
        self.assertTrue(all(event["admission_status"] == "PASS_EXACT_029_SELECTED" for event in events))
        self.assertTrue(all("raw_word" in event for event in events))
        self.assertEqual(
            len({(event["site_index"], event["va"], event["raw_word"], event["family"], event["effect"]) for event in events}),
            len(events),
        )
        self.assertNotIn("CSEL", {event["family"] for event in events})
        self.assertIn("CONDITIONAL_SELECT", {event["family"] for event in events})
        self.assertFalse(self.manifest["scope"]["writer_absence_claim"])
        text = self.manifest_bytes.decode()
        self.assertNotIn("evidence/private", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("xbl_config--sdb2.bin", text)

    def test_public_manifest_is_deterministic_and_no_clobber(self):
        first = extension.build_manifest()
        second = extension.build_manifest()
        self.assertEqual(json.dumps(first, sort_keys=True, indent=2, separators=(",", ": ")) + "\n", json.dumps(second, sort_keys=True, indent=2, separators=(",", ": ")) + "\n")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            extension.write_no_clobber(path, b"{}\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                extension.write_no_clobber(path, b"changed\n")


if __name__ == "__main__":
    unittest.main()
