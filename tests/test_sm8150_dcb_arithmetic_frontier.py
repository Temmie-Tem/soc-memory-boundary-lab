"""Focused tests for host-only Experiment 032 arithmetic frontier."""

from __future__ import annotations

import json
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_dcb_arithmetic_frontier as extension


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "evidence/manifests/032-dcb-arithmetic-frontier-20260826-01.manifest.json"


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
    return _DECODER.Image(bytes(header) + phdr + payload)


def str_w(rt: int, rn: int, offset: int = 0) -> int:
    return 0xB9000000 | ((offset // 4) << 10) | (rn << 5) | rt


def madd_x(rd: int, rn: int, rm: int, ra: int) -> int:
    return 0x9B000000 | (rm << 16) | (ra << 10) | (rn << 5) | rd


def madd_w(rd: int, rn: int, rm: int, ra: int) -> int:
    return 0x1B000000 | (rm << 16) | (ra << 10) | (rn << 5) | rd


def add_x_imm(rd: int, rn: int, immediate: int) -> int:
    return 0x91000000 | (immediate << 10) | (rn << 5) | rd


def umaddl(rd: int, rn: int, rm: int, ra: int) -> int:
    return 0x9BA00000 | (rm << 16) | (ra << 10) | (rn << 5) | rd


def logical_shift(base: int, rd: int, rn: int, rm: int, *, shift: int = 0, amount: int = 0) -> int:
    return base | (shift << 22) | (rm << 16) | (amount << 10) | (rn << 5) | rd


_DECODER, _MANIFEST_031, _MANIFEST_029, _HASHES = extension.load_pinned_dependencies()


class PinAndSourceTests(unittest.TestCase):
    def test_exact_dependency_pins_and_source_identity(self):
        self.assertEqual(_HASHES["experiment_031_tool"]["size"], extension.EXPERIMENT_031_TOOL_SIZE)
        self.assertEqual(_HASHES["experiment_031_manifest"]["sha256"], extension.EXPERIMENT_031_MANIFEST_SHA256)
        self.assertEqual(_HASHES["experiment_029_manifest"]["sha256"], extension.EXPERIMENT_029_MANIFEST_SHA256)
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["document_identifier"], "DDI0602 (ID092025)")
        self.assertTrue(extension.ARM_PRIMARY_SOURCE["canonical_url"].startswith("https://developer.arm.com/"))
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["sha256"], "683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f")

    def test_source_pages_cover_arithmetic_and_inherited_repair(self):
        self.assertTrue({539, 873} <= set(extension.ARM_FORM_SOURCES["THREE_SOURCE_UNVALIDATED"]["pages"]))
        self.assertEqual(set(extension.ARM_FORM_SOURCES["EOR_SHIFT"]["pages"]), {354})
        self.assertEqual(set(extension.ARM_FORM_SOURCES["BIC_SHIFT"]["pages"]), {62})
        self.assertEqual(set(extension.ARM_FORM_SOURCES["DIRECT_CONTROL_DISPATCH_REPAIR"]["pages"]), {54, 55, 111, 112, 849, 850})
        for source in extension.ARM_FORM_SOURCES.values():
            self.assertEqual(source["document_identifier"], "DDI0602 (ID092025)")
            self.assertEqual(source["source_access_status"], "AVAILABLE_AND_HASH_PINNED")

    def test_semantic_dependency_mutations_are_rejected(self):
        mutated_031 = json.loads(json.dumps(_MANIFEST_031))
        mutated_031["analysis"]["actual_delta_vs_027"]["sites_remaining_fail_closed"] = 19
        with self.assertRaises(extension.ExtensionError):
            extension.validate_031_manifest(mutated_031)
        mutated_029 = json.loads(json.dumps(_MANIFEST_029))
        mutated_029["accounting"]["frontier_occurrence_count"] = 351
        with self.assertRaises(extension.ExtensionError):
            extension._validate_029_manifest(mutated_029)

    def test_mutated_inherited_full_record_is_rejected_even_with_equal_count(self):
        expected = _MANIFEST_031["analysis"]["reached_extension_events"]
        for field in ("va", "raw_word", "effect"):
            actual = [dict(event) for event in expected]
            actual[0][field] = "0xdeadbeef" if field != "effect" else "MUTATED_EFFECT"
            with self.assertRaises(extension.ExtensionError):
                extension.assert_inherited_031_equivalence(expected, actual, field)

    def test_hashed_bytes_are_the_import_source_under_path_replacement(self):
        source_paths = [
            ROOT / "tools/sm8150_dcb_consumer_writer_extension.py",
            ROOT / "evidence/manifests/031-dcb-scalar-frontier-extension-20260826-01.manifest.json",
            ROOT / "tools/sm8150_dcb_consumer_writer_complement.py",
            ROOT / "evidence/manifests/027-dcb-consumer-writer-complement-20260826-01.manifest.json",
            ROOT / "tools/sm8150_dcb_unsupported_frontier.py",
            ROOT / "evidence/manifests/029-dcb-unsupported-frontier-20260826-01.manifest.json",
        ]
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            copies = []
            for source in source_paths:
                target = temp_root / source.name
                target.write_bytes(source.read_bytes())
                copies.append(target)
            imported = {}
            real_import = extension._import_031

            def replace_then_import(data, path, digest):
                Path(path).write_bytes(b"path-replaced-after-hash")
                imported["module"] = real_import(data, path, digest)
                return imported["module"]

            with mock.patch.object(extension, "_import_031", side_effect=replace_then_import):
                decoder, manifest_031, manifest_029, _hashes = extension.load_pinned_dependencies(
                    tool_031_path=copies[0],
                    manifest_031_path=copies[1],
                    tool_027_path=copies[2],
                    manifest_027_path=copies[3],
                    tool_029_path=copies[4],
                    manifest_029_path=copies[5],
                )
            self.assertEqual(imported["module"].EXPERIMENT_ID, "031-dcb-scalar-frontier-extension")
            self.assertEqual(imported["module"].__file__, str(copies[0]))
            self.assertEqual(decoder.EXPERIMENT_ID, "027-dcb-consumer-writer-complement")
            self.assertEqual(manifest_031["experiment_id"], "031-dcb-scalar-frontier-extension")
            self.assertEqual(manifest_029["experiment_id"], "029-dcb-unsupported-frontier")
            self.assertEqual(copies[0].read_bytes(), b"path-replaced-after-hash")

            bad_tool = temp_root / "bad-031.py"
            bad_tool.write_bytes(b"x")
            with mock.patch.object(extension, "_import_031", side_effect=AssertionError("imported before hash failure")):
                with self.assertRaises(extension.ExtensionError):
                    extension.load_pinned_dependencies(
                        tool_031_path=bad_tool,
                        manifest_031_path=copies[1],
                        tool_027_path=copies[2],
                        manifest_027_path=copies[3],
                        tool_029_path=copies[4],
                        manifest_029_path=copies[5],
                    )

    def test_source_unavailable_does_not_promote_arithmetic(self):
        word = madd_x(1, 2, 3, 4)
        with mock.patch.dict(extension.ARM_PRIMARY_SOURCE, {"access_status": "UNKNOWN"}):
            result = extension.classify_v3_word(word, _DECODER)
        self.assertFalse(result["supported"])
        self.assertEqual(result["label"], extension.UNKNOWN)
        self.assertEqual(result["source_access_status"], "UNKNOWN_SOURCE_UNAVAILABLE")

    def test_qualified_masks_and_reserved_negatives(self):
        self.assertTrue(extension.classify_v3_word(madd_x(1, 2, 3, 4), _DECODER)["supported"])
        self.assertTrue(extension.classify_v3_word(madd_w(1, 2, 3, 4), _DECODER)["supported"])
        self.assertTrue(extension.classify_v3_word(umaddl(1, 2, 3, 4), _DECODER)["supported"])
        self.assertTrue(extension.classify_v3_word(logical_shift(0xCA000000, 1, 2, 3), _DECODER)["supported"])
        self.assertTrue(extension.classify_v3_word(logical_shift(0x8A200000, 1, 2, 3), _DECODER)["supported"])
        for bit in (29, 30):
            result = extension.classify_v3_word(madd_x(1, 2, 3, 4) ^ (1 << bit), _DECODER)
            self.assertFalse(result["supported"])
        self.assertFalse(extension.classify_v3_word(madd_x(1, 2, 3, 4) | (1 << 15), _DECODER)["supported"])
        self.assertFalse(extension.classify_v3_word(0x9B200000 | (3 << 16) | (4 << 10) | (2 << 5) | 1, _DECODER)["supported"])
        self.assertFalse(extension.classify_v3_word(umaddl(1, 2, 3, 4) | (1 << 15), _DECODER)["supported"])
        self.assertFalse(extension.classify_v3_word(logical_shift(0x4A000000, 1, 2, 3, amount=32), _DECODER)["supported"])


class PureArithmeticSemanticsTests(unittest.TestCase):
    def test_modulo_width_and_umaddl_zero_extension(self):
        self.assertEqual(extension.evaluate_madd(0xFFFFFFFF, 2, 3, 32), 1)
        self.assertEqual(extension.evaluate_madd(0xFFFFFFFFFFFFFFFF, 2, 3, 64), 1)
        self.assertEqual(extension.evaluate_umaddl(0xFFFFFFFF, 2, 3), (0xFFFFFFFF * 2 + 3) & 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(extension.evaluate_eor_shift(0xF0, 0x3, 64, 0, 4), 0xC0)
        self.assertEqual(extension.evaluate_bic_shift(0xFF, 0x0F, 64, 0, 0), 0xF0)

    def test_pre_state_overlaps_and_rd31_discard(self):
        state = extension.V2State({1: _DECODER.constant(7), 2: _DECODER.constant(5)}, _DECODER.UNKNOWN)
        info = extension.classify_v3_word(madd_x(1, 1, 2, 1), _DECODER)
        result = extension._three_source_origin(_DECODER, state, info, 0x1000)
        self.assertEqual(result.value, 7 * 5 + 7)
        image = build_elf(0x1000, [madd_x(31, 1, 2, 3), str_w(0, 4)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={1: _DECODER.constant(2), 2: _DECODER.constant(3), 3: _DECODER.constant(4), 4: _DECODER.constant(0x9000)})
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertEqual(result["usable_target_observations"][0]["target_origin"], "0x00009000")
        self.assertEqual(result["v3_handled_forms"][0]["destination"], "ZR")

    def test_address_accumulator_and_zero_product_are_exact_only(self):
        address = _DECODER.symbolic("MC_PTR", kind="MC_BASE")
        state = extension.V2State({1: _DECODER.constant(3), 2: _DECODER.constant(4), 3: address}, _DECODER.UNKNOWN)
        info = extension.classify_v3_word(madd_x(4, 1, 2, 3), _DECODER)
        result = extension._three_source_origin(_DECODER, state, info, 0x1000)
        self.assertEqual(result.kind, "MC_BASE")
        self.assertEqual(result.offset, 12)
        zero_state = extension.V2State({1: _DECODER.constant(0), 2: _DECODER.UNKNOWN, 3: address}, _DECODER.UNKNOWN)
        self.assertEqual(extension._three_source_origin(_DECODER, zero_state, info, 0x1000), address)
        unknown_state = extension.V2State({1: _DECODER.symbolic("P", kind="BASE"), 2: _DECODER.constant(4), 3: address}, _DECODER.UNKNOWN)
        self.assertEqual(extension._three_source_origin(_DECODER, unknown_state, info, 0x1000).kind, "UNKNOWN")

    def test_address_accumulator_addition_wraps_modulo_64(self):
        info = extension.classify_v3_word(madd_x(4, 1, 2, 3), _DECODER)
        low = _DECODER.symbolic("PTR_LOW", offset=1, kind="MC_BASE")
        low_state = extension.V2State({1: _DECODER.constant(1), 2: _DECODER.constant(extension.MASK64), 3: low}, _DECODER.UNKNOWN)
        self.assertEqual(extension._three_source_origin(_DECODER, low_state, info, 0x1000).offset, 0)
        high = _DECODER.symbolic("PTR_HIGH", offset=extension.MASK64, kind="MC_BASE")
        high_state = extension.V2State({1: _DECODER.constant(1), 2: _DECODER.constant(1), 3: high}, _DECODER.UNKNOWN)
        self.assertEqual(extension._three_source_origin(_DECODER, high_state, info, 0x1000).offset, 0)

    def test_noncanonical_seed_zero_product_and_identity_are_normalized(self):
        raw = _DECODER.symbolic("PTR_NONCANONICAL", offset=extension.MASK64 + 6, kind="MC_BASE")
        normalized = extension._normalize_address_origin(raw, _DECODER)
        self.assertEqual(normalized.offset, 5)

        zero_info = extension.classify_v3_word(madd_x(4, 1, 2, 3), _DECODER)
        zero_state = extension.V2State(
            {1: _DECODER.constant(0), 2: _DECODER.UNKNOWN, 3: raw},
            _DECODER.UNKNOWN,
        )
        zero_result = extension._three_source_origin(_DECODER, zero_state, zero_info, 0x1000)
        self.assertEqual(zero_result.kind, "MC_BASE")
        self.assertEqual(zero_result.offset, 5)

        identity_info = extension.classify_v3_word(madd_x(4, 1, 2, 3), _DECODER)
        identity_state = extension.V2State(
            {1: _DECODER.constant(1), 2: raw, 3: _DECODER.constant(0)},
            _DECODER.UNKNOWN,
        )
        identity_result = extension._three_source_origin(_DECODER, identity_state, identity_info, 0x1000)
        self.assertEqual(identity_result.kind, "MC_BASE")
        self.assertEqual(identity_result.offset, 5)

        extension._set_sp(identity_state, raw, _DECODER)
        self.assertEqual(identity_state.sp.offset, 5)

    def test_eor_bic_pointer_identities_and_unknown_transforms(self):
        address = _DECODER.symbolic("PTR", kind="BASE")
        zero = _DECODER.constant(0)
        state = extension.V2State({1: address, 2: zero, 3: _DECODER.constant(7)}, _DECODER.UNKNOWN)
        eor = extension.classify_v3_word(logical_shift(0xCA000000, 4, 1, 2), _DECODER)
        bic = extension.classify_v3_word(logical_shift(0x8A200000, 4, 1, 2), _DECODER)
        self.assertEqual(extension._logical_shift_origin(_DECODER, state, eor, 0x1000), address)
        self.assertEqual(extension._logical_shift_origin(_DECODER, state, bic, 0x1000), address)
        transformed = extension.classify_v3_word(logical_shift(0xCA000000, 4, 1, 3, amount=1), _DECODER)
        self.assertEqual(extension._logical_shift_origin(_DECODER, state, transformed, 0x1000).kind, "UNKNOWN")
        w_eor = extension.classify_v3_word(logical_shift(0x4A000000, 4, 1, 2), _DECODER)
        self.assertEqual(extension._logical_shift_origin(_DECODER, state, w_eor, 0x1000).kind, "UNKNOWN")


class BoundedFlowTests(unittest.TestCase):
    def test_madd_boundary_then_inherited_add_wraps_store_to_base(self):
        # The MADD accumulator is BASE+(2^64-1), the final representable
        # offset.  The inherited ADD X1,X1,#1 must wrap that state value to
        # BASE+0 before the following store observes it.
        base = _DECODER.symbolic("BOUNDARY_BASE", offset=extension.MASK64, kind="BASE")
        image = build_elf(0x1000, [madd_x(1, 2, 3, 4), add_x_imm(1, 1, 1), str_w(0, 1)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008"}
        result = extension.analyze_site_bound(
            image,
            _DECODER,
            site,
            seed_origins={2: _DECODER.constant(0), 4: base},
        )
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        observation = result["usable_target_observations"][0]
        self.assertEqual(observation["target_kind"], "BASE")
        self.assertEqual(observation["target_offset"], 0)

    def test_direct_control_repair_is_inherited(self):
        image = build_elf(0x1000, [0x34000040, 0xD503201F, str_w(0, 1)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008"}
        old = _DECODER.analyze_bounded_site(image, site, seed_origins={1: _DECODER.constant(0x9000)})
        new = extension.analyze_site_bound(image, _DECODER, site, seed_origins={1: _DECODER.constant(0x9000)})
        self.assertIn("INDIRECT_OR_UNSUPPORTED", old["discriminators"])
        self.assertEqual(new["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertEqual(new["control_flow_events"][0]["family"], "DIRECT_CONTROL_DISPATCH_REPAIR")

    def test_unknown_arithmetic_is_destination_local_and_pair_stays_blocked(self):
        image = build_elf(0x1000, [madd_x(1, 2, 3, 4), str_w(0, 5)])
        target = _DECODER.constant(0xA000)
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={2: _DECODER.symbolic("P", kind="BASE"), 3: _DECODER.constant(4), 4: _DECODER.symbolic("A", kind="BASE"), 5: target})
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertEqual(result["usable_target_observations"][0]["target_origin"], "0x0000a000")
        self.assertEqual(result["v3_handled_forms"][0]["result_kind"], "UNKNOWN")
        pair = build_elf(0x1000, [0xA9000000, str_w(0, 1)])
        blocked = extension.analyze_site_bound(pair, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"})
        self.assertIn("INDIRECT_OR_UNSUPPORTED", blocked["discriminators"])
        self.assertTrue(blocked["reached_blocker_events"])


class ExactArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes = MANIFEST_PATH.read_bytes()
        cls.manifest = json.loads(cls.manifest_bytes)

    def test_exact_transition_and_arithmetic_admission(self):
        self.assertEqual(self.manifest["experiment_id"], extension.EXPERIMENT_ID)
        self.assertEqual(self.manifest["analysis"]["selected_syntactic_frontier"]["occurrence_count"], 298)
        self.assertEqual(self.manifest["analysis"]["selected_arithmetic_syntactic_frontier"]["occurrence_count"], 15)
        self.assertEqual(self.manifest["analysis"]["selected_arithmetic_syntactic_frontier"]["site_count"], 7)
        self.assertEqual(self.manifest["analysis"]["remaining_syntactic_frontier"]["occurrence_count"], 54)
        self.assertEqual(self.manifest["analysis"]["all_range_forms_selected"]["ratio"], "56/71")
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_027"]["sites_transitioned_to_no_target_within_v3_model"], 55)
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_027"]["v3_fail_closed_sites"], 16)
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_031"]["sites_transitioned_to_no_target_within_v3_model"], 4)
        self.assertEqual(self.manifest["analysis"]["actual_delta_vs_031"]["v3_fail_closed_sites"], 16)
        quadrants = self.manifest["analysis"]["transition_quadrants"]
        self.assertTrue(quadrants["identity_check"])
        self.assertTrue(quadrants["regression_free"])
        self.assertEqual(quadrants["counts"], {
            "031_INDIRECT_OR_UNSUPPORTED_TO_032_INDIRECT_OR_UNSUPPORTED": 16,
            "031_INDIRECT_OR_UNSUPPORTED_TO_032_NO_TARGET_WITHIN_MODEL": 4,
            "031_NO_TARGET_WITHIN_MODEL_TO_032_INDIRECT_OR_UNSUPPORTED": 0,
            "031_NO_TARGET_WITHIN_MODEL_TO_032_NO_TARGET_WITHIN_MODEL": 51,
        })
        admission = self.manifest["analysis"]["extension_admission"]
        self.assertEqual(admission["selected_029_occurrence_count"], 298)
        self.assertEqual(admission["reached_unique_event_count"], 264)
        self.assertEqual(admission["selected_not_reached_count"], 34)
        arithmetic = self.manifest["analysis"]["arithmetic_extension_admission"]
        self.assertEqual(arithmetic["selected_029_occurrence_count"], 15)
        self.assertEqual(arithmetic["reached_unique_event_count"], 14)
        self.assertEqual(arithmetic["selected_not_reached_count"], 1)
        self.assertTrue(admission["all_reached_events_admitted"])
        self.assertTrue(arithmetic["all_reached_events_admitted"])
        self.assertEqual(self.manifest["analysis"]["direct_control_dispatch_repair"]["event_count"], 143)
        self.assertEqual(self.manifest["analysis"]["direct_control_dispatch_repair"]["site_count"], 62)
        events = self.manifest["analysis"]["reached_arithmetic_events"]
        self.assertEqual(len(events), 14)
        self.assertEqual({event["family"] for event in events}, {"THREE_SOURCE_UNVALIDATED", "EOR_SHIFT", "BIC_SHIFT"})
        self.assertTrue(all(event["admission_status"] == "PASS_EXACT_029_SELECTED" for event in events))
        self.assertEqual(self.manifest["analysis"]["arithmetic_operation_counts"]["counts"], {"BIC": 2, "EOR": 2, "MADD": 3, "UMADDL": 7})
        self.assertTrue(self.manifest["analysis"]["arithmetic_operation_counts"]["identity_check"])
        for event in events:
            self.assertIn("operation", event)
            self.assertIn("width", event)
            self.assertIn("rn", event)
            self.assertIn("rm", event)
            self.assertIn("rd", event)
            if event["operation"] in {"MADD", "UMADDL"}:
                self.assertIn("ra", event)
            else:
                self.assertIn("shift_type", event)
                self.assertIn("shift_amount", event)
        equivalence = self.manifest["analysis"]["inherited_031_equivalence"]
        self.assertTrue(equivalence["all_checks_exact"])
        self.assertEqual(equivalence["reached_extension_events"]["expected_count"], 250)
        self.assertEqual(equivalence["direct_control_events"]["expected_count"], 143)
        self.assertFalse(self.manifest["scope"]["writer_absence_claim"])
        self.assertEqual(self.manifest["analysis"]["dcb_consumer_paths"], [])
        text = self.manifest_bytes.decode()
        self.assertNotIn("evidence/private", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("xbl_config--sdb2.bin", text)

    def test_public_manifest_is_deterministic_and_no_clobber(self):
        first = extension.build_manifest()
        second = extension.build_manifest()
        encoded_first = json.dumps(first, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
        encoded_second = json.dumps(second, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
        self.assertEqual(encoded_first, encoded_second)
        self.assertEqual(encoded_first.encode(), self.manifest_bytes)
        self.assertEqual(encoded_second.encode(), self.manifest_bytes)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            extension.write_no_clobber(path, b"{}\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                extension.write_no_clobber(path, b"changed\n")


if __name__ == "__main__":
    unittest.main()
