"""Focused host-only tests for Experiment 033 residual-memory frontier."""

from __future__ import annotations

import json
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_dcb_residual_memory_frontier as extension


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "sm8150_dcb_residual_memory_frontier.py"
MANIFEST_PATH = ROOT / "evidence/manifests/033-dcb-residual-memory-frontier-20260826-01.manifest.json"


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


def str_x(rt: int, rn: int, offset: int = 0) -> int:
    return 0xF9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def ldp_x(rt: int, rt2: int, rn: int, offset: int = 0) -> int:
    return 0xA9400000 | (((offset // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def ldp_x_post(rt: int, rt2: int, rn: int, offset: int) -> int:
    return 0xA8C00000 | (((offset // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def stp_x(rt: int, rt2: int, rn: int, offset: int = 0) -> int:
    return 0xA9000000 | (((offset // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def stp_w(rt: int, rt2: int, rn: int, offset: int = 0) -> int:
    return 0x29000000 | (((offset // 4) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def ldrsw_x(rt: int, rn: int, offset: int = 0) -> int:
    return 0xB9800000 | ((offset // 4) << 10) | (rn << 5) | rt


def ldrsb_w(rt: int, rn: int, offset: int = 0) -> int:
    return 0x39C00000 | (offset << 10) | (rn << 5) | rt


_DECODER, _MANIFEST_032, _MANIFEST_029, _HASHES = extension.load_pinned_dependencies()


class PinAndSourceTests(unittest.TestCase):
    def test_exact_032_pin_and_source_identity(self):
        self.assertEqual(_HASHES["experiment_032_tool"], {"filename": "sm8150_dcb_arithmetic_frontier.py", "size": 127151, "sha256": "d4233d08ebe3c28cf803f5e9e1e564f1d9e40af12eca85498d23e569821219e2"})
        self.assertEqual(_HASHES["experiment_032_manifest"]["size"], 1564295)
        self.assertEqual(_HASHES["experiment_032_manifest"]["sha256"], "beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31")
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["document_identifier"], "DDI0602 (ID092025)")
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["sha256"], "683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f")
        self.assertEqual(set(extension.ARM_FORM_SOURCES["PAIR_MEMORY"]["pages"]), {437, 438, 439, 752, 753, 754})
        self.assertEqual(set(extension.ARM_FORM_SOURCES["SIGN_EXTENDING_MEMORY"]["pages"]), {457, 458, 465, 466})
        self.assertEqual(set(extension.ARM_FORM_SOURCES["SYSTEM_CONTROL"]["pages"]), {553, 554, 555, 556})

    def test_032_semantic_mutation_is_rejected(self):
        mutated = json.loads(json.dumps(_MANIFEST_032))
        mutated["analysis"]["discriminator_counts"]["INDIRECT_OR_UNSUPPORTED"] = 15
        with self.assertRaises(extension.ExtensionError):
            extension.validate_032_manifest(mutated)

    def test_032_full_inherited_record_mutation_is_rejected(self):
        expected = _MANIFEST_032["analysis"]["reached_extension_events"]
        actual = [dict(event) for event in expected]
        actual[0]["effect"] = "MUTATED_EFFECT"
        with self.assertRaises(extension.ExtensionError):
            extension.assert_inherited_032_equivalence(expected, actual, "reached_extension_events")

    def test_hashed_032_bytes_are_import_source_under_path_replacement(self):
        source = ROOT / "tools/sm8150_dcb_arithmetic_frontier.py"
        manifest = ROOT / "evidence/manifests/032-dcb-arithmetic-frontier-20260826-01.manifest.json"
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            copied_tool = temp_root / source.name
            copied_manifest = temp_root / manifest.name
            copied_tool.write_bytes(source.read_bytes())
            copied_manifest.write_bytes(manifest.read_bytes())
            imported = {}
            real_import = extension._import_032

            def replace_then_import(data, path, digest):
                Path(path).write_bytes(b"path-replaced-after-hash")
                imported["module"] = real_import(data, path, digest)
                return imported["module"]

            with mock.patch.object(extension, "_import_032", side_effect=replace_then_import):
                extension.load_pinned_dependencies(tool_032_path=copied_tool, manifest_032_path=copied_manifest)
            self.assertEqual(imported["module"].EXPERIMENT_ID, "032-dcb-arithmetic-frontier")
            self.assertEqual(copied_tool.read_bytes(), b"path-replaced-after-hash")

            bad = temp_root / "bad-032.py"
            bad.write_bytes(b"x")
            with mock.patch.object(extension, "_import_032", side_effect=AssertionError("imported before hash failure")):
                with self.assertRaises(extension.ExtensionError):
                    extension.load_pinned_dependencies(tool_032_path=bad, manifest_032_path=manifest)

    def test_source_unavailable_fails_closed(self):
        with mock.patch.dict(extension.ARM_PRIMARY_SOURCE, {"access_status": "UNKNOWN"}):
            self.assertFalse(extension.classify_v4_word(ldp_x(0, 1, 2), _DECODER)["supported"])
            self.assertFalse(extension.classify_v4_word(ldrsw_x(0, 1), _DECODER)["supported"])
            self.assertFalse(extension.classify_v4_word(0xD50342FF, _DECODER)["supported"])


class StrictDecoderTests(unittest.TestCase):
    def test_pair_positive_forms_and_signed_scaled_immediates(self):
        offset = extension.decode_pair(ldp_x(3, 4, 5, -16))
        self.assertIsNotNone(offset)
        assert offset is not None
        self.assertEqual(offset["operation"], "LDP")
        self.assertEqual(offset["width"], "X")
        self.assertEqual(offset["offset"], -16)
        self.assertEqual(offset["address_mode"], "SIGNED_OFFSET")
        self.assertFalse(offset["writeback"])
        post = extension.decode_pair(ldp_x_post(3, 4, 5, 16))
        self.assertIsNotNone(post)
        assert post is not None
        self.assertEqual(post["operation"], "LDP")
        self.assertEqual(post["address_mode"], "POST_INDEX")
        self.assertTrue(post["writeback"])
        self.assertEqual(post["offset"], 16)
        self.assertEqual(extension.decode_pair(stp_w(1, 2, 3, -20))["width"], "W")
        self.assertEqual(extension.decode_pair(stp_x(1, 2, 3, 8))["operation"], "STP")
        same_source = extension.decode_pair(stp_x(3, 3, 5, 0))
        self.assertEqual(same_source["operation"], "STP")
        self.assertEqual((same_source["first_source_register"], same_source["second_source_register"]), (3, 3))
        self.assertNotIn("first_destination", same_source)

    def test_pair_strict_negative_masks_and_overlaps(self):
        self.assertIsNone(extension.decode_pair(0x2D000000))
        self.assertIsNone(extension.decode_pair(0xA9BF7BFD))
        self.assertIsNone(extension.decode_pair(0xA8800000 | (1 << 15) | (2 << 10) | (3 << 5) | 1))
        self.assertIsNone(extension.decode_pair(0x28C00000 | (1 << 15) | (2 << 10) | (3 << 5) | 1))
        self.assertFalse(extension.classify_v4_word(0x68C00000 | (1 << 15) | (2 << 10) | (3 << 5) | 1, _DECODER)["supported"])
        self.assertFalse(extension.classify_v4_word(ldp_x(3, 3, 5), _DECODER)["supported"])
        self.assertFalse(extension.classify_v4_word(ldp_x_post(3, 4, 3, 16), _DECODER)["supported"])

    def test_sign_extending_and_system_masks(self):
        self.assertEqual(extension.evaluate_sign_extending(0x80, 8, 32), 0xFFFFFF80)
        self.assertEqual(extension.evaluate_sign_extending(0x80000000, 32, 64), 0xFFFFFFFF80000000)
        sw = extension.decode_sign_extending(ldrsw_x(8, 21, 0))
        sb = extension.decode_sign_extending(ldrsb_w(3, 13, 30))
        self.assertEqual(sw["operation"], "LDRSW")
        self.assertEqual(sw["width"], "X")
        self.assertEqual(sb["operation"], "LDRSB")
        self.assertEqual(sb["width"], "W")
        self.assertEqual(sb["offset"], 30)
        self.assertIsNone(extension.decode_sign_extending(0x398079A3))
        self.assertIsNone(extension.decode_sign_extending(0xB89F82A8))
        self.assertEqual(extension.decode_system_control(0xD50342FF)["operation"], "DAIFClr")
        self.assertIsNone(extension.decode_system_control(0xD50342DF))
        self.assertFalse(extension.classify_v4_word(0xD50342DF, _DECODER)["supported"])


class BoundedSemanticsTests(unittest.TestCase):
    def test_ldp_two_destinations_use_prestate_memory_and_zr_discard(self):
        image = build_elf(0x1000, [ldp_x(0, 1, 2, 16), stp_x(0, 1, 3, 0)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={2: _DECODER.dcb_origin(7), 3: _DECODER.symbolic("OUT", kind="BASE")})
        event = result["v4_handled_forms"][0]
        self.assertEqual(event["pair_lane_count"], 2)
        self.assertEqual([lane["origin_kind"] for lane in event["pair_lane_results"]], ["DCB_DATA", "DCB_DATA"])
        observations = [row for row in result["target_observations"] if row["kind"] == "STP"]
        self.assertEqual(len(observations), 2)
        self.assertEqual([row["offset"] for row in observations], [0, 8])
        self.assertEqual([row["pair_lane_offset"] for row in observations], [0, 8])
        zr = build_elf(0x1000, [ldp_x(31, 1, 2, 0), stp_x(31, 1, 3, 0)])
        zr_result = extension.analyze_site_bound(zr, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={2: _DECODER.dcb_origin(7), 3: _DECODER.symbolic("OUT", kind="BASE")})
        self.assertEqual(zr_result["v4_handled_forms"][0]["pair_lane_results"][0]["destination"], "ZR")
        self.assertEqual(len([row for row in zr_result["target_observations"] if row["kind"] == "STP"]), 2)

    def test_ldp_postindex_uses_base_for_lanes_and_modulo64_writeback(self):
        image = build_elf(0x1000, [ldp_x_post(0, 1, 2, 16), stp_x(0, 1, 3, 0)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={2: _DECODER.dcb_origin(7), 3: _DECODER.symbolic("OUT", kind="BASE")})
        event = result["v4_handled_forms"][0]
        self.assertEqual(event["address_mode"], "POST_INDEX")
        self.assertEqual(event["pair_lane_results"][0]["origin_kind"], "DCB_DATA")
        self.assertEqual([lane["effective_address"] for lane in event["pair_lane_results"]], ["DCB_SECTION_7", "DCB_SECTION_7+0x8"])
        self.assertEqual([lane["effective_address_offset"] for lane in event["pair_lane_results"]], [0, 8])
        self.assertEqual(event["writeback_origin"], "DCB_SECTION_7+0x10")
        self.assertEqual([lane["source_origin"] for lane in result["v4_handled_forms"][1]["pair_lanes"]], ["DCB_DATA_7", "DCB_DATA_7"])
        self.assertEqual([row["target_origin"] for row in result["target_observations"] if row["kind"] == "STP"], ["OUT", "OUT+0x8"])
        signed = build_elf(0x1000, [ldp_x(0, 1, 2, 16), stp_x(0, 1, 3, 0)])
        signed_result = extension.analyze_site_bound(signed, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={2: _DECODER.dcb_origin(7), 3: _DECODER.symbolic("OUT", kind="BASE")})
        self.assertEqual([lane["effective_address"] for lane in signed_result["v4_handled_forms"][0]["pair_lane_results"]], ["DCB_SECTION_7+0x10", "DCB_SECTION_7+0x18"])
        wrap = build_elf(0x1000, [ldp_x_post(0, 1, 2, 16), stp_x(0, 1, 3, 0)])
        wrap_result = extension.analyze_site_bound(wrap, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={2: _DECODER.symbolic("P", offset=extension.MASK64, kind="BASE"), 3: _DECODER.symbolic("OUT", kind="BASE")})
        self.assertEqual(wrap_result["v4_handled_forms"][0]["writeback_origin"], "P+0xf")

    def test_stp_two_lanes_sources_offsets_and_no_silent_drop(self):
        image = build_elf(0x1000, [stp_w(1, 2, 3, -8), str_w(0, 4)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}, seed_origins={3: _DECODER.symbolic("BASE", kind="BASE"), 4: _DECODER.constant(0xA000)})
        observations = [row for row in result["target_observations"] if row["kind"] == "STP"]
        self.assertEqual(len(observations), 2)
        self.assertEqual([row["offset"] for row in observations], [-8, -4])
        self.assertEqual([row["pair_lane_offset"] for row in observations], [-8, -4])
        self.assertEqual([row["source_register"] for row in observations], [1, 2])
        self.assertFalse(result["v4_handled_forms"][0]["writeback"])

    def test_sign_extending_load_and_daifclr_boundaries(self):
        image = build_elf(0x1000, [ldrsb_w(1, 2, 4), str_x(0, 3), 0xD50342FF, str_x(0, 3, 8)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x100c", "loop_head_va": "0x1000", "back_edge_va": "0x100c"}, seed_origins={2: _DECODER.symbolic("UNKNOWN_BASE", kind="BASE"), 3: _DECODER.symbolic("OUT", kind="BASE")})
        sign = next(row for row in result["v4_handled_forms"] if row["family"] == extension.SIGN_EXTENDING_MEMORY)
        self.assertEqual(sign["destination"], "W1")
        self.assertEqual(sign["result_kind"], "UNKNOWN")
        system = next(row for row in result["v4_handled_forms"] if row["family"] == extension.SYSTEM_CONTROL)
        self.assertEqual(system["effect"], "SYSTEM_SIDE_EFFECT_ONLY")
        self.assertFalse(system["writes_gpr"])
        self.assertFalse(system["writes_nzcv"])
        self.assertEqual(len(result["system_side_effects"]), 1)

    def test_unknown_pair_and_postindex_overlap_fail_closed(self):
        image = build_elf(0x1000, [0xA9BF7BFD, str_w(0, 1)])
        result = extension.analyze_site_bound(image, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"})
        self.assertIn(extension.INDIRECT, result["discriminators"])
        self.assertTrue(result["reached_blocker_events"])
        overlap = build_elf(0x1000, [ldp_x_post(3, 4, 3, 16), str_w(0, 1)])
        overlap_result = extension.analyze_site_bound(overlap, _DECODER, {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"})
        self.assertIn(extension.INDIRECT, overlap_result["discriminators"])


class ExactArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not MANIFEST_PATH.exists():
            raise unittest.SkipTest("checked Experiment 033 manifest is not generated yet")
        cls.manifest_bytes = MANIFEST_PATH.read_bytes()
        cls.manifest = json.loads(cls.manifest_bytes)

    def test_exact_counts_and_boundaries(self):
        manifest = self.manifest
        self.assertEqual(manifest["schema"], extension.SCHEMA)
        self.assertEqual(manifest["experiment_id"], extension.EXPERIMENT_ID)
        self.assertEqual(manifest["mode"], "HOST_ONLY_READ_ONLY")
        self.assertEqual(manifest["device_access"], "none")
        self.assertEqual(manifest["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        analysis = manifest["analysis"]
        self.assertEqual(analysis["discriminator_counts"], {"DCB_CONSUMER_PATH": 0, "INDIRECT_OR_UNSUPPORTED": 1, "MC_OR_SHRM_SYMBOLIC_TARGET": 0, "NO_TARGET_WITHIN_MODEL": 70})
        self.assertEqual(analysis["selected_syntactic_frontier"]["occurrence_count"], 352)
        self.assertEqual(analysis["selected_syntactic_frontier"]["unique_va_count"], 219)
        self.assertEqual(analysis["selected_syntactic_frontier"]["unique_raw_word_count"], 197)
        self.assertEqual(analysis["extension_admission"]["reached_unique_event_count"], 308)
        self.assertEqual(analysis["extension_admission"]["selected_not_reached_count"], 44)
        self.assertEqual(analysis["residual_extension_admission"], {"events_outside_selected": 0, "exact_selected_identity": True, "reached_unique_event_count": 44, "selected_029_occurrence_count": 54, "selected_not_reached_count": 10})
        self.assertEqual(analysis["residual_family_admission"], {"PAIR_MEMORY": {"reached_unique_event_count": 41, "selected_029_occurrence_count": 48, "selected_not_reached_count": 7}, "SIGN_EXTENDING_MEMORY": {"reached_unique_event_count": 2, "selected_029_occurrence_count": 2, "selected_not_reached_count": 0}, "SYSTEM_CONTROL": {"reached_unique_event_count": 1, "selected_029_occurrence_count": 4, "selected_not_reached_count": 3}})
        self.assertEqual(analysis["residual_032_syntactic_frontier"]["occurrence_count"], 54)
        self.assertEqual(analysis["residual_032_syntactic_frontier"]["family_counts"], {"PAIR_MEMORY": 48, "SIGN_EXTENDING_MEMORY": 2, "SYSTEM_CONTROL": 4})
        self.assertEqual(analysis["handled_frontier_family_counts"]["PAIR_MEMORY"], 41)
        self.assertEqual(analysis["handled_frontier_family_counts"]["SIGN_EXTENDING_MEMORY"], 2)
        self.assertEqual(analysis["handled_frontier_family_counts"]["SYSTEM_CONTROL"], 1)
        self.assertEqual(analysis["reached_residual_event_count"], 44)
        self.assertEqual(analysis["residual_operation_counts"]["counts"], {"DAIFClr": 1, "LDP": 38, "LDRSB": 1, "LDRSW": 1, "STP": 3})
        self.assertTrue(analysis["residual_operation_counts"]["identity_check"])
        self.assertEqual(analysis["stp_lane_observation_count"], 6)
        self.assertEqual(analysis["stp_lane_indices"], [0, 1])
        self.assertEqual(analysis["remaining_unsupported_site_count"], 1)
        self.assertEqual(analysis["remaining_unsupported_form_count"], 0)
        self.assertEqual(analysis["inherited_032_equivalence"]["reached_extension_events"]["expected_count"], 264)
        self.assertEqual(analysis["inherited_032_equivalence"]["direct_control_events"]["expected_count"], 143)
        self.assertEqual(analysis["inherited_032_equivalence"]["reached_taint_kill_events"]["expected_count"], 23)
        self.assertTrue(analysis["inherited_032_equivalence"]["all_checks_exact"])
        self.assertEqual(analysis["arithmetic_operation_counts"]["counts"], {"BIC": 2, "EOR": 2, "MADD": 3, "UMADDL": 7})
        self.assertEqual(len(analysis["system_side_effect_events"]), 1)
        self.assertFalse(manifest["scope"]["writer_absence_claim"])
        self.assertEqual(manifest["scope"]["system_execution_context"], "UNKNOWN_CURRENT_EL_CHECKDAIFACCESS_TRAP_OUTCOME")
        text = self.manifest_bytes.decode()
        self.assertNotIn("evidence/private", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("xbl_config--sdb2.bin", text)

    def test_deterministic_generation_and_no_clobber(self):
        first = extension.build_manifest()
        second = extension.build_manifest()
        encoded_first = (json.dumps(first, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
        encoded_second = (json.dumps(second, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
        self.assertEqual(encoded_first, encoded_second)
        self.assertEqual(encoded_first, self.manifest_bytes)
        # Exact 0644 is a fresh-publication property.  Git records only the
        # executable bit for this checked-in manifest, whose bytes are pinned.
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            extension.write_no_clobber(path, b"{}\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                extension.write_no_clobber(path, b"changed\n")


if __name__ == "__main__":
    unittest.main()
