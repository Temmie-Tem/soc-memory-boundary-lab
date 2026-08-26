"""Focused host-only tests for Experiment 034 site-35 resolution."""

from __future__ import annotations

import copy
import json
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import sm8150_dcb_site35_jump_table as extension


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "evidence/manifests/034-dcb-site35-jump-table-20260826-01.manifest.json"
XBL_PATH = ROOT / "evidence/private/004-live-firmware-readonly-20260825-01/xbl--sdb1.bin"


ANALYZER, DEPENDENCY_033, PIN_HASHES = extension.load_pinned_033()
DECODER = ANALYZER._dependency_decoder
FIRMWARE = extension.load_exact(XBL_PATH, extension.XBL_SIZE, extension.XBL_SHA256, extension.XBL_NAME)
ORIGINAL_IMAGE = DECODER.Image(FIRMWARE)


class WordOverlayImage:
    def __init__(self, image, va: int, word: int):
        self.image = image
        self.va = va
        self.replacement = word

    def file_offset(self, va: int):
        return self.image.file_offset(va)

    def word(self, va: int):
        return self.replacement if va == self.va else self.image.word(va)


def mutate_word(data: bytes, va: int, word: int) -> bytes:
    image = DECODER.Image(data)
    offset = image.file_offset(va)
    if offset is None:
        raise AssertionError(f"unmapped fixture VA {va:#x}")
    result = bytearray(data)
    struct.pack_into("<I", result, offset, word)
    return bytes(result)


class PinAndSourceTests(unittest.TestCase):
    def test_exact_033_pin_and_chain(self):
        self.assertEqual(PIN_HASHES["experiment_033_tool"], {"filename": extension.EXPERIMENT_033_TOOL_NAME, "size": extension.EXPERIMENT_033_TOOL_SIZE, "sha256": extension.EXPERIMENT_033_TOOL_SHA256})
        self.assertEqual(PIN_HASHES["experiment_033_manifest"], {"filename": extension.EXPERIMENT_033_MANIFEST_NAME, "size": extension.EXPERIMENT_033_MANIFEST_SIZE, "sha256": extension.EXPERIMENT_033_MANIFEST_SHA256})
        for name in ("experiment_032_tool", "experiment_032_manifest", "experiment_031_tool", "experiment_031_manifest", "experiment_029_tool", "experiment_029_manifest", "experiment_027_tool", "experiment_027_manifest"):
            self.assertIn(name, PIN_HASHES)
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["document_identifier"], "DDI0602 (ID092025)")
        self.assertEqual(extension.ARM_PRIMARY_SOURCE["sha256"], "683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f")
        self.assertEqual(extension.ARM_FORM_SOURCES["CMP_IMMEDIATE_W"]["pages"], [135, 136])
        self.assertEqual(extension.ARM_FORM_SOURCES["B_COND_HI"]["pages"], [54, 55])
        self.assertEqual(extension.ARM_FORM_SOURCES["B_COND_HI"]["shared_pseudocode_pages"], [4913, 4954])
        self.assertEqual(extension.ARM_FORM_SOURCES["ADRP"]["pages"], [30, 31])
        self.assertEqual(extension.ARM_FORM_SOURCES["ADD_IMMEDIATE_X"]["pages"], [20, 21])
        self.assertEqual(extension.ARM_FORM_SOURCES["LDR_W_UNSIGNED_IMMEDIATE"]["pages"], [441, 442, 443])
        self.assertEqual(extension.ARM_FORM_SOURCES["LDR_REGISTER_OFFSET_X"]["pages"], [444, 445, 446])
        self.assertEqual(extension.ARM_FORM_SOURCES["BR"]["pages"], [67, 68])

    def test_033_semantic_mutation_is_rejected(self):
        mutated = copy.deepcopy(DEPENDENCY_033)
        mutated["analysis"]["discriminator_counts"]["INDIRECT_OR_UNSUPPORTED"] = 0
        with self.assertRaises(extension.ExtensionError):
            extension.validate_033_manifest(mutated)

    def test_hashed_033_source_is_imported_from_bytes(self):
        source = ROOT / "tools" / extension.EXPERIMENT_033_TOOL_NAME
        manifest = ROOT / "evidence/manifests" / extension.EXPERIMENT_033_MANIFEST_NAME
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            source_copy = temp / source.name
            manifest_copy = temp / manifest.name
            source_copy.write_bytes(source.read_bytes())
            manifest_copy.write_bytes(manifest.read_bytes())
            imported: dict[str, object] = {}
            real_import = extension._import_033

            def replace_after_hash(data, path, digest):
                path = Path(path)
                path.write_bytes(b"path-replaced-after-hash")
                imported["module"] = real_import(data, path, digest)
                return imported["module"]

            with mock.patch.object(extension, "_import_033", side_effect=replace_after_hash):
                pinned, _manifest, _hashes = extension.load_pinned_033(tool_033_path=source_copy, manifest_033_path=manifest_copy)
            self.assertIs(imported["module"], pinned)
            self.assertEqual(pinned.EXPERIMENT_ID, "033-dcb-residual-memory-frontier")
            self.assertEqual(source_copy.read_bytes(), b"path-replaced-after-hash")

            bad = temp / "bad.py"
            bad.write_bytes(b"x")
            with mock.patch.object(extension, "_import_033", side_effect=AssertionError("imported before hash failure")):
                with self.assertRaises(extension.ExtensionError):
                    extension.load_pinned_033(tool_033_path=bad, manifest_033_path=manifest_copy)


class DecoderAndGateTests(unittest.TestCase):
    def test_exact_dispatch_fields_and_table(self):
        dispatch = extension.inspect_site35_dispatch(ORIGINAL_IMAGE)
        self.assertEqual(dispatch["raw_words"], {
            "0x1484f9f0": "0xb94027e9",
            "0x1484f9f4": "0x7100113f",
            "0x1484f9f8": "0x54000d28",
            "0x1484f9fc": "0xb0fffea5",
            "0x1484fa00": "0x9133c0a5",
            "0x1484fa04": "0xf86978a1",
            "0x1484fa08": "0xd61f0020",
        })
        self.assertEqual(dispatch["call_result_load"], {"operation": "LDR", "width": "W", "rt": 9, "rn": 31, "offset": 36, "address_mode": "UNSIGNED_IMMEDIATE", "writeback": False, "zero_extend_to_x": True})
        self.assertEqual(dispatch["cmp"]["rn"], 9)
        self.assertEqual(dispatch["cmp"]["rd"], 31)
        self.assertEqual(dispatch["cmp"]["immediate"], 4)
        self.assertEqual(dispatch["guard"]["condition"], 8)
        self.assertEqual(dispatch["guard"]["target"], extension.SITE_EXPANDED_END_EXCLUSIVE)
        self.assertEqual(dispatch["adrp"]["target"], 0x14824000)
        self.assertEqual(dispatch["add"]["immediate"], 0xCF0)
        self.assertEqual(dispatch["table_load"]["rt"], 1)
        self.assertEqual(dispatch["table_load"]["rn"], 5)
        self.assertEqual(dispatch["table_load"]["rm"], 9)
        self.assertEqual(dispatch["table_load"]["option"], 3)
        self.assertEqual(dispatch["table_load"]["scale"], 1)
        self.assertEqual(dispatch["branch"], {"operation": "BR", "rn": 1})
        self.assertNotIn("W9", dispatch["fallthrough_definitions"][extension.fmt(extension.CMP_VA)])
        table = extension._validate_table(ORIGINAL_IMAGE)
        self.assertEqual(table["base"], "0x14824cf0")
        self.assertEqual(table["file_offset"], "0x0000bcf0")
        self.assertEqual(table["segment"], {"vaddr_start": "0x1481c000", "vaddr_end_exclusive": "0x1486add8", "flags": 5, "kind": "RX"})
        self.assertEqual(table["bytes_sha256"], extension.TABLE_BYTES_SHA256)
        self.assertEqual([row["target"] for row in table["entries"]], [extension.fmt(value) for value in extension.TABLE_ENTRIES])
        self.assertEqual([row["target_word"] for row in table["entries"]], ["0xf94002e3", "0xf94017ef", "0xf94017e7", "0xf94017e1", "0xf94017e1"])
        self.assertEqual(table["duplicate_target_multiplicity"]["0x1484fa0c"], 2)

    def test_direct_b_encodings_and_range(self):
        for target, word in extension.EXPECTED_DIRECT_BRANCH_WORDS.items():
            self.assertEqual(extension.encode_b(extension.BR_VA, target), word)
            self.assertEqual(extension.decode_b(word, extension.BR_VA), target)
        with self.assertRaises(extension.ExtensionError):
            extension.encode_b(extension.BR_VA + 2, extension.TABLE_ENTRIES[0])
        with self.assertRaises(extension.ExtensionError):
            extension.encode_b(extension.BR_VA, extension.BR_VA + (1 << 27))

    def test_wrong_sequence_gates_fail_closed(self):
        cases = {
            "wrong guard condition": mutate_word(FIRMWARE, extension.GUARD_VA, 0x54000D29),
            "wrong guard target": mutate_word(FIRMWARE, extension.GUARD_VA, 0x54000D08),
            "wrong compare bound": mutate_word(FIRMWARE, extension.CMP_VA, 0x7100153F),
            "wrong compare source": mutate_word(FIRMWARE, extension.CMP_VA, 0x7100115F),
            "wrong compare width": mutate_word(FIRMWARE, extension.CMP_VA, 0xF100113F),
            "w9 redefinition": mutate_word(FIRMWARE, extension.ADD_VA, 0xD2800009),
            "wrong adrp destination": mutate_word(FIRMWARE, extension.ADRP_VA, 0xB0FFFEA6),
            "wrong add base": mutate_word(FIRMWARE, extension.ADD_VA, 0x9133C0C5),
            "wrong table index": mutate_word(FIRMWARE, extension.TABLE_LOAD_VA, 0xF86978A2),
            "wrong table scale": mutate_word(FIRMWARE, extension.TABLE_LOAD_VA, 0xF86968A1),
            "wrong table load width": mutate_word(FIRMWARE, extension.TABLE_LOAD_VA, 0xB86978A1),
            "wrong branch destination": mutate_word(FIRMWARE, extension.BR_VA, 0xD61F0040),
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(extension.ExtensionError):
                    extension.inspect_site35_dispatch(DECODER.Image(data))

    def test_every_one_bit_dispatch_mutation_fails_closed(self):
        dispatch = extension.inspect_site35_dispatch(ORIGINAL_IMAGE)
        for va_text, word_text in dispatch["raw_words"].items():
            va = int(va_text, 16)
            word = int(word_text, 16)
            for bit in range(32):
                with self.subTest(va=va_text, bit=bit):
                    with self.assertRaises(extension.ExtensionError):
                        extension.inspect_site35_dispatch(WordOverlayImage(ORIGINAL_IMAGE, va, word ^ (1 << bit)))

    def test_wrong_table_identity_or_locality_fails_closed(self):
        changed = bytearray(FIRMWARE)
        offset = ORIGINAL_IMAGE.file_offset(extension.TABLE_BASE)
        assert offset is not None
        changed[offset] ^= 1
        with self.assertRaises(extension.ExtensionError):
            extension._validate_table(DECODER.Image(bytes(changed)))
        changed = bytearray(FIRMWARE)
        target_offset = ORIGINAL_IMAGE.file_offset(extension.TABLE_BASE)
        assert target_offset is not None
        struct.pack_into("<Q", changed, target_offset, 0x1484FB9C)
        changed_bytes = bytes(changed)
        table_bytes = DECODER.Image(changed_bytes).slice(extension.TABLE_BASE, extension.TABLE_BASE + extension.TABLE_BYTE_LENGTH)
        with mock.patch.object(extension, "TABLE_BYTES_SHA256", extension.sha256(table_bytes)):
            with self.assertRaises(extension.ExtensionError):
                extension._validate_table(DECODER.Image(changed_bytes))
        with mock.patch.object(extension, "TABLE_BASE", extension.TABLE_BASE + 1):
            with self.assertRaises(extension.ExtensionError):
                extension._validate_table(ORIGINAL_IMAGE)
        with mock.patch.object(ORIGINAL_IMAGE, "slice", side_effect=ValueError("truncated")):
            with self.assertRaises(extension.ExtensionError):
                extension._validate_table(ORIGINAL_IMAGE)
        original_segment_for = ORIGINAL_IMAGE.segment_for
        with mock.patch.object(ORIGINAL_IMAGE, "segment_for", side_effect=lambda va: original_segment_for(va) if va == extension.TABLE_BASE else None):
            with self.assertRaises(extension.ExtensionError):
                extension._validate_table(ORIGINAL_IMAGE)
        changed = bytearray(FIRMWARE)
        duplicate_offset = ORIGINAL_IMAGE.file_offset(extension.TABLE_BASE)
        assert duplicate_offset is not None
        struct.pack_into("<Q", changed, duplicate_offset + 4 * 8, extension.TABLE_ENTRIES[0])
        changed_bytes = bytes(changed)
        table_bytes = DECODER.Image(changed_bytes).slice(extension.TABLE_BASE, extension.TABLE_BASE + extension.TABLE_BYTE_LENGTH)
        with mock.patch.object(extension, "TABLE_BYTES_SHA256", extension.sha256(table_bytes)):
            with self.assertRaises(extension.ExtensionError):
                extension._validate_table(DECODER.Image(changed_bytes))

    def test_bounded_guard_scope_rejects_direct_bypass_edge(self):
        scope = extension._validate_bounded_guard_scope(DEPENDENCY_033)
        self.assertEqual(scope["direct_guard_bypass_edge_count"], 0)
        self.assertEqual(scope["external_or_unmodeled_entries"], "UNKNOWN_NOT_CLAIMED")
        mutated = copy.deepcopy(DEPENDENCY_033)
        site35 = next(row for row in mutated["sites"] if row["site_index"] == 35)
        site35["branch_edges"].append({"va": "0x1484f960", "kind": "B", "target": "0x1484fa04"})
        with self.assertRaises(extension.ExtensionError):
            extension._validate_bounded_guard_scope(mutated)

    def test_source_unavailable_fails_closed(self):
        with mock.patch.dict(extension.ARM_PRIMARY_SOURCE, {"access_status": "UNKNOWN"}):
            with self.assertRaises(extension.ExtensionError):
                extension.inspect_site35_dispatch(ORIGINAL_IMAGE)


class SyntheticResolutionTests(unittest.TestCase):
    def test_each_unique_target_has_independent_direct_b_result(self):
        resolution = extension.resolve_site35(ANALYZER, DEPENDENCY_033, FIRMWARE)
        self.assertEqual(resolution["table"]["entry_count"], 5)
        self.assertEqual(resolution["table"]["unique_target_count"], 4)
        self.assertEqual(resolution["table"]["duplicate_target_multiplicity"]["0x1484fa0c"], 2)
        observed = {row["target"]: row["measured"] for row in resolution["synthetic_targets"]}
        self.assertEqual(observed, {
            "0x1484fa0c": {"cfg_complete": True, "unsupported_forms": [], "discriminators": ["NO_TARGET_WITHIN_MODEL"], "cfg_states_visited": 186, "target_observation_count": 7, "handled_form_count": 19, "direct_guard_bypass_edge_count": 0},
            "0x1484fa3c": {"cfg_complete": True, "unsupported_forms": [], "discriminators": ["NO_TARGET_WITHIN_MODEL"], "cfg_states_visited": 181, "target_observation_count": 5, "handled_form_count": 19, "direct_guard_bypass_edge_count": 0},
            "0x1484fa50": {"cfg_complete": True, "unsupported_forms": [], "discriminators": ["NO_TARGET_WITHIN_MODEL"], "cfg_states_visited": 190, "target_observation_count": 6, "handled_form_count": 20, "direct_guard_bypass_edge_count": 0},
            "0x1484fa88": {"cfg_complete": True, "unsupported_forms": [], "discriminators": ["NO_TARGET_WITHIN_MODEL"], "cfg_states_visited": 212, "target_observation_count": 10, "handled_form_count": 23, "direct_guard_bypass_edge_count": 0},
        })
        self.assertTrue(resolution["aggregate"]["all_cfg_complete"])
        self.assertTrue(resolution["aggregate"]["all_unsupported_forms_empty"])
        self.assertTrue(resolution["aggregate"]["all_discriminators_exact_no_target"])
        self.assertEqual(resolution["aggregate"]["dcb_consumer_path_count"], 0)
        self.assertEqual(resolution["aggregate"]["mc_or_shrm_symbolic_target_count"], 0)
        self.assertEqual(resolution["resolver_status"], "PROVED_BOUNDED_DIRECT_BRANCH_SUBSTITUTION_NO_TARGET")
        expected_byte_differences = {
            "0x1484fa0c": (3, [0, 2, 3]),
            "0x1484fa3c": (3, [0, 2, 3]),
            "0x1484fa50": (3, [0, 2, 3]),
            "0x1484fa88": (2, [2, 3]),
        }
        synthetic_hashes = set()
        for row in resolution["synthetic_targets"]:
            count, indices = expected_byte_differences[row["target"]]
            self.assertEqual(row["replacement"]["replacement_width_bytes"], 4)
            self.assertEqual(row["replacement"]["changed_byte_count"], count)
            self.assertEqual(row["replacement"]["changed_byte_indices_within_word"], indices)
            self.assertEqual(row["replacement"]["original_image_sha256"], extension.XBL_SHA256)
            self.assertRegex(row["replacement"]["synthetic_image_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotEqual(row["replacement"]["synthetic_image_sha256"], extension.XBL_SHA256)
            synthetic_hashes.add(row["replacement"]["synthetic_image_sha256"])
        self.assertEqual(len(synthetic_hashes), 4)

    def test_replacement_changes_only_the_br_word(self):
        synthetic, replacement = extension._replace_br(FIRMWARE, DECODER, 0x1484FA50)
        offset = ORIGINAL_IMAGE.file_offset(extension.BR_VA)
        assert offset is not None
        self.assertEqual(replacement, 0x14000012)
        self.assertEqual(synthetic[:offset], FIRMWARE[:offset])
        self.assertEqual(synthetic[offset + 4:], FIRMWARE[offset + 4:])
        self.assertEqual(struct.unpack_from("<I", synthetic, offset)[0], replacement)
        self.assertEqual(FIRMWARE, XBL_PATH.read_bytes())
        with self.assertRaises(extension.ExtensionError):
            extension._replace_br(FIRMWARE, DECODER, extension.SITE_EXPANDED_END_EXCLUSIVE)


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not MANIFEST_PATH.exists():
            raise unittest.SkipTest("checked Experiment 034 manifest is not generated yet")
        cls.manifest_bytes = MANIFEST_PATH.read_bytes()
        cls.manifest = json.loads(cls.manifest_bytes)

    def test_combined_counts_baseline_identity_and_boundaries(self):
        manifest = self.manifest
        self.assertEqual(manifest["schema"], extension.SCHEMA)
        self.assertEqual(manifest["experiment_id"], extension.EXPERIMENT_ID)
        self.assertEqual(manifest["classification"], extension.CLASSIFICATION)
        self.assertEqual(manifest["device_access"], "none")
        self.assertEqual(manifest["eligibility"], "NOT_ELIGIBLE")
        analysis = manifest["analysis"]
        self.assertEqual(analysis["discriminator_counts"], {"DCB_CONSUMER_PATH": 0, "INDIRECT_OR_UNSUPPORTED": 0, "MC_OR_SHRM_SYMBOLIC_TARGET": 0, "NO_TARGET_WITHIN_MODEL": 71})
        self.assertEqual(analysis["combined_outcome"]["fail_closed_site_count"], 0)
        self.assertEqual(analysis["reached_blocker_events"], [])
        self.assertEqual(analysis["resolved_baseline_blocker_event_count"], 1)
        self.assertEqual(len(analysis["baseline_033"]["reached_blocker_events"]), 1)
        self.assertEqual(analysis["transition_quadrants"]["counts"], {
            "032_INDIRECT_OR_UNSUPPORTED_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
            "032_INDIRECT_OR_UNSUPPORTED_TO_034_NO_TARGET_WITHIN_MODEL": 16,
            "032_NO_TARGET_WITHIN_MODEL_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
            "032_NO_TARGET_WITHIN_MODEL_TO_034_NO_TARGET_WITHIN_MODEL": 55,
        })
        self.assertEqual(analysis["actual_delta_vs_033"]["sites_transitioned_to_no_target_within_034_model"], 1)
        self.assertEqual(analysis["actual_delta_vs_033"]["stable_no_target_sites"], 70)
        self.assertEqual(analysis["transition_quadrants_vs_033"]["counts"], {
            "033_INDIRECT_OR_UNSUPPORTED_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
            "033_INDIRECT_OR_UNSUPPORTED_TO_034_NO_TARGET_WITHIN_MODEL": 1,
            "033_NO_TARGET_WITHIN_MODEL_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
            "033_NO_TARGET_WITHIN_MODEL_TO_034_NO_TARGET_WITHIN_MODEL": 70,
        })
        self.assertEqual(analysis["site35_resolution"]["aggregate"]["unique_target_count"], 4)
        self.assertTrue(analysis["baseline_033_identity"]["baseline_site35_retained"])
        self.assertTrue(analysis["baseline_033_identity"]["non_site35_exact_full_record_equality"])
        self.assertTrue(analysis["baseline_033_identity"]["all_baseline_records_exact_full_record_equality"])
        self.assertEqual(analysis["baseline_033_identity"]["non_site35_count"], 70)
        self.assertEqual(len(manifest["sites"]), 71)
        self.assertEqual(next(row for row in manifest["sites"] if row["site_index"] == 35)["discriminators"], ["INDIRECT_OR_UNSUPPORTED"])
        self.assertEqual(manifest["scope"]["firmware_mutation"], "IN_MEMORY_COPY_ONLY_BR_WORD_AT_0x1484fa08")
        self.assertEqual(manifest["scope"]["top_level_sites_semantics"], "VERBATIM_BASELINE_033_ONLY_NOT_COMBINED_034_SITE_OUTCOMES")
        self.assertFalse(manifest["scope"]["writer_absence_claim"])
        text = self.manifest_bytes.decode()
        self.assertNotIn("evidence/private", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("raw firmware bytes", text.lower())

    def test_deterministic_generation_and_no_clobber(self):
        first = extension.build_manifest()
        second = extension.build_manifest()
        encoded_first = (json.dumps(first, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
        encoded_second = (json.dumps(second, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
        self.assertEqual(encoded_first, encoded_second)
        self.assertEqual(encoded_first, self.manifest_bytes)
        # Exact 0644 is asserted for the freshly published file below.  Git
        # does not preserve those exact non-executable bits on checkout.
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            extension.write_no_clobber(path, b"{}\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                extension.write_no_clobber(path, b"changed\n")


if __name__ == "__main__":
    unittest.main()
