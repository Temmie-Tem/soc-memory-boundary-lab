"""Focused synthetic and exact-image tests for Experiment 027.

The tests exercise the decoder's fail-closed boundary.  Exact-image tests are
skipped only when the private Experiment 004 artifacts are unavailable.
"""

from __future__ import annotations

import json
import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path

from tools import sm8150_dcb_consumer_writer_complement as complement


def build_elf(segments: list[tuple[int, int, bytes, int | None]]) -> bytes:
    phoff, phentsize = 64, 56
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:7] = bytes((2, 1, 1))
    struct.pack_into("<Q", header, 32, phoff)
    struct.pack_into("<H", header, 54, phentsize)
    struct.pack_into("<H", header, 56, len(segments))
    body_start = phoff + phentsize * len(segments)
    phdrs, body = bytearray(), bytearray()
    for vaddr, flags, payload, mem_size in segments:
        file_offset = body_start + len(body)
        memory_size = len(payload) if mem_size is None else mem_size
        phdrs += struct.pack(
            "<IIQQQQQQ", 1, flags, file_offset, vaddr, vaddr,
            len(payload), memory_size, 0x1000
        )
        body += payload
    return bytes(header) + bytes(phdrs) + bytes(body)


def assemble(base: int, words: list[int], flags: int = 5) -> complement.Image:
    payload = b"".join(struct.pack("<I", word) for word in words)
    return complement.Image(build_elf([(base, flags, payload, None)]))


def adrp(va: int, rd: int, target_page: int) -> int:
    delta = ((target_page & ~0xFFF) - (va & ~0xFFF)) >> 12
    encoded = delta & 0x1FFFFF
    return 0x90000000 | ((encoded & 3) << 29) | ((encoded >> 2) << 5) | rd


def add_x(rd: int, rn: int, immediate: int) -> int:
    return 0x91000000 | ((immediate & 0xFFF) << 10) | (rn << 5) | rd


def str_w(rt: int, rn: int, offset: int = 0) -> int:
    return 0xB9000000 | ((offset // 4) << 10) | (rn << 5) | rt


def str_w_indexed(rt: int, rn: int, offset: int, mode: str) -> int:
    if mode not in {"POSTINDEX", "PREINDEX"}:
        raise ValueError(mode)
    opcode = 0xB8000400 if mode == "POSTINDEX" else 0xB8000C00
    return opcode | ((offset & 0x1FF) << 12) | (rn << 5) | rt


def str_reg_w(rt: int, rn: int, rm: int, option: int = 2, scaled: bool = False) -> int:
    # STR Wt,[Xn,Wm,UXTW{,#2}] under the exact register-offset decoder.
    return 0xB8200800 | (rm << 16) | (option << 13) | ((1 if scaled else 0) << 12) | (rn << 5) | rt


def bl(va: int, target: int) -> int:
    return 0x94000000 | (((target - va) // 4) & 0x03FFFFFF)


def cbz_w(va: int, target: int, rt: int = 0) -> int:
    return 0x34000000 | ((((target - va) // 4) & 0x7FFFF) << 5) | rt


class DecoderTests(unittest.TestCase):
    def test_mov_and_logical_masks_are_distinct(self):
        self.assertEqual(complement.is_movz(0xD2800020), ("X", 1, 0, 0))
        self.assertEqual(complement.is_movk(0xF2800040), ("X", 2, 0, 0))
        self.assertEqual(complement.is_movn(0x12800060), ("W", 3, 0, 0))
        self.assertIsNotNone(complement.is_orr_imm(0xB24003E0))
        self.assertIsNotNone(complement.is_and_imm(0x924003E0))
        self.assertIsNone(complement.is_orr_imm(0x924003E0))
        self.assertIsNone(complement.is_and_imm(0xB24003E0))

    def test_orr_invalid_shift_is_not_promoted(self):
        # ORR X0,X1,X2 with reserved shift type 3.
        self.assertIsNone(complement.is_orr_reg(0xAAE20820))

    def test_register_offset_requires_exact_extension_option(self):
        decoded = complement.is_mem_reg_offset(str_reg_w(1, 2, 3, option=2, scaled=True))
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded[0:2], ("STR", "W"))
        self.assertEqual(decoded[4:6], (2, 2))
        self.assertIsNone(complement.is_mem_reg_offset(str_reg_w(1, 2, 3, option=0, scaled=True)))

    def test_reserved_shift_widths_are_not_decoded(self):
        # W-register shifted forms have a five-bit shift range.  An imm6 with
        # bit 5 set is reserved and must not preserve any symbolic origin.
        self.assertIsNone(complement.is_add_sub_reg(0x0B000000 | (32 << 10)))
        self.assertIsNone(complement.is_orr_reg(0x2A000000 | (32 << 10)))
        # ADD/SUB (extended register) accepts only imm3 values 0..4.
        self.assertIsNone(complement.is_add_sub_ext(0x0B200000 | (2 << 13) | (5 << 10)))

    def test_address_origin_orr_requires_x_lsl_zero(self):
        base = 0x1000
        exact = 0xAA000000 | (31 << 5) | (1 << 16) | 2  # ORR X2,XZR,X1
        shifted = exact | (1 << 10)  # ORR X2,XZR,X1,LSL #1
        w_copy = 0x2A000000 | (31 << 5) | (1 << 16) | 2  # ORR W2,WZR,W1
        site = {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        for words, expected_kind in (
            ([exact, str_w(0, 2)], "DCB_SECTION"),
            ([shifted, str_w(0, 2)], "UNKNOWN"),
            ([w_copy, str_w(0, 2)], "UNKNOWN"),
        ):
            result = complement.analyze_bounded_site(assemble(base, words), site, seed_origins={1: complement.dcb_origin(7)})
            self.assertEqual(result["usable_target_observations"][0]["target_kind"], expected_kind)

    def test_w_add_and_two_address_add_do_not_preserve_dcb_pointer(self):
        base = 0x1000
        w_add = 0x11000000 | (4 << 10) | (1 << 5) | 1  # ADD W1,W1,#4
        x_add_two = 0x8B000000 | (3 << 16) | (1 << 5) | 2  # ADD X2,X1,X3
        site_w = {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result_w = complement.analyze_bounded_site(assemble(base, [w_add, str_w(0, 1)]), site_w, seed_origins={1: complement.dcb_origin(7)})
        self.assertEqual(result_w["usable_target_observations"][0]["target_kind"], "UNKNOWN")
        site_x = {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result_x = complement.analyze_bounded_site(assemble(base, [x_add_two, str_w(0, 2)]), site_x, seed_origins={1: complement.dcb_origin(7), 3: complement.dcb_origin(8)})
        self.assertEqual(result_x["usable_target_observations"][0]["target_kind"], "UNKNOWN")

    def test_movk_w_clears_old_upper_half_before_address_use(self):
        base = 0x1000
        movz_x_upper = 0xD2800000 | (0x1234 << 5) | (2 << 21) | 1
        movk_x_low = 0xF2800000 | (0x9ABC << 5) | 1
        movk_w_low = 0x72800000 | (0x5678 << 5) | 1
        image = assemble(base, [movz_x_upper, movk_x_low, movk_w_low, str_w(0, 1)])
        site = {"store_va": "0x100c", "loop_head_va": "0x1000", "back_edge_va": "0x100c"}
        result = complement.analyze_bounded_site(image, site)
        observation = result["usable_target_observations"][0]
        self.assertEqual(observation["target_kind"], "CONSTANT")
        self.assertEqual(observation["target_origin"], "0x00005678")

    def test_cfg_state_limit_fails_closed(self):
        base = 0x1000
        image = assemble(base, [add_x(1, 0, 4), str_w(0, 1)])
        site = {"store_va": "0x1004", "add_va": "0x1000"}
        result = complement.analyze_bounded_site(image, site, max_states=1)
        self.assertFalse(result["cfg_complete"])
        self.assertEqual(result["discriminators"], ["INDIRECT_OR_UNSUPPORTED"])
        self.assertIn("CFG_STATE_LIMIT_REACHED", result["unsupported_forms"])
        self.assertEqual(result["usable_target_observations"], [])


class ImageAndFlowTests(unittest.TestCase):
    def test_direct_dcb_address_target_is_not_a_consumer(self):
        base = 0x1000
        image = assemble(base, [add_x(1, 1, 4), str_w(0, 1)])
        site = {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result = complement.analyze_bounded_site(image, site, seed_origins={1: complement.dcb_origin(7)})
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertEqual(result["status"], "UNKNOWN")
        observation = result["usable_target_observations"][0]
        self.assertEqual(observation["target_kind"], "DCB_SECTION")
        self.assertEqual(observation["target_offset"], 4)
        self.assertEqual(observation["source_kind"], "ARGUMENT")

    def test_dcb_taint_propagates_through_load_and_store(self):
        base = 0x1000
        image = assemble(base, [0xB9400022, str_w(2, 3)])
        site = {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result = complement.analyze_bounded_site(image, site, seed_origins={1: complement.dcb_origin(7), 3: complement.constant(0x9000)})
        self.assertEqual(result["discriminators"], ["DCB_CONSUMER_PATH"])
        self.assertEqual(result["status"], "SUPPORTED")
        observation = result["usable_target_observations"][0]
        self.assertEqual(observation["target_kind"], "CONSTANT")
        self.assertEqual(observation["source_kind"], "DCB_DATA")
        self.assertEqual(observation["source_section"], 7)

    def test_dcb_consumer_and_mc_target_labels_are_independent(self):
        base = 0x1000
        image = assemble(base, [0xB9400022, str_w(2, 3)])
        site = {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result = complement.analyze_bounded_site(
            image,
            site,
            seed_origins={1: complement.dcb_origin(7), 3: complement.symbolic("MC_TEST", kind="MC_BASE")},
        )
        self.assertEqual(result["discriminators"], ["DCB_CONSUMER_PATH", "MC_OR_SHRM_SYMBOLIC_TARGET"])
        observation = result["usable_target_observations"][0]
        self.assertEqual(observation["target_kind"], "MC_BASE")
        self.assertEqual(observation["source_kind"], "DCB_DATA")

    def test_dcb_data_copy_is_consumer_but_clear_is_not(self):
        base = 0x1000
        copy = 0x2A000000 | (31 << 5) | (2 << 16) | 3  # ORR W3,WZR,W2
        image = assemble(base, [0xB9400022, copy, str_w(3, 4)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008"}
        result = complement.analyze_bounded_site(image, site, seed_origins={1: complement.dcb_origin(7), 4: complement.constant(0x9000)})
        self.assertEqual(result["discriminators"], ["DCB_CONSUMER_PATH"])
        self.assertEqual(result["usable_target_observations"][0]["source_kind"], "DCB_DATA")

        cleared = complement.analyze_bounded_site(
            assemble(base, [0xB9400022, bl(base + 4, base + 0x20), str_w(2, 3)]),
            {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008"},
            seed_origins={1: complement.dcb_origin(7), 3: complement.constant(0x9000)},
        )
        self.assertEqual(cleared["discriminators"], ["NO_TARGET_WITHIN_MODEL"])

    def test_proximity_hint_never_seeds_dcb_taint(self):
        base = 0x1000
        image = assemble(base, [add_x(1, 1, 4), str_w(0, 1)])
        site = {"store_va": "0x1004", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result = complement.analyze_bounded_site(image, site, section_hint=7)
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])
        self.assertNotIn("DCB_CONSUMER_PATH", result["discriminators"])

    def test_dcb_section_zero_is_not_replaced_by_hint(self):
        loaded = complement._memory_load_origin(complement.dcb_origin(0), 0, section_hint=7, va=0x1000)
        self.assertEqual(loaded.kind, "DCB_DATA")
        self.assertEqual(loaded.section, 0)

    def test_unsupported_path_blocks_other_observation_and_merges_blocked(self):
        base = 0x1000
        image = assemble(base, [cbz_w(base, base + 8), 0xFFFFFFFF, str_w(0, 1)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008"}
        result = complement.analyze_bounded_site(image, site)
        self.assertEqual(result["discriminators"], ["INDIRECT_OR_UNSUPPORTED"])
        self.assertEqual(result["usable_target_observations"], [])
        observations = [row for row in result["target_observations"] if row["va"] == "0x00001008"]
        self.assertTrue(observations)
        self.assertTrue(all(row["state_blocked"] for row in observations))

    def test_postindex_uses_old_base_then_updates_base(self):
        base = 0x1000
        image = assemble(base, [str_w_indexed(0, 1, 4, "POSTINDEX"), str_w(0, 1)])
        site = {"store_va": "0x1000", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result = complement.analyze_bounded_site(image, site, seed_origins={1: complement.dcb_origin(7)})
        observations = {row["va"]: row for row in result["usable_target_observations"]}
        self.assertEqual(observations["0x00001000"]["target_offset"], 0)
        self.assertEqual(observations["0x00001004"]["target_offset"], 4)

    def test_preindex_uses_updated_base_then_keeps_writeback(self):
        base = 0x1000
        image = assemble(base, [str_w_indexed(0, 1, 4, "PREINDEX"), str_w(0, 1)])
        site = {"store_va": "0x1000", "loop_head_va": "0x1000", "back_edge_va": "0x1004"}
        result = complement.analyze_bounded_site(image, site, seed_origins={1: complement.dcb_origin(7)})
        observations = {row["va"]: row for row in result["usable_target_observations"]}
        self.assertEqual(observations["0x00001000"]["target_offset"], 4)
        self.assertEqual(observations["0x00001004"]["target_offset"], 4)

    def test_register_offset_rm_zero_uses_x0_index(self):
        base = 0x1000
        image = assemble(base, [str_reg_w(2, 1, 0, option=2, scaled=True)])
        site = {"store_va": "0x1000"}
        result = complement.analyze_bounded_site(
            image,
            site,
            seed_origins={0: complement.constant(3), 1: complement.constant(0x9000)},
        )
        observation = result["usable_target_observations"][0]
        self.assertEqual(observation["index_register"], 0)
        self.assertEqual(observation["target_origin"], "0x0000900c")

    def test_static_target_stays_unknown_current_destination(self):
        base = 0x1000
        target = 0x9000
        image = assemble(base, [adrp(base, 1, target), add_x(1, 1, target & 0xFFF), str_w(0, 1)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008", "width": "W"}
        result = complement.analyze_bounded_site(image, site)
        self.assertEqual(result["current_destination"], "UNKNOWN")
        self.assertIn("NO_TARGET_WITHIN_MODEL", result["discriminators"])
        self.assertEqual(result["usable_target_observations"][0]["target_origin"], "0x00009000")

    def test_computed_mc_symbolic_target_is_not_current(self):
        origin = complement._classify_address_origin(complement.constant(complement.MC_APERTURE_START + 0x400), 0x2000)
        self.assertEqual(origin.kind, "MC_BASE")

    def test_unknown_instruction_blocks_claim(self):
        base = 0x1000
        image = assemble(base, [adrp(base, 1, 0x9000), 0xFFFFFFFF, str_w(0, 1)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008", "width": "W"}
        result = complement.analyze_bounded_site(image, site)
        self.assertEqual(result["discriminators"], ["INDIRECT_OR_UNSUPPORTED"])
        self.assertIn("UNRECOGNIZED_AARCH64_INSTRUCTION_OR_MEMORY_FORM", result["unsupported_forms"])

    def test_direct_bl_clears_taint(self):
        base = 0x1000
        image = assemble(base, [adrp(base, 1, 0x9000), bl(base + 4, base + 0x20), str_w(0, 1)])
        site = {"store_va": "0x1008", "loop_head_va": "0x1000", "back_edge_va": "0x1008", "width": "W"}
        result = complement.analyze_bounded_site(image, site)
        self.assertEqual(result["discriminators"], ["NO_TARGET_WITHIN_MODEL"])


class BoundaryTests(unittest.TestCase):
    def test_unknown_overlap_fails_closed(self):
        site = {"store_va": "0x2008", "loop_head_va": "0x2000", "back_edge_va": "0x2008"}
        with self.assertRaises(complement.ComplementError):
            complement.validate_site_exclusions([site], [{"start": "0x2004", "end_exclusive": "0x2010", "dependency": "026"}])

    def test_known_walker_positive_control_is_allowed_only_as_exclusion(self):
        site = {"store_va": "0x14868a50", "loop_head_va": "0x148689dc", "back_edge_va": "0x14868a5c"}
        complement.validate_site_exclusions([site], [{"start": "0x148689a0", "end_exclusive": "0x14868a64", "dependency": "024"}])

    def test_full_024_caller_contexts_are_recorded(self):
        manifests, _ = complement.load_dependency_manifests()
        ranges = complement.dependency_exclusion_ranges(manifests)
        actual = {
            (row["start"], row["end_exclusive"])
            for row in ranges
            if row["dependency"] == "024"
        }
        expected = {
            (complement.fmt(complement.WALKER_START), complement.fmt(complement.WALKER_END)),
        }
        expected.update(
            (complement.fmt(start), complement.fmt(end))
            for start, end in complement.WALKER_CALLER_CONTEXT_RANGES
        )
        self.assertTrue(expected <= actual)

    def test_full_024_caller_context_overlap_fails_closed(self):
        manifests, _ = complement.load_dependency_manifests()
        exclusions = complement.dependency_exclusion_ranges(manifests)
        start, end = complement.WALKER_CALLER_CONTEXT_RANGES[0]
        site = {"store_va": complement.fmt(start), "add_va": complement.fmt(start), "back_edge_va": complement.fmt(end - 4)}
        with self.assertRaises(complement.ComplementError):
            complement.validate_site_exclusions([site], exclusions)

    def test_reader_proximity_ties_use_lowest_reader_va(self):
        hint = complement._nearby_section_hint(0x1000, {0x0000: 10, 0x2000: 11})
        self.assertEqual(hint, {"reader_va": 0x0000, "section": 10, "signed_distance": 0x1000, "absolute_distance": 0x1000})

    def test_computed_two_instruction_shape_normalizes_without_back_edge(self):
        base = 0x1000
        image = assemble(base, [add_x(1, 0, 4), str_w(0, 1)])
        site = {"add_va": "0x1000", "store_va": "0x1004", "width": "W"}
        result = complement.analyze_bounded_site(image, site)
        self.assertEqual(result["range"], {"start": "0x00001000", "end_exclusive": "0x00001008", "size": 8})

    def test_computed_loop_metadata_merge_fails_closed_on_identity_mismatch(self):
        manifests, _ = complement.load_dependency_manifests()
        d020 = json.loads(json.dumps(manifests["020-xbl-dcb-consumer-xref-20260826-01.manifest.json"]))
        image = complement.Image(complement.load_exact(complement.FIRMWARE_DIR / complement.XBL_NAME, complement.XBL_SIZE, complement.XBL_SHA256, complement.XBL_NAME))
        d020["computed_address_store_census"]["loop_sites"][0]["add_va"] = "0x1484b994"
        with self.assertRaises(complement.ComplementError):
            complement.exact_site_sets(d020, image)

    def test_computed_loop_metadata_merge_fails_closed_on_duplicate_store(self):
        manifests, _ = complement.load_dependency_manifests()
        d020 = json.loads(json.dumps(manifests["020-xbl-dcb-consumer-xref-20260826-01.manifest.json"]))
        image = complement.Image(complement.load_exact(complement.FIRMWARE_DIR / complement.XBL_NAME, complement.XBL_SIZE, complement.XBL_SHA256, complement.XBL_NAME))
        rows = d020["computed_address_store_census"]["loop_sites"]
        rows[1]["store_va"] = rows[0]["store_va"]
        with self.assertRaises(complement.ComplementError):
            complement.exact_site_sets(d020, image)

    def test_dependency_semantic_mutation_is_rejected(self):
        manifests, _ = complement.load_dependency_manifests()
        mutated = {name: json.loads(json.dumps(value)) for name, value in manifests.items()}
        d019 = mutated["019-dcb-register-programming-20260826-01.manifest.json"]
        d019["ranked_target_reach"] = "PROVED"
        with self.assertRaises(complement.ComplementError):
            complement._validate_dependency_semantics(mutated)

    def test_public_manifest_has_no_private_path_or_raw_bytes(self):
        if not (complement.FIRMWARE_DIR / complement.XBL_NAME).exists():
            self.skipTest("exact private artifacts unavailable")
        manifest = complement.build_manifest()
        text = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("/home/", text)
        self.assertNotIn("evidence/private", text)
        self.assertNotIn("raw_bytes", text)
        self.assertFalse(manifest["scope"]["writer_absence_claim"])

    def test_public_output_is_o_excl_and_mode_0644(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            complement.write_no_clobber(path, b"{}\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                complement.write_no_clobber(path, b"changed\n")


@unittest.skipUnless((complement.FIRMWARE_DIR / complement.XBL_NAME).exists(), "exact pinned artifacts unavailable")
class ExactImageTests(unittest.TestCase):
    def test_exact_manifest_site_accounting_and_pins(self):
        manifest = complement.build_manifest()
        self.assertEqual(manifest["inputs"]["firmware"]["sha256"], complement.XBL_SHA256)
        self.assertEqual(manifest["inputs"]["dcb_image"]["sha256"], complement.DCB_SHA256)
        self.assertEqual(
            [int(block["file_offset"], 16) for block in manifest["inputs"]["dcb_image"]["blocks"]],
            list(complement.DCB_BLOCK_FILE_OFFSETS),
        )
        self.assertEqual(
            manifest["inputs"]["dcb_image"]["block_file_offsets"],
            [complement.fmt(offset) for offset in complement.DCB_BLOCK_FILE_OFFSETS],
        )
        dcb_data = complement.load_exact(complement.FIRMWARE_DIR / complement.DCB_NAME, complement.DCB_SIZE, complement.DCB_SHA256, complement.DCB_NAME)
        parsed_dcb = complement.validate_dcb_image(dcb_data)
        self.assertEqual(
            [int(block["file_offset"], 16) for block in parsed_dcb["blocks"]],
            [0x1079C, 0x13BA0, 0x16FA4, 0x1A3A8],
        )
        self.assertEqual(manifest["scope"]["register_offset_sites"], 67)
        self.assertEqual(manifest["scope"]["computed_address_idioms"], 8)
        self.assertEqual(manifest["site_summary"]["register_offset_site_count"], 65)
        self.assertEqual(manifest["site_summary"]["computed_address_site_count"], 8)
        self.assertEqual(manifest["site_summary"]["site_count"], 73)
        self.assertEqual(len(manifest["sites"]), 73)
        self.assertEqual(manifest["site_summary"]["writer_absence"], "UNKNOWN")
        self.assertEqual(manifest["site_summary"]["discriminator_counts"].get("DCB_CONSUMER_PATH", 0), 0)
        for row in manifest["sites"]:
            self.assertEqual(row["current_destination"], "UNKNOWN")
        prioritized = {row["store_va"]: row for row in manifest["sites"]}
        self.assertIn("0x1484b9a0", prioritized)
        self.assertIn("0x146aea20", prioritized)
        self.assertIn("0x9fc05ef4", prioritized)
        computed = complement.derive_computed_address_sites(
            complement.Image(complement.load_exact(
                complement.FIRMWARE_DIR / complement.XBL_NAME,
                complement.XBL_SIZE,
                complement.XBL_SHA256,
                complement.XBL_NAME,
            ))
        )
        for row in computed:
            self.assertIn(row["store_va"], prioritized)

        dependencies, _ = complement.load_dependency_manifests()
        dependency_loops = dependencies["020-xbl-dcb-consumer-xref-20260826-01.manifest.json"]["computed_address_store_census"]["loop_sites"]
        loop_stores = {row["store_va"] for row in dependency_loops}
        for row in dependency_loops:
            result = prioritized[row["store_va"]]
            self.assertEqual(result["range"]["start"], row["loop_head_va"])
            self.assertEqual(result["range"]["end_exclusive"], complement.fmt(int(row["back_edge_va"], 16) + 4))
        for row in computed:
            if row["store_va"] not in loop_stores:
                self.assertNotIn("loop_head_va", row)
                self.assertNotIn("back_edge_va", row)
                self.assertEqual(prioritized[row["store_va"]]["range"]["start"], row["add_va"])
                self.assertEqual(prioritized[row["store_va"]]["range"]["end_exclusive"], complement.fmt(int(row["store_va"], 16) + 4))
        self.assertEqual(prioritized["0x9fc05ef4"]["discriminators"], ["INDIRECT_OR_UNSUPPORTED"])
        proximity = prioritized["0x148aa758"]
        self.assertIn("SECTION_READER_PROXIMITY_ONLY", proximity["discriminators"])
        self.assertNotIn("DCB_CONSUMER_PATH", proximity["discriminators"])
        self.assertEqual(proximity["status"], "HYPOTHESIS")
        expected_proximity = {
            "0x148aa758": {"reader_va": "0x148ab138", "signed_distance": -0x9E0, "absolute_distance": 0x9E0},
            "0x148ab4f8": {"reader_va": "0x148ab138", "signed_distance": 0x3C0, "absolute_distance": 0x3C0},
        }
        actual_proximity = {
            row["store_va"]: row["dcb_identity"]
            for row in manifest["sites"]
            if "SECTION_READER_PROXIMITY_ONLY" in row["discriminators"]
        }
        self.assertEqual(set(actual_proximity), set(expected_proximity))
        for store, expected in expected_proximity.items():
            identity = actual_proximity[store]
            self.assertEqual(identity["reader_va"], expected["reader_va"])
            self.assertEqual(identity["signed_distance"], expected["signed_distance"])
            self.assertEqual(identity["absolute_distance"], expected["absolute_distance"])
            self.assertEqual(identity["threshold"], complement.fmt(complement.SECTION_READER_PROXIMITY_THRESHOLD))
            self.assertEqual(identity["section"], 10)
            self.assertEqual(identity["link_proof"], "NONE")

        checked = json.loads(
            (complement.MANIFEST_DIR / "027-dcb-consumer-writer-complement-20260826-01.manifest.json").read_bytes()
        )
        self.assertEqual(checked, manifest)

    def test_exact_setter_range_and_direct_caller(self):
        image = complement.Image(complement.load_exact(complement.FIRMWARE_DIR / complement.XBL_NAME, complement.XBL_SIZE, complement.XBL_SHA256, complement.XBL_NAME))
        setter = complement.validate_setter(image)
        self.assertEqual(setter["range"]["sha256"], complement.SETTER_SHA256)
        caller = complement.resolve_setter_caller(image)
        self.assertEqual(caller["direct_calls"][0]["target"], complement.fmt(complement.SETTER_START))
        self.assertEqual(caller["current_destination"], "UNKNOWN")
