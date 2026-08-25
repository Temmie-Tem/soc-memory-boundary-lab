"""Tests for the Experiment 022 observation-coverage measure.

Arithmetic and structural tests use synthetic inputs. Tests that need the exact
Experiment 004 XBL and the live SHRM dump skip when they are absent.
"""

from __future__ import annotations

import struct
import shutil
import tempfile
import unittest
import json
from unittest import mock
from pathlib import Path

from tools import sm8150_observation_coverage as coverage


def build_elf64(vaddr: int, payload: bytes) -> bytes:
    ph_offset, ph_entry = 64, 56
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<Q", header, 32, ph_offset)
    struct.pack_into("<H", header, 54, ph_entry)
    struct.pack_into("<H", header, 56, 1)
    body_start = ph_offset + ph_entry
    table = struct.pack(
        "<IIQQQQQQ", 1, 5, body_start, vaddr, vaddr, len(payload), len(payload), 0x1000
    )
    return bytes(header) + table + payload


class TableParsingTests(unittest.TestCase):
    def test_reads_until_the_zero_terminator(self):
        payload = struct.pack("<QQQQ", 0x09260400, 0x09260404, 0, 0x09260408)
        data = build_elf64(coverage.MC_TABLE_VADDR, payload)
        self.assertEqual(coverage.xbl_mc_table(data), [0x09260400, 0x09260404])

    def test_raises_when_the_table_is_not_mapped(self):
        data = build_elf64(0x1000, struct.pack("<Q", 0))
        with self.assertRaises(coverage.CoverageError):
            coverage.xbl_mc_table(data)

    def test_an_empty_table_is_an_empty_list(self):
        data = build_elf64(coverage.MC_TABLE_VADDR, struct.pack("<Q", 0))
        self.assertEqual(coverage.xbl_mc_table(data), [])


class CoverageArithmeticTests(unittest.TestCase):
    def test_a_dense_run_is_full_span_coverage(self):
        addresses = {0x09260000 + 4 * i for i in range(4)}
        row = coverage.coverage_by_block(addresses, {"c": addresses})[0]
        self.assertEqual(row["observed_span_word_slots"], 4)
        self.assertEqual(row["observed_span_address_density_percent"], 100.0)

    def test_two_far_apart_addresses_give_a_wide_span(self):
        addresses = {0x09260000, 0x09260000 + 4 * 999}
        row = coverage.coverage_by_block(addresses, {"c": addresses})[0]
        self.assertEqual(row["observed_span_word_slots"], 1000)
        self.assertEqual(row["observed_span_address_density_percent"], 0.2)

    def test_block_coverage_uses_the_word_slot_denominator(self):
        addresses = {0x09260000 + 4 * i for i in range(coverage.WORD_SLOTS_PER_BLOCK)}
        row = coverage.coverage_by_block(addresses, {"c": addresses})[0]
        self.assertEqual(row["full_64k_word_slot_density_percent"], 100.0)

    def test_addresses_are_split_across_blocks(self):
        addresses = {0x09260000, 0x092E0000, 0x092E0004}
        rows = coverage.coverage_by_block(addresses, {"c": addresses})
        self.assertEqual([r["block"] for r in rows], ["0x09260000", "0x092e0000"])
        self.assertEqual([r["observed"] for r in rows], [1, 2])

    def test_per_channel_counts_are_reported(self):
        first = {0x09260000}
        second = {0x09260004}
        rows = coverage.coverage_by_block(first | second, {"a": first, "b": second})
        self.assertEqual(rows[0]["by_channel"], {"a": 1, "b": 1})

    def test_ranked_blocks_are_flagged(self):
        rows = coverage.coverage_by_block({0x09260000, 0x09220000}, {"c": {0x09260000, 0x09220000}})
        flags = {r["block"]: r["is_ranked_instance"] for r in rows}
        self.assertTrue(flags["0x09260000"])
        self.assertFalse(flags["0x09220000"])


class RankedSummaryTests(unittest.TestCase):
    def test_reports_which_ranked_offsets_are_in_the_sample(self):
        addresses = {0x09260000 + off for off in (0x400, 0x4D0)}
        summary = coverage.ranked_instance_summary(addresses)
        self.assertEqual(
            summary["per_instance"]["0x09260000"]["ranked_offsets_observed"], ["0x400", "0x4d0"]
        )

    def test_an_instance_with_no_observation_is_zero(self):
        summary = coverage.ranked_instance_summary({0x09260000})
        empty = summary["per_instance"]["0x092e0000"]
        self.assertEqual(empty["observed"], 0)
        self.assertEqual(empty["observed_span_address_density_percent"], 0.0)

    def test_totals_use_all_four_instances(self):
        summary = coverage.ranked_instance_summary({0x09260000, 0x092E0000})
        self.assertEqual(summary["total_observed"], 2)
        self.assertEqual(summary["total_addressable_word_slots"], 4 * coverage.WORD_SLOTS_PER_BLOCK)


class ExactArtifactTests(unittest.TestCase):
    """These need the private Experiment 004 XBL and the live SHRM dump."""

    @classmethod
    def setUpClass(cls):
        if not (coverage.FIRMWARE_DIR / coverage.XBL_NAME).exists() or not coverage.SHRM_DUMP.exists():
            raise unittest.SkipTest("exact artifacts are not present")
        cls.manifest = coverage.build_manifest(coverage.FIRMWARE_DIR, coverage.SHRM_DUMP)

    def test_refuses_a_directory_without_the_exact_image(self):
        with self.assertRaises(coverage.CoverageError):
            coverage.load_xbl(Path("/nonexistent-firmware-dir"))

    def test_xbl_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            mutated = directory / coverage.XBL_NAME
            data = (coverage.FIRMWARE_DIR / coverage.XBL_NAME).read_bytes()
            mutated.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            with self.assertRaises(coverage.CoverageError):
                coverage.load_xbl(directory)

    def test_both_channels_contribute(self):
        channels = self.manifest["channels"]
        self.assertGreater(channels["shrm_snapshot_union"], 0)
        self.assertGreater(channels["xbl_mc_table"], 0)
        self.assertEqual(
            channels["union"],
            channels["shrm_snapshot_union"] + channels["xbl_table_addresses_new_to_the_snapshot"],
        )

    def test_ranked_instance_span_coverage_is_below_one_percent(self):
        for entry in self.manifest["ranked_instances"]["per_instance"].values():
            self.assertLess(entry["observed_span_address_density_percent"], 1.0)
            self.assertEqual(entry["full_64k_word_slot_density_percent"], 0.2563)

    def test_all_three_ranked_offsets_lie_inside_the_sample(self):
        # necessarily so: the candidates were selected from this sample
        for entry in self.manifest["ranked_instances"]["per_instance"].values():
            self.assertEqual(entry["ranked_offsets_observed"], ["0x400", "0x404", "0x4d0"])

    def test_every_block_row_is_internally_consistent(self):
        for row in self.manifest["address_density_by_block"]:
            self.assertLessEqual(row["observed"], row["observed_span_word_slots"])
            self.assertGreaterEqual(
                row["observed_span_address_density_percent"],
                row["full_64k_word_slot_density_percent"],
            )

    def test_counts_are_scoped_and_known_counterexample_refutes_completeness(self):
        self.assertEqual(
            self.manifest["channels"],
            {
                "shrm_snapshot_set0": 430,
                "shrm_snapshot_union": 470,
                "xbl_mc_table": 122,
                "union": 492,
                "xbl_table_addresses_new_to_the_snapshot": 22,
            },
        )
        counterexample = self.manifest["known_counterexample_to_completeness"]
        self.assertEqual(counterexample["address"], "0x09248080")
        self.assertFalse(counterexample["in_enumerated_union"])
        self.assertEqual(counterexample["classification"], "REFUTED")
        self.assertEqual(
            counterexample["source_manifest"], coverage.COUNTEREXAMPLE_SOURCE_MANIFEST
        )
        self.assertEqual(
            counterexample["source_manifest_sha256"],
            coverage.DEPENDENCY_MANIFESTS[coverage.COUNTEREXAMPLE_SOURCE_MANIFEST],
        )
        self.assertEqual(counterexample["source_field"], coverage.COUNTEREXAMPLE_SOURCE_FIELD)
        self.assertEqual(self.manifest["completeness_conclusion"]["global_project_nameable_set"], "UNKNOWN")
        self.assertEqual(self.manifest["true_implemented_register_coverage"]["coverage"], "UNKNOWN")
        self.assertEqual(self.manifest["ranked_instances"]["total_observed"], 168)
        self.assertEqual(
            self.manifest["ranked_instances"]["full_64k_word_slot_density_percent"], 0.2563
        )
        claims = self.manifest["claims"]
        self.assertIn("enumerated channels only", " ".join(claims["PROVED"]))
        self.assertIn("cannot establish global absence", " ".join(claims["UNKNOWN"]))
        self.assertEqual(self.manifest["candidate_follow_up"]["classification"], "HYPOTHESIS")

    def test_shrm_dump_pin_is_exact(self):
        pin = self.manifest["shrm_dump"]
        self.assertEqual(pin["name"], "SHRM_MEM.BIN")
        self.assertEqual(pin["size"], 65536)
        self.assertEqual(pin["sha256"], coverage.SHRM_DUMP_SHA256)

    def test_shrm_dump_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            mutated = Path(temp) / coverage.SHRM_DUMP_NAME
            data = coverage.SHRM_DUMP.read_bytes()
            mutated.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            with self.assertRaises(coverage.CoverageError):
                coverage.shrm_snapshot_addresses(mutated)

    def test_dependency_hash_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in coverage.DEPENDENCY_MANIFESTS:
                shutil.copy2(coverage.MANIFEST_DIR / name, directory / name)
            target = directory / next(iter(coverage.DEPENDENCY_MANIFESTS))
            target.write_bytes(target.read_bytes() + b"mutation")
            with self.assertRaises(coverage.CoverageError):
                coverage.dependency_manifest_hashes(directory)

    def test_counterexample_source_missing_address_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in coverage.DEPENDENCY_MANIFESTS:
                shutil.copy2(coverage.MANIFEST_DIR / name, directory / name)
            source = directory / coverage.COUNTEREXAMPLE_SOURCE_MANIFEST
            document = json.loads(source.read_text(encoding="utf-8"))
            document["ddr_remapper"]["icb_property"]["records"][0]["register_bases"][0][
                "address"
            ] = "0xdeadbeef"
            source.write_text(json.dumps(document), encoding="utf-8")
            expected_hash = coverage.sha256(source.read_bytes())
            with mock.patch.dict(
                coverage.DEPENDENCY_MANIFESTS,
                {coverage.COUNTEREXAMPLE_SOURCE_MANIFEST: expected_hash},
            ):
                with self.assertRaises(coverage.CoverageError):
                    coverage.counterexample_provenance(directory)

    def test_decoder_hash_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            mutated = Path(temp) / "shrm_dump_decode.py"
            data = coverage.SHRM_DECODER_PATH.read_bytes()
            mutated.write_bytes(data + b"mutation")
            with self.assertRaises(coverage.CoverageError):
                coverage.dependency_file_hashes(mutated)

    def test_decoder_dependency_is_output_and_exactly_pinned(self):
        self.assertEqual(
            self.manifest["dependency_files"],
            {coverage.SHRM_DECODER_NAME: coverage.SHRM_DECODER_SHA256},
        )

    def test_output_is_no_clobber_and_nofollow(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            output = directory / "manifest.json"
            coverage.write_manifest(output, {"ok": 1})
            with self.assertRaises(coverage.CoverageError):
                coverage.write_manifest(output, {"ok": 2})
            link = directory / "link.json"
            link.symlink_to(output)
            with self.assertRaises(coverage.CoverageError):
                coverage.write_manifest(link, {"ok": 3}, force=True)

    def test_manifest_carries_no_raw_bytes_or_private_paths(self):
        blob = repr(self.manifest)
        self.assertNotIn("evidence/private", blob)
        self.assertNotIn("/home/", blob)


if __name__ == "__main__":
    unittest.main()
