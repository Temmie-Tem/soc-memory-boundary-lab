"""Focused tests for the complete MPU region coverage walk.

The tool exists because absence-of-address claims were being made against five
decoded regions out of 1,726 declared.  These tests hold it to the standard the
claim it replaces failed: the answer must come from the data, the layout
assumption must fail loudly rather than decode noise, and the accounting must
close exactly.
"""

from __future__ import annotations

import json
import struct
import unittest
from pathlib import Path

from tools import sm8150_xpu_region_coverage as cov

REPO_ROOT = Path(__file__).resolve().parents[1]
TZ = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01/tz--sdd5.bin"

APCS_REGION = {
    "instance": "CNOC_AOSS_MPU",
    "instance_base": "0x01526000",
    "resource_id": "0x39",
    "ordinal": 5,
    "start": 0x17C00000,
    "end_exclusive": 0x18200000,
    "size": 0x600000,
    "flags": "0x9",
    "read_vmid": "0x00000000",
    "write_vmid": "0x00000000",
}


def _region(start: int, end: int, **kw) -> dict:
    base = dict(APCS_REGION)
    base.update({"start": start, "end_exclusive": end, "size": end - start})
    base.update(kw)
    return base


class ClassPartition(unittest.TestCase):
    def test_mpu_suffix_and_the_one_exception(self) -> None:
        self.assertTrue(cov.is_mpu_class("CNOC_AOSS_MPU"))
        self.assertTrue(cov.is_mpu_class("DC_NOC_BROADCAST_MPU"))
        self.assertTrue(cov.is_mpu_class("QM_MPU_CFG"))

    def test_non_mpu_classes_are_excluded(self) -> None:
        for name in ("TLMM_XPU_SOUTH", "GCC_RPU", "SEC_CTRL_APU", "BAM_BLSP1_DMA",
                     "IPA_0_GSI_TOP", "BOOT_ROM", "TCSR_MUTEX"):
            self.assertFalse(cov.is_mpu_class(name), name)


class QueryAnswering(unittest.TestCase):
    def test_containment_is_half_open(self) -> None:
        regions = [_region(0x1000, 0x2000)]
        self.assertTrue(cov.answer_query(regions, 0x1FFF, 0x2000)["covered"])
        self.assertFalse(cov.answer_query(regions, 0x2000, 0x2001)["covered"])

    def test_answer_tracks_the_data_not_a_constant(self) -> None:
        """Move the region and the apcs_glb answer must move with it."""
        present = cov.answer_query([_region(0x17C00000, 0x18200000)], 0x17C00000, 0x17C01000)
        self.assertTrue(present["covered"])
        absent = cov.answer_query([_region(0x18300000, 0x18400000)], 0x17C00000, 0x17C01000)
        self.assertFalse(absent["covered"])
        self.assertEqual([], absent["covering_regions"])

    def test_permission_fields_are_decoded_per_hit(self) -> None:
        hit = cov.answer_query([_region(0x17C00000, 0x18200000)], 0x17C00000, 0x17C01000)
        record = hit["covering_regions"][0]
        self.assertFalse(record["hlos_read"])
        self.assertFalse(record["hlos_write"])
        self.assertEqual("0x17c00000..0x18200000", record["range"])

    def test_an_hlos_granting_region_is_reported_as_such(self) -> None:
        """The negative direction must be reachable, or the field proves nothing."""
        granting = _region(0x17C00000, 0x18200000,
                           read_vmid="0x00000008", write_vmid="0x00000008")
        record = cov.answer_query([granting], 0x17C00000, 0x17C01000)["covering_regions"][0]
        self.assertNotEqual(
            (False, False), (record["hlos_read"], record["hlos_write"]),
            "no VMID pattern produces an HLOS grant; the decode is a constant",
        )


class LayoutGuard(unittest.TestCase):
    """Applying the MPU layout to a non-MPU table produced 717 bad records.

    The walk must refuse rather than publish them.
    """

    class _FakeDescriptor(dict):
        pass

    def test_implausible_end_raises(self) -> None:
        regions = [{"ordinal": 0, "flags": 9, "read_vmid": 0, "write_vmid": 0,
                    "start": 0, "end_exclusive": 0xF0FFFFFFF0FFFFFF}]
        with self.assertRaises(cov.CoverageError) as ctx:
            cov.walk_branch.__wrapped__ if False else self._walk_with(regions)
        self.assertIn("layout assumption is broken", str(ctx.exception))

    def test_inverted_range_raises(self) -> None:
        regions = [{"ordinal": 0, "flags": 9, "read_vmid": 0, "write_vmid": 0,
                    "start": 0x2000, "end_exclusive": 0x1000}]
        with self.assertRaises(cov.CoverageError):
            self._walk_with(regions)

    def test_a_plausible_record_passes(self) -> None:
        regions = [{"ordinal": 0, "flags": 9, "read_vmid": 0, "write_vmid": 0,
                    "start": 0x17C00000, "end_exclusive": 0x18200000}]
        decoded, unused, skipped = self._walk_with(regions)
        self.assertEqual(1, len(decoded))
        self.assertEqual(0, len(unused))

    def test_unused_slots_are_counted_not_decoded(self) -> None:
        """Zero width, not a magic value.  The filler differs per instance:
        0xffffffff in CFG_SSC, 0x3ffff in BOOT_ROM, 0xfffffff in PMIC_ARB."""
        for filler in (cov.UNUSED_SLOT_MARKER, 0x3FFFF, 0xFFFFFFF, 0x0):
            regions = [{"ordinal": 0, "flags": 9, "read_vmid": 0, "write_vmid": 0,
                        "start": filler, "end_exclusive": filler}]
            decoded, unused, _ = self._walk_with(regions)
            self.assertEqual([], decoded, f"filler 0x{filler:x} decoded as a region")
            self.assertEqual(1, len(unused))

    def test_a_zero_width_entry_can_never_answer_a_query(self) -> None:
        """V025 counted 60 of these as regions; a zero-width span protects
        nothing and must not be able to cover an address."""
        zero = _region(0x17C00000, 0x17C00000)
        self.assertFalse(cov.answer_query([zero], 0x17C00000, 0x17C01000)["covered"])

    def _walk_with(self, records):
        original = cov.parse_mpu_regions
        cov.parse_mpu_regions = lambda *a, **k: records
        try:
            descriptors = [{"name": "CNOC_AOSS_MPU", "base": 0x1526000,
                            "resource_id": 0x39, "region_count": len(records),
                            "region_vaddr": 0x1000}]
            return cov.walk_branch(
                b"", [], descriptors, {"CNOC_AOSS_MPU": cov.ADDRESS_RECORD_SIZE}
            )
        finally:
            cov.parse_mpu_regions = original

    def test_slot_table_yields_slot_records_with_no_address(self) -> None:
        raw = struct.pack("<IIII", 0x0C, 0x09, 0x40000000, 0x40000000) * 3
        original = cov.read_vaddr
        cov.read_vaddr = lambda *a, **k: raw
        try:
            descriptors = [{"name": "TLMM_XPU_SOUTH", "base": 0x3C00000,
                            "resource_id": 0x36, "region_count": 3,
                            "region_vaddr": 0x1000}]
            decoded, unused, slots = cov.walk_branch(
                b"", [], descriptors, {"TLMM_XPU_SOUTH": cov.SLOT_RECORD_SIZE}
            )
        finally:
            cov.read_vaddr = original
        self.assertEqual([], decoded)
        self.assertEqual(3, len(slots))
        for record in slots:
            self.assertNotIn("start", record)
            self.assertNotIn("end_exclusive", record)
            self.assertEqual(0x0C, record["slot_index"])


class PinnedInputs(unittest.TestCase):
    def test_tz_pin_is_the_verification_009_input(self) -> None:
        self.assertEqual(
            "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab",
            cov.TZ_SHA256,
        )
        self.assertEqual(4_194_304, cov.TZ_SIZE)

    def test_pin_drift_is_refused(self) -> None:
        if not TZ.is_file():
            self.skipTest("retained TrustZone image is absent on this host")
        with self.assertRaises(cov.CoverageError):
            cov.load_pinned(TZ, "0" * 64)

    def test_control_query_is_named_and_present(self) -> None:
        self.assertIn(cov.CONTROL_QUERY, cov.QUERIES)
        self.assertEqual("qhs_llcc_remapper_page", cov.CONTROL_QUERY)


class LiveWalk(unittest.TestCase):
    """The real answer, from the real image."""

    @classmethod
    def setUpClass(cls) -> None:
        if not TZ.is_file():
            raise unittest.SkipTest("retained TrustZone image is absent on this host")
        cls.result = cov.build(TZ)

    def test_accounting_closes_in_both_branches(self) -> None:
        """Every declared record lands in exactly one bucket."""
        for name, branch in self.result["branches"].items():
            self.assertEqual(
                branch["records_declared"],
                branch["regions_decoded"]
                + branch["address_table"]["unused_slots"]
                + branch["slot_table"]["records"],
                f"{name} accounting does not close",
            )

    def test_nothing_is_left_undecoded(self) -> None:
        for branch in self.result["branches"].values():
            self.assertNotIn("not_decoded", branch)
            self.assertFalse(branch["slot_table"]["carries_addresses"])

    def test_size_classification_beats_the_name_heuristic(self) -> None:
        """CFG_SSC, BOOT_ROM and PMIC_ARB use address records despite the name."""
        for branch in self.result["branches"].values():
            names = set(branch["address_table"]["instance_names"])
            for extra in ("CFG_SSC", "BOOT_ROM", "PMIC_ARB"):
                self.assertIn(extra, names)
                self.assertFalse(cov.is_mpu_class(extra))

    def test_no_implausible_record_survives(self) -> None:
        for branch in self.result["branches"].values():
            self.assertLess(
                int(branch["highest_end_exclusive"], 16),
                cov.IMPLAUSIBLE_END,
                "an implausible range reached the reduction",
            )

    def test_control_reproduces_verification_009(self) -> None:
        for branch in self.result["branches"].values():
            control = branch["queries"]["qhs_llcc_remapper_page"]
            self.assertTrue(control["covered"])
            names = {r["instance"] for r in control["covering_regions"]}
            self.assertIn("DC_NOC_BROADCAST_MPU", names)

    def test_apcs_glb_is_covered_with_no_hlos_grant(self) -> None:
        for branch in self.result["branches"].values():
            hit = branch["queries"]["apcs_glb_mailbox"]
            self.assertTrue(hit["covered"], "apcs_glb is not covered")
            self.assertEqual(1, hit["covering_region_count"])
            record = hit["covering_regions"][0]
            self.assertEqual("CNOC_AOSS_MPU", record["instance"])
            self.assertEqual("0x17c00000..0x18200000", record["range"])
            self.assertFalse(record["hlos_read"])
            self.assertFalse(record["hlos_write"])

    def test_both_selector_branches_agree_on_every_query(self) -> None:
        for name, answers in self.result["branch_agreement"].items():
            self.assertEqual(1, len(answers), f"{name} differs between branches")

    def test_slot_records_exist_and_carry_no_address(self) -> None:
        for branch in self.result["branches"].values():
            self.assertGreater(branch["slot_table"]["records"], 1000)
            self.assertGreater(branch["slot_table"]["instances"], 15)

    def test_prior_scope_is_recorded(self) -> None:
        scope = self.result["prior_extraction_scope"]
        self.assertEqual(5, scope["regions_decoded_by_verification_009"])
        self.assertEqual(261, scope["address_records_decoded_by_verification_025"])

    def test_no_device_or_firmware_emission(self) -> None:
        self.assertFalse(self.result["device_access"])
        self.assertFalse(self.result["mmio_access"])
        self.assertFalse(self.result["firmware_bytes_emitted"])
        blob = json.dumps(self.result)
        self.assertNotIn("/home/", blob, "a private absolute path reached the output")


if __name__ == "__main__":
    unittest.main()
