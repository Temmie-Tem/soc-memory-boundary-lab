from __future__ import annotations

import unittest

from tools import sm8150_shrm_snapshot_boundary as boundary


def match(name: str, start: int, end: int, *, hlos_read: bool = False) -> dict[str, object]:
    region = {
        "ordinal": 5,
        "index": 5,
        "flags": 0x9,
        "read_vmid": 0x40000000 if name == "DC_NOC_NON_BROADCAST_MPU" else 0,
        "write_vmid": 0,
        "start": start,
        "end_exclusive": end,
        "size": end - start,
    }
    return {
        "xpu_name": name,
        "descriptor": {},
        "region": region,
        "permissions": {
            "hlos_present_in_read_mask": hlos_read,
            "hlos_present_in_write_mask": False,
        },
    }


def exact_matches() -> list[dict[str, object]]:
    return [
        match("DC_NOC_NON_BROADCAST_MPU", 0x09060000, 0x09070000),
        match("MEMNOC_MS_MPU", 0, 0x10000000),
        match("CNOC_SNOC_MS_MPU", 0x09000000, 0x09800000),
    ]


class Sm8150ShrmSnapshotBoundaryTests(unittest.TestCase):
    def test_workspace_is_bounded_to_0xf00_bytes(self) -> None:
        self.assertEqual(boundary.SHRM_WORKSPACE_START, 0x09065100)
        self.assertEqual(boundary.SHRM_WORKSPACE_END_EXCLUSIVE, 0x09066000)
        self.assertTrue(
            boundary.region_covers_workspace(
                {"start": 0x09060000, "end_exclusive": 0x09070000}
            )
        )
        self.assertFalse(
            boundary.region_covers_workspace(
                {"start": 0x09060000, "end_exclusive": 0x09065FFF}
            )
        )

    def test_exact_three_region_no_hlos_summary(self) -> None:
        result = boundary.validate_branch_matches("branch", exact_matches())
        self.assertEqual(result["covering_xpu_count"], 3)
        self.assertTrue(result["all_exclude_hlos_read"])
        self.assertTrue(result["all_exclude_hlos_write"])

    def test_hlos_grant_is_rejected(self) -> None:
        matches = exact_matches()
        matches[1]["permissions"]["hlos_present_in_read_mask"] = True
        with self.assertRaisesRegex(ValueError, "grants HLOS read"):
            boundary.validate_branch_matches("branch", matches)

    def test_missing_covering_xpu_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "covering XPUs"):
            boundary.validate_branch_matches("branch", exact_matches()[:-1])


if __name__ == "__main__":
    unittest.main()
