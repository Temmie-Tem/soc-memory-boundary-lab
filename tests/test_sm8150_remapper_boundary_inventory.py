from __future__ import annotations

import hashlib
import struct
import unittest

from tools import sm8150_remapper_boundary_inventory as boundary
from tools.xbl_dcb_inventory import LoadSegment


class Sm8150RemapperBoundaryInventoryTests(unittest.TestCase):
    def test_boot_log_selects_exact_dcb_and_topology(self) -> None:
        record = (
            b"S - Chip Revision @ 0x01fc8000 = 0x60030202\n"
            b"B - CDT Version:3,Platform ID:8,Major ID:1,Minor ID:0,Subtype:1\n"
            b"B - Rank 0 size = 3072 MB, Rank 1 size = 3072 MB\n"
            b"qcom-llcc-pmu: Registered llcc_pmu\n"
            b"print_xpu_info: START\n"
            b"tz log is encrypted or not parsed yet!\n"
        )
        parsed = boundary.parse_boot_evidence(record + record)
        self.assertEqual(
            parsed["dcb_selector"]["selected_name"],
            "/6003_0200_1_dcb.bin",
        )
        self.assertEqual(parsed["dram_topology"]["total_mib"], 6144)
        self.assertEqual(parsed["dram_topology"]["present_rank_mask"], "0x3")
        self.assertEqual(parsed["chip_revision"]["occurrences"], 2)
        self.assertTrue(
            parsed["post_boot_fabric_evidence"][
                "xpu_report_encrypted_or_unparsed"
            ]
        )

    def test_boot_log_rejects_conflicting_repeated_identity(self) -> None:
        data = (
            b"Chip Revision @ 0x01fc8000 = 0x60030202\n"
            b"Chip Revision @ 0x01fc8000 = 0x60030102\n"
            b"CDT Version:3,Platform ID:8,Major ID:1,Minor ID:0,Subtype:1\n"
            b"Rank 0 size = 3072 MB, Rank 1 size = 3072 MB\n"
        )
        with self.assertRaisesRegex(ValueError, "conflicting retained values"):
            boundary.parse_boot_evidence(data)

    def test_remapper_row_selection_is_unique(self) -> None:
        rows = [
            {
                "index": 6,
                "channel_rank_mask": "0x1",
                "total_mib": 6144,
                "region0_base": "0x80000000",
                "region1_base": "0x0",
            },
            {
                "index": 7,
                "channel_rank_mask": "0x3",
                "total_mib": 6144,
                "region0_base": "0x80000000",
                "region1_base": "0x140000000",
            },
        ]
        selected = boundary.select_remapper_row(rows, 3, 6144)
        self.assertEqual(selected["index"], 7)
        duplicate = [rows[1], dict(rows[1])]
        with self.assertRaisesRegex(ValueError, "expected one remapper row"):
            boundary.select_remapper_row(duplicate, 3, 6144)

    def test_layout1_schema_covers_control_and_six_slots(self) -> None:
        schema = boundary.layout1_register_schema(6)
        offsets = [int(record["offset"], 16) for record in schema]
        self.assertEqual(offsets, list(range(0, 0x5C, 4)))
        self.assertEqual(schema[0]["role"], "control")
        self.assertEqual(schema[1]["role"], "slot0_end_low32")
        self.assertEqual(schema[-1]["role"], "slot5_end_high4")
        self.assertEqual(schema[-1]["stored_value_mask"], "0x0000000f")

    def test_tz_xpu_parser_selects_primary_24_byte_record(self) -> None:
        file_offset = 0x100
        virtual_address = 0x1C100000
        file_size = 0x800
        data = bytearray(file_offset + file_size)
        segment = LoadSegment(
            0,
            file_offset,
            virtual_address,
            virtual_address,
            file_size,
            file_size,
            6,
            0x1000,
        )

        def put(vaddr: int, value: bytes) -> None:
            offset = file_offset + vaddr - virtual_address
            data[offset : offset + len(value)] = value

        name_vaddr = virtual_address + 0x80
        record_vaddr = virtual_address + 0x180
        secondary_vaddr = virtual_address + 0x280
        put(name_vaddr, b"BIMC_MPU0\0")
        put(record_vaddr, struct.pack("<QQQ", 0x2E, 0x0924E000, name_vaddr))
        # A second name-pointer reference exists in the real TZ image, but it is
        # not the primary <id, base, name> record and must be filtered out.
        put(
            secondary_vaddr,
            struct.pack("<QQQQ", record_vaddr, 0x403, name_vaddr, 0),
        )

        parsed = boundary.parse_tz_xpu_registry(
            bytes(data), [segment], names=("BIMC_MPU0",)
        )
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["resource_id"], "0x2e")
        self.assertEqual(parsed[0]["base"], "0x0924e000")
        self.assertEqual(
            parsed[0]["record_virtual_address"], f"0x{record_vaddr:x}"
        )

    def test_artifact_pin_rejects_size_and_hash_mismatch(self) -> None:
        data = b"exact"
        valid = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.assertTrue(
            boundary.verify_pinned_bytes("sample", data, valid)["pin_verified"]
        )
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            boundary.verify_pinned_bytes(
                "sample", data, {"size": len(data) + 1, "sha256": valid["sha256"]}
            )
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            boundary.verify_pinned_bytes(
                "sample", data, {"size": len(data), "sha256": "0" * 64}
            )


if __name__ == "__main__":
    unittest.main()
