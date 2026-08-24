from __future__ import annotations

import hashlib
import struct
import unittest

from tools import sm8150_xpu_policy_inventory as xpu
from tools.xbl_dcb_inventory import LoadSegment
from tools.xbl_memory_pipeline_inventory import djb2


BASE = 0x100000


def one_segment(data: bytes) -> list[LoadSegment]:
    return [
        LoadSegment(
            0,
            0,
            BASE,
            BASE,
            len(data),
            len(data),
            6,
            0x1000,
        )
    ]


class Sm8150XpuPolicyInventoryTests(unittest.TestCase):
    def test_registry_parser_reads_counted_records(self) -> None:
        data = bytearray(0x1000)
        table = BASE + 0x100
        count = BASE + 0x180
        name0 = BASE + 0x200
        name1 = BASE + 0x220
        struct.pack_into("<I", data, count - BASE, 2)
        struct.pack_into("<QQQ", data, table - BASE, 0x2E, 0x0924E000, name0)
        struct.pack_into(
            "<QQQ", data, table - BASE + 24, 0x3C, 0x090E0000, name1
        )
        data[name0 - BASE : name0 - BASE + 10] = b"BIMC_MPU0\0"
        data[name1 - BASE : name1 - BASE + 21] = b"DC_NOC_BROADCAST_MPU\0"

        records = xpu.parse_xpu_registry(
            bytes(data), one_segment(data), table, count, expected_count=2
        )
        self.assertEqual(records[0]["name"], "BIMC_MPU0")
        self.assertEqual(records[1]["resource_id"], 0x3C)
        self.assertEqual(records[1]["base"], 0x090E0000)

    def test_policy_descriptor_layout_is_40_bytes(self) -> None:
        data = bytearray(0x1000)
        table = BASE + 0x100
        struct.pack_into(
            "<QHHII4xH6xQ",
            data,
            table - BASE,
            0x090E0000,
            0x3C,
            1,
            0,
            0,
            40,
            BASE + 0x400,
        )
        record = xpu.parse_policy_descriptors(
            bytes(data), one_segment(data), table, 1
        )[0]
        self.assertEqual(record["resource_id"], 0x3C)
        self.assertEqual(record["region_count"], 40)
        self.assertEqual(record["region_vaddr"], BASE + 0x400)

    def test_critical_region_is_end_exclusive(self) -> None:
        region = {
            "start": 0x09248000,
            "end_exclusive": 0x09249000,
        }
        self.assertTrue(xpu.region_contains(region, 0x09248000))
        self.assertTrue(xpu.region_contains(region, 0x09248080))
        self.assertFalse(xpu.region_contains(region, 0x09249000))

    def test_exact_critical_permission_decode_excludes_hlos(self) -> None:
        decoded = xpu.decode_mpu_region_permissions(
            {
                "flags": 0x09,
                "read_vmid": 0x80000000,
                "write_vmid": 0,
            }
        )
        self.assertEqual(decoded["owner"], "TZ")
        self.assertEqual(decoded["multi_vmid_permission_words"], [
            "0x00000000",
            "0x00000000",
        ])
        self.assertEqual(decoded["client_permission_bytes"], ["0x11", "0x08"])
        self.assertFalse(decoded["hlos_present_in_read_mask"])
        self.assertFalse(decoded["hlos_present_in_write_mask"])
        self.assertTrue(decoded["read_bit31_maps_to_same_ro_slot_as_msa_owner"])

    def test_error_router_parser_resets_bit_number_per_bank(self) -> None:
        data = bytearray(0x1000)
        table = BASE + 0x100
        data[0x100:0x108] = bytes((0, 0x2E, 1, 0x2F, 0, 0x4D, 1, 0x3C))
        records = xpu.parse_error_router(
            bytes(data), one_segment(data), table, bank_sizes=(2, 2)
        )
        self.assertEqual(
            [(item["bank"], item["bit"], item["resource_id"]) for item in records],
            [(0, 0, 0x2E), (0, 1, 0x2F), (1, 0, 0x4D), (1, 1, 0x3C)],
        )

    def test_dal_uint32_property_value_zero(self) -> None:
        data = bytearray(0x1000)
        source = BASE + 0x40
        propbin = BASE + 0x300
        struct_table = BASE + 0x600
        device_table = BASE + 0x500
        path_vaddr = BASE + 0x700
        property_offset = 0x80
        property_vaddr = propbin + property_offset
        property_name_offset = 0x20

        struct.pack_into("<QQ", data, source - BASE, propbin, struct_table)
        struct.pack_into("<I", data, source - BASE + 0x10, 1)
        struct.pack_into("<Q", data, source - BASE + 0x18, device_table)
        data[path_vaddr - BASE : path_vaddr - BASE + 8] = b"/ac/xpu\0"
        struct.pack_into(
            "<QII",
            data,
            device_table - BASE,
            path_vaddr,
            djb2("/ac/xpu"),
            property_offset,
        )
        struct.pack_into("<I", data, propbin - BASE + 4, 0x20)
        name_vaddr = propbin + 0x20 + property_name_offset
        data[name_vaddr - BASE : name_vaddr - BASE + 15] = b"disable_xpu_ac\0"
        struct.pack_into(
            "<III",
            data,
            property_vaddr - BASE,
            (xpu.DAL_UINT32_PROPERTY_TYPE << 24) | property_name_offset,
            0,
            xpu.DAL_PROPERTY_END_MARKER,
        )

        result = xpu.parse_dal_u32_property(
            bytes(data), one_segment(data), source_vaddr=source
        )
        self.assertEqual(result["property_name"], "disable_xpu_ac")
        self.assertEqual(result["value"], 0)
        self.assertEqual(result["device_hash"], djb2("/ac/xpu"))

    def test_artifact_pin_rejects_size_and_hash_mismatch(self) -> None:
        data = b"exact"
        valid = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.assertTrue(xpu.verify_pinned_bytes("sample", data, valid)["pin_verified"])
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            xpu.verify_pinned_bytes(
                "sample", data, {"size": len(data) + 1, "sha256": valid["sha256"]}
            )
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            xpu.verify_pinned_bytes(
                "sample", data, {"size": len(data), "sha256": "0" * 64}
            )


if __name__ == "__main__":
    unittest.main()
