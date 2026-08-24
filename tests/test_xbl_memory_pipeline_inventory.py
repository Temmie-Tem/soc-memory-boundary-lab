from __future__ import annotations

import struct
import unittest

from tools import xbl_dcb_inventory as dcb
from tools import xbl_memory_pipeline_inventory as pipeline


def valid_dcb(marker: bytes) -> bytes:
    block = bytearray(dcb.DCB_SIZE)
    used_size = dcb.DCB_HEADER_SIZE + len(marker)
    struct.pack_into("<III", block, 0, 0, used_size, dcb.REQUIRED_DSF_VERSION)
    struct.pack_into(
        "<HH",
        block,
        0x0C + 16 * 4,
        dcb.DCB_HEADER_SIZE,
        len(marker),
    )
    block[dcb.DCB_HEADER_SIZE : used_size] = marker
    return bytes(block)


def synthetic_cfgl() -> bytes:
    names = (
        "/6003_0100_1_dcb.bin",
        "/6003_0100_0_dcb.bin",
        "/6003_0200_1_dcb.bin",
        "/6003_0200_0_dcb.bin",
    )
    payload_offset = 0xB0
    size = payload_offset + len(names) * dcb.DCB_SIZE
    data = bytearray(size)
    data[:4] = pipeline.CFGL_MAGIC
    struct.pack_into("<BBH", data, 4, 1, 1, len(names))
    struct.pack_into("<I", data, 8, payload_offset)
    for index, name in enumerate(names):
        descriptor = pipeline.CFGL_HEADER_SIZE + index * pipeline.CFGL_ENTRY_STRIDE
        relative = payload_offset + index * dcb.DCB_SIZE
        encoded = name.encode("ascii")
        struct.pack_into("<III", data, descriptor, relative, dcb.DCB_SIZE, len(encoded))
        data[descriptor + 12 : descriptor + 12 + len(encoded)] = encoded
        data[relative : relative + dcb.DCB_SIZE] = valid_dcb(bytes([index + 1]))
    return bytes(data)


class XblMemoryPipelineInventoryTests(unittest.TestCase):
    def test_djb2_matches_exact_xbl_device_hash(self) -> None:
        self.assertEqual(pipeline.djb2("/dev/icbcfg/boot"), 0x8DFE53C3)

    def test_cfgl_binds_selector_names_to_payloads(self) -> None:
        parsed = pipeline.inventory_dcb_descriptors(synthetic_cfgl())
        self.assertEqual(len(parsed["entries"]), 4)
        self.assertEqual(
            parsed["entries"][0]["name"], "/6003_0100_1_dcb.bin"
        )
        self.assertEqual(
            parsed["entries"][2]["selector"],
            {
                "hardware_id": "0x6003",
                "hardware_version": "0x0200",
                "physical_platform": 1,
            },
        )
        self.assertEqual(parsed["entries"][3]["section16"]["size"], 1)

    def test_layout1_offsets_cover_control_and_six_slots(self) -> None:
        offsets = pipeline.layout1_register_offsets(6)
        self.assertEqual(offsets[0], 0)
        self.assertEqual(offsets[-1], 0x58)
        self.assertEqual(offsets, list(range(0, 0x5C, 4)))

    def test_virtual_address_mapping_rejects_unbacked_range(self) -> None:
        segment = pipeline.LoadSegment(0, 0x100, 0x2000, 0x2000, 0x20, 0x20, 5, 4)
        self.assertEqual(pipeline.vaddr_to_file_offset([segment], 0x2008, 4), 0x108)
        self.assertEqual(pipeline.file_offset_to_vaddr([segment], 0x110, 4), 0x2010)
        with self.assertRaisesRegex(ValueError, "not file-backed"):
            pipeline.vaddr_to_file_offset([segment], 0x201F, 2)

    def test_parse_icb_property_follows_dal_structure_pointer(self) -> None:
        base_vaddr = 0x1481C000
        file_offset = 0x1000
        file_size = 0xB0000
        data = bytearray(file_offset + file_size)
        segment = pipeline.LoadSegment(
            0,
            file_offset,
            base_vaddr,
            base_vaddr,
            file_size,
            file_size,
            6,
            0x1000,
        )

        def put(vaddr: int, value: bytes) -> None:
            offset = pipeline.vaddr_to_file_offset([segment], vaddr, len(value))
            data[offset : offset + len(value)] = value

        propbin = 0x14823000
        structs = 0x14824000
        devices = 0x14825000
        path = 0x1481D000
        root = 0x14826000
        record_pointers = 0x14826020
        record = 0x14826100
        register_bases = 0x14826200

        put(path, pipeline.ICB_PROPERTY_PATH.encode() + b"\0")
        put(
            pipeline.ICB_PROPERTY_SOURCE_VADDR,
            struct.pack("<QQI4xQ", propbin, structs, 1, devices),
        )
        device = bytearray(pipeline.ICB_DEVICE_ENTRY_SIZE)
        struct.pack_into(
            "<QII",
            device,
            0,
            path,
            pipeline.djb2(pipeline.ICB_PROPERTY_PATH),
            0x100,
        )
        put(devices, bytes(device))

        put(propbin + 4, struct.pack("<I", 0x20))
        put(propbin + 0x30, pipeline.ICB_PROPERTY_NAME.encode() + b"\0")
        put(
            propbin + 0x100,
            struct.pack("<II", (pipeline.ICB_STRUCT_POINTER_TYPE << 24) | 0x10, 0),
        )
        put(structs, struct.pack("<I4xQ", 8, root))
        put(root, struct.pack("<I4xQ", 1, record_pointers))
        put(record_pointers, struct.pack("<Q", record))

        record_data = bytearray(0x50)
        struct.pack_into("<I", record_data, 0, 0x56)
        struct.pack_into("<II", record_data, 0x18, 6, 4)
        struct.pack_into("<II", record_data, 0x20, 36, 1)
        struct.pack_into("<Q", record_data, 0x28, register_bases)
        put(record, bytes(record_data))
        put(
            register_bases,
            struct.pack("<QQQQ", 0x9248080, 0x92C8080, 0x9348080, 0x93C8080),
        )

        parsed = pipeline.parse_icb_property(bytes(data), [segment])
        self.assertEqual(parsed["property"]["name"], "icbcfg_info")
        selected = parsed["records"][0]
        self.assertEqual(selected["mapping_slot_count"], 6)
        self.assertEqual(selected["layout1_max_touched_offset"], "0x58")
        self.assertEqual(
            selected["register_bases"][0]["qhs_llcc_window"], "0x09240000"
        )

    def test_parse_tz_crosscheck_finds_matching_separate_record(self) -> None:
        base_vaddr = 0x1C100000
        file_offset = 0x1000
        file_size = 0x50000
        data = bytearray(file_offset + file_size)
        segment = pipeline.LoadSegment(
            0,
            file_offset,
            base_vaddr,
            base_vaddr,
            file_size,
            file_size,
            6,
            0x1000,
        )

        def put(vaddr: int, value: bytes) -> None:
            offset = pipeline.vaddr_to_file_offset([segment], vaddr, len(value))
            data[offset : offset + len(value)] = value

        path = 0x1C110000
        device = 0x1C111000
        base_table = 0x1C120000
        record = 0x1C120100
        put(path, pipeline.ICB_PROPERTY_PATH.encode() + b"\0")
        put(
            device,
            struct.pack(
                "<QII",
                path,
                pipeline.djb2(pipeline.ICB_PROPERTY_PATH),
                0xEEC,
            ),
        )
        put(
            base_table,
            struct.pack("<QQQQ", 0x9248080, 0x92C8080, 0x9348080, 0x93C8080),
        )
        record_data = bytearray(0x50)
        struct.pack_into("<I", record_data, 0, 0x56)
        struct.pack_into("<I", record_data, 8, 0x10000)
        struct.pack_into("<II", record_data, 0x18, 6, 4)
        struct.pack_into("<II", record_data, 0x20, 36, 1)
        struct.pack_into("<Q", record_data, 0x28, base_table)
        put(record, bytes(record_data))

        parsed = pipeline.parse_tz_icb_crosscheck(bytes(data), [segment])
        self.assertEqual(parsed["device_entry_virtual_address"], "0x1c111000")
        self.assertEqual(parsed["record_virtual_address"], "0x1c120100")
        self.assertEqual(parsed["register_bases"][3], "0x093c8080")


if __name__ == "__main__":
    unittest.main()
