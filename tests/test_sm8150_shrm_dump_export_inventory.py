from __future__ import annotations

import struct
import unittest

from tools import sm8150_shrm_dump_export_inventory as inventory


class AArch64DecoderTests(unittest.TestCase):
    def test_primary_loop_adrp_and_add_recover_table(self) -> None:
        register, page = inventory._decode_aarch64_adrp(0xD0000249, 0x14917CA8)
        rd, rn, immediate = inventory._decode_aarch64_add_immediate(0x911CC129)
        self.assertEqual((register, page), (9, 0x14961000))
        self.assertEqual((rd, rn, immediate), (9, 9, 0x730))
        self.assertEqual(page + immediate, inventory.PRIMARY_TABLE_VADDR)

    def test_primary_loop_compare_recovers_record_count(self) -> None:
        self.assertEqual(
            inventory._decode_aarch64_compare_immediate(0xF1006B7F), (27, 0x1A)
        )

    def test_bl_call_chain_targets(self) -> None:
        self.assertEqual(
            inventory._decode_aarch64_bl(0x9400529F, 0x14902CC4), 0x14917740
        )
        self.assertEqual(
            inventory._decode_aarch64_bl(0x94000139, 0x1491777C), 0x14917C60
        )
        self.assertEqual(
            inventory._decode_aarch64_bl(0x97FFFE65, 0x14917CDC), 0x14917670
        )


class XtensaDecoderTests(unittest.TestCase):
    def test_both_l32r_encodings_resolve_one_workspace_literal(self) -> None:
        self.assertEqual(
            inventory._decode_xtensa_l32r(bytes.fromhex("413cfe"), 0x288A9),
            (4, 0x2819C),
        )
        self.assertEqual(
            inventory._decode_xtensa_l32r(bytes.fromhex("41e1fc"), 0x28E15),
            (4, 0x2819C),
        )

    def test_both_call0_encodings_target_the_common_helper(self) -> None:
        self.assertEqual(
            inventory._decode_xtensa_call0(bytes.fromhex("450105"), 0x288C4),
            0x2D8DC,
        )
        self.assertEqual(
            inventory._decode_xtensa_call0(bytes.fromhex("85aa04"), 0x28E30),
            0x2D8DC,
        )


class ExactImageIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = inventory.DEFAULT_XBL
        if not cls.path.exists():
            raise unittest.SkipTest("exact private XBL is unavailable")
        cls.result = inventory.analyze(cls.path.read_bytes())

    def test_exact_descriptor_is_unique_and_covers_both_snapshots(self) -> None:
        descriptor = self.result["raw_dump_descriptor"]
        self.assertEqual(descriptor["descriptor_vaddr"], "0x14961990")
        self.assertEqual(descriptor["base"], "0x09060000")
        self.assertEqual(descriptor["size"], 0x10000)
        self.assertEqual(descriptor["filename"], "SHRM_MEM.BIN")
        self.assertEqual(descriptor["index"], 19)
        self.assertTrue(descriptor["workspace_covered"])
        self.assertTrue(descriptor["snapshot_set0_covered"])
        self.assertTrue(descriptor["snapshot_set1_covered"])

    def test_exact_loop_and_call_chain_are_pinned(self) -> None:
        consumer = self.result["xbl_consumer"]
        self.assertEqual(consumer["primary_loop"]["table_vaddr"], "0x14961730")
        self.assertEqual(consumer["primary_loop"]["record_count"], 26)
        self.assertEqual(consumer["primary_loop"]["record_stride"], 32)
        self.assertEqual(
            [entry["target"] for entry in consumer["call_chain"]],
            ["0x14917740", "0x14917c60", "0x14917670"],
        )

    def test_exact_shrm_blob_has_one_base_literal_and_no_destination_literals(self) -> None:
        hits = self.result["embedded_shrm"]["direct_u32_literal_hits"]
        self.assertEqual(hits["0x25100"], ["0x2819c"])
        for value in ("0x25330", "0x259e8", "0x9065100", "0x9065330", "0x90659e8"):
            self.assertEqual(hits[value], [])
        callsites = self.result["embedded_shrm"]["section16_read_callsites"]
        self.assertEqual([entry["direction_argument"] for entry in callsites], [0, 0])
        self.assertEqual([entry["helper_target"] for entry in callsites], ["0x2d8dc"] * 2)

    def test_claim_language_does_not_promote_boot_dump_to_hlos_runtime_access(self) -> None:
        self.assertEqual(
            self.result["classification"],
            "BOOTLOADER_RAWDUMP_EXPORT_PRESENT_HLOS_RUNTIME_EXPORT_UNPROVED",
        )
        unknown = " ".join(self.result["claims"]["UNKNOWN"])
        self.assertIn("normal-boot HLOS-readable", unknown)
        self.assertIn("FMM/debug-level/token", unknown)


class ElfImageTests(unittest.TestCase):
    def test_minimal_elf_mapping_roundtrip(self) -> None:
        body = b"hello\0" + b"\xaa" * 10
        phoff = 0x40
        segment_offset = 0x100
        data = bytearray(segment_offset + len(body))
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", data, 0x20, phoff)
        struct.pack_into("<H", data, 0x36, 56)
        struct.pack_into("<H", data, 0x38, 1)
        struct.pack_into("<II", data, phoff, 1, 5)
        struct.pack_into(
            "<QQQQQ", data, phoff + 8, segment_offset, 0x1000, 0x1000, len(body), len(body)
        )
        data[segment_offset:] = body
        image = inventory.ElfImage(bytes(data))
        self.assertEqual(image.vaddr_to_offset(0x1000), segment_offset)
        self.assertEqual(image.offset_to_vaddr(segment_offset + 5), 0x1005)
        self.assertEqual(image.cstring(0x1000), "hello")


if __name__ == "__main__":
    unittest.main()
