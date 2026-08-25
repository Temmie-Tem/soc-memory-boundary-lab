from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from tools import independent_claim_audit as audit


def synthetic_elf(segments: list[tuple[int, int, bytes]]) -> bytes:
    """Build a minimal ELF64 whose program headers describe (offset, vaddr, body)."""
    phoff = 0x40
    phnum = len(segments)
    header = bytearray(phoff)
    header[0:4] = b"\x7fELF"
    struct.pack_into("<Q", header, 0x20, phoff)
    struct.pack_into("<H", header, 0x38, phnum)

    table = bytearray()
    for offset, vaddr, body in segments:
        entry = bytearray(56)
        struct.pack_into("<II", entry, 0, 1, 5)
        struct.pack_into("<QQQQQ", entry, 8, offset, vaddr, vaddr, len(body), len(body))
        table += entry

    end = max(offset + len(body) for offset, _vaddr, body in segments)
    image = bytearray(max(end, phoff + len(table)))
    image[0:phoff] = header
    image[phoff : phoff + len(table)] = table
    for offset, _vaddr, body in segments:
        image[offset : offset + len(body)] = body
    return bytes(image)


def load(data: bytes) -> audit.Image:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "synthetic.bin"
        path.write_bytes(data)
        return audit.Image(path)


class SegmentMappingTests(unittest.TestCase):
    def test_vaddr_and_offset_roundtrip(self) -> None:
        image = load(synthetic_elf([(0x200, 0x10000000, b"\xaa" * 0x100)]))
        self.assertEqual(image.to_vaddr(0x200), 0x10000000)
        self.assertEqual(image.to_vaddr(0x2FF), 0x100000FF)
        self.assertEqual(image.to_offset(0x10000000), 0x200)
        self.assertEqual(image.to_offset(0x100000FF), 0x2FF)

    def test_addresses_outside_any_segment_are_unmapped(self) -> None:
        image = load(synthetic_elf([(0x200, 0x10000000, b"\xaa" * 0x10)]))
        self.assertIsNone(image.to_vaddr(0x400))
        self.assertIsNone(image.to_offset(0x20000000))


class AArch64DecoderTests(unittest.TestCase):
    def test_adrp_recovers_the_exact_page_observed_in_trustzone(self) -> None:
        # 0x1c0a2630: 90000408  adrp x8, 0x1c122000
        self.assertEqual(audit._decode_adrp(0x90000408, 0x1C0A2630), (8, 0x1C122000))
        # 0x1c0a9a54: d0000448  adrp x8, 0x1c133000
        self.assertEqual(audit._decode_adrp(0xD0000448, 0x1C0A9A54), (8, 0x1C133000))

    def test_non_adrp_words_are_rejected(self) -> None:
        self.assertIsNone(audit._decode_adrp(audit.AARCH64_RET, 0x1000))
        self.assertIsNone(audit._decode_adrp(0xF9454908, 0x1000))


class XtensaDecoderTests(unittest.TestCase):
    def test_slli_by_twelve_matches_the_exact_helper_encoding(self) -> None:
        fields = audit._xtensa_rrr(bytes.fromhex("409911"))
        self.assertEqual(fields["op0"], 0)
        self.assertEqual(fields["op1"], 1)
        shift = 32 - (((fields["op2"] & 1) << 4) | fields["t"])
        self.assertEqual(shift, 12)
        self.assertEqual(fields["r"], 9)
        self.assertEqual(fields["s"], 9)

    def test_addx4_matches_the_exact_helper_encoding(self) -> None:
        fields = audit._xtensa_rrr(bytes.fromhex("90cca0"))
        self.assertEqual(fields["op0"], 0)
        self.assertEqual(fields["op1"], 0)
        self.assertEqual(fields["op2"], 0xA)
        self.assertEqual((fields["r"], fields["s"], fields["t"]), (12, 12, 9))

    def test_addx4_addend_is_the_slli_destination(self) -> None:
        slli = audit._xtensa_rrr(bytes.fromhex("409911"))
        addx4 = audit._xtensa_rrr(bytes.fromhex("90cca0"))
        self.assertEqual(addx4["t"], slli["r"])


class RegionRecordTests(unittest.TestCase):
    def region(self, index: int, flags: int, rd: int, wr: int, start: int, end: int) -> bytes:
        return struct.pack("<4I", index, flags, rd, wr) + struct.pack("<2Q", start, end)

    def test_region_fields_are_read_at_the_documented_stride(self) -> None:
        body = self.region(10, 9, 0, 0, 0x0FFFFFFF, 0x0FFFFFFF)
        body += self.region(11, 9, 0x80000000, 0x00000000, 0x09248000, 0x09249000)
        image = load(synthetic_elf([(0x200, 0x10000000, body)]))
        record = audit._read_region(image, 0x200, 1)
        self.assertEqual(record["index"], 11)
        self.assertEqual(record["read_access_word"], 0x80000000)
        self.assertEqual(record["write_access_word"], 0x00000000)
        self.assertEqual(record["start"], 0x09248000)
        self.assertEqual(record["end_exclusive"], 0x09249000)
        self.assertTrue(record["start"] <= 0x09248080 < record["end_exclusive"])


class RegistryRecordTests(unittest.TestCase):
    def test_registry_record_binds_name_to_identifier_and_base(self) -> None:
        name = b"DC_NOC_BROADCAST_MPU\x00"
        name_vaddr = 0x10000000
        record_vaddr = 0x10000100
        body = bytearray(0x200)
        body[0:len(name)] = name
        struct.pack_into("<QQQ", body, 0x100, 0x3C, 0x090E0000, name_vaddr)
        image = load(synthetic_elf([(0x200, 0x10000000, bytes(body))]))
        self.assertEqual(image.to_vaddr(0x200), name_vaddr)
        self.assertEqual(image.to_vaddr(0x300), record_vaddr)
        self.assertEqual(
            audit._registry_record(image, b"DC_NOC_BROADCAST_MPU"), (0x3C, 0x090E0000)
        )

    def test_absent_name_yields_no_record(self) -> None:
        image = load(synthetic_elf([(0x200, 0x10000000, b"\x00" * 0x100)]))
        self.assertIsNone(audit._registry_record(image, b"DC_NOC_BROADCAST_MPU"))


class CheckVerdictTests(unittest.TestCase):
    def test_confirm_and_fail_set_the_expected_verdicts(self) -> None:
        check = audit.Check("n", "claim", "source")
        self.assertEqual(check.verdict, "UNKNOWN")
        check.confirm(value=1)
        self.assertEqual(check.verdict, "CONFIRMED")
        self.assertEqual(check.observed["value"], 1)

        other = audit.Check("n", "claim", "source")
        other.fail("reason", value=2)
        self.assertEqual(other.verdict, "MISMATCH")
        self.assertIn("reason", other.notes)

    def test_manifest_classification_tracks_mismatches(self) -> None:
        image = load(synthetic_elf([(0x200, 0x10000000, b"\x00" * 0x10)]))
        passing = audit.Check("a", "c", "s").confirm()
        failing = audit.Check("b", "c", "s").fail("bad")

        clean = audit.build_manifest(image, image, [passing])
        self.assertEqual(
            clean["classification"], "INDEPENDENT_AUDIT_ALL_CHECKED_CLAIMS_CONFIRMED"
        )
        self.assertEqual(clean["summary"]["checks_mismatched"], 0)

        dirty = audit.build_manifest(image, image, [passing, failing])
        self.assertEqual(dirty["classification"], "INDEPENDENT_AUDIT_MISMATCH_PRESENT")
        self.assertEqual(dirty["summary"]["checks_mismatched"], 1)

    def test_manifest_records_host_only_posture(self) -> None:
        image = load(synthetic_elf([(0x200, 0x10000000, b"\x00" * 0x10)]))
        manifest = audit.build_manifest(image, image, [audit.Check("a", "c", "s").confirm()])
        self.assertFalse(manifest["device_access"])
        self.assertFalse(manifest["smc_access"])
        self.assertFalse(manifest["mmio_access"])
        self.assertFalse(manifest["firmware_bytes_emitted"])
        self.assertEqual(manifest["auditor"]["reused_modules"], [])


if __name__ == "__main__":
    unittest.main()
