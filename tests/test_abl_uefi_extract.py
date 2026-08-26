"""Tests for the Experiment 029A ABL UEFI extractor.

Every test builds its own synthetic image, so none needs the captured
firmware.  Two tests exist for defects that were hit while writing the tool: a
pad file's name GUID is legitimately all-`ff`, and a large file carries its
size after the header rather than inside it.
"""

from __future__ import annotations

import lzma
import struct
import unittest
import uuid

from tools import abl_uefi_extract as extract


FFS2_GUID = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3")
LZMA_GUID = uuid.UUID(extract.LZMA_CUSTOM_DECOMPRESS_GUID)


def section(section_type: int, body: bytes, header: bytes = b"") -> bytes:
    size = 4 + len(header) + len(body)
    return size.to_bytes(3, "little") + bytes([section_type]) + header + body


def pad_to(data: bytes, alignment: int) -> bytes:
    remainder = len(data) % alignment
    return data + b"\x00" * ((alignment - remainder) % alignment)


def ffs_file(file_type: int, body: bytes, name: uuid.UUID | None = None,
             large: bool = False) -> bytes:
    name_bytes = (name or uuid.uuid4()).bytes_le if name else b"\xff" * 16
    if large:
        size = 32 + len(body)
        header = (name_bytes + b"\x00\x00" + bytes([file_type, 0x01])
                  + b"\xff\xff\xff" + b"\xf8" + struct.pack("<Q", size))
    else:
        size = 24 + len(body)
        header = (name_bytes + b"\x00\x00" + bytes([file_type, 0x00])
                  + size.to_bytes(3, "little") + b"\xf8")
    return header + body


def firmware_volume(files: list[bytes], tail: int = 64) -> bytes:
    body = b""
    for entry in files:
        body = pad_to(body, 8) + entry
    body = pad_to(body, 8) + b"\xff" * tail
    length = 0x48 + len(body)
    header = (b"\x00" * 16 + FFS2_GUID.bytes_le + struct.pack("<Q", length)
              + b"_FVH" + struct.pack("<I", 0xFFFE0300)
              + struct.pack("<HHH", 0x48, 0, 0) + bytes([0x00, 0x02])
              + struct.pack("<II", 1, length) + b"\x00" * 8)
    return header + body


def elf32(payload: bytes) -> bytes:
    header = bytearray(b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"\x00" * 36)
    struct.pack_into("<I", header, 0x1C, 0x34)
    struct.pack_into("<HH", header, 0x2A, 32, 1)
    program = struct.pack("<8I", 1, 0x54, 0x9FA00000, 0x9FA00000,
                          len(payload), len(payload), 7, 0x1000)
    blob = bytes(header[:0x34]) + program
    return blob + b"\x00" * (0x54 - len(blob)) + payload


class Elf32Test(unittest.TestCase):
    def test_file_backed_load_segment_is_found(self):
        image = elf32(b"payload-bytes")
        segments = extract.elf32_loads(image)
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0]["file_offset"], 0x54)

    def test_non_elf32_is_rejected(self):
        with self.assertRaises(extract.ExtractError):
            extract.elf32_loads(b"\x7fELF\x02" + b"\x00" * 64)


class VolumeHeaderTest(unittest.TestCase):
    def test_header_fields_are_read(self):
        volume = firmware_volume([])
        header = extract.parse_fv_header(volume)
        self.assertEqual(header["header_length"], 0x48)
        self.assertEqual(header["file_system_guid"], str(FFS2_GUID).upper())
        self.assertEqual(header["length"], len(volume))

    def test_missing_signature_is_rejected(self):
        with self.assertRaises(extract.ExtractError):
            extract.parse_fv_header(b"\x00" * 128)


class FileWalkTest(unittest.TestCase):
    def test_pad_file_does_not_end_the_walk(self):
        # A pad file's name GUID is all-ff.  Terminating on an all-ff name
        # stops here and reports an empty volume, which is what happened
        # before this was fixed.
        volume = firmware_volume([
            ffs_file(0xF0, b"\x00" * 20, name=None),
            ffs_file(0x09, section(0x19, b"real-content"),
                     name=uuid.UUID(int=1)),
        ])
        files = list(extract.iter_files(volume, 0x48))
        self.assertEqual(len(files), 2)
        self.assertEqual(files[0][1], 0xF0)
        self.assertEqual(files[1][1], 0x09)

    def test_walk_ends_at_an_erased_header(self):
        volume = firmware_volume([ffs_file(0x09, b"body", name=uuid.UUID(int=2))])
        self.assertEqual(len(list(extract.iter_files(volume, 0x48))), 1)

    def test_large_file_size_is_read_from_the_extended_field(self):
        body = b"x" * 40
        volume = firmware_volume([ffs_file(0x09, body, name=uuid.UUID(int=3),
                                           large=True)])
        files = list(extract.iter_files(volume, 0x48))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0][3], 32)
        self.assertEqual(files[0][4], body)

    def test_oversized_file_is_refused(self):
        volume = bytearray(firmware_volume([
            ffs_file(0x09, b"body", name=uuid.UUID(int=4))]))
        volume[0x48 + 20:0x48 + 23] = (len(volume) * 4).to_bytes(3, "little")
        self.assertEqual(list(extract.iter_files(bytes(volume), 0x48)), [])


class SectionWalkTest(unittest.TestCase):
    def test_sections_are_four_byte_aligned(self):
        stream = pad_to(section(0x19, b"abc"), 4) + section(0x15, b"d\x00")
        found = [(t, len(s)) for _, t, s in extract.iter_sections(stream)]
        self.assertEqual([t for t, _ in found], [0x19, 0x15])

    def test_truncated_section_is_refused(self):
        self.assertEqual(list(extract.iter_sections(b"\x40\x00\x00\x19")), [])


class DecompressTest(unittest.TestCase):
    def _guided(self, payload: bytes) -> bytes:
        header = LZMA_GUID.bytes_le + struct.pack("<HH", 0x18, 0x01)
        return section(0x02, payload, header)

    def test_lzma_section_round_trips(self):
        plain = b"the quick brown fox " * 64
        blob = lzma.compress(plain, format=lzma.FORMAT_ALONE)
        section_guid, out = extract.decompress_guided(self._guided(blob))
        self.assertEqual(section_guid, extract.LZMA_CUSTOM_DECOMPRESS_GUID)
        self.assertEqual(out, plain)

    def test_unknown_declared_size_is_accepted(self):
        # The alone format's all-ff size marker is a valid stream, not a
        # mismatch, and rejecting it would refuse legitimate input.
        plain = b"content" * 32
        blob = lzma.compress(plain, format=lzma.FORMAT_ALONE)
        self.assertEqual(struct.unpack_from("<Q", blob, 5)[0],
                         extract.UNKNOWN_SIZE)
        _, out = extract.decompress_guided(self._guided(blob))
        self.assertEqual(out, plain)

    def test_exact_declared_size_is_accepted(self):
        plain = b"content" * 32
        blob = bytearray(lzma.compress(plain, format=lzma.FORMAT_ALONE))
        struct.pack_into("<Q", blob, 5, len(plain))
        _, out = extract.decompress_guided(self._guided(bytes(blob)))
        self.assertEqual(out, plain)

    def test_short_decode_against_a_declared_size_is_an_error(self):
        # A stream whose declared size disagrees with its content is rejected
        # by the decoder before this check can see it, so the check is
        # exercised directly: it exists to catch a decoder that returns fewer
        # bytes than the header promised without raising.
        plain = b"content" * 32
        blob = bytearray(lzma.compress(plain, format=lzma.FORMAT_ALONE))
        struct.pack_into("<Q", blob, 5, len(plain))
        guided = self._guided(bytes(blob))
        original = extract.lzma.decompress
        extract.lzma.decompress = lambda *a, **k: plain[:-1]
        try:
            with self.assertRaises(extract.ExtractError):
                extract.decompress_guided(guided)
        finally:
            extract.lzma.decompress = original

    def test_unknown_guid_yields_no_payload(self):
        header = uuid.UUID(int=9).bytes_le + struct.pack("<HH", 0x18, 0x01)
        section_guid, out = extract.decompress_guided(section(0x02, b"data", header))
        self.assertEqual(out, b"")
        self.assertNotEqual(section_guid, extract.LZMA_CUSTOM_DECOMPRESS_GUID)


class ExtractTest(unittest.TestCase):
    def _image(self) -> bytes:
        inner = firmware_volume([
            ffs_file(0xF0, b"\x00" * 16, name=None),
            ffs_file(0x09,
                     pad_to(section(0x15, "Loader\x00".encode("utf-16-le")), 4)
                     + section(0x10, b"PE32-BODY" * 8),
                     name=uuid.UUID(int=11)),
        ])
        stream = section(0x17, inner)
        blob = lzma.compress(stream, format=lzma.FORMAT_ALONE)
        header = LZMA_GUID.bytes_le + struct.pack("<HH", 0x18, 0x01)
        outer = firmware_volume([
            ffs_file(0x0B, section(0x02, blob, header), name=uuid.UUID(int=10)),
        ])
        return elf32(outer)

    def test_nested_volume_and_module_are_recovered(self):
        result = extract.extract(self._image())
        self.assertEqual(len(result["volumes"]), 2)
        self.assertEqual(result["volumes"][1]["files"], 2)
        names = [m["name"] for m in result["modules"]]
        self.assertIn("Loader", names)

    def test_extracted_bytes_are_plain(self):
        result = extract.extract(self._image())
        module = next(v for k, v in result["blobs"].items() if k.endswith("PE32"))
        self.assertIn(b"PE32-BODY", module)

    def test_depth_limit_is_enforced(self):
        with self.assertRaises(extract.ExtractError):
            extract.extract(self._image(), max_depth=0)


if __name__ == "__main__":
    unittest.main()
