#!/usr/bin/env python3
"""Make the exact A90 `abl` image searchable by walking its UEFI volume.

Experiment 021 measured the `abl` PT_LOAD payload at 2,293,760 bytes with
`_FVH` at payload offset 0x28 and Shannon entropy 8.000 bits/byte, and recorded
it as `NOT SEARCHABLE`.  That was the right call -- a literal search over
compressed content cannot fail informatively -- but it left one captured image
as a void rather than as evidence.  Every negative that included `abl` in its
target list was, for `abl`, vacuous.

This module removes the void.  It parses the ELF32 program headers, the
firmware volume header, the FFS file list and the section streams, and
decompresses the LZMA-wrapped inner volume, yielding plain bytes that a literal
search can actually be run against.

Two details are easy to get wrong and are handled explicitly.  A pad file's
name GUID is legitimately all-`ff`, so terminating the file walk on an all-`ff`
*name* stops at the first pad and silently reports an empty volume; the walk
terminates on a fully erased *header* instead.  And a file whose 24-bit size
field reads `0xffffff` with the large-file attribute set carries a 64-bit size
after the header, which a fixed 24-byte header would misparse.

Host-only; it never contacts the device.
"""
from __future__ import annotations

import hashlib
import lzma
import struct
import uuid

SCHEMA = "abl-uefi-extract-v1"

FV_SIGNATURE = b"_FVH"
ERASED = 0xFF
LZMA_CUSTOM_DECOMPRESS_GUID = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"
UNKNOWN_SIZE = 0xFFFFFFFFFFFFFFFF

FILE_TYPES = {
    0x01: "RAW", 0x02: "FREEFORM", 0x03: "SECURITY_CORE", 0x04: "PEI_CORE",
    0x05: "DXE_CORE", 0x06: "PEIM", 0x07: "DRIVER",
    0x08: "COMBINED_PEIM_DRIVER", 0x09: "APPLICATION", 0x0A: "SMM",
    0x0B: "FIRMWARE_VOLUME_IMAGE", 0x0C: "COMBINED_SMM_DXE",
    0x0D: "SMM_CORE", 0xF0: "FFS_PAD",
}
SECTION_TYPES = {
    0x01: "COMPRESSION", 0x02: "GUID_DEFINED", 0x03: "DISPOSABLE",
    0x10: "PE32", 0x11: "PIC", 0x12: "TE", 0x13: "DXE_DEPEX",
    0x14: "VERSION", 0x15: "USER_INTERFACE", 0x16: "COMPATIBILITY16",
    0x17: "FIRMWARE_VOLUME_IMAGE", 0x18: "FREEFORM_SUBTYPE_GUID",
    0x19: "RAW", 0x1B: "PEI_DEPEX", 0x1C: "SMM_DEPEX",
}


class ExtractError(ValueError):
    pass


def guid(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw)).upper()


def elf32_loads(data: bytes) -> list[dict]:
    """The file-backed PT_LOAD segments of a little-endian ELF32 image."""
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise ExtractError("not a little-endian ELF32 image")
    phoff, = struct.unpack_from("<I", data, 0x1C)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    segments = []
    for index in range(phnum):
        base = phoff + index * phentsize
        ptype, offset, vaddr, paddr, filesz, memsz, flags, align = \
            struct.unpack_from("<8I", data, base)
        if ptype == 1 and filesz and offset + filesz <= len(data):
            segments.append({"index": index, "file_offset": offset,
                             "vaddr": vaddr, "file_size": filesz,
                             "memory_size": memsz, "flags": flags})
    return segments


def parse_fv_header(buf: bytes, offset: int = 0) -> dict:
    if buf[offset + 0x28:offset + 0x2C] != FV_SIGNATURE:
        raise ExtractError(f"no _FVH at 0x{offset:x}")
    length, = struct.unpack_from("<Q", buf, offset + 0x20)
    header_length, = struct.unpack_from("<H", buf, offset + 0x30)
    revision = buf[offset + 0x37]
    return {"file_system_guid": guid(buf[offset + 0x10:offset + 0x20]),
            "length": length, "header_length": header_length,
            "revision": revision}


def iter_files(volume: bytes, header_length: int):
    """Yield each FFS file as (offset, type, attributes, header size, body).

    Termination is on a fully erased header.  A pad file's name GUID is
    legitimately all-`ff`, so stopping at an all-`ff` name would end the walk
    at the first pad and report an empty volume.
    """
    offset = header_length
    while offset + 24 <= len(volume):
        header = volume[offset:offset + 24]
        if all(byte == ERASED for byte in header):
            return
        file_type = header[18]
        attributes = header[19]
        size = int.from_bytes(header[20:23], "little")
        header_size = 24
        if attributes & 0x01 and size == 0xFFFFFF:
            # FFS3 large file: the real size is a 64-bit field after the
            # header, and a fixed 24-byte header would misparse it.
            size, = struct.unpack_from("<Q", volume, offset + 24)
            header_size = 32
        if size < header_size or offset + size > len(volume):
            return
        yield offset, file_type, attributes, header_size, \
            volume[offset + header_size:offset + size], header[:16]
        offset = (offset + size + 7) & ~7


def iter_sections(stream: bytes):
    """Yield each section as (offset, type, whole bytes)."""
    offset = 0
    while offset + 4 <= len(stream):
        size = int.from_bytes(stream[offset:offset + 3], "little")
        section_type = stream[offset + 3]
        if size < 4 or offset + size > len(stream):
            return
        yield offset, section_type, stream[offset:offset + size]
        offset = (offset + size + 3) & ~3


def decompress_guided(section: bytes) -> tuple[str, bytes]:
    """Decompress a GUID_DEFINED section, returning its GUID and payload."""
    section_guid = guid(section[4:20])
    data_offset, attributes = struct.unpack_from("<HH", section, 20)
    payload = section[data_offset:]
    if section_guid != LZMA_CUSTOM_DECOMPRESS_GUID:
        return section_guid, b""
    declared, = struct.unpack_from("<Q", payload, 5)
    out = lzma.decompress(payload, format=lzma.FORMAT_ALONE)
    # The alone format may leave the size unknown, which is a valid stream and
    # not a mismatch; verify only when a size is actually declared.
    if declared != UNKNOWN_SIZE and len(out) != declared:
        raise ExtractError(
            f"LZMA output {len(out)} bytes, header declared {declared}")
    return section_guid, out


def _ui_name(stream: bytes) -> str | None:
    for _, section_type, section in iter_sections(stream):
        if section_type == 0x15:
            return section[4:].decode("utf-16-le", "ignore").rstrip("\x00")
    return None


def extract(data: bytes, max_depth: int = 8) -> dict:
    """Walk the image and return every plain byte range it yields."""
    segments = elf32_loads(data)
    if not segments:
        raise ExtractError("no file-backed PT_LOAD segment")
    payload_segment = max(segments, key=lambda s: s["file_size"])
    payload = data[payload_segment["file_offset"]:
                   payload_segment["file_offset"] + payload_segment["file_size"]]

    volumes: list[dict] = []
    modules: list[dict] = []
    blobs: dict[str, bytes] = {}

    def walk_volume(buf: bytes, origin: str, depth: int) -> None:
        if depth > max_depth:
            raise ExtractError(f"volume nesting exceeded {max_depth}")
        header = parse_fv_header(buf)
        record = {"origin": origin, "depth": depth, "files": 0,
                  "bytes": len(buf), **header}
        volumes.append(record)
        for offset, file_type, _attr, _hsz, body, name in \
                iter_files(buf, header["header_length"]):
            record["files"] += 1
            label = _ui_name(body) or guid(name)
            for section_offset, section_type, section in iter_sections(body):
                if section_type == 0x02:
                    section_guid, out = decompress_guided(section)
                    if out:
                        key = f"{origin}/file@0x{offset:x}/lzma"
                        blobs[key] = out
                        walk_sections_for_volumes(out, key, depth + 1)
                elif section_type == 0x17:
                    walk_volume(section[4:], f"{origin}/file@0x{offset:x}/fv",
                                depth + 1)
                elif section_type in (0x10, 0x11, 0x12, 0x19):
                    key = f"{origin}/{label}/{SECTION_TYPES[section_type]}"
                    blobs[key] = section[4:]
                    modules.append({
                        "origin": origin, "name": label,
                        "file_type": FILE_TYPES.get(file_type, hex(file_type)),
                        "section_type": SECTION_TYPES[section_type],
                        "bytes": len(section) - 4,
                        "sha256": hashlib.sha256(section[4:]).hexdigest(),
                    })

    def walk_sections_for_volumes(buf: bytes, origin: str, depth: int) -> None:
        """A decompressed payload is a section stream, not a bare volume."""
        for offset, section_type, section in iter_sections(buf):
            if section_type == 0x17:
                walk_volume(section[4:], f"{origin}/fv@0x{offset:x}", depth)

    walk_volume(payload, "abl", 0)
    return {
        "schema": SCHEMA,
        "image_sha256": hashlib.sha256(data).hexdigest(),
        "image_bytes": len(data),
        "pt_load": payload_segment,
        "volumes": volumes,
        "modules": modules,
        "blobs": blobs,
    }


def main(argv: list[str]) -> int:
    import argparse
    import json
    import pathlib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True, help="manifest path")
    parser.add_argument("--dump-dir", help="write extracted blobs here")
    args = parser.parse_args(argv)

    result = extract(pathlib.Path(args.image).read_bytes())
    blobs = result.pop("blobs")
    result["extracted"] = {name: {"bytes": len(data),
                                  "sha256": hashlib.sha256(data).hexdigest()}
                           for name, data in sorted(blobs.items())}
    result["extracted_total_bytes"] = sum(len(b) for b in blobs.values())
    pathlib.Path(args.output).write_text(json.dumps(result, indent=1) + "\n")
    if args.dump_dir:
        out = pathlib.Path(args.dump_dir)
        out.mkdir(parents=True, exist_ok=True)
        for name, data in blobs.items():
            (out / name.replace("/", "_")).write_bytes(data)
    print(json.dumps({"volumes": result["volumes"],
                      "modules": result["modules"],
                      "extracted_total_bytes": result["extracted_total_bytes"]},
                     indent=1))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
