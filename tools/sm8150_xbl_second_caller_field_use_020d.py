#!/usr/bin/env python3
"""Bounded host-only trace of the second caller of the 020C helper.

The pass follows only the exact function at ``0x9fc26e24``.  It records which
static object fields are loaded and which static ELF slots receive those
symbolic origins.  Static ELF addresses are not promoted to runtime physical,
MMIO, or DRAM destinations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
SCHEMA = "sm8150-xbl-second-caller-field-use-v1"
EXPERIMENT_ID = "020D-second-caller-field-use"
MODE = "HOST_ONLY_READ_ONLY"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
HELPER_START = 0x9FC160B8
HELPER_END = 0x9FC160C4
HELPER_SHA256 = "aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9"
CALLER_START = 0x9FC26E24
CALLER_END = 0x9FC26E78
CALLER_SIZE = CALLER_END - CALLER_START
CALLER_SHA256 = "4c3100f3dff6b8684aa17fc616f6737b283484bb92199dbe98b747a8ab85721d"
OBJECT_START = 0x9FC362C0
OBJECT_END = 0x9FC36300
OBJECT_SIZE = OBJECT_END - OBJECT_START
OBJECT_SHA256 = "07f284b58048d944e3d6ef2e19438d9d1e04bde32eafb5541f2eabe294af8277"
OBJECT_PAGE = 0x9FC36000
STATIC_SLOT_PAGE = 0x9FC3E000
CALLER_VAS = (0x9FC22CC0, CALLER_START + 0x08)


class TraceError(ValueError):
    """Raised when an exact input or bounded static invariant fails."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: int) -> str:
    return f"0x{value:08x}"


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


@dataclass(frozen=True)
class Segment:
    file_offset: int
    vaddr: int
    file_size: int
    mem_size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)


class Image:
    """Minimal ELF64 PT_LOAD reader for bounded file-backed ranges."""

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01" or data[6] != 1:
            raise TraceError("input is not a little-endian ELF64 image")
        self.data = data
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x36)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
        if phoff < 64 or phentsize < 56 or phnum > 4096 or phoff + phentsize * phnum > len(data):
            raise TraceError("invalid or truncated program-header table")
        self.segments: list[Segment] = []
        for index in range(phnum):
            off = phoff + index * phentsize
            p_type, flags, file_off, vaddr, _paddr, file_size, mem_size, _align = struct.unpack_from(
                "<IIQQQQQQ", data, off
            )
            if p_type != 1:
                continue
            if mem_size < file_size or file_off > len(data) or file_size > len(data) - file_off:
                raise TraceError(f"PT_LOAD {index} exceeds input")
            segment = Segment(file_off, vaddr, file_size, mem_size, flags)
            for prior in self.segments:
                if not (segment.file_offset + segment.file_size <= prior.file_offset or prior.file_offset + prior.file_size <= segment.file_offset):
                    raise TraceError("overlapping file-backed PT_LOAD ranges")
                if not (segment.vaddr + segment.file_size <= prior.vaddr or prior.vaddr + prior.file_size <= segment.vaddr):
                    raise TraceError("overlapping virtual PT_LOAD ranges")
            self.segments.append(segment)

    def segment_for(self, vaddr: int, size: int = 1) -> Segment | None:
        if size < 0:
            raise TraceError("negative read size")
        matches = [s for s in self.segments if s.vaddr <= vaddr and vaddr + size <= s.vaddr + s.file_size]
        if len(matches) > 1:
            raise TraceError(f"ambiguous mapping at {fmt(vaddr)}")
        return matches[0] if matches else None

    def file_offset(self, vaddr: int, size: int = 1) -> int | None:
        segment = self.segment_for(vaddr, size)
        return None if segment is None else segment.file_offset + vaddr - segment.vaddr

    def read(self, vaddr: int, size: int) -> bytes:
        offset = self.file_offset(vaddr, size)
        if offset is None:
            raise TraceError(f"range is not file-backed: {fmt(vaddr)} size {size}")
        return self.data[offset : offset + size]

    def word(self, vaddr: int) -> int:
        return struct.unpack("<I", self.read(vaddr, 4))[0]

    def executable_words(self) -> Iterable[tuple[int, int]]:
        for segment in self.segments:
            if not segment.executable:
                continue
            for index in range(segment.file_size // 4):
                yield segment.vaddr + index * 4, struct.unpack_from("<I", self.data, segment.file_offset + index * 4)[0]


def decode_bl_target(word: int, va: int) -> int | None:
    if word & 0xFC000000 != 0x94000000:
        return None
    return va + 4 * sign_extend(word & 0x03FFFFFF, 26)


def decode_adrp(word: int, va: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    immediate = sign_extend((immhi << 2) | immlo, 21)
    return word & 0x1F, (va & ~0xFFF) + (immediate << 12)


def decode_add_sub_imm(word: int) -> tuple[str, int, int, int, int, int] | None:
    if word & 0x1F000000 != 0x11000000:
        return None
    sf = (word >> 31) & 1
    op = (word >> 30) & 1
    set_flags = (word >> 29) & 1
    shift = (word >> 22) & 1
    if sf != 1 or set_flags or ((word >> 23) & 1) or shift not in (0, 1):
        return None
    immediate = ((word >> 10) & 0xFFF) << (12 if shift else 0)
    return ("SUB" if op else "ADD", word & 0x1F, (word >> 5) & 0x1F, immediate, shift, 64)


def decode_ldr_unsigned(word: int) -> tuple[int, int, int, int] | None:
    prefix = word & 0xFFC00000
    if prefix == 0xB9400000:
        width, scale = 32, 4
    elif prefix == 0xF9400000:
        width, scale = 64, 8
    else:
        return None
    return width, word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * scale


def decode_str_unsigned(word: int) -> tuple[int, int, int, int] | None:
    prefix = word & 0xFFC00000
    if prefix == 0xB9000000:
        width, scale = 32, 4
    elif prefix == 0xF9000000:
        width, scale = 64, 8
    else:
        return None
    return width, word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * scale


def decode_ldp_unsigned(word: int) -> tuple[int, int, int, int, int] | None:
    if word & 0xFFC00000 != 0xA9400000 or not (word & (1 << 31)) or word & (1 << 23):
        return None
    return 64, word & 0x1F, (word >> 10) & 0x1F, (word >> 5) & 0x1F, ((word >> 15) & 0x7F) * 8


def direct_callers(image: Image, target: int) -> list[dict[str, str]]:
    result = []
    for va, word in image.executable_words():
        if decode_bl_target(word, va) == target:
            result.append({"va": fmt(va), "target": fmt(target), "kind": "BL"})
    return result


def range_record(image: Image, start: int, end: int, expected: str, label: str) -> dict[str, Any]:
    payload = image.read(start, end - start)
    digest = sha256(payload)
    if digest != expected:
        raise TraceError(f"{label} hash mismatch")
    offset = image.file_offset(start, end - start)
    if offset is None:
        raise TraceError(f"{label} is not file-backed")
    return {"start": fmt(start), "end_exclusive": fmt(end), "file_offset": fmt(offset), "size": end - start, "sha256": digest}


@dataclass(frozen=True)
class Origin:
    kind: str
    base: str
    offset: int = 0
    width_bits: int = 64

    def record(self) -> dict[str, Any]:
        result = {"kind": self.kind, "origin": "UNKNOWN", "width_bits": self.width_bits, "base": self.base, "offset": fmt(self.offset)}
        if self.kind == "STATIC_OBJECT_FIELD":
            result["provenance"] = "static ELF object field; runtime value UNKNOWN"
        elif self.kind == "STATIC_PAGE":
            result["provenance"] = "static ELF page base; runtime destination UNKNOWN"
        return result


def object_field(offset: int, width_bits: int) -> Origin:
    return Origin("STATIC_OBJECT_FIELD", fmt(OBJECT_START), offset, width_bits)


def trace_second_caller(image: Image) -> dict[str, Any]:
    helper_range = range_record(image, HELPER_START, HELPER_END, HELPER_SHA256, "helper")
    caller_range = range_record(image, CALLER_START, CALLER_END, CALLER_SHA256, "second caller")
    object_range = range_record(image, OBJECT_START, OBJECT_END, OBJECT_SHA256, "object fields")
    callers = direct_callers(image, HELPER_START)
    expected_callers = [{"va": fmt(va), "target": fmt(HELPER_START), "kind": "BL"} for va in CALLER_VAS]
    if callers != expected_callers:
        raise TraceError("helper direct-caller census changed")

    exact = {
        0x00: 0xA9BF7BFD,
        0x04: 0x910003FD,
        0x08: 0x97FFBCA3,
        0x0C: 0xA942A40A,
        0x10: 0x900000C8,
        0x14: 0xF9401C0B,
        0x18: 0x900000CD,
        0x1C: 0xB9400C0C,
        0x20: 0x900000CE,
        0x24: 0xF9009D09,
        0x28: 0x900000C9,
        0x2C: 0xA941BC08,
        0x30: 0xF900A1AB,
        0x34: 0x900000CB,
        0x38: 0xF900A52C,
        0x3C: 0x900000CC,
        0x40: 0xF900A9C8,
        0x44: 0xF900AD6F,
        0x48: 0xF900B18A,
        0x4C: 0xA8C17BFD,
        0x50: 0xD65F03C0,
    }
    for relative, expected in exact.items():
        if image.word(CALLER_START + relative) != expected:
            raise TraceError(f"second caller instruction changed at {fmt(CALLER_START + relative)}")
    if decode_bl_target(exact[0x08], CALLER_START + 0x08) != HELPER_START:
        raise TraceError("second caller helper target changed")
    if decode_add_sub_imm(exact[0x04]) != ("ADD", 29, 31, 0, 0, 64):
        raise TraceError("second caller frame setup changed")
    if decode_ldp_unsigned(exact[0x0C]) != (64, 10, 9, 0, 0x28):
        raise TraceError("first object pair load changed")
    if decode_ldp_unsigned(exact[0x2C]) != (64, 8, 15, 0, 0x18):
        raise TraceError("second object pair load changed")

    regs: dict[int, Origin] = {0: Origin("STATIC_OBJECT", fmt(OBJECT_START), 0, 64)}
    page_regs: dict[int, Origin] = {}
    loads: list[dict[str, Any]] = []
    stores: list[dict[str, Any]] = []

    def load(relative: int, expected: tuple[int, int, int, int]) -> None:
        decoded = decode_ldr_unsigned(image.word(CALLER_START + relative))
        if decoded != expected:
            raise TraceError(f"object load changed at {fmt(CALLER_START + relative)}")
        width, target, base, offset = decoded
        if base != 0:
            raise TraceError("object load base changed")
        origin = object_field(offset, width)
        regs[target] = origin
        loads.append({"va": fmt(CALLER_START + relative), "register": f"{'W' if width == 32 else 'X'}{target}", "object_offset": fmt(offset), "width_bits": width, "value": origin.record()})

    def adrp(relative: int, expected_register: int) -> None:
        decoded = decode_adrp(image.word(CALLER_START + relative), CALLER_START + relative)
        if decoded != (expected_register, STATIC_SLOT_PAGE):
            raise TraceError(f"static page construction changed at {fmt(CALLER_START + relative)}")
        page_regs[expected_register] = Origin("STATIC_PAGE", fmt(STATIC_SLOT_PAGE), 0, 64)

    def store(relative: int, expected: tuple[int, int, int, int], page_register: int) -> None:
        decoded = decode_str_unsigned(image.word(CALLER_START + relative))
        if decoded != expected:
            raise TraceError(f"static slot store changed at {fmt(CALLER_START + relative)}")
        width, source, base, offset = decoded
        if base != page_register or page_register not in page_regs:
            raise TraceError("static store base is not the pinned page register")
        origin = regs.get(source)
        if origin is None:
            raise TraceError("static store source is unresolved")
        destination = STATIC_SLOT_PAGE + offset
        stores.append({"va": fmt(CALLER_START + relative), "source": f"{'W' if width == 32 else 'X'}{source}", "source_value": origin.record(), "destination": {"kind": "STATIC_ELF_VADDR", "va": fmt(destination), "runtime_value": "UNKNOWN"}, "width_bits": width})

    first_pair = decode_ldp_unsigned(image.word(CALLER_START + 0x0C))
    if first_pair != (64, 10, 9, 0, 0x28):
        raise TraceError("first object pair decode changed")
    regs[10] = object_field(0x28, 64)
    regs[9] = object_field(0x30, 64)
    loads.extend([
        {"va": fmt(CALLER_START + 0x0C), "register": "X10", "object_offset": fmt(0x28), "width_bits": 64, "value": regs[10].record()},
        {"va": fmt(CALLER_START + 0x0C), "register": "X9", "object_offset": fmt(0x30), "width_bits": 64, "value": regs[9].record()},
    ])
    load(0x14, (64, 11, 0, 0x38))
    load(0x1C, (32, 12, 0, 0x0C))
    adrp(0x10, 8)
    adrp(0x18, 13)
    adrp(0x20, 14)
    store(0x24, (64, 9, 8, 0x138), 8)
    adrp(0x28, 9)
    load_pair = decode_ldp_unsigned(image.word(CALLER_START + 0x2C))
    if load_pair != (64, 8, 15, 0, 0x18):
        raise TraceError("second object pair decode changed")
    regs[8] = object_field(0x18, 64)
    regs[15] = object_field(0x20, 64)
    loads.extend([
        {"va": fmt(CALLER_START + 0x2C), "register": "X8", "object_offset": fmt(0x18), "width_bits": 64, "value": regs[8].record()},
        {"va": fmt(CALLER_START + 0x2C), "register": "X15", "object_offset": fmt(0x20), "width_bits": 64, "value": regs[15].record()},
    ])
    store(0x30, (64, 11, 13, 0x140), 13)
    adrp(0x34, 11)
    store(0x38, (64, 12, 9, 0x148), 9)
    adrp(0x3C, 12)
    store(0x40, (64, 8, 14, 0x150), 14)
    store(0x44, (64, 15, 11, 0x158), 11)
    store(0x48, (64, 10, 12, 0x160), 12)

    return {
        "helper_range": helper_range,
        "caller_range": caller_range,
        "object_range": object_range,
        "direct_callers": {"count": len(callers), "callers": callers},
        "caller": {"start": fmt(CALLER_START), "call_va": fmt(CALLER_START + 8), "helper": fmt(HELPER_START), "object_base": fmt(OBJECT_START)},
        "object_loads": loads,
        "static_slot_stores": stores,
        "status": "SUPPORTED_BOUNDED_SECOND_CALLER_FIELD_USE_TRACE",
        "current_values": "UNKNOWN",
    }


def load_exact(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise TraceError(f"cannot open exact XBL: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != XBL_SIZE:
            raise TraceError("exact XBL size/type mismatch")
        chunks: list[bytes] = []
        remaining = XBL_SIZE
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError("exact XBL truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise TraceError("exact XBL changed during read")
        payload = b"".join(chunks)
        if sha256(payload) != XBL_SHA256:
            raise TraceError("exact XBL SHA-256 mismatch")
        return payload
    finally:
        os.close(fd)


def definition_of_done() -> dict[str, Any]:
    reason = "NOT_APPLICABLE: bounded host-only static trace; no device or runtime state was touched"
    return {
        "target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"},
        "build": {"status": "NOT_APPLICABLE", "reason": reason},
        "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."},
        "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_second_caller_field_use_020d.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."},
        "repetitions": {"status": "NOT_APPLICABLE", "reason": reason},
        "rollback": {"status": "NOT_APPLICABLE", "reason": reason},
        "recovery": {"status": "NOT_APPLICABLE", "reason": reason},
        "device_binding": {"status": "NOT_APPLICABLE", "reason": reason},
        "tool_and_build": {"build": "NOT_APPLICABLE", "build_reason": "Interpreted host Python; no firmware/kernel build.", "tool": f"{Path(__file__).name} schema {SCHEMA}"},
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    image = Image(load_exact(firmware_dir / XBL_NAME))
    trace = trace_second_caller(image)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "helper": trace["helper_range"], "caller": trace["caller_range"], "object_fields": trace["object_range"], "helper_direct_callers": trace["direct_callers"]},
        "trace": trace,
        "scope": {"model": "ONE_EXACT_SECOND_HELPER_CALLER", "recognized_forms": ["BL_DIRECT", "ADRP", "LDR/STR_UNSIGNED", "LDP_UNSIGNED", "FRAME_RAW_PIN"], "static_destinations_only": True, "runtime_values": "UNKNOWN", "physical_to_dram": "UNKNOWN", "indirect_paths": "UNKNOWN", "never_scan_arbitrary_ranges": True},
        "claims": {
            "PROVED": [
                "The exact retained A90 XBL is bound by size and SHA-256 before analysis.",
                "The second helper caller at 0x9fc26e24 loads object fields at +0x0c, +0x18, +0x20, +0x28, +0x30 and +0x38 under the exact finite model.",
                "Six symbolic object-field origins are stored to static ELF VADDR slots 0x9fc3e138, 0x9fc3e140, 0x9fc3e148, 0x9fc3e150, 0x9fc3e158 and 0x9fc3e160.",
            ],
            "SUPPORTED": ["The second caller is a bounded static field-use edge from the shared 020C object; static slot identity is not a runtime controller/DRAM proof."],
            "HYPOTHESIS": ["The shared static object and slots may be configuration state consumed by multiple XBL paths."],
            "REFUTED": [],
            "UNKNOWN": ["Runtime field values/type/currentness, slot semantics, writer timing, mutability/locking, physical-to-DRAM mapping, MMIO meaning, protected reach, aliasing/bypass, and indirect paths."],
        },
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only static trace; no activation or live state was accessed."},
        "definition_of_done": definition_of_done(),
    }


def write_no_clobber(path: Path, payload: bytes) -> dict[str, Any]:
    if not path.parent.is_dir():
        raise TraceError(f"manifest parent does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise TraceError(f"manifest output already exists or is unsafe: {path}") from exc
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise TraceError("manifest write made no progress")
            view = view[count:]
        os.fsync(fd)
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    return {"basename": path.name, "size_bytes": len(payload), "sha256": sha256(payload), "mode": "0644"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = (json.dumps(build_manifest(args.firmware_dir), indent=1, sort_keys=True) + "\n").encode()
        publication = write_no_clobber(args.output, payload)
    except (TraceError, OSError) as exc:
        print(f"020D: {exc}", file=__import__("sys").stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
