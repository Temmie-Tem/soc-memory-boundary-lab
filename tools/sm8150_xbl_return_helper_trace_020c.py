#!/usr/bin/env python3
"""Bounded host-only trace of the exact XBL helper returning the 020B object.

The helper is checked as ``ADRP X0`` + ``ADD X0`` + ``RET``.  Its result is
reported as a static ELF code/data address only; this tool never treats it as a
runtime pointer, physical address, MMIO register, or DRAM destination.
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
SCHEMA = "sm8150-xbl-return-helper-trace-v1"
EXPERIMENT_ID = "020C-return-helper-origin"
MODE = "HOST_ONLY_READ_ONLY"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
HELPER_START = 0x9FC160B8
HELPER_END = 0x9FC160C4
HELPER_SHA256 = "aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9"
OBJECT_START = 0x9FC362C0
OBJECT_END = 0x9FC362F0
OBJECT_SIZE = OBJECT_END - OBJECT_START
OBJECT_SHA256 = "29dfe1d501b1842425aae853943382cf45a0eb6929aab0a78eb5ad745418a649"
RETURN_VA = OBJECT_START
CALLER_VAS = (0x9FC22CC0, 0x9FC26E2C)


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
    """Small ELF64 PT_LOAD view; only file-backed bytes are readable."""

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
    """Return ``(destination, page_address)`` for ADRP."""
    if word & 0x9F000000 != 0x90000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    immediate = sign_extend((immhi << 2) | immlo, 21)
    return word & 0x1F, (va & ~0xFFF) + (immediate << 12)


def decode_add_sub_imm(word: int) -> tuple[str, int, int, int, int, int] | None:
    """Return ``(op, destination, base, immediate, shift, width)``."""
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


def direct_callers(image: Image, target: int) -> list[dict[str, str]]:
    result = []
    for va, word in image.executable_words():
        if decode_bl_target(word, va) == target:
            result.append({"va": fmt(va), "target": fmt(target), "kind": "BL"})
    return result


def range_record(image: Image, start: int, end: int, expected: str, label: str) -> dict[str, Any]:
    if end <= start:
        raise TraceError(f"{label} range is empty")
    payload = image.read(start, end - start)
    digest = sha256(payload)
    if digest != expected:
        raise TraceError(f"{label} hash mismatch")
    offset = image.file_offset(start, end - start)
    if offset is None:
        raise TraceError(f"{label} is not file-backed")
    return {"start": fmt(start), "end_exclusive": fmt(end), "file_offset": fmt(offset), "size": end - start, "sha256": digest}


def trace_helper(image: Image) -> dict[str, Any]:
    helper = range_record(image, HELPER_START, HELPER_END, HELPER_SHA256, "helper")
    object_range = range_record(image, OBJECT_START, OBJECT_END, OBJECT_SHA256, "returned object fields")
    callers = direct_callers(image, HELPER_START)
    expected_callers = [{"va": fmt(va), "target": fmt(HELPER_START), "kind": "BL"} for va in CALLER_VAS]
    if callers != expected_callers:
        raise TraceError("helper direct-caller census changed")
    adrp = decode_adrp(image.word(HELPER_START), HELPER_START)
    if adrp != (0, 0x9FC36000):
        raise TraceError("helper ADRP changed")
    add = decode_add_sub_imm(image.word(HELPER_START + 4))
    if add != ("ADD", 0, 0, 0x2C0, 0, 64):
        raise TraceError("helper ADD changed")
    if image.word(HELPER_START + 8) != 0xD65F03C0:
        raise TraceError("helper RET changed")
    return {
        "helper_range": helper,
        "object_range": object_range,
        "direct_callers": {"count": len(callers), "callers": callers},
        "return": {
            "kind": "STATIC_ELF_VADDR",
            "origin": "STATIC_ELF_VADDR",
            "va": fmt(RETURN_VA),
            "construction": [
                {"va": fmt(HELPER_START), "form": "ADRP", "destination": "X0", "page": fmt(0x9FC36000)},
                {"va": fmt(HELPER_START + 4), "form": "ADD_IMMEDIATE", "destination": "X0", "base": "X0", "byte_offset": fmt(0x2C0)},
                {"va": fmt(HELPER_START + 8), "form": "RET"},
            ],
            "runtime_value": "UNKNOWN",
            "runtime_physical_mapping": "UNKNOWN",
        },
        "status": "SUPPORTED_BOUNDED_STATIC_RETURN_HELPER_TRACE",
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
        data = bytearray()
        while len(data) < XBL_SIZE:
            chunk = os.read(fd, min(1 << 20, XBL_SIZE - len(data)))
            if not chunk:
                raise TraceError("exact XBL truncated during read")
            data.extend(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise TraceError("exact XBL changed during read")
        payload = bytes(data)
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
        "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_return_helper_trace_020c.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."},
        "repetitions": {"status": "NOT_APPLICABLE", "reason": reason},
        "rollback": {"status": "NOT_APPLICABLE", "reason": reason},
        "recovery": {"status": "NOT_APPLICABLE", "reason": reason},
        "device_binding": {"status": "NOT_APPLICABLE", "reason": reason},
        "tool_and_build": {"build": "NOT_APPLICABLE", "build_reason": "Interpreted host Python; no firmware/kernel build.", "tool": f"{Path(__file__).name} schema {SCHEMA}"},
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    image = Image(load_exact(firmware_dir / XBL_NAME))
    trace = trace_helper(image)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "helper": trace["helper_range"], "returned_object_fields": trace["object_range"], "helper_direct_callers": trace["direct_callers"]},
        "trace": trace,
        "scope": {"model": "ONE_EXACT_RETURN_HELPER_AND_TWO_DIRECT_CALLERS", "recognized_forms": ["ADRP", "ADD_SUB_IMMEDIATE", "BL_DIRECT", "RET"], "static_object_range_only": True, "runtime_values": "UNKNOWN", "runtime_physical_mapping": "UNKNOWN", "indirect_paths": "UNKNOWN", "never_scan_arbitrary_ranges": True},
        "claims": {
            "PROVED": [
                "The exact retained A90 XBL is bound by size and SHA-256 before analysis.",
                "The exact helper 0x9fc160b8 is ADRP X0 to page 0x9fc36000, ADD X0,#0x2c0 and RET, yielding static ELF VADDR 0x9fc362c0.",
                "The exact XBL contains two direct BL callers of the helper: 0x9fc22cc0 and 0x9fc26e2c.",
                "The returned-object field range [0x9fc362c0,0x9fc362f0) is file-backed and hash-pinned without publishing its raw bytes.",
            ],
            "SUPPORTED": ["The helper's static return address is the bounded source used by Verification 020B; this does not establish runtime object semantics."],
            "HYPOTHESIS": ["The static object may be a configuration carrier consumed by more than one XBL path."],
            "REFUTED": [],
            "UNKNOWN": ["Runtime execution, object contents/type/currentness, writer identity, mutability/locking, physical-to-DRAM mapping, MMIO semantics, protected-memory reach, aliasing and bypass; indirect callers and paths outside the executable scan."],
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
        print(f"020C: {exc}", file=__import__("sys").stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
