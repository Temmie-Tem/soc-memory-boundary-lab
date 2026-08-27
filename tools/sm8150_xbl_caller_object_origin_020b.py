#!/usr/bin/env python3
"""Bounded host-only trace of the XBL object passed into the 020A setter path.

The pass follows one exact direct caller of the 020A object consumer at
``0x9fc023c8``.  That caller builds a small stack object from the opaque return
value of ``BL 0x9fc160b8`` and passes ``SP+0x20`` to the consumer.  The output
is symbolic only: it never assigns a value, type, current address, MMIO role,
or physical/DRAM destination to the callee return or any copied field.
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

SCHEMA = "sm8150-xbl-caller-object-origin-v1"
EXPERIMENT_ID = "020B-caller-object-origin"
MODE = "HOST_ONLY_READ_ONLY"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

CONSUMER_START = 0x9FC023C8
CONSUMER_ENTRY_END = 0x9FC023D4
CONSUMER_ENTRY_SIZE = CONSUMER_ENTRY_END - CONSUMER_START
CONSUMER_ENTRY_SHA256 = "3870d341e69765b3f956c106c02dc49d150d3c34998b313dd3dc5951e51d593c"

# This is the complete bounded caller context, including the frame setup and
# epilogue.  The construction trace is the same caller's body from the query
# call through the consumer BL, while the context pin catches accidental
# reads past either function boundary.
CALLER_START = 0x9FC22CB4
CALLER_END = 0x9FC22D30
CALLER_SIZE = CALLER_END - CALLER_START
CALLER_SHA256 = "60e652142c73aec2bc17bef548e00bbb9edcdab08d75dcb3c4e11d0ca72b2162"
CALLER_TRACE_START = 0x9FC22CC0
CALLER_TRACE_END = 0x9FC22D28
CALLER_TRACE_SIZE = CALLER_TRACE_END - CALLER_TRACE_START
CALLER_TRACE_SHA256 = "b9407c190ddb88b0da62a9e2eefb988fa8fe1829ab3b8232f62019cf65d81c08"
CONSUMER_CALLER_VA = 0x9FC22D24
CONSUMER_CALLER_TARGET = CONSUMER_START
QUERY_CALL_VA = 0x9FC22CC0
QUERY_CALL_TARGET = 0x9FC160B8
QUERY_CALL_SHA256 = "bd89ed4c616b950308c637acaea5531e7439bb6f9ad3d894314d2e51e694ae63"
CONSUMER_CALL_SHA256 = "a40a1250460105fcaa37d9fbb64fbbf392b8591fc147b4b1a8321e19507d883f"

# The stack object passed to the 020A consumer begins at SP+0x20.  These are
# the four fields that the 020A pre-call block consumes.
OBJECT_BASE_OFFSET = 0x20
SETTER_ARGUMENT_FIELDS = {
    "W3": (0x10, 32),
    "X0": (0x18, 64),
    "X1": (0x20, 64),
    "X2": (0x28, 64),
}


class OriginError(ValueError):
    """Raised when an exact input or bounded data-flow invariant fails."""


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
    """Independent ELF64 PT_LOAD view used only by this experiment."""

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01" or data[6] != 1:
            raise OriginError("input is not a little-endian ELF64 image")
        self.data = data
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x36)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
        if phentsize < 56 or phnum > 4096 or phoff < 64 or phoff + phentsize * phnum > len(data):
            raise OriginError("invalid or truncated program-header table")
        segments: list[Segment] = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            p_type, flags, file_offset, vaddr, _paddr, file_size, mem_size, _align = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if p_type != 1:
                continue
            if mem_size < file_size or file_offset > len(data) or file_size > len(data) - file_offset:
                raise OriginError(f"PT_LOAD {index} exceeds input")
            segment = Segment(file_offset, vaddr, file_size, mem_size, flags)
            for prior in segments:
                if not (
                    segment.file_offset + segment.file_size <= prior.file_offset
                    or prior.file_offset + prior.file_size <= segment.file_offset
                ) or not (
                    segment.vaddr + segment.file_size <= prior.vaddr
                    or prior.vaddr + prior.file_size <= segment.vaddr
                ):
                    raise OriginError("overlapping PT_LOAD ranges")
            segments.append(segment)
        self.segments = segments

    def segment_for(self, vaddr: int, size: int = 1) -> Segment | None:
        if size < 0:
            raise OriginError("negative read size")
        matches = [
            segment
            for segment in self.segments
            if segment.vaddr <= vaddr and vaddr + size <= segment.vaddr + segment.file_size
        ]
        if len(matches) > 1:
            raise OriginError(f"ambiguous mapping at {fmt(vaddr)}")
        return matches[0] if matches else None

    def file_offset(self, vaddr: int, size: int = 1) -> int | None:
        segment = self.segment_for(vaddr, size)
        return None if segment is None else segment.file_offset + vaddr - segment.vaddr

    def read(self, vaddr: int, size: int) -> bytes:
        offset = self.file_offset(vaddr, size)
        if offset is None:
            raise OriginError(f"range is not file-backed: {fmt(vaddr)} size {size}")
        return self.data[offset : offset + size]

    def word(self, vaddr: int) -> int:
        return struct.unpack("<I", self.read(vaddr, 4))[0]

    def executable_words(self) -> Iterable[tuple[int, int]]:
        for segment in self.segments:
            if not segment.executable:
                continue
            for index in range(segment.file_size // 4):
                yield segment.vaddr + index * 4, struct.unpack_from(
                    "<I", self.data, segment.file_offset + index * 4
                )[0]


def decode_bl_target(word: int, va: int) -> int | None:
    if (word & 0xFC000000) != 0x94000000:
        return None
    return va + 4 * sign_extend(word & 0x03FFFFFF, 26)


def decode_add_sub_imm(word: int) -> tuple[str, int, int, int, int, int] | None:
    """Decode the 64-bit, no-flags ADD/SUB immediate form.

    The result is ``(op, destination, base, immediate, shift, width_bits)``.
    Only this narrow form is needed by the pinned frame setup/teardown and
    object-address construction.  Other arithmetic is deliberately left
    unsupported so a changed caller fails closed.
    """

    if word & 0x1F000000 != 0x11000000:
        return None
    sf = (word >> 31) & 1
    op = (word >> 30) & 1
    set_flags = (word >> 29) & 1
    shift = (word >> 22) & 1
    # Bit 23 is fixed zero in the ADD/SUB-immediate encoding.  Rejecting it
    # matters for the synthetic decoder contract even though the exact caller
    # words are hash-pinned separately.
    if sf != 1 or set_flags or ((word >> 23) & 1) or shift not in (0, 1):
        return None
    immediate = ((word >> 10) & 0xFFF) << (12 if shift else 0)
    return ("SUB" if op else "ADD", word & 0x1F, (word >> 5) & 0x1F, immediate, shift, 64)


def decode_add_sp_imm(word: int) -> tuple[int, int] | None:
    """Return ``(destination, byte_offset)`` for ``ADD Xd,SP,#imm``."""

    decoded = decode_add_sub_imm(word)
    if decoded is None or decoded[0] != "ADD" or decoded[2] != 31:
        return None
    return decoded[1], decoded[3]


def decode_sub_sp_imm(word: int) -> int | None:
    """Return the immediate for ``SUB SP,SP,#imm``."""

    decoded = decode_add_sub_imm(word)
    if decoded is None or decoded[:3] != ("SUB", 31, 31):
        return None
    return decoded[3]


def decode_ldr_unsigned(word: int) -> tuple[int, int, int, int] | None:
    """Return ``(width_bits, target, base, byte_offset)`` for scalar LDR."""
    prefix = word & 0xFFC00000
    if prefix == 0xB9400000:
        width, scale = 32, 4
    elif prefix == 0xF9400000:
        width, scale = 64, 8
    else:
        return None
    return width, word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * scale


def decode_str_unsigned(word: int) -> tuple[int, int, int, int] | None:
    """Return ``(width_bits, source, base, byte_offset)`` for scalar STR."""
    prefix = word & 0xFFC00000
    if prefix == 0xB9000000:
        width, scale = 32, 4
    elif prefix == 0xF9000000:
        width, scale = 64, 8
    else:
        return None
    return width, word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * scale


def decode_ldp_unsigned(word: int) -> tuple[int, int, int, int, int] | None:
    """Return ``(width_bits, target1, target2, base, byte_offset)`` for LDP X."""
    if (word & 0xFFC00000) != 0xA9400000 or not (word & (1 << 31)) or word & (1 << 23):
        return None
    return 64, word & 0x1F, (word >> 10) & 0x1F, (word >> 5) & 0x1F, ((word >> 15) & 0x7F) * 8


def decode_stp_unsigned(word: int) -> tuple[int, int, int, int, int] | None:
    """Return ``(width_bits, source1, source2, base, byte_offset)`` for STP X."""

    if (word & 0xFFC00000) != 0xA9000000 or not (word & (1 << 31)) or word & (1 << 23):
        return None
    return 64, word & 0x1F, (word >> 10) & 0x1F, (word >> 5) & 0x1F, ((word >> 15) & 0x7F) * 8


def _ror(value: int, rotate: int, width: int) -> int:
    rotate %= width
    mask = (1 << width) - 1
    return ((value >> rotate) | (value << (width - rotate))) & mask


def decode_orr_wzr_imm(word: int) -> tuple[int, int] | None:
    """Decode ``ORR Wd,WZR,#bitmask`` as ``(destination, immediate)``.

    This is the logical-immediate encoding's small ARM-defined bitmask
    decoder, restricted to 32-bit ORR with WZR as the source.  Supporting the
    encoding rather than pinning one raw word makes synthetic negative tests
    meaningful while still rejecting all other logical operations.
    """

    if word & 0x7F800000 != 0x32000000:
        return None
    # Logical-immediate W forms have sf=0 and N=0.  Without the sf check a
    # 64-bit ORR Xd,XZR,#imm can be misreported as the documented W form.
    if ((word >> 31) & 1) or ((word >> 5) & 0x1F) != 31 or ((word >> 22) & 1):
        return None
    immr = (word >> 16) & 0x3F
    imms = (word >> 10) & 0x3F
    pattern = (~imms) & 0x3F
    if pattern == 0:
        return None
    length = pattern.bit_length() - 1
    if length < 1 or length > 5:
        return None
    levels = (1 << length) - 1
    ones = imms & levels
    rotate = immr & levels
    if ones == levels:
        return None
    element_width = 1 << length
    element = _ror((1 << (ones + 1)) - 1, rotate, element_width)
    immediate = 0
    for offset in range(0, 32, element_width):
        immediate |= element << offset
    return word & 0x1F, immediate


def decode_q_sp(word: int) -> tuple[str, int, int] | None:
    """Return ``(form, Q register, byte_offset)`` for LDR/STR Q,[SP,#imm]."""
    prefix = word & 0xFFC00000
    if prefix == 0x3DC00000:
        form = "LDR_Q"
    elif prefix == 0x3D800000:
        form = "STR_Q"
    else:
        return None
    if ((word >> 5) & 0x1F) != 31:
        return None
    return form, word & 0x1F, ((word >> 10) & 0xFFF) * 16


@dataclass(frozen=True)
class Origin:
    kind: str
    base: str | None = None
    offset: int | None = None
    width_bits: int | None = None

    def describe(self) -> str:
        if self.kind == "CONSTANT":
            return self.base or "CONSTANT"
        # A return register and every load through it are intentionally
        # value-unknown.  The base/offset fields below retain static
        # provenance without turning it into a runtime address or typed
        # object claim.
        if self.kind == "MEMORY_FIELD":
            return "UNKNOWN"
        if self.kind == "STACK_ADDRESS":
            return f"STACK[{self.base}+0x{self.offset:x}]"
        return "UNKNOWN"


UNKNOWN = Origin("UNKNOWN")


def memory_field(base: Origin, offset: int, width_bits: int) -> Origin:
    """Return a symbolic unknown for a load through the opaque return.

    The returned ``Origin`` retains the static base label and field offset for
    audit output, but ``describe()`` remains exactly ``UNKNOWN``.  This is the
    important boundary: a firmware helper's return does not become a runtime
    value, type, physical address, or MMIO claim merely because a load uses it.
    """

    if base.kind not in ("CALLEE_RETURN", "UNKNOWN") or base.base != "BL 0x9fc160b8 return X0":
        raise OriginError("load base is not the pinned opaque callee return")
    return Origin("MEMORY_FIELD", base=base.base, offset=offset, width_bits=width_bits)


@dataclass(frozen=True)
class VectorValue:
    """Two 64-bit symbolic lanes carried by the exact Q0 stack copy."""

    lanes: tuple[Origin, Origin]


def direct_callers(image: Image, target: int) -> list[dict[str, str]]:
    callers = []
    for va, word in image.executable_words():
        destination = decode_bl_target(word, va)
        if destination == target:
            callers.append({"va": fmt(va), "target": fmt(destination), "kind": "BL"})
    return callers


def _range_record(image: Image, start: int, end: int, expected_sha: str, label: str) -> dict[str, Any]:
    if end <= start:
        raise OriginError(f"{label} range is empty")
    payload = image.read(start, end - start)
    digest = sha256(payload)
    if digest != expected_sha:
        raise OriginError(f"{label} hash mismatch")
    offset = image.file_offset(start, end - start)
    if offset is None:
        raise OriginError(f"{label} is not file-backed")
    return {"start": fmt(start), "end_exclusive": fmt(end), "file_offset": fmt(offset), "size": end - start, "sha256": digest}


@dataclass(frozen=True)
class _StackCell:
    start: int
    size: int
    value: Origin | VectorValue


class _StackMemory:
    """Tiny last-write symbolic stack model for the pinned Q0 transfer.

    This is deliberately not a general memory interpreter.  Reads require a
    single prior full-width write (or the two exact 64-bit lanes of the Q0
    copy), and any missing/ambiguous coverage raises ``OriginError``.  Thus a
    changed aliasing pattern cannot silently turn into a claimed object field.
    """

    def __init__(self) -> None:
        self._cells: list[_StackCell] = []

    def store(self, start: int, size: int, value: Origin | VectorValue) -> None:
        if start < 0 or size <= 0:
            raise OriginError("invalid symbolic stack store")
        self._cells.append(_StackCell(start, size, value))

    def _find(self, start: int, size: int) -> Origin | None:
        end = start + size
        for cell in reversed(self._cells):
            if cell.start <= start and end <= cell.start + cell.size:
                if isinstance(cell.value, VectorValue):
                    lane_offset = start - cell.start
                    if size == 8 and lane_offset in (0, 8):
                        return cell.value.lanes[lane_offset // 8]
                    return None
                if size == cell.size:
                    return cell.value
                # A scalar write cannot prove a differently sized read.
                return None
        return None

    def load_scalar(self, start: int, size: int) -> Origin:
        value = self._find(start, size)
        if value is None:
            raise OriginError(f"unresolved symbolic stack read at SP+{fmt(start)} size {size}")
        return value

    def load_vector_q(self, start: int) -> VectorValue:
        return VectorValue((self.load_scalar(start, 8), self.load_scalar(start + 8, 8)))


def _origin_record(origin: Origin) -> dict[str, Any]:
    """Serialize an origin while retaining UNKNOWN provenance separately."""

    result: dict[str, Any] = {"kind": origin.kind, "origin": origin.describe()}
    if origin.width_bits is not None:
        result["width_bits"] = origin.width_bits
    if origin.kind == "MEMORY_FIELD":
        result["provenance"] = "symbolic load through BL 0x9fc160b8 return X0"
        result["field_offset"] = fmt(origin.offset or 0)
        result["base"] = origin.base
    elif origin.kind == "CALLEE_RETURN":
        result["provenance"] = "BL 0x9fc160b8 return in X0; value UNKNOWN"
    elif origin.kind == "STACK_ADDRESS":
        result["stack_base"] = origin.base
        result["stack_offset"] = fmt(origin.offset or 0)
    elif origin.kind == "CONSTANT":
        result["constant"] = origin.base
    return result


def _trace_object_legacy(image: Image) -> dict[str, Any]:
    """Retained only as an audit reference; use :func:`trace_object` below."""
    trace_range = _range_record(image, CALLER_START, CALLER_END, CALLER_SHA256, "caller")
    callers = direct_callers(image, CONSUMER_START)
    if callers != [{"va": fmt(CONSUMER_CALLER_VA), "target": fmt(CONSUMER_CALLER_TARGET), "kind": "BL"}]:
        raise OriginError("consumer direct-caller cardinality changed")

    # The exact instruction sequence is intentionally enumerated.  This keeps
    # the symbolic pass finite and fail-closed instead of pretending to be a
    # general AArch64 interpreter.
    expected_words = {
        CALLER_START + 0x00: 0xD10183FF,  # sub sp,sp,#0x60
        CALLER_START + 0x04: 0xA9057BFD,  # stp x29,x30,[sp,#0x50]
        CALLER_START + 0x08: 0x910143FD,  # add x29,sp,#0x50
        QUERY_CALL_VA: 0x97FFCCFE,  # bl 0x9fc160b8
        CALLER_START + 0x50: 0x910083E0,  # add x0,sp,#0x20
        CONSUMER_CALLER_VA: 0x97FF7DA9,  # bl 0x9fc023c8
        CALLER_END - 0x0C: 0xA9457BFD,  # ldp x29,x30,[sp,#0x50]
        CALLER_END - 0x08: 0x910183FF,  # add sp,sp,#0x60
        CALLER_END - 0x04: 0xD65F03C0,
    }
    for va, expected in expected_words.items():
        if image.word(va) != expected:
            raise OriginError(f"caller instruction changed at {fmt(va)}")
    if decode_bl_target(image.word(QUERY_CALL_VA), QUERY_CALL_VA) != QUERY_CALL_TARGET:
        raise OriginError("query call target changed")
    if decode_bl_target(image.word(CONSUMER_CALLER_VA), CONSUMER_CALLER_TARGET) != CONSUMER_START:
        raise OriginError("consumer call target changed")

    return_value = Origin("CALLEE_RETURN", base="BL 0x9fc160b8 return X0", width_bits=64)
    regs: dict[int, Origin] = {0: return_value}
    stack: dict[int, Origin] = {}
    observations: list[dict[str, Any]] = []

    def scalar_load(va: int, width: int, target: int, base_reg: int, offset: int) -> None:
        base = regs.get(base_reg, UNKNOWN)
        origin = memory_field(base, offset, width)
        regs[target] = origin
        observations.append({"va": fmt(va), "form": "LDR_UNSIGNED", "target": f"{'W' if width == 32 else 'X'}{target}", "base": f"X{base_reg}", "byte_offset": fmt(offset), "origin": origin.describe(), "width_bits": width})

    def scalar_store(va: int, width: int, source: int, base_reg: int, offset: int) -> None:
        if base_reg != 31:
            raise OriginError(f"caller store base is not SP at {fmt(va)}")
        origin = regs.get(source, UNKNOWN)
        stack[offset] = origin
        observations.append({"va": fmt(va), "form": "STR_UNSIGNED", "source": f"{'W' if width == 32 else 'X'}{source}", "base": "SP", "byte_offset": fmt(offset), "origin": origin.describe(), "width_bits": width})

    # Prologue and query return.
    observations.extend([
        {"va": fmt(CALLER_START), "form": "SUB_SP", "byte_offset": fmt(0x60)},
        {"va": fmt(CALLER_START + 4), "form": "STP_FRAME", "byte_offset": fmt(0x50)},
        {"va": fmt(CALLER_START + 8), "form": "ADD_FRAME", "byte_offset": fmt(0x50)},
        {"va": fmt(QUERY_CALL_VA), "form": "BL", "target": fmt(QUERY_CALL_TARGET), "return_origin": return_value.describe()},
    ])
    # 0x9fc22cc4: ORR W8,WZR,#1; this is a constant field, not a controller value.
    if image.word(CALLER_START + 0x10) != 0x320003E8:
        raise OriginError("constant object-field initializer changed")
    regs[8] = Origin("CONSTANT", base="1", width_bits=32)
    observations.append({"va": fmt(CALLER_START + 0x10), "form": "ORR_W_IMM", "target": "W8", "value": 1})

    # The exact loads/stores are decoded, and each source must be the opaque
    # query return in X0.  Stack offsets are relative to the current SP.
    load_store_pairs = [
        (0x14, 64, 9, 0, 0x20, "load"),
        (0x1C, 32, 10, 0, 0x00, "load"),
        (0x24, 32, 11, 0, 0x04, "load"),
        (0x2C, 32, 12, 0, 0x08, "load"),
        (0x34, 32, 13, 0, 0x0C, "load"),
        (0x3C, 32, 14, 0, 0x10, "load"),
    ]
    for offset, width, target, base, field, _kind in load_store_pairs:
        word = image.word(CALLER_START + offset)
        decoded = decode_ldr_unsigned(word)
        if decoded != (width, target, base, field):
            raise OriginError(f"query-return load changed at {fmt(CALLER_START + offset)}")
        scalar_load(CALLER_START + offset, width, target, base, field)
    stores = [
        (0x18, 32, 8, 31, 0x20),
        (0x20, 32, 10, 31, 0x24),
        (0x28, 32, 11, 31, 0x28),
        (0x30, 32, 12, 31, 0x2C),
        (0x38, 32, 13, 31, 0x30),
        (0x40, 32, 14, 31, 0x34),
    ]
    for offset, width, source, base, stack_offset in stores:
        decoded = decode_str_unsigned(image.word(CALLER_START + offset))
        if decoded != (width, source, base, stack_offset):
            raise OriginError(f"stack field store changed at {fmt(CALLER_START + offset)}")
        scalar_store(CALLER_START + offset, width, source, base, stack_offset)

    # X9 is [return+0x20], copied through the pair at SP/SP+8; the second
    # qword is [return+0x18].  The vector transfer itself is treated as one
    # opaque pair operation, then LDP splits it into two scalar origins.
    for va, expected, form, reg, stack_offset in [
        (CALLER_START + 0x3C, 0, "", 0, 0),
    ]:
        del va, expected, form, reg, stack_offset
    # The six-byte offsets above leave the exact X9/X8 sequence at these fixed
    # addresses; decode each instruction rather than trusting prose.
    if decode_str_unsigned(image.word(CALLER_START + 0x3C)) is not None:
        raise OriginError("caller sequence layout unexpectedly overlaps")
    if decode_str_unsigned(image.word(CALLER_START + 0x40)) is not None:
        raise OriginError("caller sequence layout unexpectedly overlaps")

    # The sequence is easier and safer to pin by its exact words and derive its
    # four relevant field origins directly from the validated stack layout.
    exact_tail = {
        0x3C: 0xB940100E,  # already checked above; retained for audit output
        0x40: 0xF90007E9,
        0x48: 0xF9400C08,
        0x4C: 0x3DC003E0,
        0x50: 0x3D8007E0,
        0x54: 0xA9412BEB,
        0x58: 0xF90023EA,
        0x5C: 0xF940140C,
        0x60: 0x910083E0,
        0x64: 0xF9001FEB,
        0x68: 0xF90027EC,
    }
    # This tail table is checked below after the initial scalar stores.  The
    # first entry is a duplicate of the last load above and intentionally
    # anchors the contiguous exact sequence.
    for rel, expected in exact_tail.items():
        if image.word(CALLER_START + rel) != expected:
            raise OriginError(f"tail instruction changed at {fmt(CALLER_START + rel)}")

    # Replace the provisional stack values with the precise tail semantics.
    x9 = regs[9]
    x8 = memory_field(return_value, 0x18, 64)
    regs[8] = x8
    stack[0] = x8
    stack[8] = x9
    stack[0x10] = x8
    stack[0x18] = x9
    regs[11] = x8
    regs[10] = x9
    stack[0x38] = regs[11]
    stack[0x40] = regs[10]
    regs[12] = memory_field(return_value, 0x28, 64)
    regs[0] = Origin("STACK_ADDRESS", base="SP", offset=OBJECT_BASE_OFFSET, width_bits=64)
    stack[0x48] = regs[12]
    observations.extend([
        {"va": fmt(CALLER_START + 0x40), "form": "STR_UNSIGNED", "source": "X9", "base": "SP", "byte_offset": fmt(8), "origin": x9.describe(), "width_bits": 64},
        {"va": fmt(CALLER_START + 0x48), "form": "LDR_UNSIGNED", "target": "X8", "base": "X0", "byte_offset": fmt(0x18), "origin": x8.describe(), "width_bits": 64},
        {"va": fmt(CALLER_START + 0x4C), "form": "LDR_Q", "target": "Q0", "base": "SP", "byte_offset": fmt(0)},
        {"va": fmt(CALLER_START + 0x50), "form": "STR_Q", "source": "Q0", "base": "SP", "byte_offset": fmt(0x10)},
        {"va": fmt(CALLER_START + 0x54), "form": "LDP_X", "targets": ["X11", "X10"], "base": "SP", "byte_offset": fmt(0x10), "origins": [x8.describe(), x9.describe()]},
        {"va": fmt(CALLER_START + 0x58), "form": "STR_UNSIGNED", "source": "X10", "base": "SP", "byte_offset": fmt(0x40), "origin": x9.describe(), "width_bits": 64},
        {"va": fmt(CALLER_START + 0x5C), "form": "LDR_UNSIGNED", "target": "X12", "base": "X0", "byte_offset": fmt(0x28), "origin": regs[12].describe(), "width_bits": 64},
        {"va": fmt(CALLER_START + 0x60), "form": "ADD_SP", "target": "X0", "byte_offset": fmt(OBJECT_BASE_OFFSET), "origin": regs[0].describe()},
        {"va": fmt(CALLER_START + 0x64), "form": "STR_UNSIGNED", "source": "X11", "base": "SP", "byte_offset": fmt(0x38), "origin": x8.describe(), "width_bits": 64},
        {"va": fmt(CALLER_START + 0x68), "form": "STR_UNSIGNED", "source": "X12", "base": "SP", "byte_offset": fmt(0x48), "origin": regs[12].describe(), "width_bits": 64},
        {"va": fmt(CONSUMER_CALLER_VA), "form": "BL", "target": fmt(CONSUMER_START), "argument": regs[0].describe()},
    ])

    object_fields: dict[str, dict[str, Any]] = {}
    for register, (offset, width) in SETTER_ARGUMENT_FIELDS.items():
        origin = stack.get(OBJECT_BASE_OFFSET + offset, UNKNOWN)
        expected_offsets = {"W3": 0x0C, "X0": 0x18, "X1": 0x20, "X2": 0x28}
        if origin.kind != "MEMORY_FIELD" or origin.offset != expected_offsets[register] or origin.width_bits != width:
            raise OriginError(f"object field {register} origin changed")
        object_fields[register] = {"object_offset": fmt(offset), "width_bits": width, "origin": origin.describe()}
    return {
        "range": trace_range,
        "direct_callers": {"count": len(callers), "callers": callers},
        "query_call": {"va": fmt(QUERY_CALL_VA), "target": fmt(QUERY_CALL_TARGET), "return_origin": return_value.describe()},
        "consumer_call": {"va": fmt(CONSUMER_CALLER_VA), "target": fmt(CONSUMER_START), "object_argument": regs[0].describe()},
        "object_base": {"base": "SP", "offset": fmt(OBJECT_BASE_OFFSET), "opaque": True},
        "object_fields": object_fields,
        "observations": observations,
        "status": "SUPPORTED_BOUNDED_SYMBOLIC_CALLER_OBJECT_TRACE",
        "current_values": "UNKNOWN",
    }


def trace_object(image: Image) -> dict[str, Any]:
    """Trace only the exact caller's finite stack-object construction.

    The return value of ``BL 0x9fc160b8`` is an opaque symbolic token.  The
    interpreter recognizes only the pinned instructions below; it never
    executes XBL or assigns a runtime/type/physical meaning to a field.
    """

    caller_range = _range_record(image, CALLER_START, CALLER_END, CALLER_SHA256, "caller")
    trace_range = _range_record(image, CALLER_TRACE_START, CALLER_TRACE_END, CALLER_TRACE_SHA256, "caller trace")
    query_range = _range_record(image, QUERY_CALL_VA, QUERY_CALL_VA + 4, QUERY_CALL_SHA256, "query call")
    consumer_range = _range_record(
        image, CONSUMER_CALLER_VA, CONSUMER_CALLER_VA + 4, CONSUMER_CALL_SHA256, "consumer call"
    )
    consumer_entry = _range_record(
        image, CONSUMER_START, CONSUMER_ENTRY_END, CONSUMER_ENTRY_SHA256, "consumer entry"
    )

    callers = direct_callers(image, CONSUMER_START)
    expected_callers = [{"va": fmt(CONSUMER_CALLER_VA), "target": fmt(CONSUMER_START), "kind": "BL"}]
    if callers != expected_callers:
        raise OriginError("consumer direct-caller cardinality changed")

    expected_words = {
        0x00: 0xD10183FF,  # sub sp,sp,#0x60
        0x04: 0xA9057BFD,  # stp x29,x30,[sp,#0x50]
        0x08: 0x910143FD,  # add x29,sp,#0x50
        0x0C: 0x97FFCCFE,  # bl 0x9fc160b8
        0x10: 0x320003E8,  # orr w8,wzr,#1
        0x14: 0xF9401009,  # ldr x9,[x0,#0x20]
        0x18: 0xB90023E8,  # str w8,[sp,#0x20]
        0x1C: 0xB940000A,  # ldr w10,[x0,#0]
        0x20: 0xB90027EA,  # str w10,[sp,#0x24]
        0x24: 0xB940040B,  # ldr w11,[x0,#0x4]
        0x28: 0xB9002BEB,  # str w11,[sp,#0x28]
        0x2C: 0xB940080C,  # ldr w12,[x0,#0x8]
        0x30: 0xB9002FEC,  # str w12,[sp,#0x2c]
        0x34: 0xB9400C0D,  # ldr w13,[x0,#0xc]
        0x38: 0xB90033ED,  # str w13,[sp,#0x30]
        0x3C: 0xB940100E,  # ldr w14,[x0,#0x10]
        0x40: 0xF90007E9,  # str x9,[sp,#8]
        0x44: 0xB90037EE,  # str w14,[sp,#0x34]
        0x48: 0xF9400C08,  # ldr x8,[x0,#0x18]
        0x4C: 0xF90003E8,  # str x8,[sp]
        0x50: 0x3DC003E0,  # ldr q0,[sp]
        0x54: 0x3D8007E0,  # str q0,[sp,#0x10]
        0x58: 0xA9412BEB,  # ldp x11,x10,[sp,#0x10]
        0x5C: 0xF90023EA,  # str x10,[sp,#0x40]
        0x60: 0xF940140C,  # ldr x12,[x0,#0x28]
        0x64: 0x910083E0,  # add x0,sp,#0x20
        0x68: 0xF9001FEB,  # str x11,[sp,#0x38]
        0x6C: 0xF90027EC,  # str x12,[sp,#0x48]
        0x70: 0x97FF7DA9,  # bl 0x9fc023c8
        0x74: 0xA9457BFD,  # ldp x29,x30,[sp,#0x50]
        0x78: 0x910183FF,  # add sp,sp,#0x60
    }
    for relative, expected in expected_words.items():
        if image.word(CALLER_START + relative) != expected:
            raise OriginError(f"caller instruction changed at {fmt(CALLER_START + relative)}")
    # The return instruction is just outside the hashed caller body.  Pin it
    # separately so the bounded function shape cannot silently change.
    if image.word(CALLER_END) != 0xD65F03C0:
        raise OriginError("caller return instruction changed")
    if decode_bl_target(image.word(QUERY_CALL_VA), QUERY_CALL_VA) != QUERY_CALL_TARGET:
        raise OriginError("query call target changed")
    if decode_bl_target(image.word(CONSUMER_CALLER_VA), CONSUMER_CALLER_VA) != CONSUMER_START:
        raise OriginError("consumer call target changed")

    return_value = Origin("CALLEE_RETURN", base="BL 0x9fc160b8 return X0", width_bits=64)
    regs: dict[int, Origin] = {0: return_value}
    stack = _StackMemory()
    observations: list[dict[str, Any]] = []

    def add_observation(va: int, form: str, **fields: Any) -> None:
        observations.append({"va": fmt(va), "form": form, **fields})

    def load_scalar(relative: int, expected: tuple[int, int, int, int]) -> Origin:
        va = CALLER_START + relative
        decoded = decode_ldr_unsigned(image.word(va))
        if decoded != expected:
            raise OriginError(f"query-return load changed at {fmt(va)}")
        width, target, base, offset = decoded
        if base != 0:
            raise OriginError(f"query-return load base changed at {fmt(va)}")
        origin = memory_field(regs.get(base, UNKNOWN), offset, width)
        regs[target] = origin
        add_observation(
            va,
            "LDR_UNSIGNED",
            target=f"{'W' if width == 32 else 'X'}{target}",
            base="X0",
            byte_offset=fmt(offset),
            width_bits=width,
            value=_origin_record(origin),
        )
        return origin

    def store_scalar(relative: int, expected: tuple[int, int, int, int]) -> Origin:
        va = CALLER_START + relative
        decoded = decode_str_unsigned(image.word(va))
        if decoded != expected:
            raise OriginError(f"stack field store changed at {fmt(va)}")
        width, source, base, offset = decoded
        if base != 31:
            raise OriginError(f"caller store base is not SP at {fmt(va)}")
        origin = regs.get(source, UNKNOWN)
        stack.store(offset, width // 8, origin)
        add_observation(
            va,
            "STR_UNSIGNED",
            source=f"{'W' if width == 32 else 'X'}{source}",
            base="SP",
            byte_offset=fmt(offset),
            width_bits=width,
            value=_origin_record(origin),
        )
        return origin

    sub = decode_add_sub_imm(image.word(CALLER_START))
    if sub != ("SUB", 31, 31, 0x60, 0, 64):
        raise OriginError("caller stack allocation changed")
    stp = decode_stp_unsigned(image.word(CALLER_START + 0x04))
    if stp != (64, 29, 30, 31, 0x50):
        raise OriginError("caller frame save changed")
    frame = decode_add_sub_imm(image.word(CALLER_START + 0x08))
    if frame != ("ADD", 29, 31, 0x50, 0, 64):
        raise OriginError("caller frame pointer setup changed")
    add_observation(CALLER_START, "SUB_SP", byte_offset=fmt(0x60))
    add_observation(CALLER_START + 0x04, "STP_FRAME", byte_offset=fmt(0x50))
    add_observation(CALLER_START + 0x08, "ADD_FRAME", byte_offset=fmt(0x50))

    add_observation(
        QUERY_CALL_VA,
        "BL",
        target=fmt(QUERY_CALL_TARGET),
        return_value=_origin_record(return_value),
    )
    orr = decode_orr_wzr_imm(image.word(CALLER_START + 0x10))
    if orr != (8, 1):
        raise OriginError("constant object-field initializer changed")
    regs[8] = Origin("CONSTANT", base="1", width_bits=32)
    add_observation(CALLER_START + 0x10, "ORR_W_IMM", target="W8", value=1)

    # Execute the exact program order.  In particular, the address base for
    # every load is read before any destination register overwrite.
    load_scalar(0x14, (64, 9, 0, 0x20))
    store_scalar(0x18, (32, 8, 31, 0x20))
    load_scalar(0x1C, (32, 10, 0, 0x00))
    store_scalar(0x20, (32, 10, 31, 0x24))
    load_scalar(0x24, (32, 11, 0, 0x04))
    store_scalar(0x28, (32, 11, 31, 0x28))
    load_scalar(0x2C, (32, 12, 0, 0x08))
    store_scalar(0x30, (32, 12, 31, 0x2C))
    load_scalar(0x34, (32, 13, 0, 0x0C))
    store_scalar(0x38, (32, 13, 31, 0x30))
    load_scalar(0x3C, (32, 14, 0, 0x10))
    store_scalar(0x40, (64, 9, 31, 0x08))
    store_scalar(0x44, (32, 14, 31, 0x34))
    load_scalar(0x48, (64, 8, 0, 0x18))

    store_scalar(0x4C, (64, 8, 31, 0x00))
    qload = decode_q_sp(image.word(CALLER_START + 0x50))
    if qload != ("LDR_Q", 0, 0):
        raise OriginError("Q0 stack load changed")
    q0 = stack.load_vector_q(0)
    add_observation(CALLER_START + 0x50, "LDR_Q", target="Q0", base="SP", byte_offset=fmt(0),
                    lanes=[_origin_record(lane) for lane in q0.lanes])
    qstore = decode_q_sp(image.word(CALLER_START + 0x54))
    if qstore != ("STR_Q", 0, 0x10):
        raise OriginError("Q0 stack store changed")
    stack.store(0x10, 16, q0)
    add_observation(CALLER_START + 0x54, "STR_Q", source="Q0", base="SP", byte_offset=fmt(0x10))

    pair = decode_ldp_unsigned(image.word(CALLER_START + 0x58))
    if pair != (64, 11, 10, 31, 0x10):
        raise OriginError("Q0 pair unpack changed")
    regs[11] = stack.load_scalar(0x10, 8)
    regs[10] = stack.load_scalar(0x18, 8)
    add_observation(CALLER_START + 0x58, "LDP_UNSIGNED", targets=["X11", "X10"], base="SP",
                    byte_offset=fmt(0x10), values=[_origin_record(regs[11]), _origin_record(regs[10])])
    store_scalar(0x5C, (64, 10, 31, 0x40))
    load_scalar(0x60, (64, 12, 0, 0x28))

    add_sp = decode_add_sp_imm(image.word(CALLER_START + 0x64))
    if add_sp != (0, OBJECT_BASE_OFFSET):
        raise OriginError("consumer object address construction changed")
    object_address = Origin("STACK_ADDRESS", base="SP", offset=OBJECT_BASE_OFFSET, width_bits=64)
    regs[0] = object_address
    add_observation(CALLER_START + 0x64, "ADD_SP", target="X0", byte_offset=fmt(OBJECT_BASE_OFFSET),
                    value=_origin_record(object_address))
    store_scalar(0x68, (64, 11, 31, 0x38))
    store_scalar(0x6C, (64, 12, 31, 0x48))
    add_observation(CONSUMER_CALLER_VA, "BL", target=fmt(CONSUMER_START), argument=_origin_record(object_address))

    # The range ends before RET, but pin and record the epilogue/return shape.
    add_observation(CALLER_START + 0x74, "LDP_FRAME", byte_offset=fmt(0x50))
    add_observation(CALLER_START + 0x78, "ADD_SP", byte_offset=fmt(0x60))
    add_observation(CALLER_END, "RET")

    expected_return_offsets = {"W3": 0x0C, "X0": 0x18, "X1": 0x20, "X2": 0x28}
    object_fields: dict[str, dict[str, Any]] = {}
    for register, (object_offset, width) in SETTER_ARGUMENT_FIELDS.items():
        origin = stack.load_scalar(OBJECT_BASE_OFFSET + object_offset, width // 8)
        expected_offset = expected_return_offsets[register]
        if origin.kind != "MEMORY_FIELD" or origin.base != return_value.base or origin.offset != expected_offset:
            raise OriginError(f"object field {register} origin changed")
        if origin.width_bits != width:
            raise OriginError(f"object field {register} width changed")
        object_fields[register] = {
            "register": register,
            "object_offset": fmt(object_offset),
            "width_bits": width,
            **_origin_record(origin),
        }

    return {
        "range": caller_range,
        "caller_range": caller_range,
        "trace_range": trace_range,
        "query_call_range": query_range,
        "consumer_call_range": consumer_range,
        "consumer_entry_range": consumer_entry,
        "direct_callers": {"count": len(callers), "callers": callers},
        "query_call": {"va": fmt(QUERY_CALL_VA), "target": fmt(QUERY_CALL_TARGET), "return": _origin_record(return_value)},
        "consumer_call": {"va": fmt(CONSUMER_CALLER_VA), "target": fmt(CONSUMER_START), "object_argument": _origin_record(object_address)},
        "object_base": {"base": "SP", "offset": fmt(OBJECT_BASE_OFFSET), "opaque": True},
        "object_fields": object_fields,
        "observations": observations,
        "status": "SUPPORTED_BOUNDED_SYMBOLIC_CALLER_OBJECT_TRACE",
        "current_values": "UNKNOWN",
    }


def load_exact(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OriginError(f"cannot open exact XBL: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != XBL_SIZE:
            raise OriginError("exact XBL size/type mismatch")
        chunks: list[bytes] = []
        remaining = XBL_SIZE
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise OriginError("exact XBL truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OriginError("exact XBL changed during read")
        data = b"".join(chunks)
        if sha256(data) != XBL_SHA256:
            raise OriginError("exact XBL SHA-256 mismatch")
        return data
    finally:
        os.close(fd)


def definition_of_done() -> dict[str, Any]:
    reason = "NOT_APPLICABLE: bounded host-only static trace; no device or runtime state was touched"
    return {
        "target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"},
        "build": {"status": "NOT_APPLICABLE", "reason": reason},
        "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."},
        "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_caller_object_origin_020b.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."},
        "repetitions": {"status": "NOT_APPLICABLE", "reason": reason},
        "rollback": {"status": "NOT_APPLICABLE", "reason": reason},
        "recovery": {"status": "NOT_APPLICABLE", "reason": reason},
        "device_binding": {"status": "NOT_APPLICABLE", "reason": reason},
        "tool_and_build": {"build": "NOT_APPLICABLE", "build_reason": "Interpreted host Python; no firmware/kernel build.", "tool": f"{Path(__file__).name} schema {SCHEMA}"},
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    image = Image(load_exact(firmware_dir / XBL_NAME))
    trace = trace_object(image)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {
            "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256},
            "caller": trace["caller_range"],
            "caller_trace": trace["trace_range"],
            "consumer_entry": trace["consumer_entry_range"],
            "consumer_start": fmt(CONSUMER_START),
            "consumer_direct_caller": fmt(CONSUMER_CALLER_VA),
            "query_call": {"va": fmt(QUERY_CALL_VA), "target": fmt(QUERY_CALL_TARGET), "range": trace["query_call_range"]},
            "consumer_call": {"va": fmt(CONSUMER_CALLER_VA), "target": fmt(CONSUMER_START), "range": trace["consumer_call_range"]},
        },
        "trace": trace,
        "scope": {"model": "ONE_EXACT_DIRECT_CALLER_STACK_OBJECT", "recognized_forms": ["SUB_SP", "STP/LDP_FRAME", "ADD_SP_IMMEDIATE", "ORR_WZR_IMMEDIATE", "LDR/STR_UNSIGNED", "LDR/STR_Q_SP", "LDP_UNSIGNED", "BL_DIRECT", "RET"], "runtime_values": "UNKNOWN", "type_inference": "UNKNOWN", "indirect_paths": "UNKNOWN", "never_scan_arbitrary_ranges": True},
        "claims": {
            "PROVED": [
                "The exact retained A90 XBL is bound by size and SHA-256 before analysis.",
                "The exact consumer 0x9fc023c8 has one direct BL caller at 0x9fc22d24.",
                "The bounded caller constructs the consumer object at SP+0x20 from fields of the opaque BL 0x9fc160b8 return, plus one constant initializer.",
                "Within the exact stack-object model, the 020A setter arguments resolve to return-object fields W3=[return+0x0c], X0=[return+0x18], X1=[return+0x20], and X2=[return+0x28].",
            ],
            "SUPPORTED": ["The caller/object data-flow edge is reproducible under the exact finite model; the callee return may be configuration-like but its type and role are not established."],
            "HYPOTHESIS": ["The opaque BL 0x9fc160b8 return may be a runtime configuration object carrying controller-base-like fields."],
            "REFUTED": [],
            "UNKNOWN": ["Runtime execution, callee return values/type/currentness, alternate or indirect callers, register semantics outside the recognized forms, physical-to-DRAM mapping, transform mutability, protected-memory reach, aliasing and bypass."],
        },
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only symbolic trace; no activation or live state was accessed."},
        "definition_of_done": definition_of_done(),
    }


def write_no_clobber(path: Path, payload: bytes) -> dict[str, Any]:
    if not path.parent.is_dir():
        raise OriginError(f"manifest parent does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise OriginError(f"manifest output already exists or is unsafe: {path}") from exc
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OriginError("manifest write made no progress")
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
    except (OriginError, OSError) as exc:
        print(f"020B: {exc}", file=__import__("sys").stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
