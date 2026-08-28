#!/usr/bin/env python3
"""Host-only bounded trace of the SDM855 XBL controller-base setter.

This is a deliberately small follow-on to the earlier XBL DCB consumer
cross-reference.  It validates the exact candidate setter at ``0x9fc06410``
and its unique direct ``BL`` caller at ``0x9fc023f0``, then traces only the
five-instruction pre-call block.  The result is symbolic: values are reported
as fields of the incoming ``X0`` object, never as current physical or MMIO
addresses.

The model is fail-closed.  It recognizes only the exact MOV-copy, unsigned
LDR, unsigned LDP, and direct BL forms needed by the pinned block.  It does
not follow indirect branches/calls, execute firmware, infer a type for the
incoming object, or claim that any field is a controller base at runtime.
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
MANIFEST_DIR = REPO_ROOT / "evidence/manifests"

SCHEMA = "sm8150-xbl-setter-base-trace-v1"
EXPERIMENT_ID = "020A-setter-base-trace"
MODE = "HOST_ONLY_READ_ONLY"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

SETTER_START = 0x9FC06410
SETTER_END = 0x9FC0643C
SETTER_SIZE = SETTER_END - SETTER_START
SETTER_SHA256 = "4f90392f2e5c34415ad0bb4709227445f3cad1d2444b57a90fa645f1488e063a"

CALLER_VA = 0x9FC023F0
# The pre-call block starts at the MOV which preserves incoming X0 in X19 and
# ends immediately after BL.  It is intentionally separate from the larger
# context window recorded by Experiments 020A/027.
CALLER_TRACE_START = 0x9FC023E0
CALLER_TRACE_END = 0x9FC023F4
CALLER_TRACE_SIZE = CALLER_TRACE_END - CALLER_TRACE_START
CALLER_TRACE_SHA256 = "2c33e795998978ddc8ddd01c1b168abb24033aa78f168ea73ef73ac4c335bef5"
CALLER_CONTEXT_START = 0x9FC023D4
CALLER_CONTEXT_END = 0x9FC02430
CALLER_CONTEXT_SIZE = CALLER_CONTEXT_END - CALLER_CONTEXT_START
CALLER_CONTEXT_SHA256 = "c7c47500cd7d252f3e6aa310e19c6b908c11910effe0121e50f9edbff430fa18"

# The global slots are static ELF addresses.  Their interpretation as DDR
# controller state remains the prior candidate-segment inference, not a new
# symbol proof made by this tool.
EXPECTED_SETTER_GLOBALS = {
    0x9FC38368: ("XZR", 64),
    0x9FC38360: ("X0", 64),
    0x9FC38370: ("X1", 64),
    0x9FC38378: ("X2", 64),
    0x9FC38350: ("W3", 32),
}
EXPECTED_ARGUMENT_FIELDS = {
    "X0": (0x18, 64),
    "X1": (0x20, 64),
    "X2": (0x28, 64),
    "W3": (0x10, 32),
}


class TraceError(ValueError):
    """Raised when an exact input or bounded static precondition fails."""


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
    """Minimal, independent ELF64 PT_LOAD view for this bounded pass."""

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
            raise TraceError("input is not a little-endian ELF64 image")
        if data[6] != 1:
            raise TraceError("unsupported ELF identification version")
        self.data = data
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x36)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
        if phentsize < 56 or phnum > 4096:
            raise TraceError("invalid ELF64 program-header shape")
        if phoff < 64 or phoff + phentsize * phnum > len(data):
            raise TraceError("ELF64 program-header table is truncated")
        segments: list[Segment] = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            p_type, flags, file_offset, vaddr, _paddr, file_size, mem_size, _align = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if p_type != 1:
                continue
            if mem_size < file_size:
                raise TraceError(f"PT_LOAD {index} has memsz smaller than filesz")
            if file_offset > len(data) or file_size > len(data) - file_offset:
                raise TraceError(f"PT_LOAD {index} exceeds input")
            segment = Segment(file_offset, vaddr, file_size, mem_size, flags)
            for prior in segments:
                if not (
                    segment.file_offset + segment.file_size <= prior.file_offset
                    or prior.file_offset + prior.file_size <= segment.file_offset
                ):
                    raise TraceError("overlapping file-backed PT_LOAD ranges")
                if not (
                    segment.vaddr + segment.file_size <= prior.vaddr
                    or prior.vaddr + prior.file_size <= segment.vaddr
                ):
                    raise TraceError("overlapping virtual PT_LOAD ranges")
            segments.append(segment)
        self.segments = segments

    def segment_for(self, vaddr: int, size: int = 1) -> Segment | None:
        if size < 0:
            raise TraceError("negative mapped read size")
        matches = [
            segment
            for segment in self.segments
            if segment.vaddr <= vaddr
            and vaddr + size <= segment.vaddr + segment.file_size
        ]
        if len(matches) > 1:
            raise TraceError(f"ambiguous virtual mapping at {fmt(vaddr)}")
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
            count = segment.file_size // 4
            for index in range(count):
                yield segment.vaddr + index * 4, struct.unpack_from(
                    "<I", self.data, segment.file_offset + index * 4
                )[0]


def decode_bl_target(word: int, va: int) -> int | None:
    if word & 0xFC000000 != 0x94000000:
        return None
    return va + 4 * sign_extend(word & 0x03FFFFFF, 26)


def decode_mov_register(word: int) -> tuple[int, int] | None:
    """Decode the register-only ORR alias, returning ``(source, destination)``."""

    # ORR (shifted register), 64-bit, LSL #0; register 31 is XZR here.
    if word & 0xFFE0FC00 != 0xAA000000:
        return None
    if (word >> 5) & 0x1F != 31 or (word >> 10) & 0x3F:
        return None
    return (word >> 16) & 0x1F, word & 0x1F


def decode_ldr_unsigned(word: int) -> tuple[int, int, int, int] | None:
    """Return ``(width_bits, target, base, byte_offset)`` for LDR W/X."""

    prefix = word & 0xFFC00000
    if prefix == 0xB9400000:
        width = 32
        scale = 4
    elif prefix == 0xF9400000:
        width = 64
        scale = 8
    else:
        return None
    return width, word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * scale


def decode_ldp_unsigned(word: int) -> tuple[int, int, int, int] | None:
    """Return ``(width_bits, target1, target2, base, byte_offset)`` for LDP.

    The tuple has five elements despite the compact docstring notation above.
    Only the 64-bit, unsigned-offset, no-writeback form is accepted.
    """

    if word & 0xFFC00000 != 0xA9400000:
        return None
    # Reject pre/post-index and the 32-bit pair form.  The exact opcode has
    # bit 31 set and bits 24:23 clear for unsigned-offset LDP.
    if word & (1 << 23) or not (word & (1 << 31)):
        return None
    return (
        64,
        word & 0x1F,
        (word >> 10) & 0x1F,
        (word >> 5) & 0x1F,
        ((word >> 15) & 0x7F) * 8,
    )


def decode_str_unsigned(word: int) -> tuple[int, int, int, int] | None:
    """Return ``(width_bits, source, base, byte_offset)`` for STR W/X."""

    prefix = word & 0xFFC00000
    if prefix == 0xB9000000:
        width = 32
        scale = 4
    elif prefix == 0xF9000000:
        width = 64
        scale = 8
    else:
        return None
    return width, word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * scale


@dataclass(frozen=True)
class Origin:
    """A symbolic value in the small bounded data-flow lattice."""

    kind: str
    base: str | None = None
    offset: int | None = None
    width_bits: int | None = None

    def describe(self) -> str:
        if self.kind == "ENTRY_ARGUMENT":
            return self.base or "ENTRY_ARGUMENT"
        if self.kind == "MEMORY_FIELD":
            if self.offset is None:
                return f"MEMORY[{self.base}+?]"
            return f"MEMORY[{self.base}+0x{self.offset:x}]"
        return "UNKNOWN"


UNKNOWN = Origin("UNKNOWN")


def _entry_x0() -> Origin:
    return Origin("ENTRY_ARGUMENT", base="incoming X0", width_bits=64)


def _field(base: Origin, offset: int, width_bits: int) -> Origin:
    if base.kind != "ENTRY_ARGUMENT" or base.base != "incoming X0":
        raise TraceError("caller base is not the pinned incoming X0 origin")
    return Origin("MEMORY_FIELD", base=base.base, offset=offset, width_bits=width_bits)


def _fmt_reg(reg: int, width_bits: int) -> str:
    return f"{'W' if width_bits == 32 else 'X'}{reg}"


def direct_callers(image: Image, target: int) -> list[dict[str, str]]:
    callers: list[dict[str, str]] = []
    for va, word in image.executable_words():
        destination = decode_bl_target(word, va)
        if destination == target:
            callers.append({"va": fmt(va), "target": fmt(destination), "kind": "BL"})
    return callers


def _range_record(image: Image, start: int, end: int, expected_sha: str, label: str) -> dict[str, Any]:
    if end <= start:
        raise TraceError(f"{label} range is empty")
    data = image.read(start, end - start)
    digest = sha256(data)
    if digest != expected_sha:
        raise TraceError(f"{label} exact range hash mismatch")
    offset = image.file_offset(start, end - start)
    if offset is None:
        raise TraceError(f"{label} is not fully file-backed")
    return {
        "start": fmt(start),
        "end_exclusive": fmt(end),
        "file_offset": fmt(offset),
        "size": end - start,
        "sha256": digest,
    }


def validate_setter(image: Image) -> dict[str, Any]:
    """Decode the exact five-store setter, preserving static slot identity."""

    record = _range_record(image, SETTER_START, SETTER_END, SETTER_SHA256, "setter")
    pages: dict[int, int] = {}
    stores: list[dict[str, Any]] = []
    for va in range(SETTER_START, SETTER_END, 4):
        word = image.word(va)
        # ADRP Xd, page is sufficient here; an unexpected instruction in the
        # pinned range is an error rather than an ignored decode hole.
        if word & 0x9F000000 == 0x90000000:
            immediate = sign_extend(
                ((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)), 21
            ) << 12
            page = ((va & ~0xFFF) + immediate) & 0xFFFFFFFFFFFFFFFF
            pages[word & 0x1F] = page
            continue
        decoded = decode_str_unsigned(word)
        if decoded is not None:
            width_bits, source, base, byte_offset = decoded
            if base not in pages:
                raise TraceError("setter store uses an unresolved ADRP base")
            source_name = _fmt_reg(source, width_bits) if source != 31 else ("WZR" if width_bits == 32 else "XZR")
            destination = pages[base] + byte_offset
            stores.append(
                {
                    "store_va": fmt(va),
                    "global": fmt(destination),
                    "width_bits": width_bits,
                    "source": source_name,
                    "source_register": source_name,
                }
            )
            continue
        if word == 0xD65F03C0 and va == SETTER_END - 4:
            continue
        raise TraceError(f"unsupported instruction in exact setter at {fmt(va)}")

    if len(stores) != len(EXPECTED_SETTER_GLOBALS):
        raise TraceError("exact setter store count changed")
    actual = {int(row["global"], 16): (row["source"], row["width_bits"]) for row in stores}
    if actual != EXPECTED_SETTER_GLOBALS:
        raise TraceError("exact setter destination/source contract changed")
    return {
        "range": record,
        "store_count": len(stores),
        "stores": stores,
        "candidate_segment_identity": "SUPPORTED_PRIOR_BOUNDED_INFERENCE",
    }


def trace_caller_arguments(image: Image) -> dict[str, Any]:
    """Trace only the pinned linear pre-call block into symbolic fields."""

    trace_record = _range_record(
        image,
        CALLER_TRACE_START,
        CALLER_TRACE_END,
        CALLER_TRACE_SHA256,
        "caller pre-call trace",
    )
    context_record = _range_record(
        image,
        CALLER_CONTEXT_START,
        CALLER_CONTEXT_END,
        CALLER_CONTEXT_SHA256,
        "caller context",
    )
    word_at_call = image.word(CALLER_VA)
    if decode_bl_target(word_at_call, CALLER_VA) != SETTER_START:
        raise TraceError("pinned caller does not BL the exact setter")

    regs: dict[int, Origin] = {0: _entry_x0()}
    observations: list[dict[str, Any]] = []

    for va in range(CALLER_TRACE_START, CALLER_TRACE_END, 4):
        word = image.word(va)
        if va == CALLER_TRACE_START:
            decoded = decode_mov_register(word)
            if decoded != (0, 19):
                raise TraceError("pre-call trace does not preserve incoming X0 in X19")
            if 0 not in regs:
                raise TraceError("incoming X0 origin was lost before MOV")
            regs[19] = regs[0]
            observations.append({"va": fmt(va), "form": "MOV", "destination": "X19", "source": "incoming X0"})
            continue

        ldr = decode_ldr_unsigned(word)
        if ldr is not None:
            width_bits, target, base_register, byte_offset = ldr
            base = regs.get(base_register, UNKNOWN)
            origin = _field(base, byte_offset, width_bits)
            regs[target] = origin
            observations.append(
                {
                    "va": fmt(va),
                    "form": "LDR_UNSIGNED",
                    "target": _fmt_reg(target, width_bits),
                    "base": f"X{base_register}",
                    "byte_offset": fmt(byte_offset),
                    "origin": origin.describe(),
                    "width_bits": width_bits,
                }
            )
            continue

        ldp = decode_ldp_unsigned(word)
        if ldp is not None:
            width_bits, target1, target2, base_register, byte_offset = ldp
            base = regs.get(base_register, UNKNOWN)
            origin1 = _field(base, byte_offset, width_bits)
            origin2 = _field(base, byte_offset + width_bits // 8, width_bits)
            # The base is read before either destination is written.  This is
            # essential for LDP X0,X1,[X0,#imm] and is covered by tests.
            regs[target1] = origin1
            regs[target2] = origin2
            observations.append(
                {
                    "va": fmt(va),
                    "form": "LDP_UNSIGNED",
                    "targets": [f"X{target1}", f"X{target2}"],
                    "base": f"X{base_register}",
                    "byte_offset": fmt(byte_offset),
                    "origins": [origin1.describe(), origin2.describe()],
                    "width_bits": width_bits,
                }
            )
            continue

        destination = decode_bl_target(word, va)
        if destination is not None:
            if va != CALLER_VA or destination != SETTER_START:
                raise TraceError("unexpected branch in bounded pre-call trace")
            observations.append(
                {"va": fmt(va), "form": "BL", "target": fmt(destination), "callee": "candidate setter"}
            )
            continue
        raise TraceError(f"unsupported instruction in bounded pre-call trace at {fmt(va)}")

    argument_origins = {
        name: {
            "register": name,
            "origin": regs.get(int(name[1:]), UNKNOWN).describe(),
            "width_bits": width_bits,
        }
        for name, (_offset, width_bits) in EXPECTED_ARGUMENT_FIELDS.items()
    }
    for name, (offset, width_bits) in EXPECTED_ARGUMENT_FIELDS.items():
        origin = regs.get(int(name[1:]), UNKNOWN)
        if origin.kind != "MEMORY_FIELD" or origin.offset != offset or origin.width_bits != width_bits:
            raise TraceError(f"bounded argument origin changed for {name}")
    return {
        "trace_range": trace_record,
        "context_range": context_record,
        "call_site": {"va": fmt(CALLER_VA), "target": fmt(SETTER_START), "kind": "BL"},
        "observations": observations,
        "argument_origins": argument_origins,
        "entry": "incoming X0 is an opaque runtime object pointer",
        "status": "SUPPORTED_BOUNDED_SYMBOLIC_ARGUMENT_TRACE",
        "current_values": "UNKNOWN",
    }


def load_exact(path: Path, expected_size: int, expected_sha256: str, label: str) -> bytes:
    """Read one exact regular file without following symlinks or races."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise TraceError(f"cannot open exact {label}: {error}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise TraceError(f"exact {label} is not a regular file")
        if before.st_size != expected_size:
            raise TraceError(f"exact {label} size mismatch")
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError(f"exact {label} truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TraceError(f"exact {label} changed during read")
        data = b"".join(chunks)
        if len(data) != expected_size or sha256(data) != expected_sha256:
            raise TraceError(f"exact {label} SHA-256 mismatch")
        return data
    finally:
        os.close(fd)


def definition_of_done() -> dict[str, Any]:
    reason = "NOT_APPLICABLE: host-only static analysis; no device or runtime state was touched"
    return {
        "target": {
            "binding": "PROVED_EXACT_XBL_INPUT_HASH",
            "marketing_name": "A90 5G",
            "model": "SM-A908N",
            "soc": "SM8150",
            "soc_name": "Snapdragon 855",
        },
        "build": {"status": "NOT_APPLICABLE", "reason": reason},
        "timestamp": {
            "status": "NOT_APPLICABLE",
            "reason": "Deterministic host-only publication does not embed a wall-clock timestamp.",
        },
        "commands": {
            "status": "REDACTED_REPRODUCTION_TEMPLATE",
            "command": "python3 tools/sm8150_xbl_setter_base_trace_020a.py --output <public-manifest-path>",
            "reason": "Private input and output paths are redacted; pinned artifact hashes are retained.",
        },
        "repetitions": {"status": "NOT_APPLICABLE", "reason": reason},
        "rollback": {"status": "NOT_APPLICABLE", "reason": reason},
        "recovery": {"status": "NOT_APPLICABLE", "reason": reason},
        "device_binding": {"status": "NOT_APPLICABLE", "reason": reason},
        "tool_and_build": {
            "build": "NOT_APPLICABLE",
            "build_reason": "The analyzer is interpreted host Python; no firmware or kernel is built.",
            "tool": f"{Path(__file__).name} schema {SCHEMA}",
        },
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    data = load_exact(firmware_dir / XBL_NAME, XBL_SIZE, XBL_SHA256, XBL_NAME)
    image = Image(data)
    setter = validate_setter(image)
    caller = trace_caller_arguments(image)
    callers = direct_callers(image, SETTER_START)
    if callers != [{"va": fmt(CALLER_VA), "target": fmt(SETTER_START), "kind": "BL"}]:
        raise TraceError("exact XBL direct-caller census is not the pinned singleton")

    bindings: list[dict[str, Any]] = []
    for row in setter["stores"]:
        source = row["source"]
        if source in ("X0", "X1", "X2", "W3"):
            origin = caller["argument_origins"][source]
            bindings.append(
                {
                    "global": row["global"],
                    "setter_store_va": row["store_va"],
                    "setter_source": source,
                    "width_bits": row["width_bits"],
                    "caller_origin": origin["origin"],
                    "caller_field_width_bits": origin["width_bits"],
                }
            )
        else:
            bindings.append(
                {
                    "global": row["global"],
                    "setter_store_va": row["store_va"],
                    "setter_source": source,
                    "width_bits": row["width_bits"],
                    "caller_origin": "NOT_APPLICABLE_ZERO",
                    "caller_field_width_bits": None,
                }
            )
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {
            "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256},
            "exact_setter": {
                "start": fmt(SETTER_START),
                "end_exclusive": fmt(SETTER_END),
                "size": SETTER_SIZE,
                "sha256": SETTER_SHA256,
            },
            "caller_trace": {
                "start": fmt(CALLER_TRACE_START),
                "end_exclusive": fmt(CALLER_TRACE_END),
                "size": CALLER_TRACE_SIZE,
                "sha256": CALLER_TRACE_SHA256,
            },
            "caller_context": {
                "start": fmt(CALLER_CONTEXT_START),
                "end_exclusive": fmt(CALLER_CONTEXT_END),
                "size": CALLER_CONTEXT_SIZE,
                "sha256": CALLER_CONTEXT_SHA256,
            },
        },
        "scope": {
            "static_model": "SINGLE_DIRECT_CALL_PRECALL_LINEAR_BLOCK",
            "recognized_forms": ["MOV_REGISTER_COPY", "LDR_UNSIGNED", "LDP_UNSIGNED", "BL_DIRECT"],
            "fail_closed_on": [
                "UNSUPPORTED_INSTRUCTION",
                "INDIRECT_BRANCH_OR_CALL",
                "UNRESOLVED_BASE_ORIGIN",
                "EXACT_RANGE_HASH_MISMATCH",
                "DIRECT_CALLER_CARDINALITY_CHANGE",
            ],
            "instruction_count": CALLER_TRACE_SIZE // 4,
            "never_scan_arbitrary_ranges": True,
        },
        "setter": setter,
        "direct_callers": {"count": len(callers), "callers": callers},
        "caller_trace": caller,
        "setter_argument_bindings": bindings,
        "claims": {
            "PROVED": [
                "The exact retained A90 XBL is bound by its expected size and SHA-256 before analysis.",
                "The exact setter range [0x9fc06410,0x9fc0643c) has five static global stores: one XZR zero and four values sourced from X0, X1, X2 and W3.",
                "The exact XBL contains exactly one direct BL caller of the pinned setter, at 0x9fc023f0.",
                "Within the five-instruction pre-call block, the four setter argument registers resolve to incoming X0 fields: W3=[X0+0x10] (32-bit), X0=[X0+0x18] (64-bit), X1=[X0+0x20] (64-bit), and X2=[X0+0x28] (64-bit).",
                "The bounded result is symbolic and does not assign a current physical, DRAM, or MMIO destination to any field.",
            ],
            "SUPPORTED": [
                "The five static global destinations are compatible with the prior bounded candidate-segment DDR-driver interpretation; that segment identity remains an inference, not a symbol proof.",
                "The setter-to-caller data-flow edge is reproducible under the stated exact linear-block model.",
            ],
            "HYPOTHESIS": [
                "The incoming X0 object may be a runtime configuration object carrying controller-base-like fields; this tool does not establish its type or role.",
            ],
            "REFUTED": [],
            "UNKNOWN": [
                "Runtime origin and values of the incoming X0 object fields, boot execution, and currentness of the resulting globals.",
                "Whether any field is a DDR/MC/SHRM address, the final physical-to-DRAM mapping, and the identity or semantics of the static global slots.",
                "Indirect callers, BLR/BR reachability, alternate setter paths, writer identity outside the singleton direct caller, post-boot mutability or locking.",
                "Normal-World observability or modification, protected-memory reach, aliasing, and boundary bypass.",
            ],
        },
        "boundary_bypass": {
            "status": "NOT_AUTHORIZED",
            "device": "none",
            "smc": "none",
            "mmio": "none",
            "protected_memory": "none",
            "reason": "Host-only static symbolic trace; no activation or live state was accessed.",
        },
        "definition_of_done": definition_of_done(),
    }


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Publish once, without following a symlink or replacing an artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short manifest write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir)
    payload = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")
    write_no_clobber(args.output, payload)
    print(f"wrote {args.output} ({len(payload)} bytes, sha256={sha256(payload)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
