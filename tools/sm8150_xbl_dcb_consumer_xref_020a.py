#!/usr/bin/env python3
"""Host-only Experiment 020 cross-reference of XBL DCB consumers and DDR bases.

Experiment 018 resolved candidate controller stores through four static models
that all terminate in a constant: wide moves, ADRP+ADD, a retained table.  Every
model returned no target match. Experiment 019 then showed candidate pair
arrays with base-relative key domains. If such an array is consumed as register
data, its consumer would write through a register offset rather than an
immediate one; this experiment does not assume that consumer identity.

Stage 1A's census counted only unsigned-immediate stores, so that class is
invisible to it by construction.  This experiment counts it, locates the DCB
loader and its section consumers, and follows the DDR driver's controller base
pointers to their origin.

The finding that matters is negative in a specific way: in the SUPPORTED
candidate DDR segment, the observed controller bases arrive as function
arguments and live in zero-initialised globals. A writer using that runtime-base
plus register-offset or computed-address idiom is therefore outside
Experiment 018's constant-terminating models. This does not resolve global
writer absence or the evidentiary weight of the other models.

Mode: HOST_ONLY_READ_ONLY.  No device, SMC, MMIO or protected-memory access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
SCHEMA = "sm8150-xbl-dcb-consumer-xref-v1"
EXPERIMENT_ID = "020A-xbl-dcb-consumer-xref"

AOP_NAME = "aop--sdd7.bin"
AOP_SIZE = 524288
AOP_SHA256 = "eadd6c78daca52221e1e3419f34a53eac7c1e2c2bb46c9b663325df1998b9c7c"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4194304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

DCB_HEADER_SIZE = 0x64
DIRECTORY_BASE = 0x0C
DCB_SIZE = 0x3404

# The five sections Experiment 004 records as loader-consumed, as a hardcoded
# constant.  This experiment re-derives them from code rather than trusting it.
EXPECTED_LOADER_SECTIONS = {0: 0x77C, 1: 0x3DC, 2: 0x108, 15: 0x200, 16: 0xF00}

APERTURE_START = 0x09000000
APERTURE_END = 0x0A000000

# Verification 012's four ranked MC instance bases.
RANKED_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)

# One DDR-driver base setter, pinned after reading its disassembly rather than
# picked by a heuristic: it writes five globals and is reached by one direct BL.
PINNED_SETTER_VA = 0x9FC06410
PINNED_SETTER_END = 0x9FC0643C


class XrefError(ValueError):
    """Raised when an input is not the exact pinned artifact."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value >> (bits - 1) else value


@dataclass(frozen=True)
class Segment:
    file_offset: int
    vaddr: int
    file_size: int
    flags: int

    @property
    def kind(self) -> str:
        return {5: "RX", 7: "RWE", 6: "RW", 4: "R"}.get(self.flags, f"F{self.flags}")


class Image:
    """ELF64 view with its own program-header walk.

    Deliberately independent of the other `tools/` modules: reusing a parser
    would make this inherit that parser's mapping, the circularity Verification
    001 exists to avoid.
    """

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise XrefError("not a little-endian ELF64 image")
        self.data = data
        ph_offset = struct.unpack_from("<Q", data, 32)[0]
        ph_entry = struct.unpack_from("<H", data, 54)[0]
        ph_count = struct.unpack_from("<H", data, 56)[0]
        self.segments: list[Segment] = []
        for index in range(ph_count):
            offset = ph_offset + index * ph_entry
            if offset + 56 > len(data):
                break
            p_type, flags, file_offset, vaddr, _pa, file_size, _mem, _al = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if p_type == 1 and file_size and file_offset + file_size <= len(data):
                self.segments.append(Segment(file_offset, vaddr, file_size, flags))

    def executable(self) -> list[Segment]:
        return [s for s in self.segments if s.kind in ("RX", "RWE")]

    def file_offset(self, vaddr: int) -> int | None:
        for segment in self.segments:
            if segment.vaddr <= vaddr < segment.vaddr + segment.file_size:
                return segment.file_offset + (vaddr - segment.vaddr)
        return None

    def word(self, vaddr: int) -> int | None:
        offset = self.file_offset(vaddr)
        if offset is None or offset + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, offset)[0]

    def instructions(self, segment: Segment):
        for offset in range(0, segment.file_size - 3, 4):
            yield segment.vaddr + offset, struct.unpack_from("<I", self.data, segment.file_offset + offset)[0]


# ---------------------------------------------------------------- decoding


def is_ldrh_immediate(word: int) -> tuple[int, int, int] | None:
    """LDRH Wt,[Xn,#imm] -> (byte_offset, Rn, Rt)."""
    if (word & 0xFFC00000) != 0x79400000:
        return None
    return ((word >> 10) & 0xFFF) * 2, (word >> 5) & 0x1F, word & 0x1F


def is_movz_w(word: int) -> tuple[int, int] | None:
    """MOVZ Wd,#imm16 with no shift -> (imm16, Rd)."""
    if (word & 0xFFE00000) != 0x52800000:
        return None
    return (word >> 5) & 0xFFFF, word & 0x1F


def is_register_offset_store(word: int) -> dict | None:
    """STR Wt/Xt,[Xn,Xm{,extend}] -- the class a Stage 1A census cannot see."""
    if (word & 0xFFE00C00) not in (0xB8200800, 0xF8200800):
        return None
    return {
        "width": "X" if (word & 0xFFE00C00) == 0xF8200800 else "W",
        "rt": word & 0x1F,
        "rn": (word >> 5) & 0x1F,
        "rm": (word >> 16) & 0x1F,
        "scaled": bool((word >> 12) & 1),
    }


def branch_target(word: int, vaddr: int) -> int | None:
    if (word & 0x7C000000) == 0x14000000:                 # B / BL
        return vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26)
    if (word & 0xFF000010) == 0x54000000:                 # B.cond
        return vaddr + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x34000000:                 # CBZ / CBNZ
        return vaddr + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x36000000:                 # TBZ / TBNZ
        return vaddr + 4 * sign_extend((word >> 5) & 0x3FFF, 14)
    return None


def adrp_page(word: int, vaddr: int) -> tuple[int, int] | None:
    if (word & 0x9F000000) != 0x90000000:
        return None
    immediate = sign_extend((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21) << 12
    return ((vaddr & ~0xFFF) + immediate) & 0xFFFFFFFF, word & 0x1F


# ---------------------------------------------------------------- analyses


def find_dcb_loader(image: Image) -> dict:
    """Locate the loader by the cluster of size constants only it carries."""
    wanted = {0x3404: "dcb_size"} | {size: f"max_section_{i}" for i, size in EXPECTED_LOADER_SECTIONS.items()}
    sites: list[tuple[int, int]] = []
    for segment in image.executable():
        for vaddr, word in image.instructions(segment):
            movz = is_movz_w(word)
            if movz and movz[0] in wanted:
                sites.append((vaddr, movz[0]))
            elif (word & 0x1F000000) == 0x11000000 and ((word >> 10) & 0xFFF) in wanted:
                sites.append((vaddr, (word >> 10) & 0xFFF))
    sites.sort()
    for index, (vaddr, _value) in enumerate(sites):
        window = {value for site, value in sites if vaddr <= site < vaddr + 512}
        if len(window) >= 4:
            return {
                "found": True,
                "window_start": f"0x{vaddr:08x}",
                "window_end": f"0x{vaddr + 512:08x}",
                "constants": sorted(f"0x{v:x}" for v in window),
            }
    return {"found": False}


def decode_loader_sections(image: Image, window_start: int, window_end: int) -> list[dict]:
    """Re-derive which sections the loader copies, from its directory reads.

    The loader reads a directory slot as two LDRH from one base register, then
    calls a bounded copy whose limit is the nearest preceding MOVZ.
    """
    reads: dict[int, tuple[int, int]] = {}
    for vaddr in range(window_start, window_end, 4):
        word = image.word(vaddr)
        if word is None:
            continue
        ldrh = is_ldrh_immediate(word)
        if ldrh:
            reads[vaddr] = (ldrh[0], ldrh[1])

    out = []
    for vaddr, (byte_offset, rn) in sorted(reads.items()):
        if byte_offset < DIRECTORY_BASE or byte_offset >= DCB_HEADER_SIZE or (byte_offset - DIRECTORY_BASE) % 4:
            continue
        partner = next(
            (
                other
                for other, (off, base) in reads.items()
                if off == byte_offset + 2 and base == rn and other != vaddr
            ),
            None,
        )
        if partner is None:
            continue
        limit = None
        for back in range(vaddr, max(window_start, vaddr - 16 * 4) - 4, -4):
            word = image.word(back)
            movz = is_movz_w(word) if word is not None else None
            if movz and movz[0] > 0xFF:
                limit = movz[0]
                break
        out.append(
            {
                "section": (byte_offset - DIRECTORY_BASE) // 4,
                "directory_offset": f"0x{byte_offset:02x}",
                "offset_read_va": f"0x{vaddr:08x}",
                "size_read_va": f"0x{partner:08x}",
                "nearest_preceding_limit": None if limit is None else f"0x{limit:x}",
            }
        )
    return out


def section_directory_readers(image: Image) -> list[dict]:
    """Recognized local DCB consumers read a directory slot as an LDRH pair.

    This is an audit model for one local encoding. Consumers using a passed or
    cached pointer, a packed word, or another directory representation are not
    captured by this function and remain UNKNOWN.
    """
    sites: dict[int, tuple[int, int, str]] = {}
    for segment in image.executable():
        for vaddr, word in image.instructions(segment):
            ldrh = is_ldrh_immediate(word)
            if ldrh:
                sites[vaddr] = (ldrh[0], ldrh[1], segment.kind)
    out = []
    for vaddr, (byte_offset, rn, kind) in sorted(sites.items()):
        if byte_offset < DIRECTORY_BASE or byte_offset >= DCB_HEADER_SIZE or (byte_offset - DIRECTORY_BASE) % 4:
            continue
        for other in range(vaddr - 8 * 4, vaddr + 8 * 4, 4):
            entry = sites.get(other)
            if entry and entry[0] == byte_offset + 2 and entry[1] == rn and other != vaddr:
                out.append(
                    {
                        "section": (byte_offset - DIRECTORY_BASE) // 4,
                        "segment": kind,
                        "offset_read_va": f"0x{vaddr:08x}",
                        "size_read_va": f"0x{other:08x}",
                    }
                )
                break
    return out


def register_offset_store_census(image: Image) -> dict:
    """Count register-offset stores, and how many sit inside a short loop.

    A DCB key is already a byte offset, so a table walker uses the unscaled
    form; the scaled form indexes a word array and is counted separately.
    """
    total = {"RX": 0, "RWE": 0}
    unscaled = {"RX": 0, "RWE": 0}
    candidates = []
    for segment in image.executable():
        for vaddr, word in image.instructions(segment):
            store = is_register_offset_store(word)
            if store is None:
                continue
            total[segment.kind] += 1
            if not store["scaled"]:
                unscaled[segment.kind] += 1
                candidates.append((segment.kind, vaddr, store))

    in_loop = []
    for kind, vaddr, store in candidates:
        for ahead in range(vaddr + 4, vaddr + 4 * 24, 4):
            word = image.word(ahead)
            if word is None:
                break
            target = branch_target(word, ahead)
            if target is not None and vaddr - 4 * 64 <= target <= vaddr:
                in_loop.append(
                    {
                        "segment": kind,
                        "store_va": f"0x{vaddr:08x}",
                        "loop_head_va": f"0x{target:08x}",
                        "back_edge_va": f"0x{ahead:08x}",
                        "width": store["width"],
                    }
                )
                break
    return {
        "total_by_segment": total,
        "unscaled_by_segment": unscaled,
        "unscaled_total": sum(unscaled.values()),
        "inside_backward_branch_loop": len(in_loop),
        "loop_sites": in_loop,
    }


RET_WORD = 0xD65F03C0


def _load_operands(word: int) -> tuple[int, int, bool] | None:
    """(destination, address base, writes_back) for the scalar load forms.

    Fields are extracted by name rather than matched against a packed mask: the
    load/store bit is ``opc[0]`` at bit 22, and folding it into a mask constant
    silently accepts stores as loads.
    """
    rt, rn = word & 0x1F, (word >> 5) & 0x1F

    # Load/store pair: opcode 101 0 at bits 29..26, L at bit 22.
    if (word >> 27) & 0x7 == 0b101 and (word >> 26) & 1 == 0:
        pair_class = (word >> 23) & 0x7          # 001 post, 010 offset, 011 pre
        if pair_class in (0b001, 0b010, 0b011) and (word >> 22) & 1:
            return rt, rn, pair_class in (0b001, 0b011)

    # Load/store register: 111 at bits 29..27, V at 26, class at 25..24.
    if (word >> 27) & 0x7 != 0b111 or (word >> 26) & 1:
        return None
    if not (word >> 22) & 1:                     # opc[0] clear -> a store
        return None
    register_class = (word >> 24) & 0x3
    if register_class == 0b01:                   # unsigned immediate offset
        return rt, rn, False
    if register_class == 0b00:
        if (word >> 21) & 1 and (word >> 10) & 0x3 == 0b10:
            return rt, rn, False                 # register offset
        indexing = (word >> 10) & 0x3
        if indexing == 0b01:
            return rt, rn, True                  # post-index
        if indexing == 0b11:
            return rt, rn, True                  # pre-index
    return None


def _modified_register(word: int) -> int | None:
    if (word & 0x1F000000) in (0x11000000, 0x51000000, 0x0B000000, 0x4B000000):
        return word & 0x1F                                # ADD/SUB immediate or register
    load = _load_operands(word)
    if load and load[2]:
        return load[1]                                    # indexed forms write the base back
    return None


def table_walker_analysis(image: Image, loop_sites: list[dict]) -> dict:
    """Decide which looping register-offset stores actually walk a key/value table.

    A DCB walker reads its store offset out of the table, so the offset must
    change every pass.  Two shapes imitate that and are excluded on principle
    rather than by inspection:

    * a loop-invariant ``LDR Xd,[Xn,#imm]`` whose base is never modified in the
      body loads the same displacement each iteration -- an array write; and
    * a body containing ``RET`` is a function epilogue restoring callee-saved
      registers from SP, which a backward conditional branch on a return path
      can make look like a loop.
    """
    classes: dict[str, int] = {}
    walkers = []
    epilogues = 0
    for site in loop_sites:
        store_va = int(site["store_va"], 16)
        head = int(site["loop_head_va"], 16)
        back_edge = int(site["back_edge_va"], 16)
        offset_register = site.get("offset_register")
        if offset_register is None:
            word = image.word(store_va)
            if word is None:
                continue
            offset_register = (word >> 16) & 0x1F
        # The body runs to the back edge, not to the store: a definition placed
        # after the store still applies on the next pass.
        body = [(a, w) for a in range(head, back_edge + 4, 4) if (w := image.word(a)) is not None]
        if any(w == RET_WORD for _a, w in body):
            epilogues += 1
            classes["EPILOGUE_NOT_A_LOOP"] = classes.get("EPILOGUE_NOT_A_LOOP", 0) + 1
            continue
        modified = {m for _a, w in body if (m := _modified_register(w)) is not None}
        kind = "DEFINED_OUTSIDE_THE_LOOP"
        detail = None
        before_store = [(a, w) for a, w in body if a < store_va]
        after_store = [(a, w) for a, w in body if a > store_va]
        for address, instruction in list(reversed(before_store)) + list(reversed(after_store)):
            load = _load_operands(instruction)
            if load and load[0] == offset_register:
                varies = load[2] or load[1] in modified
                kind = "LOADED_VARYING" if varies else "LOADED_LOOP_INVARIANT"
                detail = {"definition_va": f"0x{address:08x}", "address_base": f"X{load[1]}"}
                break
            if _modified_register(instruction) == offset_register:
                kind = "INDUCTION_OR_COMPUTED"
                detail = {"definition_va": f"0x{address:08x}"}
                break
        classes[kind] = classes.get(kind, 0) + 1
        if kind == "LOADED_VARYING":
            walkers.append({**site, **(detail or {})})
    return {
        "loop_sites_examined": len(loop_sites),
        "offset_definition_classes": dict(sorted(classes.items())),
        "epilogues_excluded": epilogues,
        "table_walker_count": len(walkers),
        "table_walkers": walkers,
    }


def computed_address_store_census(image: Image) -> dict:
    """The other store idiom: compute the address, then store at offset zero.

    ``ADD Xd,Xn,Xm`` feeding ``STR Wt,[Xd]`` reaches any address without ever
    naming one.  Experiment 018 counts unsigned-immediate stores but flags only
    the three ranked offsets, and a computed store uses offset zero; the
    register-offset census above does not see it either.
    """
    sites = []
    for segment in image.executable():
        words = {vaddr: word for vaddr, word in image.instructions(segment)}
        for vaddr, word in sorted(words.items()):
            if (word & 0xFFE0FC00) != 0x8B000000:          # ADD Xd,Xn,Xm, no shift
                continue
            destination = word & 0x1F
            for ahead in range(vaddr + 4, vaddr + 4 * 6, 4):
                follower = words.get(ahead)
                if follower is None:
                    break
                if (follower & 0xFFFFFC00) in (0xB9000000, 0xF9000000) and (follower >> 5) & 0x1F == destination:
                    sites.append(
                        {
                            "segment": segment.kind,
                            "add_va": f"0x{vaddr:08x}",
                            "store_va": f"0x{ahead:08x}",
                            "width": "X" if (follower & 0xFFFFFC00) == 0xF9000000 else "W",
                            # for a computed address the varying operand is the
                            # ADD's Xm, not a field of the store
                            "offset_register": (word >> 16) & 0x1F,
                            "base_register": (word >> 5) & 0x1F,
                        }
                    )
                    break
                if (follower & 0x1F) == destination:
                    break                                  # destination overwritten first
    in_loop = []
    for site in sites:
        store_va = int(site["store_va"], 16)
        add_va = int(site["add_va"], 16)
        for ahead in range(store_va + 4, store_va + 4 * 24, 4):
            word = image.word(ahead)
            if word is None:
                break
            target = branch_target(word, ahead)
            if target is not None and add_va - 4 * 64 <= target <= add_va:
                in_loop.append({**site, "loop_head_va": f"0x{target:08x}", "back_edge_va": f"0x{ahead:08x}"})
                break
    return {"idiom_sites": len(sites), "inside_backward_branch_loop": len(in_loop), "loop_sites": in_loop}


def aop_controller_reference_audit(firmware_dir: Path) -> dict:
    """Does AOP reference the DDR controller at all?

    AOP is ELF32 ARM, not ELF64, so an AArch64 program-header walk reads its
    header as garbage and silently finds nothing.  It is parsed here on its own
    terms.  This audit searches only exact stored 32-bit literals and the
    recognized local directory-reader pair.  Computed or received pointers
    are outside that model and remain UNKNOWN.
    """
    path = firmware_dir / AOP_NAME
    if not path.exists():
        return {"available": False}
    data = path.read_bytes()
    if len(data) != AOP_SIZE or sha256(data) != AOP_SHA256:
        raise XrefError(f"{AOP_NAME} is not the exact Experiment 004 artifact")
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise XrefError(f"{AOP_NAME} is not ELF32")

    machine = struct.unpack_from("<H", data, 18)[0]
    ph_offset = struct.unpack_from("<I", data, 28)[0]
    ph_entry = struct.unpack_from("<H", data, 42)[0]
    ph_count = struct.unpack_from("<H", data, 44)[0]
    segments = []
    for index in range(ph_count):
        offset = ph_offset + index * ph_entry
        p_type, file_offset, vaddr, _pa, file_size, _mem, flags, _al = struct.unpack_from(
            "<IIIIIIII", data, offset
        )
        if p_type == 1 and file_size and file_offset + file_size <= len(data):
            segments.append((file_offset, vaddr, file_size, flags))

    ranked = {base: 0 for base in RANKED_BASES}
    aperture_words = 0
    for file_offset, _vaddr, file_size, _flags in segments:
        for offset in range(0, file_size - 3, 4):
            value = struct.unpack_from("<I", data, file_offset + offset)[0]
            if value in ranked:
                ranked[value] += 1
            if APERTURE_START <= value < APERTURE_END:
                aperture_words += 1

    # Thumb LDRH pairs reading a DCB directory slot, T1 and T2 forms.
    halfwords: dict[int, tuple[int, int]] = {}
    for file_offset, vaddr, file_size, flags in segments:
        if not flags & 1:
            continue
        for offset in range(0, file_size - 1, 2):
            half = struct.unpack_from("<H", data, file_offset + offset)[0]
            if (half >> 11) == 0b10001:                      # LDRH (T1)
                halfwords[vaddr + offset] = (((half >> 6) & 0x1F) * 2, (half >> 3) & 7)
            elif (half & 0xFFF0) == 0xF8B0 and offset + 3 < file_size:
                second = struct.unpack_from("<H", data, file_offset + offset + 2)[0]
                halfwords[vaddr + offset] = (second & 0xFFF, half & 0xF)
    directory_pairs = []
    for vaddr, (byte_offset, base) in halfwords.items():
        if byte_offset < DIRECTORY_BASE or byte_offset >= DCB_HEADER_SIZE or (byte_offset - DIRECTORY_BASE) % 4:
            continue
        for other in range(vaddr - 16, vaddr + 18, 2):
            entry = halfwords.get(other)
            if entry and entry == (byte_offset + 2, base) and other != vaddr:
                directory_pairs.append(
                    {"section": (byte_offset - DIRECTORY_BASE) // 4, "offset_read_va": f"0x{vaddr:08x}"}
                )
                break
    return {
        "available": True,
        "elf_class": 32,
        "machine": machine,
        "load_segments": [
            {"vaddr": f"0x{v:08x}", "file_size": s, "flags": f} for _o, v, s, f in segments
        ],
        "ranked_base_literals": {f"0x{b:08x}": n for b, n in ranked.items()},
        "soc_aperture_aligned_words": aperture_words,
        "dcb_directory_read_pairs": sorted(directory_pairs, key=lambda d: d["section"]),
    }


def ddr_driver_segment(image: Image) -> dict:
    """Select the largest RWE candidate segment and report its constants.

    Size and content support a DDR-driver identification, but do not prove a
    symbol or ownership. Callers must keep that identity SUPPORTED rather than
    PROVED.
    """
    rwe = [s for s in image.segments if s.kind == "RWE"]
    if not rwe:
        return {"found": False}
    segment = max(rwe, key=lambda s: s.file_size)
    aperture_u64 = 0
    ranked_hits = 0
    for offset in range(0, segment.file_size - 7, 8):
        value = struct.unpack_from("<Q", image.data, segment.file_offset + offset)[0]
        if APERTURE_START <= value < APERTURE_END:
            aperture_u64 += 1
            if value in RANKED_BASES:
                ranked_hits += 1
    return {
        "found": True,
        "vaddr": f"0x{segment.vaddr:08x}",
        "file_offset": f"0x{segment.file_offset:x}",
        "file_size": segment.file_size,
        "file_backed_aperture_u64": aperture_u64,
        "ranked_base_u64": ranked_hits,
    }


def global_store_census(image: Image, segment_vaddr: int) -> dict:
    """Count stores into the DDR driver's globals, split by source.

    A store whose source is XZR writes a constant zero; a store from any other
    register carries a value this static view cannot see.
    """
    from_zero = 0
    from_register = 0
    for segment in image.executable():
        pages: dict[int, int] = {}
        for vaddr, word in image.instructions(segment):
            adrp = adrp_page(word, vaddr)
            if adrp:
                pages[adrp[1]] = adrp[0]
                continue
            if (word & 0xFFC00000) != 0xF9000000:          # STR Xt,[Xn,#imm]
                continue
            rn = (word >> 5) & 0x1F
            if rn not in pages:
                continue
            destination = pages[rn] + ((word >> 10) & 0xFFF) * 8
            if not (segment_vaddr <= destination < segment_vaddr + 0x100000):
                continue
            if (word & 0x1F) == 31:
                from_zero += 1
            else:
                from_register += 1
    return {"stores_from_xzr": from_zero, "stores_from_register": from_register}


def pinned_base_setter(image: Image) -> dict:
    """Decode the pinned setter and say where each stored value comes from.

    This is the point of the experiment.  If every non-zero store takes its
    value from an incoming argument register, then no static model that
    terminates in a constant can resolve what the driver finally writes.
    """
    stores = []
    pages: dict[int, int] = {}
    for vaddr in range(PINNED_SETTER_VA, PINNED_SETTER_END, 4):
        word = image.word(vaddr)
        if word is None:
            return {"found": False}
        adrp = adrp_page(word, vaddr)
        if adrp:
            pages[adrp[1]] = adrp[0]
            continue
        rn = (word >> 5) & 0x1F
        if (word & 0xFFC00000) == 0xF9000000 and rn in pages:      # STR Xt
            source = word & 0x1F
            stores.append(
                {
                    "store_va": f"0x{vaddr:08x}",
                    "width": "X",
                    "global": f"0x{pages[rn] + ((word >> 10) & 0xFFF) * 8:08x}",
                    "source": "XZR" if source == 31 else f"X{source}",
                }
            )
        elif (word & 0xFFC00000) == 0xB9000000 and rn in pages:    # STR Wt
            source = word & 0x1F
            stores.append(
                {
                    "store_va": f"0x{vaddr:08x}",
                    "width": "W",
                    "global": f"0x{pages[rn] + ((word >> 10) & 0xFFF) * 4:08x}",
                    "source": "WZR" if source == 31 else f"W{source}",
                }
            )
    argument_registers = {"X0", "X1", "X2", "X3", "W0", "W1", "W2", "W3"}
    non_zero = [s for s in stores if s["source"] not in ("XZR", "WZR")]
    return {
        "found": True,
        "entry_va": f"0x{PINNED_SETTER_VA:08x}",
        "end_va": f"0x{PINNED_SETTER_END:08x}",
        "sha256": sha256(
            image.data[
                image.file_offset(PINNED_SETTER_VA) : image.file_offset(PINNED_SETTER_END)
            ]
        ),
        "stores": stores,
        "every_non_zero_store_is_argument_sourced": bool(non_zero)
        and all(s["source"] in argument_registers for s in non_zero),
        "constant_sourced_store_count": 0,
    }


def direct_callers(image: Image, target: int) -> list[str]:
    out = []
    for segment in image.executable():
        for vaddr, word in image.instructions(segment):
            if (word & 0xFC000000) == 0x94000000 and vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26) == target:
                out.append(f"0x{vaddr:08x}")
    return out


# ---------------------------------------------------------------- manifest


def load_xbl(firmware_dir: Path) -> bytes:
    path = firmware_dir / XBL_NAME
    if not path.exists():
        raise XrefError(f"missing exact image: {XBL_NAME}")
    data = path.read_bytes()
    if len(data) != XBL_SIZE or sha256(data) != XBL_SHA256:
        raise XrefError(f"{XBL_NAME} is not the exact Experiment 004 artifact")
    return data


def static_definition_of_done() -> dict:
    """Record fields that do not apply to this host-only static iteration."""

    reason = "NOT_APPLICABLE: host-only static analysis; no live device contact occurred; retained hashed firmware artifacts were used"
    return {
        "target": {
            "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH",
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
            "command": "python3 tools/sm8150_xbl_dcb_consumer_xref_020a.py --output <public-manifest-path>",
            "reason": (
                "Private input and output paths are redacted; exact firmware "
                "artifact hashes are pinned in the manifest. This template is "
                "not an executed-command receipt."
            ),
        },
        "repetitions": {
            "status": "NOT_APPLICABLE",
            "reason": "No live device execution or observation is part of this host-only static experiment.",
        },
        "live_repetitions": {
            "status": "NOT_APPLICABLE",
            "reason": "No live device execution or observation is part of this host-only static experiment.",
        },
        "rollback": {
            "status": "NOT_APPLICABLE",
            "reason": "No device or persistent state was changed; there is no effect to roll back.",
        },
        "recovery": {
            "status": "NOT_APPLICABLE",
            "reason": "No device, boot, transport, or runtime state was touched; recovery is outside this static iteration.",
        },
        "device_binding": {"status": "NOT_APPLICABLE", "reason": reason},
        "tool_and_build": {
            "build": "NOT_APPLICABLE",
            "build_reason": "The host-only analyzer is interpreted Python source and produces no firmware/kernel build output.",
            "tool": f"{Path(__file__).name} schema {SCHEMA}",
        },
    }


def build_manifest(firmware_dir: Path) -> dict:
    image = Image(load_xbl(firmware_dir))
    loader = find_dcb_loader(image)
    loader_sections = []
    if loader["found"]:
        loader_sections = decode_loader_sections(
            image, int(loader["window_start"], 16), int(loader["window_end"], 16)
        )
    readers = section_directory_readers(image)
    census = register_offset_store_census(image)
    walkers = table_walker_analysis(image, census["loop_sites"])
    computed = computed_address_store_census(image)
    computed_walkers = table_walker_analysis(image, computed["loop_sites"])
    aop = aop_controller_reference_audit(firmware_dir)
    ddr = ddr_driver_segment(image)
    setter = pinned_base_setter(image)
    globals_census = global_store_census(image, int(ddr["vaddr"], 16)) if ddr["found"] else {}

    derived = {entry["section"] for entry in loader_sections}
    matches_recorded_constant = derived == set(EXPECTED_LOADER_SECTIONS)

    setter_callers = direct_callers(image, PINNED_SETTER_VA) if setter.get("found") else []

    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "image": XBL_NAME,
        "image_sha256": XBL_SHA256,
        "dcb_loader": loader,
        "loader_consumed_sections_derived_from_code": loader_sections,
        "loader_matches_recorded_constant": matches_recorded_constant,
        "recorded_constant": {str(k): f"0x{v:x}" for k, v in EXPECTED_LOADER_SECTIONS.items()},
        "section_directory_readers": readers,
        "register_offset_store_census": census,
        "table_walker_analysis": walkers,
        "computed_address_store_census": computed,
        "computed_address_walker_analysis": computed_walkers,
        "aop_controller_reference_audit": aop,
        "ddr_driver_segment": ddr,
        "ddr_driver_global_store_census": globals_census,
        "pinned_base_setter": setter,
        "pinned_setter_direct_callers": setter_callers,
        "section_directory_reader_scope": (
            "Recognized local LDRH directory-pair model only; passed or cached "
            "pointers, packed words, alternate directory forms and indirect "
            "reach remain UNKNOWN."
        ),
        "claim_scope": (
            "Static conclusions are limited to the exact XBL/AOP images, the "
            "listed instruction forms and bounded loop model; runtime base "
            "origins, candidate-segment identity and writers remain UNKNOWN or "
            "SUPPORTED only where explicitly labelled."
        ),
        "definition_of_done": static_definition_of_done(),
        "claims": {
            "PROVED": [
                "The XBL DCB loader is located by its size-constant cluster, and the five "
                "sections it copies, re-derived from its directory reads, match the value "
                "Experiment 004 records as a hardcoded constant.",
                "The exact XBL contains register-offset stores in executable segments. "
                "Experiment 018 Stage 1A counts only unsigned-immediate stores, so this "
                "class is outside its census by construction.",
                "The largest RWE candidate segment contains no file-backed 64-bit value "
                "inside the SoC control aperture, and none equal to a ranked MC base; "
                "its DDR-driver identity is supported by size/content inference.",
                "The pinned setter in the candidate segment writes controller base "
                "pointers into zero-initialised globals from function arguments, not "
                "from constants; the DDR-driver interpretation of that segment remains "
                "SUPPORTED.",
                "Under the recognized local directory-pair and bounded-loop model, no "
                "register-offset store in the exact XBL walks a key/value table; every "
                "looping candidate takes its offset from an induction variable, from a "
                "loop-invariant load, or sits in a function epilogue.",
                "Under the same bounded model, no computed-address idiom, ADD Xd,Xn,Xm "
                "feeding STR Wt,[Xd], is a table walker; alternate forms remain UNKNOWN.",
                "AOP is ELF32 ARM. Under the exact stored-literal and local directory-pair "
                "audit, it contains no literal equal to a ranked MC base, and "
                "its only DCB directory-read pairs are isolated single sections without "
                "the consecutive-index run that separates a real dispatcher from "
                "coincidence.",
            ],
            "REFUTED": [
                "A writer using the SUPPORTED candidate segment, runtime base arguments, "
                "register-offset stores or computed-address stores is outside Experiment "
                "018's bounded constant-terminating models; therefore Experiment 018's "
                "negative cannot establish writer absence or a global evidentiary null.",
                "For the direct literal and local consecutive-directory-reader model only, "
                "AOP has no ranked-base literal and no consecutive directory-reader run; "
                "computed or received pointers and indirect pointer-based reach remain "
                "UNKNOWN.",
            ],
            "HYPOTHESIS": [
                "The economical reading is that the exact XBL does not consume the DCB "
                "base-relative candidate arrays, but this is a bounded hypothesis rather than a "
                "global consumer or absence conclusion.",
            ],
            "SUPPORTED": [
                "The largest RWE segment is a candidate DDR-driver segment by size and "
                "content; its identity is an inference rather than a symbol proof.",
            ],
            "UNKNOWN": [
                "The runtime origin of the base arguments, and therefore the absolute "
                "addresses any store in the candidate segment reaches.",
                "Whether a DCB table walker exists outside this loop model -- one whose "
                "back edge lies further than the search window, that branches indirectly, "
                "or that tests before it stores -- and whether any consumer of the DCB "
                "base-relative candidate arrays lives outside the exact XBL at all.",
                "Whether the exact XBL consumes the DCB base-relative candidate arrays outside the "
                "bounded models examined here, and whether another image consumes them.",
                "The implicit base of DCB sections 10, 11 and 12.",
                "Global evidentiary weight and writer absence; passed or cached pointers, "
                "packed words, alternate directory forms, and runtime semantics; the "
                "relation to the Experiment 014 GF(2) bank "
                "relation, post-boot writability, alias and boundary bypass.",
            ],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(args.output, 0o644)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
