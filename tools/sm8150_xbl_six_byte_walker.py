#!/usr/bin/env python3
"""Host-only Experiment 024: resolve Experiment 020's six-byte walker.

This is a bounded, fail-closed static proof over one exact SM8150 XBL ELF and
two exact Samsung DTS design snapshots (public and OSRC).  It proves the
instruction/data shape and the direct caller/provider links that are visible in
those inputs.  It does not infer live-DTB equality, runtime selector state,
execution, register semantics, or a current MMIO base from a static
initializer.

No device, SMC, MMIO, protected-memory, normal-RAM, or runtime-register access
is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

KERNEL_DTSI_NAME = "sm8150.dtsi"
PUBLIC_KERNEL_DTSI_SIZE = 101_386
PUBLIC_KERNEL_DTSI_SHA256 = "38db804d589bb01206adbf2a351c4d074f5c92f7ef351dc3976cbcb846f1a31c"
PUBLIC_KERNEL_PROVENANCE = "kernel_samsung_r3q@e1d271581eff"
OSRC_KERNEL_DTSI_SIZE = 102_419
OSRC_KERNEL_DTSI_SHA256 = "c0d42e66ddd5640e2dd7b65527c25fb617008d94a6a04062b9e1077f0eb63849"
OSRC_KERNEL_PROVENANCE = (
    "A908N OSRC Kernel.tar.gz sha256 "
    "403fdc49f086d238c01a796c390083c3c47c1754c218e228f29b55cc7c35d554; "
    "correspondence to installed config is SUPPORTED by A90_SELF_BUILT_KERNEL_H0 report"
)
UFS_BLOCK_SIZE = 4464
UFS_BLOCK_SHA256 = "cea31db3785be5916a1ff08d1c99b92155a7914b07d09ecb6c3638d8c16ff10a"

SCHEMA = "sm8150-xbl-six-byte-walker-v1"
DEPENDENCY_019_NAME = "019-dcb-register-programming-20260826-01.manifest.json"
DEPENDENCY_019_PATH = REPO_ROOT / "evidence/manifests" / DEPENDENCY_019_NAME
DEPENDENCY_019_SIZE = 40368
DEPENDENCY_019_SHA256 = "232eb0375fadf96db1fd303d83d707cf47cb668a24129d7e4791b193fb3fc70c"

WALKER_START = 0x148689A0
WALKER_END = 0x14868A64
WALKER_FILE_OFFSET = 0x4F9A0
WALKER_SHA256 = "08265307d79c5f82b85266613f241ae160151dcfe51b19da108f9ad6c4e15021"
PREHEADER_LOOP_START = 0x148689C8
PREHEADER_LOOP_END = 0x14868A60
PREHEADER_LOOP_FILE_OFFSET = 0x4F9C8
PREHEADER_LOOP_SHA256 = "02248b786ffb501a5fa9242aa3952e1e4d783f47464952e96ca2704a9f94341e"
WALKER_STORE_VA = 0x14868A50
WALKER_LOOP_HEAD = 0x148689DC
WALKER_BACK_EDGE = 0x14868A5C
WALKER_STRIDE = 6
WALKER_FLAG_GATE_START = 0x148689F8
WALKER_FLAG_GATE_END = 0x14868A4C
WALKER_FLAG_GATE_SHA256 = "0f5f409b78e51bc7aad6c1a7d0472a184670bf8b908cd897e621af9c5db80698"

WALKER_WORDS = {
    0x148689A0: 0xF9400408,  # LDR X8,[X0,#8]
    0x148689C8: 0x2A1F03E9,  # MOV W9,WZR
    0x148689CC: 0x321F07EA,  # ORR W10,WZR,#6
    0x148689D8: 0x14000020,  # B 0x14868A58
    0x148689DC: 0x9BAA052E,  # UMADDL X14,W9,W10,X1
    0x148689E0: 0x794005CD,  # LDRH W13,[X14,#2]
    0x148689E4: 0x794001CF,  # LDRH W15,[X14]
    0x148689E8: 0x394011CE,  # LDRB W14,[X14,#4]
    0x14868A4C: 0xF940040F,  # LDR X15,[X0,#8]
    0x14868A50: 0xB82D69EE,  # STR W14,[X15,X13]
    0x14868A54: 0x11000529,  # ADD W9,W9,#1
    0x14868A58: 0x6B02013F,  # CMP W9,W2
    0x14868A5C: 0x54FFFC03,  # B.CC 0x148689DC
    0x148689F0: 0x714021FF,  # CMP W15,#0x8000, LSL #12
    0x148689F4: 0x54000360,  # B.EQ 0x14868A60
}

CALLER_SITES = (0x14868640, 0x1486867C, 0x14868698)
CALLER_FLOW_RANGES = (
    (0x14868630, 0x14868644),
    (0x14868668, 0x14868680),
    (0x14868684, 0x1486869C),
)
CALLER_FLOW_WORDS = {
    0x14868630: 0x940008E1,  # BL 0x1486A9B4
    0x14868634: 0xF9400FE1,  # LDR X1,[SP,#24]
    0x14868638: 0x2A0003E2,  # MOV W2,W0
    0x1486863C: 0xAA1303E0,  # MOV X0,X19
    0x14868640: 0x940000D8,  # BL walker
    0x14868668: 0x940008E1,  # BL 0x1486A9EC
    0x1486866C: 0xF9400FE1,  # LDR X1,[SP,#24]
    0x14868670: 0x2A0003E3,  # MOV W3,W0
    0x14868674: 0xAA1303E0,  # MOV X0,X19
    0x14868678: 0x2A0303E2,  # MOV W2,W3
    0x1486867C: 0x940000C9,  # BL walker
    0x14868684: 0x940008E7,  # BL 0x1486AA20
    0x14868688: 0xF9400FE1,  # LDR X1,[SP,#24]
    0x1486868C: 0x2A0003E4,  # MOV W4,W0
    0x14868690: 0xAA1303E0,  # MOV X0,X19
    0x14868694: 0x2A0403E2,  # MOV W2,W4
    0x14868698: 0x940000C2,  # BL walker
}

PROVIDER_RANGES = (
    (0x1486A9B4, 0x1486A9EC, "abd87bf51feb5731a66a0ff258b90f365e818a93fab36e702be701b9534a8720"),
    (0x1486A9EC, 0x1486AA20, "027a60ffefe19ec8537e2253915e292ea8bb26e82bce2046d8c067a007cc3437"),
    (0x1486AA20, 0x1486AA50, "6760464b6a32ca9a5c8d7f800b247e9643e592f972a629796852a8edbf2091d8"),
)
SELECTOR_VA = 0x146B3000

TABLE_SPECS = (
    (0x14880B40, 16, "1c596a44cbec1cdbcc5b23e81eccde1c20556b17ab3c434ef393c29ab63aa015"),
    (0x14880BA0, 13, "eac051599765de4842c6ecf7a6076813eac93a07cd052d829787b1095fa353b1"),
    (0x14880BEE, 43, "f7b7ca7dae26320d69c87c9b4c59472eb0933aa7216936ed7564f78b770f643c"),
    (0x14880CF0, 64, "7c0fb81701455fb380cf4a2d1af4120a444a6be66235c2a87dad5ca2c932711f"),
    (0x14880E70, 90, "8c26948bb9e7e24ae9c2d950412e851dd1e60e412aa4f82d7936c247103ac240"),
)

INITIALIZER_START = 0x1486AAFC
INITIALIZER_END = 0x1486AB04
INITIALIZER_SHA256 = "40fb695e26eac295c251383a0077146e9dd820231a85feedeb791b456086d8a4"
INITIALIZER_RETURN = 0x01D80000
INITIALIZER_CALLER = 0x14868464
INITIALIZER_STORE = 0x14868468
MAIN_INIT_START = 0x14868418
MAIN_INIT_END = 0x148688F0
MAIN_INIT_SHA256 = "28fd589dc6e2d47fdf592b3a08aa8883e9e0d90a648f76733dab5376dfd369da"

# The helper is direct-called on the success path and then performs an
# unresolved BLR through a runtime-BSS object.  That prevents a global
# current-base proof, even though the main function has only one direct local
# [ctx,#8] store.
BASE_HELPER_START = 0x1486ABEC
BASE_HELPER_END = 0x1486ACAC
BASE_HELPER_SHA256 = "679384b78fab5cf3903f5c7a34e5efa45552c983b4d2bb1fcc8dc12e66d555c2"
BASE_HELPER_CALLER = 0x1486847C
BASE_HELPER_BLR = 0x1486AC1C
BASE_HELPER_BLR_WORD = 0xD63F0120
BASE_HELPER_RELOAD = 0x1486ACA4
BASE_HELPER_RELOAD_WORD = 0xF942CA88
BASE_HELPER_SLOT_LOAD = 0x1486AC04
BASE_HELPER_SLOT_LOAD_WORD = 0xF942CA88
BASE_HELPER_SLOT_ADDRESS = 0x1486AC40
BASE_HELPER_SLOT_ADDRESS_WORD = 0x91164021
BASE_RUNTIME_BSS_SLOT = 0x14890590

BASE = INITIALIZER_RETURN
UFS_PHY_START = 0x01D87000
UFS_PHY_END = 0x01D87E00
UFS_PHY_STANDALONE_END = 0x01D87DA8


class WalkerError(ValueError):
    """Raised when an input is malformed or not the exact pinned artifact."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: int) -> str:
    return f"0x{value:08x}"


def fmt_offset(value: int) -> str:
    return f"0x{value:x}"


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


@dataclass(frozen=True)
class Segment:
    index: int
    file_offset: int
    vaddr: int
    file_size: int
    mem_size: int
    flags: int

    @property
    def kind(self) -> str:
        return {1: "X", 2: "W", 3: "WX", 4: "R", 5: "RX", 6: "RW", 7: "RWX"}.get(
            self.flags, f"F{self.flags}"
        )

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)


class Image:
    """Independent ELF64 PT_LOAD parser used by this experiment only."""

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise WalkerError("not a little-endian ELF64 image")
        if data[6] != 1:
            raise WalkerError("unsupported ELF version")
        ph_offset = struct.unpack_from("<Q", data, 32)[0]
        ph_entry = struct.unpack_from("<H", data, 54)[0]
        ph_count = struct.unpack_from("<H", data, 56)[0]
        if ph_entry < 56 or ph_count > 4096:
            raise WalkerError("invalid program-header shape")
        if ph_offset > len(data) or ph_offset + ph_entry * ph_count > len(data):
            raise WalkerError("program headers exceed image")
        self.data = data
        self.segments: list[Segment] = []
        for index in range(ph_count):
            offset = ph_offset + index * ph_entry
            p_type, flags, file_offset, vaddr, _pa, file_size, mem_size, _align = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if p_type != 1:
                continue
            if file_offset + file_size > len(data) or file_offset > len(data):
                raise WalkerError(f"PT_LOAD {index} exceeds image")
            if mem_size < file_size:
                raise WalkerError(f"PT_LOAD {index} has memsz smaller than filesz")
            if file_size == 0:
                # Keep memory-only PT_LOADs: proving that the selector has no
                # file-backed current value depends on retaining this fact.
                self.segments.append(Segment(index, file_offset, vaddr, 0, mem_size, flags))
            else:
                self.segments.append(Segment(index, file_offset, vaddr, file_size, mem_size, flags))

    def file_backed(self) -> list[Segment]:
        return [segment for segment in self.segments if segment.file_size]

    def executable(self) -> list[Segment]:
        return [segment for segment in self.file_backed() if segment.executable]

    def segment_for(self, vaddr: int, *, file_backed: bool = True) -> Segment | None:
        matches = [
            segment
            for segment in self.segments
            if segment.vaddr <= vaddr < segment.vaddr + (segment.file_size if file_backed else segment.mem_size)
            and (not file_backed or segment.file_size)
        ]
        if len(matches) > 1:
            raise WalkerError(f"ambiguous PT_LOAD mapping at {fmt(vaddr)}")
        return matches[0] if matches else None

    def file_offset(self, vaddr: int) -> int | None:
        segment = self.segment_for(vaddr)
        return None if segment is None else segment.file_offset + (vaddr - segment.vaddr)

    def slice(self, start: int, end: int) -> bytes:
        if end <= start:
            raise WalkerError("empty or reversed range")
        start_offset = self.file_offset(start)
        end_offset = self.file_offset(end - 1)
        if start_offset is None or end_offset is None or end_offset + 1 != start_offset + (end - start):
            raise WalkerError(f"range is not one file-backed PT_LOAD: {fmt(start)}..{fmt(end)}")
        return self.data[start_offset : start_offset + end - start]

    def word(self, vaddr: int) -> int | None:
        offset = self.file_offset(vaddr)
        if offset is None or offset % 4 or offset + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, offset)[0]

    def instructions(self, segment: Segment) -> Iterable[tuple[int, int]]:
        if segment.file_size < 4:
            return
        for offset in range(0, segment.file_size - 3, 4):
            yield segment.vaddr + offset, struct.unpack_from("<I", self.data, segment.file_offset + offset)[0]


def decode_bl_target(word: int, vaddr: int) -> int | None:
    if (word & 0xFC000000) != 0x94000000:
        return None
    return vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26)


def decode_b_target(word: int, vaddr: int) -> int | None:
    if (word & 0x7C000000) == 0x14000000:
        return vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26)
    if (word & 0xFF000010) == 0x54000000:
        return vaddr + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x34000000:
        return vaddr + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x36000000:
        return vaddr + 4 * sign_extend((word >> 5) & 0x3FFF, 14)
    return None


def is_adrp(word: int) -> tuple[int, int] | None:
    if (word & 0x9F000000) != 0x90000000:
        return None
    immediate = sign_extend((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3), 21) << 12
    return ((immediate + 0) & 0xFFFFFFFF, word & 0x1F)


def adrp_page(word: int, vaddr: int) -> tuple[int, int] | None:
    decoded = is_adrp(word)
    if decoded is None:
        return None
    immediate, register = decoded
    # ``immediate`` is signed 32-bit after the helper above; the ADRP base is
    # the page of the instruction, not zero.
    signed = immediate if immediate < 0x80000000 else immediate - 0x100000000
    return ((vaddr & ~0xFFF) + signed) & 0xFFFFFFFF, register


def is_add_x_imm(word: int) -> tuple[int, int, int, int] | None:
    if (word & 0xFF000000) != 0x91000000 or (word >> 22) & 1:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF, 12 if (word >> 22) & 1 else 0


def is_ldrh(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFFC00000) != 0x79400000:
        return None
    return (word >> 10 & 0xFFF) * 2, (word >> 5) & 0x1F, word & 0x1F


def is_ldrb(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFFC00000) != 0x39400000:
        return None
    return (word >> 10 & 0xFFF), (word >> 5) & 0x1F, word & 0x1F


def is_ldr_x_imm(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFFC00000) != 0xF9400000:
        return None
    return (word >> 10 & 0xFFF) * 8, (word >> 5) & 0x1F, word & 0x1F


def is_str_w_register_offset(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFFE00C00) != 0xB8200800:
        return None
    # Option=011 is UXTX/LSL for an X offset register; S=0 is the byte-offset
    # form.  The scaled S=1 form reaches a different address and is not this
    # six-byte byte-offset store.
    if ((word >> 13) & 0x7) != 0x3 or ((word >> 12) & 0x1):
        return None
    return (word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F)


def is_umaddl(word: int) -> tuple[int, int, int, int] | None:
    # Bit 15 distinguishes UMADDL from UMSUBL; bits 14..10 are the XRa field.
    if (word & 0xFFE08000) != 0x9BA00000:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, (word >> 10) & 0x1F


def decode_movz_w(word: int) -> tuple[int, int] | None:
    if (word & 0xFFC00000) != 0x52800000:
        return None
    halfword = (word >> 21) & 0x3
    # MOVZ Wd supports only LSL #0 or LSL #16 (hw 0 or 1).
    if halfword > 1:
        return None
    return ((word >> 5) & 0xFFFF) << (16 * halfword), word & 0x1F


def is_add_w_imm(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFF000000) != 0x11000000 or ((word >> 22) & 1):
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF


def is_cmp_w_reg(word: int) -> tuple[int, int] | None:
    if (word & 0xFFE0FC1F) != 0x6B00001F:
        return None
    return (word >> 5) & 0x1F, (word >> 16) & 0x1F


def is_cmp_w_imm(word: int) -> tuple[int, int] | None:
    """CMP Wn,#imm (including the optional LSL #12 immediate form)."""
    if (word & 0xFF80001F) != 0x7100001F:
        return None
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return (word >> 5) & 0x1F, immediate


def is_b_cond(word: int) -> int | None:
    if (word & 0xFF000010) != 0x54000000:
        return None
    return word & 0xF


def direct_callers(image: Image, target: int) -> list[int]:
    sites: list[int] = []
    for segment in image.executable():
        for vaddr, word in image.instructions(segment):
            if decode_bl_target(word, vaddr) == target:
                sites.append(vaddr)
    return sorted(sites)


def range_record(image: Image, start: int, end: int, expected_offset: int | None = None, expected_hash: str | None = None) -> dict:
    data = image.slice(start, end)
    offset = image.file_offset(start)
    if offset is None or (expected_offset is not None and offset != expected_offset):
        raise WalkerError(f"range file mapping mismatch for {fmt(start)}")
    digest = sha256(data)
    if expected_hash is not None and digest != expected_hash:
        raise WalkerError(f"range hash mismatch for {fmt(start)}")
    return {
        "start": fmt(start),
        "end_exclusive": fmt(end),
        "file_offset": fmt_offset(offset),
        "size": end - start,
        "sha256": digest,
    }


def _assert_words(image: Image, expected: dict[int, int]) -> None:
    for vaddr, word in expected.items():
        actual = image.word(vaddr)
        if actual != word:
            raise WalkerError(f"instruction mismatch at {fmt(vaddr)}")


def decode_six_byte_walker(image: Image, start: int, end: int) -> dict:
    """Decode the bounded UMADDL + field-load + register-store shape.

    The decoder intentionally does not assign meanings to the flag bits.  It
    only proves the exact field offsets, terminator comparison/control effect,
    and induction branch in a supplied range.  It is useful for synthetic
    negative tests as well as for the pinned image.
    """
    if end <= start or (end - start) % 4:
        raise WalkerError("walker range must contain aligned instructions")
    words = {vaddr: image.word(vaddr) for vaddr in range(start, end, 4)}
    if any(word is None for word in words.values()):
        raise WalkerError("walker range is not fully mapped")
    umaddl = is_umaddl(words.get(WALKER_LOOP_HEAD, 0))
    if umaddl is None:
        # Synthetic callers may use a different loop head; find exactly one.
        candidates = [(vaddr, is_umaddl(word)) for vaddr, word in words.items()]
        candidates = [(vaddr, decoded) for vaddr, decoded in candidates if decoded is not None]
        if len(candidates) != 1:
            raise WalkerError("expected exactly one UMADDL in walker range")
        loop_head, umaddl = candidates[0]
    else:
        loop_head = WALKER_LOOP_HEAD
    assert umaddl is not None
    destination, index_register, stride_register, table_register = umaddl
    stride_literals = [
        (vaddr, word)
        for vaddr, word in words.items()
        if word == 0x321F07EA and (word & 0x1F) == stride_register and vaddr < loop_head
    ]
    if len(stride_literals) != 1:
        raise WalkerError("walker does not pin the six-byte stride literal")
    ldrh = [(vaddr, is_ldrh(word)) for vaddr, word in words.items()]
    ldrh = [(vaddr, decoded) for vaddr, decoded in ldrh if decoded is not None]
    offset_loads = [(vaddr, off, rn, rt) for vaddr, (off, rn, rt) in ldrh if off == 2 and rn == destination]
    flag_loads = [(vaddr, off, rn, rt) for vaddr, (off, rn, rt) in ldrh if off == 0 and rn == destination]
    if len(offset_loads) != 1 or len(flag_loads) != 1:
        raise WalkerError("walker does not have one offset and one flags LDRH")
    value_loads = [(vaddr, off, rn, rt) for vaddr, decoded in ((v, is_ldrb(w)) for v, w in words.items()) if decoded is not None for off, rn, rt in [decoded] if off == 4 and rn == destination]
    if len(value_loads) != 1:
        raise WalkerError("walker does not have one value LDRB")
    stores = [(vaddr, is_str_w_register_offset(word)) for vaddr, word in words.items()]
    stores = [(vaddr, decoded) for vaddr, decoded in stores if decoded is not None]
    stores = [(vaddr, rt, rn, rm) for vaddr, (rt, rn, rm) in stores if rn != 31]
    if len(stores) != 1:
        raise WalkerError("walker does not have one register-offset W store")
    store_va, value_register, base_register, offset_register = stores[0]
    if value_register != value_loads[0][3] or offset_register != offset_loads[0][3]:
        raise WalkerError("walker field loads do not feed the store")
    base_loads = [
        (vaddr, off, rn, rt)
        for vaddr, word in words.items()
        for decoded in [is_ldr_x_imm(word)]
        if decoded is not None
        for off, rn, rt in [decoded]
        if off == 8 and rn == 0 and rt == base_register
    ]
    if len(base_loads) != 1:
        raise WalkerError("walker does not load its store base from [X0,#8]")
    increments = [(vaddr, is_add_w_imm(word)) for vaddr, word in words.items()]
    increments = [(vaddr, decoded) for vaddr, decoded in increments if decoded is not None and decoded[2] == 1]
    if len(increments) != 1 or increments[0][1][0] != index_register or increments[0][1][1] != index_register:
        raise WalkerError("walker does not increment its UMADDL index")
    compares = [(vaddr, is_cmp_w_reg(word)) for vaddr, word in words.items()]
    compares = [(vaddr, decoded) for vaddr, decoded in compares if decoded is not None and decoded[0] == index_register]
    if len(compares) != 1 or compares[0][1][1] != 2:
        raise WalkerError("walker does not compare its induction index")
    branches = [(vaddr, word, is_b_cond(word)) for vaddr, word in words.items()]
    branches = [(vaddr, word, cond) for vaddr, word, cond in branches if cond is not None]
    back_edges = [(vaddr, decode_b_target(word, vaddr), cond) for vaddr, word, cond in branches]
    back_edges = [(vaddr, target, cond) for vaddr, target, cond in back_edges if target == loop_head and cond == 3]
    if len(back_edges) != 1:
        raise WalkerError("walker does not have one conditional back edge")
    # The exact image compares flags against 0x8000 and branches on EQ to the
    # return instruction.  This proves the terminator control effect without
    # assigning meanings to any other flag bits.
    flags_register = flag_loads[0][3]
    terminator_comparisons = [
        (vaddr, decoded)
        for vaddr, word in words.items()
        for decoded in [is_cmp_w_imm(word)]
        if decoded == (flags_register, 0x8000)
    ]
    if len(terminator_comparisons) != 1:
        raise WalkerError("walker terminator comparison is not pinned")
    terminator_cmp_va = terminator_comparisons[0][0]
    terminator_branch_va = terminator_cmp_va + 4
    terminator_branch_word = words.get(terminator_branch_va)
    terminator_condition = None if terminator_branch_word is None else is_b_cond(terminator_branch_word)
    terminator_target = None if terminator_branch_word is None else decode_b_target(terminator_branch_word, terminator_branch_va)
    if terminator_condition != 0 or terminator_target != end - 4:
        raise WalkerError("walker terminator does not branch EQ to its return instruction")
    if terminator_target is None or image.word(terminator_target) != 0xD65F03C0:
        raise WalkerError("walker terminator target is not an actual RET instruction")
    if terminator_branch_va >= store_va:
        raise WalkerError("walker terminator branch does not precede the store")
    # Ensure the table pointer arithmetic uses the immediate six, rather than
    # merely finding a six-byte-looking load/store cluster.
    if stride_register == 31:
        raise WalkerError("invalid stride register")
    return {
        "range": {"start": fmt(start), "end_exclusive": fmt(end), "size": end - start},
        "loop_head": fmt(loop_head),
        "back_edge": fmt(back_edges[0][0]),
        "umaddl": {
            "va": fmt(loop_head),
            "destination": f"X{destination}",
            "index_register": f"W{index_register}",
            "stride_register": f"W{stride_register}",
            "table_register": f"X{table_register}",
            "stride": 6,
        },
        "fields": {
            "flags": {"load": "LDRH", "offset": 0, "register": f"W{flags_register}", "semantics": "UNKNOWN"},
            "offset": {"load": "LDRH", "offset": 2, "register": f"W{offset_loads[0][3]}"},
            "value": {"load": "LDRB", "offset": 4, "register": f"W{value_loads[0][3]}", "zero_extended": True},
        },
        "terminator": {
            "comparison": f"CMP W{flags_register},#0x8000",
            "comparison_va": fmt(terminator_cmp_va),
            "flags_register": f"W{flags_register}",
            "flags_value": "0x8000",
            "branch": "B.EQ",
            "branch_va": fmt(terminator_branch_va),
            "branch_target": fmt(terminator_target),
            "semantics": "TERMINATOR_BRANCHES_TO_RETURN_BEFORE_STORE",
        },
        "base_load": {
            "load": f"LDR X{base_loads[0][3]},[X{base_loads[0][2]},#8]",
            "offset": 8,
            "base_register": f"X{base_loads[0][2]}",
            "destination": f"X{base_loads[0][3]}",
        },
        "store": {
            "va": fmt(store_va),
            "instruction": f"STR W{value_register},[X{base_register},X{offset_register}]",
            "value_width": 32,
            "value_zero_extended_from_byte": True,
            "conditional_on_flag_gate": True,
            "flag_gate_semantics": "UNKNOWN",
        },
        "induction": {
            "instruction": f"ADD W{index_register},W{index_register},#1",
            "compare": f"CMP W{compares[0][1][0]},W{compares[0][1][1]}",
            "back_edge_condition": "B.CC",
        },
        "record_shape": "DIRECT_SIX_BYTE_RECORD_OFFSET_VALUE_STORE_SHAPE",
        "record_stride": 6,
        "record": {
            "stride": 6,
            "flags_offset": 0,
            "offset_offset": 2,
            "value_offset": 4,
            "value_load": "LDRB",
            "value_store_width": 32,
            "terminator_flags": "0x8000",
        },
        "flags_semantics": "UNKNOWN_EXCEPT_EXACT_TERMINATOR_COMPARISON",
    }


def decode_exact_walker(image: Image) -> dict:
    _assert_words(image, WALKER_WORDS)
    walker_range = range_record(image, WALKER_START, WALKER_END, WALKER_FILE_OFFSET, WALKER_SHA256)
    loop_range = range_record(image, PREHEADER_LOOP_START, PREHEADER_LOOP_END, PREHEADER_LOOP_FILE_OFFSET, PREHEADER_LOOP_SHA256)
    flag_gate_range = range_record(image, WALKER_FLAG_GATE_START, WALKER_FLAG_GATE_END, expected_hash=WALKER_FLAG_GATE_SHA256)
    result = decode_six_byte_walker(image, WALKER_START, WALKER_END)
    result["range"] = walker_range
    result["preheader_loop_range"] = loop_range
    result["flag_gate_range"] = flag_gate_range
    result["instruction_pins"] = [
        {"va": fmt(vaddr), "word": fmt(word)} for vaddr, word in sorted(WALKER_WORDS.items())
    ]
    result["branch_pins"] = {
        "preheader_to_loop": {"va": fmt(0x148689D8), "target": fmt(0x14868A58)},
        "back_edge": {"va": fmt(WALKER_BACK_EDGE), "target": fmt(WALKER_LOOP_HEAD), "condition": "CC"},
        "terminator_to_return": {"va": fmt(0x148689F4), "target": fmt(0x14868A60), "condition": "EQ"},
    }
    result["zero_count_control"] = {
        "initial_index": "W9=0",
        "count_register": "W2",
        "compare": "CMP W9,W2",
        "compare_va": fmt(0x14868A58),
        "branch": "B.CC",
        "branch_va": fmt(WALKER_BACK_EDGE),
        "if_count_is_zero": "B.CC is false for 0 < 0; RET 0x14868a60 is reached before any table dereference",
    }
    return result


def parse_table(image: Image, start: int, count: int, expected_hash: str) -> dict:
    if count < 1:
        raise WalkerError("table count must include at least a terminator")
    data = image.slice(start, start + count * 6)
    digest = sha256(data)
    if digest != expected_hash:
        raise WalkerError(f"table hash mismatch at {fmt(start)}")
    records: list[tuple[int, int, int, int]] = []
    for index in range(count):
        flags, offset, value, reserved = struct.unpack_from("<HHBB", data, index * 6)
        records.append((flags, offset, value, reserved))
    if records[-1] != (0x8000, 0, 0, 0):
        raise WalkerError(f"table at {fmt(start)} has no exact terminator")
    if any(flags == 0x8000 for flags, _off, _value, _reserved in records[:-1]):
        raise WalkerError(f"table at {fmt(start)} has an early terminator")
    if any(reserved != 0 for _flags, _off, _value, reserved in records):
        raise WalkerError(f"table at {fmt(start)} has a nonzero reserved byte")
    nonterminators = records[:-1]
    if any(offset % 4 for _flags, offset, _value, _reserved in nonterminators):
        raise WalkerError(f"table at {fmt(start)} contains an unaligned offset")
    segment = image.segment_for(start)
    if segment is None or not segment.file_size:
        raise WalkerError(f"table at {fmt(start)} is not XBL file-backed")
    return {
        "start": fmt(start),
        "end_exclusive": fmt(start + count * 6),
        "count": count,
        "nonterminator_count": count - 1,
        "stride": 6,
        "sha256": digest,
        "terminator": {"flags": "0x8000", "offset": "0x0000", "value": "0x00", "reserved": "0x00"},
        "offset_alignment": 4,
        "file_backed_pt_load": {
            "segment_index": segment.index,
            "flags": segment.flags,
            "kind": segment.kind,
            "file_offset": fmt_offset(image.file_offset(start) or 0),
        },
    }, records


def tables_analysis(image: Image) -> dict:
    table_rows: list[dict] = []
    all_offsets: list[int] = []
    offsets_by_start: dict[int, list[int]] = {}
    for start, count, expected_hash in TABLE_SPECS:
        row, records = parse_table(image, start, count, expected_hash)
        table_rows.append(row)
        offsets_by_start[start] = [offset for _flags, offset, _value, _reserved in records[:-1]]
        all_offsets.extend(offsets_by_start[start])
    unique = sorted(set(all_offsets))
    if len(unique) != 170 or len(all_offsets) != 221:
        raise WalkerError("unexpected six-byte table offset union cardinality")
    if unique[0] != 0x7000 or unique[-1] != 0x7DE0 or any(value % 4 for value in unique):
        raise WalkerError("unexpected six-byte table offset bounds/alignment")
    excluded = [0x400, 0x404, 0x4D0]
    if any(value in unique for value in excluded):
        raise WalkerError("forbidden ranked offsets appeared in six-byte table union")
    scenario_tables = {
        "selector_eq_0xf": (0x14880BEE, 0x14880BA0),
        "selector_ne_0xf": (0x14880E70, 0x14880CF0, 0x14880B40),
    }
    scenario_unions = {}
    for scenario, starts in scenario_tables.items():
        scenario_offsets = sorted({offset for start in starts for offset in offsets_by_start[start]})
        scenario_unions[scenario] = {
            "table_starts": [fmt(start) for start in starts],
            "nonterminator_record_count": sum(len(offsets_by_start[start]) for start in starts),
            "unique_offset_count": len(scenario_offsets),
            "offset_min": fmt(scenario_offsets[0]),
            "offset_max": fmt(scenario_offsets[-1]),
            "offsets": [fmt(offset) for offset in scenario_offsets],
        }
    if scenario_unions["selector_eq_0xf"]["unique_offset_count"] != 53 or scenario_unions["selector_ne_0xf"]["unique_offset_count"] != 127:
        raise WalkerError("selector scenario union cardinality changed")
    return {
        "tables": table_rows,
        "table_count": len(table_rows),
        "nonterminator_record_count": len(all_offsets),
        "nonterminator_offset_union": [fmt(value) for value in unique],
        "nonterminator_offset_union_count": len(unique),
        "nonterminator_offset_min": fmt(unique[0]),
        "nonterminator_offset_max": fmt(unique[-1]),
        "all_offsets_aligned": True,
        "excluded_offsets_absent": [fmt(value) for value in excluded],
        "scenario_offset_unions": scenario_unions,
        "cross_alternative_union": {
            "unique_offset_count": len(unique),
            "offset_min": fmt(unique[0]),
            "offset_max": fmt(unique[-1]),
        },
        "record_interpretation": "LDRH_FLAGS_PLUS_0;LDRH_OFFSET_PLUS_2;LDRB_VALUE_PLUS_4;TERMINATOR_FLAGS_0x8000",
    }


def caller_flow(image: Image) -> dict:
    _assert_words(image, CALLER_FLOW_WORDS)
    callers = direct_callers(image, WALKER_START)
    if callers != list(CALLER_SITES):
        raise WalkerError(f"direct walker callers mismatch: {[fmt(v) for v in callers]}")
    flows = []
    providers = (0x1486A9B4, 0x1486A9EC, 0x1486AA20)
    for (start, end), caller, provider in zip(CALLER_FLOW_RANGES, CALLER_SITES, providers):
        data = image.slice(start, end)
        x1_status = (
            "PROVIDER_POINTER_STORE_FOR_BOTH_SELECTOR_ALTERNATIVES"
            if provider != 0x1486AA20
            else "NO_POINTER_STORE_ON_SELECTOR_EQ_0XF;PREEXISTING_STACK_SLOT_UNKNOWN"
        )
        flows.append(
            {
                "caller": fmt(caller),
                "provider": fmt(provider),
                "range": {
                    "start": fmt(start),
                    "end_exclusive": fmt(end),
                    "file_offset": fmt_offset(image.file_offset(start) or 0),
                    "size": end - start,
                    "sha256": sha256(data),
                },
                "arguments": {
                    "X0": "X19_CONTEXT",
                    "X1": "LDR_X1_FROM_SP_PLUS_0x18",
                    "W2": "PROVIDER_RETURN_W0",
                },
                "x1_pointer_status": x1_status,
            }
        )
    return {
        "target": fmt(WALKER_START),
        "direct_bl_callers": [fmt(vaddr) for vaddr in callers],
        "direct_bl_caller_count": len(callers),
        "scan_scope": "ALL_FILE_BACKED_EXECUTABLE_PT_LOAD_WORDS",
        "argument_flow": flows,
        "argument_flow_boundary": "Every caller loads X1 from the stack slot and passes W2 from the provider return; only the five nonzero alternatives prove that X1 is a provider-written table pointer.",
    }


def resolve_adrp_add(image: Image, adrp_va: int, add_va: int) -> int:
    adrp = adrp_page(image.word(adrp_va) or 0, adrp_va)
    add = is_add_x_imm(image.word(add_va) or 0)
    if adrp is None or add is None or add[1] != adrp[1] or add[3] != 0:
        raise WalkerError(f"ADRP+ADD pointer construction mismatch at {fmt(add_va)}")
    return (adrp[0] + add[2]) & 0xFFFFFFFF


def resolve_add_from_base(image: Image, base_adrp_va: int, base_add_va: int, add_va: int) -> int:
    base = resolve_adrp_add(image, base_adrp_va, base_add_va)
    base_add = is_add_x_imm(image.word(base_add_va) or 0)
    add = is_add_x_imm(image.word(add_va) or 0)
    if base_add is None or add is None or add[1] != base_add[0] or add[3] != 0:
        raise WalkerError(f"relative pointer construction mismatch at {fmt(add_va)}")
    return (base + add[2]) & 0xFFFFFFFF


def provider_analysis(image: Image, table_data: dict) -> dict:
    rows = []
    for start, end, expected_hash in PROVIDER_RANGES:
        row = range_record(image, start, end, expected_hash=expected_hash)
        row["entry"] = fmt(start)
        row["selector_address"] = fmt(SELECTOR_VA)
        rows.append(row)
    _assert_words(
        image,
        {
            0x1486A9C0: 0xB9400129,
            0x1486A9D0: 0x71003D3F,
            0x1486A9D4: 0x52800569,
            0x1486A9C4: 0x52800B4C,
            0x1486A9D8: 0x1A8C0120,
            0x1486A9E0: 0x9A8B0189,
            0x1486A9F8: 0xB9400129,
            0x1486AA04: 0x71003D3F,
            0x1486AA08: 0x528001A9,
            0x1486A9FC: 0x321A03EB,
            0x1486AA0C: 0x1A8B0120,
            0x1486AA14: 0x9A8B0149,
            0x1486AA28: 0xB9400129,
            0x1486AA2C: 0x71003D3F,
            0x1486AA30: 0x54000061,
            0x1486AA34: 0x2A1F03E0,
            0x1486AA38: 0xD65F03C0,
            0x1486AA40: 0x321C03E0,
            0x1486AA48: 0xF9000109,
        },
    )
    table_by_start = {int(row["start"], 16): row for row in table_data["tables"]}
    derived_targets = {
        "provider1_eq": resolve_add_from_base(image, 0x1486A9B8, 0x1486A9BC, 0x1486A9DC),
        "provider1_ne": resolve_add_from_base(image, 0x1486A9B8, 0x1486A9BC, 0x1486A9CC),
        "provider2_eq": resolve_adrp_add(image, 0x1486A9F0, 0x1486A9F4),
        "provider2_ne": resolve_add_from_base(image, 0x1486A9F0, 0x1486A9F4, 0x1486AA10),
        "provider3_ne": resolve_adrp_add(image, 0x1486AA3C, 0x1486AA44),
    }
    if set(derived_targets.values()) != set(table_by_start):
        raise WalkerError("provider pointer targets do not cover the five parsed tables")
    alternatives = [
        {"provider": fmt(0x1486A9B4), "condition": "selector == 0xf", "table": fmt(derived_targets["provider1_eq"]), "count": table_by_start[derived_targets["provider1_eq"]]["count"]},
        {"provider": fmt(0x1486A9B4), "condition": "selector != 0xf", "table": fmt(derived_targets["provider1_ne"]), "count": table_by_start[derived_targets["provider1_ne"]]["count"]},
        {"provider": fmt(0x1486A9EC), "condition": "selector == 0xf", "table": fmt(derived_targets["provider2_eq"]), "count": table_by_start[derived_targets["provider2_eq"]]["count"]},
        {"provider": fmt(0x1486A9EC), "condition": "selector != 0xf", "table": fmt(derived_targets["provider2_ne"]), "count": table_by_start[derived_targets["provider2_ne"]]["count"]},
        {"provider": fmt(0x1486AA20), "condition": "selector != 0xf", "table": fmt(derived_targets["provider3_ne"]), "count": table_by_start[derived_targets["provider3_ne"]]["count"]},
    ]
    return {
        "functions": rows,
        "runtime_selector": {
            "address": fmt(SELECTOR_VA),
            "current_value": "UNKNOWN",
            "storage": "MEMORY_ONLY_PT_LOAD",
            "file_backed": False,
            "semantics": "UNKNOWN",
        },
        "five_table_alternatives": alternatives,
        "derived_pointer_targets": {name: fmt(value) for name, value in sorted(derived_targets.items())},
        "selector_eq_0xf_provider3": {
            "table": None,
            "count": 0,
            "status": "NO_TABLE_POINTER_STORE",
            "branch": {"va": fmt(0x1486AA30), "instruction": "B.NE", "target": fmt(0x1486AA3C)},
            "eq_return_range": {"start": fmt(0x1486AA34), "end_exclusive": fmt(0x1486AA3C), "size": 8},
            "eq_return": {"va": fmt(0x1486AA38), "instruction": "RET"},
            "caller_w2": "0",
            "caller_x1": "LDR_X1_FROM_PREEXISTING_STACK_SLOT_UNKNOWN",
            "walker_zero_count_control": "CONDITIONALLY_RETURNS_BEFORE_ANY_TABLE_DEREFERENCE",
        },
        "flags_semantics": "UNKNOWN",
    }


def extract_ufs_block(data: bytes) -> bytes:
    """Return the complete adjacent ufsphy_mem/ufshc_mem source block.

    The block starts at the indentation immediately before ``ufsphy_mem`` and
    ends after the ``ufshc_mem`` node's ``};`` and following newline.  Pinning
    this complete slice lets the public and OSRC snapshots be compared without
    publishing either source path or source bytes.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WalkerError("DTS source is not UTF-8") from exc
    first = re.search(r"\bufsphy_mem\s*:[^{]*\{", text)
    second = re.search(r"\bufshc_mem\s*:[^{]*\{", text)
    if first is None or second is None or second.start() <= first.start():
        raise WalkerError("DTS UFS nodes are missing or out of order")
    start = text.rfind("\n", 0, first.start()) + 1
    depth = 1
    index = second.end()
    while index < len(text) and depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    if depth or text[index : index + 1] != ";":
        raise WalkerError("unterminated ufshc_mem DTS node")
    end = index + 2 if text[index + 1 : index + 2] == "\n" else index + 1
    block = data[start:end]
    if len(block) != UFS_BLOCK_SIZE or sha256(block) != UFS_BLOCK_SHA256:
        raise WalkerError("UFS source block is not the exact pinned design block")
    return block


def parse_dts_resources(data: bytes) -> dict:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WalkerError("DTS source is not UTF-8") from exc

    def node_body(label: str) -> str:
        match = re.search(rf"\b{re.escape(label)}\s*:[^{{]*\{{", text)
        if not match:
            raise WalkerError(f"DTS node not found: {label}")
        depth = 1
        index = match.end()
        while index < len(text) and depth:
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
            index += 1
        if depth:
            raise WalkerError(f"unterminated DTS node: {label}")
        return text[match.end() : index - 1]

    def regs(body: str) -> list[tuple[int, int]]:
        values = []
        statements = re.findall(r"\breg\s*=\s*([^;]+);", body, re.S)
        if len(statements) != 1:
            raise WalkerError("DTS node must have exactly one reg property")
        for cells in re.findall(r"<([^>]+)>", statements[0]):
            tokens = [token for token in cells.replace(",", " ").split() if token]
            if len(tokens) != 2 or not all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", token) for token in tokens):
                continue
            values.append((int(tokens[0], 0), int(tokens[1], 0)))
        return values

    standalone = regs(node_body("ufsphy_mem"))
    if standalone != [(0x1D87000, 0xDA8)]:
        raise WalkerError(f"unexpected ufsphy_mem reg: {standalone!r}")
    ufshc_body = node_body("ufshc_mem")
    ufshc_regs = regs(ufshc_body)
    names_match = re.search(r"reg-names\s*=\s*([^;]+);", ufshc_body, re.S)
    if not names_match:
        raise WalkerError("ufshc reg-names missing")
    names = re.findall(r'"([^"]+)"', names_match.group(1))
    if len(names) != len(ufshc_regs) or "ufs_phy" not in names:
        raise WalkerError("ufshc reg/resource count mismatch")
    phy = ufshc_regs[names.index("ufs_phy")]
    if phy != (0x1D87000, 0xE00):
        raise WalkerError(f"unexpected ufshc ufs_phy reg: {phy!r}")
    return {
        "ufsphy_mem": {
            "resource_start": fmt(standalone[0][0]),
            "resource_end_exclusive": fmt(standalone[0][0] + standalone[0][1]),
            "size": standalone[0][1],
            "reg_name": "phy_mem",
        },
        "ufshc_ufs_phy": {
            "resource_start": fmt(phy[0]),
            "resource_end_exclusive": fmt(phy[0] + phy[1]),
            "size": phy[1],
            "reg_name": "ufs_phy",
        },
    }


def load_exact(path: Path, expected_size: int, expected_hash: str, label: str) -> bytes:
    if not path.exists() or not path.is_file():
        raise WalkerError(f"missing exact {label}")
    data = path.read_bytes()
    if len(data) != expected_size or sha256(data) != expected_hash:
        raise WalkerError(f"{label} is not the exact pinned artifact")
    return data


def resolve_kernel_dtsi(path: Path | None, option_name: str, environment_name: str) -> Path:
    if path is not None:
        return path
    configured = os.environ.get(environment_name)
    if configured:
        return Path(configured)
    raise WalkerError(f"{option_name} is required")


def dts_analysis(public_path: Path | None = None, osrc_path: Path | None = None) -> dict:
    public_resolved = resolve_kernel_dtsi(public_path, "--public-kernel-dtsi", "EXP024_PUBLIC_KERNEL_DTSI")
    osrc_resolved = resolve_kernel_dtsi(osrc_path, "--osrc-kernel-dtsi", "EXP024_OSRC_KERNEL_DTSI")
    public_data = load_exact(public_resolved, PUBLIC_KERNEL_DTSI_SIZE, PUBLIC_KERNEL_DTSI_SHA256, KERNEL_DTSI_NAME)
    osrc_data = load_exact(osrc_resolved, OSRC_KERNEL_DTSI_SIZE, OSRC_KERNEL_DTSI_SHA256, KERNEL_DTSI_NAME)
    public_resources = parse_dts_resources(public_data)
    osrc_resources = parse_dts_resources(osrc_data)
    public_block = extract_ufs_block(public_data)
    osrc_block = extract_ufs_block(osrc_data)
    if public_block != osrc_block or public_resources != osrc_resources:
        raise WalkerError("public and OSRC UFS design sources disagree")
    return {
        "public_source": {
            "filename": KERNEL_DTSI_NAME,
            "size": len(public_data),
            "sha256": sha256(public_data),
            "provenance": PUBLIC_KERNEL_PROVENANCE,
        },
        "osrc_source": {
            "filename": KERNEL_DTSI_NAME,
            "size": len(osrc_data),
            "sha256": sha256(osrc_data),
            "provenance": OSRC_KERNEL_PROVENANCE,
        },
        "ufs_design_block": {"size": len(public_block), "sha256": sha256(public_block), "byte_identical": True},
        "public_resources": public_resources,
        "osrc_resources": osrc_resources,
        "resources": public_resources,
        "live_dtb_equality": "UNKNOWN",
    }


def base_audit(image: Image) -> dict:
    init_range = range_record(image, INITIALIZER_START, INITIALIZER_END, expected_hash=INITIALIZER_SHA256)
    main_range = range_record(image, MAIN_INIT_START, MAIN_INIT_END, expected_hash=MAIN_INIT_SHA256)
    _assert_words(image, {INITIALIZER_START: 0x52A03B00, INITIALIZER_START + 4: 0xD65F03C0, INITIALIZER_CALLER: 0x940009A6, INITIALIZER_STORE: 0xF9000660, BASE_HELPER_BLR: BASE_HELPER_BLR_WORD, BASE_HELPER_CALLER: 0x940009DC, BASE_HELPER_RELOAD: BASE_HELPER_RELOAD_WORD, BASE_HELPER_SLOT_LOAD: BASE_HELPER_SLOT_LOAD_WORD, BASE_HELPER_SLOT_ADDRESS: BASE_HELPER_SLOT_ADDRESS_WORD})
    returned = decode_movz_w(image.word(INITIALIZER_START) or 0)
    if returned != (INITIALIZER_RETURN, 0):
        raise WalkerError("initializer return literal mismatch")
    helper_range = range_record(image, BASE_HELPER_START, BASE_HELPER_END, expected_hash=BASE_HELPER_SHA256)
    context_stores = []
    for vaddr in range(MAIN_INIT_START, MAIN_INIT_END, 4):
        word = image.word(vaddr)
        if word is None or (word & 0xFFC00000) != 0xF9000000:
            continue
        rn = (word >> 5) & 0x1F
        offset = ((word >> 10) & 0xFFF) * 8
        if rn == 19 and offset == 8:
            context_stores.append(vaddr)
    if context_stores != [INITIALIZER_STORE]:
        raise WalkerError("unexpected direct context base store census")
    selector_segment = image.segment_for(SELECTOR_VA, file_backed=False)
    if selector_segment is None or selector_segment.file_size:
        raise WalkerError("selector is unexpectedly file-backed")
    runtime_bss_segment = image.segment_for(BASE_RUNTIME_BSS_SLOT, file_backed=False)
    if runtime_bss_segment is None or runtime_bss_segment.file_size or runtime_bss_segment.vaddr != 0x14882800 or runtime_bss_segment.mem_size != 0x1CC00:
        raise WalkerError("runtime-BSS slot mapping changed")
    return {
        "initializer": {
            "range": init_range,
            "returns": fmt(INITIALIZER_RETURN),
            "return_value": returned[0],
            "direct_caller": fmt(INITIALIZER_CALLER),
            "store": {"va": fmt(INITIALIZER_STORE), "instruction": "STR X0,[X19,#8]", "field_offset": 8},
        },
        "main_init": main_range,
        "local_context_base_store_census": {
            "store_count": len(context_stores),
            "store_vas": [fmt(value) for value in context_stores],
            "no_second_direct_store": True,
        },
        "unresolved_success_path": {
            "direct_call": fmt(BASE_HELPER_CALLER),
            "helper_range": helper_range,
            "unresolved_blr": {"va": fmt(BASE_HELPER_BLR), "word": fmt(BASE_HELPER_BLR_WORD), "target_register": "X9", "target": "UNKNOWN"},
            "runtime_bss_slot": {
                "address": fmt(BASE_RUNTIME_BSS_SLOT),
                "segment_index": runtime_bss_segment.index,
                "segment_vaddr": fmt(runtime_bss_segment.vaddr),
                "segment_file_size": runtime_bss_segment.file_size,
                "segment_mem_size": runtime_bss_segment.mem_size,
                "load_xref": {"va": fmt(BASE_HELPER_SLOT_LOAD), "word": fmt(BASE_HELPER_SLOT_LOAD_WORD)},
                "address_xref": {"va": fmt(BASE_HELPER_SLOT_ADDRESS), "word": fmt(BASE_HELPER_SLOT_ADDRESS_WORD)},
                "reload_xref": {"va": fmt(BASE_HELPER_RELOAD), "word": fmt(BASE_HELPER_RELOAD_WORD)},
            },
            "reason": "RUNTIME_BSS_OBJECT_INDIRECT_CALL_CONTINUES_TO_WALKER_PATH",
        },
        "base_currentness": "UNKNOWN",
        "mapping": {
            "status": "SUPPORTED",
            "conditional": True,
            "condition": "Conditional on the initialized 0x01d80000 base remaining current through every reachable direct success-path callee and alias.",
        },
    }


def destination_analysis(table_data: dict, dts_data: dict) -> dict:
    offsets = [int(value, 16) for value in table_data["nonterminator_offset_union"]]
    broad_start = int(dts_data["resources"]["ufshc_ufs_phy"]["resource_start"], 16)
    broad_end = int(dts_data["resources"]["ufshc_ufs_phy"]["resource_end_exclusive"], 16)
    standalone_end = int(dts_data["resources"]["ufsphy_mem"]["resource_end_exclusive"], 16)
    destinations = [BASE + offset for offset in offsets]
    if not all(broad_start <= destination < broad_end for destination in destinations):
        raise WalkerError("conditional destinations escaped ufshc ufs_phy resource")
    beyond = [offset for offset, destination in zip(offsets, destinations) if destination >= standalone_end]
    if beyond != [0x7DC4, 0x7DD8, 0x7DE0]:
        raise WalkerError("unexpected standalone ufsphy_mem out-of-range subset")
    return {
        "base": fmt(BASE),
        "base_currentness": "UNKNOWN",
        "condition": "If the initializer's stored base remains current at walker execution.",
        "domain": "CROSS_ALTERNATIVE_SYMBOLIC_OFFSET_SUPERSET",
        "conditional_destination_count": len(destinations),
        "conditional_destinations_within_ufshc_ufs_phy": len(destinations),
        "conditional_destinations_within_standalone_ufsphy_mem": len(destinations) - len(beyond),
        "outside_standalone_ufsphy_mem_offsets": [fmt(value) for value in beyond],
        "actual_current_destinations": "UNKNOWN",
        "actual_reached_store_subset": "UNKNOWN",
        "flag_semantics": "UNKNOWN",
        "broader_resource": dts_data["resources"]["ufshc_ufs_phy"],
        "standalone_resource": dts_data["resources"]["ufsphy_mem"],
    }


def provider_pointer_proof(image: Image, table_data: dict) -> dict:
    # Pin the exact ADRP/ADD/CSEL/STR constructions that put the five table
    # addresses into the caller's stack slot.  The table ranges are already
    # mapped to XBL file-backed PT_LOAD 4 by parse_table.
    pins = {
        0x1486A9B8: 0xD00000AA,
        0x1486A9BC: 0x912E814A,
        0x1486A9CC: 0x910B414B,
        0x1486A9DC: 0x9101394C,
        0x1486A9E0: 0x9A8B0189,
        0x1486A9E4: 0xF9000109,
        0x1486A9EC: 0xB0FFF249,
        0x1486A9F0: 0xD00000AA,
        0x1486A9F4: 0x912E814A,
        0x1486AA10: 0x9105414B,
        0x1486AA14: 0x9A8B0149,
        0x1486AA18: 0xF9000109,
        0x1486AA3C: 0xD00000A9,
        0x1486AA44: 0x912D0129,
        0x1486AA48: 0xF9000109,
    }
    _assert_words(image, pins)
    table_by_start = {row["start"]: row for row in table_data["tables"]}
    for start in table_by_start:
        segment = image.segment_for(int(start, 16))
        if segment is None or not segment.file_size:
            raise WalkerError(f"table pointer target is not file-backed: {start}")
    return {
        "status": "PROVED",
        "pointer_targets": [
            {"table": fmt(0x14880BEE), "provider": fmt(0x1486A9B4), "selection": "selector == 0xf", "pointer_storage": "X9"},
            {"table": fmt(0x14880E70), "provider": fmt(0x1486A9B4), "selection": "selector != 0xf", "pointer_storage": "X9"},
            {"table": fmt(0x14880BA0), "provider": fmt(0x1486A9EC), "selection": "selector == 0xf", "pointer_storage": "X9"},
            {"table": fmt(0x14880CF0), "provider": fmt(0x1486A9EC), "selection": "selector != 0xf", "pointer_storage": "X9"},
            {"table": fmt(0x14880B40), "provider": fmt(0x1486AA20), "selection": "selector != 0xf", "pointer_storage": "X9"},
        ],
        "target_residence": "EXACT_XBL_FILE_BACKED_PT_LOAD",
        "record_stride": 6,
        "not_xbl_config_8byte_candidate_arrays": "PROVED_BY_XBL_RESIDENCE_AND_SIX_BYTE_STRIDE_PLUS_PINNED_019_COMPARISON",
        "xbl_config_semantic_identity": "UNKNOWN",
        "instruction_pins": [{"va": fmt(vaddr), "word": fmt(word)} for vaddr, word in sorted(pins.items())],
    }


def load_xbl(firmware_dir: Path) -> bytes:
    return load_exact(firmware_dir / XBL_NAME, XBL_SIZE, XBL_SHA256, XBL_NAME)


def load_019_dependency(path: Path = DEPENDENCY_019_PATH) -> dict:
    """Pin the prior eight-byte xbl_config pair-array structural result."""
    data = load_exact(path, DEPENDENCY_019_SIZE, DEPENDENCY_019_SHA256, DEPENDENCY_019_NAME)
    try:
        prior = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WalkerError("Experiment 019 dependency is not valid JSON") from exc
    if prior.get("dcb_image") != "xbl_config--sdb2.bin" or prior.get("candidate_pair_array_count") != 28:
        raise WalkerError("Experiment 019 dependency does not pin the expected pair-array result")
    if prior.get("dcb_image_sha256") != "0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c":
        raise WalkerError("Experiment 019 dependency DCB hash changed")
    return {
        "filename": DEPENDENCY_019_NAME,
        "size": len(data),
        "sha256": sha256(data),
        "dcb_image": prior["dcb_image"],
        "dcb_image_sha256": prior["dcb_image_sha256"],
        "candidate_pair_array_count": prior["candidate_pair_array_count"],
        "representation": "EIGHT_BYTE_XBL_CONFIG_CANDIDATE_PAIR_ARRAYS",
    }


def build_manifest(
    firmware_dir: Path = FIRMWARE_DIR,
    public_kernel_dtsi: Path | None = None,
    osrc_kernel_dtsi: Path | None = None,
    kernel_dtsi: Path | None = None,
) -> dict:
    # ``kernel_dtsi`` is retained as a compatibility spelling for callers of
    # the earlier one-source draft; it always denotes the public snapshot.
    if public_kernel_dtsi is None and kernel_dtsi is not None:
        public_kernel_dtsi = kernel_dtsi
    image = Image(load_xbl(firmware_dir))
    walker = decode_exact_walker(image)
    callers = caller_flow(image)
    tables = tables_analysis(image)
    providers = provider_analysis(image, tables)
    dts = dts_analysis(public_kernel_dtsi, osrc_kernel_dtsi)
    dependency_019 = load_019_dependency()
    base_audit_result = base_audit(image)
    destinations = destination_analysis(tables, dts)
    pointer_proof = provider_pointer_proof(image, tables)
    selector_segment = image.segment_for(SELECTOR_VA, file_backed=False)
    executable_words = sum(segment.file_size // 4 for segment in image.executable())
    if len(direct_callers(image, WALKER_START)) != 3:
        raise WalkerError("direct caller census changed")
    return {
        "schema": SCHEMA,
        "experiment_id": "024-xbl-six-byte-walker",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "boundary_bypass": "NO_BOUNDARY_BYPASS_OBSERVED",
        "eligibility": {"class": "C", "experiments_015_016": "NOT_ELIGIBLE", "device_action": "NONE"},
        "inputs": {
            "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256},
            "public_kernel_dtsi": dts["public_source"],
            "osrc_kernel_dtsi": dts["osrc_source"],
            "ufs_design_block": dts["ufs_design_block"],
        },
        "elf": {
            "format": "ELF64_LITTLE_AARCH64",
            "file_backed_executable_pt_load_count": len(image.executable()),
            "file_backed_executable_aligned_word_count": executable_words,
            "scan_scope": "ALL_FILE_BACKED_EXECUTABLE_PT_LOAD_WORDS",
            "file_backed_pt_loads": [
                {
                    "segment_index": segment.index,
                    "file_offset": fmt_offset(segment.file_offset),
                    "vaddr": fmt(segment.vaddr),
                    "file_size": segment.file_size,
                    "mem_size": segment.mem_size,
                    "flags": segment.flags,
                    "kind": segment.kind,
                }
                for segment in image.file_backed()
            ],
            "runtime_selector_pt_load": {"address": fmt(SELECTOR_VA), "file_backed": False, "memory_only": bool(selector_segment and not selector_segment.file_size)},
        },
        "walker": walker,
        "direct_callers": callers,
        "providers": providers,
        "tables": tables,
        "provider_pointer_proof": pointer_proof,
        "dependencies": {"experiment_019": dependency_019},
        "dts_resources": {
            "public": dts["public_resources"],
            "osrc": dts["osrc_resources"],
            "ufs_design_block": dts["ufs_design_block"],
            "live_dtb_equality": dts["live_dtb_equality"],
        },
        "initializer_and_base_audit": base_audit_result,
        "conditional_ufs_destinations": destinations,
        "claims": {
            "PROVED": [
                "The exact XBL contains the pinned six-byte record walker at [0x148689a0,0x14868a64), with UMADDL pointer arithmetic, LDRH fields at +0/+2, LDRB at +4, a 0x8000 comparison, and B.EQ to RET before the conditional store.",
                "The walker uses a six-byte record stride; when the flag-gated store path is taken, LDRB zero-extends the byte and STR writes a 32-bit word. Other nonterminator flag combinations may skip the store, and flag semantics remain UNKNOWN.",
                "Exactly three direct BL callers to the walker exist across all file-backed executable PT_LOAD words; each loads X1 from the stack slot and passes W2 from the provider return, while only the five nonzero alternatives prove a provider-written table pointer.",
                "The five provider-selected table ranges are file-backed in the exact XBL, each has an exact six-byte stride and terminating flags 0x8000/0/0/0 record; selector==0xf has 53 unique offsets, selector!=0xf has 127, and their cross-alternative union has 170.",
                "If the initializer's 0x01d80000 base remains current, the public and OSRC DTS snapshots independently pin byte-identical UFS design blocks and all 170 symbolic BASE+offset destinations derived from the cross-alternative syntactic offset superset lie inside broader ufshc ufs_phy [0x01d87000,0x01d87e00); three then lie beyond standalone ufsphy_mem [0x01d87000,0x01d87da8). Actual current destinations remain UNKNOWN.",
                "The direct provider pointer targets are structurally XBL-resident six-byte tables, distinct from the pinned Experiment 019 eight-byte xbl_config candidate-pair-array representation; semantic DCB identity remains UNKNOWN.",
                "On selector==0xf, provider3 writes no table pointer and returns count zero; the pinned walker zero-count control reaches RET before any table dereference, conditional on that returned count.",
            ],
            "SUPPORTED": [
                "The direct-call positive control supports a table-driven path that is conditional on the initialized base remaining current and on flag-gated store reach; it does not prove or refute a ranked DDR/MC/DCB path.",
                "The five selector alternatives and counts are supported by exact provider instruction pins; the selector's current value and runtime execution remain UNKNOWN.",
            ],
            "HYPOTHESIS": [],
            "UNKNOWN": [
                "The current runtime value at selector address 0x146b3000, runtime execution, flag-gated reached subsets, postboot mutation, and equality of either design source to the live DTB.",
                "Whether the initialized 0x01d80000 base remains current through every reachable direct success-path callee or alias; the unresolved BLR X9 at 0x1486ac1c prevents a global current-base proof.",
                "Whether any table is a DCB consumer, which indirect callers or other walkers exist, global DCB consumer/writer presence, and any xbl_config semantic alias.",
                "Register semantics, the Experiment 014 GF(2) relation, physical ownership, aliases, boundary bypass, and any device authority.",
            ],
            "REFUTED": [],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--public-kernel-dtsi", type=Path, default=None)
    parser.add_argument("--osrc-kernel-dtsi", type=Path, default=None)
    # Compatibility spelling for the first one-source draft.  It is treated
    # as --public-kernel-dtsi; the OSRC source is still independently pinned.
    parser.add_argument("--kernel-dtsi", dest="public_kernel_dtsi_compat", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        # os.open's creation mode is umask-filtered; fchmod makes the
        # publication contract exact even under a restrictive caller umask.
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    public_path = args.public_kernel_dtsi or args.public_kernel_dtsi_compat
    if public_path is None:
        parser.error("--public-kernel-dtsi is required for publication")
    if args.osrc_kernel_dtsi is None:
        parser.error("--osrc-kernel-dtsi is required for publication")
    manifest = build_manifest(args.firmware_dir, public_path, args.osrc_kernel_dtsi)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")
    write_no_clobber(args.output, payload)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
