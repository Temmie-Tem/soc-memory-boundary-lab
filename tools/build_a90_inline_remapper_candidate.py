#!/usr/bin/env python3
"""Build fixed, inline A90 remapper control/read boot candidates.

The candidate reuses the exact stock-kernel hook site that booted in
Experiment 007, but removes the generic call/peek/poke REPL.  One guarded op
performs one of two pinned operations in one kernel control flow.  ``control``
maps and immediately unmaps without a bus load; ``read`` performs:

    __ioremap(0x09248080, 0x5c, PROT_DEVICE_nGnRE)
    32-bit load at offset zero
    __iounmap(mapping)
    printk("A90R%llx\\n", zero_extended_value)

There is no runtime address or call-target input and no MMIO store.  This tool
only builds host artifacts; it performs no device action.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools.build_a90_repl_candidate import (
        BASE_SHA256,
        DEFAULT_BASE,
        HISTORICAL_SOURCES,
        SOURCE_COMMIT,
        SOURCE_REPO,
        load_live_proven_builder,
        sha256_file,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from build_a90_repl_candidate import (
        BASE_SHA256,
        DEFAULT_BASE,
        HISTORICAL_SOURCES,
        SOURCE_COMMIT,
        SOURCE_REPO,
        load_live_proven_builder,
        sha256_file,
    )


MANIFEST_NAME = "candidate-manifest.json"
MODE_CONTROL = "control"
MODE_READ = "read"
MODES = (MODE_CONTROL, MODE_READ)
CONTROL_SENTINEL = 0xC071
EXPECTED_HASHES = {
    MODE_CONTROL: {
        "candidate": "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247",
        "body": "0a094ef803e78c773bb548f12c4eb364da27b4b3681dc0d4b37edbf883cf30a7",
    },
    MODE_READ: {
        "candidate": "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed",
        "body": "730f420b219f9ad3ab7da5488f5b8dac3638099cc0007aad7dd31ddfb53982d6",
    },
}

ENTRY_OFF = 0x8A73C8
MAGIC_BEFORE_OFF = 0x8A73C4
NEXT_MAGIC_OFF = 0x8A749C
PATCH_ROOM = NEXT_MAGIC_OFF - ENTRY_OFF
JOPP_MAGIC = 0x00BE7BAD
REPL_MAGIC = 0xA90C0DE5DEADBEEF
OP_FIXED_READ = 4
FIXED_PHYS = 0x09248080
FIXED_SIZE = 0x5C
PROT_DEVICE_NGNRE = 0x0068000000000707
IOREMAP_LINK = 0xFFFFFF80080A4094
IOUNMAP_LINK = 0xFFFFFF80080A4194
PRINTK_WRAPPER_LINK = 0xFFFFFF800813D8CC
FORMAT = b"A90R%llx\n\x00"

EXPECTED_TARGET_PREFIXES = {
    IOREMAP_LINK: (0xCA1103D0, 0xA9BF43FD, 0x910003FD, 0xAA1E03E3),
    IOUNMAP_LINK: (0xCA1103D0, 0xA9BE43FD, 0xF9000BF3, 0x910003FD),
}


def _check_reg(value: int) -> None:
    if not 0 <= value <= 31:
        raise ValueError(f"bad register: {value}")


def _scaled_imm(imm: int, scale: int, bits: int, *, signed: bool = False) -> int:
    if imm % scale:
        raise ValueError(f"unaligned immediate {imm} for scale {scale}")
    value = imm // scale
    if signed:
        low = -(1 << (bits - 1))
        high = (1 << (bits - 1)) - 1
        if not low <= value <= high:
            raise ValueError(f"signed immediate out of range: {imm}")
        return value & ((1 << bits) - 1)
    if not 0 <= value < (1 << bits):
        raise ValueError(f"immediate out of range: {imm}")
    return value


def encode_stp_offset_x(rt: int, rt2: int, rn: int, imm: int) -> int:
    for reg in (rt, rt2, rn):
        _check_reg(reg)
    imm7 = _scaled_imm(imm, 8, 7, signed=True)
    return 0xA9000000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt


def encode_movz_x(rd: int, imm16: int, shift: int = 0) -> int:
    _check_reg(rd)
    if not 0 <= imm16 <= 0xFFFF or shift not in (0, 16, 32, 48):
        raise ValueError("invalid MOVZ immediate or shift")
    return 0xD2800000 | ((shift // 16) << 21) | (imm16 << 5) | rd


def encode_movk_x(rd: int, imm16: int, shift: int = 0) -> int:
    _check_reg(rd)
    if not 0 <= imm16 <= 0xFFFF or shift not in (0, 16, 32, 48):
        raise ValueError("invalid MOVK immediate or shift")
    return 0xF2800000 | ((shift // 16) << 21) | (imm16 << 5) | rd


def encode_cbz_x_index(rt: int, site_index: int, target_index: int) -> int:
    _check_reg(rt)
    imm19 = target_index - site_index
    if not -(1 << 18) <= imm19 < (1 << 18):
        raise ValueError("CBZ target out of range")
    return 0xB4000000 | ((imm19 & 0x7FFFF) << 5) | rt


def encode_ldr_w_imm(rt: int, rn: int, imm: int = 0) -> int:
    _check_reg(rt)
    _check_reg(rn)
    imm12 = _scaled_imm(imm, 4, 12)
    return 0xB9400000 | (imm12 << 10) | (rn << 5) | rt


def encode_mov_w(rd: int, rn: int) -> int:
    _check_reg(rd)
    _check_reg(rn)
    return 0x2A0003E0 | (rn << 16) | rd


def _site(entry_vaddr: int, word_index: int) -> int:
    return entry_vaddr + word_index * 4


def output_names(mode: str) -> tuple[str, str]:
    if mode not in MODES:
        raise ValueError(f"unsupported mode: {mode}")
    return (
        f"boot_linux_inline_remapper_{mode}_v1.img",
        f"force_no_nap_store_inline_remapper_{mode}_v1.bin",
    )


def default_output_dir(mode: str) -> Path:
    if mode not in MODES:
        raise ValueError(f"unsupported mode: {mode}")
    return Path(f"evidence/private/007-inline-remapper-{mode}-20260825-01")


def build_inline_words(legacy: Any, mode: str = MODE_READ) -> list[int]:
    if mode not in MODES:
        raise ValueError(f"unsupported mode: {mode}")
    stage = legacy.stage_c
    entry_vaddr = stage.kernel_vaddr(ENTRY_OFF)
    labels = {"fail": 27, "print": 28, "out": 30, "magic": 35, "fmt": 37}
    words = [
        stage.U32_EOR_PROLOGUE,  # 00 eor x16,x30,x17
        legacy.encode_stp_pre_x(16, 17, 31, -48),  # 01 save ROPP value/key
        encode_stp_offset_x(19, 20, 31, 16),  # 02 preserve callee-saved values
        legacy.encode_str_x_imm(3, 31, 32),  # 03 preserve sysfs count
        legacy.encode_ldr_literal_x(
            7, _site(entry_vaddr, 4), _site(entry_vaddr, labels["magic"])
        ),
        legacy.encode_ldr_x_imm(4, 2, 0),  # 05 command magic
        0xEB07009F,  # 06 cmp x4,x7
        legacy.encode_b_cond_index(7, labels["out"], 0x1),  # 07 b.ne out
        legacy.encode_ldrb_w_imm(4, 2, 8),  # 08 fixed op
        legacy.encode_cmp_w_imm(4, OP_FIXED_READ),
        legacy.encode_b_cond_index(10, labels["out"], 0x1),  # 10 b.ne out
        encode_movz_x(0, FIXED_PHYS & 0xFFFF),
        encode_movk_x(0, (FIXED_PHYS >> 16) & 0xFFFF, 16),
        encode_movz_x(1, FIXED_SIZE),
        encode_movz_x(2, PROT_DEVICE_NGNRE & 0xFFFF),
        encode_movk_x(2, (PROT_DEVICE_NGNRE >> 48) & 0xFFFF, 48),
        stage.encode_bl(_site(entry_vaddr, 16), IOREMAP_LINK),
        encode_cbz_x_index(0, 17, labels["fail"]),
        legacy.encode_mov_x(19, 0),
        (
            encode_ldr_w_imm(20, 19, 0)  # 19 read mode's sole MMIO access
            if mode == MODE_READ
            else encode_movz_x(20, CONTROL_SENTINEL)  # map/unmap control
        ),
        0xD5033F9F,  # 20 dsb sy
        0xD5033FDF,  # 21 isb
        0xD5033D9F,  # 22 dsb ld, matching the stock readl ordering barrier
        legacy.encode_mov_x(0, 19),
        stage.encode_bl(_site(entry_vaddr, 24), IOUNMAP_LINK),
        encode_mov_w(1, 20),  # 25 zero-extend observed u32 for printk
        legacy.encode_b_index(26, labels["print"]),
        0x92800001,  # 27 fail: movn x1,#0 => distinct 64-bit map-failure value
        legacy.encode_adr(
            0, _site(entry_vaddr, 28), _site(entry_vaddr, labels["fmt"])
        ),
        stage.encode_bl(_site(entry_vaddr, 29), PRINTK_WRAPPER_LINK),
        legacy.encode_ldr_x_imm(0, 31, 32),  # 30 return original sysfs count
        legacy.encode_ldp_x_imm(19, 20, 31, 16),
        legacy.encode_ldp_post_x(16, 17, 31, 48),
        stage.U32_EOR_EPILOGUE,
        stage.U32_RET,
    ]
    if len(words) != labels["magic"]:
        raise RuntimeError(f"inline code size drifted: {len(words)}")
    return words


def build_inline_payload(legacy: Any, mode: str = MODE_READ) -> bytes:
    words = build_inline_words(legacy, mode)
    payload = b"".join(legacy.stage_c.put_u32(word) for word in words)
    payload += struct.pack("<Q", REPL_MAGIC)
    payload += FORMAT
    while len(payload) % 4:
        payload += b"\x00"
    if len(payload) > PATCH_ROOM:
        raise RuntimeError(f"inline payload too large: {len(payload)} > {PATCH_ROOM}")
    payload += legacy.stage_c.put_u32(legacy.stage_c.U32_NOP) * (
        (PATCH_ROOM - len(payload)) // 4
    )
    if len(payload) != PATCH_ROOM:
        raise RuntimeError("inline payload does not exactly fill patch room")
    return payload


def validate_base_kernel(kernel: bytes, legacy: Any) -> None:
    stage = legacy.stage_c
    poke = legacy.poke
    if stage.u32_at(kernel, MAGIC_BEFORE_OFF) != JOPP_MAGIC:
        raise RuntimeError("missing JOPP magic before hook")
    if stage.u32_at(kernel, ENTRY_OFF) != poke.U32_FNN_STORE_FIRST:
        raise RuntimeError("hook entry fingerprint mismatch")
    if stage.u32_at(kernel, ENTRY_OFF + 4) != poke.U32_EOR_PROLOGUE:
        raise RuntimeError("hook ROPP fingerprint mismatch")
    if stage.u32_at(kernel, NEXT_MAGIC_OFF) != JOPP_MAGIC:
        raise RuntimeError("missing JOPP magic after hook room")
    for link, expected in EXPECTED_TARGET_PREFIXES.items():
        off = link - stage.KERNEL_FILE_VADDR_BASE
        if stage.u32_at(kernel, off - 4) != JOPP_MAGIC:
            raise RuntimeError(f"call target is not a JOPP entry: 0x{link:x}")
        got = tuple(stage.u32_at(kernel, off + 4 * index) for index in range(len(expected)))
        if got != expected:
            raise RuntimeError(f"call target prefix mismatch: 0x{link:x}")


def build(
    base: Path,
    output_dir: Path,
    source_repo: Path,
    *,
    mode: str = MODE_CONTROL,
) -> dict[str, object]:
    if mode not in MODES:
        raise ValueError(f"unsupported mode: {mode}")
    base = base.resolve()
    output_dir = output_dir.resolve()
    if sha256_file(base) != BASE_SHA256:
        raise RuntimeError("V2321 base boot SHA-256 mismatch")
    candidate_name, body_name = output_names(mode)
    candidate = output_dir / candidate_name
    body = output_dir / body_name
    manifest_path = output_dir / MANIFEST_NAME
    for path in (candidate, body, manifest_path):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite output: {path}")

    with tempfile.TemporaryDirectory(prefix="sdm855-inline-remapper-") as temp_text:
        legacy = load_live_proven_builder(
            source_repo.resolve(), SOURCE_COMMIT, Path(temp_text)
        )
        original = base.read_bytes()
        layout = legacy.stage_c.parse_boot_layout(original)
        kernel = bytes(
            original[layout.kernel_off : layout.kernel_off + layout.kernel_size]
        )
        if kernel[:16] != b"UNCOMPRESSED_IMG":
            raise RuntimeError("kernel wrapper is not UNCOMPRESSED_IMG")
        validate_base_kernel(kernel, legacy)
        _magic, printk_off, _va_helper, _emit_core = (
            legacy.stage_c.locate_printk_variadic_wrapper(kernel)
        )
        if legacy.stage_c.kernel_vaddr(printk_off) != PRINTK_WRAPPER_LINK:
            raise RuntimeError("printk wrapper identity drifted")
        payload = build_inline_payload(legacy, mode)

        patched = bytearray(original)
        patch_abs = layout.kernel_off + ENTRY_OFF
        patched[patch_abs : patch_abs + len(payload)] = payload
        patched_kernel = bytes(
            patched[layout.kernel_off : layout.kernel_off + layout.kernel_size]
        )
        if legacy.stage_c.u32_at(patched_kernel, MAGIC_BEFORE_OFF) != JOPP_MAGIC:
            raise RuntimeError("patched image clobbered prior JOPP magic")
        if legacy.stage_c.u32_at(patched_kernel, NEXT_MAGIC_OFF) != JOPP_MAGIC:
            raise RuntimeError("patched image clobbered next JOPP magic")
        boot_id = legacy.stage_c.recompute_boot_id(patched, layout)
        changed = legacy.stage_c.changed_offsets(original, bytes(patched))
        allowed = set(range(patch_abs, patch_abs + len(payload)))
        allowed.update(
            range(
                legacy.stage_c.BOOT_ID_OFFSET,
                legacy.stage_c.BOOT_ID_OFFSET + legacy.stage_c.BOOT_ID_SIZE,
            )
        )
        unexpected = [offset for offset in changed if offset not in allowed]
        if unexpected:
            raise RuntimeError(f"unexpected patched offsets: {unexpected[:8]}")

        output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        candidate_bytes = bytes(patched)
        candidate_sha = hashlib.sha256(candidate_bytes).hexdigest()
        body_sha = hashlib.sha256(payload).hexdigest()
        if candidate_sha != EXPECTED_HASHES[mode]["candidate"]:
            raise RuntimeError(f"{mode} candidate reproduction hash mismatch")
        if body_sha != EXPECTED_HASHES[mode]["body"]:
            raise RuntimeError(f"{mode} body reproduction hash mismatch")
        write_new(candidate, candidate_bytes, 0o600)
        write_new(body, payload, 0o600)
        manifest = {
            "schema": "sdm855-a90-inline-remapper-candidate-v1",
            "device_action": False,
            "mode": mode,
            "source_repo": str(source_repo.resolve()),
            "source_commit": SOURCE_COMMIT,
            "historical_source_sha256": HISTORICAL_SOURCES,
            "base_boot": str(base),
            "base_sha256": BASE_SHA256,
            "candidate": str(candidate),
            "candidate_sha256": candidate_sha,
            "candidate_size": len(candidate_bytes),
            "body": str(body),
            "body_sha256": body_sha,
            "body_size": len(payload),
            "boot_id": boot_id[:20].hex(),
            "hook": {
                "handler": "kgsl_pwrctrl_force_no_nap_store",
                "sysfs_node": legacy.poke.SYSFS_NODE,
                "entry_off": f"0x{ENTRY_OFF:x}",
                "entry_vaddr": f"0x{legacy.stage_c.kernel_vaddr(ENTRY_OFF):x}",
                "patch_room": PATCH_ROOM,
                "jopp_boundaries_preserved": True,
            },
            "fixed_operation": {
                "op": OP_FIXED_READ,
                "physical_base": f"0x{FIXED_PHYS:08x}",
                "size": FIXED_SIZE,
                "width_bits": 32,
                "offset": 0,
                "prot_device_ngnre": f"0x{PROT_DEVICE_NGNRE:016x}",
                "sequence": (
                    ["__ioremap", "ldr-w", "__iounmap", "printk"]
                    if mode == MODE_READ
                    else ["__ioremap", "__iounmap", "printk-control-sentinel"]
                ),
                "ioremap_link": f"0x{IOREMAP_LINK:x}",
                "iounmap_link": f"0x{IOUNMAP_LINK:x}",
                "printk_wrapper_link": f"0x{PRINTK_WRAPPER_LINK:x}",
                "map_failure_result": "0xffffffffffffffff",
                "control_sentinel": f"0x{CONTROL_SENTINEL:x}",
            },
            "safety": {
                "generic_call_target": False,
                "runtime_address_input": False,
                "arbitrary_address_input": False,
                "mmio_write_instruction": False,
                "mmio_read_instruction": mode == MODE_READ,
                "mapping_cleanup_precedes_result": True,
                "device_write": False,
            },
            "changed_byte_count": len(changed),
            "changed_ranges": [
                [hex(start), hex(end)]
                for start, end in legacy.stage_c.contiguous_ranges(changed)
            ],
            "reproduction_hash_pinned": True,
        }
        write_new(manifest_path, json_bytes(manifest), 0o600)
        os.chmod(output_dir, 0o700)
        return manifest


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--source-repo", type=Path, default=SOURCE_REPO)
    parser.add_argument("--mode", choices=MODES, default=MODE_CONTROL)
    parser.add_argument("--output-dir", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    output_dir = args.output_dir or default_output_dir(args.mode)
    print(
        json.dumps(
            build(args.base, output_dir, args.source_repo, mode=args.mode), indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
