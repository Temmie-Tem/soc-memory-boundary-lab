#!/usr/bin/env python3
"""Inspect exactly one landing word for each unique conditional target in 020K."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, struct, sys
from pathlib import Path
from typing import Any, Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path: sys.path.insert(0, str(_ROOT))
from tools.sm8150_xbl_caller_context_barrier_operand_target_inventory_020k import Image, TraceError, write_no_clobber
from tools import sm8150_xbl_caller_context_barrier_operand_target_inventory_020k as k
from tools.sm8150_xbl_second_caller_field_use_020d import decode_adrp, decode_ldr_unsigned
from tools.sm8150_xbl_static_slot_load_use_020f import decode_mov_register

SCHEMA = "sm8150-xbl-caller-context-branch-target-landing-word-inventory-v1"
EXPERIMENT_ID = "020L-branch-target-landing-word"
MODE = "HOST_ONLY_READ_ONLY"
XBL_NAME, XBL_SIZE = "xbl--sdb1.bin", 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
K_NAME = "020K-caller-context-barrier-operand-target-inventory-20260827-01.manifest.json"
K_SIZE, K_SHA256 = 9961, "90a0cf4d264c64d0d2836b567a2dc8ac5abff7809be839e5131fc7e91e32975a"
K_TOOL_NAME, K_TOOL_SIZE = "sm8150_xbl_caller_context_barrier_operand_target_inventory_020k.py", 19309
K_TOOL_SHA256 = "efe1a4dd062bd76adfe3f535f441e86fc74a36c105433c884296f648ae5e4ae1"
K_PATH = _ROOT / "evidence/manifests" / K_NAME
K_TOOL_PATH = _ROOT / "tools" / K_TOOL_NAME
DECODER_020D_NAME, DECODER_020D_SIZE = "sm8150_xbl_second_caller_field_use_020d.py", 21053
DECODER_020D_SHA256 = "5a315f8735c38c86147367a1ad7c953d263d58c4bc63251473fa565e15efb332"
DECODER_020F_NAME, DECODER_020F_SIZE = "sm8150_xbl_static_slot_load_use_020f.py", 23772
DECODER_020F_SHA256 = "b1f12fb516b52e3b15168e61930d407f08788dd2379fa330b9f2220fc2cf3a53"
EXPECTED_TARGETS = ("0x9fc264d0", "0x9fc26594", "0x9fc26b64", "0x9fc26ca4", "0x9fc280e4", "0x9fc282b4", "0x9fc2c3bc")
EXPECTED_FAMILIES = ("ADRP", "LDR_UNSIGNED", "LOGICAL_OR_BITMASK_IMMEDIATE", "ADRP", "LOGICAL_OR_BITMASK_IMMEDIATE", "MOV_REGISTER", "LDP_STP_PAIR")

def _sha(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def _read_landing_word(image: Image, va: int) -> int:
    if va % 4:
        raise TraceError(f"landing VA is not instruction-aligned at 0x{va:08x}")
    return image.word(va)

def _read(path: Path, size: int, digest: str, label: str) -> bytes:
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as e: raise TraceError(f"cannot open exact {label}: {e}") from e
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size: raise TraceError(f"exact {label} size/type mismatch")
        data = b""; remain = size
        while remain:
            x = os.read(fd, min(1 << 20, remain))
            if not x: raise TraceError(f"exact {label} truncated during read")
            data += x; remain -= len(x)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns): raise TraceError(f"exact {label} changed during read")
    finally: os.close(fd)
    if _sha(data) != digest: raise TraceError(f"exact {label} SHA-256 mismatch")
    return data

def _dependency() -> dict[str, Any]:
    raw = _read(K_PATH, K_SIZE, K_SHA256, "020K manifest")
    if b"evidence/private" in raw: raise TraceError("020K manifest contains a private path")
    m = json.loads(raw)
    if m.get("schema") != k.SCHEMA or m.get("classification") != "CLASS C (TRANSFORM ONLY)" or m.get("eligibility") != "NOT_ELIGIBLE": raise TraceError("020K identity/classification changed")
    if m.get("census", {}).get("stop_count") != 12: raise TraceError("020K stop cardinality changed")
    return m

def _decode(word: int, va: int, image: Image) -> dict[str, Any]:
    if va % 4:
        raise TraceError(f"landing VA is not instruction-aligned at 0x{va:08x}")
    result: dict[str, Any] | None = None
    adrp = decode_adrp(word, va)
    if adrp is not None: result = {"family":"ADRP", "rd":adrp[0], "page":adrp[1]}
    ldr = decode_ldr_unsigned(word)
    if result is None and ldr is not None: result = {"family":"LDR_UNSIGNED", "width_bits":ldr[0], "rt":ldr[1], "rn":ldr[2], "imm12":ldr[3]}
    if result is None and k.decode_logical_immediate(word) is not None: result = k.decode_logical_immediate(word)
    mov = decode_mov_register(word)
    if result is None and mov is not None: result = {"family":"MOV_REGISTER", "width_bits":mov[0], "rn":mov[1], "rd":mov[2]}
    pair = k.decode_pair_memory(word)
    if result is None and pair is not None: result = pair
    if result is None: raise TraceError(f"unsupported landing word at 0x{va:08x}")
    seg = image.segment_for(va, 4)
    if seg is None or not seg.executable: raise TraceError(f"landing word is not executable at 0x{va:08x}")
    return result

def _build_manifest(firmware_dir: Path = k.FIRMWARE_DIR) -> dict[str, Any]:
    _read(K_TOOL_PATH, K_TOOL_SIZE, K_TOOL_SHA256, "020K tool source")
    _read(_ROOT / "tools" / DECODER_020D_NAME, DECODER_020D_SIZE, DECODER_020D_SHA256, "020D decoder source")
    _read(_ROOT / "tools" / DECODER_020F_NAME, DECODER_020F_SIZE, DECODER_020F_SHA256, "020F decoder source")
    dep = _dependency(); image = Image(_read(firmware_dir / XBL_NAME, XBL_SIZE, XBL_SHA256, "XBL firmware"))
    targets = sorted({r["operands"]["target_va"] for r in dep["census"]["stops"] if "target_va" in r.get("operands", {})}, key=lambda x:int(x,16))
    if targets != sorted(EXPECTED_TARGETS, key=lambda x:int(x,16)) or len(targets) != 7: raise TraceError("conditional target set changed")
    rows=[]
    for va_s in targets:
        va=int(va_s,16); word=_read_landing_word(image, va); decoded=_decode(word,va,image)
        rows.append({"target_va":va_s,"family":decoded["family"],"landing_word":decoded,"word_sha256":_sha(struct.pack("<I",word))})
    expected_by_va=dict(zip(EXPECTED_TARGETS, EXPECTED_FAMILIES))
    if any(r["family"] != expected_by_va[r["target_va"]] for r in rows): raise TraceError("landing family changed")
    return {"schema":SCHEMA,"experiment_id":EXPERIMENT_ID,"mode":MODE,"device_access":"none","classification":"CLASS C (TRANSFORM ONLY)","eligibility":"NOT_ELIGIBLE","inputs":{"firmware":{"filename":XBL_NAME,"size":XBL_SIZE,"sha256":XBL_SHA256},"dependency_020k_manifest":{"filename":K_NAME,"size":K_SIZE,"sha256":K_SHA256},"dependency_020k_tool":{"filename":K_TOOL_NAME,"size":K_TOOL_SIZE,"sha256":K_TOOL_SHA256}},"census":{"target_count":7,"unique_target_va_count":7,"targets":rows,"status":"SUPPORTED_BOUNDED_LANDING_WORD_INVENTORY"},"scope":{"inspect_one_word_per_unique_conditional_target":True,"landing_va_alignment":"va % 4 == 0 before word read/decode","raw_word_values":"REDACTED_HASH_ONLY","same_executable_segment":True,"no_trace_past_landing_word":True,"runtime_execution":"UNKNOWN","physical_mmio_dram_identity":"UNKNOWN"},"claims":{"PROVED":["Exact XBL, 020K source and public manifest are size/hash pinned.","Exactly seven unique conditional target VAs are inspected once with strict family/operand decoding and executable-segment checks."],"SUPPORTED":["Landing words are finite ADRP/LDR/logical/MOV/pair shapes."],"HYPOTHESIS":[],"REFUTED":[],"UNKNOWN":["Execution, data-flow, function boundaries, runtime values, pointer meaning, MMIO/DRAM identity, mutability, protected reach and bypass."]},"boundary_bypass":{"status":"NOT_AUTHORIZED","device":"none","smc":"none","mmio":"none","protected_memory":"none","reason":"Host-only one-word static inventory."},"definition_of_done":{"target":{"binding":"PROVED_EXACT_XBL_INPUT_HASH","marketing_name":"A90 5G","model":"SM-A908N","soc":"SM8150"},"build":{"status":"NOT_APPLICABLE"},"timestamp":{"status":"NOT_APPLICABLE"},"device_binding":{"status":"NOT_APPLICABLE","reason":"No device contact."}}}

def build_manifest(firmware_dir: Path = k.FIRMWARE_DIR) -> dict[str, Any]:
    manifest = _build_manifest(firmware_dir)
    manifest["inputs"]["decoder_020d_source"] = {"filename": DECODER_020D_NAME, "size": DECODER_020D_SIZE, "sha256": DECODER_020D_SHA256}
    manifest["inputs"]["decoder_020f_source"] = {"filename": DECODER_020F_NAME, "size": DECODER_020F_SIZE, "sha256": DECODER_020F_SHA256}
    return manifest

def encode_manifest(m: dict[str,Any]) -> bytes: return (json.dumps(m,indent=1,sort_keys=True)+"\n").encode()
def main(argv: Sequence[str]|None=None)->int:
    p=argparse.ArgumentParser(); p.add_argument("--firmware-dir",type=Path,default=k.FIRMWARE_DIR); p.add_argument("--output",type=Path,required=True); a=p.parse_args(argv)
    try: pub=write_no_clobber(a.output,encode_manifest(build_manifest(a.firmware_dir)))
    except (TraceError,OSError,ValueError,json.JSONDecodeError) as e: print(f"020L: {e}",file=sys.stderr); return 2
    print(f"wrote {pub['basename']} {pub['size_bytes']} bytes sha256={pub['sha256']} mode={pub['mode']}"); return 0
if __name__ == "__main__": raise SystemExit(main())
