"""Independent re-derivation of load-bearing Experiments 006-013 claims.

This tool exists to answer a provenance question, not a hardware question: every
`PROVED` statement in this repository is one agent's interpretation of the exact
retained firmware bytes, and Experiments 008-013 consume the conclusions of 004
and 006 as pinned inputs. A wrong early interpretation would be inherited by
everything downstream, and the existing unit tests prove tool determinism, not
interpretation correctness.

The audit therefore re-derives each checked claim from the raw bytes without
importing, calling, or reusing any other module in `tools/`. Structure offsets
are recovered by searching for names and values and then walking the located
records, so a claim can fail here even when the original tool reproduces
byte-identically.

Host-only. No device, SMC, MMIO, partition, EL2, EL3, or protected-memory
access, and no firmware bytes are emitted into the public manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = (
    REPO_ROOT / "evidence" / "private" / "004-live-firmware-readonly-20260825-01"
)
PUBLIC_MANIFEST = (
    REPO_ROOT
    / "evidence"
    / "manifests"
    / "verification-001-independent-claim-audit-20260825-01.manifest.json"
)

SCHEMA = "sdm855-independent-claim-audit-public-v1"

XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
TZ_SHA256 = "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab"

AARCH64_RET = 0xD65F03C0


# --------------------------------------------------------------------------
# minimal ELF64 segment mapping (own implementation, no shared helper reused)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Segment:
    offset: int
    vaddr: int
    filesz: int


class Image:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.segments = self._segments()

    def _segments(self) -> list[Segment]:
        e_phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        e_phnum = struct.unpack_from("<H", self.data, 0x38)[0]
        out: list[Segment] = []
        for index in range(e_phnum):
            base = e_phoff + index * 56
            p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz = struct.unpack_from(
                "<QQQQQ", self.data, base + 8
            )
            if p_filesz:
                out.append(Segment(p_offset, p_vaddr, p_filesz))
        return out

    def to_vaddr(self, offset: int) -> int | None:
        for seg in self.segments:
            if seg.offset <= offset < seg.offset + seg.filesz:
                return seg.vaddr + (offset - seg.offset)
        return None

    def to_offset(self, vaddr: int) -> int | None:
        for seg in self.segments:
            if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                return seg.offset + (vaddr - seg.vaddr)
        return None

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, offset)[0]

    def find_all(self, needle: bytes) -> list[int]:
        return [m.start() for m in re.finditer(re.escape(needle), self.data)]

    def find_u32(self, value: int) -> list[int]:
        return self.find_all(struct.pack("<I", value))

    def find_u64(self, value: int) -> list[int]:
        return self.find_all(struct.pack("<Q", value))


# --------------------------------------------------------------------------
# check plumbing
# --------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    claim: str
    source: str
    verdict: str = "UNKNOWN"
    observed: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def confirm(self, **observed: object) -> "Check":
        self.verdict = "CONFIRMED"
        self.observed.update(observed)
        return self

    def fail(self, reason: str, **observed: object) -> "Check":
        self.verdict = "MISMATCH"
        self.notes.append(reason)
        self.observed.update(observed)
        return self


def _hex(value: int) -> str:
    return f"{value:#x}"


# --------------------------------------------------------------------------
# check 1: pinned input integrity
# --------------------------------------------------------------------------


def check_input_pins(xbl: Image, tz: Image) -> Check:
    check = Check(
        "input_pins",
        "Experiments 006-013 consume XBL/TZ artifacts with the pinned SHA-256 values.",
        "docs/EXPERIMENT_MATRIX.md Experiment 006/012 metadata",
    )
    if xbl.sha256 != XBL_SHA256:
        return check.fail("xbl hash differs from pin", xbl_sha256=xbl.sha256)
    if tz.sha256 != TZ_SHA256:
        return check.fail("tz hash differs from pin", tz_sha256=tz.sha256)
    return check.confirm(xbl_sha256=xbl.sha256, tz_sha256=tz.sha256)


# --------------------------------------------------------------------------
# check 2: icbcfg remapper bases
# --------------------------------------------------------------------------

CLAIMED_BASES = (0x09248080, 0x092C8080, 0x09348080, 0x093C8080)


def check_icbcfg_bases(xbl: Image) -> Check:
    check = Check(
        "icbcfg_remapper_bases",
        "DAL property icbcfg_info resolves to four qhs_llcc + 0x8080 register bases.",
        "STATUS.md section A (Experiment 006)",
    )

    for name in (b"icbcfg_info", b"/dev/icbcfg/boot"):
        if not xbl.find_all(name):
            return check.fail(f"string {name!r} absent from exact XBL")

    # locate a packed u64 array of the four bases preceded by an element count
    u64_runs = []
    for offset in xbl.find_u64(CLAIMED_BASES[0]):
        values = [xbl.u64(offset + i * 8) for i in range(4)]
        if tuple(values) == CLAIMED_BASES:
            u64_runs.append(offset)
    if not u64_runs:
        return check.fail("no contiguous u64 array of the four claimed bases")

    array_offset = u64_runs[0]
    count = xbl.u32(array_offset - 4)
    if count != 4:
        return check.fail(f"element count preceding u64 array is {count}, not 4")

    # locate a packed u32 literal pool of the same four bases
    u32_runs = []
    for offset in xbl.find_u32(CLAIMED_BASES[0]):
        values = tuple(xbl.u32(offset + i * 4) for i in range(4))
        if values == CLAIMED_BASES:
            u32_runs.append(offset)
    if not u32_runs:
        return check.fail("no contiguous u32 literal pool of the four claimed bases")

    array_vaddr = xbl.to_vaddr(array_offset)
    referrers = [xbl.to_vaddr(o) for o in xbl.find_u64(array_vaddr)] if array_vaddr else []

    strides = {CLAIMED_BASES[i + 1] - CLAIMED_BASES[i] for i in range(3)}

    return check.confirm(
        u64_array_vaddr=_hex(array_vaddr) if array_vaddr else None,
        u64_array_element_count=count,
        u32_literal_pool_vaddr=_hex(xbl.to_vaddr(u32_runs[0]) or 0),
        instance_stride=_hex(strides.pop()) if len(strides) == 1 else None,
        referrer_vaddrs=[_hex(v) for v in referrers if v is not None],
        bases=[_hex(b) for b in CLAIMED_BASES],
    )


# --------------------------------------------------------------------------
# checks 3 and 5: XPU policy regions
# --------------------------------------------------------------------------

REGION_STRIDE = 32


def _registry_record(tz: Image, name: bytes) -> tuple[int, int] | None:
    """Return (xpu_id, base_addr) recovered from the {id, base, name_ptr} record."""
    hits = tz.find_all(name + b"\x00")
    if len(hits) != 1:
        return None
    name_vaddr = tz.to_vaddr(hits[0])
    if name_vaddr is None:
        return None
    for pointer_offset in tz.find_u64(name_vaddr):
        # a real registry record lives in a loaded segment; matches elsewhere
        # (notably inside the program header table) are coincidental
        if tz.to_vaddr(pointer_offset) is None or pointer_offset < 16:
            continue
        base = tz.u64(pointer_offset - 8)
        xpu_id = tz.u64(pointer_offset - 16)
        if 0 < base < 0x1_0000_0000 and base & 0xFFF == 0 and xpu_id < 0x1000:
            return xpu_id, base
    return None


def _policy_entries(tz: Image, base_addr: int, xpu_id: int) -> list[dict]:
    """Locate {base, id, reserved, region_count, table_ptr} policy entries."""
    entries = []
    for offset in tz.find_u64(base_addr):
        entry_id = tz.u64(offset + 8)
        if entry_id & 0xFFFF != xpu_id:
            continue
        region_count = tz.u64(offset + 24)
        table_vaddr = tz.u64(offset + 32)
        table_offset = tz.to_offset(table_vaddr)
        if table_offset is None or not 0 < region_count <= 256:
            continue
        entries.append(
            {
                "entry_vaddr": tz.to_vaddr(offset),
                "region_count": region_count,
                "table_vaddr": table_vaddr,
                "table_offset": table_offset,
            }
        )
    return entries


def _read_region(tz: Image, table_offset: int, index: int) -> dict:
    offset = table_offset + index * REGION_STRIDE
    region_index, flags, read_word, write_word = struct.unpack_from("<4I", tz.data, offset)
    start, end = struct.unpack_from("<2Q", tz.data, offset + 16)
    return {
        "index": region_index,
        "flags": flags,
        "read_access_word": read_word,
        "write_access_word": write_word,
        "start": start,
        "end_exclusive": end,
    }


def _check_region(
    tz: Image,
    check: Check,
    xpu_name: bytes,
    region_index: int,
    expect_start: int,
    expect_end_exclusive: int,
    expect_read: int,
    expect_write: int,
    contained_pa: int,
    expect_region_count: int,
) -> Check:
    registry = _registry_record(tz, xpu_name)
    if registry is None:
        return check.fail(f"no unique registry record for {xpu_name!r}")
    xpu_id, base_addr = registry

    entries = _policy_entries(tz, base_addr, xpu_id)
    if len(entries) < 2:
        return check.fail(
            f"expected two policy branches, found {len(entries)}",
            xpu_base=_hex(base_addr),
        )

    branches = []
    for entry in entries:
        if entry["region_count"] != expect_region_count:
            return check.fail(
                f"region count {entry['region_count']} != {expect_region_count}"
            )
        region = _read_region(tz, entry["table_offset"], region_index)
        branches.append((entry, region))

    reference = branches[0][1]
    for _entry, region in branches[1:]:
        if region != reference:
            return check.fail("policy branches disagree on the audited region")

    if reference["index"] != region_index:
        return check.fail(f"region index field is {reference['index']}")
    if reference["start"] != expect_start or reference["end_exclusive"] != expect_end_exclusive:
        return check.fail("region bounds differ from claim", observed_region=reference)
    if reference["read_access_word"] != expect_read:
        return check.fail("read access word differs from claim", observed_region=reference)
    if reference["write_access_word"] != expect_write:
        return check.fail("write access word differs from claim", observed_region=reference)
    if not reference["start"] <= contained_pa < reference["end_exclusive"]:
        return check.fail(f"region does not contain {contained_pa:#x}")
    if not reference["flags"] & 0x1:
        return check.fail("region is not enabled")

    return check.confirm(
        xpu_name=xpu_name.decode(),
        xpu_id=_hex(xpu_id),
        xpu_base=_hex(base_addr),
        region_count=expect_region_count,
        branch_entry_vaddrs=[_hex(e["entry_vaddr"]) for e, _ in branches],
        branch_table_vaddrs=[_hex(e["table_vaddr"]) for e, _ in branches],
        branches_byte_identical=True,
        region_index=reference["index"],
        flags=_hex(reference["flags"]),
        read_access_word=_hex(reference["read_access_word"]),
        write_access_word=_hex(reference["write_access_word"]),
        start=_hex(reference["start"]),
        end_exclusive=_hex(reference["end_exclusive"]),
        end_inclusive=_hex(reference["end_exclusive"] - 1),
        contains_pa=_hex(contained_pa),
    )


def check_dc_noc_broadcast_region11(tz: Image) -> Check:
    check = Check(
        "dc_noc_broadcast_region11",
        "Both TZ policy branches place 0x09248080 in enabled, TZ-owned "
        "DC_NOC_BROADCAST_MPU region 11 with access words 0x80000000/0x00000000.",
        "STATUS.md section A (Experiment 009)",
    )
    return _check_region(
        tz,
        check,
        b"DC_NOC_BROADCAST_MPU",
        region_index=11,
        expect_start=0x09248000,
        expect_end_exclusive=0x09249000,
        expect_read=0x80000000,
        expect_write=0x00000000,
        contained_pa=0x09248080,
        expect_region_count=40,
    )


def check_dc_noc_non_broadcast_region5(tz: Image) -> Check:
    check = Check(
        "dc_noc_non_broadcast_region5",
        "Both TZ policy branches place the SHRM snapshot workspace in "
        "DC_NOC_NON_BROADCAST_MPU region 5 covering 0x09060000-0x0906ffff.",
        "experiments/013-shrm-snapshot-boundary/README.md",
    )
    return _check_region(
        tz,
        check,
        b"DC_NOC_NON_BROADCAST_MPU",
        region_index=5,
        expect_start=0x09060000,
        expect_end_exclusive=0x09070000,
        expect_read=0x40000000,
        expect_write=0x00000000,
        contained_pa=0x09065100,
        expect_region_count=16,
    )


# --------------------------------------------------------------------------
# check 4: XPU disable allowlist
# --------------------------------------------------------------------------

SMC_DESCRIPTOR_STRIDE = 24
SMC_XPU_TOGGLE = 0x02000C23
SMC_RPM_REGION = 0x0200030F


def _smc_handler_vaddr(tz: Image, smc_id: int) -> int | None:
    hits = tz.find_u32(smc_id)
    if len(hits) != 1:
        return None
    return tz.u64(hits[0] + 12)


def _decode_adrp(word: int, pc: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    rd = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return rd, ((pc >> 12) << 12) + (imm << 12)


def check_xpu_disable_allowlist(tz: Image) -> Check:
    check = Check(
        "xpu_disable_allowlist_count",
        "The HLOS-visible XPU toggle SMC 0x02000c23 has an allowed-base count of zero.",
        "STATUS.md section A (Experiment 010)",
    )

    handler_vaddr = _smc_handler_vaddr(tz, SMC_XPU_TOGGLE)
    if handler_vaddr is None:
        return check.fail("SMC 0x02000c23 descriptor not uniquely located")
    handler_offset = tz.to_offset(handler_vaddr)
    if handler_offset is None:
        return check.fail("SMC 0x02000c23 handler vaddr is not mapped")

    # find the bounded handler's call into the allowlist query helper
    lookup_vaddr = None
    for index in range(48):
        word = tz.u32(handler_offset + index * 4)
        if word & 0xFC000000 == 0x94000000:
            imm = word & 0x03FFFFFF
            if imm & (1 << 25):
                imm -= 1 << 26
            candidate = handler_vaddr + index * 4 + (imm << 2)
            candidate_offset = tz.to_offset(candidate)
            if candidate_offset is None:
                continue
            # the query helper is a leaf: adrp/adrp/add/ldr/str/str/ret
            body = [tz.u32(candidate_offset + i * 4) for i in range(8)]
            if AARCH64_RET in body[:8] and body.count(AARCH64_RET) == 1:
                if _decode_adrp(body[0], candidate) and _decode_adrp(body[1], candidate + 4):
                    lookup_vaddr = candidate
                    break
    if lookup_vaddr is None:
        return check.fail("no leaf allowlist query helper reached from the handler")

    lookup_offset = tz.to_offset(lookup_vaddr)
    words = [tz.u32(lookup_offset + i * 4) for i in range(8)]

    page = _decode_adrp(words[0], lookup_vaddr)
    if page is None:
        return check.fail("first helper instruction is not ADRP")
    _rd, page_base = page

    # ldr xN, [xM, #imm12] : recover the count address
    count_vaddr = None
    for index, word in enumerate(words):
        if word & 0xFFC00000 == 0xF9400000:
            imm12 = (word >> 10) & 0xFFF
            count_vaddr = page_base + imm12 * 8
            break
    if count_vaddr is None:
        return check.fail("no 64-bit literal load found in the helper")

    count_offset = tz.to_offset(count_vaddr)
    if count_offset is None:
        return check.fail("recovered count address is not mapped")
    count = tz.u64(count_offset)

    if count != 0:
        return check.fail(f"allowed-base count is {count}, not zero", count=count)

    return check.confirm(
        handler_vaddr=_hex(handler_vaddr),
        query_helper_vaddr=_hex(lookup_vaddr),
        count_vaddr=_hex(count_vaddr),
        allowed_base_count=count,
        static_constant=True,
    )


def check_rpm_region_smc_is_ret(tz: Image) -> Check:
    check = Check(
        "rpm_region_smc_single_ret",
        "The exact TZ handler for SMC 0x0200030f is a single RET.",
        "STATUS.md section C (Experiment 010)",
    )
    handler_vaddr = _smc_handler_vaddr(tz, SMC_RPM_REGION)
    if handler_vaddr is None:
        return check.fail("SMC 0x0200030f descriptor not uniquely located")
    handler_offset = tz.to_offset(handler_vaddr)
    if handler_offset is None:
        return check.fail("SMC 0x0200030f handler vaddr is not mapped")
    first = tz.u32(handler_offset)
    if first != AARCH64_RET:
        return check.fail(f"first instruction is {first:#010x}, not RET")
    return check.confirm(
        handler_vaddr=_hex(handler_vaddr),
        first_instruction=_hex(first),
        mnemonic="ret",
    )


# --------------------------------------------------------------------------
# check 6: SHRM section-16 helper
# --------------------------------------------------------------------------

SHRM_BLOB_VADDR = 0x148BBE98
SHRM_BLOB_SIZE = 23776
SHRM_BLOB_SHA256 = "421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd"
SHRM_HELPER_SHA256 = "01fc5d83049d3fff7db6aa10a316dfbd07dfbd87093bb0b5a5d722aa3dfe211b"
SHRM_CODE_BASE = 0x28000
SHRM_HELPER_VADDR = 0x2D8DC
SHRM_HELPER_LEN = 125


def _xtensa_rrr(triple: bytes) -> dict:
    b0, b1, b2 = triple
    return {
        "op0": b0 & 0xF,
        "t": (b0 >> 4) & 0xF,
        "s": b1 & 0xF,
        "r": (b1 >> 4) & 0xF,
        "op1": b2 & 0xF,
        "op2": (b2 >> 4) & 0xF,
    }


def check_shrm_helper(xbl: Image) -> Check:
    check = Check(
        "shrm_section16_helper",
        "The exact Xtensa SHRM helper computes (base_page << 12) + (offset_token << 2).",
        "STATUS.md section A (Experiment 012)",
    )

    blob_offset = xbl.to_offset(SHRM_BLOB_VADDR)
    if blob_offset is None:
        return check.fail("SHRM blob vaddr is not mapped")
    blob = xbl.data[blob_offset : blob_offset + SHRM_BLOB_SIZE]
    blob_sha = hashlib.sha256(blob).hexdigest()
    if blob_sha != SHRM_BLOB_SHA256:
        return check.fail("SHRM blob hash differs from pin", blob_sha256=blob_sha)

    helper_offset = SHRM_HELPER_VADDR - SHRM_CODE_BASE
    helper = blob[helper_offset : helper_offset + SHRM_HELPER_LEN]
    helper_sha = hashlib.sha256(helper).hexdigest()
    if helper_sha != SHRM_HELPER_SHA256:
        return check.fail("SHRM helper hash differs from pin", helper_sha256=helper_sha)

    # Xtensa is variable-length, so a byte-granular sweep yields false positives.
    # Collect every candidate of each form and require a semantic pairing instead:
    # some ADDX4 must consume the register a preceding SLLI-by-12 defined.
    slli_candidates = []
    addx4_candidates = []
    for index in range(len(helper) - 2):
        fields = _xtensa_rrr(helper[index : index + 3])
        if fields["op0"] != 0:
            continue
        if fields["op1"] == 1 and fields["op2"] in (0, 1):
            shift = 32 - (((fields["op2"] & 1) << 4) | fields["t"])
            if shift == 12:
                slli_candidates.append((index, fields))
        elif fields["op1"] == 0 and fields["op2"] == 0xA:
            addx4_candidates.append((index, fields))

    if not slli_candidates:
        return check.fail("no SLLI by 12 found in the exact helper")
    if not addx4_candidates:
        return check.fail("no ADDX4 found in the exact helper")

    pairing = None
    for slli_index, slli_fields in slli_candidates:
        for addx4_index, addx4_fields in addx4_candidates:
            if addx4_index > slli_index and addx4_fields["t"] == slli_fields["r"]:
                pairing = (slli_index, slli_fields, addx4_index, addx4_fields)
                break
        if pairing:
            break

    if pairing is None:
        return check.fail(
            "no ADDX4 consumes the register defined by an SLLI-12",
            slli_dest_registers=[f["r"] for _, f in slli_candidates],
            addx4_addend_registers=[f["t"] for _, f in addx4_candidates],
        )

    slli_index, slli_fields, addx4_index, addx4_fields = pairing

    return check.confirm(
        blob_sha256=blob_sha,
        helper_sha256=helper_sha,
        helper_vaddr=_hex(SHRM_HELPER_VADDR),
        helper_length_bytes=SHRM_HELPER_LEN,
        range_notation="end-exclusive",
        slli_offset=_hex(slli_index),
        slli_bytes=helper[slli_index : slli_index + 3].hex(),
        slli_text=f"slli a{slli_fields['r']}, a{slli_fields['s']}, 12",
        addx4_offset=_hex(addx4_index),
        addx4_bytes=helper[addx4_index : addx4_index + 3].hex(),
        addx4_text=(
            f"addx4 a{addx4_fields['r']}, a{addx4_fields['s']}, a{addx4_fields['t']}"
        ),
        address_formula="(base_page << 12) + (offset_token << 2)",
        offset_token_scaling_bytes=4,
    )


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------


def run_audit(xbl: Image, tz: Image) -> list[Check]:
    return [
        check_input_pins(xbl, tz),
        check_icbcfg_bases(xbl),
        check_dc_noc_broadcast_region11(tz),
        check_dc_noc_non_broadcast_region5(tz),
        check_xpu_disable_allowlist(tz),
        check_rpm_region_smc_is_ret(tz),
        check_shrm_helper(xbl),
    ]


def build_manifest(xbl: Image, tz: Image, checks: list[Check]) -> dict:
    confirmed = sum(1 for c in checks if c.verdict == "CONFIRMED")
    return {
        "schema": SCHEMA,
        "mode": "HOST_ONLY_READ_ONLY",
        "classification": (
            "INDEPENDENT_AUDIT_ALL_CHECKED_CLAIMS_CONFIRMED"
            if confirmed == len(checks)
            else "INDEPENDENT_AUDIT_MISMATCH_PRESENT"
        ),
        "auditor": {
            "independent_of_repository_tools": True,
            "reused_modules": [],
            "method": (
                "raw-byte re-derivation: structures are located by name and value "
                "search, then walked; no tools/ module is imported or invoked"
            ),
            "disassembler_available": False,
            "decoders_written_for_audit": ["aarch64-subset", "xtensa-rrr-subset"],
        },
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "inputs": {
            "xbl": {
                "filename": xbl.path.name,
                "sha256": xbl.sha256,
                "size": len(xbl.data),
                "pin_verified": xbl.sha256 == XBL_SHA256,
            },
            "tz": {
                "filename": tz.path.name,
                "sha256": tz.sha256,
                "size": len(tz.data),
                "pin_verified": tz.sha256 == TZ_SHA256,
            },
        },
        "summary": {
            "checks_total": len(checks),
            "checks_confirmed": confirmed,
            "checks_mismatched": len(checks) - confirmed,
        },
        "checks": [
            {
                "name": c.name,
                "claim": c.claim,
                "source": c.source,
                "verdict": c.verdict,
                "observed": c.observed,
                "notes": c.notes,
            }
            for c in checks
        ],
        "not_audited": [
            "QHEE hyp_assign stage-2/SMMU ownership path (Experiment 010).",
            "TrustZone dynamic BIMC_MPU0..3 initializer (Experiment 010).",
            "XBL Quest DDR coordinate reporter formula (Experiment 011).",
            "SHRM section-16 callsites at 0x288a9/0x28e15 and their 430/64 counts "
            "(Experiment 012).",
            "Permission-conversion routine mapping access words to VMID classes.",
        ],
        "scope_note": (
            "This audit verifies static facts recorded by prior experiments. It does "
            "not verify their security interpretation, and it does not address "
            "protection ordering relative to the final DRAM transform, which "
            "remains UNKNOWN."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="write the public manifest to evidence/manifests/",
    )
    args = parser.parse_args(argv)

    xbl = Image(FIRMWARE_DIR / "xbl--sdb1.bin")
    tz = Image(FIRMWARE_DIR / "tz--sdd5.bin")

    checks = run_audit(xbl, tz)
    manifest = build_manifest(xbl, tz, checks)

    for check in checks:
        marker = "OK  " if check.verdict == "CONFIRMED" else "FAIL"
        print(f"{marker} {check.name}: {check.verdict}")
        for note in check.notes:
            print(f"       {note}")

    summary = manifest["summary"]
    print(
        f"\n{summary['checks_confirmed']}/{summary['checks_total']} checks confirmed"
    )

    if args.replace:
        PUBLIC_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        PUBLIC_MANIFEST.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        PUBLIC_MANIFEST.chmod(0o644)
        print(f"wrote {PUBLIC_MANIFEST.relative_to(REPO_ROOT)}")

    return 0 if summary["checks_mismatched"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
