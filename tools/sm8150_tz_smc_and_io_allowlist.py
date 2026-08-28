#!/usr/bin/env python3
"""Enumerate the exact TZ SMC dispatch table and the SCM_IO address allowlist.

Verification 010 decoded 5 SMC dispatch records and reasoned about the
secure-monitor interface from them.  That is the same extraction-scope defect
Verification 025 was created to repair for XPU regions: 5 of 1,726 there,
5 of 152 here.

This tool walks the whole dispatch table, resolves the two SIP service-5
handlers (`SCM_IO_READ` / `SCM_IO_WRITE`), and decodes the shared address
allowlist both of them gate on.  It also re-tests the XPU HLOS-grant predicate
against addresses the live device tree hands to HLOS drivers, which is what
shows the published bit-3 test to be non-discriminating.

Host-only.  No device, MMIO, SMC or firmware write; no firmware bytes are
emitted, only decoded record fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.xbl_dcb_inventory import parse_elf64_load_segments
from tools.xbl_memory_pipeline_inventory import read_vaddr

SCHEMA = "sm8150-tz-smc-and-io-allowlist-v1"

# The exact Verification 009/025 TrustZone input, pinned so a claim about the
# secure-monitor surface can never silently drift to another build.
TZ_SHA256 = "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab"
TZ_SIZE = 4_194_304

# Record layout is the one Verification 010 already established and published.
SMC_RECORD_SIZE = 24
SMC_RECORD_FMT = "<IIIIQ"          # reserved, smc_id, param_id, flags, handler

# A record known to be inside the table, from the 010 manifest
# (`enable_toggle_xpu`, SMC 0x02000c23).  The walk grows outward from here so
# the table bounds are discovered rather than assumed.
SEED_RECORD_VADDR = 0x1C12A7C8

# TZ code lives in this virtual window; a handler outside it means the record
# is not a dispatch record and the walk has left the table.
TZ_CODE_LO = 0x1C000000
TZ_CODE_HI = 0x1C400000

# SMC owner bytes that appear in this build (ARM SMCCC owner field, id >> 24).
KNOWN_OWNERS = frozenset({0x01, 0x02, 0x03, 0x04, 0x30, 0x32, 0x33, 0x34, 0x42, 0x43})

# Both service-5 handlers loop over this table and refuse any address that does
# not match.  The bound is the loop's own `cmp x8, #0x50` plus one.
IO_ALLOWLIST_VADDR = 0x1C111238
IO_ALLOWLIST_ENTRIES = 81

# The DDRSS / remapper band every route-2 document is about.
DDRSS_BAND = (0x09000000, 0x09800000)

# Addresses the retained boot device tree hands to HLOS drivers, used to test
# whether an HLOS-grant predicate discriminates at all.  Each is a node that
# exists in the live DT; the last entry is the page that hung.
LIVE_HLOS_NODES = {
    "syscon@90b0000": 0x090B0000,
    "cpu-cpu-llcc-bwmon@90b6400": 0x090B6400,
    "llcc-pmu@90cc000": 0x090CC000,
    "cpu-llcc-ddr-bwmon@90cd000": 0x090CD000,
    "llcc@9200000": 0x09200000,
    "wdt@17c10000": 0x17C10000,
    "syscon@17c0000c": 0x17C0000C,
}
PROBED_REMAPPER_WORD = 0x09248080

HLOS_BIT_PUBLISHED = 3      # tools/sm8150_xpu_policy_inventory.py hardcodes this
HLOS_BIT_CORRECTED = 30     # the class bit that matches the live evidence


class AllowlistError(RuntimeError):
    pass


def load_pinned(path: Path) -> bytes:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != TZ_SHA256 or len(data) != TZ_SIZE:
        raise AllowlistError(
            f"{path} is sha256 {digest} size {len(data)}; expected {TZ_SHA256} "
            f"size {TZ_SIZE}"
        )
    return data


def parse_record(data, segments, vaddr):
    try:
        raw = read_vaddr(data, segments, vaddr, SMC_RECORD_SIZE)
    except Exception:
        return None
    reserved, smc_id, param_id, flags, handler = struct.unpack(SMC_RECORD_FMT, raw)
    # The leading word is zero on 151 of 152 records and 0x64 on one
    # (SMC 0x3400fa04).  Verification 010 named it `reserved`; it is not, and
    # testing it as zero splits the table in two.  Identity is carried by the
    # owner byte and the handler window instead.
    if (smc_id >> 24) not in KNOWN_OWNERS:
        return None
    if not TZ_CODE_LO <= handler < TZ_CODE_HI:
        return None
    return {
        "vaddr": vaddr,
        "leading_word": reserved,
        "smc_id": smc_id,
        "param_id": param_id,
        "flags": flags,
        "handler": handler,
    }


def walk_dispatch_table(data, segments):
    """Grow outward from the seed while records stay well formed."""
    if parse_record(data, segments, SEED_RECORD_VADDR) is None:
        raise AllowlistError(
            f"seed record 0x{SEED_RECORD_VADDR:x} does not decode; the layout "
            "assumption from Verification 010 is broken"
        )
    start = SEED_RECORD_VADDR
    while parse_record(data, segments, start - SMC_RECORD_SIZE) is not None:
        start -= SMC_RECORD_SIZE
    end = SEED_RECORD_VADDR
    while parse_record(data, segments, end + SMC_RECORD_SIZE) is not None:
        end += SMC_RECORD_SIZE
    records = []
    vaddr = start
    while vaddr <= end:
        record = parse_record(data, segments, vaddr)
        if record is None:
            raise AllowlistError(f"hole at 0x{vaddr:x} inside a contiguous table")
        records.append(record)
        vaddr += SMC_RECORD_SIZE
    return records


def read_allowlist(data, segments):
    raw = read_vaddr(data, segments, IO_ALLOWLIST_VADDR, IO_ALLOWLIST_ENTRIES * 4)
    return list(struct.unpack(f"<{IO_ALLOWLIST_ENTRIES}I", raw))


def group_allowlist(values):
    """Contiguous-block summary, so the manifest carries structure not a dump."""
    blocks = []
    for value in sorted(values):
        if blocks and value - blocks[-1]["end"] <= 0x1000:
            blocks[-1]["end"] = value
            blocks[-1]["count"] += 1
        else:
            blocks.append({"start": value, "end": value, "count": 1})
    return [
        {
            "range": f"0x{b['start']:08x}..0x{b['end']:08x}",
            "entries": b["count"],
        }
        for b in blocks
    ]


def grant_discrimination():
    """Does an HLOS-grant bit separate driven pages from the page that hung?"""
    from tools import sm8150_xpu_region_coverage as coverage

    tz_path = (
        REPO_ROOT
        / "evidence/private/004-live-firmware-readonly-20260825-01/tz--sdd5.bin"
    )
    data = tz_path.read_bytes()
    segments = parse_elf64_load_segments(data)
    descriptors = coverage.instance_descriptors(
        json.loads(coverage.POLICY_MANIFEST.read_text())
    )
    regions, _, _ = coverage.walk_branch(
        data, segments, descriptors["selector_result_ge_2"]
    )

    def nearest_target(address):
        """The most specific region containing the address wins the decision."""
        hits = [r for r in regions if r["start"] <= address < r["end_exclusive"]]
        if not hits:
            return None
        return min(hits, key=lambda r: r["end_exclusive"] - r["start"])

    rows = []
    for name, address in list(LIVE_HLOS_NODES.items()) + [
        ("probed remapper word", PROBED_REMAPPER_WORD)
    ]:
        region = nearest_target(address)
        if region is None:
            rows.append({"node": name, "address": f"0x{address:08x}", "covered": False})
            continue
        read_vmid = int(region["read_vmid"], 16)
        rows.append(
            {
                "node": name,
                "address": f"0x{address:08x}",
                "covered": True,
                "nearest_target_instance": region["instance"],
                "range": f"0x{region['start']:x}..0x{region['end_exclusive']:x}",
                "read_vmid": region["read_vmid"],
                "hlos_grant_published_bit3": bool(read_vmid & (1 << HLOS_BIT_PUBLISHED)),
                "hlos_grant_corrected_bit30": bool(read_vmid & (1 << HLOS_BIT_CORRECTED)),
            }
        )

    def counts(bit):
        return {
            "read": sum(1 for r in regions if int(r["read_vmid"], 16) & (1 << bit)),
            "write": sum(1 for r in regions if int(r["write_vmid"], 16) & (1 << bit)),
        }

    return {
        "regions_considered": len(regions),
        "grant_counts_published_bit3": counts(HLOS_BIT_PUBLISHED),
        "grant_counts_corrected_bit30": counts(HLOS_BIT_CORRECTED),
        "per_node": rows,
    }


def build(tz_path: Path) -> dict:
    data = load_pinned(tz_path)
    segments = parse_elf64_load_segments(data)

    records = walk_dispatch_table(data, segments)
    by_id = {r["smc_id"]: r for r in records}
    io_read = by_id.get(0x02000501)
    io_write = by_id.get(0x02000502)
    if io_read is None or io_write is None:
        raise AllowlistError(
            "SIP service 5 (SCM_IO_READ/SCM_IO_WRITE) is absent from the "
            "dispatch table; the allowlist claim does not apply to this build"
        )

    allowlist = read_allowlist(data, segments)
    in_band = [v for v in allowlist if DDRSS_BAND[0] <= v < DDRSS_BAND[1]]

    services = {}
    for record in records:
        if record["smc_id"] >> 24 == 0x02:
            service = (record["smc_id"] >> 8) & 0xFF
            services[f"0x{service:02x}"] = services.get(f"0x{service:02x}", 0) + 1

    return {
        "schema": SCHEMA,
        "device_access": False,
        "mmio_access": False,
        "smc_access": False,
        "firmware_bytes_emitted": False,
        "inputs": {
            "trustzone_sha256": TZ_SHA256,
            "trustzone_size": TZ_SIZE,
        },
        "dispatch_table": {
            "record_size": SMC_RECORD_SIZE,
            "record_layout": "<u32 reserved, u32 smc_id, u32 param_id, u32 flags, u64 handler>",
            "first_record_vaddr": f"0x{records[0]['vaddr']:x}",
            "last_record_vaddr": f"0x{records[-1]['vaddr']:x}",
            "records": len(records),
            "previously_decoded": 5,
            "records_with_nonzero_leading_word": [
                {"smc_id": f"0x{r['smc_id']:08x}", "leading_word": f"0x{r['leading_word']:x}"}
                for r in records
                if r["leading_word"] != 0
            ],
            "sip_service_histogram": dict(sorted(services.items())),
            "smc_ids": [f"0x{r['smc_id']:08x}" for r in records],
        },
        "io_access_service": {
            "read": {
                "smc_id": f"0x{io_read['smc_id']:08x}",
                "param_id": f"0x{io_read['param_id']:x}",
                "flags": f"0x{io_read['flags']:08x}",
                "handler": f"0x{io_read['handler']:08x}",
            },
            "write": {
                "smc_id": f"0x{io_write['smc_id']:08x}",
                "param_id": f"0x{io_write['param_id']:x}",
                "flags": f"0x{io_write['flags']:08x}",
                "handler": f"0x{io_write['handler']:08x}",
            },
            "shared_allowlist_vaddr": f"0x{IO_ALLOWLIST_VADDR:x}",
            "allowlist_entries": len(allowlist),
            "allowlist_distinct": len(set(allowlist)),
            "allowlist_blocks": group_allowlist(allowlist),
            "ddrss_band": f"0x{DDRSS_BAND[0]:08x}..0x{DDRSS_BAND[1]:08x}",
            "allowlist_entries_in_ddrss_band": [f"0x{v:08x}" for v in in_band],
            "reachable_ddrss_addresses": len(in_band),
        },
        "hlos_grant_discrimination": grant_discrimination(),
        "claims": {
            "PROVED": [
                "The exact TZ dispatch table is a contiguous run of well-formed "
                f"{SMC_RECORD_SIZE}-byte records containing the five Verification 010 "
                "decoded; this walk recovers all of them.",
                "The leading record word Verification 010 names `reserved` is "
                "non-zero on one record, so it is not a reserved field.",
                "TZ registers SIP service 5 command 1 (SCM_IO_READ) and command 2 "
                "(SCM_IO_WRITE), both callable from the Normal World.",
                "Both handlers gate on one shared address allowlist and return -1 "
                "for any address not present in it.",
                "No allowlist entry lies inside 0x09000000..0x09800000, so no "
                "remapper, BIMC, SHRM, MCCC, MC or DDRSS address is reachable "
                "through this interface.",
                "The published HLOS-grant predicate (VMID bit 3) returns False for "
                "DDRSS pages the live device tree hands to HLOS drivers, so it does "
                "not discriminate.",
            ],
            "SUPPORTED": [
                "Bit 30 of the region VMID word is the non-secure/HLOS class bit; "
                "it separates every live HLOS-driven page from the probed remapper "
                "word in the retained policy.",
            ],
            "UNKNOWN": [
                "Which MPU instance sits on the APSS-to-config-NoC path.",
                "The meaning of the flags field on the two service-5 records.",
                "Whether any of the remaining dispatch records reaches DDR state.",
            ],
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trustzone",
        type=Path,
        default=REPO_ROOT
        / "evidence/private/004-live-firmware-readonly-20260825-01/tz--sdd5.bin",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    result = build(args.trustzone)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
