#!/usr/bin/env python3
"""Qualify the exact A90 Samsung-upload ``SHRM_MEM.BIN`` acquisition.

This is deliberately a host-only evidence combiner.  It validates the raw
64-KiB dump against its pinned SHA-256 and the section-16 workspace header,
maps all 494 staged words back to their source register addresses through
``shrm_dump_decode``, and then decides which staged set is coherent enough to
use in subsequent research.

The public output contains bounded controller candidates and qualification
metrics, not the complete dump.  The private output retains every labelled
word and the exact host-journal excerpt.  No device, MMIO, SMC, or firmware
write is performed.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, Mapping, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools import shrm_dump_decode as decoder
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new  # type: ignore
    import shrm_dump_decode as decoder  # type: ignore


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_ID = "verification-012-a90-samsung-upload-shrm-20260825-01"
RAW_DUMP = (
    REPO_ROOT / "evidence/private" / EXPERIMENT_ID / "memory/SHRM_MEM.BIN"
)
RAW_SHA256 = "409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7"

SAMUPLOAD_SOURCE = REPO_ROOT / "evidence/private/host-tools/sboot_dump-src/samupload.py"
SAMUPLOAD_SHA256 = "7580a6c1aab8f03ecb8130d418b43d8f264c6926aa5f527ca8a213e4b523672c"
SAMUPLOAD_COMMIT = "8c9f6eb79ffbe702152ca7810f6382bf5e1bfd58"
SAMUPLOAD_URL = "https://github.com/bkerler/sboot_dump"

JOURNAL_SHA256 = "4b326be73287e38a90ff9e6cb1de0c3e756562b56f2804720465dc7302fbe177"
JOURNAL_MARKERS = (
    "idVendor=04e8, idProduct=685d",
    "Product: MSM_UPLOAD",
    "Manufacturer: Samsung",
    "USB disconnect, device number 17",
    "idVendor=04e8, idProduct=6861",
    "Product: A90 Linux ARM64",
    "Manufacturer: A90-LNX",
    "ttyACM0: USB ACM device",
)

EVIDENCE_PINS = {
    "xbl_export": {
        "filename": "verification-002-shrm-dump-export-20260825-01.manifest.json",
        "sha256": "7f35e4e6dd3ede0c1bc2f398d3148656ac95b948a257ad19e8ab6d030c20e635",
    },
    "xbl_gate": {
        "filename": "verification-005-xbl-rawdump-gate-static-20260825-01.manifest.json",
        "sha256": "5024b24ec72a715c2c23ef7f6600f80f9aefff5172f43f9ad4c74a7ed6a2916e",
    },
    "param_capture": {
        "filename": "verification-006-a90-param-capture-20260825-01.manifest.json",
        "sha256": "c9bc183871a37cc0166b4e6c29bde9a90d19be8f6410f00e7d1b28596a218993",
    },
    "mid_reboot": {
        "filename": "verification-010-a90-mid-normal-reboot-20260825-01.manifest.json",
        "sha256": "d466bf945c81f65fe8cbd529c3aebe11dcb3b231dba096ca9958928b20d19d44",
    },
    "sysrq_trigger": {
        "filename": "verification-011-a90-sysrq-crash-trigger-20260825-01.manifest.json",
        "sha256": "aa3ef26baaa77acd3b05f566eda66a1b01c13cd3b29b61b765d03afaefe013d8",
    },
    "qdl_capture": {
        "filename": "verification-011-a90-shrm-sahara-capture-20260825-01.manifest.json",
        "sha256": "bed07a93a54da162ecb7409b1dad5da94c7b4f8480cc9b08091dc6c56423f3bd",
    },
    "param_low_restore": {
        "filename": "verification-013-a90-param-debug-low-final-restore-20260825-01.manifest.json",
        "sha256": "81b734c2b75bcd18c2aeeca86bce9c61cada394b4e850b6ab2b78a16ea29f799",
    },
    "native_health": {
        "filename": "verification-013-a90-final-health-20260825-01.manifest.json",
        "sha256": "c27f307b25c3361414a3ef22d92c4fd164f648432d545e16f1dd15517e172d85",
    },
    "low_reboot": {
        "filename": "verification-014-a90-low-final-reboot-20260825-01.manifest.json",
        "sha256": "c3d7983e1ce76fbc137df4b877b1236f421906f4e64bb6e84183043c01fd1563",
    },
}

# The topology labels and addresses are exact Experiment-012 results.  The
# semantic purpose of these offsets is intentionally UNKNOWN.  Candidate rank
# means only "best next register to name/cross-check", never "proved hash
# register".
MC_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
MCCC_BASES = (0x09250000, 0x092D0000, 0x09350000, 0x093D0000)
CANDIDATES = (
    {
        "rank": 1,
        "block": "qhs_mc",
        "offset": 0x400,
        "bases": MC_BASES,
        "reason": "four-instance exact equality inside the MC aperture",
    },
    {
        "rank": 2,
        "block": "qhs_mc",
        "offset": 0x404,
        "bases": MC_BASES,
        "reason": "four-instance exact equality inside the MC aperture",
    },
    {
        "rank": 3,
        "block": "qhs_mccc",
        "offset": 0x118,
        "bases": MCCC_BASES,
        "reason": "four-instance exact equality inside the MCCC aperture",
    },
    {
        "rank": 4,
        "block": "qhs_mc",
        "offset": 0x4D0,
        "bases": MC_BASES,
        "reason": "stable two-by-two instance split inside the MC aperture",
    },
    {
        "rank": 5,
        "block": "qhs_mccc_master",
        "offset": 0x294,
        "bases": (0x090B0000,),
        "reason": "single master-side word paired with four MCCC instances",
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_sha(label: str, data: bytes, expected: str) -> None:
    actual = sha256(data)
    if actual != expected:
        raise ValueError(f"{label} SHA-256 {actual} != pinned {expected}")


def values(words: Iterable[decoder.StagedWord]) -> dict[int, int]:
    result: dict[int, int] = {}
    for word in words:
        if word.value is None:
            raise ValueError(f"decoded word {word.index} has no value")
        result[word.register] = word.value
    return result


def set_metrics(word_map: Mapping[int, int]) -> dict[str, object]:
    vals = list(word_map.values())
    return {
        "words": len(vals),
        "zero_words": sum(value == 0 for value in vals),
        "nonzero_words": sum(value != 0 for value in vals),
        "distinct_values": len(set(vals)),
        "all_values_distinct": len(set(vals)) == len(vals),
    }


def instance_offsets(word_map: Mapping[int, int], bases: Sequence[int]) -> list[int]:
    per_base = [
        {address - base for address in word_map if base <= address < base + 0x1000}
        for base in bases
    ]
    if not per_base:
        return []
    return sorted(set.intersection(*per_base))


def mc_symmetry(word_map: Mapping[int, int]) -> dict[str, object]:
    offsets = instance_offsets(word_map, MC_BASES)
    groups = [
        {
            "offset": f"0x{offset:03x}",
            "values": [f"0x{word_map[base + offset]:08x}" for base in MC_BASES],
            "distinct_values": len({word_map[base + offset] for base in MC_BASES}),
        }
        for offset in offsets
    ]
    return {
        "instance_bases": [f"0x{base:08x}" for base in MC_BASES],
        "common_offsets": len(offsets),
        "exactly_equal_groups": sum(group["distinct_values"] == 1 for group in groups),
        "two_value_groups": sum(group["distinct_values"] == 2 for group in groups),
        "four_value_groups": sum(group["distinct_values"] == 4 for group in groups),
        "groups": groups,
    }


def overlap_metrics(first: Mapping[int, int], second: Mapping[int, int]) -> dict[str, object]:
    common = sorted(first.keys() & second.keys())
    matches = [address for address in common if first[address] == second[address]]
    return {
        "common_registers": len(common),
        "equal_values": len(matches),
        "different_values": len(common) - len(matches),
        "registers": [f"0x{address:08x}" for address in common],
    }


def candidate_inventory(word_map: Mapping[int, int]) -> list[dict[str, object]]:
    result = []
    for item in CANDIDATES:
        offset = int(item["offset"])
        bases = tuple(int(base) for base in item["bases"])
        addresses = [base + offset for base in bases]
        missing = [address for address in addresses if address not in word_map]
        if missing:
            raise ValueError(
                f"candidate rank {item['rank']} missing "
                + ", ".join(f"0x{address:08x}" for address in missing)
            )
        vals = [word_map[address] for address in addresses]
        result.append(
            {
                "rank": item["rank"],
                "block": item["block"],
                "relative_offset": f"0x{offset:03x}",
                "addresses": [f"0x{address:08x}" for address in addresses],
                "values": [f"0x{value:08x}" for value in vals],
                "distinct_values": len(set(vals)),
                "semantic_name": "UNKNOWN",
                "transform_role": "HYPOTHESIS_NOT_PROVED",
                "ranking_reason": item["reason"],
            }
        )
    return result


def validate_journal(data: bytes) -> list[str]:
    require_sha("host kernel journal excerpt", data, JOURNAL_SHA256)
    text = data.decode("utf-8", errors="strict")
    lines = text.splitlines()
    if len(lines) != len(JOURNAL_MARKERS):
        raise ValueError(f"journal line count {len(lines)} != {len(JOURNAL_MARKERS)}")
    for line, marker in zip(lines, JOURNAL_MARKERS):
        if marker not in line:
            raise ValueError(f"journal line lacks ordered marker {marker!r}: {line!r}")
    if any("SerialNumber" in line for line in lines):
        raise ValueError("journal excerpt contains a device serial")
    return lines


def load_evidence_chain() -> dict[str, object]:
    manifest_dir = REPO_ROOT / "evidence/manifests"
    result: dict[str, object] = {}
    for label, pin in EVIDENCE_PINS.items():
        path = manifest_dir / str(pin["filename"])
        data = path.read_bytes()
        require_sha(label, data, str(pin["sha256"]))
        result[label] = json.loads(data)

    export = result["xbl_export"]
    gate = result["xbl_gate"]
    capture = result["param_capture"]
    mid_reboot = result["mid_reboot"]
    trigger = result["sysrq_trigger"]
    qdl = result["qdl_capture"]
    restore = result["param_low_restore"]
    health = result["native_health"]
    reboot = result["low_reboot"]
    if export["classification"] != "BOOTLOADER_RAWDUMP_EXPORT_PRESENT_HLOS_RUNTIME_EXPORT_UNPROVED":
        raise ValueError("static XBL export descriptor is not proved")
    if gate["classification"] != "DEBUG_ONLY_SUFFICIENT_WHEN_OUTER_DUMP_TRIGGER_PRESENT":
        raise ValueError("exact XBL debug-only gate classification changed")
    if capture["classification"] != "PARAM_CAPTURED_DEBUG_ONLY_PRECONDITIONS_MET":
        raise ValueError("initial param capture is not qualified")
    captured_fields = capture["decoded_gate_fields"]
    expected_captured = {
        "debuglevel": "0x574f4c44",
        "force_upload_flag": "0x00000000",
        "FMM_lock": "0x00000000",
        "dump_sink": "0x00000000",
    }
    for key, value in expected_captured.items():
        if captured_fields[key]["value"] != value:
            raise ValueError(f"initial param {key} changed")
    if mid_reboot["classification"] != "NEW_BOOT_PROVED":
        raise ValueError("MID reboot is not proved")
    if mid_reboot["post_boot"]["debug_level"] != "0x494d":
        raise ValueError("MID reboot did not consume MID")
    if trigger["classification"] != "CRASH_DISPATCHED_NO_REPLAY":
        raise ValueError("SysRq trigger classification changed")
    if trigger["effect_dispatched_count"] != 1 or trigger["effect_replayed"] is not False:
        raise ValueError("SysRq trigger is not exactly-once/no-replay")
    if qdl["classification"] != "NO_SHRM_DUMP_CAPTURED":
        raise ValueError("qdl negative classification changed")
    if qdl["dump_files"] != [] or qdl["dump"]["filename"] is not None:
        raise ValueError("qdl negative unexpectedly contains a dump")
    if restore["classification"] != "RESTORED_VERIFIED":
        raise ValueError("final param restore is not verified")
    if restore["transition"]["after_label"] != "LOW":
        raise ValueError("final param transition is not LOW")
    if health["selftest"]["fail"] != 0:
        raise ValueError("final native health has a failure")
    if reboot["classification"] != "NEW_BOOT_PROVED":
        raise ValueError("final LOW reboot is not proved")
    post = reboot["post_boot"]
    expected = {
        "debug_level": "0x4f4c",
        "force_upload": "0x0",
        "dump_sink": "0x0",
        "download_mode": "1",
    }
    for key, value in expected.items():
        if post.get(key) != value:
            raise ValueError(f"final LOW reboot {key}={post.get(key)!r} != {value!r}")
    if post["selftest"]["fail"] != 0:
        raise ValueError("final LOW reboot selftest has a failure")
    return result


def analyze(
    dump_data: bytes,
    samupload_data: bytes,
    journal_data: bytes,
) -> tuple[dict[str, object], dict[str, object]]:
    require_sha("SHRM_MEM.BIN", dump_data, RAW_SHA256)
    require_sha("samupload.py", samupload_data, SAMUPLOAD_SHA256)
    journal_lines = validate_journal(journal_data)
    evidence_chain = load_evidence_chain()

    decoded = decoder.decode(dump_data)
    if [item.count for item in decoded] != [430, 64]:
        raise ValueError("decoded set shape is not 430 + 64")
    maps = [values(item.words) for item in decoded]
    set0_metrics = set_metrics(maps[0])
    set1_metrics = set_metrics(maps[1])
    set0_mc = mc_symmetry(maps[0])
    set1_mc = mc_symmetry(maps[1])
    overlap = overlap_metrics(maps[0], maps[1])

    # This is an evidence qualification, not an assumption about why set 1 is
    # bad.  The exact acquisition has 64/64 distinct nonzero values, no match
    # among 24 addresses duplicated in set 0, and four different values for
    # the same MC +0x80 slot across four symmetric instances.  It therefore
    # cannot be used as a coherent current register snapshot.
    if set0_mc["common_offsets"] != 18:
        raise ValueError("set 0 does not expose the expected 18 MC offset groups")
    if set0_mc["exactly_equal_groups"] != 17 or set0_mc["two_value_groups"] != 1:
        raise ValueError("set 0 MC symmetry changed")
    if not set1_metrics["all_values_distinct"] or set1_metrics["zero_words"] != 0:
        raise ValueError("set 1 no longer has the captured all-distinct pattern")
    if set1_mc["common_offsets"] != 1 or set1_mc["four_value_groups"] != 1:
        raise ValueError("set 1 MC incoherence pattern changed")
    if overlap["common_registers"] != 24 or overlap["equal_values"] != 0:
        raise ValueError("set overlap qualification changed")

    candidates = candidate_inventory(maps[0])
    common = {
        "experiment_id": EXPERIMENT_ID,
        "mode": "HOST_ONLY_EVIDENCE_QUALIFICATION",
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "device_access": False,
        "dump": {
            "filename": "SHRM_MEM.BIN",
            "size": len(dump_data),
            "sha256": sha256(dump_data),
            "physical_range": "0x09060000..0x0906ffff",
            "workspace_offset": "0x5100",
            "section16_header": ["0x0008", "0x0230", "0x01b8", "0x08e8"],
            "decoded_staged_entries": sum(item.count for item in decoded),
            "distinct_source_registers": len(set(maps[0]) | set(maps[1])),
        },
        "transport": {
            "observed_usb": "04e8:685d",
            "observed_product": "MSM_UPLOAD",
            "protocol_family": "SAMSUNG_UPLOAD",
            "qualcomm_sahara_05c6": False,
            "source": {
                "repository": SAMUPLOAD_URL,
                "commit": SAMUPLOAD_COMMIT,
                "samupload_py_sha256": sha256(samupload_data),
            },
            "host_journal": {
                "sha256": sha256(journal_data),
                "line_count": len(journal_lines),
                "upload_enumerated": True,
                "upload_disconnected": True,
                "native_04e8_6861_returned": True,
                "device_serial_omitted": True,
            },
            "static_catalog_descriptor": {
                "record_index": 19,
                "name": "SHRM_MEM.BIN",
                "start": "0x09060000",
                "end_inclusive": "0x0906ffff",
            },
            "live_catalog_transcript": "OBSERVED_BUT_NOT_SEPARATELY_PINNED",
            "selected_record_count": 1,
        },
        "set_qualification": {
            "set0": {
                "classification": "SUPPORTED_POPULATED_COHERENT_SNAPSHOT",
                "metrics": set0_metrics,
                "mc_symmetry": {
                    key: value for key, value in set0_mc.items() if key != "groups"
                },
                "use_for_follow_up": True,
            },
            "set1": {
                "classification": "REFUTED_AS_COHERENT_CURRENT_SNAPSHOT",
                "possible_explanations": ["STALE", "UNPOPULATED", "UNINITIALIZED"],
                "metrics": set1_metrics,
                "mc_symmetry": {
                    key: value for key, value in set1_mc.items() if key != "groups"
                },
                "use_for_follow_up": False,
            },
            "overlap": {
                key: value for key, value in overlap.items() if key != "registers"
            },
        },
        "controller_candidates_top5": candidates,
        "remapper_coverage": decoder.remapper_coverage(decoded),
        "final_state": {
            "param_partition": "LOW_RESTORED_VERIFIED",
            "post_reboot_debug_level": "0x4f4c",
            "post_reboot_force_upload": "0x0",
            "post_reboot_dump_sink": "0x0",
            "post_reboot_download_mode": "1",
            "post_reboot_selftest_fail": 0,
            "evidence": {
                label: dict(EVIDENCE_PINS[label])
                for label in ("param_low_restore", "native_health", "low_reboot")
            },
        },
        "evidence_chain": {
            label: dict(pin) for label, pin in EVIDENCE_PINS.items()
        },
        "classification": "REAL_SHRM_DUMP_ACQUIRED_SET0_QUALIFIED_NO_BYPASS",
        "security_state": "NO_ALIAS_OR_BOUNDARY_BYPASS_OBSERVED",
        "claims": {
            "PROVED": [
                "One exact 64-KiB file has the pinned SHA-256 and the exact section-16 workspace header at dump offset 0x5100.",
                "The decoder mapped 430 + 64 staged entries to 494 labelled positions covering 470 distinct source-register addresses without reading a live device.",
                "The host kernel journal records Samsung 04e8:685d MSM_UPLOAD enumeration, disconnect, and return of the A90 native 04e8:6861 runtime.",
                "The acquisition used Samsung Upload transport; the concurrently waiting qdl 05c6 Sahara collector captured no file.",
                "The final param image was restored to LOW and a subsequent boot proved LOW/force-upload 0/dump-sink 0 with selftest fail=0.",
            ],
            "SUPPORTED": [
                "Set 0 is populated controller state: 17 of 18 four-instance MC offset groups are identical and the remaining group has a stable two-by-two split.",
                "The five ranked words are high-value semantic-recovery and timing-cross-check candidates because they sit in exact MC/MCCC topology blocks and show repeated structure.",
            ],
            "REFUTED": [
                "Qualcomm 05c6 Sahara/qdl is the exact A90 crash-dump transport used by this boot.",
                "Set 1 can be treated as a coherent current register snapshot in this acquisition: all 64 values are distinct, its four MC +0x80 values all differ, and none of 24 duplicated addresses matches set 0.",
                "This dump covers the separate qhs_llcc +0x8080 remapper control window.",
                "This acquisition demonstrates a physical-address alias or protected-memory isolation bypass.",
            ],
            "UNKNOWN": [
                "The exact semantic register names and bitfields for the five controller candidates.",
                "Whether any candidate controls channel/bank/rank/row/column hashing or is writable after boot.",
                "Whether set 1 is stale, unpopulated, or uninitialized; only its use as a coherent current snapshot is refuted.",
                "The final transform owner, lock state, and protection ordering relative to that transform.",
            ],
        },
    }

    private = {
        "schema": "sdm855-a90-shrm-live-dump-private-v1",
        **copy.deepcopy(common),
        "host_journal_lines": journal_lines,
        "set_qualification_full": {
            "set0_mc_groups": set0_mc["groups"],
            "set1_mc_groups": set1_mc["groups"],
            "overlap_registers": overlap["registers"],
        },
        "decoded_registers": [
            {
                "set": set_index,
                "index": word.index,
                "dump_offset": f"0x{word.dump_offset:04x}",
                "register": f"0x{word.register:08x}",
                "topology": list(word.topology),
                "value": f"0x{word.value:08x}",
            }
            for set_index, item in enumerate(decoded)
            for word in item.words
        ],
        "evidence_chain_decoded": evidence_chain,
    }
    public = {
        "schema": "sdm855-a90-shrm-live-dump-public-v1",
        **copy.deepcopy(common),
    }
    return private, public


def atomic_replace(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(temporary)
    write_new(temporary, data, mode)
    os.replace(temporary, path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=Path, default=RAW_DUMP)
    parser.add_argument("--samupload-source", type=Path, default=SAMUPLOAD_SOURCE)
    parser.add_argument(
        "--journal",
        type=Path,
        required=True,
        help="exact eight-line serial-free host kernel journal excerpt",
    )
    parser.add_argument(
        "--private-output",
        type=Path,
        default=REPO_ROOT / "evidence/private" / EXPERIMENT_ID / "analysis.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=REPO_ROOT / "evidence/manifests" / f"{EXPERIMENT_ID}.manifest.json",
    )
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    private_output = args.private_output.resolve()
    manifest_output = args.manifest_output.resolve()
    if not args.replace:
        for output in (private_output, manifest_output):
            if output.exists():
                raise FileExistsError(output)

    private, public = analyze(
        args.dump.read_bytes(),
        args.samupload_source.read_bytes(),
        args.journal.read_bytes(),
    )
    private_bytes = json_bytes(private)
    public["private_record"] = {
        "filename": private_output.name,
        "size": len(private_bytes),
        "sha256": sha256(private_bytes),
        "git_ignored": True,
    }
    public_bytes = json_bytes(public)
    if args.replace:
        atomic_replace(private_output, private_bytes, 0o600)
        atomic_replace(manifest_output, public_bytes, 0o644)
    else:
        write_new(private_output, private_bytes, 0o600)
        write_new(manifest_output, public_bytes, 0o644)
    print(private_output)
    print(manifest_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
