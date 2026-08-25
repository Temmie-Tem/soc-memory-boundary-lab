#!/usr/bin/env python3
"""Build fixed A90 control/read candidates for one SHRM snapshot word.

The exact destination is section-16 set 0 word 207 at physical 0x0906566c.
Experiment 012 maps that word to the MCCC source register 0x09250118. The
control candidate maps and unmaps without a load; the read candidate performs
one 32-bit load. There is no runtime address, call target, width, or write
value input. This tool performs no device action.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools import build_a90_inline_remapper_candidate as inline
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    import build_a90_inline_remapper_candidate as inline


WORKSPACE_BASE = 0x09065100
SET0_DESTINATION_OFFSET = 0x230
SNAPSHOT_WORD_INDEX = 207
SNAPSHOT_WORD_OFFSET = SET0_DESTINATION_OFFSET + SNAPSHOT_WORD_INDEX * 4
SNAPSHOT_WORD_PHYS = WORKSPACE_BASE + SNAPSHOT_WORD_OFFSET
SOURCE_REGISTER_PHYS = 0x09250118
FIXED_SIZE = 4

EXPECTED_HASHES = {
    inline.MODE_CONTROL: {
        "candidate": "d1d4956b64ae5ca39eb5218d8e84e3da40bc2772e39f2a9d438bfaf778be46e0",
        "body": "c1283584e3220f6119694c2bc8bf77419e53824875f7f871bf45eee35713a51b",
    },
    inline.MODE_READ: {
        "candidate": "7ee6a41f3f55f6eea768a7fd7b66bf011b84e63fa523ee8a0430a50091b02116",
        "body": "1349ec040c59d34d1ad90c960f04ab4cdf2b2474e753ee30a2a3c82e138748db",
    },
}


def output_names(mode: str) -> tuple[str, str]:
    if mode not in inline.MODES:
        raise ValueError(f"unsupported mode: {mode}")
    return (
        f"boot_linux_inline_shrm_snapshot_{mode}_v1.img",
        f"force_no_nap_store_inline_shrm_snapshot_{mode}_v1.bin",
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_one(
    original: bytes,
    layout: Any,
    legacy: Any,
    mode: str,
) -> tuple[bytes, bytes, dict[str, object]]:
    payload = inline.build_inline_payload(
        legacy,
        mode,
        fixed_phys=SNAPSHOT_WORD_PHYS,
        fixed_size=FIXED_SIZE,
    )
    patched = bytearray(original)
    patch_abs = layout.kernel_off + inline.ENTRY_OFF
    patched[patch_abs : patch_abs + len(payload)] = payload
    patched_kernel = bytes(
        patched[layout.kernel_off : layout.kernel_off + layout.kernel_size]
    )
    if legacy.stage_c.u32_at(patched_kernel, inline.MAGIC_BEFORE_OFF) != inline.JOPP_MAGIC:
        raise RuntimeError("patched image clobbered prior JOPP magic")
    if legacy.stage_c.u32_at(patched_kernel, inline.NEXT_MAGIC_OFF) != inline.JOPP_MAGIC:
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

    candidate = bytes(patched)
    candidate_sha = sha256(candidate)
    body_sha = sha256(payload)
    if candidate_sha != EXPECTED_HASHES[mode]["candidate"]:
        raise RuntimeError(
            f"{mode} candidate hash {candidate_sha} != pinned "
            f"{EXPECTED_HASHES[mode]['candidate']}"
        )
    if body_sha != EXPECTED_HASHES[mode]["body"]:
        raise RuntimeError(
            f"{mode} body hash {body_sha} != pinned {EXPECTED_HASHES[mode]['body']}"
        )
    return candidate, payload, {
        "mode": mode,
        "candidate_sha256": candidate_sha,
        "candidate_size": len(candidate),
        "body_sha256": body_sha,
        "body_size": len(payload),
        "boot_id": boot_id[:20].hex(),
        "changed_byte_count": len(changed),
        "changed_ranges": [
            [hex(start), hex(end)]
            for start, end in legacy.stage_c.contiguous_ranges(changed)
        ],
    }


def build(
    base: Path,
    output_dir: Path,
    source_repo: Path,
    public_manifest_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    base = base.resolve()
    output_dir = output_dir.resolve()
    public_manifest_path = public_manifest_path.resolve()
    if inline.sha256_file(base) != inline.BASE_SHA256:
        raise RuntimeError("V2321 base boot SHA-256 mismatch")

    private_manifest_path = output_dir / "candidate-manifest.json"
    targets = [private_manifest_path, public_manifest_path]
    for mode in inline.MODES:
        candidate_name, body_name = output_names(mode)
        targets.extend((output_dir / candidate_name, output_dir / body_name))
    for path in targets:
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite output: {path}")

    with tempfile.TemporaryDirectory(prefix="sdm855-inline-shrm-") as temp_text:
        legacy = inline.load_live_proven_builder(
            source_repo.resolve(), inline.SOURCE_COMMIT, Path(temp_text)
        )
        original = base.read_bytes()
        layout = legacy.stage_c.parse_boot_layout(original)
        kernel = bytes(
            original[layout.kernel_off : layout.kernel_off + layout.kernel_size]
        )
        if kernel[:16] != b"UNCOMPRESSED_IMG":
            raise RuntimeError("kernel wrapper is not UNCOMPRESSED_IMG")
        inline.validate_base_kernel(kernel, legacy)
        _magic, printk_off, _va_helper, _emit_core = (
            legacy.stage_c.locate_printk_variadic_wrapper(kernel)
        )
        if legacy.stage_c.kernel_vaddr(printk_off) != inline.PRINTK_WRAPPER_LINK:
            raise RuntimeError("printk wrapper identity drifted")

        output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        records: list[dict[str, object]] = []
        for mode in inline.MODES:
            candidate, body, record = _build_one(original, layout, legacy, mode)
            candidate_name, body_name = output_names(mode)
            candidate_path = output_dir / candidate_name
            body_path = output_dir / body_name
            write_new(candidate_path, candidate, 0o600)
            write_new(body_path, body, 0o600)
            record.update(
                {
                    "candidate": str(candidate_path),
                    "body": str(body_path),
                    "mmio_load_count": 1 if mode == inline.MODE_READ else 0,
                }
            )
            records.append(record)

    common = {
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "device_action": False,
        "base_sha256": inline.BASE_SHA256,
        "source_commit": inline.SOURCE_COMMIT,
        "snapshot": {
            "workspace_base": f"0x{WORKSPACE_BASE:08x}",
            "set": 0,
            "word_index": SNAPSHOT_WORD_INDEX,
            "destination_offset": f"0x{SNAPSHOT_WORD_OFFSET:x}",
            "physical_address": f"0x{SNAPSHOT_WORD_PHYS:08x}",
            "width_bits": 32,
            "source_register": f"0x{SOURCE_REGISTER_PHYS:08x}",
        },
        "hook": {
            "handler": "kgsl_pwrctrl_force_no_nap_store",
            "entry_off": f"0x{inline.ENTRY_OFF:x}",
            "patch_room": inline.PATCH_ROOM,
            "jopp_boundaries_preserved": True,
        },
        "safety": {
            "generic_call_target": False,
            "runtime_address_input": False,
            "arbitrary_address_input": False,
            "memory_or_mmio_store_instruction": False,
            "read_candidate_load_count": 1,
            "control_candidate_load_count": 0,
            "mapping_cleanup_precedes_result": True,
            "device_write": False,
        },
    }
    private = {
        "schema": "sdm855-a90-inline-shrm-snapshot-candidate-private-v1",
        "base_boot": str(base),
        "source_repo": str(source_repo.resolve()),
        "records": records,
        **common,
    }
    public_records = [
        {key: value for key, value in record.items() if key not in {"candidate", "body"}}
        for record in records
    ]
    public = {
        "schema": "sdm855-a90-inline-shrm-snapshot-candidate-public-v1",
        "records": public_records,
        "state": "HOST_READY_CONTROL_ONLY",
        "read_candidate_live_eligible": False,
        "next_gate": (
            "Run the exact no-load control once and prove V2321 recovery; only a "
            "clean control result can make the one-load read candidate eligible"
        ),
        **common,
    }
    private_bytes = json_bytes(private)
    public["private_manifest"] = {
        "filename": private_manifest_path.name,
        "size": len(private_bytes),
        "sha256": sha256(private_bytes),
        "git_ignored": True,
    }
    write_new(private_manifest_path, private_bytes, 0o600)
    write_new(public_manifest_path, json_bytes(public), 0o644)
    os.chmod(output_dir, 0o700)
    return private, public


def make_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=inline.DEFAULT_BASE)
    parser.add_argument("--source-repo", type=Path, default=inline.SOURCE_REPO)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=root / "evidence/private/013-inline-shrm-snapshot-20260825-01",
    )
    parser.add_argument(
        "--public-manifest",
        type=Path,
        default=root / "evidence/manifests/013-inline-shrm-snapshot-candidates-20260825-01.manifest.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    _private, public = build(
        args.base, args.output_dir, args.source_repo, args.public_manifest
    )
    print(json_bytes(public).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
