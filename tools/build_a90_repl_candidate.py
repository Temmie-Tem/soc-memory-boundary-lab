#!/usr/bin/env python3
"""Rebuild the previously live-proven A90 v1 REPL boot candidate.

The implementation remains sourced from android-native-init-lab, but all
derived bytes and metadata are written under this repository's ignored private
evidence directory.  No device operation is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _upstream_root() -> Path:
    """Root of the upstream android-native-init-lab checkout.

    Override with ANDROID_NATIVE_INIT_LAB when it is not at the default path.
    """
    return Path(
        os.environ.get(
            "ANDROID_NATIVE_INIT_LAB",
            Path.home() / "dev" / "android-native-init-lab",
        )
    )



SOURCE_REPO = _upstream_root()
SOURCE_COMMIT = "f44b34c8f44a9a01c99bb589644494c732a6c3fa"
SOURCE_DIR = "workspace/public/src/scripts/revalidation"
HISTORICAL_SOURCES = {
    "build_kernel_tier2_repl_v1_repl.py":
        "4d7dd48e9638b44d296d0fddbd8c35fdb7a58b0f3de7f2f191fa36e5ed6979ee",
    "build_kernel_runtime_poke_agent.py":
        "c365f69eb55a7e067a08d5af1dc319ca8017701c22cb658215a1bd137cd72f90",
    "build_kernel_tier2_stage_c_direct_bl_printk.py":
        "9c630efa3aad656f2396444196f7fe4d171b09297016d95cf116a3518acac9a2",
}
CURRENT_SCRIPT_DIR = SOURCE_REPO / SOURCE_DIR
DEFAULT_BASE = (
    _upstream_root()
    / "workspace/private/inputs/boot_images"
    / "boot_linux_v2321_usb_clean_identity_rodata.img"
)
DEFAULT_OUTPUT_DIR = Path(
    "evidence/private/007-kernel-remapper-readonly-20260825-02"
)

BASE_SHA256 = "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
CANDIDATE_SHA256 = "b846ae9f74d8ceb922bbcd854d78b6795ef833d61e38465d3cc474cb6f0dfb65"
CANDIDATE_NAME = "boot_linux_tier2_repl_v1_repl.img"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_new_regular_targets(paths: tuple[Path, ...]) -> None:
    for path in paths:
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite existing output: {path}")


def git_blob(repo: Path, commit: str, relative_path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{relative_path}"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def load_live_proven_builder(repo: Path, commit: str, temp_dir: Path):
    resolved = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{commit}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if resolved != SOURCE_COMMIT:
        raise RuntimeError(f"historical builder commit mismatch: {resolved}")

    for name, expected_sha in HISTORICAL_SOURCES.items():
        payload = git_blob(repo, commit, f"{SOURCE_DIR}/{name}")
        actual_sha = hashlib.sha256(payload).hexdigest()
        if actual_sha != expected_sha:
            raise RuntimeError(f"historical source SHA-256 mismatch for {name}")
        (temp_dir / name).write_bytes(payload)

    # The historical files use the current workspace bootstrap/evidence helper
    # only for locating the read-only base and writing redirected outputs.
    current_dir = str(CURRENT_SCRIPT_DIR)
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    sys.path.insert(0, str(temp_dir))
    return importlib.import_module("build_kernel_tier2_repl_v1_repl")


def build(base: Path, output_dir: Path, source_repo: Path) -> dict[str, object]:
    base = base.resolve()
    output_dir = output_dir.resolve()
    if sha256_file(base) != BASE_SHA256:
        raise RuntimeError("V2321 base boot SHA-256 mismatch")

    candidate = output_dir / CANDIDATE_NAME
    builder_dir = output_dir / "candidate-build"
    provenance_path = output_dir / "candidate-provenance.json"
    require_new_regular_targets((candidate, builder_dir, provenance_path))

    with tempfile.TemporaryDirectory(prefix="sdm855-repl-f44-") as temp_text:
        external = load_live_proven_builder(
            source_repo.resolve(), SOURCE_COMMIT, Path(temp_text)
        )
        # Redirect every output before calling the historical implementation.
        # The source/base stays read-only in android-native-init-lab.
        external.BASE_BOOT = base
        external.stage_c.BASE_BOOT = base
        external.OUT_BOOT = candidate
        external.OUT_DIR = builder_dir
        # Its manifest records relative paths; slash is the only common
        # ancestor and changes representation only, never target selection.
        external.REPO_ROOT = Path("/")
        manifest = external.build_candidate()
    candidate_sha = sha256_file(candidate)
    if candidate_sha != CANDIDATE_SHA256:
        raise RuntimeError(
            f"candidate SHA-256 mismatch: {candidate_sha} != {CANDIDATE_SHA256}"
        )

    provenance = {
        "schema": "sdm855-a90-repl-candidate-provenance-v1",
        "device_action": False,
        "base_boot": str(base),
        "base_sha256": BASE_SHA256,
        "source_repo": str(source_repo.resolve()),
        "source_commit": SOURCE_COMMIT,
        "historical_source_sha256": HISTORICAL_SOURCES,
        "candidate": str(candidate),
        "candidate_sha256": candidate_sha,
        "candidate_size": candidate.stat().st_size,
        "external_manifest": manifest,
    }
    output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(provenance_path, 0o600)
    os.chmod(candidate, 0o600)
    return provenance


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rebuild the exact live-proven A90 v1 REPL candidate"
    )
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--source-repo", type=Path, default=SOURCE_REPO)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser


def main() -> int:
    args = make_parser().parse_args()
    print(json.dumps(build(args.base, args.output_dir, args.source_repo), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
