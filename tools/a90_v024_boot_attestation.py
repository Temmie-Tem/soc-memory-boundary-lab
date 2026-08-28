#!/usr/bin/env python3
"""Reusable Verification 024 current-boot and temporary-path attestation.

The implementation remains owned by the exact inline probe so the probe and
its health consumer cannot drift in their fixed sysfs/stat/capture contract.
This module supplies the stable public seam and the additional read-only
absence proof used by final runtime health.  It never discovers a target or
opens a transport while being imported.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from tools import a90_inline_remapper_mid_probe as _probe


BOOT_PREFIX_SIZE = _probe.BOOT_PREFIX_SIZE
BOOT_BLOCK_NODE = _probe.BOOT_BLOCK_NODE
BOOT_SYSFS_ROOT = _probe.BOOT_SYSFS_ROOT
BOOT_SYSFS_UEVENT = _probe.BOOT_SYSFS_UEVENT
BOOT_SYSFS_SIZE = _probe.BOOT_SYSFS_SIZE
BOOT_SYSFS_RO = _probe.BOOT_SYSFS_RO
BOOT_ATTEST_DIR = _probe.BOOT_ATTEST_DIR
BOOT_ATTEST_NODE = _probe.BOOT_ATTEST_NODE
BOOT_ATTEST_FILE = _probe.BOOT_ATTEST_FILE
BOOT_EXPECTED_MAJOR = _probe.BOOT_EXPECTED_MAJOR
BOOT_EXPECTED_MINOR = _probe.BOOT_EXPECTED_MINOR
BOOT_EXPECTED_PARTN = _probe.BOOT_EXPECTED_PARTN
BOOT_EXPECTED_PARTNAME = _probe.BOOT_EXPECTED_PARTNAME
BOOT_EXPECTED_SECTORS = _probe.BOOT_EXPECTED_SECTORS

PARAM_PAYLOAD_PATH = "/tmp/sdm855_mblab_param_debug_payload"
PARAM_SMOKE_PATH = "/tmp/sdm855_mblab_param_debug_dd_smoke"
PARAM_NODE_PATH = "/dev/sdm855_mblab_sda10"
V024_NATIVE_TEMP_PATHS = (
    BOOT_ATTEST_NODE,
    BOOT_ATTEST_FILE,
    PARAM_PAYLOAD_PATH,
    PARAM_SMOKE_PATH,
    PARAM_NODE_PATH,
)
TEMP_PATHS = V024_NATIVE_TEMP_PATHS

AttestationError = _probe.ProbeError
ProbeError = _probe.ProbeError


def attest_current_boot(*args: Any, **kwargs: Any) -> dict[str, object]:
    """Delegate the exact current-boot prefix proof to the hardened probe."""

    return _probe.attest_current_boot(*args, **kwargs)


def verify_v024_temp_absence(
    host: str,
    port: int,
    timeout: float,
    frames: list[dict[str, object]],
    *,
    exchange_fn: Callable[..., Any] | None = None,
) -> dict[str, object]:
    """Prove every fixed V024 temporary node/file is absent and not a link."""

    start = len(frames)
    for index, path in enumerate(V024_NATIVE_TEMP_PATHS):
        _probe._attest_marker(
            host,
            port,
            timeout,
            f"v024_temp_{index}",
            path,
            frames,
            exchange_fn=exchange_fn,
        )
    return {
        "paths": list(V024_NATIVE_TEMP_PATHS),
        "absence_verified": True,
        "frame_count": len(frames) - start,
    }


__all__ = [
    "AttestationError",
    "BOOT_ATTEST_DIR",
    "BOOT_ATTEST_FILE",
    "BOOT_ATTEST_NODE",
    "BOOT_BLOCK_NODE",
    "BOOT_EXPECTED_MAJOR",
    "BOOT_EXPECTED_MINOR",
    "BOOT_EXPECTED_PARTN",
    "BOOT_EXPECTED_PARTNAME",
    "BOOT_EXPECTED_SECTORS",
    "BOOT_PREFIX_SIZE",
    "PARAM_NODE_PATH",
    "PARAM_PAYLOAD_PATH",
    "PARAM_SMOKE_PATH",
    "TEMP_PATHS",
    "V024_NATIVE_TEMP_PATHS",
    "attest_current_boot",
    "verify_v024_temp_absence",
]
