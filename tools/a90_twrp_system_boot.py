#!/usr/bin/env python3
"""Read-only primitives for the exact A90 TWRP System-boot identity.

The Samsung TWRP build used by this lab crashes its OpenRecoveryScript process
on ``twrp reboot``.  Its GUI reboot action instead sets ``tw_reboot_arg`` and
``tw_gui_done``; recovery's main thread then calls ``TWFunc::tw_reboot`` after
normal GUI teardown.  The historical mutating helper and CLI in this module
are permanently disabled.  The durable Verification 024 owner
``a90_twrp_system_boot_once`` is the only supported state-transition path;
this module retains only target selection, parsing, disconnect observation,
and finite-timeout subprocess primitives for that owner.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import math
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Sequence


TARGET_MODEL = "SM-A908N"
TARGET_DEVICE = "r3q"
TARGET_SERIAL_SHA256 = (
    "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46"
)
TWRP_VERSION = "3.7.0_12-0"
SUBPROCESS_TIMEOUT_SEC = 120.0
MIN_TIMEOUT_SEC = 0.001
MAX_TIMEOUT_SEC = SUBPROCESS_TIMEOUT_SEC
ASSIGNMENT_RE = re.compile(r"^(?P<key>[a-zA-Z0-9_]+) = (?P<value>.*)$")
READONLY_SHELL_COMMANDS = frozenset(
    {
        "getprop ro.product.model",
        "getprop ro.product.device",
    }
)


class BootError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdbEndpoint:
    serial: str
    state: str

    @property
    def serial_sha256(self) -> str:
        return hashlib.sha256(self.serial.encode("utf-8")).hexdigest()


Runner = Callable[[Sequence[str]], str]


def run_text(argv: Sequence[str], *, timeout: float = SUBPROCESS_TIMEOUT_SEC) -> str:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise BootError("subprocess timeout is not numeric")
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout < MIN_TIMEOUT_SEC or timeout > MAX_TIMEOUT_SEC:
        raise BootError(
            f"subprocess timeout must be finite and in [{MIN_TIMEOUT_SEC}, {MAX_TIMEOUT_SEC}]"
        )
    try:
        result = subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise BootError(
            f"command timed out after bounded {timeout}s; argv={tuple(argv)!r}"
        ) from exc
    if result.returncode != 0:
        raise BootError(
            f"command failed before a boot effect: rc={result.returncode}; "
            f"stderr={result.stderr.strip()!r}"
        )
    return result.stdout.replace("\r", "")


def parse_adb_devices(output: str) -> tuple[AdbEndpoint, ...]:
    endpoints: list[AdbEndpoint] = []
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2:
            endpoints.append(AdbEndpoint(fields[0], fields[1]))
    return tuple(endpoints)


def adb_shell(adb: str, serial: str, command: str, run: Runner) -> str:
    if command not in READONLY_SHELL_COMMANDS:
        raise BootError(
            "legacy TWRP shell mutation is disabled; use the durable one-shot owner"
        )
    return run((adb, "-s", serial, "shell", command))


def select_exact_recovery(
    adb: str,
    run: Runner = run_text,
    expected_serial_sha256: str = TARGET_SERIAL_SHA256,
) -> AdbEndpoint:
    endpoints = parse_adb_devices(run((adb, "devices")))
    matches: list[AdbEndpoint] = []
    for endpoint in endpoints:
        if endpoint.state != "recovery":
            continue
        if endpoint.serial_sha256 != expected_serial_sha256:
            continue
        model = adb_shell(adb, endpoint.serial, "getprop ro.product.model", run).strip()
        device = adb_shell(adb, endpoint.serial, "getprop ro.product.device", run).strip()
        if model == TARGET_MODEL and device == TARGET_DEVICE:
            matches.append(endpoint)
    if len(matches) != 1:
        raise BootError(
            "expected exactly one bound SM-A908N/r3q Recovery endpoint; "
            f"matched={len(matches)}"
        )
    return matches[0]


def parse_assignment(output: str, expected_key: str) -> str:
    matches = []
    for line in output.splitlines():
        match = ASSIGNMENT_RE.fullmatch(line.strip())
        if match and match.group("key") == expected_key:
            matches.append(match.group("value"))
    if len(matches) != 1:
        raise BootError(f"expected one {expected_key} assignment, got {len(matches)}")
    return matches[0]


def dispatch_system_boot(adb: str, serial: str, run: Runner = run_text) -> None:
    """Refuse the historical mutating helper before touching its runner."""

    del adb, serial, run
    raise BootError(
        "direct TWRP System mutation is disabled; use "
        "a90_twrp_system_boot_once"
    )


def wait_for_disconnect(
    adb: str,
    endpoint: AdbEndpoint,
    timeout: float,
    run: Runner = run_text,
) -> bool:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise BootError("disconnect timeout is not numeric")
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout < MIN_TIMEOUT_SEC or timeout > MAX_TIMEOUT_SEC:
        raise BootError(
            f"disconnect timeout must be finite and in [{MIN_TIMEOUT_SEC}, {MAX_TIMEOUT_SEC}]"
        )
    deadline = time.monotonic() + timeout
    runner_accepts_timeout = False
    try:
        parameters = inspect.signature(run).parameters
        runner_accepts_timeout = "timeout" in parameters or any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
    except (TypeError, ValueError):
        runner_accepts_timeout = False

    def bounded_run(argv: Sequence[str]) -> str:
        remaining = deadline - time.monotonic()
        if remaining < MIN_TIMEOUT_SEC:
            return ""
        bounded = min(SUBPROCESS_TIMEOUT_SEC, remaining)
        if run is run_text or runner_accepts_timeout:
            return run(argv, timeout=bounded)  # type: ignore[call-arg]
        return run(argv)

    while time.monotonic() < deadline:
        endpoints = parse_adb_devices(bounded_run((adb, "devices")))
        if not any(item.serial == endpoint.serial for item in endpoints):
            return True
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    return False


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # Parse only the empty primitive-only interface, then fail before any
    # selector/runner invocation.  ``--help`` remains argparse's harmless
    # documentation path; all execution attempts are explicitly disabled.
    make_parser().parse_args(argv)
    raise BootError(
        "legacy TWRP System CLI is disabled; use a90_twrp_system_boot_once"
    )


if __name__ == "__main__":
    raise SystemExit(main())


# Star-imports expose only the read-only target/parsing primitives.  The
# historical dispatch name remains a refusal shim for compatibility, but is
# intentionally not an exported mutation API.
__all__ = [
    "TARGET_MODEL",
    "TARGET_DEVICE",
    "TARGET_SERIAL_SHA256",
    "TWRP_VERSION",
    "SUBPROCESS_TIMEOUT_SEC",
    "BootError",
    "AdbEndpoint",
    "Runner",
    "run_text",
    "parse_adb_devices",
    "parse_assignment",
    "select_exact_recovery",
    "wait_for_disconnect",
]
