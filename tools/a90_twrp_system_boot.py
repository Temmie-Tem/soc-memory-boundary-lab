#!/usr/bin/env python3
"""Exit the exact A90 TWRP GUI main loop into the System boot path.

The Samsung TWRP build used by this lab crashes its OpenRecoveryScript process
on ``twrp reboot``.  Its GUI reboot action instead sets ``tw_reboot_arg`` and
``tw_gui_done``; recovery's main thread then calls ``TWFunc::tw_reboot`` after
normal GUI teardown.  This tool invokes that exact state transition without a
touch event.  The effect is dispatched once and is never retried.
"""

from __future__ import annotations

import argparse
import hashlib
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
ASSIGNMENT_RE = re.compile(r"^(?P<key>[a-zA-Z0-9_]+) = (?P<value>.*)$")


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


def run_text(argv: Sequence[str]) -> str:
    result = subprocess.run(
        list(argv),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
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
    help_text = adb_shell(adb, serial, "twrp --help 2>&1", run)
    if "TWRP openrecoveryscript command line tool" not in help_text:
        raise BootError("bound endpoint does not expose the expected TWRP CLI")
    if f"TWRP version {TWRP_VERSION}" not in help_text:
        raise BootError("bound endpoint TWRP version differs from the proved build")

    gui_done = parse_assignment(
        adb_shell(adb, serial, "twrp get tw_gui_done", run), "tw_gui_done"
    )
    if gui_done != "0":
        raise BootError(f"tw_gui_done is not at the pre-effect value 0: {gui_done!r}")

    adb_shell(adb, serial, "twrp set tw_reboot_arg system", run)
    reboot_arg = parse_assignment(
        adb_shell(adb, serial, "twrp get tw_reboot_arg", run), "tw_reboot_arg"
    )
    if reboot_arg != "system":
        raise BootError(f"tw_reboot_arg verification failed: {reboot_arg!r}")

    # This is the only effect dispatch.  Do not retry it on an ambiguous exit.
    adb_shell(adb, serial, "sync; twrp set tw_gui_done 1", run)


def wait_for_disconnect(
    adb: str,
    endpoint: AdbEndpoint,
    timeout: float,
    run: Runner = run_text,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        endpoints = parse_adb_devices(run((adb, "devices")))
        if not any(item.serial == endpoint.serial for item in endpoints):
            return True
        time.sleep(0.25)
    return False


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--disconnect-timeout", type=float, default=20.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.disconnect_timeout <= 0:
        raise BootError("disconnect timeout must be positive")
    endpoint = select_exact_recovery(args.adb)
    dispatch_system_boot(args.adb, endpoint.serial)
    disconnected = wait_for_disconnect(args.adb, endpoint, args.disconnect_timeout)
    print(f"target={TARGET_MODEL}/{TARGET_DEVICE}")
    print(f"serial_sha256={endpoint.serial_sha256}")
    print("system_exit_dispatched_once=1")
    print(f"adb_disconnect_observed={int(disconnected)}")
    if not disconnected:
        raise BootError(
            "boot effect was dispatched once but disconnect was not observed; "
            "do not rerun automatically"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
