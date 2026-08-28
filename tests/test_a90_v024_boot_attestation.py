from __future__ import annotations

import unittest

from tools import a90_inline_remapper_mid_probe as probe
from tools import a90_v024_boot_attestation as attestation


class Frame:
    def __init__(self, command: str, payload: bytes = b"", *, rc: int = 0, status: str = "ok", argc: int | None = None) -> None:
        self.payload = payload
        protocol_flags = probe.protocol_flags_for_argv((command,))
        if protocol_flags is None:
            raise AssertionError(f"test command has no native flag contract: {command}")
        default_argc = {
            "run": 5,
            "stophud": 1,
            "writefile": 3,
            "version": 1,
            "cat": 2,
            "selftest": 2,
            "mknodb": 4,
            "stat": 2,
        }[command]
        argc = default_argc if argc is None else argc
        self.begin = {"cmd": command, "seq": "1", "argc": str(argc), "flags": protocol_flags}
        self.end = {
            "cmd": command,
            "seq": "1",
            "rc": str(rc),
            "errno": str(abs(rc)),
            "duration_ms": "0",
            "flags": protocol_flags,
            "status": status,
        }
        if rc == 0 and status == "ok":
            terminal = f"[done] {command} (0ms)\n".encode("ascii")
        elif rc == -16 and status == "busy":
            terminal = b"[busy] auto menu active; send hide/q before command\n"
        elif rc < 0:
            terminal = (
                f"[err] {command} rc={rc} errno={abs(rc)} (error) (0ms)\n"
            ).encode("ascii")
        else:
            terminal = f"[err] {command} rc={rc} (0ms)\n".encode("ascii")
        self.transcript = (
            b"A90P1 BEGIN seq=1 cmd=" + command.encode("ascii")
            + b" argc=" + str(argc).encode("ascii")
            + b" flags=" + protocol_flags.encode("ascii") + b"\n"
            + payload + b"\n" + terminal
            + b"A90P1 END seq=1 cmd=" + command.encode("ascii")
            + b" rc=" + str(rc).encode("ascii")
            + b" errno=" + str(abs(rc)).encode("ascii")
            + b" duration_ms=0 flags=" + protocol_flags.encode("ascii")
            + b" status=" + status.encode("ascii") + b"\n"
        )


class BootAttestationTests(unittest.TestCase):
    def test_fixed_temp_paths_are_experiment_owned(self) -> None:
        self.assertEqual(
            attestation.V024_NATIVE_TEMP_PATHS,
            (
                "/tmp/a90-native/verification-024-sda24",
                "/tmp/a90-native/verification-024-boot-prefix.bin",
                "/tmp/sdm855_mblab_param_debug_payload",
                "/tmp/sdm855_mblab_param_debug_dd_smoke",
                "/dev/sdm855_mblab_sda10",
            ),
        )

    def test_attests_real_stat_contract_and_exact_mutation_argv(self) -> None:
        frames: list[dict[str, object]] = []
        commands: list[tuple[str, ...]] = []
        binding = {"serial": "pinned", "pid": 1}

        def rebind(initial):
            return dict(initial)

        def toybox(body: bytes = b"", *, argc: int = 5) -> Frame:
            payload = b"run: pid=1, q/Ctrl-C cancels\n" + body
            if body and not body.endswith(b"\n"):
                payload += b"\n"
            return Frame("run", payload + b"[exit 0]\n", argc=argc)

        def exchange(host, port, command, timeout):
            del host, port, timeout
            commands.append(command.argv)
            if command.evidence_id == "boot_sysfs_uevent":
                return Frame("cat", b"MAJOR=259\nMINOR=8\nDEVNAME=sda24\nDEVTYPE=partition\nPARTN=24\nPARTNAME=boot\n")
            if command.evidence_id == "boot_sysfs_size":
                return Frame("cat", b"131072\n")
            if command.evidence_id == "boot_sysfs_ro":
                return Frame("cat", b"0\n")
            if command.evidence_id == "boot_attest_stat_node":
                return Frame("stat", b"mode=0600 uid=0 gid=0 size=0\nrdev=259:8\n")
            if command.evidence_id == "boot_attest_hash":
                return toybox(f"{probe.CONTROL_SHA256}  {probe.BOOT_ATTEST_FILE}".encode(), argc=len(command.argv))
            if command.evidence_id == "boot_attest_size":
                return toybox(f"{probe.BOOT_PREFIX_SIZE} {probe.BOOT_ATTEST_FILE}".encode(), argc=len(command.argv))
            if command.evidence_id == "boot_attest_mknod":
                return Frame("mknodb")
            if command.argv and command.argv[0] == "run":
                return toybox(argc=len(command.argv))
            return Frame(command.argv[0], argc=len(command.argv))

        record = attestation.attest_current_boot(
            "127.0.0.1",
            54321,
            1.0,
            probe.CONTROL_SHA256,
            frames,
            bridge_binding=binding,
            exchange_fn=exchange,
            revalidate_fn=rebind,
        )
        self.assertTrue(record["cleanup_ok"])
        self.assertEqual(record["stat"]["rdev"], "259:8")
        self.assertEqual(record["captured_size"], probe.BOOT_PREFIX_SIZE)
        self.assertIn(("run", "/bin/toybox", "mkdir", "-p", probe.BOOT_ATTEST_DIR), commands)
        self.assertIn(("mknodb", probe.BOOT_ATTEST_NODE, "259", "8"), commands)
        self.assertIn(("run", "/bin/toybox", "dd", f"if={probe.BOOT_ATTEST_NODE}", f"of={probe.BOOT_ATTEST_FILE}", "bs=4096", "count=14864", "conv=fsync", "status=none"), commands)
        self.assertIn(("run", "/bin/toybox", "sha256sum", probe.BOOT_ATTEST_FILE), commands)
        self.assertIn(("run", "/bin/toybox", "wc", "-c", probe.BOOT_ATTEST_FILE), commands)
        self.assertTrue(record["binding_events"])

    def test_wrong_stat_metadata_fails_closed_before_capture(self) -> None:
        frames: list[dict[str, object]] = []
        commands: list[str] = []
        binding = {"serial": "pinned", "pid": 1}

        def exchange(host, port, command, timeout):
            del host, port, timeout
            commands.append(command.evidence_id)
            if command.evidence_id == "boot_sysfs_uevent":
                return Frame("cat", b"MAJOR=259\nMINOR=8\nDEVNAME=sda24\nDEVTYPE=partition\nPARTN=24\nPARTNAME=boot\n")
            if command.evidence_id == "boot_sysfs_size":
                return Frame("cat", b"131072\n")
            if command.evidence_id == "boot_sysfs_ro":
                return Frame("cat", b"0\n")
            if command.evidence_id == "boot_attest_stat_node":
                return Frame("stat", b"mode=0644 uid=0 gid=0 size=0\nrdev=259:8\n")
            return Frame(command.argv[0], b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n")

        with self.assertRaises(probe.ProbeError):
            attestation.attest_current_boot(
                "127.0.0.1", 54321, 1.0, probe.CONTROL_SHA256, frames,
                bridge_binding=binding,
                exchange_fn=exchange,
                revalidate_fn=lambda initial: dict(initial),
            )
        self.assertNotIn("boot_attest_capture", commands)

    def test_absence_requires_toybox_test_and_rejects_output(self) -> None:
        frames: list[dict[str, object]] = []
        commands: list[tuple[str, ...]] = []

        def exchange(host, port, command, timeout):
            del host, port, timeout
            commands.append(command.argv)
            return Frame("run", b"run: pid=1, q/Ctrl-C cancels\nunexpected\n[exit 0]\n")

        with self.assertRaises(probe.ProbeError):
            attestation.verify_v024_temp_absence(
                "127.0.0.1", 54321, 1.0, frames, exchange_fn=exchange
            )
        self.assertEqual(commands[0][:5], ("run", "/bin/toybox", "test", "!", "-e"))


if __name__ == "__main__":
    unittest.main()
