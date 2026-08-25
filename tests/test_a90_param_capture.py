from __future__ import annotations

import struct
import unittest

from tools import a90_param_capture as capture
from tools.a90_partition_capture import Partition


class A90ParamCaptureTests(unittest.TestCase):
    def test_exact_partition_validation(self) -> None:
        partition = Partition(
            "param", "sda10", 8, 10, 20480, 0xA00000, 0, 4096
        )
        capture.validate_param_partition(partition, 125080)
        with self.assertRaisesRegex(ValueError, "10 MiB"):
            capture.validate_param_partition(
                Partition("param", "sda10", 8, 10, 20479, 20479 * 512, 0, 4096),
                125080,
            )
        with self.assertRaisesRegex(ValueError, "read-only state"):
            capture.validate_param_partition(
                Partition("param", "sda10", 8, 10, 20480, 0xA00000, 1, 4096),
                125080,
            )

    def test_field_offsets_and_values(self) -> None:
        data = bytearray(capture.PARAM_PARTITION_BYTES)
        values = {
            "debuglevel": capture.KERNEL_DEBUG_LOW,
            "force_upload_flag": 0,
            "FMM_lock": 0,
            "dump_sink": 0,
        }
        for name, value in values.items():
            struct.pack_into("<I", data, capture.FIELD_OFFSETS[name], value)
        decoded = capture.decode_fields(bytes(data))
        self.assertEqual(decoded["debuglevel"]["partition_offset"], "0x900000")
        self.assertEqual(decoded["force_upload_flag"]["partition_offset"], "0x9003f4")
        self.assertEqual(decoded["FMM_lock"]["partition_offset"], "0x9003fc")
        self.assertEqual(decoded["dump_sink"]["partition_offset"], "0x900400")
        self.assertEqual(decoded["debuglevel"]["label"], "LOW")
        self.assertEqual(decoded["FMM_lock"]["label"], "NOT_LOCK_MAGIC")
        self.assertEqual(decoded["dump_sink"]["label"], "USB_DEFAULT")

    def test_decoder_rejects_non_exact_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "image size"):
            capture.decode_fields(b"\0" * 4096)

    def test_cmdline_and_runtime_binding(self) -> None:
        cmdline = capture.parse_cmdline(
            b"androidboot.em.model=SM-A908N "
            b"androidboot.bootloader=A908NKSU5EWA3 "
            b"androidboot.debug_level=0x4f4c"
        )
        version = (
            b"version: 0.9.285 build=v2321-usb-clean-identity-rodata\n"
            b"kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n"
        )
        capture.validate_runtime(version, cmdline)
        cmdline["androidboot.em.model"] = "SM-S906N"
        with self.assertRaisesRegex(ValueError, "SM-A908N"):
            capture.validate_runtime(version, cmdline)


if __name__ == "__main__":
    unittest.main()
