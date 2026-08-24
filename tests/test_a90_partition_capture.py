from __future__ import annotations

import contextlib
import io
import unittest

from tools import a90_partition_capture as capture


def binary_frame(payload: bytes, *, seq: int = 11) -> bytes:
    return (
        b"a90:/# cmdv1 cat /dev/test\r\n"
        + f"A90P1 BEGIN seq={seq} cmd=cat argc=2 flags=0x0\r\n".encode()
        + payload
        + b"\r\n[done] cat (9ms)\r\n"
        + (
            f"A90P1 END seq={seq} cmd=cat rc=0 errno=0 duration_ms=9 "
            "flags=0x0 status=ok\r\n"
        ).encode()
        + b"a90:/# "
    )


class PartitionCaptureTests(unittest.TestCase):
    def test_binary_parser_uses_advertised_size_not_embedded_marker(self) -> None:
        payload = b"\x00firmware\r\nA90P1 END fake\r\n\xfftail"
        fields, parsed = capture.parse_binary_frame(binary_frame(payload), len(payload))
        self.assertEqual(parsed, payload)
        self.assertEqual(fields["status"], "ok")

    def test_binary_parser_rejects_wrong_size_or_trailer(self) -> None:
        payload = b"abcd"
        with self.assertRaisesRegex(ValueError, "trailer"):
            capture.parse_binary_frame(binary_frame(payload), len(payload) - 1)
        bad = binary_frame(payload).replace(b"[done] cat", b"[done] write")
        with self.assertRaisesRegex(ValueError, "trailer"):
            capture.parse_binary_frame(bad, len(payload))

    def test_parse_uevent(self) -> None:
        parsed = capture.parse_uevent(
            b"MAJOR=8\nMINOR=17\nDEVNAME=sdb1\nDEVTYPE=partition\nPARTNAME=xbl\n"
        )
        self.assertEqual(parsed["PARTNAME"], "xbl")
        with self.assertRaises(ValueError):
            capture.parse_uevent(b"MAJOR=8\nMAJOR=9\n")

    def test_partition_validation_and_selection(self) -> None:
        xbl = capture.Partition("xbl", "sdb1", 8, 17, 8192, 4194304, 1, 4096)
        capture.validate_partition(xbl)
        self.assertEqual(capture.select_partitions([xbl], ["xbl"]), [xbl])
        with self.assertRaisesRegex(ValueError, "not found"):
            capture.select_partitions([xbl], ["hyp"])
        with self.assertRaisesRegex(ValueError, "not sysfs read-only"):
            capture.validate_partition(
                capture.Partition("xbl", "sdb1", 8, 17, 8192, 4194304, 0, 4096)
            )

    def test_cli_does_not_accept_arbitrary_partition(self) -> None:
        parser = capture.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    ["--experiment-id", "x", "--partname", "userdata"]
                )


if __name__ == "__main__":
    unittest.main()
