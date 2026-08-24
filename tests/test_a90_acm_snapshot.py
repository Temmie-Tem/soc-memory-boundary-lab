from __future__ import annotations

import unittest

from tools import a90_acm_snapshot as snapshot


def frame(command: str, payload: bytes, *, seq: int = 4) -> bytes:
    return (
        b"prompt noise\r\n"
        + f"A90P1 BEGIN seq={seq} cmd={command} argc=2 flags=0x0\r\n".encode()
        + payload
        + b"\r\n[done] cat (1ms)\r\n"
        + (
            f"A90P1 END seq={seq} cmd={command} rc=0 errno=0 "
            "duration_ms=1 flags=0x0 status=ok\r\n"
        ).encode()
        + b"a90:/# "
    )


class SnapshotParserTests(unittest.TestCase):
    def test_zero_length_success_payload(self) -> None:
        raw = (
            b"A90P1 BEGIN seq=9 cmd=mknodb argc=4 flags=0x0\r\n"
            b"[done] mknodb (0ms)\r\n"
            b"A90P1 END seq=9 cmd=mknodb rc=0 errno=0 duration_ms=0 "
            b"flags=0x0 status=ok\r\n"
        )
        parsed = snapshot.parse_last_frame(raw, "mknodb")
        self.assertEqual(parsed.payload, b"")

    def test_binary_payload_is_not_decoded(self) -> None:
        payload = bytes.fromhex("00000000b02000000000000000200000")
        parsed = snapshot.parse_last_frame(frame("cat", payload), "cat")
        self.assertEqual(parsed.payload, payload)
        self.assertEqual(
            snapshot.parse_dt_reg(parsed.payload),
            {
                "cells": ["0x00000000", "0xb0200000", "0x00000000", "0x00200000"],
                "base": "0xb0200000",
                "size": "0x200000",
                "end_inclusive": "0xb03fffff",
            },
        )

    def test_last_complete_frame_is_selected(self) -> None:
        combined = frame("version", b"old", seq=1) + frame("cat", b"new", seq=2)
        self.assertEqual(snapshot.parse_last_frame(combined, "cat").payload, b"new")

    def test_command_mismatch_and_missing_done_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "command mismatch"):
            snapshot.parse_last_frame(frame("cat", b"x"), "ls")
        bad = frame("cat", b"x").replace(b"[done] cat (1ms)", b"not-done")
        with self.assertRaisesRegex(ValueError, "terminal"):
            snapshot.parse_last_frame(bad, "cat")

    def test_error_frame_is_parsed_without_promoting_success(self) -> None:
        raw = (
            b"A90P1 BEGIN seq=10 cmd=run argc=5 flags=0x0\r\n"
            b"run: pid=44, q/Ctrl-C cancels\r\n"
            b"mmap: Operation not permitted\r\n"
            b"[exit 1]\r\n"
            b"[err] run rc=1 (2ms)\r\n"
            b"A90P1 END seq=10 cmd=run rc=1 errno=0 duration_ms=2 "
            b"flags=0x0 status=error\r\n"
            b"a90:/# "
        )
        parsed = snapshot.parse_last_frame(raw, "run")
        self.assertEqual(parsed.end["status"], "error")
        self.assertIn(b"Operation not permitted", parsed.payload)

    def test_dt_reg_rejects_partial_cell(self) -> None:
        with self.assertRaises(ValueError):
            snapshot.parse_dt_reg(b"\x00\x01")


if __name__ == "__main__":
    unittest.main()
