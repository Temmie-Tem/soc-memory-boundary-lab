from __future__ import annotations

import base64
import unittest
from unittest import mock

from tools import a90_autohud_arbitration as hud


class Frame:
    def __init__(self, rc: int, status: str, *, command: str = "stophud") -> None:
        self.payload = b"hud"
        self.transcript = b"frame"
        self.begin = {"cmd": command, "seq": "1"}
        self.end = {"cmd": command, "seq": "1", "rc": str(rc), "status": status}


class AutohudArbitrationTests(unittest.TestCase):
    def test_only_busy_is_retried_and_every_attempt_is_retained(self) -> None:
        calls: list[tuple[tuple[str, ...], bool]] = []
        frames = [Frame(-16, "busy"), Frame(-16, "busy"), Frame(0, "ok")]
        outcomes = iter(frames)
        records: list[dict[str, object]] = []
        persisted: list[list[dict[str, object]]] = []

        def exchange(host, port, command, timeout, *, allow_error=False):
            del host, port, timeout
            calls.append((command.argv, allow_error))
            return next(outcomes)

        result = hud.run_stophud(
            "127.0.0.1",
            54321,
            1.0,
            exchange,
            frame_records=records,
            persist=lambda items: persisted.append(items),
            sleep_fn=lambda delay: None,
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["busy_retries"], 2)
        self.assertEqual(calls, [(hud.STOPHUD_ARGV, True)] * 3)
        self.assertEqual(len(records), 3)
        self.assertEqual(len(persisted), 3)
        self.assertEqual([item["rc"] for item in result["attempts"]], [-16, -16, 0])
        for record, frame in zip(records, frames):
            self.assertEqual(
                base64.b64decode(record["payload_base64"]), frame.payload
            )
            self.assertEqual(
                base64.b64decode(record["transcript_base64"]), frame.transcript
            )
            self.assertEqual(record["payload_size"], len(frame.payload))
            self.assertEqual(record["payload_sha256"], hud._sha256(frame.payload))
            self.assertEqual(record["transcript_size"], len(frame.transcript))
            self.assertEqual(
                record["transcript_sha256"], hud._sha256(frame.transcript)
            )
            self.assertEqual(record["begin"], frame.begin)
            self.assertEqual(record["end"], frame.end)

    def test_nonbusy_failure_is_not_retried(self) -> None:
        calls = 0

        def exchange(*args, **kwargs):
            nonlocal calls
            calls += 1
            return Frame(1, "error")

        with self.assertRaisesRegex(hud.StopHudError, "rc=1"):
            hud.run_stophud("127.0.0.1", 54321, 1.0, exchange, sleep_fn=lambda _: None)
        self.assertEqual(calls, 1)

    def test_transport_exception_is_not_retried(self) -> None:
        calls = 0
        records: list[dict[str, object]] = []
        persisted: list[list[dict[str, object]]] = []

        def exchange(*args, **kwargs):
            nonlocal calls
            calls += 1
            raise TimeoutError("bridge timeout")

        with self.assertRaises(TimeoutError):
            hud.run_stophud(
                "127.0.0.1",
                54321,
                1.0,
                exchange,
                frame_records=records,
                persist=lambda items: persisted.append(items),
                sleep_fn=lambda _: None,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(records[0]["transport_error_type"], "TimeoutError")
        self.assertEqual(len(persisted), 1)

    def test_transport_partial_frame_is_retained(self) -> None:
        class Partial:
            payload = b"partial-payload"
            transcript = b"partial-transcript"
            begin = {"cmd": "stophud", "seq": "2"}
            end = None

        error = TimeoutError("partial disconnect")
        error.partial = Partial()  # type: ignore[attr-defined]

        records: list[dict[str, object]] = []
        with self.assertRaises(TimeoutError):
            hud.run_stophud(
                "127.0.0.1",
                54321,
                1.0,
                lambda *args, **kwargs: (_ for _ in ()).throw(error),
                frame_records=records,
            )
        self.assertEqual(records[0]["partial_payload_size"], len(Partial.payload))
        self.assertEqual(records[0]["partial_transcript_size"], len(Partial.transcript))

    def test_wrong_frame_command_is_not_retried(self) -> None:
        calls = 0

        def exchange(*args, **kwargs):
            nonlocal calls
            calls += 1
            return Frame(0, "ok", command="version")

        with self.assertRaisesRegex(hud.StopHudError, "command/sequence"):
            hud.run_stophud("127.0.0.1", 54321, 1.0, exchange)
        self.assertEqual(calls, 1)

    def test_rc_zero_is_idempotent_success_and_postboot_bound_can_be_one_attempt(self) -> None:
        exchange = mock.Mock(return_value=Frame(0, "ok"))
        result = hud.run_stophud(
            "127.0.0.1", 54321, 1.0, exchange, max_attempts=1, sleep_fn=lambda _: None
        )
        self.assertTrue(result["accepted"])
        exchange.assert_called_once()
        with self.assertRaisesRegex(hud.StopHudError, "max_attempts"):
            hud.run_stophud(
                "127.0.0.1", 54321, 1.0, exchange, max_attempts=4, sleep_fn=lambda _: None
            )
        with self.assertRaisesRegex(hud.StopHudError, "finite"):
            hud.run_stophud("127.0.0.1", 54321, float("inf"), exchange)


if __name__ == "__main__":
    unittest.main()
