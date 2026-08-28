from __future__ import annotations

import base64
import unittest
from unittest import mock

from tools import a90_autohud_arbitration as hud


class Frame:
    def __init__(
        self,
        rc: int,
        status: str,
        *,
        command: str = "stophud",
        payload: bytes | None = None,
    ) -> None:
        if payload is None:
            payload = b"autohud: stopped" if rc == 0 and status == "ok" else b""
        self.payload = payload
        self.begin = {"cmd": command, "seq": "1", "argc": "1", "flags": "0x8"}
        self.end = {
            "cmd": command,
            "seq": "1",
            "rc": str(rc),
            "errno": str(abs(rc)),
            "duration_ms": "0",
            "flags": "0x8",
            "status": status,
        }
        terminal = (
            f"[done] {command} (0ms)\r\n".encode("ascii")
            if rc == 0 and status == "ok"
            else (
                b"[busy] auto menu active; send hide/q before command\r\n"
                if rc == -16 and status == "busy"
                else f"[err] {command} rc={rc} (0ms)\r\n".encode("ascii")
            )
        )
        self.transcript = (
            b"A90P1 BEGIN seq=1 cmd="
            + command.encode("ascii")
            + b" argc=1 flags=0x8\r\n"
            + payload
            + b"\r\n"
            + terminal
            + b"A90P1 END seq=1 cmd="
            + command.encode("ascii")
            + b" rc="
            + str(rc).encode("ascii")
            + b" errno="
            + str(abs(rc)).encode("ascii")
            + b" duration_ms=0 flags=0x8 status="
            + status.encode("ascii")
            + b"\r\n"
        )


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

    def test_both_success_payloads_are_accepted(self) -> None:
        for payload in sorted(hud.STOPHUD_SUCCESS_PAYLOADS):
            with self.subTest(payload=payload):
                result = hud.run_stophud(
                    "127.0.0.1",
                    54321,
                    1.0,
                    lambda *args, payload=payload, **kwargs: Frame(
                        0, "ok", payload=payload
                    ),
                )
                self.assertTrue(result["accepted"])

    def test_success_payload_variants_and_busy_nonempty_are_rejected_without_retry(self) -> None:
        invalid_success = (
            b"",
            b"autohud: stopped\n",
            b"autohud: not running\r\n",
            b" autohud: stopped",
            b"autohud: stopped extra",
            b"AUTOHUD: STOPPED",
            b"arbitrary",
        )
        for payload in invalid_success:
            with self.subTest(payload=payload):
                calls = 0
                records: list[dict[str, object]] = []

                def exchange(*args, payload=payload, **kwargs):
                    nonlocal calls
                    calls += 1
                    return Frame(0, "ok", payload=payload)

                with self.assertRaisesRegex(hud.StopHudError, "payload"):
                    hud.run_stophud(
                        "127.0.0.1",
                        54321,
                        1.0,
                        exchange,
                        frame_records=records,
                        sleep_fn=lambda _: None,
                    )
                self.assertEqual(calls, 1)
                self.assertEqual(len(records), 1)

        calls = 0
        records = []

        def busy_exchange(*args, **kwargs):
            nonlocal calls
            calls += 1
            return Frame(-16, "busy", payload=b"autohud: stopped")

        with self.assertRaisesRegex(hud.StopHudError, "payload"):
            hud.run_stophud(
                "127.0.0.1",
                54321,
                1.0,
                busy_exchange,
                frame_records=records,
                sleep_fn=lambda _: None,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(len(records), 1)

    def test_terminal_rc_is_canonical_and_missing_wire_is_not_empty_provenance(self) -> None:
        for raw_rc in ("0x0", "00", "+0", "-0", " -16", "-16 ", "-0x10"):
            with self.subTest(raw_rc=raw_rc):
                frame = Frame(0, "ok")
                frame.end["rc"] = raw_rc
                records: list[dict[str, object]] = []
                persisted: list[list[dict[str, object]]] = []
                with self.assertRaisesRegex(hud.StopHudError, "rc="):
                    hud.run_stophud(
                        "127.0.0.1",
                        54321,
                        1.0,
                        lambda *args, frame=frame, **kwargs: frame,
                        frame_records=records,
                        persist=lambda attempts: persisted.append(attempts),
                    )
                self.assertEqual(len(records), 1)
                self.assertEqual(len(persisted), 1)
                self.assertIn("validation_error", persisted[0][0])
                self.assertNotIn("transport_error", persisted[0][0])

        class MissingWire:
            begin = {"cmd": "stophud", "seq": "1", "argc": "1", "flags": "0x8"}
            end = {
                "cmd": "stophud",
                "seq": "1",
                "rc": "-16",
                "errno": "16",
                "duration_ms": "0",
                "flags": "0x8",
                "status": "busy",
            }

        records = []
        persisted = []
        with self.assertRaisesRegex(hud.StopHudError, "payload"):
            hud.run_stophud(
                "127.0.0.1",
                54321,
                1.0,
                lambda *args, **kwargs: MissingWire(),
                frame_records=records,
                persist=lambda attempts: persisted.append(attempts),
            )
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0]["payload_size"])
        self.assertIsNone(records[0]["payload_sha256"])
        self.assertIsNone(records[0]["payload_base64"])
        self.assertIsNone(records[0]["transcript_size"])
        self.assertIsNone(records[0]["transcript_sha256"])
        self.assertIsNone(records[0]["transcript_base64"])
        self.assertEqual(len(persisted), 1)
        self.assertIn("validation_error", persisted[0][0])
        self.assertNotIn("transport_error", persisted[0][0])

    def test_terminal_marker_and_post_end_tail_are_source_exact(self) -> None:
        attacks = []
        forged_marker = Frame(0, "ok")
        forged_marker.transcript = forged_marker.transcript.replace(
            b"[done] stophud (0ms)", b"[done] forged (0ms)"
        )
        attacks.append(forged_marker)
        cross_kind_success = Frame(0, "ok")
        cross_kind_success.transcript = cross_kind_success.transcript.replace(
            b"[done] stophud (0ms)",
            b"[busy] auto menu active; send hide/q before command",
        )
        attacks.append(cross_kind_success)
        cross_kind_busy = Frame(-16, "busy")
        cross_kind_busy.transcript = cross_kind_busy.transcript.replace(
            b"[busy] auto menu active; send hide/q before command",
            b"[done] stophud (0ms)",
        )
        attacks.append(cross_kind_busy)
        for tail in (b"garbage", b"a90:/#\n", b"a90:/#  "):
            forged_tail = Frame(0, "ok")
            forged_tail.transcript += tail
            attacks.append(forged_tail)

        for frame in attacks:
            with self.subTest(transcript=frame.transcript):
                records: list[dict[str, object]] = []
                persisted: list[list[dict[str, object]]] = []
                with self.assertRaises(hud.StopHudError):
                    hud.run_stophud(
                        "127.0.0.1",
                        54321,
                        1.0,
                        lambda *args, frame=frame, **kwargs: frame,
                        frame_records=records,
                        persist=lambda attempts: persisted.append(attempts),
                    )
                self.assertEqual(len(records), 1)
                self.assertEqual(len(persisted), 1)
                self.assertIn("validation_error", persisted[0][0])
                self.assertNotIn("transport_error", persisted[0][0])

    def test_protocol_fields_are_exact_and_coherent(self) -> None:
        mutations = (
            ("begin", "argc", "2"),
            ("begin", "flags", "0x0"),
            ("begin", "seq", "01"),
            ("end", "seq", "2"),
            ("end", "errno", "16"),
            ("end", "duration_ms", "00"),
            ("end", "status", "busy"),
        )
        for section, field, replacement in mutations:
            with self.subTest(section=section, field=field):
                frame = Frame(0, "ok")
                getattr(frame, section)[field] = replacement
                records: list[dict[str, object]] = []
                persisted: list[list[dict[str, object]]] = []
                with self.assertRaises(hud.StopHudError):
                    hud.run_stophud(
                        "127.0.0.1",
                        54321,
                        1.0,
                        lambda *args, frame=frame, **kwargs: frame,
                        frame_records=records,
                        persist=lambda attempts: persisted.append(attempts),
                    )
                self.assertEqual(len(records), 1)
                self.assertEqual(len(persisted), 1)
                self.assertIn("validation_error", persisted[0][0])
                self.assertNotIn("transport_error", persisted[0][0])

    def test_shared_evidence_bounds_have_exact_boundaries(self) -> None:
        self.assertEqual(
            hud.validate_stophud_evidence_sizes(b"x" * 19, b"x" * 4095),
            (b"x" * 19, b"x" * 4095),
        )
        self.assertEqual(
            hud.validate_stophud_evidence_sizes(
                b"x" * hud.STOPHUD_MAX_PAYLOAD_BYTES,
                b"x" * hud.STOPHUD_MAX_TRANSCRIPT_BYTES,
            ),
            (b"x" * 20, b"x" * 4096),
        )
        with self.assertRaises(hud.StopHudError):
            hud.validate_stophud_evidence_sizes(b"x" * 21, b"x" * 4096)
        with self.assertRaises(hud.StopHudError):
            hud.validate_stophud_evidence_sizes(b"x" * 20, b"x" * 4097)

        base = Frame(0, "ok")
        for target in (
            hud.STOPHUD_MAX_TRANSCRIPT_BYTES - 1,
            hud.STOPHUD_MAX_TRANSCRIPT_BYTES,
        ):
            with self.subTest(target=target):
                frame = Frame(0, "ok")
                prefix_size = target - len(frame.transcript)
                self.assertGreater(prefix_size, 0)
                frame.transcript = b"x" * (prefix_size - 1) + b"\n" + frame.transcript
                result = hud.run_stophud(
                    "127.0.0.1",
                    54321,
                    1.0,
                    lambda *args, frame=frame, **kwargs: frame,
                )
                self.assertTrue(result["accepted"])

        for oversized in (
            b"x"
            * (hud.STOPHUD_MAX_TRANSCRIPT_BYTES + 1 - len(base.transcript) - 1)
            + b"\n"
            + base.transcript,
            base.transcript + b"x" * (hud.STOPHUD_MAX_TRANSCRIPT_BYTES + 1 - len(base.transcript)),
        ):
            with self.subTest(oversized_len=len(oversized)):
                frame = Frame(0, "ok")
                frame.transcript = oversized
                records: list[dict[str, object]] = []
                with self.assertRaisesRegex(hud.StopHudError, "evidence bound"):
                    hud.run_stophud(
                        "127.0.0.1",
                        54321,
                        1.0,
                        lambda *args, frame=frame, **kwargs: frame,
                        frame_records=records,
                    )
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["transcript_size"], len(oversized))

    def test_shared_callback_owner_rejects_frame_mutation(self) -> None:
        invalid = Frame(0, "ok", payload=b"forged")
        callback = mock.Mock()
        records: list[dict[str, object]] = []
        persisted: list[list[dict[str, object]]] = []
        with self.assertRaises(hud.StopHudError):
            hud.run_stophud(
                "127.0.0.1",
                54321,
                1.0,
                lambda *args, **kwargs: invalid,
                frame_records=records,
                persist=lambda attempts: persisted.append(attempts),
                validate_frame=callback,
            )
        callback.assert_not_called()
        self.assertEqual(len(records), 1)
        self.assertEqual(len(persisted), 1)
        self.assertIn("validation_error", persisted[0][0])

        changed = Frame(0, "ok")
        original_payload = changed.payload
        original_transcript = changed.transcript

        def mutate_after_valid(frame: Frame) -> None:
            frame.payload = b"autohud: not running"
            frame.transcript = original_transcript.replace(
                original_payload, frame.payload
            )

        records = []
        persisted = []
        with self.assertRaisesRegex(hud.StopHudError, "mutated"):
            hud.run_stophud(
                "127.0.0.1",
                54321,
                1.0,
                lambda *args, frame=changed, **kwargs: frame,
                frame_records=records,
                persist=lambda attempts: persisted.append(attempts),
                validate_frame=mutate_after_valid,
            )
        self.assertEqual(len(records), 1)
        self.assertEqual(len(persisted), 1)
        self.assertIn("validation_error", persisted[0][0])
        self.assertNotIn("transport_error", persisted[0][0])

        restored = Frame(0, "ok")
        restored_payload = restored.payload
        restored_transcript = restored.transcript

        def mutate_and_restore(frame: Frame) -> None:
            frame.payload = b"autohud: not running"
            frame.transcript = restored_transcript.replace(
                restored_payload, frame.payload
            )
            frame.payload = restored_payload
            frame.transcript = restored_transcript

        result = hud.run_stophud(
            "127.0.0.1",
            54321,
            1.0,
            lambda *args, frame=restored, **kwargs: frame,
            validate_frame=mutate_and_restore,
        )
        self.assertTrue(result["accepted"])

    def test_invalid_frame_provenance_is_persisted_before_rejection(self) -> None:
        records: list[dict[str, object]] = []
        persisted: list[list[dict[str, object]]] = []
        with self.assertRaisesRegex(hud.StopHudError, "command/sequence"):
            hud.run_stophud(
                "127.0.0.1",
                54321,
                1.0,
                lambda *args, **kwargs: Frame(0, "ok", command="version"),
                frame_records=records,
                persist=lambda attempts: persisted.append(attempts),
            )
        self.assertEqual(len(records), 1)
        self.assertEqual(len(persisted), 1)
        self.assertEqual(
            persisted[0][0]["payload_sha256"],
            records[0]["payload_sha256"],
        )

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
