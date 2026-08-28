from __future__ import annotations

import ast
import unittest
from unittest import mock

from tools import a90_param_debug_recovery as core
from tools import a90_param_debug_recovery_effect as effect
from tools import a90_param_capture as capture


class Frame:
    def __init__(self, *, rc: str = "0", status: str = "ok") -> None:
        self.begin = {"cmd": "run", "seq": "9"}
        self.end = {"cmd": "run", "seq": "9", "rc": rc, "status": status}
        self.payload = b""
        self.transcript = b"A90P1"


class ParamDebugRecoveryEffectTests(unittest.TestCase):
    def _run(
        self,
        *,
        classification: str = effect.RECOVERABLE_MID,
        dispatch_result: object | None = None,
        dispatch_error: BaseException | None = None,
        after_hash: str = core.ROLLBACK_SHA256,
        persist_error_at: int | None = None,
        stage_error: BaseException | None = None,
        stage_result: object | None = None,
        smoke_result: object | None = None,
        capture_image: bytes | None = None,
        before_byte0: int = 0,
        capture_mutation: str | None = None,
    ) -> tuple[dict[str, object], list[str], list[dict[str, object]], dict[str, mock.Mock]]:
        journal: dict[str, object] = {
            "effect_dispatched": False,
            "effect_replayed": False,
            "write_count": 0,
            "effect_dispatched_count": 0,
            "partition_writes": False,
            "volatile_byte0_before": before_byte0,
        }
        events: list[str] = []
        persisted: list[dict[str, object]] = []
        persist_count = 0

        def persist(value: dict[str, object]) -> None:
            nonlocal persist_count
            persist_count += 1
            events.append("persist")
            persisted.append(dict(value))
            if persist_error_at == persist_count:
                raise RuntimeError("persist failed")

        def fresh_bind() -> dict[str, object]:
            events.append("fresh_bind")
            return {"pid": 1}

        def stage() -> dict[str, object]:
            events.append("stage")
            if stage_error is not None:
                raise stage_error
            if stage_result is not None:
                return stage_result  # type: ignore[return-value]
            return {
                "path": core.PAYLOAD_PATH,
                "size": core.DLOW_PAYLOAD_SIZE,
                "sha256": core.DLOW_PAYLOAD_SHA256,
                "readback_base64": "RExPVw==",
            }

        def smoke() -> dict[str, object]:
            events.append("smoke")
            if smoke_result is not None:
                return smoke_result  # type: ignore[return-value]
            return {
                "args": list(core.SMOKE_DD_ARGS),
                "passed": True,
                "expected_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
                "readback_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
            }

        def dispatch() -> object:
            events.append("dispatch")
            if dispatch_error is not None:
                raise dispatch_error
            return Frame() if dispatch_result is None else dispatch_result

        def full_hash() -> dict[str, object]:
            events.append("full_hash")
            image = core.pinned_images()[0] if capture_image is None else capture_image
            if capture_mutation == "volatile" and capture_image is None:
                # Reproduce the hostile case: the returned raw image contains
                # the observed post-boot byte-0 variant, while the caller's
                # summary lies and reports the pre-image byte.
                variant = bytearray(image)
                variant[0] = 0x02
                image = bytes(variant)
            evidence = capture.stable_param_evidence(image)
            evidence["image"] = image
            if after_hash != core.ROLLBACK_SHA256:
                evidence["sha256"] = after_hash
                evidence["full_sha256"] = after_hash
            if capture_mutation == "volatile":
                evidence["volatile_byte0"] = 0
            elif capture_mutation == "fields":
                forged = dict(evidence["decoded_fields"])
                forged["force_upload_flag"] = dict(forged["force_upload_flag"])
                forged["force_upload_flag"]["value"] = "0x00000005"
                evidence["decoded_fields"] = forged
            return evidence

        callbacks = {
            "persist": mock.Mock(side_effect=persist),
            "fresh_bind": mock.Mock(side_effect=fresh_bind),
            "stage": mock.Mock(side_effect=stage),
            "smoke": mock.Mock(side_effect=smoke),
            "dispatch": mock.Mock(side_effect=dispatch),
            "full_hash": mock.Mock(side_effect=full_hash),
        }
        try:
            effect.coordinate_dlow_effect(
                classification,
                journal,
                callbacks["persist"],
                callbacks["fresh_bind"],
                callbacks["stage"],
                callbacks["smoke"],
                callbacks["dispatch"],
                callbacks["full_hash"],
                capture_device_image=callbacks["full_hash"],
            )
        except BaseException:
            pass
        return journal, events, persisted, callbacks

    def test_exact_order_marker_before_single_dispatch_and_hash(self) -> None:
        journal, events, persisted, callbacks = self._run()
        self.assertEqual(
            events,
            [
                "fresh_bind",
                "stage",
                "smoke",
                "fresh_bind",
                "persist",
                "dispatch",
                "persist",
                "full_hash",
                "persist",
            ],
        )
        self.assertEqual(callbacks["dispatch"].call_count, 1)
        self.assertEqual(callbacks["full_hash"].call_count, 1)
        self.assertEqual(persisted[0]["status"], effect.EFFECT_DISPATCH_STARTED)
        self.assertTrue(persisted[0]["effect_armed"])
        self.assertTrue(persisted[0]["effect_dispatched"])
        self.assertEqual(persisted[0]["write_count"], 1)
        self.assertTrue(persisted[0]["partition_writes"])
        self.assertEqual(persisted[0]["effect_argv"], list(core.FIXED_EFFECT_ARGV))
        self.assertEqual(persisted[0]["current_state"], "UNKNOWN")
        self.assertFalse(persisted[0]["effect_replayed"])
        self.assertEqual(persisted[1]["status"], effect.EFFECT_RETURNED_VERIFYING_FULL_HASH)
        self.assertEqual(persisted[2]["status"], effect.PASS_EFFECT_LOW_VERIFIED)
        self.assertEqual(journal["current_state"], "LOW")
        self.assertFalse(journal["reconcile_required"])

    def test_success_authorizes_cleanup_but_never_calls_cleanup(self) -> None:
        cleanup = mock.Mock()
        journal, _events, _persisted, callbacks = self._run()
        self.assertEqual(journal["status"], effect.PASS_EFFECT_LOW_VERIFIED)
        staged = {
            "path": core.PAYLOAD_PATH,
            "size": core.DLOW_PAYLOAD_SIZE,
            "sha256": core.DLOW_PAYLOAD_SHA256,
            "readback_base64": "RExPVw==",
        }
        smoke = {
            "args": list(core.SMOKE_DD_ARGS),
            "passed": True,
            "expected_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
            "readback_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
        }
        result = effect.coordinate_dlow_effect(
            effect.RECOVERABLE_TORN,
            {
                "effect_dispatched": False,
                "effect_replayed": False,
                "write_count": 0,
                "effect_dispatched_count": 0,
                "partition_writes": False,
                "volatile_byte0_before": 0,
            },
            lambda value: None,
            lambda: None,
            lambda: staged,
            lambda: smoke,
            lambda: Frame(),
            lambda: {
                **capture.stable_param_evidence(core.pinned_images()[0]),
                "image": core.pinned_images()[0],
            },
            capture_device_image=lambda: {
                **capture.stable_param_evidence(core.pinned_images()[0]),
                "image": core.pinned_images()[0],
            },
        )
        self.assertTrue(result["cleanup_authorized"])
        cleanup.assert_not_called()
        self.assertEqual(callbacks["dispatch"].call_count, 1)

    def test_dispatch_exception_is_ambiguous_without_hash_or_post_callbacks(self) -> None:
        journal, events, persisted, callbacks = self._run(
            dispatch_error=TimeoutError("transport lost")
        )
        self.assertEqual(
            events[:6],
            ["fresh_bind", "stage", "smoke", "fresh_bind", "persist", "dispatch"],
        )
        self.assertEqual(callbacks["dispatch"].call_count, 1)
        callbacks["full_hash"].assert_not_called()
        self.assertEqual(persisted[-1]["status"], effect.AMBIGUOUS_STATUS)
        self.assertTrue(journal["reconcile_required"])
        self.assertTrue(journal["cleanup_deferred"])
        self.assertEqual(journal["current_state"], "UNKNOWN")
        self.assertEqual(journal["write_count"], 1)

    def test_malformed_and_nonzero_dispatch_are_ambiguous_without_hash(self) -> None:
        for result in (object(), {"end": {"rc": "0", "status": "bad"}}, Frame(rc="-1")):
            with self.subTest(result=result):
                journal, _events, persisted, callbacks = self._run(dispatch_result=result)
                callbacks["full_hash"].assert_not_called()
                self.assertEqual(persisted[-1]["status"], effect.AMBIGUOUS_STATUS)
                self.assertTrue(journal["cleanup_deferred"])

        malformed_frame = Frame()
        malformed_frame.begin["cmd"] = "cat"
        mismatched_frame = Frame()
        mismatched_frame.end["seq"] = "10"
        for result in (
            {"end": {"cmd": "run", "seq": "9", "rc": "0", "status": "ok"}},
            malformed_frame,
            mismatched_frame,
            {"rc": "0", "status": "ok", "extra": "not-a-direct-end"},
        ):
            with self.subTest(result=result):
                journal, _events, persisted, callbacks = self._run(dispatch_result=result)
                callbacks["full_hash"].assert_not_called()
                self.assertEqual(persisted[-1]["status"], effect.AMBIGUOUS_STATUS)
                self.assertEqual(journal["write_count"], 1)

    def test_stage_or_smoke_receipt_mutation_refuses_before_arm(self) -> None:
        valid_stage = {
            "path": core.PAYLOAD_PATH,
            "size": core.DLOW_PAYLOAD_SIZE,
            "sha256": core.DLOW_PAYLOAD_SHA256,
            "readback_base64": "RExPVw==",
        }
        valid_smoke = {
            "args": list(core.SMOKE_DD_ARGS),
            "passed": True,
            "expected_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
            "readback_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
            "a90p1_end": {"cmd": "run", "rc": "0", "status": "ok"},
        }
        for stage, smoke in (
            ({**valid_stage, "size": 8}, valid_smoke),
            (valid_stage, {**valid_smoke, "passed": False}),
            (valid_stage, {**valid_smoke, "args": ["dd", "if=/tmp/other"]}),
        ):
            with self.subTest(stage=stage, smoke=smoke):
                journal, events, persisted, callbacks = self._run(
                    stage_result=stage,
                    smoke_result=smoke,
                )
                self.assertEqual(events[:2], ["fresh_bind", "stage"])
                self.assertEqual(persisted, [])
                callbacks["dispatch"].assert_not_called()
                callbacks["full_hash"].assert_not_called()
                self.assertEqual(journal["write_count"], 0)

    def test_wrong_low_hash_is_ambiguous_and_never_authorizes_cleanup(self) -> None:
        journal, events, persisted, callbacks = self._run(after_hash="a" * 64)
        self.assertEqual(events[-2:], ["full_hash", "persist"])
        self.assertEqual(callbacks["full_hash"].call_count, 1)
        self.assertEqual(persisted[-1]["status"], effect.AMBIGUOUS_STATUS)
        self.assertFalse(journal.get("cleanup_authorized", False))
        self.assertTrue(journal["reconcile_required"])

    def test_prearm_failure_keeps_zero_write_and_never_dispatches(self) -> None:
        journal, events, persisted, callbacks = self._run(
            stage_error=RuntimeError("stage failed")
        )
        self.assertEqual(events, ["fresh_bind", "stage"])
        self.assertEqual(persisted, [])
        callbacks["dispatch"].assert_not_called()
        callbacks["full_hash"].assert_not_called()
        self.assertEqual(journal["write_count"], 0)
        self.assertEqual(journal["effect_dispatched_count"], 0)
        self.assertFalse(journal["effect_dispatched"])

    def test_marker_persist_failure_keeps_zero_write_and_never_dispatches(self) -> None:
        journal, events, _persisted, callbacks = self._run(persist_error_at=1)
        self.assertEqual(
            events,
            ["fresh_bind", "stage", "smoke", "fresh_bind", "persist"],
        )
        callbacks["dispatch"].assert_not_called()
        callbacks["full_hash"].assert_not_called()
        self.assertEqual(journal["write_count"], 0)
        self.assertFalse(journal["effect_dispatched"])

    def test_post_effect_persist_failure_does_not_hash_or_retry_effect(self) -> None:
        journal, events, persisted, callbacks = self._run(persist_error_at=2)
        self.assertEqual(callbacks["dispatch"].call_count, 1)
        callbacks["full_hash"].assert_not_called()
        self.assertEqual(callbacks["persist"].call_count, 3)
        self.assertEqual(persisted[-1]["status"], effect.AMBIGUOUS_STATUS)
        self.assertTrue(journal["reconcile_required"])
        self.assertNotIn("full_hash", events)

    def test_invalid_classification_refuses_before_callbacks(self) -> None:
        callbacks = [mock.Mock() for _ in range(6)]
        with self.assertRaises(effect.ParamDebugRecoveryEffectError):
            effect.coordinate_dlow_effect(
                core.ALREADY_LOW if hasattr(core, "ALREADY_LOW") else "ALREADY_LOW",
                {},
                *callbacks,
            )
        for callback in callbacks:
            callback.assert_not_called()

    def test_full_only_hash_callback_is_refused_before_any_effect(self) -> None:
        journal = {
            "effect_dispatched": False,
            "effect_replayed": False,
            "write_count": 0,
            "effect_dispatched_count": 0,
            "partition_writes": False,
            "volatile_byte0_before": 0,
        }
        callbacks = [mock.Mock() for _ in range(6)]
        with self.assertRaisesRegex(effect.ParamDebugRecoveryEffectError, "full-only"):
            effect.coordinate_dlow_effect(
                effect.RECOVERABLE_MID,
                journal,
                *callbacks,
            )
        for callback in callbacks:
            callback.assert_not_called()

    def test_post_effect_low_byte0_variant_uses_stable_not_full_pin(self) -> None:
        variant = bytearray(core.pinned_images()[0])
        variant[0] = 0x02
        journal, _events, _persisted, callbacks = self._run(
            capture_image=bytes(variant), before_byte0=0x02
        )
        self.assertEqual(journal["status"], effect.PASS_EFFECT_LOW_VERIFIED)
        self.assertNotEqual(journal["device_sha256_after"], core.ROLLBACK_SHA256)
        self.assertEqual(
            journal["device_stable_sha256_after"], core.PARAM_STABLE_LOW_SHA256
        )
        callbacks["dispatch"].assert_called_once()

    def test_post_effect_reported_observations_must_bind_to_raw_image(self) -> None:
        for mutation in ("volatile", "fields"):
            with self.subTest(mutation=mutation):
                journal, events, persisted, callbacks = self._run(
                    capture_mutation=mutation
                )
                self.assertEqual(journal["status"], effect.AMBIGUOUS_STATUS)
                self.assertTrue(journal["reconcile_required"])
                self.assertTrue(journal["cleanup_deferred"])
                self.assertEqual(callbacks["dispatch"].call_count, 1)
                self.assertEqual(persisted[-1]["status"], effect.AMBIGUOUS_STATUS)
                self.assertNotIn("cleanup", journal)

    def test_import_has_no_device_or_subprocess_imports(self) -> None:
        tree = ast.parse(
            __import__("pathlib").Path(
                "tools/a90_param_debug_recovery_effect.py"
            ).read_text()
        )
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("socket", imported)
        self.assertNotIn("subprocess", imported)


if __name__ == "__main__":
    unittest.main()
