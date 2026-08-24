from __future__ import annotations

import contextlib
import io
import unittest

from tools import a90_inline_remapper_probe as probe


class FakeSession:
    def __init__(self, values: list[int]) -> None:
        self.values = values
        self.calls: list[tuple[int, tuple[int, ...], bool]] = []

    def _op_values(
        self, op: int, args: tuple[int, ...], *, replay_safe: bool
    ) -> list[int]:
        self.calls.append((op, args, replay_safe))
        return self.values


class InlineProbeTests(unittest.TestCase):
    def test_fixed_op_has_no_arguments_and_is_not_replayed(self) -> None:
        session = FakeSession([probe.CONTROL_SENTINEL])
        self.assertEqual(probe.run_fixed_inline_op(session), probe.CONTROL_SENTINEL)
        self.assertEqual(session.calls, [(probe.OP_FIXED_READ, (), False)])

    def test_multiple_results_are_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            probe.run_fixed_inline_op(FakeSession([1, 2]))

    def test_mode_specific_classification(self) -> None:
        self.assertEqual(
            probe.classify_value(probe.MODE_CONTROL, probe.CONTROL_SENTINEL),
            "CONTROL_PASS",
        )
        self.assertEqual(
            probe.classify_value(probe.MODE_CONTROL, 0), "CONTROL_UNEXPECTED"
        )
        self.assertEqual(probe.classify_value(probe.MODE_READ, 0), "READABLE")
        self.assertEqual(
            probe.classify_value(probe.MODE_READ, probe.MAP_FAILURE_RESULT),
            "MAP_FAILED",
        )

    def test_cli_rejects_arbitrary_live_inputs(self) -> None:
        parser = probe.make_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--experiment-id", "x", "--address", "0x0"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["--experiment-id", "x", "--call-target", "0x0"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["--experiment-id", "x", "--retry", "1"])

    def test_experiment_id_pattern_rejects_path_components(self) -> None:
        self.assertIsNone(probe.SAFE_ID_RE.fullmatch("../escape"))


if __name__ == "__main__":
    unittest.main()
