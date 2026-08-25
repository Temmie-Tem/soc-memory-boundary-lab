from __future__ import annotations

import contextlib
import io
import unittest

from tools import a90_param_debug_transition as transition


class A90ParamDebugTransitionTests(unittest.TestCase):
    def test_host_images_match_both_complete_hash_pins(self) -> None:
        original, modified = transition.derive_images()
        self.assertEqual(transition.sha256(original), transition.ROLLBACK_SHA256)
        self.assertEqual(transition.sha256(modified), transition.MID_SHA256)
        differences = [
            index for index, pair in enumerate(zip(original, modified)) if pair[0] != pair[1]
        ]
        self.assertEqual(
            differences,
            [
                transition.PARAM_DEBUG_OFFSET + 1,
                transition.PARAM_DEBUG_OFFSET + 2,
                transition.PARAM_DEBUG_OFFSET + 3,
            ],
        )

    def test_transitions_are_exact_inverses(self) -> None:
        original, modified = transition.derive_images()
        apply_before, apply_after = transition.transition_images(
            transition.TRANSITIONS["apply-mid"], original, modified
        )
        restore_before, restore_after = transition.transition_images(
            transition.TRANSITIONS["restore-low"], original, modified
        )
        self.assertEqual((apply_before, apply_after), (original, modified))
        self.assertEqual((restore_before, restore_after), (modified, original))

    def test_dd_target_offset_and_extent_are_fixed(self) -> None:
        args = transition.fixed_dd_args("/tmp/in", "/dev/fixed")
        self.assertIn("bs=4", args)
        self.assertIn("count=1", args)
        self.assertIn("seek=2359296", args)
        self.assertIn("conv=notrunc,fsync", args)
        self.assertEqual(transition.DD_SEEK_BLOCKS * 4, 0x900000)

    def test_cli_has_no_partition_offset_or_value_inputs(self) -> None:
        parser = transition.build_parser()
        parsed = parser.parse_args(
            ["--experiment-id", "test", "--action", "apply-mid", "--execute"]
        )
        self.assertTrue(parsed.execute)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "--experiment-id",
                        "test",
                        "--action",
                        "apply-mid",
                        "--offset",
                        "0",
                    ]
                )


if __name__ == "__main__":
    unittest.main()
