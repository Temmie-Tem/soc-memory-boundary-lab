"""Tests for the Verification 019 suspend/permutation analysis.

The result this module reports is a null, so what needs pinning is everything
that could make a null meaningless.  A null is admissible only if the tags were
readable before the state change *and* the state change demonstrably happened,
and each way of failing either condition is tested to clear
`invariance_is_admissible` rather than quietly pass.

The other half is that the detector can see a permutation at all.  splitmix64
is a bijection, so a moved tag names its own source exactly; the synthetic
control permutes one address bit and every decoded move must point back to it.
"""

from __future__ import annotations

import json
import pathlib
import re
import unittest

from tools import a90_suspend_permutation_analysis as sp

SEED = 0x5DA9F0E3C17B2846
PROBE_SOURCE = (pathlib.Path(__file__).resolve().parents[1]
                / "tools" / "a90_suspend_permute_probe.c")


def run(**kwargs) -> dict:
    params = dict(seed=SEED, tags=4096, stride=64, permuted_bit=None)
    params.update(kwargs)
    return sp.analyse(sp.parse(sp.simulate(**params)))


class MixTests(unittest.TestCase):
    def test_unmix_inverts_mix(self):
        for value in (0, 1, 2, 0xDEAD, 1 << 63, sp.MASK64, 0x5DA9F0E3C17B2846):
            self.assertEqual(sp.unmix(sp.mix(value)), value, hex(value))

    def test_mix_is_injective_over_a_sample(self):
        seen = {sp.mix(v) for v in range(4096)}
        self.assertEqual(len(seen), 4096)

    def test_decode_move_names_the_source_offset(self):
        offset = 0x12340
        self.assertEqual(sp.decode_move(sp.tag_for(offset, SEED), SEED), offset)

    def test_a_value_that_is_not_a_tag_decodes_to_none_or_itself(self):
        # unmix always returns something; decode_move must verify the round
        # trip rather than trust it.  A tag of a negative offset is rejected
        # because tag_for() of the decoded value would not match.
        stray = 0x0123456789ABCDEF
        decoded = sp.decode_move(stray, SEED)
        self.assertTrue(decoded is None or sp.tag_for(decoded, SEED) == stray)


class ProbeAgreementTests(unittest.TestCase):
    """The synthetic control only validates the probe if both compute the same
    tags and use the same stride."""

    def setUp(self):
        self.source = PROBE_SOURCE.read_text()

    def test_splitmix_constants_match_the_probe(self):
        for constant in (sp.ADD, sp.MUL1, sp.MUL2):
            self.assertIn(f"0x{constant:x}", self.source.lower(),
                          f"probe lost constant 0x{constant:x}")

    def test_tag_stride_matches_the_probe(self):
        match = re.search(r"#define TAG_SHIFT (\d+)U", self.source)
        self.assertIsNotNone(match)
        self.assertEqual(1 << int(match.group(1)), 64)

    def test_probe_verifies_the_baseline_before_suspending(self):
        # A baseline pass after the state change would prove nothing.  The
        # header comment also names /sys/power/state, so anchor on the call.
        body = self.source
        self.assertLess(body.index('\\"type\\":\\"baseline'),
                        body.index('open("/sys/power/state"'))

    def test_probe_reads_the_tags_back_after_suspending(self):
        body = self.source
        self.assertLess(body.index('open("/sys/power/state"'),
                        body.index('\\"type\\":\\"moved'))


class PositiveControlTests(unittest.TestCase):
    def test_a_permuted_bit_is_detected(self):
        result = run(permuted_bit=12)
        self.assertEqual(result["verdict"], "MAP_CHANGED")
        self.assertFalse(result["invariance_is_admissible"])

    def test_every_move_decodes_back_to_the_permuted_bit(self):
        result = run(permuted_bit=12)
        self.assertTrue(result["decoded_moves"])
        for move in result["decoded_moves"]:
            self.assertEqual(move["delta"], hex(1 << 12))

    def test_permutations_at_several_bits_are_all_found(self):
        for bit in (6, 7, 11):
            result = run(permuted_bit=bit, tags=4096, stride=64)
            self.assertEqual(result["verdict"], "MAP_CHANGED", f"bit {bit}")
            self.assertEqual(result["decoded_moves"][0]["delta"], hex(1 << bit))


class NegativeControlTests(unittest.TestCase):
    def test_an_unchanged_map_is_admissible(self):
        result = run()
        self.assertEqual(result["verdict"], "MAP_INVARIANT")
        self.assertEqual(result["moved"], 0)
        self.assertTrue(result["invariance_is_admissible"])

    def test_the_suspended_interval_is_reported(self):
        self.assertEqual(run(suspended_seconds=25.0)["suspended_seconds"], 25.0)


class GateTests(unittest.TestCase):
    """No way of failing a precondition may yield an admissible invariance."""

    def test_a_failed_baseline_fails_the_instrument(self):
        result = run(baseline_bad=17)
        self.assertEqual(result["verdict"], "INSTRUMENT_FAILED")
        self.assertFalse(result["invariance_is_admissible"])
        self.assertIn("tags did not read back before the state change",
                      result["gate_reasons"])

    def test_a_run_that_never_suspended_is_not_an_invariance(self):
        result = run(suspended_seconds=0.0)
        self.assertEqual(result["verdict"], "SUSPEND_NOT_REACHED")
        self.assertFalse(result["invariance_is_admissible"])

    def test_a_suspend_the_kernel_counter_does_not_corroborate_is_refused(self):
        result = run(suspended_seconds=25.0, stats_advance=False)
        self.assertEqual(result["verdict"], "SUSPEND_NOT_REACHED")
        self.assertFalse(result["suspend_corroborated_by_stats"])

    def test_a_sub_second_gap_does_not_count_as_a_suspend(self):
        result = run(suspended_seconds=0.4)
        self.assertEqual(result["verdict"], "SUSPEND_NOT_REACHED")

    def test_a_transcript_with_no_summary_fails_the_instrument(self):
        records = [r for r in sp.parse(sp.simulate(SEED, 4096, 64, None))
                   if r.get("type") != "summary"]
        result = sp.analyse(records)
        self.assertEqual(result["verdict"], "INSTRUMENT_FAILED")
        self.assertFalse(result["invariance_is_admissible"])

    def test_an_empty_transcript_is_not_an_invariance(self):
        result = sp.analyse([])
        self.assertEqual(result["verdict"], "INSTRUMENT_FAILED")
        self.assertFalse(result["invariance_is_admissible"])

    def test_foreign_records_are_ignored(self):
        self.assertEqual(sp.parse('{"schema":"a90_alias_marker_v1"}'), [])


class SelfTestTests(unittest.TestCase):
    def test_the_module_self_test_passes(self):
        result = sp.self_test()
        self.assertTrue(result["passed"])
        self.assertTrue(
            result["positive"]["every_move_decoded_to_the_permuted_bit"])

    def test_the_cli_refuses_without_a_passing_control(self):
        import tempfile

        original = sp.self_test
        sp.self_test = lambda *a, **k: {"passed": False}
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "m.json"
                with self.assertRaises(sp.PermutationError):
                    sp.main(["--output", str(output)])
        finally:
            sp.self_test = original

    def test_the_cli_writes_a_manifest(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "m.json"
            self.assertEqual(sp.main(["--output", str(output)]), 0)
            self.assertTrue(json.loads(output.read_text())["self_test"]["passed"])


if __name__ == "__main__":
    unittest.main()
