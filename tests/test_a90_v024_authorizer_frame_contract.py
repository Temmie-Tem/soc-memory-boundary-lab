"""Regression proof for the V024 control authorizer's complete frame gate.

The control producer fixture in ``test_a90_inline_remapper_mid_probe`` is the
source of these receipts.  This test intentionally does not hand-build a
summary: it runs the mocked producer, then removes one retained frame at a
time while rebinding the corresponding private hash/size in the public
manifest.  A consumer that validates only summaries (or only the first few
frames) would accept one of those mutations.
"""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import a90_inline_remapper_mid_probe as probe
from tools import a90_verification024_finalize as finalizer


def _json_bytes(value: object) -> bytes:
    """Use the same deterministic bytes emitted by the mocked producer."""

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_and_rebind(
    path: Path,
    value: dict[str, object],
    manifest_path: Path,
    manifest: dict[str, object],
    *,
    binding_key: str,
    size_key: str,
) -> None:
    data = _json_bytes(value)
    path.write_bytes(data)
    manifest[binding_key] = hashlib.sha256(data).hexdigest()
    manifest[size_key] = len(data)
    manifest_path.write_bytes(_json_bytes(manifest))


class V024AuthorizerFrameContractTests(unittest.TestCase):
    """Prove both consumers reject every omitted complete producer frame."""

    def setUp(self) -> None:
        from tests.test_a90_inline_remapper_mid_probe import (
            InlineRemapperMidProbeTests,
        )

        fixture_builder = InlineRemapperMidProbeTests("run")
        self._capsule, self._capsule_sha256, self._capsule_size = (
            fixture_builder._predecessor_capsule_fixture()
        )
        self._original_finalizer_capsule_sha256 = (
            finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256
        )
        self._original_finalizer_capsule_size = (
            finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE
        )
        self._original_probe_capsule_sha256 = probe.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256
        self._original_probe_capsule_size = probe.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = self._capsule_sha256
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = self._capsule_size
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = self._capsule_sha256
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = self._capsule_size
        self._capsule_builder_patch = mock.patch.object(
            finalizer.control_retry,
            "build_predecessor_capsule",
            return_value=self._capsule,
        )
        self._capsule_builder_patch.start()

    def tearDown(self) -> None:
        self._capsule_builder_patch.stop()
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = (
            self._original_finalizer_capsule_sha256
        )
        finalizer.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = (
            self._original_finalizer_capsule_size
        )
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = self._original_probe_capsule_sha256
        probe.CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = self._original_probe_capsule_size

    @staticmethod
    def _install_r2_incident_manifest(root: Path) -> Path:
        """Install exact committed R2 checkpoint bytes in an isolated root."""

        relative = probe.r2_incident.MANIFEST_RELATIVE_PATH
        source = probe.r2_incident.REPO_ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        # The real validator accepts readable, non-executable, non-world-
        # writable regular files.  Pin a deterministic accepted mode.
        destination.chmod(0o644)
        return destination

    @staticmethod
    def _install_r3_incident_manifest(root: Path) -> Path:
        """Install exact committed R3 checkpoint bytes in an isolated root."""

        relative = probe.r2_incident.R3_MANIFEST_RELATIVE_PATH
        source = probe.r2_incident.REPO_ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o644)
        return destination

    def _collect_control(self, root: Path) -> tuple[Path, Path, Path]:
        # Reuse the existing actual mocked collect path.  Calling the helper
        # on a fixture instance keeps all device-facing work replaced by its
        # exchange mock; this test never contacts a device.
        from tests.test_a90_inline_remapper_mid_probe import (
            InlineRemapperMidProbeTests,
        )

        producer_fixture = InlineRemapperMidProbeTests("run")
        result, _session, _exchange_ids = producer_fixture._run_collect(
            root, probe.MODE_CONTROL
        )
        self.assertIsNotNone(result)
        assert result is not None
        raw_path, manifest_path = result
        journal_path = (
            root
            / "evidence/private"
            / f"{probe.CONTROL_EXPERIMENT_ID}.journal.json"
        )
        self.assertTrue(raw_path.is_file())
        self.assertTrue(manifest_path.is_file())
        self.assertTrue(journal_path.is_file())
        self._install_r2_incident_manifest(root)
        self._install_r3_incident_manifest(root)
        return raw_path, manifest_path, journal_path

    @staticmethod
    def _assert_summary_unchanged(
        before_public: dict[str, object],
        after_public: dict[str, object],
        before_raw: dict[str, object],
        after_raw: dict[str, object],
        before_journal: dict[str, object],
        after_journal: dict[str, object],
    ) -> None:
        # Only the explicitly rebound private hash/size is allowed to change
        # in the public object.  The summaries and their attestation/health
        # projections remain byte-for-byte semantically unchanged.
        for key, before in before_public.items():
            if key in {"raw_snapshot_sha256", "raw_snapshot_size", "journal_sha256", "journal_size"}:
                continue
            if after_public.get(key) != before:
                raise AssertionError(f"public summary changed at {key!r}")
        for key in ("current_boot_attestation", "health_after_ok", "target_model", "runtime", "soc"):
            if after_public.get(key) != before_public.get(key):
                raise AssertionError(f"public projection changed at {key!r}")
        for key in before_raw:
            if key != "frames" and after_raw.get(key) != before_raw.get(key):
                raise AssertionError(f"raw summary changed at {key!r}")
        for key in ("current_boot_attestation", "health_after", "target", "fixed_op_measurement"):
            if after_raw.get(key) != before_raw.get(key):
                raise AssertionError(f"raw projection changed at {key!r}")
        for key in before_journal:
            if key not in {"frames", "stophud_attempts"} and after_journal.get(key) != before_journal.get(key):
                raise AssertionError(f"journal summary changed at {key!r}")
        for key in ("current_boot_attestation", "health_after", "target", "fixed_op_measurement"):
            if after_journal.get(key) != before_journal.get(key):
                raise AssertionError(f"journal projection changed at {key!r}")

    def test_valid_actual_collect_fixture_is_accepted_by_both_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, manifest_path, journal_path = self._collect_control(root)
            final_receipt = finalizer.validate_control(manifest_path, root)
            self.assertEqual(final_receipt["kind"], "control")
            self.assertEqual(final_receipt["value"], "0x000000000000c071")
            authorizer_receipt = probe.verify_control_manifest(
                manifest_path, root=root
            )
            self.assertEqual(authorizer_receipt["value"], "0x000000000000c071")

    def test_removing_every_raw_frame_position_is_rejected_by_both_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, manifest_path, journal_path = self._collect_control(root)
            baseline_raw = json.loads(raw_path.read_text())
            baseline_public = json.loads(manifest_path.read_text())
            baseline_journal = json.loads(journal_path.read_text())
            expected_ids = finalizer._expected_full_frame_ids(
                1, allow_fixed=True, restored=True, include_health=True
            )
            self.assertEqual(
                [frame["evidence_id"] for frame in baseline_raw["frames"]],
                expected_ids,
            )
            self.assertGreater(
                len(expected_ids),
                len(set(expected_ids)),
                "the regression must exercise duplicate frame IDs by position",
            )

            for position, expected_id in enumerate(expected_ids):
                with self.subTest(position=position, evidence_id=expected_id):
                    mutated_raw = copy.deepcopy(baseline_raw)
                    removed = mutated_raw["frames"].pop(position)
                    self.assertEqual(removed["evidence_id"], expected_id)
                    mutated_public = copy.deepcopy(baseline_public)
                    _write_and_rebind(
                        raw_path,
                        mutated_raw,
                        manifest_path,
                        mutated_public,
                        binding_key="raw_snapshot_sha256",
                        size_key="raw_snapshot_size",
                    )
                    observed_raw = json.loads(raw_path.read_text())
                    observed_public = json.loads(manifest_path.read_text())
                    observed_journal = json.loads(journal_path.read_text())
                    self._assert_summary_unchanged(
                        baseline_public,
                        observed_public,
                        baseline_raw,
                        observed_raw,
                        baseline_journal,
                        observed_journal,
                    )
                    with self.assertRaises(finalizer.FinalizeError):
                        finalizer.validate_control(manifest_path, root)
                    with self.assertRaises(probe.ProbeError):
                        probe.verify_control_manifest(manifest_path, root=root)

                    # Restore the actual producer bytes before the next
                    # position.  This also makes each subtest independent of
                    # any consumer read caching.
                    raw_path.write_bytes(_json_bytes(baseline_raw))
                    manifest_path.write_bytes(_json_bytes(baseline_public))

    def test_removing_every_journal_frame_position_is_rejected_by_both_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, manifest_path, journal_path = self._collect_control(root)
            baseline_raw = json.loads(raw_path.read_text())
            baseline_public = json.loads(manifest_path.read_text())
            baseline_journal = json.loads(journal_path.read_text())
            expected_ids = finalizer._expected_full_frame_ids(
                1, allow_fixed=True, restored=True, include_health=True
            )
            self.assertEqual(
                [frame["evidence_id"] for frame in baseline_journal["frames"]],
                expected_ids,
            )
            for position, expected_id in enumerate(expected_ids):
                with self.subTest(position=position, evidence_id=expected_id):
                    mutated_journal = copy.deepcopy(baseline_journal)
                    removed = mutated_journal["frames"].pop(position)
                    self.assertEqual(removed["evidence_id"], expected_id)
                    mutated_public = copy.deepcopy(baseline_public)
                    _write_and_rebind(
                        journal_path,
                        mutated_journal,
                        manifest_path,
                        mutated_public,
                        binding_key="journal_sha256",
                        size_key="journal_size",
                    )
                    observed_raw = json.loads(raw_path.read_text())
                    observed_public = json.loads(manifest_path.read_text())
                    observed_journal = json.loads(journal_path.read_text())
                    self._assert_summary_unchanged(
                        baseline_public,
                        observed_public,
                        baseline_raw,
                        observed_raw,
                        baseline_journal,
                        observed_journal,
                    )
                    with self.assertRaises(finalizer.FinalizeError):
                        finalizer.validate_control(manifest_path, root)
                    with self.assertRaises(probe.ProbeError):
                        probe.verify_control_manifest(manifest_path, root=root)
                    journal_path.write_bytes(_json_bytes(baseline_journal))
                    manifest_path.write_bytes(_json_bytes(baseline_public))

    def test_representative_extra_and_reordered_frames_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, manifest_path, journal_path = self._collect_control(root)
            baseline_raw = json.loads(raw_path.read_text())
            baseline_public = json.loads(manifest_path.read_text())
            baseline_journal = json.loads(journal_path.read_text())

            extra_raw = copy.deepcopy(baseline_raw)
            extra_raw["frames"].append(copy.deepcopy(extra_raw["frames"][-1]))
            extra_public = copy.deepcopy(baseline_public)
            _write_and_rebind(
                raw_path,
                extra_raw,
                manifest_path,
                extra_public,
                binding_key="raw_snapshot_sha256",
                size_key="raw_snapshot_size",
            )
            with self.assertRaises(finalizer.FinalizeError):
                finalizer.validate_control(manifest_path, root)
            with self.assertRaises(probe.ProbeError):
                probe.verify_control_manifest(manifest_path, root=root)

            raw_path.write_bytes(_json_bytes(baseline_raw))
            manifest_path.write_bytes(_json_bytes(baseline_public))

            reordered_journal = copy.deepcopy(baseline_journal)
            reordered_journal["frames"][0], reordered_journal["frames"][1] = (
                reordered_journal["frames"][1],
                reordered_journal["frames"][0],
            )
            reordered_public = copy.deepcopy(baseline_public)
            _write_and_rebind(
                journal_path,
                reordered_journal,
                manifest_path,
                reordered_public,
                binding_key="journal_sha256",
                size_key="journal_size",
            )
            with self.assertRaises(finalizer.FinalizeError):
                finalizer.validate_control(manifest_path, root)
            with self.assertRaises(probe.ProbeError):
                probe.verify_control_manifest(manifest_path, root=root)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
