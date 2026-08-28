from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from tools import a90_v024_r2_incident as checkpoint


class R2IncidentTests(unittest.TestCase):
    def _fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        holder: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
        root = Path(holder.name)
        destination = root / checkpoint.MANIFEST_RELATIVE_PATH
        destination.parent.mkdir(parents=True)
        source = checkpoint.REPO_ROOT / checkpoint.MANIFEST_RELATIVE_PATH
        shutil.copyfile(source, destination)
        # The retained host file is group-readable; both 0644 and 0664 are
        # deliberately accepted by the checkpoint reader.
        os.chmod(destination, 0o664)
        return holder, destination

    def _r3_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        holder: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
        root = Path(holder.name)
        destination = root / checkpoint.R3_MANIFEST_RELATIVE_PATH
        destination.parent.mkdir(parents=True)
        source = checkpoint.REPO_ROOT / checkpoint.R3_MANIFEST_RELATIVE_PATH
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o664)
        return holder, destination

    def _r4_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        holder: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
        root = Path(holder.name)
        destination = root / checkpoint.R4_MANIFEST_RELATIVE_PATH
        destination.parent.mkdir(parents=True)
        source = checkpoint.REPO_ROOT / checkpoint.R4_MANIFEST_RELATIVE_PATH
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o664)
        return holder, destination

    def test_real_checkpoint_passes_and_result_is_redacted(self) -> None:
        holder, _ = self._fixture()
        with holder:
            result = checkpoint.validate_r2_incident(Path(holder.name))
        self.assertEqual(result["status"], "VALIDATED_ZERO_EFFECT")
        self.assertEqual(result["next_registered_id"], "verification-024-control-r3")
        self.assertEqual(result["zero_effect_validated"]["dispatch_count"], 0)
        self.assertEqual(
            result["checkpoint"]["sha256"], checkpoint.INCIDENT_MANIFEST_SHA256
        )
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("/evidence/private/", encoded)
        self.assertNotIn("frames", encoded)
        self.assertNotIn("payload_base64", encoded)

    def test_real_r3_checkpoint_passes_as_consumed_and_is_redacted(self) -> None:
        holder, _ = self._r3_fixture()
        with holder:
            result = checkpoint.validate_r3_incident(Path(holder.name))
        self.assertEqual(
            result["status"], "VALIDATED_CONSUMED_ZERO_OP_RESTORED_STATE"
        )
        self.assertEqual(result["experiment_id"], "verification-024-control-r3")
        self.assertEqual(result["next_registered_id"], "verification-024-control-r4")
        self.assertTrue(result["consumed_checkpoint"])
        self.assertEqual(result["incident_facts"]["fixed_op_dispatch_count"], 0)
        self.assertTrue(result["reconciliation"]["temporary_sysctl_write"])
        self.assertTrue(result["reconciliation"]["temporary_sysctl_write_rolled_back"])
        self.assertEqual(
            result["checkpoint"]["sha256"], checkpoint.R3_INCIDENT_MANIFEST_SHA256
        )
        self.assertEqual(
            result["artifact_descriptors"]["panic_recovery"]["sha256"],
            checkpoint.R3_RECOVERY_DESCRIPTOR_SHA256,
        )
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("/evidence/private/", encoded)
        self.assertNotIn("frames", encoded)
        self.assertNotIn("payload_base64", encoded)

    def test_r3_critical_claims_and_pins_cannot_be_rebound(self) -> None:
        mutations = (
            (b'"fixed_op_dispatch_count": 0', b'"fixed_op_dispatch_count": 1'),
            (b'"effect_dispatched": false', b'"effect_dispatched": true'),
            (b'"effect_ambiguous": false', b'"effect_ambiguous": true'),
            (b'"effect_replayed": false', b'"effect_replayed": true'),
            (b'"partition_writes": false', b'"partition_writes": true'),
            (b'"memory_or_mmio_writes": false', b'"memory_or_mmio_writes": true'),
            (b'"controller_writes": false', b'"controller_writes": true'),
            (b'"protected_memory_read": false', b'"protected_memory_read": true'),
            (b'"smc": false', b'"smc": true'),
            (b'"panic_after_recovery": 1', b'"panic_after_recovery": 0'),
            (b'"panic_restore_verified": true', b'"panic_restore_verified": false'),
            (b'"semantic_claim_retained": true', b'"semantic_claim_retained": false'),
            (
                b'"security_boundary_result": "UNKNOWN_NOT_REACHED"',
                b'"security_boundary_result": "REACHED"',
            ),
            (
                b'"sha256": "29439f2d8a6dc5cbb6113ca7a8843f37940e7201a26c378ceb019fa3cbbfc149"',
                b'"sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (
                b'"sha256": "551465718605e47db02ca8b4e469ae8be2def65b79f7e8aeb5c5b7648a0606bc"',
                b'"sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (
                b'"writefile_payload_size": 13',
                b'"writefile_payload_size": 14',
            ),
        )
        for old, new in mutations:
            with self.subTest(field=old):
                holder, path = self._r3_fixture()
                with holder:
                    data = path.read_bytes()
                    self.assertEqual(data.count(old), 1)
                    mutated = data.replace(old, new)
                    path.write_bytes(mutated)
                    digest = hashlib.sha256(mutated).hexdigest()
                    with mock.patch.object(
                        checkpoint, "R3_INCIDENT_MANIFEST_SHA256", digest
                    ):
                        with self.assertRaises(checkpoint.R2IncidentError):
                            checkpoint.validate_r3_incident(Path(holder.name))

    def test_real_r4_checkpoint_passes_as_returned_incident_and_is_redacted(self) -> None:
        holder, _ = self._r4_fixture()
        with holder:
            result = checkpoint.validate_r4_incident(Path(holder.name))
        self.assertEqual(
            result["status"], "VALIDATED_CONSUMED_RETURNED_FRAMING_INCIDENT"
        )
        self.assertNotEqual(result["status"], "CONTROL_PASS")
        self.assertEqual(result["schema"], checkpoint.R4_VALIDATION_SCHEMA)
        self.assertEqual(result["experiment_id"], "verification-024-control-r4")
        self.assertEqual(result["next_registered_id"], "verification-024-control-r5")
        self.assertEqual(result["classification"], "CLASS_C_UNCHANGED")
        self.assertEqual(result["security_boundary_result"], "UNKNOWN_NOT_REACHED")
        self.assertTrue(result["consumed_checkpoint"])
        self.assertEqual(result["target"], dict(checkpoint.R4_TARGET_PINS))
        self.assertEqual(
            result["incident_facts"]["fixed_op_dispatch_count"], 1
        )
        self.assertTrue(result["incident_facts"]["fixed_op_returned"])
        self.assertTrue(result["incident_facts"]["effect_dispatched"])
        self.assertFalse(result["incident_facts"]["effect_ambiguous"])
        self.assertFalse(result["incident_facts"]["effect_replayed"])
        self.assertTrue(result["incident_facts"]["semantic_claim_retained"])
        self.assertTrue(result["panic_transition"]["restored"])
        self.assertFalse(result["panic_transition"]["restore_deferred"])
        self.assertEqual(
            result["fixed_op"]["canonical_value_candidate"],
            "0x000000000000c071",
        )
        self.assertEqual(
            result["fixed_op"]["result_grade"],
            "RETURNED_SENTINEL_CANDIDATE_NOT_CONTROL_PASS",
        )
        self.assertEqual(
            result["parser_incident"], dict(checkpoint.R4_PARSER_INCIDENT_PINS)
        )
        self.assertEqual(
            result["artifact_descriptors"],
            {role: dict(pin) for role, pin in checkpoint.R4_ARTIFACT_PINS.items()},
        )
        self.assertEqual(
            result["checkpoint"]["sha256"], checkpoint.R4_INCIDENT_MANIFEST_SHA256
        )
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("/evidence/private/", encoded)
        self.assertNotIn('"frames"', encoded)
        self.assertNotIn("payload_base64", encoded)

    def test_r4_semantic_claims_and_pins_cannot_be_rebound(self) -> None:
        mutations = (
            (b'"model": "SM-A908N"', b'"model": "SM-A908X"'),
            (b'"classification": "CLASS_C_UNCHANGED"', b'"classification": "CLASS_C_MUTATED"'),
            (
                b'"security_boundary_result": "UNKNOWN_NOT_REACHED"',
                b'"security_boundary_result": "REACHED_NOT_ALLOWED"',
            ),
            (b'"fixed_op_dispatch_count": 1', b'"fixed_op_dispatch_count": 2'),
            (b'"fixed_op_returned": true', b'"fixed_op_returned": false'),
            (b'"effect_dispatched": true', b'"effect_dispatched": false'),
            (b'"effect_ambiguous": false', b'"effect_ambiguous": true'),
            (b'"effect_replayed": false', b'"effect_replayed": true'),
            (b'"partition_writes": false', b'"partition_writes": true'),
            (b'"memory_or_mmio_writes": false', b'"memory_or_mmio_writes": true'),
            (b'"controller_writes": false', b'"controller_writes": true'),
            (b'"protected_memory_read": false', b'"protected_memory_read": true'),
            (b'"smc": false', b'"smc": true'),
            (b'"panic_after_recovery": 1', b'"panic_after_recovery": 0'),
            (b'"panic_restore_verified": true', b'"panic_restore_verified": false'),
            (b'"semantic_claim_retained": true', b'"semantic_claim_retained": false'),
            (b'"restored": true', b'"restored": false'),
            (
                b'"sha256": "6110b5bbd94fce23e433a046598b38b117f99f6b94db6b62d0a30235e72e4730"',
                b'"sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (b'"size": 6355', b'"size": 6356'),
            (b'"mode": "0644"', b'"mode": "0600"'),
            (
                b'"frame_canonical_sha256": "c4d0530cb6b60797acab56aa056f094b700d40f2d39349c5e221c383f1a7a858"',
                b'"frame_canonical_sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (b'"frame_canonical_size": 9665', b'"frame_canonical_size": 9666'),
            (
                b'"payload_sha256": "0fdb2adf322e5f6848428c19430b87a39e7a6ea5081e1672c1cf9be39da44003"',
                b'"payload_sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (b'"payload_size": 1730', b'"payload_size": 1731'),
            (b'"payload_line_count": 19', b'"payload_line_count": 18'),
            (
                b'"transcript_sha256": "05ef2e84b9160ee00909b06a9bd819f4127fcc357601375ce9ddbc722f7521d6"',
                b'"transcript_sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (b'"transcript_size": 4215', b'"transcript_size": 4216'),
            (
                b'"a90r_marker_line": "[  116.230307] [5:        busybox:  676] A90Rc071"',
                b'"a90r_marker_line": "[  116.230307] [5:        busybox:  676] A90Rc072"',
            ),
            (b'"a90r_marker_count": 1', b'"a90r_marker_count": 2'),
            (
                b'"canonical_value_candidate": "0x000000000000c071"',
                b'"canonical_value_candidate": "0x000000000000c072"',
            ),
            (
                b'"result_grade": "RETURNED_SENTINEL_CANDIDATE_NOT_CONTROL_PASS"',
                b'"result_grade": "RETURNED_SENTINEL_CANDIDATE_NOT_CONTROL_FAIL"',
            ),
            (
                b'"commit": "5395249ce31170c43a45fcf42d7d438ad2957477"',
                b'"commit": "5395249ce31170c43a45fcf42d7d438ad2957478"',
            ),
            (
                b'"producer_sha256": "12c8690520e4bbd054a1e6155d700753f23eb3a20a3322552e0fc8fc69c55786"',
                b'"producer_sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (b'"panic_on_oops": 1', b'"panic_on_oops": 0'),
            (
                b'"post_incident_readonly_health": {\n    "boot_id_sha256": "8953331fec3a0c638cb06e4f77fa1b6127e75f5e30d55f7e638ec5703a185dc9"',
                b'"post_incident_readonly_health": {\n    "boot_id_sha256": "0000000000000000000000000000000000000000000000000000000000000000"',
            ),
            (
                b'"evidence_grade": "SUPPORTED_EXEC_TRANSCRIPT"',
                b'"evidence_grade": "UNSUPPORTED_EXEC_TRANSCRIPT"',
            ),
            (
                b'"started_utc": "2026-08-28T10:38:40+00:00"',
                b'"started_utc": "2026-08-28T10:38:41+00:00"',
            ),
            (
                b'"completed_utc": "2026-08-28T10:38:43+00:00"',
                b'"completed_utc": "2026-08-28T10:38:44+00:00"',
            ),
            (b"empty line", b"empty Line"),
            (b"noise.", b"noisE."),
        )
        for old, new in mutations:
            with self.subTest(field=old):
                holder, path = self._r4_fixture()
                with holder:
                    data = path.read_bytes()
                    self.assertEqual(data.count(old), 1)
                    mutated = data.replace(old, new)
                    path.write_bytes(mutated)
                    digest = hashlib.sha256(mutated).hexdigest()
                    with mock.patch.object(
                        checkpoint, "R4_INCIDENT_MANIFEST_SHA256", digest
                    ):
                        with self.assertRaises(checkpoint.R2IncidentError):
                            checkpoint.validate_r4_incident(Path(holder.name))

    def test_r4_top_level_key_set_rejects_extra_field(self) -> None:
        holder, path = self._r4_fixture()
        with holder:
            data = path.read_bytes()
            prefix, suffix = data.rsplit(b"\n}\n", 1)
            mutated = prefix + b',\n  "extra": false\n}\n' + suffix
            path.write_bytes(mutated)
            digest = hashlib.sha256(mutated).hexdigest()
            with mock.patch.object(
                checkpoint,
                "R4_INCIDENT_MANIFEST_SHA256",
                digest,
            ), mock.patch.object(
                checkpoint,
                "R4_INCIDENT_MANIFEST_SIZE",
                len(mutated),
            ):
                with self.assertRaises(checkpoint.R2IncidentError):
                    checkpoint.validate_r4_incident(Path(holder.name))

    def test_fixed_reader_rejects_hash_size_mode_symlink_hardlink_and_drift(self) -> None:
        cases = ("hash", "size", "mode", "symlink", "hardlink", "drift")
        for case in cases:
            with self.subTest(case=case):
                holder, path = self._fixture()
                with holder:
                    if case == "hash":
                        data = bytearray(path.read_bytes())
                        data[0] ^= 1
                        path.write_bytes(data)
                    elif case == "size":
                        with path.open("ab") as stream:
                            stream.write(b"x")
                    elif case == "mode":
                        os.chmod(path, 0o777)
                    elif case == "symlink":
                        path.unlink()
                        path.symlink_to(Path(holder.name) / "outside")
                    elif case == "hardlink":
                        sibling = Path(holder.name) / "held-manifest"
                        os.link(path, sibling)
                        path.unlink()
                        os.link(sibling, path)
                    else:
                        real_fstat = os.fstat
                        calls = 0

                        class DriftedStat:
                            def __init__(self, original: os.stat_result) -> None:
                                self._original = original
                                self.st_mtime_ns = original.st_mtime_ns + 1

                            def __getattr__(self, name: str) -> object:
                                return getattr(self._original, name)

                        def fstat(fd: int) -> os.stat_result | DriftedStat:
                            nonlocal calls
                            calls += 1
                            original = real_fstat(fd)
                            return original if calls == 1 else DriftedStat(original)

                        with mock.patch.object(checkpoint.os, "fstat", side_effect=fstat):
                            with self.assertRaises(checkpoint.R2IncidentError):
                                checkpoint.validate_r2_incident(Path(holder.name))
                        continue
                    with self.assertRaises(checkpoint.R2IncidentError):
                        checkpoint.validate_r2_incident(Path(holder.name))

    def test_core_claim_mutations_fail_when_test_only_digest_pin_is_rebound(self) -> None:
        mutations = (
            (b'"dispatch_count": 0', b'"dispatch_count": 1'),
            (b'"effect_dispatched": false', b'"effect_dispatched": true'),
            (b'"effect_ambiguous": false', b'"effect_ambiguous": true'),
            (b'"effect_replayed": false', b'"effect_replayed": true'),
            (b'"partition_writes": false', b'"partition_writes": true'),
            (b'"memory_or_mmio_writes": false', b'"memory_or_mmio_writes": true'),
            (b'"controller_writes": false', b'"controller_writes": true'),
            (b'"device_state_write": false', b'"device_state_write": true'),
            (b'"panic_zero_set": false', b'"panic_zero_set": true'),
            (b'"panic_zero_verified": false', b'"panic_zero_verified": true'),
            (b'"semantic_claim_created": false', b'"semantic_claim_created": true'),
            (
                b'"security_boundary_result": "UNKNOWN_NOT_REACHED"',
                b'"security_boundary_result": "REACHED"',
            ),
        )
        for old, new in mutations:
            with self.subTest(field=old):
                holder, path = self._fixture()
                with holder:
                    data = path.read_bytes()
                    self.assertEqual(data.count(old), 1)
                    mutated = data.replace(old, new)
                    path.write_bytes(mutated)
                    digest = hashlib.sha256(mutated).hexdigest()
                    with mock.patch.object(
                        checkpoint, "INCIDENT_MANIFEST_SHA256", digest
                    ):
                        with self.assertRaises(checkpoint.R2IncidentError):
                            checkpoint.validate_r2_incident(Path(holder.name))


if __name__ == "__main__":
    unittest.main()
