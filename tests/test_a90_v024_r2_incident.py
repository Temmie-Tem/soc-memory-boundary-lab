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
        self.assertEqual(result["status"], "VALIDATED_CONSUMED_ZERO_EFFECT")
        self.assertEqual(result["experiment_id"], "verification-024-control-r3")
        self.assertEqual(result["next_registered_id"], "verification-024-control-r4")
        self.assertTrue(result["consumed_checkpoint"])
        self.assertEqual(result["zero_effect_validated"]["fixed_op_dispatch_count"], 0)
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
