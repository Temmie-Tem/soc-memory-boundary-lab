from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from tools import a90_v024_physical_claim as claims
from tools import a90_native_recovery_entry as recovery_entry
from tools import a90_native_reboot_observe as native_reboot
from tools import a90_twrp_boot_rollback_recovery as rollback_recovery


PREIMAGE = (
    "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
)
BOOT_ID = "7501ac1e-373b-46d9-b2ee-eec653c170c5"


class V024PhysicalClaimTests(unittest.TestCase):
    def test_boot_key_is_only_preimage_and_geometry(self) -> None:
        identity, key = claims.boot_prefix_claim_identity(PREIMAGE)
        self.assertEqual(identity["partition"], "/dev/block/sda24")
        self.assertEqual(identity["current_preimage_size"], claims.BOOT_PREFIX_SIZE)
        self.assertEqual(identity["block_size"], claims.BOOT_PREFIX_BLOCK_SIZE)
        self.assertEqual(identity["block_count"], claims.BOOT_PREFIX_BLOCK_COUNT)
        self.assertEqual(
            claims.boot_prefix_claim_identity(PREIMAGE)[1],
            claims.boot_prefix_claim_identity(PREIMAGE)[1],
        )
        # Provenance is content only and cannot create a second physical key.
        self.assertEqual(key, claims.boot_prefix_claim_identity(PREIMAGE)[1])
        self.assertNotEqual(key, claims.boot_prefix_claim_identity("2" * 64)[1])

    def test_native_key_is_effect_and_phase_independent(self) -> None:
        identity, key = claims.native_transition_claim_identity(BOOT_ID)
        self.assertEqual(identity["resource"], claims.NATIVE_TRANSITION_RESOURCE)
        self.assertEqual(identity["schema"], claims.NATIVE_TRANSITION_CLAIM_SCHEMA)
        self.assertNotIn("effect", identity)
        self.assertNotIn("phase", identity)
        self.assertNotIn("debug", identity)
        self.assertEqual(key, claims.native_transition_claim_identity(BOOT_ID)[1])
        self.assertNotEqual(
            key,
            claims.native_transition_claim_identity(
                "7501ac1e-373b-46d9-b2ee-eec653c170c6"
            )[1],
        )

    def test_boot_claim_race_has_one_final_inode_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = threading.Barrier(2)
            results: list[str] = []

            def owner(label: str) -> None:
                gate.wait()
                try:
                    claims.claim_boot_prefix(
                        root,
                        current_preimage_sha256=PREIMAGE,
                        experiment_id=label,
                        provenance={"owner_kind": label},
                    )
                except (claims.PhysicalClaimAlreadyExists, claims.PhysicalClaimPartial):
                    results.append("lost")
                else:
                    results.append("won")

            threads = [threading.Thread(target=owner, args=(label,)) for label in ("read", "rollback")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(results), ["lost", "won"])
            record = claims.inspect_boot_prefix_claim(root, PREIMAGE)
            self.assertIsNotNone(record)
            self.assertEqual(record.key_sha256, claims.boot_prefix_claim_identity(PREIMAGE)[1])

    def test_native_claim_race_has_one_final_inode_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = threading.Barrier(2)
            results: list[str] = []

            def owner(label: str) -> None:
                gate.wait()
                try:
                    claims.claim_native_transition(
                        root,
                        boot_id=BOOT_ID,
                        experiment_id=label,
                        provenance={"effect": label},
                    )
                except (claims.PhysicalClaimAlreadyExists, claims.PhysicalClaimPartial):
                    results.append("lost")
                else:
                    results.append("won")

            threads = [threading.Thread(target=owner, args=("recovery",)), threading.Thread(target=owner, args=("reboot",))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(results), ["lost", "won"])
            record = claims.inspect_native_transition_claim(root, BOOT_ID)
            self.assertIsNotNone(record)

    def test_partial_final_claim_blocks_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, key = claims.boot_prefix_claim_identity(PREIMAGE)
            path = claims.boot_prefix_claim_path(root, key)
            path.write_bytes(b"{\"partial\":")
            with self.assertRaises(claims.PhysicalClaimPartial):
                claims.claim_boot_prefix(
                    root,
                    current_preimage_sha256=PREIMAGE,
                    experiment_id="retry",
                )
            self.assertEqual(path.read_bytes(), b"{\"partial\":")

    def test_partial_native_final_claim_blocks_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, key = claims.native_transition_claim_identity(BOOT_ID)
            path = claims.native_transition_claim_path(root, key)
            path.write_bytes(b"{\"partial\":")
            with self.assertRaises(claims.PhysicalClaimPartial):
                claims.claim_native_transition(
                    root,
                    boot_id=BOOT_ID,
                    experiment_id="retry",
                )
            self.assertEqual(path.read_bytes(), b"{\"partial\":")

    def test_claim_creator_rejects_alternate_final_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity, key = claims.boot_prefix_claim_identity(PREIMAGE)
            alternate = root / "evidence" / "private" / "alternate.claim.json"
            with self.assertRaises(claims.PhysicalClaimError):
                claims.create_boot_prefix_claim(
                    alternate,
                    identity=identity,
                    key_sha256=key,
                    experiment_id="alternate",
                )
            self.assertFalse(alternate.exists())

    def test_boot_owner_wrappers_share_key_path_and_one_race_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            normal_identity, normal_key = claims.boot_prefix_claim_identity(PREIMAGE)
            recovery_identity, recovery_key = rollback_recovery._rollback_effect_identity(
                PREIMAGE,
                claims.BOOT_PREFIX_SIZE,
            )
            self.assertEqual(normal_identity, recovery_identity)
            self.assertEqual(normal_key, recovery_key)
            with mock.patch.object(rollback_recovery, "REPO_ROOT", root):
                self.assertEqual(
                    claims.boot_prefix_claim_path(root, normal_key),
                    rollback_recovery._rollback_effect_claim_path(recovery_key),
                )
                path = rollback_recovery._rollback_effect_claim_path(recovery_key)
                gate = threading.Barrier(2)
                results: list[str] = []

                def normal_owner() -> None:
                    gate.wait()
                    try:
                        claims.claim_boot_prefix(
                            root,
                            current_preimage_sha256=PREIMAGE,
                            experiment_id="normal-read",
                            provenance={
                                "owner_kind": "normal-remapper",
                                "profile": "read",
                                "predecessor_sha256": PREIMAGE,
                                "predecessor_size": claims.BOOT_PREFIX_SIZE,
                                "image_sha256": claims.V024_IMAGE_HASHES["read"],
                                "image_size": claims.BOOT_PREFIX_SIZE,
                                "journal_path": str(
                                    root
                                    / "evidence/private/verification-024-remapper-boot-flash-read.journal.json"
                                ),
                            },
                        )
                    except claims.PhysicalClaimError:
                        results.append("lost")
                    else:
                        results.append("normal")

                def recovery_owner() -> None:
                    gate.wait()
                    try:
                        rollback_recovery._create_rollback_effect_claim(
                            path,
                            identity=recovery_identity,
                            effect_key_sha256=recovery_key,
                            experiment_id="recovery-read",
                            terminal="before_recovery_effect_marker",
                        )
                    except rollback_recovery.RollbackRecoveryError:
                        results.append("lost")
                    else:
                        results.append("recovery")

                threads = [
                    threading.Thread(target=normal_owner),
                    threading.Thread(target=recovery_owner),
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                self.assertEqual(sum(result != "lost" for result in results), 1)
                self.assertEqual(
                    claims.inspect_boot_prefix_claim(root, PREIMAGE) is not None,
                    True,
                )

    def test_native_owner_wrappers_share_key_path_and_one_race_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry_identity, entry_key = recovery_entry._recovery_effect_identity(BOOT_ID)
            reboot_identity, reboot_key = native_reboot._reboot_effect_identity(BOOT_ID)
            self.assertEqual(entry_identity, reboot_identity)
            self.assertEqual(entry_key, reboot_key)
            self.assertEqual(
                recovery_entry._recovery_effect_claim_path(root, entry_key),
                native_reboot._reboot_effect_claim_path(root, reboot_key),
            )
            path = recovery_entry._recovery_effect_claim_path(root, entry_key)
            gate = threading.Barrier(2)
            results: list[str] = []

            def recovery_owner() -> None:
                gate.wait()
                try:
                    recovery_entry._create_recovery_effect_claim(
                        path,
                        identity=entry_identity,
                        key_sha256=entry_key,
                        experiment_id="entry",
                    )
                except recovery_entry.RecoveryEntryError:
                    results.append("lost")
                else:
                    results.append("recovery")

            def reboot_owner() -> None:
                gate.wait()
                try:
                    native_reboot._create_reboot_effect_claim(
                        path,
                        identity=reboot_identity,
                        key_sha256=reboot_key,
                        experiment_id="reboot",
                    )
                except ValueError:
                    results.append("lost")
                else:
                    results.append("reboot")

            threads = [
                threading.Thread(target=recovery_owner),
                threading.Thread(target=reboot_owner),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sum(result != "lost" for result in results), 1)
            self.assertIsNotNone(claims.inspect_native_transition_claim(root, BOOT_ID))

    def test_normal_ambiguous_claim_is_the_only_recovery_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "evidence/private/verification-024-remapper-boot-flash-read.journal.json"
            journal_path.parent.mkdir(parents=True)
            journal = {
                "schema": "sdm855-a90-remapper-boot-flash-private-v1",
                "status": "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED",
                "profile": "read",
                "allowed_predecessors": [
                    "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
                ],
                "predecessor_sha256": PREIMAGE,
                "predecessor_size": claims.BOOT_PREFIX_SIZE,
                "image_sha256": claims.V024_IMAGE_HASHES["read"],
                "image_size": claims.BOOT_PREFIX_SIZE,
                "remote_staging": claims.V024_STAGING["read"],
                "effect_armed": True,
                "effect_dispatched": True,
                "effect_replayed": False,
                "write_count": 1,
                "current_state": "UNKNOWN",
                "staging_cleanup_deferred": True,
                "reconcile_required": True,
            }
            journal_path.write_text(json.dumps(journal) + "\n", encoding="utf-8")
            claim = claims.claim_boot_prefix(
                root,
                current_preimage_sha256=PREIMAGE,
                experiment_id="normal-read",
                provenance={
                    "owner_kind": "normal-remapper",
                    "profile": "read",
                    "predecessor_sha256": PREIMAGE,
                    "predecessor_size": claims.BOOT_PREFIX_SIZE,
                    "image_sha256": claims.V024_IMAGE_HASHES["read"],
                    "image_size": claims.BOOT_PREFIX_SIZE,
                    "journal_path": str(journal_path),
                },
            )
            claims.validate_normal_remapper_continuation(
                claim,
                root=root,
                journal_path=journal_path,
                profile="read",
                predecessor_sha256=PREIMAGE,
            )
            with self.assertRaises(claims.PhysicalClaimError):
                claims.validate_normal_remapper_continuation(
                    claim,
                    root=root,
                    journal_path=journal_path,
                    profile="rollback",
                    predecessor_sha256=PREIMAGE,
                )

    def test_rollback_predecessor_matrix_has_canonical_order_and_rejects_shape_variants(self) -> None:
        expected = [
            claims.V024_IMAGE_HASHES["read"],
            claims.V024_IMAGE_HASHES["control"],
        ]
        self.assertEqual(claims.V024_PREDECESSORS["rollback"], expected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = (
                root
                / "evidence/private/verification-024-remapper-boot-flash-rollback.journal.json"
            )
            journal_path.parent.mkdir(parents=True)
            journal = {
                "schema": "sdm855-a90-remapper-boot-flash-private-v1",
                "status": "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED",
                "profile": "rollback",
                "allowed_predecessors": expected,
                "predecessor_sha256": claims.V024_IMAGE_HASHES["control"],
                "predecessor_size": claims.BOOT_PREFIX_SIZE,
                "image_sha256": claims.V024_IMAGE_HASHES["rollback"],
                "image_size": claims.BOOT_PREFIX_SIZE,
                "remote_staging": claims.V024_STAGING["rollback"],
                "effect_armed": True,
                "effect_dispatched": True,
                "effect_replayed": False,
                "write_count": 1,
                "current_state": "UNKNOWN",
                "staging_cleanup_deferred": True,
                "reconcile_required": True,
            }
            journal_path.write_text(json.dumps(journal) + "\n", encoding="utf-8")
            claim = claims.claim_boot_prefix(
                root,
                current_preimage_sha256=claims.V024_IMAGE_HASHES["control"],
                experiment_id="normal-rollback",
                provenance={
                    "owner_kind": "normal-remapper",
                    "profile": "rollback",
                    "predecessor_sha256": claims.V024_IMAGE_HASHES["control"],
                    "predecessor_size": claims.BOOT_PREFIX_SIZE,
                    "image_sha256": claims.V024_IMAGE_HASHES["rollback"],
                    "image_size": claims.BOOT_PREFIX_SIZE,
                    "journal_path": str(journal_path),
                },
            )
            claims.validate_normal_remapper_continuation(
                claim,
                root=root,
                journal_path=journal_path,
                profile="rollback",
                predecessor_sha256=claims.V024_IMAGE_HASHES["control"],
            )
            for variant in (
                list(reversed(expected)),
                expected[:1],
                expected + [expected[0]],
            ):
                with self.subTest(allowed_predecessors=variant):
                    journal["allowed_predecessors"] = variant
                    journal_path.write_text(
                        json.dumps(journal) + "\n", encoding="utf-8"
                    )
                    with self.assertRaisesRegex(
                        claims.PhysicalClaimError, "exact ambiguous source"
                    ):
                        claims.validate_normal_remapper_continuation(
                            claim,
                            root=root,
                            journal_path=journal_path,
                            profile="rollback",
                            predecessor_sha256=claims.V024_IMAGE_HASHES["control"],
                        )


if __name__ == "__main__":
    unittest.main()
