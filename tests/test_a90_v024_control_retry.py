from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from tools import a90_v024_control_retry as retry


class ControlRetryReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "evidence" / "manifests").mkdir(parents=True)
        (self.root / "evidence" / "private").mkdir(parents=True)

        self.payloads = {
            "public": b'{"kind":"public","value":1,"path":"/fixture/public"}\n',
            "raw": b'{"kind":"raw","value":2,"path":"/fixture/raw"}\n',
            "journal": b'{"kind":"journal","value":3,"path":"/fixture/journal"}\n',
        }
        self.paths = {
            "public": self.root / retry.PREDECESSOR_PUBLIC_RELATIVE_PATH,
            "raw": self.root / retry.PREDECESSOR_RAW_RELATIVE_PATH,
            "journal": self.root / retry.PREDECESSOR_JOURNAL_RELATIVE_PATH,
        }
        for role, path in self.paths.items():
            path.write_bytes(self.payloads[role])
            os.chmod(path, 0o644 if role == "public" else 0o600)

        self.pins = {
            role: {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                "mode": 0o644 if role == "public" else 0o600,
            }
            for role, data in self.payloads.items()
        }
        self.pin_patch = mock.patch.object(retry, "TRIPLET_PINS", self.pins)
        self.pin_patch.start()

    def tearDown(self) -> None:
        if self.pin_patch is not None:
            self.pin_patch.stop()
        self.temp.cleanup()

    def read(self) -> dict[str, object]:
        return retry._stable_read_triplet_for_root(self.root)

    def test_positive_result_has_three_dicts_and_redacted_artifacts(self) -> None:
        result = self.read()

        self.assertEqual(result["predecessor_id"], retry.PREDECESSOR_ID)
        self.assertEqual(result["active_control_id"], retry.ACTIVE_CONTROL_ID)
        self.assertEqual(
            result["public"],
            {"kind": "public", "value": 1, "path": "/fixture/public"},
        )
        self.assertEqual(
            result["raw"],
            {"kind": "raw", "value": 2, "path": "/fixture/raw"},
        )
        self.assertEqual(
            result["journal"],
            {"kind": "journal", "value": 3, "path": "/fixture/journal"},
        )
        artifacts = result["artifacts"]
        self.assertIsInstance(artifacts, dict)
        assert isinstance(artifacts, dict)
        for role, data in self.payloads.items():
            self.assertEqual(set(artifacts[role]), {"basename", "size_bytes", "sha256"})
            self.assertEqual(
                artifacts[role],
                {
                    "basename": self.paths[role].name,
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                },
            )
        self.assertNotIn(str(self.root), json.dumps(artifacts))

    def test_content_hash_and_size_mutations_are_rejected(self) -> None:
        path = self.paths["raw"]
        original = path.read_bytes()
        path.write_bytes(original.replace(b"2", b"9"))
        with self.assertRaisesRegex(retry.ControlRetryError, "SHA-256|size"):
            self.read()

        path.write_bytes(original + b" ")
        with self.assertRaises(retry.ControlRetryError):
            self.read()

    def test_mode_mutation_is_rejected(self) -> None:
        os.chmod(self.paths["public"], 0o600)
        with self.assertRaisesRegex(retry.ControlRetryError, "mode"):
            self.read()

    def test_uid_and_gid_mutations_are_rejected(self) -> None:
        with mock.patch.object(retry.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(retry.ControlRetryError, "uid/gid"):
                self.read()
        with mock.patch.object(retry.os, "getgid", return_value=os.getgid() + 1):
            with self.assertRaisesRegex(retry.ControlRetryError, "uid/gid"):
                self.read()

    def test_hardlink_nlink_mutation_is_rejected(self) -> None:
        link = self.root / "evidence" / "private" / "hardlink-target"
        os.link(self.paths["raw"], link)
        with self.assertRaisesRegex(retry.ControlRetryError, "link count"):
            self.read()

    def test_final_and_parent_symlinks_are_rejected(self) -> None:
        raw = self.paths["raw"]
        saved = raw.read_bytes()
        raw.unlink()
        raw.symlink_to(self.paths["journal"])
        with self.assertRaisesRegex(retry.ControlRetryError, "symlink"):
            self.read()
        raw.unlink()
        raw.write_bytes(saved)
        os.chmod(raw, 0o600)

        private = self.root / "evidence" / "private"
        moved = self.root / "evidence" / "private-real"
        private.rename(moved)
        private.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(retry.ControlRetryError, "symlink"):
            self.read()

    def test_symlink_parent_followed_by_dotdot_is_rejected_before_normalization(self) -> None:
        real = self.root / "real"
        real.mkdir()
        (self.root / "evidence").rename(real / "evidence")
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        disguised_root = alias / ".." / "real"
        with self.assertRaisesRegex(retry.ControlRetryError, r"\.\."):
            retry._stable_read_triplet_for_root(disguised_root)

    def test_fifo_and_nonregular_files_are_rejected_without_blocking(self) -> None:
        raw = self.paths["raw"]
        raw.unlink()
        os.mkfifo(raw, 0o600)
        with self.assertRaisesRegex(retry.ControlRetryError, "regular file"):
            self.read()

    def test_concurrent_fstat_identity_change_is_rejected(self) -> None:
        original_fstat = retry.os.fstat
        calls = 0

        def changing_fstat(fd: int) -> os.stat_result:
            nonlocal calls
            calls += 1
            result = original_fstat(fd)
            if calls == 2:
                # mtime/ctime are in the required before/after identity tuple.
                values = list(result)
                values[8] += 1
                return os.stat_result(values)
            return result

        with mock.patch.object(retry.os, "fstat", side_effect=changing_fstat):
            with self.assertRaisesRegex(retry.ControlRetryError, "changed"):
                self.read()

    def test_duplicate_json_and_nonfinite_values_are_rejected(self) -> None:
        raw = self.paths["raw"]
        for payload, pattern in (
            (b'{"kind":"raw","kind":"other"}\n', "duplicate"),
            (b'{"kind":"raw","value":NaN}\n', "non-finite"),
            (b'{"kind":"raw","value":Infinity}\n', "non-finite"),
            (b'{"kind":"raw","value":-Infinity}\n', "non-finite"),
            (b'{"kind":"raw","value":1e309}\n', "non-finite"),
            (b'{"kind":"raw","value":-1e309}\n', "non-finite"),
            (b'{"kind":"raw","value":{"nested":[1e309]}}\n', "non-finite"),
        ):
            with self.subTest(payload=payload):
                raw.write_bytes(payload)
                self.pins["raw"].update(
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size_bytes=len(payload),
                )
                with self.assertRaisesRegex(retry.ControlRetryError, pattern):
                    self.read()

    def test_oversized_file_is_rejected_before_retention(self) -> None:
        raw = self.paths["raw"]
        oversized = b"{" + b"x" * (retry.MAX_FILE_BYTES + 1) + b"}"
        raw.write_bytes(oversized)
        self.pins["raw"].update(
            sha256=hashlib.sha256(oversized).hexdigest(),
            size_bytes=len(oversized),
        )
        with self.assertRaisesRegex(retry.ControlRetryError, "bounded|size"):
            self.read()

    @unittest.skipUnless(
        (
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_PUBLIC_RELATIVE_PATH
        ).is_file()
        and (
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_RAW_RELATIVE_PATH
        ).is_file()
        and (
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_JOURNAL_RELATIVE_PATH
        ).is_file(),
        "private predecessor triplet is not present",
    )
    def test_actual_triplet_when_private_evidence_is_present(self) -> None:
        # The fixture pins are intentionally different from the canonical
        # repository bytes; restore the module's hard pins for this optional
        # integration check.
        self.pin_patch.stop()
        self.pin_patch = None
        result = retry.stable_read_triplet()
        artifacts = result["artifacts"]
        assert isinstance(artifacts, dict)
        self.assertEqual(artifacts["public"]["size_bytes"], 3715)
        self.assertEqual(artifacts["raw"]["size_bytes"], 4952)
        self.assertEqual(artifacts["journal"]["size_bytes"], 4662)


class ControlRetrySemanticTests(unittest.TestCase):
    """Exercise A2a over the retained producer-shaped predecessor triplet."""

    def _actual_triplet(self) -> dict[str, object]:
        paths = (
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_PUBLIC_RELATIVE_PATH,
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_RAW_RELATIVE_PATH,
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_JOURNAL_RELATIVE_PATH,
        )
        if not all(path.is_file() for path in paths):
            self.skipTest("private predecessor triplet is not present")
        return retry.stable_read_triplet()

    def test_actual_triplet_builds_redacted_deterministic_capsule(self) -> None:
        capsule = retry._validate_predecessor_semantics(self._actual_triplet())
        self.assertEqual(capsule["schema"], retry.CAPSULE_SCHEMA)
        self.assertEqual(capsule["phase"], retry.CAPSULE_PHASE)
        self.assertEqual(capsule["predecessor_id"], retry.PREDECESSOR_ID)
        self.assertEqual(capsule["active_control_id"], retry.ACTIVE_CONTROL_ID)
        self.assertEqual(
            set(capsule["claims"]),
            {
                "effect_grades",
                "mmio_effect",
                "stophud_state_change",
                "partial_transport_retained_private_is_authority",
                "historical_bridge_is_authority",
                "live_authority",
                "replay_allowed",
                "old_id_reuse_allowed",
                "fallback_allowed",
                "legacy_marker",
            },
        )
        self.assertEqual(
            capsule["claims"]["effect_grades"],
            {
                "fixed_op": "PROVED_ZERO",
                "panic": "PROVED_ZERO",
                "partition": "PROVED_ZERO",
                "controller": "PROVED_ZERO",
                "device_state": "PROVED_ZERO",
            },
        )
        self.assertEqual(capsule["claims"]["mmio_effect"], "PROVED_ZERO")
        self.assertEqual(
            capsule["claims"]["stophud_state_change"], "UNKNOWN_IDEMPOTENT"
        )
        self.assertEqual(
            capsule["semantic"]["legacy_frame"]["recorded_failure"],
            "STOPHUD_SUCCESS_PAYLOAD_NONEMPTY",
        )
        self.assertEqual(
            capsule["claims"]["legacy_marker"],
            {"partial_transport_retained_private": True, "authority": False},
        )
        self.assertFalse(capsule["claims"]["historical_bridge_is_authority"])
        self.assertFalse(capsule["claims"]["live_authority"])
        self.assertFalse(capsule["claims"]["replay_allowed"])
        self.assertIn("current_r2_pins_are_A3_journal_scope", capsule["provenance"]["scope"])

        serialized = retry.canonical_capsule_bytes(capsule)
        self.assertEqual(serialized, retry.canonical_capsule_bytes(capsule))
        descriptor = retry._canonical_capsule_descriptor(capsule)
        self.assertEqual(descriptor["size_bytes"], len(serialized))
        self.assertEqual(descriptor["sha256"], hashlib.sha256(serialized).hexdigest())
        self.assertTrue(serialized.endswith(b"\n"))

        encoded = serialized.decode("utf-8")
        for forbidden in (
            "/home/",
            "/dev/tty",
            "bridge_binding",
            "process_argv",
            "process_pid",
            "listener",
            "serial_identity",
            "payload_base64",
            "transcript_base64",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, encoded)

        self.assertEqual(
            capsule["provenance"]["historical_producer_commit"],
            "6eaad666a7d666fdf50955d372e9b837bcb326ed",
        )
        for name, expected in retry.PRODUCER_SOURCE_PINS.items():
            pin = capsule["provenance"]["historical_source_byte_pins"][name]
            self.assertEqual(pin["pin_kind"], "historical_source_bytes")
            self.assertEqual(pin["basename"], expected["basename"])
            self.assertEqual(pin["size_bytes"], expected["size_bytes"])
            self.assertEqual(pin["sha256"], expected["sha256"])

    def test_semantic_mutations_and_cross_splices_are_rejected(self) -> None:
        baseline = self._actual_triplet()
        mutations: list[tuple[str, object]] = []

        def public_outcome(triplet: dict[str, object]) -> None:
            triplet["public"]["outcome"] = "CONTROL_PASS"

        def public_type_confusion(triplet: dict[str, object]) -> None:
            triplet["public"]["dispatch_count"] = False

        def raw_measurement(triplet: dict[str, object]) -> None:
            triplet["raw"]["fixed_op_measurement"] = {}

        def raw_frame_id(triplet: dict[str, object]) -> None:
            triplet["raw"]["frames"][0]["evidence_id"] = "fixed_op_4"

        def journal_status(triplet: dict[str, object]) -> None:
            triplet["journal"]["status"] = "CONTROL_VERIFIED"

        def journal_frame_synthesis(triplet: dict[str, object]) -> None:
            triplet["journal"]["frames"].append(
                copy.deepcopy(triplet["journal"]["frames"][0])
            )

        def cross_splice(triplet: dict[str, object]) -> None:
            triplet["journal"]["frames"][0]["transport_error"] = "foreign"

        def hidden_a90r(triplet: dict[str, object]) -> None:
            triplet["raw"]["error"]["exception_text"] = "A90Rc071"

        mutations.extend(
            [
                ("public outcome", public_outcome),
                ("public bool/int confusion", public_type_confusion),
                ("raw fixed measurement", raw_measurement),
                ("raw frame id", raw_frame_id),
                ("journal status", journal_status),
                ("journal frame synthesis", journal_frame_synthesis),
                ("raw/journal frame cross-splice", cross_splice),
                ("hidden A90R", hidden_a90r),
            ]
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                hostile = copy.deepcopy(baseline)
                mutate(hostile)
                with self.assertRaises(retry.ControlRetryError):
                    retry._validate_predecessor_semantics(hostile)

    def test_capsule_serializer_rejects_nonfinite_values(self) -> None:
        capsule = self._actual_triplet()
        body = retry._validate_predecessor_semantics(capsule)
        hostile = copy.deepcopy(body)
        hostile["semantic"]["candidate"]["not_finite"] = float("nan")
        with self.assertRaises(retry.ControlRetryError):
            retry.canonical_capsule_bytes(hostile)

    def test_exact_leaf_mutations_are_rejected_except_non_authority_bridge_values(self) -> None:
        baseline = self._actual_triplet()
        mutations = {
            "public/arbitrary_address_input": lambda value: value["public"].update(
                arbitrary_address_input=True
            ),
            "public/automatic_retries": lambda value: value["public"].update(
                automatic_retries=True
            ),
            "public/controller_writes": lambda value: value["public"].update(
                controller_writes=True
            ),
            "public/current_boot_attestation": lambda value: value["public"].update(
                current_boot_attestation={}
            ),
            "public/device_state_write": lambda value: value["public"].update(
                device_state_write=True
            ),
            "public/final_bridge_bound": lambda value: value["public"].update(
                final_bridge_bound=True
            ),
            "public/semantic_claim": lambda value: value["public"].update(
                semantic_claim={}
            ),
            "public/raw_snapshot_size": lambda value: value["public"].update(
                raw_snapshot_size=float(retry.RAW_SIZE_BYTES)
            ),
            "public/journal_size": lambda value: value["public"].update(
                journal_size=float(retry.JOURNAL_SIZE_BYTES)
            ),
            "raw/controller_writes": lambda value: value["raw"].update(
                controller_writes=True
            ),
            "raw/final_bridge_bound": lambda value: value["raw"].update(
                final_bridge_bound=True
            ),
            "raw/health_after": lambda value: value["raw"].update(
                health_after={"ok": 0, "reason": "target_not_bound", "skipped": 1}
            ),
            "journal/health_after": lambda value: value["journal"].update(
                health_after={"ok": 0, "reason": "target_not_bound", "skipped": 1}
            ),
            "artifacts/public/basename": lambda value: value["artifacts"]["public"].update(
                basename="foreign.manifest.json"
            ),
            "artifacts/raw/basename": lambda value: value["artifacts"]["raw"].update(
                basename="foreign.json"
            ),
            "artifacts/journal/basename": lambda value: value["artifacts"]["journal"].update(
                basename="foreign.journal.json"
            ),
        }
        for path, mutate in mutations.items():
            with self.subTest(path=path):
                hostile = copy.deepcopy(baseline)
                mutate(hostile)
                with self.assertRaises(retry.ControlRetryError):
                    retry._validate_predecessor_semantics(hostile)

    def test_bridge_descendant_is_not_promoted_into_capsule(self) -> None:
        baseline = self._actual_triplet()
        hostile = copy.deepcopy(baseline)
        hostile["raw"]["bridge_binding"]["process_pid"] += 1
        capsule = retry._validate_predecessor_semantics(hostile)
        encoded = retry.canonical_capsule_bytes(capsule).decode("utf-8")
        self.assertNotIn("bridge_binding", encoded)
        self.assertFalse(capsule["claims"]["historical_bridge_is_authority"])

    def test_capsule_args_do_not_alias_validator_state(self) -> None:
        baseline = self._actual_triplet()
        first = retry._validate_predecessor_semantics(baseline)
        baseline_bytes = retry.canonical_capsule_bytes(first)
        first["semantic"]["fixed_op"]["args"].append(99)

        second = retry._validate_predecessor_semantics(baseline)
        self.assertEqual(second["semantic"]["fixed_op"]["args"], [])
        self.assertEqual(retry.canonical_capsule_bytes(second), baseline_bytes)
        self.assertEqual(retry.FIXED_OP_ARGS, [])

        hostile = copy.deepcopy(baseline)
        hostile["raw"]["op_args"] = [99]
        with self.assertRaises(retry.ControlRetryError):
            retry._validate_predecessor_semantics(hostile)


class ControlRetryHistoricalGitTests(unittest.TestCase):
    def test_historical_git_receipt_pins_commit_and_all_three_blobs(self) -> None:
        first = retry._verify_historical_git_sources()
        second = retry._verify_historical_git_sources()
        self.assertEqual(first, second)
        self.assertEqual(
            set(first), {"schema", "commit_id", "commit_type", "sources"}
        )
        self.assertEqual(first["commit_id"], retry.PRODUCER_COMMIT)
        self.assertEqual(first["commit_type"], "commit")
        expected = {
            "inline": (
                "tools/a90_inline_remapper_mid_probe.py",
                "209cdea93f344a45475c8b96476bad2a7e7b9524",
                "0b171d4ca0b5a2f77b01745a285a67eea3436c9f78eb1d800ab0792bf0818c63",
                160591,
            ),
            "autohud": (
                "tools/a90_autohud_arbitration.py",
                "4b827dfd395fbb2f19105fdbc559a8e7b8c3f4d9",
                "5da86cb927543e60626a679cbd949348c4f377c91148e59669990b6b3a6ba926",
                8213,
            ),
            "transport": (
                "tools/a90_pa28_live.py",
                "81c426069be191b061e33b26803da113fffe878f",
                "0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66",
                150104,
            ),
        }
        self.assertEqual(set(first["sources"]), set(expected))
        for role, (path, blob_sha1, body_sha256, size) in expected.items():
            with self.subTest(role=role):
                source = first["sources"][role]
                self.assertEqual(
                    source,
                    {
                        "relative_path": path,
                        "basename": Path(path).name,
                        "blob_sha1": blob_sha1,
                        "sha256": body_sha256,
                        "size_bytes": size,
                    },
                )

    def test_final_builder_is_no_arg_and_redacted(self) -> None:
        private_paths = (
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_RAW_RELATIVE_PATH,
            Path(retry.REPO_ROOT) / retry.PREDECESSOR_JOURNAL_RELATIVE_PATH,
        )
        if not all(path.is_file() for path in private_paths):
            self.skipTest("private predecessor triplet is not present")
        self.assertEqual(set(inspect.signature(retry.build_predecessor_capsule).parameters), set())
        first = retry.build_predecessor_capsule()
        second = retry.build_predecessor_capsule()
        self.assertEqual(first, second)
        self.assertEqual(set(first), {"schema", "semantic_capsule", "historical_git_verification"})
        encoded = retry.canonical_capsule_bytes(first).decode("utf-8")
        for forbidden in ("/home/", "/dev/tty", "bridge_binding", "process_pid", "listener", "payload_base64", "transcript_base64"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, encoded)
        descriptor = retry._canonical_capsule_descriptor(first)
        self.assertEqual(descriptor["size_bytes"], len(encoded.encode("utf-8")))
        self.assertEqual(descriptor["sha256"], hashlib.sha256(encoded.encode("utf-8")).hexdigest())

    def test_git_runner_excludes_caller_git_environment_and_rejects_nonzero(self) -> None:
        result = subprocess.CompletedProcess(
            args=[retry.GIT_BINARY, "cat-file", "--batch"],
            returncode=1,
            stdout=b"",
            stderr=b"git failure",
        )
        with mock.patch.object(retry.subprocess, "run", return_value=result) as run:
            with mock.patch.dict(
                os.environ,
                {"GIT_DIR": "/attacker", "GIT_OBJECT_DIRECTORY": "/attacker/objects"},
                clear=False,
            ):
                with self.assertRaises(retry.ControlRetryError):
                    retry._verify_historical_git_sources()
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        self.assertNotIn("GIT_DIR", kwargs["env"])
        self.assertNotIn("GIT_OBJECT_DIRECTORY", kwargs["env"])
        self.assertFalse(kwargs["shell"])
        self.assertLessEqual(kwargs["timeout"], 10.0)

    def test_git_runner_rejects_timeout(self) -> None:
        with mock.patch.object(
            retry.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(
                cmd=[retry.GIT_BINARY, "cat-file", "--batch"], timeout=10.0
            ),
        ):
            with self.assertRaises(retry.ControlRetryError):
                retry._verify_historical_git_sources()


if __name__ == "__main__":
    unittest.main()
