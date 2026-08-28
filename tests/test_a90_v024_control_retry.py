from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
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


if __name__ == "__main__":
    unittest.main()
