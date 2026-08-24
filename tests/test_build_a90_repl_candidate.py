from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import build_a90_repl_candidate as candidate


class BuildA90ReplCandidateTests(unittest.TestCase):
    def test_live_proven_identity_is_pinned(self) -> None:
        self.assertEqual(
            candidate.SOURCE_COMMIT,
            "f44b34c8f44a9a01c99bb589644494c732a6c3fa",
        )
        self.assertEqual(
            candidate.CANDIDATE_SHA256,
            "b846ae9f74d8ceb922bbcd854d78b6795ef833d61e38465d3cc474cb6f0dfb65",
        )
        self.assertEqual(len(candidate.HISTORICAL_SOURCES), 3)

    def test_existing_or_symlink_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            existing = root / "existing"
            existing.write_bytes(b"x")
            with self.assertRaises(FileExistsError):
                candidate.require_new_regular_targets((existing,))

            target = root / "target"
            target.write_bytes(b"y")
            symlink = root / "link"
            symlink.symlink_to(target)
            with self.assertRaises(FileExistsError):
                candidate.require_new_regular_targets((symlink,))


if __name__ == "__main__":
    unittest.main()
