"""Evidence retention hygiene: no private evidence path may be a symbolic link.

Verification 019's raw receipt was published as `SUPPORTED_EXTERNAL_MANIFEST_ONLY`
because `evidence/private/verification-019-suspend-permutation-20260827-01` was a
symbolic link into a scratch worktree; pruning that worktree dangled the link and
removed the raw from the repository's view.  The analyzers already refuse to
*read* through a symlink (`O_NOFOLLOW`), but nothing refused to *retain* through
one.  This closes that side.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = REPO_ROOT / "evidence" / "private"

# `host-tools` is a vendored build/venv tree, not evidence.  Virtualenvs and
# autotools trees legitimately contain internal symlinks; nothing under it is a
# receipt that a manifest is pinned to.  Every other subtree holds receipts.
TOOL_SUBTREES = frozenset({"host-tools"})


def _receipt_walk():
    """Walk only the receipt subtrees of evidence/private."""
    for entry in sorted(PRIVATE_ROOT.iterdir()):
        if entry.name in TOOL_SUBTREES:
            continue
        yield entry
        if entry.is_dir() and not entry.is_symlink():
            for dirpath, dirnames, filenames in os.walk(entry, followlinks=False):
                here = Path(dirpath)
                for name in list(dirnames) + filenames:
                    yield here / name


class EvidencePrivateNoSymlinks(unittest.TestCase):
    def test_private_root_is_a_real_directory(self) -> None:
        if not PRIVATE_ROOT.exists():
            self.skipTest("evidence/private is absent on this host")
        self.assertFalse(
            PRIVATE_ROOT.is_symlink(),
            "evidence/private itself is a symbolic link",
        )
        self.assertTrue(PRIVATE_ROOT.is_dir(), "evidence/private is not a directory")

    def test_no_receipt_path_is_a_symlink(self) -> None:
        """A receipt reached through a link is one worktree prune from gone."""
        if not PRIVATE_ROOT.is_dir():
            self.skipTest("evidence/private is absent on this host")
        offenders: list[str] = []
        for candidate in _receipt_walk():
            if candidate.is_symlink():
                state = "dangling" if not candidate.exists() else "resolves"
                offenders.append(
                    f"{candidate.relative_to(REPO_ROOT)} -> "
                    f"{os.readlink(candidate)} ({state})"
                )
        self.assertEqual(
            [],
            offenders,
            "private evidence must be retained in place, not linked elsewhere:\n"
            + "\n".join(offenders),
        )

    def test_no_dangling_symlink_anywhere_under_private(self) -> None:
        """The exact V019 failure: the link outlived what it pointed at."""
        if not PRIVATE_ROOT.is_dir():
            self.skipTest("evidence/private is absent on this host")
        dangling: list[str] = []
        for dirpath, dirnames, filenames in os.walk(PRIVATE_ROOT, followlinks=False):
            here = Path(dirpath)
            for name in list(dirnames) + filenames:
                candidate = here / name
                if candidate.is_symlink() and not candidate.exists():
                    dangling.append(
                        f"{candidate.relative_to(REPO_ROOT)} -> {os.readlink(candidate)}"
                    )
        self.assertEqual(
            [],
            dangling,
            "dangling links under evidence/private:\n" + "\n".join(dangling),
        )

    def test_retained_receipts_are_readable_regular_files(self) -> None:
        """A retained receipt that cannot be opened is not retained."""
        if not PRIVATE_ROOT.is_dir():
            self.skipTest("evidence/private is absent on this host")
        broken: list[str] = []
        for candidate in _receipt_walk():
            if candidate.is_symlink() or candidate.is_dir():
                continue
            try:
                fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as exc:
                broken.append(f"{candidate.relative_to(REPO_ROOT)}: {exc}")
                continue
            try:
                if not os.path.isfile(candidate):
                    broken.append(
                        f"{candidate.relative_to(REPO_ROOT)}: not a regular file"
                    )
            finally:
                os.close(fd)
        self.assertEqual([], broken, "unreadable retained evidence:\n" + "\n".join(broken))


class GuardFiresOnTheDefect(unittest.TestCase):
    """Negative control: rebuild the exact V019 shape and require a failure."""

    def _run_against(self, root: Path) -> list[str]:
        offenders: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            for name in list(dirnames) + filenames:
                candidate = here / name
                if candidate.is_symlink() and not candidate.exists():
                    offenders.append(str(candidate))
        return offenders

    def test_dangling_receipt_link_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gone = root / "pruned-worktree" / "evidence" / "private" / "v019"
            gone.mkdir(parents=True)
            link = root / "verification-019-suspend-permutation-20260827-01"
            link.symlink_to(gone)
            self.assertEqual([], self._run_against(root), "link resolves while target exists")
            shutil.rmtree(root / "pruned-worktree")
            self.assertEqual(
                [str(link)],
                self._run_against(root),
                "guard failed to detect the dangling receipt link",
            )


if __name__ == "__main__":
    unittest.main()
