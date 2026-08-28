from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import a90_pa28_dt_snapshot as snap


def _frame_record(evidence_id: str, payload: bytes, rc: int = 0, errno: int = 0) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "argv": [],
        "rc": rc,
        "status": "ok" if rc == 0 else "error",
        "errno": errno,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }


def _records() -> dict[str, dict[str, object]]:
    u32 = lambda value: value.to_bytes(4, "big")
    records = {
        "ion_heap30_reg": _frame_record("ion_heap30_reg", u32(30)),
        "ion_heap30_memory_region": _frame_record("ion_heap30_memory_region", u32(0x67A)),
        "ion_heap30_name": _frame_record("ion_heap30_name", b"qcom,ion-heap\0"),
        "camera_reg": _frame_record("camera_reg", bytes.fromhex("00000000c20000000000000014000000")),
        "camera_phandle": _frame_record("camera_phandle", u32(0x67A)),
        "camera_name": _frame_record("camera_name", b"camera_mem_region\0"),
        "camera_ion_recyclable": _frame_record("camera_ion_recyclable", b""),
        "camera_no_map": _frame_record("camera_no_map", b"", -2, 2),
        "camera_reusable": _frame_record("camera_reusable", b"", -2, 2),
    }
    return records


class SnapshotTests(unittest.TestCase):
    def test_dt_semantics_require_the_exact_heap_chain(self) -> None:
        semantic = snap._semantic(_records())
        self.assertEqual(semantic["ion_heap30"]["reg"], "0x1e")
        self.assertEqual(semantic["ion_heap30"]["memory_region_phandle"], "0x67a")
        self.assertEqual(semantic["camera_mem_region"]["reg"]["base"], "0xc2000000")
        self.assertEqual(semantic["camera_mem_region"]["reg"]["size"], "0x14000000")
        self.assertFalse(semantic["camera_mem_region"]["optional_properties"]["camera_no_map"]["present"])

    def test_chain_mutation_fails_closed(self) -> None:
        records = _records()
        records["camera_phandle"]["payload_base64"] = base64.b64encode((0x678).to_bytes(4, "big")).decode()
        with self.assertRaises(snap.SnapshotError):
            snap._semantic(records)

    def test_property_error_mutation_fails_closed(self) -> None:
        records = _records()
        records["camera_reusable"]["rc"] = 0
        records["camera_reusable"]["status"] = "ok"
        with self.assertRaises(snap.SnapshotError):
            snap._semantic(records)

    def test_target_drift_fails_closed(self) -> None:
        with self.assertRaises(snap.SnapshotError):
            snap.validate_target(b"A90 Linux init 0.9.286", b"androidboot.em.model=SM-A908N")

    def test_command_surface_is_fixed(self) -> None:
        paths = [argv for _, argv, _ in snap.COMMANDS]
        self.assertTrue(all(argv[0] in {"version", "cat", "ls"} for argv in paths))
        self.assertFalse(any("/dev/mem" in argv for argv in paths))
        self.assertEqual(len({evidence_id for evidence_id, _, _ in snap.COMMANDS}), len(snap.COMMANDS))

    def test_write_new_refuses_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(snap, "ROOT", Path(tmp)):
                path = Path(tmp) / "x"
                snap.write_new(path, b"x", 0o600)
                with self.assertRaises(FileExistsError):
                    snap.write_new(path, b"y", 0o600)

    def test_symlinked_parent_component_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (root / "evidence").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(snap, "ROOT", root):
                with self.assertRaises(snap.SnapshotError):
                    snap.write_new(root / "evidence" / "private" / "x", b"x", 0o600)

    def test_output_root_is_bound_to_this_repository(self) -> None:
        with self.assertRaises(snap.SnapshotError):
            snap.collect("verification-020m-fixture", Path(tempfile.gettempdir()))


if __name__ == "__main__":
    unittest.main()
