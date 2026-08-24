from __future__ import annotations

import hashlib
import struct
import unittest
from unittest import mock

from tools import sm8150_xpu_initializer_inventory as init
from tools.xbl_dcb_inventory import LoadSegment


BASE = 0x100000


def one_segment(data: bytes) -> list[LoadSegment]:
    return [
        LoadSegment(
            0,
            0,
            BASE,
            BASE,
            len(data),
            len(data),
            6,
            0x1000,
        )
    ]


def encode_direct_branch(pc: int, target: int, *, link: bool) -> int:
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch")
    opcode = 0x94000000 if link else 0x14000000
    return opcode | ((delta // 4) & 0x03FFFFFF)


class Sm8150XpuInitializerInventoryTests(unittest.TestCase):
    def test_syscall_record_layout_is_24_bytes(self) -> None:
        data = bytearray(0x100)
        vaddr = BASE + 0x20
        struct.pack_into(
            "<IIIIQ",
            data,
            0x20,
            0,
            init.SMC_HYP_ASSIGN,
            0x1117,
            0x80000000,
            0x85723B90,
        )
        record = init.parse_syscall_record(bytes(data), one_segment(data), vaddr)
        self.assertEqual(init.SYSCALL_RECORD_SIZE, 24)
        self.assertEqual(record["smc_id"], init.SMC_HYP_ASSIGN)
        self.assertEqual(record["flags"], 0x80000000)
        self.assertEqual(record["handler"], 0x85723B90)

    def test_syscall_verifier_checks_file_offset_to_vaddr(self) -> None:
        data = bytearray(0x100)
        raw = struct.pack("<IIIIQ", 0, init.SMC_RPM_ONLINE_DUMP, 1, 0, BASE + 0x80)
        data[0x20 : 0x20 + len(raw)] = raw
        spec = {
            "rpm": {
                "file_offset": 0x20,
                "record_vaddr": BASE + 0x20,
                "reserved": 0,
                "smc_id": init.SMC_RPM_ONLINE_DUMP,
                "param_id": 1,
                "flags": 0,
                "handler": BASE + 0x80,
            }
        }
        parsed = init.verify_syscall_records(
            "test", bytes(data), one_segment(data), spec
        )
        self.assertEqual(parsed["rpm"]["file_offset"], "0x20")
        self.assertEqual(parsed["rpm"]["raw_sha256"], hashlib.sha256(raw).hexdigest())

    def test_direct_branch_decoder_handles_forward_call_and_backward_jump(self) -> None:
        call_target = BASE + 0x40
        words = (
            encode_direct_branch(BASE, call_target, link=True),
            encode_direct_branch(BASE + 4, BASE, link=False),
        )
        branches = init.aarch64_direct_branch_targets(
            struct.pack("<II", *words), BASE
        )
        self.assertEqual(branches["calls"], [call_target])
        self.assertEqual(branches["jumps"], [BASE])

    def test_direct_branch_decoder_rejects_partial_instruction(self) -> None:
        with self.assertRaisesRegex(ValueError, "multiple of four"):
            init.aarch64_direct_branch_targets(b"\0", BASE)

    def test_all_offsets_reports_overlapping_matches(self) -> None:
        self.assertEqual(init.all_offsets(b"aaaa", b"aa"), [0, 1, 2])
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            init.all_offsets(b"aaaa", b"")

    def test_master_selector_resolves_resource_through_registry(self) -> None:
        data = bytearray(0x800)
        table = BASE + 0x100
        selector = 2
        record_vaddr = BASE + 0x300
        resource_id = 0x2E
        struct.pack_into("<Q", data, table - BASE + selector * 8, record_vaddr)
        struct.pack_into("<I", data, record_vaddr - BASE, selector)
        struct.pack_into("<I", data, record_vaddr - BASE + 312, resource_id)
        registry = {resource_id: {"name": "BIMC_MPU0"}}
        with (
            mock.patch.object(init, "MASTER_MPU_POINTER_TABLE_VADDR", table),
            mock.patch.object(
                init,
                "MASTER_MPU_SELECTORS",
                {selector: (record_vaddr, resource_id, "BIMC_MPU0")},
            ),
        ):
            parsed = init.parse_master_mpu_selectors(
                bytes(data), one_segment(data), registry
            )
        self.assertEqual(parsed[0]["selector"], "0x2")
        self.assertEqual(parsed[0]["resource_name"], "BIMC_MPU0")

    def test_artifact_pin_rejects_size_and_hash_mismatch(self) -> None:
        data = b"exact"
        valid = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.assertTrue(init.verify_pinned_bytes("sample", data, valid)["pin_verified"])
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            init.verify_pinned_bytes(
                "sample", data, {"size": len(data) + 1, "sha256": valid["sha256"]}
            )
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            init.verify_pinned_bytes(
                "sample", data, {"size": len(data), "sha256": "0" * 64}
            )

    def test_controller_inventory_binds_four_distinct_instances(self) -> None:
        self.assertEqual(len(init.CONTROLLER_INSTANCES), 4)
        self.assertEqual(
            {entry["resource_id"] for entry in init.CONTROLLER_INSTANCES},
            {0x2E, 0x2F, 0x3F, 0x40},
        )
        self.assertEqual(
            {entry["bimc_mpu"] for entry in init.CONTROLLER_INSTANCES},
            {0x0924E000, 0x092CE000, 0x0934E000, 0x093CE000},
        )


if __name__ == "__main__":
    unittest.main()
