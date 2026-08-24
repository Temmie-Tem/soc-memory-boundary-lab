from __future__ import annotations

import hashlib
import struct
import unittest

from tools import sm8150_dram_coordinate_inventory as dram


def encode_section16_record(bases: tuple[int, ...], offsets: tuple[int, ...]) -> bytes:
    return (
        struct.pack("<BB", len(bases), len(offsets))
        + struct.pack(f"<{len(bases)}H", *bases)
        + struct.pack(f"<{len(offsets)}H", *offsets)
    )


def synthetic_section16() -> bytes:
    first = encode_section16_record((0x9250, 0x92D0, 0x9350, 0x93D0), (0x46,))
    first += b"\0\0"
    split = 8 + len(first)
    second = encode_section16_record((0x90B0,), (0xA0, 0xA1))
    second += b"\0\0"
    total = split + len(second)
    return struct.pack("<HHHH", 8, total, split, 0x8E8) + first + second


def topology_record(
    group: int, instance: int, master: str, target: str, address: str
) -> bytes:
    return (
        struct.pack("<II", group, instance)
        + master.encode("ascii").ljust(25, b"\0")
        + target.encode("ascii").ljust(32, b"\0")
        + address.encode("ascii").ljust(19, b"\0")
    )


def synthetic_shrm_topology() -> bytes:
    records: list[bytes] = []

    def add_group(group: int, target: str, addresses: tuple[str, ...]) -> None:
        for instance, address in enumerate(addresses):
            records.append(
                topology_record(group, instance, "qhm_shrm", target, address)
            )

    add_group(0x20, "qhs_ahb2phy", ("0x9180000", "0x9190000", "0x91C0000"))
    add_group(
        0x21,
        "qhs_mccc",
        ("0x9250000", "0x92D0000", "0x9350000", "0x93D0000", "0x9650000"),
    )
    add_group(
        0x21,
        "qhs_llcc",
        (
            "0x9240000",
            "0x92C0000",
            "0x9340000",
            "0x93C0000",
            "0x9640000",
            "0x9200000",
            "0x9280000",
            "0x9300000",
            "0x9380000",
            "0x9600000",
        ),
    )
    records.append(topology_record(0x21, 15, "qhm_shrm", "qhs_mccc", "NA"))
    add_group(
        0x24,
        "qhs_mc",
        ("0x9260000", "0x92E0000", "0x9360000", "0x93E0000", "0x9660000"),
    )
    add_group(0x25, "qhs_memnoc", ("0x96C0000", "0x9680000"))
    add_group(0x26, "qhs_mccc_master", ("0x90B0000",))
    add_group(0x26, "qhs_qmip0", ("0x90B6000",))
    add_group(0x26, "qhs_qmip1", ("0x90B7000",))
    add_group(0x26, "qhs_qmip2", ("0x90B8000",))
    add_group(0x26, "qhs_shrm_csr", ("0x9050000",))
    add_group(0x26, "qhs_ddrss_regs", ("0x90C0000",))
    add_group(0x29, "srvc_dc_noc", ("0x9160000",))
    assert len(records) == dram.SHRM_TOPOLOGY_RECORD_COUNT
    return b"prefix" + b"".join(records) + b"suffix"


class Sm8150DramCoordinateInventoryTests(unittest.TestCase):
    def test_section16_two_set_grammar_ends_exactly(self) -> None:
        parsed = dram.parse_section16_register_sets(synthetic_section16())
        self.assertEqual(parsed["header"]["unknown_u16_3"], "0x08e8")
        self.assertEqual([item["record_count"] for item in parsed["sets"]], [2, 2])
        first = parsed["sets"][0]["records"][0]
        self.assertEqual(first["base_pages"], ["0x9250", "0x92d0", "0x9350", "0x93d0"])
        self.assertEqual(first["base_addresses_if_4k_pages"][0], "0x09250000")
        self.assertEqual(first["offset_tokens"], ["0x0046"])
        self.assertTrue(parsed["sets"][1]["records"][1]["padding"])

    def test_section16_rejects_bad_total_and_record_crossing_split(self) -> None:
        data = bytearray(synthetic_section16())
        struct.pack_into("<H", data, 2, len(data) + 1)
        with self.assertRaisesRegex(ValueError, "total-size mismatch"):
            dram.parse_section16_register_sets(bytes(data))

        data = bytearray(synthetic_section16())
        struct.pack_into("<H", data, 4, 11)
        with self.assertRaisesRegex(ValueError, "crosses its boundary"):
            dram.parse_section16_register_sets(bytes(data))

    def test_shrm_topology_binds_exact_controller_families(self) -> None:
        parsed = dram.parse_shrm_topology(synthetic_shrm_topology())
        self.assertEqual(parsed["record_count"], 33)
        self.assertEqual(
            parsed["bindings"]["qhs_mccc"],
            [
                "0x09250000",
                "0x092d0000",
                "0x09350000",
                "0x093d0000",
                "0x09650000",
            ],
        )
        self.assertEqual(parsed["bindings"]["qhs_mccc_master"], ["0x090b0000"])

    def test_current_rank_boundary_matches_selected_row(self) -> None:
        self.assertEqual(dram.diagnostic_rank1_base(6), 0x140000000)
        self.assertEqual(
            dram.diagnostic_coordinate(0x13FFFFFFF, 6)["rank"], 0
        )
        self.assertEqual(
            dram.diagnostic_coordinate(0x140000000, 6)["rank"], 1
        )

    def test_coordinate_formula_round_trips_and_partitions_bits(self) -> None:
        for rank in (0, 1):
            base = dram.SYSTEM_DRAM_BASE if rank == 0 else dram.diagnostic_rank1_base(6)
            for offset in (
                0,
                1,
                1 << 1,
                1 << 9,
                1 << 11,
                1 << 13,
                1 << 16,
                0x12345678,
                0xBFFFFFFF,
            ):
                parsed = dram.diagnostic_coordinate(base + offset, 6)
                observed = dram.coordinate_to_pa(
                    rank=parsed["rank"],
                    row=parsed["row"],
                    bank=parsed["bank"],
                    channel=parsed["channel"],
                    column=parsed["column"],
                    byte_in_x16=parsed["byte_in_x16"],
                    total_gib=6,
                )
                self.assertEqual(observed, base + offset)

        base = dram.SYSTEM_DRAM_BASE
        self.assertEqual(dram.diagnostic_coordinate(base + (1 << 9), 6)["channel"], 1)
        self.assertEqual(dram.diagnostic_coordinate(base + (1 << 13), 6)["bank"], 1)
        self.assertEqual(dram.diagnostic_coordinate(base + (1 << 16), 6)["row"], 1)
        self.assertEqual(dram.diagnostic_coordinate(base + (1 << 11), 6)["column"], 0x100)

    def test_coordinate_encoding_has_no_collisions_in_sample_domain(self) -> None:
        seen = set()
        for offset in range(1 << 16):
            parsed = dram.diagnostic_coordinate(dram.SYSTEM_DRAM_BASE + offset, 6)
            key = (
                parsed["rank"],
                parsed["row"],
                parsed["bank"],
                parsed["channel"],
                parsed["column"],
                parsed["byte_in_x16"],
            )
            self.assertNotIn(key, seen)
            seen.add(key)
        self.assertEqual(len(seen), 1 << 16)

    def test_artifact_pin_rejects_size_and_hash_mismatch(self) -> None:
        data = b"exact"
        valid = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.assertTrue(dram.verify_pinned_bytes("sample", data, valid)["pin_verified"])
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            dram.verify_pinned_bytes(
                "sample", data, {"size": len(data) + 1, "sha256": valid["sha256"]}
            )
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            dram.verify_pinned_bytes(
                "sample", data, {"size": len(data), "sha256": "0" * 64}
            )


if __name__ == "__main__":
    unittest.main()
