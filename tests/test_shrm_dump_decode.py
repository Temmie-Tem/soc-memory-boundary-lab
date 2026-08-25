from __future__ import annotations

import json
import struct
import unittest

from tools import shrm_dump_decode as decoder


def synthetic_dump(values: dict[int, int] | None = None) -> bytes:
    """Build a dump whose workspace header matches the proved section-16 layout."""
    data = bytearray(decoder.DUMP_SIZE)
    struct.pack_into(
        "<4H", data, decoder.WORKSPACE_OFFSET, *decoder.EXPECTED_HEADER
    )
    for offset, value in (values or {}).items():
        struct.pack_into("<I", data, offset, value)
    return bytes(data)


class PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plans = decoder.load_plan()

    def test_two_sets_match_experiment_012_counts(self) -> None:
        self.assertEqual([plan.count for plan in self.plans], [430, 64])

    def test_destination_offsets_match_the_proved_header(self) -> None:
        self.assertEqual(
            [plan.destination_offset for plan in self.plans], [0x230, 0x8E8]
        )

    def test_register_order_matches_the_manifest_sequence(self) -> None:
        manifest = json.loads(decoder.SECTION16_MANIFEST.read_text(encoding="utf-8"))
        for plan, entry in zip(self.plans, manifest["section16_interpreter"]["sets"]):
            expected = [
                int(address, 16)
                for record in entry["records"]
                for address in record["register_addresses"]
            ]
            self.assertEqual([word.register for word in plan.words], expected)

    def test_every_register_is_distinct(self) -> None:
        for plan in self.plans:
            self.assertEqual(len({word.register for word in plan.words}), plan.count)

    def test_staged_words_are_contiguous_from_their_destination(self) -> None:
        for plan in self.plans:
            base = decoder.WORKSPACE_OFFSET + plan.destination_offset
            for position, word in enumerate(plan.words):
                self.assertEqual(word.dump_offset, base + position * 4)

    def test_staged_words_stay_inside_the_workspace(self) -> None:
        limit = decoder.WORKSPACE_OFFSET + decoder.WORKSPACE_SIZE
        for plan in self.plans:
            for word in plan.words:
                self.assertLess(word.dump_offset + 4, limit + 4)
                self.assertGreaterEqual(word.dump_offset, decoder.WORKSPACE_OFFSET)


class ValidationTests(unittest.TestCase):
    def test_correct_dump_validates(self) -> None:
        decoder.validate_dump(synthetic_dump())

    def test_wrong_size_is_rejected(self) -> None:
        with self.assertRaises(decoder.DumpError):
            decoder.validate_dump(synthetic_dump()[:-1])

    def test_wrong_header_is_rejected(self) -> None:
        data = bytearray(synthetic_dump())
        struct.pack_into("<H", data, decoder.WORKSPACE_OFFSET, 0x9999)
        with self.assertRaises(decoder.DumpError):
            decoder.validate_dump(bytes(data))

    def test_zeroed_dump_is_rejected_rather_than_decoded_as_zeros(self) -> None:
        with self.assertRaises(decoder.DumpError):
            decoder.validate_dump(bytes(decoder.DUMP_SIZE))


class DecodeTests(unittest.TestCase):
    def test_values_land_on_their_registers(self) -> None:
        plans = decoder.load_plan()
        first = plans[0].words[0]
        second = plans[1].words[0]
        data = synthetic_dump(
            {first.dump_offset: 0xDEADBEEF, second.dump_offset: 0x0000C071}
        )
        decoded = decoder.decode(data)
        self.assertEqual(decoded[0].words[0].register, first.register)
        self.assertEqual(decoded[0].words[0].value, 0xDEADBEEF)
        self.assertEqual(decoded[1].words[0].register, second.register)
        self.assertEqual(decoded[1].words[0].value, 0x0000C071)

    def test_decode_preserves_plan_shape(self) -> None:
        decoded = decoder.decode(synthetic_dump())
        self.assertEqual([plan.count for plan in decoded], [430, 64])


class RemapperCoverageTests(unittest.TestCase):
    """The limitation most likely to be misread by a future reader."""

    def setUp(self) -> None:
        self.coverage = decoder.remapper_coverage(decoder.load_plan())

    def test_snapshot_does_not_reach_the_remapper_window(self) -> None:
        self.assertFalse(self.coverage["covers_remapper_window"])
        self.assertEqual(self.coverage["staged_inside_remapper_window"], [])

    def test_control_register_is_the_experiment_007_watchdog_address(self) -> None:
        self.assertIn("0x09248080", self.coverage["control_registers"])

    def test_snapshot_does_touch_the_same_pages(self) -> None:
        staged = self.coverage["staged_on_remapper_pages"]
        self.assertEqual(len(staged), 36, "nine words on each of four instances")
        self.assertIn("0x09248030", staged)
        self.assertIn("0x09248064", staged)

    def test_every_staged_page_word_is_below_the_window(self) -> None:
        for value in self.coverage["staged_on_remapper_pages"]:
            self.assertLess(int(value, 16) & 0xFFF, 0x080)


class ManifestTests(unittest.TestCase):
    def test_plan_only_manifest_reports_no_dump(self) -> None:
        manifest = decoder.build_manifest(decoder.load_plan(), None, None)
        self.assertEqual(manifest["state"], "PLAN_ONLY_NO_DUMP_PRESENT")
        self.assertIsNone(manifest["dump"]["sha256"])

    def test_decoded_manifest_records_the_dump_hash(self) -> None:
        data = synthetic_dump()
        manifest = decoder.build_manifest(decoder.decode(data), None, data)
        self.assertEqual(manifest["state"], "DECODED")
        self.assertEqual(len(manifest["dump"]["sha256"]), 64)

    def test_manifest_never_emits_register_values(self) -> None:
        data = synthetic_dump({decoder.WORKSPACE_OFFSET + 0x230: 0xDEADBEEF})
        manifest = decoder.build_manifest(decoder.decode(data), None, data)
        self.assertFalse(manifest["register_values_emitted"])
        self.assertNotIn("deadbeef", json.dumps(manifest).lower())

    def test_manifest_records_host_only_posture(self) -> None:
        manifest = decoder.build_manifest(decoder.load_plan(), None, None)
        self.assertFalse(manifest["device_access"])
        self.assertFalse(manifest["smc_access"])
        self.assertFalse(manifest["mmio_access"])


if __name__ == "__main__":
    unittest.main()
