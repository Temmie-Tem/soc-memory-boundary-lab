from __future__ import annotations

import contextlib
import io
import unittest
from dataclasses import dataclass
from types import SimpleNamespace

from tools import a90_repl_mmio_snapshot as snapshot


@dataclass(frozen=True)
class FakeSymbol:
    vaddr: int


class FakeImage:
    def __init__(self, links: dict[str, int]) -> None:
        self.links = links

    def u32_at_vaddr(self, address: int) -> int:
        if address in {link - 4 for link in self.links.values()}:
            return snapshot.JOPP_MAGIC
        raise AssertionError(f"unexpected word address: {address:#x}")

    def u32_words_at_vaddr(self, address: int, count: int) -> list[int]:
        name = next(name for name, link in self.links.items() if link == address)
        return list(snapshot.EXPECTED_PREFIXES[name][:count])


class FakeSession:
    def __init__(self, links: dict[str, int]) -> None:
        self.links = links
        self.slide_value = 0x400000
        self.calls: list[tuple[int, tuple[int, ...]]] = []
        self.pointers = {
            base: 0xFFFFFFC100000000 + index * 0x1000
            for index, base in enumerate(snapshot.BASES)
        }
        self.values = {
            pointer: 0xA9000000 + index
            for index, pointer in enumerate(self.pointers.values())
        }

    def slide(self) -> int:
        return self.slide_value

    def call_runtime(self, target: int, args: tuple[int, ...]) -> int:
        self.calls.append((target, args))
        if target == self.links["__ioremap"] + self.slide_value:
            base, size, prot = args
            self.assert_equal(size, snapshot.WINDOW_SIZE)
            self.assert_equal(prot, snapshot.PROT_DEVICE_NGNRE)
            return self.pointers[base]
        if target == self.links["msm_readl"] + self.slide_value:
            return self.values[args[0]]
        if target == self.links["__iounmap"] + self.slide_value:
            return 0
        raise AssertionError(f"unexpected target: {target:#x}")

    @staticmethod
    def assert_equal(actual: int, expected: int) -> None:
        if actual != expected:
            raise AssertionError(f"{actual:#x} != {expected:#x}")


class A90ReplMmioSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.links = {
            "__ioremap": 0xFFFFFF80080A4094,
            "msm_readl": 0xFFFFFF80088BC98C,
            "__iounmap": 0xFFFFFF80080A4194,
        }
        self.symbols = {
            name: FakeSymbol(link) for name, link in self.links.items()
        }

    def test_fixed_read_maps_reads_and_unmaps_each_window(self) -> None:
        session = FakeSession(self.links)
        public, raw = snapshot.read_fixed_controls(
            session, self.symbols, FakeImage(self.links)
        )
        self.assertEqual([row["base"] for row in public], [
            f"0x{base:08x}" for base in snapshot.BASES
        ])
        self.assertEqual([row["value"] for row in public], [
            f"0x{0xA9000000 + index:08x}" for index in range(4)
        ])
        self.assertEqual(len(session.calls), 12)
        self.assertTrue(all(row["iounmap_completed"] for row in raw["records"]))

    def test_symbol_gate_rejects_non_jopp_entry(self) -> None:
        image = FakeImage(self.links)
        image.u32_at_vaddr = lambda _address: 0  # type: ignore[method-assign]
        with self.assertRaisesRegex(RuntimeError, "JOPP"):
            snapshot.symbol_links(self.symbols, image)

    def test_cli_has_no_arbitrary_address_or_full_mode(self) -> None:
        parser = snapshot.make_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--experiment-id", "test", "--address", "0x0"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["--experiment-id", "test", "--full"])

    def test_decimal_parser_is_strict(self) -> None:
        self.assertEqual(snapshot.parse_single_decimal(b"1\n"), 1)
        with self.assertRaises(ValueError):
            snapshot.parse_single_decimal(b"1 2\n")

    def test_live_collect_is_disabled_before_argument_or_device_use(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "known watchdog path disabled"):
            snapshot.collect(SimpleNamespace())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
