from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = REPO_ROOT / "tools" / "a90_pa28_probe_v022r.c"
HISTORICAL_SOURCE_PATH = REPO_ROOT / "tools" / "a90_pa28_probe.c"
HISTORICAL_SOURCE_SHA256 = (
    "b324c1c3332c61b00f6d6e5c75891721be4a5fb2a998c7f0222900d4eba5e199"
)


class Pa28ProbeV022RContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")

    def test_historical_probe_remains_byte_identical(self) -> None:
        digest = hashlib.sha256(HISTORICAL_SOURCE_PATH.read_bytes()).hexdigest()
        self.assertEqual(digest, HISTORICAL_SOURCE_SHA256)

    def test_exact_argv_path_and_ordered_difference_contract(self) -> None:
        source = self.source
        self.assertIn('#define PROBE_SCHEMA "a90_pa28_probe_v022r_v1"', source)
        self.assertIn('#define FIXED_ION_PATH "/tmp/a90-native/v022r-ion"', source)
        self.assertIn("#define EXPECTED_ARGC 20", source)
        self.assertRegex(source, r"if \(argc != EXPECTED_ARGC\)")
        self.assertNotIn("argc < 9", source)
        self.assertNotIn("difference_count", source)

        definitions = dict(
            re.findall(
                r"#define (DIFFERENCE_[A-Z0-9_]+) UINT64_C\((0x[0-9a-f]+)\)",
                source,
            )
        )
        expected_names = [
            "DIFFERENCE_CONFLICT",
            "DIFFERENCE_NEGATIVE",
            "DIFFERENCE_PA28_BANK13",
            "DIFFERENCE_PA28_BANK14",
            "DIFFERENCE_PA28_BANK13_14",
            "DIFFERENCE_PA28_BANK15",
            "DIFFERENCE_PA28_BANK13_15",
            "DIFFERENCE_PA28_BANK14_15",
            "DIFFERENCE_PA28_BANK13_14_15",
            "DIFFERENCE_CONFLICT",
            "DIFFERENCE_NEGATIVE",
        ]
        list_body = re.search(
            r"FIXED_DIFFERENCES\[MAX_DIFFERENCES\]\s*=\s*\{(?P<body>.*?)\};",
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(list_body)
        actual_names = re.findall(
            r"\bDIFFERENCE_[A-Z0-9_]+\b", list_body.group("body")
        )
        self.assertEqual(actual_names, expected_names)
        self.assertEqual(
            [definitions[name] for name in actual_names],
            [
                "0x16000",
                "0x2000",
                "0x10002000",
                "0x10004000",
                "0x10006000",
                "0x10008000",
                "0x1000a000",
                "0x1000c000",
                "0x1000e000",
                "0x16000",
                "0x2000",
            ],
        )
        self.assertNotIn("0x10000000", source)
        self.assertIn("value != FIXED_DIFFERENCES[index]", source)
        self.assertIn('strcmp(ion_path, FIXED_ION_PATH) != 0', source)
        self.assertIn(
            'ion_fd = open(FIXED_ION_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);',
            source,
        )
        self.assertNotIn('strcmp(path, "/dev/ion")', source)
        self.assertNotIn("safe_ion_path", source)

    def test_rejection_happens_before_device_effect(self) -> None:
        main = self.source[self.source.index("int main("):]
        before_pin = main.split("if (pin_cpu(cpu) != 0)", 1)[0]
        self.assertNotIn("open(", before_pin)
        self.assertNotIn("ioctl(", before_pin)
        self.assertNotIn("mmap(", before_pin)
        self.assertIn("value != FIXED_DIFFERENCES[index]", before_pin)

    def test_all_post_open_failures_use_one_cleanup_epilogue(self) -> None:
        post_open = self.source.split("ion_fd = open(FIXED_ION_PATH", 1)[1]
        post_open, cleanup = post_open.split("cleanup:", 1)
        self.assertNotIn("return ", post_open)
        self.assertGreaterEqual(post_open.count("goto cleanup;"), 9)
        self.assertIn("int allocation_fd = -1;", self.source)
        self.assertIn("if (allocation_fd >= 0)", cleanup)
        self.assertIn("if (ion_fd >= 0)", cleanup)
        self.assertIn("if (map_mapped)", cleanup)
        self.assertIn("if (eviction_mapped)", cleanup)
        self.assertIn("munmap(eviction, EVICTION_BYTES)", cleanup)
        self.assertIn("munmap(map, bytes)", cleanup)
        self.assertIn("free(relation)", cleanup)
        self.assertIn("free(baseline)", cleanup)
        self.assertIn("free(heaps)", cleanup)
        self.assertNotIn("close((int)allocation.fd)", cleanup)

    def test_cleanup_record_is_terminal_and_strict(self) -> None:
        source = self.source
        cleanup_label = source.index("cleanup:")
        record = source[cleanup_label:]
        self.assertNotIn('\\"type\\":\\"cleanup\\"', source[:cleanup_label])
        self.assertLess(source.index('\\"type\\":\\"cleanup\\"'), source.rindex("return 0;"))
        for field in (
            "schema",
            "type",
            "attempted",
            "released",
            "ion_fd_closed",
            "allocation_fd_closed",
            "map_unmapped",
            "eviction_unmapped",
            "heaps_freed",
            "sample_buffers_freed",
            "status",
        ):
            self.assertIn(f'\\"{field}\\"', record)
        self.assertIn('\\"status\\":\\"PASS\\"', record)
        self.assertIn("if (exit_code == 0 && cleanup_failed)", source)
        self.assertIn("if (exit_code != 0)", source)
        self.assertIn("return exit_code;", source)

    def test_probe_has_no_forbidden_device_surfaces(self) -> None:
        source = self.source
        self.assertIn("SUPPORTED_WITHIN_RETAINED_RECEIPT", source)
        self.assertNotIn("Verification 021 proved", source)
        for forbidden in (
            '"/dev/mem"',
            '"/dev/kmem"',
            '"/sys/kernel/debug"',
            "devmem",
            "SMC",
            "SCM",
            "mcr",
            "mrc",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("DIFFERENCE_PA28 UINT64_C", source)
        self.assertIn("EXPECTED_HEAP_TYPE 10U", source)
        self.assertIn("EXPECTED_HEAP_ID 30U", source)
        self.assertIn("EXPECTED_MIB UINT64_C(320)", source)
        self.assertIn("EXPECTED_REPETITIONS 201U", source)
        self.assertIn("EXPECTED_PAIRS 256U", source)
        self.assertIn("EXPECTED_CPU 7U", source)
        self.assertIn("EXPECTED_CNTFRQ UINT64_C(19200000)", source)
        self.assertIn("EXPECTED_BASE UINT64_C(0xc2000000)", source)
        self.assertIn("This allocation is not a power of two", source)
        self.assertNotIn("The allocation is a power of two", source)

    def test_host_syntax_check(self) -> None:
        result = subprocess.run(
            [
                "gcc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsyntax-only",
                str(SOURCE_PATH),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
