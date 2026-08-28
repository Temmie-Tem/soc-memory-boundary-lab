from __future__ import annotations

import contextlib
import json
import subprocess
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools import a90_rbin_phys_oracle_live as live


SLOPE = 64
# Exact sign extension of bit 38 for the fixed VA_BITS=39 arm64 kernel.
INTERCEPT = 0xFFFFFF8000000000
CALIBRATION_PFNS = (0x1000, 0x2000, 0x3000)
HEAP_NAME_PTR = INTERCEPT + 0x100000
BUFFER_PTR = INTERCEPT + 0x200000


def _static_aarch64_elf() -> bytes:
    """Minimal bounded ELF64/aarch64/PT_LOAD-only test binary."""

    data = bytearray(64 + 56)
    data[:4] = b"\x7fELF"
    data[4:7] = bytes((2, 1, 1))
    struct.pack_into("<H", data, 16, 2)  # ET_EXEC
    struct.pack_into("<H", data, 18, 183)  # EM_AARCH64
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 24, 0x400040)  # nonzero entry in PT_LOAD
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 1)
    struct.pack_into("<I", data, 64, 1)  # PT_LOAD
    struct.pack_into("<I", data, 68, 5)  # PF_R|PF_X
    struct.pack_into("<Q", data, 72, 0)
    struct.pack_into("<Q", data, 80, 0x400000)
    struct.pack_into("<Q", data, 96, len(data))
    struct.pack_into("<Q", data, 104, len(data))
    return bytes(data)


def _format(event: str) -> str:
    if event == "cma_alloc":
        return "\n".join(
            (
                "name: cma_alloc",
                "ID: 100",
                "format: field:...",
                "print fmt: ...",
                "",
                "\tfield:unsigned short common_type; offset:0; size:2; signed:0;",
                "\tfield:unsigned char common_flags; offset:2; size:1; signed:0;",
                "\tfield:unsigned char common_preempt_count; offset:3; size:1; signed:0;",
                "\tfield:int common_pid; offset:4; size:4; signed:1;",
                "\tfield:unsigned long pfn; offset:8; size:8; signed:0;",
                "\tfield:const struct page * page; offset:16; size:8; signed:0;",
                "\tfield:unsigned int count; offset:24; size:4; signed:0;",
                "\tfield:unsigned int align; offset:28; size:4; signed:0;",
            )
        )
    return "\n".join(
        (
            f"name: {event}",
            "ID: 100",
            "format: field:...",
            "print fmt: ...",
            "",
            "\tfield:unsigned short common_type; offset:0; size:2; signed:0;",
            "\tfield:unsigned char common_flags; offset:2; size:1; signed:0;",
            "\tfield:unsigned char common_preempt_count; offset:3; size:1; signed:0;",
            "\tfield:int common_pid; offset:4; size:4; signed:1;",
            "\tfield:const char * heap_name; offset:8; size:8; signed:0;",
            "\tfield:void * buffer; offset:16; size:8; signed:0;",
            "\tfield:unsigned long size; offset:24; size:8; signed:0;",
            "\tfield:void * page; offset:32; size:8; signed:0;",
        )
    )


def _encoded_raw(
    event: str,
    *,
    page: int = 0,
    size: int = 0,
    pfn: int | None = None,
    count: int | None = None,
) -> tuple[int, str]:
    """Encode non-zero, format-bound tracepoint bytes for a fixture row."""

    description = live.parse_trace_format(_format(event), event)
    raw_size = int(description["raw_size"])
    raw = bytearray(raw_size)
    values = {
        "page": page,
        "size": size,
        "pfn": pfn,
        "count": count,
        # ion_rbin_heap.c passes NULL heap_name/buffer to the partial
        # allocator while retaining the common four-field event class.
        "heap_name": HEAP_NAME_PTR
        if event not in {"cma_alloc", "ion_rbin_partial_alloc_end"}
        else 0,
        "buffer": BUFFER_PTR if event in {"ion_rbin_alloc_start", "ion_rbin_alloc_end"} else 0,
    }
    fields = description["fields"]
    assert isinstance(fields, dict)
    for role, field in fields.items():
        value = values.get(role, 0)
        if value is None:
            value = 0
        offset = int(field["offset"])
        width = int(field["size"])
        raw[offset : offset + width] = int(value).to_bytes(width, "little")
    return raw_size, bytes(raw).hex()


def _event(
    event: str,
    *,
    phase: str,
    page: int = 0,
    size: int = 0,
    pfn: int | None = None,
    count: int | None = None,
    raw_size: int | None = None,
) -> dict[str, object]:
    encoded_size, raw_hex = _encoded_raw(
        event, page=page, size=size, pfn=pfn, count=count
    )
    if raw_size is not None:
        encoded_size = raw_size
    return {
        "schema": live.PROBE_SCHEMA,
        "type": "event",
        "phase": phase,
        "event": event,
        "page_ptr": hex(page),
        # The class carries page on every ION event; start/end are present but
        # NULL at their call sites, while pool/partial carry concrete pages.
        "has_page": True,
        "pfn": pfn is not None,
        "pfn_value": hex(pfn) if pfn is not None else None,
        "count": count is not None,
        "count_value": hex(count) if count is not None else None,
        "has_heap_name": event != "cma_alloc",
        "heap_name_value": (
            hex(HEAP_NAME_PTR)
            if event not in {"cma_alloc", "ion_rbin_partial_alloc_end"}
            else "0x0"
            if event == "ion_rbin_partial_alloc_end"
            else None
        ),
        "has_buffer": event != "cma_alloc",
        "buffer_ptr": hex(BUFFER_PTR) if event in {"ion_rbin_alloc_start", "ion_rbin_alloc_end"} else "0x0" if event != "cma_alloc" else None,
        "size_bytes": size,
        "raw_size": encoded_size,
        "raw_hex": raw_hex,
    }


def _valid_payload() -> bytes:
    rows: list[dict[str, object]] = [
        {
            "schema": live.PROBE_SCHEMA,
            "type": "context",
            "backend": "perf_event_open",
            "scope": "pid=0,cpu=-1",
            "cpu": 7,
            "heap": "camera_preview",
            "heap_id": 30,
            "heap_type": 10,
            "calibration_heap": "user_contig",
            "calibration_heap_id": 26,
            "calibration_heap_type": 4,
            "allocation_bytes": live.EXPECTED_BYTES,
            "flags": 0,
        }
    ]
    rows.extend(
        {
            "schema": live.PROBE_SCHEMA,
            "type": "format",
            "event": event,
            "id": 100 + index,
            "format_path": f"/sys/kernel/tracing/events/{'cma' if event == 'cma_alloc' else 'ion'}/{event}/format",
            "format_size": len(_format(event).encode()),
            "has_page": True,
            "has_size": event != "cma_alloc",
            "has_pfn": event == "cma_alloc",
            "has_count": event == "cma_alloc",
            "has_heap_name": event != "cma_alloc",
            "has_buffer": event != "cma_alloc",
            "format_hex": _format(event).encode().hex(),
        }
        for index, event in enumerate(live.EXPECTED_TRACE_EVENTS)
    )
    for index, pfn in enumerate(CALIBRATION_PFNS, 1):
        rows.append(
            _event(
                "cma_alloc",
                phase="calibration",
                page=INTERCEPT + SLOPE * pfn,
                size=4096 * index,
                pfn=pfn,
                count=index,
            )
        )
    first_pfn = live.EXPECTED_REGION_FIRST // 4096
    rows.extend(
        (
            _event("ion_rbin_alloc_start", phase="allocation", size=live.EXPECTED_BYTES),
            _event(
                "ion_rbin_alloc_end",
                phase="allocation",
                page=0,
                size=live.EXPECTED_BYTES,
            ),
            _event(
                "ion_rbin_pool_alloc_end",
                phase="allocation",
                page=INTERCEPT + SLOPE * first_pfn,
                size=live.EXPECTED_BYTES,
            ),
        )
    )
    rows.append(
        {
            "schema": live.PROBE_SCHEMA,
            "type": "summary",
            "status": "PA_BOUND",
            "allocation_backend": "rbin",
            "event_pool_count": 1,
            "event_partial_count": 0,
            "event_cma_count": 0,
            "event_start_count": 1,
            "event_end_count": 1,
            "nents": 1,
            "total_bytes": live.EXPECTED_BYTES,
            "first_pa": hex(live.EXPECTED_REGION_FIRST),
            "end_pa": hex(live.EXPECTED_REGION_END),
            "contiguous": True,
            "exact_region_match": True,
            "classification": "EXACT_CAMERA_PREVIEW_RBIN_REGION",
            "affine_slope": SLOPE,
            "affine_intercept": hex(INTERCEPT),
            "struct_page_size_source": "same-run-cma-affine",
        }
    )
    rows.append(
        {
            "schema": live.PROBE_SCHEMA,
            "type": "cleanup",
            "allocation_returned": True,
            "perf_disabled": True,
            "allocation_fd_closed": True,
            "ion_fd_closed": True,
            "calibration_fds_closed": True,
            "perf_unmapped": True,
            "perf_closed": True,
            "status": "PASS",
        }
    )
    return b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in rows)


def _rows(payload: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in payload.splitlines()]


def _payload(rows: list[dict[str, object]]) -> bytes:
    return b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in rows)


def _mixed_rbin_payload() -> bytes:
    rows = _rows(_valid_payload())
    first_pfn = live.EXPECTED_REGION_FIRST // 4096
    allocation_start = 1 + len(live.EXPECTED_TRACE_EVENTS) + 3
    allocation_end = len(rows) - 2
    rows[allocation_start:allocation_end] = [
        _event(
            "ion_rbin_alloc_start",
            phase="allocation",
            size=live.EXPECTED_BYTES,
        ),
        _event("ion_rbin_alloc_end", phase="allocation", page=0, size=live.EXPECTED_BYTES),
        _event(
            "ion_rbin_pool_alloc_end",
            phase="allocation",
            page=INTERCEPT + SLOPE * first_pfn,
            size=4096,
        ),
        _event("ion_rbin_pool_alloc_end", phase="allocation", page=0, size=0),
        _event(
            "ion_rbin_partial_alloc_end",
            phase="allocation",
            page=INTERCEPT + SLOPE * (first_pfn + 1),
            size=4096,
        ),
        _event(
            "ion_rbin_pool_alloc_end",
            phase="allocation",
            page=INTERCEPT + SLOPE * (first_pfn + 2),
            size=live.EXPECTED_BYTES - 8192,
        ),
    ]
    summary = rows[-2]
    summary.update(
        {
            "event_pool_count": 3,
            "event_partial_count": 1,
            "event_cma_count": 0,
            "event_start_count": 1,
            "event_end_count": 1,
            "nents": 3,
            "total_bytes": live.EXPECTED_BYTES,
            "first_pa": hex(live.EXPECTED_REGION_FIRST),
            "end_pa": hex(live.EXPECTED_REGION_END),
            "contiguous": True,
            "exact_region_match": True,
            "classification": "EXACT_CAMERA_PREVIEW_RBIN_REGION",
            "allocation_backend": "rbin",
        }
    )
    return _payload(rows)


class _RunFrame:
    def __init__(self, command: str, payload: bytes) -> None:
        self.payload = payload
        self.transcript = f"A90P1 {command}\n".encode() + payload
        self.begin = {"cmd": command, "seq": "1"}
        self.end = {"cmd": command, "seq": "1", "rc": "0", "status": "ok"}


class _RunSession:
    def __init__(
        self,
        timeline: list[str],
        probe_payload: bytes,
        *,
        existing_paths: set[str] | None = None,
        dangling_paths: set[str] | None = None,
    ) -> None:
        self.timeline = timeline
        self.probe_payload = probe_payload
        self.existing_paths = set(existing_paths or ())
        self.dangling_paths = set(dangling_paths or ())
        self.transcript_parts: list[bytes] = []
        self.commands: list[dict[str, object]] = []
        self.probe_calls = 0
        self.prompt_ready = True

    def invoke(self, evidence_id: str, argv: tuple[str, ...], *args: object, **kwargs: object) -> _RunFrame:
        del args, kwargs
        self.timeline.append(evidence_id)
        if evidence_id == "probe":
            self.probe_calls += 1
            payload = self.probe_payload
        elif evidence_id == "final_selftest":
            payload = b"selftest: pass=11 warn=1 fail=0 duration=0ms entries=12\n"
        elif evidence_id.startswith("precheck_") and any(
            path in argv for path in self.existing_paths | self.dangling_paths
        ):
            path = next(
                path
                for path in self.existing_paths | self.dangling_paths
                if path in argv
            )
            predicate = argv[4] if len(argv) > 4 else "-e"
            is_dangling = path in self.dangling_paths
            if is_dangling and predicate == "-e":
                payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n"
            else:
                payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 1]\n"
        elif argv and argv[0] == "run":
            payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n"
        else:
            payload = b""
        frame = _RunFrame(argv[0] if argv else "", payload)
        self.transcript_parts.append(frame.transcript)
        self.commands.append({"evidence_id": evidence_id, "argv": list(argv)})
        return frame


@contextlib.contextmanager
def _mocked_run(
    probe_payload: bytes,
    *,
    validation_fails: bool = False,
    existing_paths: set[str] | None = None,
    dangling_paths: set[str] | None = None,
    boot_ids: list[str] | None = None,
):
    """Provide a no-device run seam while retaining the real journal writer."""

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        timeline: list[str] = []
        journal_events: list[dict[str, object]] = []
        writes: list[tuple[Path, bytes, int]] = []
        boot_id_values = list(boot_ids or ())
        session = _RunSession(
            timeline,
            probe_payload,
            existing_paths=existing_paths,
            dangling_paths=dangling_paths,
        )
        binding = {"process_pid": 1, "serial_device": "/dev/ttyACM0"}
        binary = _static_aarch64_elf()
        parsed = live.validate_oracle_payload(_valid_payload())
        source_bytes = (
            Path(live.__file__).resolve().parents[1]
            / "tools"
            / live.SOURCE_BASENAME
        ).read_bytes()

        def fake_read(path: Path, label: str, **kwargs: object) -> bytes:
            del label, kwargs
            if Path(path).is_file():
                return Path(path).read_bytes()
            return source_bytes if Path(path).name == live.SOURCE_BASENAME else binary

        def fake_build(command: list[str], **kwargs: object) -> SimpleNamespace:
            del kwargs
            output = Path(command[command.index("-o") + 1])
            output.write_bytes(binary)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        original_append = live._append_journal
        original_write_exclusive = live._write_exclusive

        def append_journal(path: Path, event: dict[str, object]) -> None:
            journal_events.append(dict(event))
            timeline.append(f"journal:{event.get('state')}")
            original_append(path, event)

        def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
            if Path(path).name == live.JOURNAL_NAME:
                event = json.loads(data)
                journal_events.append(dict(event))
                timeline.append(f"journal:{event.get('state')}")
            original_write_exclusive(path, data, mode)

        def bridge_bind() -> dict[str, object]:
            timeline.append("bridge_validate")
            return dict(binding)

        def bridge_rebind(initial: object) -> dict[str, object]:
            del initial
            timeline.append("bridge_revalidate")
            return dict(binding)

        def boot_attest(*args: object, **kwargs: object) -> dict[str, object]:
            del args, kwargs
            timeline.append("boot_attestation")
            return {
                "expected_sha256": live.BOOT_PREFIX_SHA256,
                "captured_sha256": live.BOOT_PREFIX_SHA256,
                "expected_size": live.BOOT_PREFIX_SIZE,
                "captured_size": live.BOOT_PREFIX_SIZE,
                "hash_matches_candidate": True,
                "size_matches_candidate": True,
                "cleanup_ok": True,
                "binding_failure": False,
                "cleanup_error": None,
                "binding_events": [{"stage": "test"}],
            }

        def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
            writes.append((Path(path), data, mode))

        def boot_id(session_arg: object, evidence_id: str) -> str:
            del session_arg
            timeline.append(evidence_id)
            if boot_id_values:
                return boot_id_values.pop(0)
            return "11111111-1111-4111-8111-111111111111"

        def require_child_exit(payload: bytes, label: str) -> None:
            del label
            if b"[exit 1]" in payload:
                raise live.LiveError("synthetic nonzero child")

        validator_patch = (
            mock.patch.object(
                live,
                "validate_oracle_payload",
                side_effect=live.LiveError("synthetic oracle validation failure"),
            )
            if validation_fails
            else mock.patch.object(live, "validate_oracle_payload", return_value=parsed)
        )
        with mock.patch.object(live, "REPO_ROOT", root), mock.patch.object(
            live, "EXPECTED_BINARY_SIZE", len(binary)
        ), mock.patch.object(
            live, "EXPECTED_BINARY_SHA256", live.sha256(binary)
        ), mock.patch.object(
            live, "_read_stable", side_effect=fake_read
        ), mock.patch.object(live.subprocess, "run", side_effect=fake_build), mock.patch.object(
            live.transport, "_Session", return_value=session
        ), mock.patch.object(live.transport, "validate_bridge_binding", side_effect=bridge_bind), mock.patch.object(
            live.transport, "revalidate_bridge_binding", side_effect=bridge_rebind
        ), mock.patch.object(live, "_append_journal", side_effect=append_journal), mock.patch.object(
            live, "_write_exclusive", side_effect=write_exclusive
        ), mock.patch.object(
            live.transport, "write_new", side_effect=write_new
        ), mock.patch.object(live, "_remote_hash", return_value=live.sha256(binary)), mock.patch.object(
            live.transport, "validate_target", return_value=dict(live.EXPECTED_TARGET)
        ), mock.patch.object(live.transport, "parse_run_value", return_value=live.EXPECTED_ION_DEV), validator_patch, mock.patch.object(
            live.transport,
            "require_child_exit_zero",
            side_effect=require_child_exit,
        ), mock.patch.object(
            live.boot_attestation, "attest_current_boot", side_effect=boot_attest
        ), mock.patch.object(
            live, "_read_boot_id", side_effect=boot_id
        ):
            yield root, timeline, journal_events, writes, session, parsed


class RbinOracleLiveTests(unittest.TestCase):
    def test_trace_format_uses_declared_group_and_fields(self) -> None:
        cma = live.parse_trace_format(_format("cma_alloc"), "cma_alloc")
        self.assertEqual(cma["fields"]["pfn"]["offset"], 8)
        self.assertEqual(cma["fields"]["page"]["offset"], 16)
        self.assertEqual(cma["fields"]["count"]["offset"], 24)
        self.assertEqual(cma["raw_size"], 36)
        self.assertEqual(
            live.parse_trace_format(_format("ion_rbin_alloc_end"), "ion_rbin_alloc_end")["raw_size"],
            44,
        )
        with self.assertRaises(live.LiveError):
            live.parse_trace_format(
                _format("cma_alloc").replace(
                    "const struct page * page; offset:16;",
                    "const struct page * page; offset:4092;",
                ),
                "cma_alloc",
            )
        with self.assertRaises(live.LiveError):
            live.parse_trace_format(
                _format("cma_alloc").replace(
                    "const struct page * page", "unsigned long page"
                ),
                "cma_alloc",
            )
        with self.assertRaises(live.LiveError):
            live.parse_trace_format(
                _format("ion_rbin_alloc_end").replace(
                    "const char * heap_name", "__data_loc char[] heap_name"
                ),
                "ion_rbin_alloc_end",
            )
        with self.assertRaises(live.LiveError):
            live.parse_trace_format(
                _format("ion_rbin_alloc_end").replace(
                    "heap_name; offset:8; size:8;",
                    "heap_name; offset:8; size:4;",
                ),
                "ion_rbin_alloc_end",
            )

    def test_c_parser_is_line_bounded_and_ion_class_is_source_exact(self) -> None:
        source_path = (
            Path(live.__file__).resolve().parents[1]
            / "tools"
            / live.SOURCE_BASENAME
        )
        source = source_path.read_text()
        self.assertIn("memchr(cursor, '\\n'", source)
        self.assertIn("char line_copy[MAX_FORMAT_LINE_BYTES]", source)
        self.assertIn("role = parse_format_line(line_copy, &field)", source)
        self.assertNotIn("role = parse_format_line(cursor,", source)
        self.assertIn("retain_calibration_events(sources, calibration_events", source)
        self.assertIn("for (index = 0; index < calibration_event_count; ++index)", source)
        expected_roles = {"heap_name", "buffer", "size", "page"}
        for event in live.EXPECTED_TRACE_EVENTS[1:]:
            description = live.parse_trace_format(_format(event), event)
            self.assertEqual(set(description["fields"]), expected_roles)
        partial = _event(
            "ion_rbin_partial_alloc_end",
            phase="allocation",
            page=INTERCEPT + SLOPE * 0x1000,
            size=4096,
        )
        self.assertEqual(live._event_row(partial, 0)["heap_name_value"], 0)
        self.assertEqual(live._event_row(partial, 0)["buffer_ptr_value"], 0)

    def test_c_line_parser_seam_handles_tracefs_preamble_without_cross_line_fields(self) -> None:
        source_path = (
            Path(live.__file__).resolve().parents[1]
            / "tools"
            / live.SOURCE_BASENAME
        )
        realistic = "\n".join(
            (
                "name: ion_rbin_alloc_end",
                "ID: 321",
                "format: field:...",
                "print fmt: ...",
                "",
                "\tfield:unsigned short common_type; offset:0; size:2; signed:0;",
                "\tfield:unsigned char common_flags; offset:2; size:1; signed:0;",
                "\tfield:unsigned char common_preempt_count; offset:3; size:1; signed:0;",
                "\tfield:int common_pid; offset:4; size:4; signed:1;",
                "\tfield:const char * heap_name; offset:8; size:8; signed:0;",
                "\tfield:void * buffer; offset:16; size:8; signed:0;",
                "\tfield:unsigned long size; offset:24; size:8; signed:0;",
                "\tfield:void * page; offset:32; size:8; signed:0;",
            )
        ).encode("ascii")
        malformed_split = (
            b"field:const char * heap_name;\n"
            b"offset:8; size:8; signed:0;\n" + realistic
        )
        duplicate = realistic + b"\n\tfield:void * page; offset:40; size:8; signed:0;"
        harness = (
            "#define A90_RBIN_ORACLE_TEST 1\n"
            "#define main a90_probe_main\n"
            f"#include {json.dumps(str(source_path))}\n"
            "#undef main\n"
            "#include <string.h>\n"
            "int main(void) {\n"
            f"  static const unsigned char good[] = {json.dumps(realistic.decode('ascii'))};\n"
            f"  static const unsigned char split[] = {json.dumps(malformed_split.decode('ascii'))};\n"
            f"  static const unsigned char duplicate[] = {json.dumps(duplicate.decode('ascii'))};\n"
            "  size_t roles = 0, entry = 0;\n"
            "  if (a90_test_parse_format_lines(good, sizeof(good)-1, &roles, &entry) != 0 || roles != 4 || entry != 40) return 1;\n"
            "  roles = entry = 0;\n"
            "  if (a90_test_parse_format_lines(split, sizeof(split)-1, &roles, &entry) != 0 || roles != 4 || entry != 40) return 2;\n"
            "  if (a90_test_parse_format_lines(duplicate, sizeof(duplicate)-1, &roles, &entry) == 0) return 3;\n"
            "  if (declaration_matches(\"__data_loc char[] heap_name\", \"const char * heap_name\") != 0) return 4;\n"
            "  if (declaration_matches(\"unsigned long page\", \"void * page\") != 0) return 5;\n"
            "  struct perf_source calibration_source = {0};\n"
            "  struct trace_event calibration_input[CALIBRATION_ALLOCS] = {0};\n"
            "  struct trace_event calibration_retained[CALIBRATION_ALLOCS] = {0};\n"
            "  calibration_source.events = calibration_input; calibration_source.event_count = CALIBRATION_ALLOCS;\n"
            "  for (size_t i = 0; i < CALIBRATION_ALLOCS; ++i) { calibration_input[i].raw_size = (unsigned int)(i + 1); calibration_input[i].raw[0] = (unsigned char)(0xa0 + i); }\n"
            "  size_t retained_count = 0;\n"
            "  if (retain_calibration_events(&calibration_source, calibration_retained, CALIBRATION_ALLOCS, &retained_count) != 0 || retained_count != CALIBRATION_ALLOCS) return 6;\n"
            "  memset(calibration_input, 0, sizeof(calibration_input));\n"
            "  for (size_t i = 0; i < CALIBRATION_ALLOCS; ++i) if (calibration_retained[i].raw_size != (unsigned int)(i + 1) || calibration_retained[i].raw[0] != (unsigned char)(0xa0 + i)) return 7;\n"
            "  struct perf_source sources[5] = {0};\n"
            "  struct trace_event *pool = calloc(MAX_SEGMENTS, sizeof(*pool));\n"
            "  struct trace_event *partial = calloc(MAX_SEGMENTS, sizeof(*partial));\n"
            "  if (pool == NULL || partial == NULL) return 8;\n"
            "  sources[3].events = pool; sources[3].event_count = MAX_SEGMENTS;\n"
            "  sources[4].events = partial; sources[4].event_count = MAX_SEGMENTS;\n"
            "  for (size_t i = 0; i < 5; ++i) sources[i].desc.format_bytes_size = 1;\n"
            "  for (size_t i = 0; i < MAX_SEGMENTS; ++i) { pool[i].raw_size = MAX_RAW_BYTES; partial[i].raw_size = MAX_RAW_BYTES; }\n"
            "  size_t estimate = 0;\n"
            "  if (estimate_output_bytes(sources, 5, calibration_retained, CALIBRATION_ALLOCS, &estimate) != 0 || estimate <= MAX_CAPTURE_OUTPUT_BYTES) return 9;\n"
            "  free(pool); free(partial);\n"
            "  return 0;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            harness_path = directory_path / "format_seam.c"
            executable = directory_path / "format_seam"
            harness_path.write_text(harness)
            built = subprocess.run(
                ["gcc", "-std=gnu11", "-O0", "-Wall", "-Wextra", "-Werror", "-o", str(executable), str(harness_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(built.returncode, 0, built.stderr.decode())
            executed = subprocess.run(
                [str(executable)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(executed.returncode, 0, executed.stderr.decode())

    def test_capture_ceiling_and_bounded_max_cardinality_are_explicit(self) -> None:
        source_path = (
            Path(live.__file__).resolve().parents[1]
            / "tools"
            / live.SOURCE_BASENAME
        )
        source = source_path.read_text()
        self.assertIn(
            "#define MAX_SEGMENTS ((size_t)(EXPECTED_BYTES / PAGE_BYTES))",
            source,
        )
        self.assertIn("#define MAX_CAPTURE_OUTPUT_BYTES (7U * 1024U * 1024U)", source)
        self.assertIn("OUTPUT_TOO_LARGE", source)
        self.assertIn("estimate_output_bytes(sources, 5U", source)
        self.assertIn("qsort(segments, count", source)
        self.assertNotIn("MAX_EVENTS", source)

    def test_static_aarch64_validator_rejects_dynamic_or_invalid_fixtures(self) -> None:
        descriptor = live._validate_static_aarch64_elf(_static_aarch64_elf())
        self.assertEqual(descriptor["machine"], "AArch64")
        dynamic = bytearray(_static_aarch64_elf())
        struct.pack_into("<I", dynamic, 64, 3)  # PT_INTERP
        with self.assertRaises(live.LiveError):
            live._validate_static_aarch64_elf(bytes(dynamic))
        invalid = bytearray(_static_aarch64_elf())
        invalid[5] = 2  # big-endian marker
        with self.assertRaises(live.LiveError):
            live._validate_static_aarch64_elf(bytes(invalid))
        et_none = bytearray(_static_aarch64_elf())
        struct.pack_into("<H", et_none, 16, 0)
        with self.assertRaises(live.LiveError):
            live._validate_static_aarch64_elf(bytes(et_none))
        pt_null = bytearray(_static_aarch64_elf())
        struct.pack_into("<I", pt_null, 64, 0)
        with self.assertRaises(live.LiveError):
            live._validate_static_aarch64_elf(bytes(pt_null))

    def test_v030_remote_hash_parser_binds_exact_binary_path(self) -> None:
        digest = "a" * 64
        correct = (
            b"run: pid=7, q/Ctrl-C cancels\n"
            + f"{digest}  {live.REMOTE_BINARY}\n".encode()
            + b"[exit 0]\n"
        )
        self.assertEqual(live._parse_remote_hash_v030(correct, "hash"), digest)
        wrong = correct.replace(live.REMOTE_BINARY.encode(), b"/tmp/other")
        with self.assertRaises(live.LiveError):
            live._parse_remote_hash_v030(wrong, "hash")
        with self.assertRaises(live.LiveError):
            live._parse_remote_hash_v030(
                correct.replace(b"[exit 0]", b"[exit 0]\nextra"), "hash"
            )

    def test_source_pin_and_perf_mmap_order_are_explicit(self) -> None:
        source_path = Path(live.__file__).resolve().parents[1] / "tools" / live.SOURCE_BASENAME
        source = source_path.read_bytes()
        self.assertEqual(len(source), live.EXPECTED_SOURCE_SIZE)
        self.assertEqual(live.sha256(source), live.EXPECTED_SOURCE_SHA256)
        text = source.decode("ascii")
        head = text.index("head = __atomic_load_n(&metadata->data_head")
        acquire_barrier = text.index("__sync_synchronize();", head)
        ring_read = text.index("ring_copy(source, tail", acquire_barrier)
        release_barrier = text.index("__sync_synchronize();", ring_read)
        tail_store = text.index("__atomic_store_n(&metadata->data_tail", release_barrier)
        self.assertLess(head, acquire_barrier)
        self.assertLess(acquire_barrier, ring_read)
        self.assertLess(ring_read, release_barrier)
        self.assertLess(release_barrier, tail_store)
        self.assertNotIn("MAX_EVENTS", text)
        self.assertNotIn("#define MAX_SEGMENTS 2048", text)
        with self.assertRaises(live.LiveError):
            live._pinned_source_descriptor(source_path, source + b"mutation")

    def test_host_redecode_rejects_raw_field_mismatch(self) -> None:
        rows = _rows(_valid_payload())
        event = next(
            row
            for row in rows
            if row["type"] == "event" and row["event"] == "cma_alloc"
        )
        raw = bytearray.fromhex(event["raw_hex"])
        raw[8] ^= 1  # pfn field in the retained cma_alloc format
        event["raw_hex"] = bytes(raw).hex()
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

    def test_camera_cma_backend_is_rejected(self) -> None:
        rows = _rows(_valid_payload())
        summary = next(row for row in rows if row["type"] == "summary")
        summary["allocation_backend"] = "cma"
        summary["classification"] = "EXACT_CAMERA_PREVIEW_CMA_REGION"
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

    def test_ion_class_layout_mutation_is_rejected(self) -> None:
        rows = _rows(_valid_payload())
        ion_format = next(
            row
            for row in rows
            if row.get("type") == "format"
            and row.get("event") == "ion_rbin_pool_alloc_end"
        )
        changed = _format("ion_rbin_pool_alloc_end").replace(
            "offset:16; size:8;", "offset:20; size:8;"
        )
        ion_format["format_hex"] = changed.encode().hex()
        ion_format["format_size"] = len(changed.encode())
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

    def test_perf_raw_and_ring_wrap_parse(self) -> None:
        description = live.parse_trace_format(_format("ion_rbin_pool_alloc_end"), "ion_rbin_pool_alloc_end")
        # PERF_SAMPLE_RAW stores the kernel's internal tracepoint padding in
        # raw_size; the class format here has a 40-byte entry and raw_size=44.
        _, raw_hex = _encoded_raw(
            "ion_rbin_pool_alloc_end",
            page=INTERCEPT + SLOPE * 0x1000,
            size=4096,
        )
        raw = bytes.fromhex(raw_hex)
        parsed = live.parse_perf_raw_record(raw, description, event_name="ion_rbin_pool_alloc_end")
        self.assertEqual(parsed["size_bytes"], 4096)
        record_size = 12 + len(raw)
        record = struct.pack("<IHHI", 9, 0, record_size, len(raw)) + raw
        ring = bytearray(64)
        for index, byte in enumerate(record):
            ring[(56 + index) & 63] = byte
        rows = live.parse_perf_ring_bytes(bytes(ring), description, event_name="ion_rbin_pool_alloc_end", data_head=56 + len(record), data_tail=56)
        self.assertEqual(rows[0]["page"], INTERCEPT + SLOPE * 0x1000)
        with self.assertRaises(live.LiveError):
            live.parse_perf_ring_bytes(struct.pack("<IHH", 2, 0, 8), description, event_name="ion_rbin_pool_alloc_end")
        with self.assertRaises(live.LiveError):
            live.parse_perf_ring_bytes(struct.pack("<IHHI", 9, 0, 64, len(raw)) + raw, description, event_name="ion_rbin_pool_alloc_end")
        with self.assertRaises(live.LiveError):
            live.parse_perf_ring_bytes(
                struct.pack("<IHHI", 9, 0, 28, 16) + b"\0" * 16,
                description,
                event_name="ion_rbin_pool_alloc_end",
            )
        with self.assertRaises(live.LiveError):
            live.parse_perf_ring_bytes(
                struct.pack("<IHHI", 2, 0, record_size, len(raw)) + raw,
                description,
                event_name="ion_rbin_pool_alloc_end",
            )

    def test_calibration_requires_exact_one_two_three_page_order(self) -> None:
        rows = _rows(_valid_payload())
        calibration_start = 1 + len(live.EXPECTED_TRACE_EVENTS)
        rows[calibration_start]["count_value"] = "0x2"
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

        rows = _rows(_valid_payload())
        rows.insert(calibration_start + 3, dict(rows[calibration_start + 2]))
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

    def test_cma_source_order_binds_affine_slope_and_first_pa(self) -> None:
        description = live.parse_trace_format(_format("cma_alloc"), "cma_alloc")
        self.assertEqual(description["fields"]["pfn"]["offset"], 8)
        self.assertEqual(description["fields"]["page"]["offset"], 16)

        parsed = live.validate_oracle_payload(_valid_payload())
        self.assertEqual(parsed["summary"]["affine_slope"], 64)
        self.assertEqual(parsed["summary"]["first_pa"], "0xc2000000")

        calibration = parsed["calibration"]
        self.assertEqual(len(calibration), 3)
        for index, row in enumerate(calibration, 1):
            raw = bytes.fromhex(row["raw_hex"])
            pfn = CALIBRATION_PFNS[index - 1]
            self.assertEqual(int.from_bytes(raw[8:16], "little"), pfn)
            self.assertEqual(
                int.from_bytes(raw[16:24], "little"), INTERCEPT + SLOPE * pfn
            )
            self.assertEqual(row["count_value"], index)

    def test_mixed_rbin_pool_miss_binds_one_next_partial(self) -> None:
        parsed = live.validate_oracle_payload(_mixed_rbin_payload())
        self.assertEqual(parsed["summary"]["allocation_backend"], "rbin")
        self.assertEqual(parsed["summary"]["nents"], 3)

        rows = _rows(_mixed_rbin_payload())
        allocation_start = 1 + len(live.EXPECTED_TRACE_EVENTS) + 3
        allocation_end = len(rows) - 2
        partial_index = next(
            index
            for index in range(allocation_start, allocation_end)
            if rows[index].get("event") == "ion_rbin_partial_alloc_end"
        )
        rows.pop(partial_index)
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

        rows = _rows(_mixed_rbin_payload())
        allocation_start = 1 + len(live.EXPECTED_TRACE_EVENTS) + 3
        allocation_end = len(rows) - 2
        partial_index = next(
            index
            for index in range(allocation_start, allocation_end)
            if rows[index].get("event") == "ion_rbin_partial_alloc_end"
        )
        extra = dict(rows[partial_index])
        rows.insert(allocation_end, extra)
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

        rows = _rows(_mixed_rbin_payload())
        allocation_start = 1 + len(live.EXPECTED_TRACE_EVENTS) + 3
        partial_index = next(
            index
            for index in range(allocation_start, len(rows) - 2)
            if rows[index].get("event") == "ion_rbin_partial_alloc_end"
        )
        rows[partial_index]["page_ptr"] = "0x0"
        rows[partial_index]["size_bytes"] = 0
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(_payload(rows))

    def test_affine_and_segment_union_overflow_or_noncontiguous(self) -> None:
        points = [(INTERCEPT + SLOPE * pfn, pfn) for pfn in CALIBRATION_PFNS]
        self.assertEqual(live.derive_affine_page_relation(points), (SLOPE, INTERCEPT))
        with self.assertRaises(live.LiveError):
            live.derive_affine_page_relation([(0xFFFFFF0000000000, 1), (0xFFFFFF0000000040, 2), (0xFFFFFF00000000C0, 3)])
        exact = live.compute_segment_union(
            [{"page_ptr_value": INTERCEPT + SLOPE * (live.EXPECTED_REGION_FIRST // 4096), "size_bytes": live.EXPECTED_BYTES}],
            slope=SLOPE,
            intercept=INTERCEPT,
        )
        self.assertTrue(exact["contiguous"])
        gap = live.compute_segment_union(
            [
                {"page_ptr_value": INTERCEPT + SLOPE * (live.EXPECTED_REGION_FIRST // 4096), "size_bytes": 4096},
                {"page_ptr_value": INTERCEPT + SLOPE * (live.EXPECTED_REGION_FIRST // 4096 + 2), "size_bytes": live.EXPECTED_BYTES - 4096},
            ],
            slope=SLOPE,
            intercept=INTERCEPT,
        )
        self.assertFalse(gap["contiguous"])
        with self.assertRaises(live.LiveError):
            live.compute_segment_union([{"page_ptr_value": INTERCEPT + SLOPE * ((1 << 52) - 1), "size_bytes": 4096}], slope=SLOPE, intercept=INTERCEPT)

    def test_payload_exact_contract_and_public_redaction(self) -> None:
        parsed = live.validate_oracle_payload(_valid_payload())
        target = dict(live.EXPECTED_TARGET)
        binary = {"basename": live.BINARY_BASENAME, "size_bytes": 20, "sha256": "a" * 64}
        descriptor_names = {
            "receipt": live.PRIVATE_RECEIPT_NAME,
            "raw_output": live.RAW_OUTPUT_NAME,
            "transcript": live.TRANSCRIPT_NAME,
            "journal": live.JOURNAL_NAME,
            "build_receipt": live.BUILD_RECEIPT_NAME,
        }
        descriptor_bytes = {
            key: f"non-empty-{key}".encode("ascii") for key in descriptor_names
        }
        artifact_descriptors = {
            key: {
                "filename": filename,
                "sha256": live.sha256(descriptor_bytes[key]),
                "size_bytes": len(descriptor_bytes[key]),
            }
            for key, filename in descriptor_names.items()
        }
        boot_id = "11111111-1111-4111-8111-111111111111"
        projection_kwargs = {
            "completed_utc": "2026-08-28T00:00:00+00:00",
            "target": target,
            "binary": binary,
            "artifact_descriptors": artifact_descriptors,
            "boot_prefix_sha256": live.BOOT_PREFIX_SHA256,
            "boot_id_sha256": live.sha256(boot_id.encode("ascii")),
            "final_health_ok": True,
        }
        public = live.public_projection(parsed, **projection_kwargs)
        live.validate_public_projection(public, target=target, binary=binary)
        with self.assertRaises(live.LiveError):
            live.validate_public_projection(public, target=target)
        self.assertNotIn("page_ptr", json.dumps(public))
        self.assertNotIn("raw_hex", json.dumps(public))
        zero_size_descriptors = {
            key: dict(value) for key, value in artifact_descriptors.items()
        }
        zero_size_descriptors["receipt"]["size_bytes"] = 0
        with self.assertRaises(live.LiveError):
            live.public_projection(
                parsed,
                **dict(projection_kwargs, artifact_descriptors=zero_size_descriptors),
            )
        with self.assertRaises(TypeError):
            missing_boot_id = dict(projection_kwargs)
            missing_boot_id.pop("boot_id_sha256")
            live.public_projection(parsed, **missing_boot_id)
        with self.assertRaises(live.LiveError):
            live.public_projection(
                parsed,
                **dict(projection_kwargs, boot_id_sha256=live.sha256(b"")),
            )
        forged = dict(public)
        forged["target"] = dict(public["target"])
        forged["target"]["runtime_version"] = "wrong"
        with self.assertRaises(live.LiveError):
            live.validate_public_projection(forged, target=target, binary=binary)
        forged = dict(public)
        forged["serial"] = "A90"
        with self.assertRaises(live.LiveError):
            live.validate_public_projection(forged, target=target, binary=binary)
        forged = dict(public)
        forged["result_classification"] = "NONEXACT_CAMERA_PREVIEW_RBIN_REGION"
        with self.assertRaises(live.LiveError):
            live.validate_public_projection(forged, target=target, binary=binary)
        forged = dict(public)
        forged["source_binary"] = dict(public["source_binary"])
        forged["source_binary"]["sha256"] = "b" * 64
        with self.assertRaises(live.LiveError):
            live.validate_public_projection(forged, target=target, binary=binary)

    def test_payload_rejects_cleanup_event_and_record_mutations(self) -> None:
        rows = [json.loads(line) for line in _valid_payload().splitlines()]
        cleanup = next(row for row in rows if row["type"] == "cleanup")
        cleanup["perf_disabled"] = False
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
        rows = [json.loads(line) for line in _valid_payload().splitlines()]
        event = next(row for row in rows if row["type"] == "event" and row["phase"] == "calibration")
        event["raw_hex"] = "00"
        with self.assertRaises(live.LiveError):
            live.validate_oracle_payload(b"".join(json.dumps(row).encode() + b"\n" for row in rows))

    def test_preflight_wrong_id_and_output_collision_are_no_contact(self) -> None:
        result = live.preflight()
        self.assertFalse(result["device_contact"])
        with self.assertRaises(live.LiveError):
            live._validate_args(type("Args", (), {"execute": False, "experiment_id": live.EXPERIMENT_ID})())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            output.mkdir(parents=True)
            with mock.patch.object(live, "REPO_ROOT", root), mock.patch.object(
                live.transport, "validate_bridge_binding"
            ) as bind:
                with self.assertRaises((live.LiveError, live.transport.LiveError)):
                    live.run(type("Args", (), {"execute": True, "experiment_id": live.EXPERIMENT_ID})())
            bind.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            output.mkdir(parents=True)
            (output / live.JOURNAL_NAME).write_bytes(b"existing\n")
            with mock.patch.object(live, "REPO_ROOT", root), mock.patch.object(
                live.transport, "validate_bridge_binding"
            ) as bind:
                with self.assertRaises((live.LiveError, live.transport.LiveError)):
                    live.run(type("Args", (), {"execute": True, "experiment_id": live.EXPERIMENT_ID})())
            bind.assert_not_called()

    def test_run_journal_boot_binding_and_single_probe_order(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (root, timeline, journal_events, writes, session, _parsed):
            result = live.run(args)
            journal_path = result / live.JOURNAL_NAME
            self.assertTrue(journal_path.exists())
            journal = journal_path.read_text()
            self.assertTrue((result / live.PRIVATE_RECEIPT_NAME).exists())
            receipt = json.loads((result / live.PRIVATE_RECEIPT_NAME).read_text())
            self.assertEqual(receipt["status"], "PREPARED_NOT_AUTHORITY")
            self.assertEqual(receipt["closure_state"], "CLOSURE_PREPARED")
            build_receipt = json.loads((result / live.BUILD_RECEIPT_NAME).read_text())
            self.assertTrue(Path(build_receipt["compiler"][0]).is_absolute())
            self.assertEqual(build_receipt["binary"]["sha256"], receipt["binary"]["sha256"])
            self.assertEqual(receipt["effect_profile"], live.EFFECT_PROFILE)
            self.assertTrue(receipt["cleanup"]["absence_proved"])
            self.assertTrue(receipt["final_health"]["ok"])
            public_path = (
                root
                / "evidence"
                / "manifests"
                / live.PUBLIC_MANIFEST_NAME
            )
            self.assertTrue(public_path.exists())
            public = json.loads(public_path.read_text())
            self.assertEqual(public["effect_profile"], live.EFFECT_PROFILE)
            live.validate_public_projection(
                public,
                target=live.EXPECTED_TARGET,
                binary=receipt["binary"],
            )
            expected_artifacts = {
                "receipt": result / live.PRIVATE_RECEIPT_NAME,
                "raw_output": result / live.RAW_OUTPUT_NAME,
                "transcript": result / live.TRANSCRIPT_NAME,
                "journal": result / live.JOURNAL_NAME,
                "build_receipt": result / live.BUILD_RECEIPT_NAME,
            }
            for key, artifact_path in expected_artifacts.items():
                descriptor = public["private_record"][key]
                artifact = artifact_path.read_bytes()
                if key == "journal":
                    # The public/private journal descriptor intentionally
                    # covers the immutable prefix before terminal PASS.
                    artifact = artifact[: descriptor["size_bytes"]]
                    self.assertEqual(
                        json.loads(artifact.splitlines()[-1])["state"],
                        "FINAL_HEALTH",
                    )
                self.assertEqual(descriptor["sha256"], live.sha256(artifact))
                if key != "journal":
                    self.assertEqual(descriptor["size_bytes"], len(artifact_path.read_bytes()))

        self.assertEqual(session.probe_calls, 1)
        self.assertEqual(sum(item == "probe" for item in timeline), 1)
        states = [event.get("state") for event in journal_events]
        self.assertIn("OWNERSHIP_CLAIM", states)
        self.assertIn("EFFECT_DISPATCHED", states)
        self.assertLess(timeline.index("journal:OWNERSHIP_CLAIM"), timeline.index("version"))
        self.assertLess(timeline.index("boot_attestation"), timeline.index("journal:EFFECT_DISPATCHED"))
        self.assertLess(timeline.index("boot_id_before_attestation"), timeline.index("journal:EFFECT_DISPATCHED"))
        self.assertLess(timeline.index("boot_id_after_attestation"), timeline.index("journal:EFFECT_DISPATCHED"))
        self.assertLess(timeline.index("bridge_revalidate"), timeline.index("journal:EFFECT_DISPATCHED"))
        boot_attestation_index = timeline.index("boot_attestation")
        boot_id_index = timeline.index("boot_id_before_attestation")
        for mutation in (
            "precheck_node_not_exists",
            "precheck_node_not_link",
            "precheck_envelope_not_exists",
            "precheck_envelope_not_link",
            "precheck_binary_not_exists",
            "precheck_binary_not_link",
            "envelope_header",
            "ion_node_create",
            "ion_node_chmod",
        ):
            self.assertLess(boot_attestation_index, timeline.index(mutation))
            self.assertLess(boot_id_index, timeline.index(mutation))
        self.assertLess(timeline.index("journal:EFFECT_DISPATCHED"), timeline.index("probe"))
        self.assertIn("boot_id_after", timeline)
        self.assertGreater(timeline.index("boot_id_after"), timeline.index("probe"))
        for absence in (
            "absence_node_not_exists",
            "absence_node_not_link",
            "absence_envelope_not_exists",
            "absence_envelope_not_link",
            "absence_binary_not_exists",
            "absence_binary_not_link",
        ):
            self.assertIn(absence, timeline)
        effect = next(event for event in journal_events if event.get("state") == "EFFECT_DISPATCHED")
        self.assertEqual(effect["source"]["basename"], live.SOURCE_BASENAME)
        self.assertEqual(effect["binary"]["basename"], live.BINARY_BASENAME)
        self.assertEqual(effect["remote_binary"]["path"], live.REMOTE_BINARY)
        self.assertEqual(effect["remote_binary"]["sha256"], live.sha256(_static_aarch64_elf()))
        self.assertIn('"state":"EFFECT_DISPATCHED"', journal)
        journal_lines = [json.loads(line) for line in journal.splitlines()]
        self.assertEqual(journal_lines[-1]["state"], "PASS")
        prefix_descriptor = receipt["journal_prefix"]
        prefix = journal.encode()[: prefix_descriptor["size_bytes"]]
        self.assertEqual(
            live.sha256(prefix),
            prefix_descriptor["sha256"],
        )
        self.assertEqual(journal_lines[prefix.count(b"\n") - 1]["state"], "FINAL_HEALTH")

    def test_preclean_refuses_existing_fixed_path_without_mutation(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(
            _valid_payload(), existing_paths={live.REMOTE_BINARY}
        ) as (root, timeline, journal_events, _writes, session, _parsed):
            with self.assertRaises(live.LiveError):
                live.run(args)
            self.assertEqual(session.probe_calls, 0)
            self.assertNotIn("envelope_header", timeline)
            self.assertNotIn("ion_node_create", timeline)
            self.assertNotIn("cleanup_files", timeline)
            self.assertEqual(
                [event["state"] for event in journal_events][-1], "INCIDENT"
            )
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            self.assertFalse((output / live.PRIVATE_RECEIPT_NAME).exists())

    def test_preclean_rejects_dangling_symlink_without_rm(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(
            _valid_payload(), dangling_paths={live.REMOTE_BINARY}
        ) as (_root, timeline, journal_events, _writes, session, _parsed):
            with self.assertRaises(live.LiveError):
                live.run(args)
            self.assertEqual(session.probe_calls, 0)
            self.assertIn("precheck_binary_not_exists", timeline)
            self.assertIn("precheck_binary_not_link", timeline)
            self.assertNotIn("envelope_header", timeline)
            self.assertNotIn("cleanup_files", timeline)
            self.assertEqual(journal_events[-1]["state"], "INCIDENT")

    def test_create_attempt_is_owned_before_error_and_cleanup_is_scoped(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (
            root,
            timeline,
            journal_events,
            _writes,
            session,
            _parsed,
        ):
            original_invoke = session.invoke

            def fail_header(evidence_id: str, argv: tuple[str, ...], *args: object, **kwargs: object):
                if evidence_id == "envelope_header":
                    session.prompt_ready = True
                    timeline.append("envelope_create_attempted_then_error")
                    raise RuntimeError("synthetic create response loss")
                return original_invoke(evidence_id, argv, *args, **kwargs)

            session.invoke = fail_header  # type: ignore[method-assign]
            with self.assertRaises(live.LiveError):
                live.run(args)
            self.assertEqual(session.probe_calls, 0)
            self.assertIn("envelope_create_attempted_then_error", timeline)
            self.assertIn("cleanup_files", timeline)
            self.assertIn("absence_envelope_not_exists", timeline)
            self.assertIn("absence_envelope_not_link", timeline)
            self.assertNotIn("cleanup_node", timeline)
            self.assertEqual(journal_events[-1]["state"], "INCIDENT")
            self.assertTrue((root / "evidence" / "private" / live.OUTPUT_DIR_NAME / live.JOURNAL_NAME).exists())

    def test_boot_attestation_is_bracketed_and_drift_blocks_staging(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        first = "11111111-1111-4111-8111-111111111111"
        second = "22222222-2222-4222-8222-222222222222"
        with _mocked_run(_valid_payload(), boot_ids=[first, second]) as (
            _root,
            timeline,
            journal_events,
            _writes,
            session,
            _parsed,
        ):
            with self.assertRaises(live.LiveError):
                live.run(args)
            self.assertEqual(session.probe_calls, 0)
            self.assertLess(timeline.index("boot_id_before_attestation"), timeline.index("boot_attestation"))
            self.assertLess(timeline.index("boot_attestation"), timeline.index("boot_id_after_attestation"))
            self.assertNotIn("precheck_node_not_exists", timeline)
            self.assertNotIn("envelope_header", timeline)
            self.assertEqual(journal_events[-1]["state"], "INCIDENT")

    def test_completed_run_validator_binds_terminal_pass_and_prepared_files(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (
            root,
            _timeline,
            _journal_events,
            _writes,
            _session,
            _parsed,
        ):
            output = live.run(args)
            private_data = (output / live.PRIVATE_RECEIPT_NAME).read_bytes()
            public_data = (
                root / "evidence" / "manifests" / live.PUBLIC_MANIFEST_NAME
            ).read_bytes()
            journal_data = (output / live.JOURNAL_NAME).read_bytes()
            artifacts = {
                "raw_output": (output / live.RAW_OUTPUT_NAME).read_bytes(),
                "transcript": (output / live.TRANSCRIPT_NAME).read_bytes(),
                "build_receipt": (output / live.BUILD_RECEIPT_NAME).read_bytes(),
            }
            live.validate_completed_run(
                journal_data, private_data, public_data, artifacts
            )
            forged = journal_data.replace(b'"state":"PASS"', b'"state":"INCIDENT"')
            with self.assertRaises(live.LiveError):
                live.validate_completed_run(forged, private_data, public_data, artifacts)
            with self.assertRaises(live.LiveError):
                live.validate_completed_run(
                    journal_data,
                    private_data,
                    public_data,
                    dict(artifacts, raw_output=artifacts["raw_output"] + b"x"),
                )
            journal_lines = journal_data.splitlines()
            terminal = json.loads(journal_lines[-1])
            for key, value in (
                ("cleanup", {**terminal["cleanup"], "ok": False}),
                ("final_health", {**terminal["final_health"], "ok": False}),
                ("target", {**terminal["target"], "model": "wrong"}),
                (
                    "remote_binary",
                    {**terminal["remote_binary"], "unchanged": False},
                ),
            ):
                mutated_terminal = dict(terminal)
                mutated_terminal[key] = value
                forged_lines = list(journal_lines)
                forged_lines[-1] = json.dumps(mutated_terminal, sort_keys=True).encode()
                with self.assertRaises(live.LiveError):
                    live.validate_completed_run(
                        b"\n".join(forged_lines) + b"\n",
                        private_data,
                        public_data,
                        artifacts,
                    )
            extra = b"\n".join(journal_lines + [b'{"state":"EXTRA"}']) + b"\n"
            with self.assertRaises(live.LiveError):
                live.validate_completed_run(extra, private_data, public_data, artifacts)
            duplicate_pass = b"\n".join(journal_lines + [journal_lines[-1]]) + b"\n"
            with self.assertRaises(live.LiveError):
                live.validate_completed_run(
                    duplicate_pass, private_data, public_data, artifacts
                )

    def test_publication_prepare_failure_is_terminal_incident(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (
            root,
            _timeline,
            journal_events,
            _writes,
            _session,
            _parsed,
        ):
            original_read = live._read_stable

            def fail_transcript(path: Path, label: str, **kwargs: object) -> bytes:
                if label == "V030 transcript":
                    raise live.LiveError("synthetic pre-publication read failure")
                return original_read(path, label, **kwargs)

            with mock.patch.object(live, "_read_stable", side_effect=fail_transcript):
                with self.assertRaises(live.LiveError):
                    live.run(args)
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            records = [
                json.loads(line) for line in (output / live.JOURNAL_NAME).read_text().splitlines()
            ]
            self.assertEqual(records[-1]["state"], "INCIDENT")
            self.assertTrue(records[-1]["terminal"])
            self.assertIn("INCIDENT", [event["state"] for event in journal_events])

    def test_post_dispatch_validation_error_retains_incident_and_blocks_replay(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(b"malformed probe", validation_fails=True) as (
            root,
            timeline,
            journal_events,
            writes,
            session,
            _parsed,
        ):
            with self.assertRaises((live.LiveError, live.transport.LiveError)):
                live.run(args)
            self.assertEqual(session.probe_calls, 1)
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            self.assertTrue((output / live.RAW_OUTPUT_NAME).exists())
            self.assertTrue((output / live.TRANSCRIPT_NAME).exists())
            self.assertTrue((output / live.JOURNAL_NAME).exists())
            self.assertEqual((output / live.RAW_OUTPUT_NAME).read_bytes(), b"malformed probe")
            states = [event.get("state") for event in journal_events]
            self.assertIn("EFFECT_DISPATCHED", states)
            self.assertIn("INCIDENT", states)
            with self.assertRaises((live.LiveError, live.transport.LiveError)):
                live.run(args)
            self.assertEqual(session.probe_calls, 1)
        self.assertIn("probe", timeline)

    def test_ambiguous_probe_uses_one_cancel_and_does_not_replay(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (
            root,
            timeline,
            journal_events,
            writes,
            session,
            _parsed,
        ):
            del writes
            original_invoke = session.invoke

            def raise_probe(evidence_id: str, argv: tuple[str, ...], *args: object, **kwargs: object):
                if evidence_id == "probe":
                    timeline.append("probe_dispatched_then_lost")
                    session.prompt_ready = False
                    raise RuntimeError("synthetic timeout")
                return original_invoke(evidence_id, argv, *args, **kwargs)

            session.invoke = raise_probe  # type: ignore[method-assign]
            cancel = {
                "proved": True,
                "channel_ready": True,
                "pid": 1,
                "terminal_payload": b"partial oracle output",
                "errors": [],
            }
            with mock.patch.object(
                live.transport, "cancel_probe_raw", return_value=cancel
            ) as cancel_mock:
                with self.assertRaises(live.LiveError):
                    live.run(args)
                cancel_mock.assert_called_once()
                self.assertEqual(session.probe_calls, 0)
            states = [event.get("state") for event in journal_events]
            self.assertIn("EFFECT_DISPATCHED", states)
            self.assertIn("INCIDENT", states)
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            self.assertEqual(
                (output / live.RAW_OUTPUT_NAME).read_bytes(),
                b"partial oracle output",
            )

    def test_ambiguous_probe_cancel_failure_skips_unsafe_cleanup(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (
            root,
            timeline,
            journal_events,
            writes,
            session,
            _parsed,
        ):
            del root, writes
            original_invoke = session.invoke

            def raise_probe(evidence_id: str, argv: tuple[str, ...], *args: object, **kwargs: object):
                if evidence_id == "probe":
                    session.prompt_ready = False
                    raise RuntimeError("synthetic timeout")
                return original_invoke(evidence_id, argv, *args, **kwargs)

            session.invoke = raise_probe  # type: ignore[method-assign]
            cancel = {
                "proved": False,
                "channel_ready": False,
                "pid": 1,
                "errors": ["timeout"],
            }
            with mock.patch.object(
                live.transport, "cancel_probe_raw", return_value=cancel
            ) as cancel_mock:
                with self.assertRaises(live.LiveError):
                    live.run(args)
                cancel_mock.assert_called_once()
            self.assertNotIn("cleanup_node", timeline)
            self.assertNotIn("final_version", timeline)
            self.assertIn("INCIDENT", [event.get("state") for event in journal_events])

    def test_post_health_publication_failure_is_terminal_incident(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (
            root,
            timeline,
            journal_events,
            writes,
            session,
            _parsed,
        ):
            del timeline, writes, session
            original_write = live._write_or_verify

            def fail_public(path: Path, data: bytes, mode: int = 0o600) -> None:
                if Path(path).name == live.PUBLIC_MANIFEST_NAME:
                    raise live.LiveError("synthetic public publication failure")
                original_write(path, data, mode)

            with mock.patch.object(live, "_write_or_verify", side_effect=fail_public):
                with self.assertRaises(live.LiveError):
                    live.run(args)
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            records = [json.loads(line) for line in (output / live.JOURNAL_NAME).read_text().splitlines()]
            self.assertEqual(records[-1]["state"], "INCIDENT")
            self.assertTrue(records[-1]["terminal"])
            self.assertNotEqual(records[-1]["state"], "PASS")
            self.assertIn("INCIDENT", [event.get("state") for event in journal_events])

    def test_terminal_pass_append_failure_cannot_leave_authoritative_artifacts(self) -> None:
        args = SimpleNamespace(execute=True, experiment_id=live.EXPERIMENT_ID)
        with _mocked_run(_valid_payload()) as (
            root,
            _timeline,
            journal_events,
            _writes,
            _session,
            _parsed,
        ):
            original_append = live._append_journal

            def fail_pass(path: Path, event: dict[str, object]) -> None:
                if event.get("state") == "PASS":
                    raise live.LiveError("synthetic terminal append failure")
                original_append(path, event)

            with mock.patch.object(live, "_append_journal", side_effect=fail_pass):
                with self.assertRaises(live.LiveError):
                    live.run(args)
            output = root / "evidence" / "private" / live.OUTPUT_DIR_NAME
            records = [
                json.loads(line)
                for line in (output / live.JOURNAL_NAME).read_text().splitlines()
            ]
            self.assertEqual(records[-1]["state"], "INCIDENT")
            self.assertFalse(any(record["state"] == "PASS" for record in records))
            self.assertEqual(
                json.loads((output / live.PRIVATE_RECEIPT_NAME).read_text())["status"],
                "PREPARED_NOT_AUTHORITY",
            )
            self.assertEqual(
                json.loads(
                    (root / "evidence" / "manifests" / live.PUBLIC_MANIFEST_NAME).read_text()
                )["status"],
                "PREPARED_NOT_AUTHORITY",
            )

if __name__ == "__main__":
    unittest.main()
