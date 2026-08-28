from __future__ import annotations

import contextlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools import a90_rbin_phys_oracle_live as live


SLOPE = 64
INTERCEPT = 0xFFFF000000000000
CALIBRATION_PFNS = (0x1000, 0x2000, 0x3000)


def _format(event: str) -> str:
    if event == "cma_alloc":
        return "\n".join(
            (
                "name: cma_alloc",
                "\tfield:unsigned long page; offset:0; size:8; signed:0;",
                "\tfield:unsigned long pfn; offset:8; size:8; signed:0;",
                "\tfield:unsigned int count; offset:16; size:4; signed:0;",
                "\tfield:unsigned int align; offset:20; size:4; signed:0;",
            )
        )
    if event == "ion_rbin_alloc_start":
        return "\tfield:unsigned long size; offset:0; size:8; signed:0;"
    if event == "ion_rbin_alloc_end":
        return "\tfield:void *page; offset:0; size:8; signed:0;"
    return "\n".join(
        (
            "\tfield:void *page; offset:0; size:8; signed:0;",
            "\tfield:unsigned long size; offset:8; size:8; signed:0;",
        )
    )


def _raw_hex(size: int = 20) -> str:
    return (b"\x00" * size).hex()


def _event(
    event: str,
    *,
    phase: str,
    page: int = 0,
    size: int = 0,
    pfn: int | None = None,
    count: int | None = None,
    raw_size: int = 20,
) -> dict[str, object]:
    return {
        "schema": live.PROBE_SCHEMA,
        "type": "event",
        "phase": phase,
        "event": event,
        "page_ptr": hex(page),
        # The C probe reports field presence, not value presence: the
        # allocation-end tracepoint has a present-but-NULL page field.
        "has_page": event != "ion_rbin_alloc_start",
        "pfn": pfn is not None,
        "pfn_value": hex(pfn) if pfn is not None else None,
        "count": count is not None,
        "count_value": hex(count) if count is not None else None,
        "size_bytes": size,
        "raw_size": raw_size,
        "raw_hex": _raw_hex(raw_size),
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
            "format_size": 128,
            "has_page": event != "ion_rbin_alloc_start",
            "has_size": event != "ion_rbin_alloc_end" and event != "cma_alloc",
            "has_pfn": event == "cma_alloc",
            "has_count": event == "cma_alloc",
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
                size=0,
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
        _event("ion_rbin_alloc_end", phase="allocation", page=0, size=0),
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
    def __init__(self, timeline: list[str], probe_payload: bytes) -> None:
        self.timeline = timeline
        self.probe_payload = probe_payload
        self.transcript_parts: list[bytes] = []
        self.commands: list[dict[str, object]] = []
        self.probe_calls = 0

    def invoke(self, evidence_id: str, argv: tuple[str, ...], *args: object, **kwargs: object) -> _RunFrame:
        del args, kwargs
        self.timeline.append(evidence_id)
        if evidence_id == "probe":
            self.probe_calls += 1
            payload = self.probe_payload
        elif evidence_id == "final_selftest":
            payload = b"selftest: pass=11 warn=1 fail=0 duration=0ms entries=12\n"
        elif argv and argv[0] == "run":
            payload = b"run: pid=1, q/Ctrl-C cancels\n[exit 0]\n"
        else:
            payload = b""
        frame = _RunFrame(argv[0] if argv else "", payload)
        self.transcript_parts.append(frame.transcript)
        self.commands.append({"evidence_id": evidence_id, "argv": list(argv)})
        return frame


@contextlib.contextmanager
def _mocked_run(probe_payload: bytes, *, validation_fails: bool = False):
    """Provide a no-device run seam while retaining the real journal writer."""

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        timeline: list[str] = []
        journal_events: list[dict[str, object]] = []
        writes: list[tuple[Path, bytes, int]] = []
        session = _RunSession(timeline, probe_payload)
        binding = {"process_pid": 1, "serial_device": "/dev/ttyACM0"}
        binary = b"fixed-test-binary"
        parsed = live.validate_oracle_payload(_valid_payload())

        def fake_read(path: Path, label: str, **kwargs: object) -> bytes:
            del label, kwargs
            if Path(path).is_file():
                return Path(path).read_bytes()
            return b"fixed-test-source" if Path(path).name == live.SOURCE_BASENAME else binary

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
            return "11111111-1111-4111-8111-111111111111"

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
            live.transport, "require_child_exit_zero"
        ), mock.patch.object(
            live.boot_attestation, "attest_current_boot", side_effect=boot_attest
        ), mock.patch.object(
            live, "_read_boot_id", side_effect=boot_id
        ):
            yield root, timeline, journal_events, writes, session, parsed


class RbinOracleLiveTests(unittest.TestCase):
    def test_trace_format_uses_declared_group_and_fields(self) -> None:
        cma = live.parse_trace_format(_format("cma_alloc"), "cma_alloc")
        self.assertEqual(cma["fields"]["page"]["offset"], 0)
        self.assertEqual(cma["fields"]["pfn"]["offset"], 8)
        self.assertEqual(cma["fields"]["count"]["offset"], 16)
        with self.assertRaises(live.LiveError):
            live.parse_trace_format(_format("cma_alloc").replace("offset:8", "offset:4092"), "cma_alloc")

    def test_perf_raw_and_ring_wrap_parse(self) -> None:
        description = live.parse_trace_format(_format("ion_rbin_pool_alloc_end"), "ion_rbin_pool_alloc_end")
        # PERF_SAMPLE_RAW stores the kernel's internal tracepoint padding in
        # raw_size.  A 16-byte declared payload is therefore represented by
        # raw_size=20 and record_size=12+20=32, with no extra record padding.
        raw = (
            (0xFFFF000000001000).to_bytes(8, "little")
            + (4096).to_bytes(8, "little")
            + b"\0" * 4
        )
        parsed = live.parse_perf_raw_record(raw, description, event_name="ion_rbin_pool_alloc_end")
        self.assertEqual(parsed["size_bytes"], 4096)
        record = struct.pack("<IHHI", 9, 0, 32, len(raw)) + raw
        ring = bytearray(64)
        for index, byte in enumerate(record):
            ring[(56 + index) & 63] = byte
        rows = live.parse_perf_ring_bytes(bytes(ring), description, event_name="ion_rbin_pool_alloc_end", data_head=56 + len(record), data_tail=56)
        self.assertEqual(rows[0]["page"], 0xFFFF000000001000)
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
                struct.pack("<IHHI", 2, 0, 32, len(raw)) + raw,
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
            live.derive_affine_page_relation([(0xFFFF000000000000, 1), (0xFFFF000000000040, 2), (0xFFFF0000000000C0, 3)])
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
            self.assertEqual(receipt["status"], "PASS")
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
                self.assertEqual(descriptor["sha256"], live.sha256(artifact))
                self.assertEqual(descriptor["size_bytes"], len(artifact))

        self.assertEqual(session.probe_calls, 1)
        self.assertEqual(sum(item == "probe" for item in timeline), 1)
        states = [event.get("state") for event in journal_events]
        self.assertIn("OWNERSHIP_CLAIM", states)
        self.assertIn("EFFECT_DISPATCHED", states)
        self.assertLess(timeline.index("journal:OWNERSHIP_CLAIM"), timeline.index("version"))
        self.assertLess(timeline.index("boot_attestation"), timeline.index("journal:EFFECT_DISPATCHED"))
        self.assertLess(timeline.index("boot_id_before"), timeline.index("journal:EFFECT_DISPATCHED"))
        self.assertLess(timeline.index("bridge_revalidate"), timeline.index("journal:EFFECT_DISPATCHED"))
        self.assertLess(timeline.index("journal:EFFECT_DISPATCHED"), timeline.index("probe"))
        self.assertIn("boot_id_after", timeline)
        self.assertGreater(timeline.index("boot_id_after"), timeline.index("probe"))
        self.assertIn('"state": "EFFECT_DISPATCHED"', journal)

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

if __name__ == "__main__":
    unittest.main()
