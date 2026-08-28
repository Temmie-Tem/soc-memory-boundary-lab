#!/usr/bin/env python3
"""Host-side Verification 030 RBIN physical-placement runner.

The module is import-safe and performs no device contact until ``run`` is
called with an explicit ``--execute`` namespace.  It owns one fixed A90
camera_preview allocation, keeps perf tracepoint evidence private, and emits
only the derived SG/PA summary publicly.  A missing same-run CMA affine
calibration is an incident, never an invitation to guess a vmemmap base.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import struct
import tempfile
from typing import Mapping, Sequence

try:
    from tools import a90_pa28_live as transport
    from tools import a90_v024_boot_attestation as boot_attestation
except ModuleNotFoundError:  # Direct execution from tools/.
    import a90_pa28_live as transport  # type: ignore
    import a90_v024_boot_attestation as boot_attestation  # type: ignore


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_ID = "verification-030-rbin-phys-oracle"
PUBLIC_SCHEMA = "a90-rbin-phys-oracle-public-v1"
PRIVATE_SCHEMA = "a90-rbin-phys-oracle-private-v1"
PROBE_SCHEMA = "a90_rbin_phys_oracle_v030_v1"
SOURCE_BASENAME = "a90_rbin_phys_oracle_probe.c"
BINARY_BASENAME = "a90-rbin-phys-oracle"
# Updated only when the owned C probe is stable.  This pin is checked before
# the build subprocess and before any bridge/device contact.
EXPECTED_SOURCE_SIZE = 70_971
EXPECTED_SOURCE_SHA256 = "cee8f32b432e2e62e3169d06f6cd95419df16cb55096b61790595580f30a019e"
# Updated together with the source pin after the reviewed C probe is stable.
EXPECTED_BINARY_SIZE = 777_200
EXPECTED_BINARY_SHA256 = "f12959b5772d8b89ebe5abb15505a0ee2662864f6847189f77c101834337159e"
OUTPUT_DIR_NAME = EXPERIMENT_ID
PUBLIC_MANIFEST_NAME = f"{EXPERIMENT_ID}.manifest.json"
PRIVATE_RECEIPT_NAME = "receipt.json"
RAW_OUTPUT_NAME = "oracle-output.jsonl"
TRANSCRIPT_NAME = "transcript.bin"
BUILD_RECEIPT_NAME = "build-receipt.json"
JOURNAL_NAME = "journal.jsonl"
REMOTE_ROOT = "/tmp/a90-native"
REMOTE_ENVELOPE = f"{REMOTE_ROOT}/v030-rbin-phys-oracle.b64u"
REMOTE_BINARY = f"{REMOTE_ROOT}/{BINARY_BASENAME}"
REMOTE_ION = f"{REMOTE_ROOT}/v030-rbin-ion"
ION_DEV_PATH = transport.ION_DEV_PATH
EXPECTED_ION_DEV = transport.EXPECTED_ION_DEV
TOYBOX = transport.TOYBOX
EXPECTED_HEAP = "camera_preview"
EXPECTED_HEAP_ID = 30
EXPECTED_HEAP_TYPE = 10
EXPECTED_BYTES = 0x14000000
EXPECTED_FLAGS = 0
EXPECTED_CALIBRATION_HEAP = "user_contig"
EXPECTED_CALIBRATION_HEAP_ID = 26
EXPECTED_CALIBRATION_HEAP_TYPE = 4
EXPECTED_CPU = 7
EXPECTED_REGION_FIRST = 0xC2000000
EXPECTED_REGION_END = 0xD6000000
BOOT_PREFIX_SIZE = 60_882_944
BOOT_PREFIX_SHA256 = "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
EXPECTED_TRACE_EVENTS = (
    "cma_alloc",
    "ion_rbin_alloc_start",
    "ion_rbin_alloc_end",
    "ion_rbin_pool_alloc_end",
    "ion_rbin_partial_alloc_end",
)
EXPECTED_TARGET = {
    "model": transport.EXPECTED_MODEL,
    "soc": transport.EXPECTED_SOC,
    "runtime_version": transport.EXPECTED_RUNTIME,
    "runtime_build": transport.EXPECTED_RUNTIME_BUILD,
    "kernel": transport.EXPECTED_KERNEL,
    "bootloader": transport.EXPECTED_BOOTLOADER,
    "debug_level": "0x4f4c",
    "force_upload": "0x0",
    "dump_sink": "0x0",
}
EFFECT_PROFILE = {
    "temporary_runtime_writes": True,
    "normal_ram_allocation": True,
    "persistent_device_writes": False,
    "partition_writes": False,
    "mmio_writes": False,
    "controller_writes": False,
    "smc": False,
    "protected_memory_read": False,
    "reboot": False,
    "automatic_retries": False,
}
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
VA_BITS = 39
PAGE_PTR_STRIDE_MIN = 32
PAGE_PTR_STRIDE_MAX = 256
HEX_U64_RE = re.compile(r"0x[0-9a-f]+\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_DECL_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\*|\[|\]")
_EXPECTED_DECLARATION_TOKENS = {
    ("cma_alloc", "page"): ("const", "struct", "page", "*", "page"),
    ("cma_alloc", "pfn"): ("unsigned", "long", "pfn"),
    ("cma_alloc", "count"): ("unsigned", "int", "count"),
    ("cma_alloc", "align"): ("unsigned", "int", "align"),
    ("ion", "heap_name"): ("const", "char", "*", "heap_name"),
    ("ion", "buffer"): ("void", "*", "buffer"),
    ("ion", "size"): ("unsigned", "long", "size"),
    ("ion", "page"): ("void", "*", "page"),
}
_EXPECTED_DECLARATION_SIZES = {
    ("cma_alloc", "page"): 8,
    ("cma_alloc", "pfn"): 8,
    ("cma_alloc", "count"): 4,
    ("cma_alloc", "align"): 4,
    ("ion", "heap_name"): 8,
    ("ion", "buffer"): 8,
    ("ion", "size"): 8,
    ("ion", "page"): 8,
}


class LiveError(RuntimeError):
    """The fixed V030 live/evidence contract was not satisfied."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _strict_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise LiveError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise LiveError(f"non-finite JSON constant: {value}")


def json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise LiveError("receipt is not strict JSON") from exc


def _journal_bytes(value: object) -> bytes:
    """Encode exactly one compact JSON object followed by one newline."""

    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise LiveError("journal record is not strict JSON") from exc


def _append_journal(path: Path, event: Mapping[str, object]) -> None:
    """Append one fsynced lifecycle record without ever replacing the file."""

    data = _journal_bytes(dict(event))
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise LiveError("V030 durable journal cannot be opened") from exc
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise LiveError("V030 durable journal made no progress")
            view = view[count:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create one private file with durable no-clobber semantics."""

    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise LiveError(f"V030 refusing to replace existing file {path}") from exc
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise LiveError(f"V030 short write while creating {path}")
            view = view[count:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)


def _fsync_directory(path: Path) -> None:
    """Durably publish a newly-created ownership-journal dentry."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(Path(path), flags)
    except OSError as exc:
        raise LiveError(f"V030 ownership directory cannot be synced: {path}") from exc
    try:
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)


def _write_or_verify(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Publish once, or accept an identical already-published sidecar."""

    path = Path(path)
    try:
        _write_exclusive(path, data, mode)
        return
    except LiveError:
        # A pre-existing file is safe only when it is the exact bytes already
        # owned by this one-shot run.  Different bytes are a collision.
        try:
            existing = _read_stable(path, f"V030 existing sidecar {path}")
        except LiveError:
            raise
        if existing != data:
            raise LiveError(f"V030 sidecar collision at {path}")


def _read_boot_id(session: object, evidence_id: str) -> str:
    """Read and strictly validate the current kernel boot UUID."""

    frame = session.invoke(
        evidence_id,
        ("run", TOYBOX, "cat", BOOT_ID_PATH),
        allow_error=True,
    )
    transport.require_frame_ok(frame, evidence_id)
    value = transport.parse_run_value(frame.payload, evidence_id)
    if BOOT_ID_RE.fullmatch(value) is None:
        raise LiveError(f"{evidence_id} returned a malformed boot_id")
    return value


def _normalise_probe_payload(payload: bytes) -> bytes:
    """Strip only the fixed run banner/exit lines around oracle JSONL."""

    if not isinstance(payload, bytes) or not payload:
        raise LiveError("V030 oracle payload is empty")
    lines = payload.replace(b"\r\n", b"\n").splitlines()
    if not lines:
        raise LiveError("V030 oracle payload has no lines")
    run_prefix = re.fullmatch(rb"run: pid=[0-9]+, q/Ctrl-C cancels", lines[0])
    exit_line = re.fullmatch(rb"\[exit [0-9]+\]", lines[-1])
    if run_prefix is not None or exit_line is not None:
        if run_prefix is None or exit_line is None or len(lines) < 3:
            raise LiveError("V030 oracle transport framing is incomplete")
        lines = lines[1:-1]
    if any(not line or not line.lstrip().startswith(b"{") for line in lines):
        raise LiveError("V030 oracle payload contains non-JSON output")
    return b"\n".join(lines) + b"\n"


def _validate_boot_record(record: Mapping[str, object]) -> dict[str, object]:
    """Require the attestation delegate's exact pinned prefix proof."""

    if not isinstance(record, Mapping):
        raise LiveError("V030 boot attestation is not an object")
    if (
        record.get("expected_sha256") != BOOT_PREFIX_SHA256
        or record.get("captured_sha256") != BOOT_PREFIX_SHA256
        or record.get("expected_size") != BOOT_PREFIX_SIZE
        or record.get("captured_size") != BOOT_PREFIX_SIZE
        or record.get("hash_matches_candidate") is not True
        or record.get("size_matches_candidate") is not True
        or record.get("cleanup_ok") is not True
        or record.get("binding_failure") is True
        or record.get("cleanup_error") is not None
    ):
        raise LiveError("V030 current boot prefix attestation is not exact")
    events = record.get("binding_events")
    if not isinstance(events, list) or not events:
        raise LiveError("V030 boot attestation lacks binding events")
    return dict(record)


def _pinned_source_descriptor(path: Path, data: bytes) -> dict[str, object]:
    """Bind the exact reviewed V030 C bytes, never a caller replacement."""

    descriptor = {
        "basename": Path(path).name,
        "size_bytes": len(data),
        "sha256": sha256(data),
    }
    if (
        descriptor["basename"] != SOURCE_BASENAME
        or descriptor["size_bytes"] != EXPECTED_SOURCE_SIZE
        or descriptor["sha256"] != EXPECTED_SOURCE_SHA256
    ):
        raise LiveError("V030 source bytes do not match the reviewed pin")
    return descriptor


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_stable(path: Path, label: str, *, maximum: int = MAX_OUTPUT_BYTES) -> bytes:
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            raise LiveError(f"{label} is not a regular file")
        before = path.stat()
        if before.st_size < 0 or before.st_size > maximum:
            raise LiveError(f"{label} exceeds bounded size")
        data = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise LiveError(f"{label} cannot be read") from exc
    if (
        len(data) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise LiveError(f"{label} changed while being read")
    return data


def _descriptor(path: Path, label: str) -> dict[str, object]:
    data = _read_stable(path, label)
    return {"basename": path.name, "size_bytes": len(data), "sha256": sha256(data)}


def _compiler_descriptor(compiler: str) -> dict[str, object]:
    """Identify the exact compiler executable used for both deterministic builds."""

    resolved = shutil.which(compiler)
    if not resolved:
        raise LiveError(f"V030 compiler is unavailable: {compiler}")
    compiler_path = Path(os.path.realpath(resolved))
    data = _read_stable(compiler_path, "V030 compiler executable", maximum=64 * 1024 * 1024)
    if not data:
        raise LiveError("V030 compiler executable is empty")
    return {
        "requested": compiler,
        "path": str(compiler_path),
        "size_bytes": len(data),
        "sha256": sha256(data),
    }


def _validate_static_aarch64_elf(data: bytes) -> dict[str, object]:
    """Require an ELF64 little-endian AArch64 binary with no PT_INTERP."""

    if not isinstance(data, bytes) or len(data) < 64:
        raise LiveError("V030 binary is not a complete ELF64 header")
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise LiveError("V030 binary is not ELF64 little-endian")
    elf_type = struct.unpack_from("<H", data, 16)[0]
    if elf_type != 2:  # ET_EXEC is the reviewed static build shape.
        raise LiveError("V030 binary is not an ET_EXEC image")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 183:  # EM_AARCH64
        raise LiveError("V030 binary is not AArch64")
    entry = struct.unpack_from("<Q", data, 24)[0]
    if entry == 0:
        raise LiveError("V030 binary entry point is empty")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    if phentsize < 56 or phnum == 0:
        raise LiveError("V030 binary lacks bounded program headers")
    if phoff > len(data) or phnum > (len(data) - phoff) // phentsize:
        raise LiveError("V030 binary program headers exceed file bounds")
    load_count = 0
    executable_entry = False
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type = struct.unpack_from("<I", data, offset)[0]
        p_flags = struct.unpack_from("<I", data, offset + 4)[0]
        p_offset = struct.unpack_from("<Q", data, offset + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, offset + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, offset + 32)[0]
        p_memsz = struct.unpack_from("<Q", data, offset + 40)[0]
        if p_offset > len(data) or p_filesz > len(data) - p_offset:
            raise LiveError("V030 binary program segment exceeds file bounds")
        if p_memsz < p_filesz or p_vaddr > (1 << 64) - p_memsz:
            raise LiveError("V030 binary program segment bounds are invalid")
        if p_type == 1:  # PT_LOAD
            load_count += 1
            if p_flags & 1 and p_vaddr <= entry < p_vaddr + p_memsz:
                executable_entry = True
        if p_type in {2, 3}:  # PT_DYNAMIC / PT_INTERP
            raise LiveError("V030 binary is dynamically interpreted")
    if load_count == 0 or not executable_entry:
        raise LiveError("V030 binary lacks an executable PT_LOAD entry")
    return {
        "elf_type": "ET_EXEC",
        "elf_class": "ELF64",
        "endianness": "little",
        "machine": "AArch64",
        "pt_interp": False,
        "static": True,
    }


def _parse_json_line(line: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except LiveError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise LiveError(f"{label} is not an object")
    return value


def _u64(value: object, label: str) -> int:
    if not isinstance(value, str) or HEX_U64_RE.fullmatch(value) is None:
        raise LiveError(f"{label} is not canonical lowercase hex")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise LiveError(f"{label} is malformed") from exc
    if parsed < 0 or parsed > (1 << 64) - 1:
        raise LiveError(f"{label} is outside uint64")
    return parsed


def _canonical_kernel_pointer(value: int) -> bool:
    """Require exact sign extension for the fixed VA_BITS=39 kernel."""

    return (
        type(value) is int
        and 0 < value <= (1 << 64) - 1
        and (value >> VA_BITS) == ((1 << (64 - VA_BITS)) - 1)
    )


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise LiveError(f"{label} is not lowercase SHA-256")
    return value


def _declaration_tokens(value: str) -> tuple[str, ...] | None:
    """Tokenize a trace declaration while rejecting data_loc/other syntax."""

    tokens = tuple(_DECL_TOKEN_RE.findall(value))
    if not tokens:
        return None
    remainder = _DECL_TOKEN_RE.sub("", value)
    if remainder.strip():
        return None
    return tokens


def _expected_declaration_tokens(event_name: str, role: str) -> tuple[str, ...] | None:
    if event_name == "cma_alloc":
        return _EXPECTED_DECLARATION_TOKENS.get((event_name, role))
    return _EXPECTED_DECLARATION_TOKENS.get(("ion", role))


def _expected_declaration_size(event_name: str, role: str) -> int | None:
    if event_name == "cma_alloc":
        return _EXPECTED_DECLARATION_SIZES.get((event_name, role))
    return _EXPECTED_DECLARATION_SIZES.get(("ion", role))


def parse_trace_format(text: str | bytes, event_name: str) -> dict[str, object]:
    """Parse a fixed tracepoint ``format`` using its declared offsets/sizes."""

    if event_name not in EXPECTED_TRACE_EVENTS:
        raise LiveError("trace event name is not fixed")
    if isinstance(text, bytes):
        try:
            text = text.decode("ascii")
        except UnicodeDecodeError as exc:
            raise LiveError("trace format is not ASCII") from exc
    fields: dict[str, dict[str, object]] = {}
    declared_raw_size_limit = 0
    for line in text.splitlines():
        if not line.startswith("\tfield:") and not line.startswith("field:"):
            continue
        match = re.search(
            r"field:\s*(?P<name>[^;]+);\s*offset:(?P<offset>[0-9]+);\s*"
            r"size:(?P<size>[0-9]+);\s*signed:(?P<signed>[01]);",
            line,
        )
        if match is None:
            raise LiveError(f"{event_name} has malformed field format")
        name = match.group("name").strip()
        offset = int(match.group("offset"), 10)
        size = int(match.group("size"), 10)
        if size <= 0 or size > 4096 or offset > 4096 or offset + size > 4096:
            raise LiveError(f"{event_name} field bounds are unsafe")
        declared_raw_size_limit = max(declared_raw_size_limit, offset + size)
        short = name.split("__entry->", 1)[-1].split(".")[-1]
        short = short.split()[-1]
        short = short.lstrip("*")
        short = short.split("[", 1)[0].strip()
        role = {
            "page": "page",
            "page_ptr": "page",
            "size": "size",
            "len": "size",
            "length": "size",
            "pfn": "pfn",
            "count": "count",
            "nr_pages": "count",
            "npages": "count",
            "align": "align",
            "ret": "result",
            "retval": "result",
            "result": "result",
            "rc": "result",
            "status": "result",
            "heap_name": "heap_name",
            "name": "heap_name",
            "buffer": "buffer",
        }.get(short)
        if role is None:
            continue
        actual_declaration = _declaration_tokens(name)
        expected_declaration = _expected_declaration_tokens(event_name, role)
        expected_size = _expected_declaration_size(event_name, role)
        if (
            actual_declaration is None
            or expected_declaration is None
            or actual_declaration != expected_declaration
            or expected_size != size
            or match.group("signed") != "0"
        ):
            raise LiveError(f"{event_name} declaration for {role} is not source-exact")
        if role in fields:
            raise LiveError(f"{event_name} repeats {role} field")
        if size not in {1, 2, 4, 8}:
            raise LiveError(f"{event_name} field bounds are unsafe")
        fields[role] = {
            "name": name,
            "offset": offset,
            "size": size,
            "signed": match.group("signed") == "1",
        }
    required = {
        "cma_alloc": {"page", "pfn", "count"},
        "ion_rbin_alloc_start": {"heap_name", "buffer", "size", "page"},
        "ion_rbin_alloc_end": {"heap_name", "buffer", "size", "page"},
        "ion_rbin_pool_alloc_end": {"heap_name", "buffer", "size", "page"},
        "ion_rbin_partial_alloc_end": {"heap_name", "buffer", "size", "page"},
    }[event_name]
    if not required.issubset(fields):
        raise LiveError(f"{event_name} lacks required declared fields")
    raw_size_limit = declared_raw_size_limit
    # PERF_SAMPLE_RAW's u32 includes the trace-entry bytes plus its internal
    # four-byte alignment pad.  Keep this derived size with the retained
    # format so every emitted raw_hex can be independently re-decoded.
    raw_size_with_header = (raw_size_limit + 4 + 7) & ~7
    expected_raw_size = raw_size_with_header - 4
    if expected_raw_size <= 0 or expected_raw_size > 4096:
        raise LiveError(f"{event_name} raw record size is unbounded")
    return {
        "event": event_name,
        "fields": fields,
        "raw_size_limit": raw_size_limit,
        "raw_size": expected_raw_size,
    }


def _read_le(data: bytes, offset: int, size: int, label: str) -> int:
    if offset < 0 or size not in {1, 2, 4, 8} or offset + size > len(data):
        raise LiveError(f"{label} field exceeds raw record")
    return int.from_bytes(data[offset : offset + size], "little", signed=False)


def parse_perf_raw_record(
    raw: bytes, format_description: Mapping[str, object], *, event_name: str
) -> dict[str, object]:
    """Decode one tracepoint raw payload according to its live format."""

    if not isinstance(raw, bytes) or len(raw) == 0 or len(raw) > 4096:
        raise LiveError("tracepoint raw record is unbounded")
    if format_description.get("event") != event_name:
        raise LiveError("tracepoint format/event identity differs")
    fields = format_description.get("fields")
    if not isinstance(fields, Mapping):
        raise LiveError("tracepoint format fields are missing")
    expected_raw_size = format_description.get("raw_size")
    if type(expected_raw_size) is int and len(raw) != expected_raw_size:
        raise LiveError("tracepoint raw record size differs from retained format")
    result: dict[str, object] = {
        "event": event_name,
        "raw_size": len(raw),
        "raw_sha256": sha256(raw),
        "raw_hex": raw.hex(),
    }
    for role, field in fields.items():
        if not isinstance(field, Mapping):
            raise LiveError("tracepoint field descriptor is malformed")
        offset = field.get("offset")
        size = field.get("size")
        if (
            type(offset) is not int
            or type(size) is not int
            or offset < 0
            or size not in {1, 2, 4, 8}
        ):
            raise LiveError("tracepoint field descriptor bounds are malformed")
        value = _read_le(
            raw,
            offset,
            size,
            f"{event_name} {role}",
        )
        if role == "result" and field.get("signed") is True and size < 8:
            sign = 1 << (8 * size - 1)
            if value & sign:
                value -= 1 << (8 * size)
        result[role] = value
    if event_name == "cma_alloc":
        count = int(result.get("count", 0))
        if count <= 0 or count > (1 << 52):
            raise LiveError("CMA count is invalid")
        result["size_bytes"] = count * 4096
    elif "size" in result:
        result["size_bytes"] = int(result["size"])
    if "result" in result and int(result["result"]) != 0:
        raise LiveError(f"{event_name} returned a non-success result")
    return result


def parse_perf_ring_bytes(
    data: bytes,
    format_description: Mapping[str, object],
    *,
    event_name: str,
    data_head: int | None = None,
    data_tail: int = 0,
    data_size: int | None = None,
) -> list[dict[str, object]]:
    """Parse synthetic/perf ring bytes, including wrap and loss rejection."""

    if not isinstance(data, bytes):
        raise LiveError("perf ring is not bytes")
    if data_size is None:
        data_size = len(data)
    if (
        type(data_size) is not int
        or data_size <= 0
        or data_size > len(data)
        or data_size & (data_size - 1)
    ):
        raise LiveError("perf ring size is not a power of two")
    head = len(data) if data_head is None else data_head
    if (
        type(head) is not int
        or type(data_tail) is not int
        or head < 0
        or data_tail < 0
        or head < data_tail
        or head - data_tail > data_size
    ):
        raise LiveError("perf ring overflow/lost bytes")

    def copy(offset: int, size: int) -> bytes:
        position = offset & (data_size - 1)
        first = min(size, data_size - position)
        return data[position : position + first] + data[: size - first]

    rows: list[dict[str, object]] = []
    cursor = data_tail
    while cursor < head:
        header = copy(cursor, 8)
        record_type = int.from_bytes(header[:4], "little")
        record_size = int.from_bytes(header[6:8], "little")
        if (
            record_size < 12
            or (record_size & 7)
            or record_size > head - cursor
            or record_size > data_size
        ):
            raise LiveError("perf record is truncated or malformed")
        record = copy(cursor, record_size)
        if record_type != 9:  # PERF_RECORD_SAMPLE
            raise LiveError("perf ring contains lost/throttle/unexpected record")
        # With PERF_SAMPLE_RAW the u32 raw-size is followed by exactly that
        # many bytes.  The kernel includes its internal tracepoint padding in
        # raw-size; there is no additional record-level padding to invent.
        raw_size = int.from_bytes(record[8:12], "little")
        if raw_size <= 0 or raw_size > 4096 or 12 + raw_size != record_size:
            raise LiveError("perf sample raw payload shape is not exact")
        rows.append(
            parse_perf_raw_record(
                record[12 : 12 + raw_size],
                format_description,
                event_name=event_name,
            )
        )
        cursor += record_size
    return rows


def _event_row(row: Mapping[str, object], index: int) -> dict[str, object]:
    required = {
        "schema",
        "type",
        "phase",
        "event",
        "page_ptr",
        "has_page",
        "pfn",
        "pfn_value",
        "count",
        "count_value",
        "has_heap_name",
        "heap_name_value",
        "has_buffer",
        "buffer_ptr",
        "size_bytes",
        "raw_size",
        "raw_hex",
    }
    if set(row) != required or row.get("schema") != PROBE_SCHEMA or row.get("type") != "event":
        raise LiveError(f"oracle event {index} fields/schema differ")
    event_name = row.get("event")
    if row.get("phase") not in {"calibration", "allocation"} or event_name not in EXPECTED_TRACE_EVENTS:
        raise LiveError(f"oracle event {index} identity differs")
    page = _u64(row.get("page_ptr"), f"oracle event {index} page_ptr")
    has_page = row.get("has_page")
    if type(has_page) is not bool:
        raise LiveError(f"oracle event {index} page presence differs")
    has_pfn = row.get("pfn")
    has_count = row.get("count")
    if type(has_pfn) is not bool or type(has_count) is not bool:
        raise LiveError(f"oracle event {index} field-presence markers differ")
    has_heap_name = row.get("has_heap_name")
    has_buffer = row.get("has_buffer")
    if type(has_heap_name) is not bool or type(has_buffer) is not bool:
        raise LiveError(f"oracle event {index} shared-field presence differs")
    pfn_value = row.get("pfn_value")
    count_value = row.get("count_value")
    if has_pfn:
        pfn_value = _u64(pfn_value, f"oracle event {index} pfn_value")
    elif pfn_value is not None:
        raise LiveError(f"oracle event {index} has an unbound pfn value")
    if has_count:
        count_value = _u64(count_value, f"oracle event {index} count_value")
    elif count_value is not None:
        raise LiveError(f"oracle event {index} has an unbound count value")
    heap_name_value = row.get("heap_name_value")
    buffer_ptr = row.get("buffer_ptr")
    if has_heap_name:
        heap_name_value = _u64(heap_name_value, f"oracle event {index} heap_name_value")
    elif heap_name_value is not None:
        raise LiveError(f"oracle event {index} has an unbound heap name value")
    if has_buffer:
        buffer_ptr = _u64(buffer_ptr, f"oracle event {index} buffer_ptr")
    elif buffer_ptr is not None:
        raise LiveError(f"oracle event {index} has an unbound buffer pointer")
    if type(row.get("size_bytes")) is not int or row["size_bytes"] < 0:
        raise LiveError(f"oracle event {index} size is invalid")
    if type(row.get("raw_size")) is not int or row["raw_size"] <= 0:
        raise LiveError(f"oracle event {index} raw size is invalid")
    raw_hex = row.get("raw_hex")
    if not isinstance(raw_hex, str) or len(raw_hex) != int(row["raw_size"]) * 2 or re.fullmatch(r"[0-9a-f]+", raw_hex) is None:
        raise LiveError(f"oracle event {index} raw bytes are not canonical")
    raw = bytes.fromhex(raw_hex)
    parsed = dict(row)
    parsed["page_ptr_value"] = page
    parsed["pfn_value"] = pfn_value
    parsed["count_value"] = count_value
    parsed["heap_name_value"] = heap_name_value
    parsed["buffer_ptr_value"] = buffer_ptr
    parsed["raw_sha256"] = sha256(raw)
    expected_presence = {
        "cma_alloc": (True, True, True, False, False),
        "ion_rbin_alloc_start": (True, False, False, True, True),
        "ion_rbin_alloc_end": (True, False, False, True, True),
        "ion_rbin_pool_alloc_end": (True, False, False, True, True),
        "ion_rbin_partial_alloc_end": (True, False, False, True, True),
    }[event_name]
    if (has_page, has_pfn, has_count, has_heap_name, has_buffer) != expected_presence:
        raise LiveError(f"oracle event {index} field presence is not source-exact")
    if event_name == "cma_alloc":
        if page == 0 or type(pfn_value) is not int or type(count_value) is not int:
            raise LiveError(f"oracle CMA event {index} lacks concrete calibration values")
    elif event_name in {"ion_rbin_alloc_start", "ion_rbin_alloc_end"}:
        if (
            page != 0
            or row["size_bytes"] <= 0
            or heap_name_value == 0
            or buffer_ptr == 0
        ):
            raise LiveError(f"oracle allocation start is malformed")
    elif event_name == "ion_rbin_pool_alloc_end":
        if heap_name_value == 0 or buffer_ptr != 0 or (page == 0) != (row["size_bytes"] == 0):
            raise LiveError(f"oracle RBIN pool result is malformed")
    elif event_name == "ion_rbin_partial_alloc_end":
        # The retained Samsung call site passes NULL for both heap_name and
        # buffer on partial_alloc_end.  The fields remain present in the
        # shared ion_rbin class, but their values are intentionally zero.
        if heap_name_value != 0 or buffer_ptr != 0 or page == 0 or row["size_bytes"] <= 0:
            raise LiveError(f"oracle RBIN partial result is malformed")
    return parsed


def derive_affine_page_relation(points: Sequence[tuple[int, int]]) -> tuple[int, int]:
    """Derive page_ptr = slope*pfn + intercept from three CMA points."""

    if len(points) != 3:
        raise LiveError("CMA calibration requires exactly three points")
    (page0, pfn0), (page1, pfn1), (page2, pfn2) = points
    if any(
        type(value) is not int or value < 0 or value > (1 << 64) - 1
        for value in (page0, page1, page2, pfn0, pfn1, pfn2)
    ):
        raise LiveError("CMA calibration values are outside uint64")
    if len({pfn0, pfn1, pfn2}) != 3 or len({page0, page1, page2}) != 3:
        raise LiveError("CMA calibration PFNs/page pointers are not distinct")
    if not all(_canonical_kernel_pointer(page) for page in (page0, page1, page2)):
        raise LiveError("CMA calibration page pointer is not canonical")
    dp = page1 - page0
    df = pfn1 - pfn0
    if dp == 0 or df == 0 or (dp > 0) != (df > 0):
        raise LiveError("CMA calibration relation is not positive")
    dp_abs = abs(dp)
    df_abs = abs(df)
    if dp_abs % df_abs:
        raise LiveError("CMA calibration relation is not integral")
    slope = dp_abs // df_abs
    if (
        slope < PAGE_PTR_STRIDE_MIN
        or slope > PAGE_PTR_STRIDE_MAX
        or slope & (slope - 1)
    ):
        raise LiveError("CMA calibration stride is not a defensible power of two")
    intercept = page0 - slope * pfn0
    if intercept < 0 or intercept + slope * pfn2 != page2:
        raise LiveError("CMA calibration third point does not bind")
    return slope, intercept


def compute_segment_union(
    segments: Sequence[Mapping[str, object]],
    *,
    slope: int,
    intercept: int,
    direct_pfn: bool = False,
) -> dict[str, object]:
    """Resolve and union private segment rows with checked uint64 arithmetic."""

    if slope <= 0 or intercept < 0:
        raise LiveError("segment affine relation is invalid")
    ranges: list[tuple[int, int]] = []
    seen: set[int] = set()
    total = 0
    for index, segment in enumerate(segments):
        page = segment.get("page_ptr_value", segment.get("page_ptr"))
        if isinstance(page, str):
            page = _u64(page, f"segment {index} page_ptr")
        if not isinstance(page, int) or not _canonical_kernel_pointer(page):
            raise LiveError(f"segment {index} page pointer is not canonical")
        size = segment.get("size_bytes")
        if type(size) is not int or size <= 0 or size % 4096:
            raise LiveError(f"segment {index} size is invalid")
        pfn = segment.get("pfn_value", segment.get("pfn"))
        if isinstance(pfn, str):
            pfn = _u64(pfn, f"segment {index} pfn")
        if pfn is None:
            delta = page - intercept
            if delta < 0 or delta % slope:
                raise LiveError(f"segment {index} is outside affine relation")
            pfn = delta // slope
        if type(pfn) is not int or pfn < 0 or pfn > (1 << 64) - 1 or intercept + slope * pfn != page:
            raise LiveError(f"segment {index} pointer/PFN relation differs")
        if direct_pfn and segment.get("pfn_value") is None:
            raise LiveError(f"segment {index} lacks direct PFN")
        if pfn in seen:
            raise LiveError("segment PFN is duplicated")
        seen.add(pfn)
        pa = pfn * 4096
        if pa > (1 << 64) - size:
            raise LiveError("segment PA arithmetic overflow")
        total += size
        if total > (1 << 64) - 1:
            raise LiveError("segment total arithmetic overflow")
        ranges.append((pa, pa + size))
    if not ranges:
        raise LiveError("segment union is empty")
    ranges.sort()
    contiguous = all(right[0] == left[1] for left, right in zip(ranges, ranges[1:]))
    return {
        "nents": len(ranges),
        "total_bytes": total,
        "first_pa": ranges[0][0],
        "end_pa": ranges[-1][1],
        "contiguous": contiguous,
        "ranges": ranges,
    }


def validate_oracle_payload(payload: bytes) -> dict[str, object]:
    """Validate the C oracle JSONL and return private parsed evidence."""

    if not isinstance(payload, bytes) or len(payload) == 0 or len(payload) > MAX_OUTPUT_BYTES:
        raise LiveError("oracle payload is outside bounded size")
    rows = [_parse_json_line(line, f"oracle line {i}") for i, line in enumerate(payload.splitlines()) if line]
    if not rows:
        raise LiveError("oracle payload has no records")
    if any(row.get("type") not in {"context", "format", "event", "summary", "cleanup"} for row in rows):
        raise LiveError("oracle payload contains an unexpected record type")
    row_types = [row.get("type") for row in rows]
    if row_types[0] != "context" or row_types[-2:] != ["summary", "cleanup"]:
        raise LiveError("oracle record framing/order is not exact")
    contexts = [row for row in rows if row.get("type") == "context"]
    formats = [row for row in rows if row.get("type") == "format"]
    events = [row for row in rows if row.get("type") == "event"]
    summaries = [row for row in rows if row.get("type") == "summary"]
    cleanups = [row for row in rows if row.get("type") == "cleanup"]
    if len(contexts) != 1 or len(summaries) != 1 or len(cleanups) != 1:
        raise LiveError("oracle context/summary/cleanup multiplicity differs")
    context = contexts[0]
    expected_context = {
        "schema": PROBE_SCHEMA,
        "type": "context",
        "backend": "perf_event_open",
        "scope": "pid=0,cpu=-1",
        "cpu": EXPECTED_CPU,
        "heap": EXPECTED_HEAP,
        "heap_id": EXPECTED_HEAP_ID,
        "heap_type": EXPECTED_HEAP_TYPE,
        "calibration_heap": EXPECTED_CALIBRATION_HEAP,
        "calibration_heap_id": EXPECTED_CALIBRATION_HEAP_ID,
        "calibration_heap_type": EXPECTED_CALIBRATION_HEAP_TYPE,
        "allocation_bytes": EXPECTED_BYTES,
        "flags": EXPECTED_FLAGS,
    }
    if context != expected_context:
        raise LiveError("oracle context is not exact")
    format_events = [row.get("event") for row in formats]
    if format_events != list(EXPECTED_TRACE_EVENTS):
        raise LiveError("oracle trace format set is not exact")
    format_ids: set[int] = set()
    normalized_formats: list[dict[str, object]] = []
    for row in formats:
        if set(row) != {"schema", "type", "event", "id", "format_path", "format_size", "has_page", "has_size", "has_pfn", "has_count", "has_heap_name", "has_buffer", "format_hex"}:
            raise LiveError("oracle format fields are not exact")
        if row.get("schema") != PROBE_SCHEMA or row.get("type") != "format" or row.get("event") not in EXPECTED_TRACE_EVENTS:
            raise LiveError("oracle format identity differs")
        if type(row.get("id")) is not int or row["id"] <= 0 or row["id"] in format_ids or type(row.get("format_size")) is not int or row["format_size"] <= 0 or row["format_size"] > 1 << 20:
            raise LiveError("oracle format id/size is invalid")
        format_ids.add(row["id"])
        root = "/sys/kernel/tracing"
        if row["event"] == "cma_alloc":
            group = "cma"
        else:
            group = "ion"
        expected_path = f"{root}/events/{group}/{row['event']}/format"
        alternate_path = f"/sys/kernel/debug/tracing/events/{group}/{row['event']}/format"
        if row.get("format_path") not in {expected_path, alternate_path}:
            raise LiveError("oracle trace format path differs")
        expected_presence = {
            "cma_alloc": (True, False, True, True, False, False),
            "ion_rbin_alloc_start": (True, True, False, False, True, True),
            "ion_rbin_alloc_end": (True, True, False, False, True, True),
            "ion_rbin_pool_alloc_end": (True, True, False, False, True, True),
            "ion_rbin_partial_alloc_end": (True, True, False, False, True, True),
        }[row["event"]]
        format_presence_keys = ("has_page", "has_size", "has_pfn", "has_count", "has_heap_name", "has_buffer")
        if any(type(row[key]) is not bool for key in format_presence_keys) or tuple(row[key] for key in format_presence_keys) != expected_presence:
            raise LiveError("oracle trace format field presence differs")
        format_hex = row.get("format_hex")
        if (
            not isinstance(format_hex, str)
            or len(format_hex) == 0
            or len(format_hex) % 2
            or re.fullmatch(r"[0-9a-f]+", format_hex) is None
        ):
            raise LiveError("oracle trace format bytes are not canonical")
        format_bytes = bytes.fromhex(format_hex)
        if len(format_bytes) != row["format_size"]:
            raise LiveError("oracle trace format size/hash differs")
        description = parse_trace_format(format_bytes, row["event"])
        normalized = dict(row)
        normalized["format_sha256"] = sha256(format_bytes)
        normalized["fields"] = description["fields"]
        normalized["raw_size_limit"] = description["raw_size_limit"]
        normalized["raw_size"] = description["raw_size"]
        normalized_formats.append(normalized)
    ion_layout = normalized_formats[1]["fields"]
    if any(row["fields"] != ion_layout for row in normalized_formats[2:]):
        raise LiveError("oracle ion_rbin event layouts are not class-identical")
    event_rows = [_event_row(row, i) for i, row in enumerate(events)]
    format_by_event = {
        row["event"]: {
            "event": row["event"],
            "fields": row["fields"],
            "raw_size": row["raw_size"],
        }
        for row in normalized_formats
    }
    for index, row in enumerate(event_rows):
        description = format_by_event.get(row["event"])
        if not isinstance(description, Mapping):
            raise LiveError(f"oracle event {index} has no retained format")
        raw = bytes.fromhex(str(row["raw_hex"]))
        decoded = parse_perf_raw_record(raw, description, event_name=row["event"])
        fields = description["fields"]
        if not isinstance(fields, Mapping):
            raise LiveError("oracle retained format fields are malformed")
        if "page" in fields and decoded.get("page") != row["page_ptr_value"]:
            raise LiveError(f"oracle event {index} page decode differs")
        if "pfn" in fields and decoded.get("pfn") != row.get("pfn_value"):
            raise LiveError(f"oracle event {index} PFN decode differs")
        if "count" in fields and decoded.get("count") != row.get("count_value"):
            raise LiveError(f"oracle event {index} count decode differs")
        if "heap_name" in fields and decoded.get("heap_name") != row.get("heap_name_value"):
            raise LiveError(f"oracle event {index} heap-name decode differs")
        if "buffer" in fields and decoded.get("buffer") != row.get("buffer_ptr_value"):
            raise LiveError(f"oracle event {index} buffer decode differs")
        if "size" in fields and decoded.get("size_bytes") != row["size_bytes"]:
            raise LiveError(f"oracle event {index} size decode differs")
        if row["event"] == "cma_alloc" and decoded.get("size_bytes") != row["size_bytes"]:
            raise LiveError(f"oracle CMA size decode differs")
    if len(row_types) < 1 + len(EXPECTED_TRACE_EVENTS) + 3 + 2:
        raise LiveError("oracle record sequence is incomplete")
    if row_types[1 : 1 + len(EXPECTED_TRACE_EVENTS)] != ["format"] * len(EXPECTED_TRACE_EVENTS):
        raise LiveError("oracle format records are not contiguous")
    if any(kind != "event" for kind in row_types[1 + len(EXPECTED_TRACE_EVENTS) : -2]):
        raise LiveError("oracle event records are not contiguous")
    calibration = [row for row in event_rows if row["phase"] == "calibration"]
    allocation = [row for row in event_rows if row["phase"] == "allocation"]
    if len(calibration) != 3 or any(row["event"] != "cma_alloc" for row in calibration):
        raise LiveError("oracle CMA calibration event set is not exact")
    phases = [row["phase"] for row in event_rows]
    if phases[: len(calibration)] != ["calibration"] * len(calibration) or any(
        phase != "allocation" for phase in phases[len(calibration) :]
    ):
        raise LiveError("oracle calibration/allocation order differs")
    summary = summaries[0]
    expected_summary_keys = {
        "schema", "type", "status", "allocation_backend", "event_pool_count", "event_partial_count", "event_cma_count", "event_start_count", "event_end_count", "nents", "total_bytes", "first_pa", "end_pa", "contiguous", "exact_region_match", "classification", "affine_slope", "affine_intercept", "struct_page_size_source"
    }
    if set(summary) != expected_summary_keys or summary.get("schema") != PROBE_SCHEMA or summary.get("type") != "summary" or summary.get("status") != "PA_BOUND":
        raise LiveError("oracle summary fields/status differ")
    if summary.get("allocation_backend") != "rbin":
        raise LiveError("oracle allocation backend is not fixed RBIN")
    if type(summary.get("nents")) is not int or summary["nents"] <= 0:
        raise LiveError("oracle segment count is not exact")
    if summary.get("total_bytes") != EXPECTED_BYTES or summary.get("contiguous") is not True:
        raise LiveError("oracle SG total/contiguity is not exact")
    first_pa = _u64(summary.get("first_pa"), "oracle first_pa")
    end_pa = _u64(summary.get("end_pa"), "oracle end_pa")
    if end_pa <= first_pa or end_pa - first_pa != EXPECTED_BYTES:
        raise LiveError("oracle PA range is not one exact allocation")
    if summary.get("exact_region_match") is not (first_pa == EXPECTED_REGION_FIRST and end_pa == EXPECTED_REGION_END):
        raise LiveError("oracle exact region flag differs")
    expected_prefix = (
        "EXACT_CAMERA_PREVIEW_" if summary.get("exact_region_match")
        else "NONEXACT_CAMERA_PREVIEW_"
    )
    expected_classification = (
        f"{expected_prefix}{str(summary['allocation_backend']).upper()}_REGION"
    )
    if summary.get("classification") != expected_classification:
        raise LiveError("oracle result classification is not truthful")
    if type(summary.get("affine_slope")) is not int or summary["affine_slope"] <= 0 or not isinstance(summary.get("affine_intercept"), str):
        raise LiveError("oracle affine summary is malformed")
    _u64(summary["affine_intercept"], "oracle affine intercept")
    if summary.get("struct_page_size_source") not in {
        "same-run-cma-affine",
        "btf:/sys/kernel/btf/vmlinux",
    }:
        raise LiveError("oracle page-size provenance is not source-defined")
    event_counts = {
        "event_pool_count": sum(row["event"] == "ion_rbin_pool_alloc_end" for row in allocation),
        "event_partial_count": sum(row["event"] == "ion_rbin_partial_alloc_end" for row in allocation),
        "event_cma_count": sum(row["event"] == "cma_alloc" for row in allocation),
        "event_start_count": sum(row["event"] == "ion_rbin_alloc_start" for row in allocation),
        "event_end_count": sum(row["event"] == "ion_rbin_alloc_end" for row in allocation),
    }
    if any(summary.get(key) != count for key, count in event_counts.items()):
        raise LiveError("oracle event count projection differs")
    if summary.get("nents") != sum(
        row["event"] in {"ion_rbin_pool_alloc_end", "ion_rbin_partial_alloc_end", "cma_alloc"}
        and row["page_ptr_value"] != 0
        for row in allocation
    ):
        raise LiveError("oracle nents projection differs")
    if event_counts["event_start_count"] != 1 or event_counts["event_end_count"] != 1:
        raise LiveError("oracle outer allocation bracket is not exactly one")
    if len(allocation) < 2 or allocation[0]["event"] != "ion_rbin_alloc_start" or allocation[1]["event"] != "ion_rbin_alloc_end":
        raise LiveError("oracle outer allocation bracket order differs")
    start = next(row for row in allocation if row["event"] == "ion_rbin_alloc_start")
    end = next(row for row in allocation if row["event"] == "ion_rbin_alloc_end")
    if (
        start["size_bytes"] != EXPECTED_BYTES
        or end["size_bytes"] != EXPECTED_BYTES
        or end["page_ptr_value"] != 0
        or start["heap_name_value"] == 0
        or end["heap_name_value"] != start["heap_name_value"]
        or start["buffer_ptr_value"] == 0
        or end["buffer_ptr_value"] != start["buffer_ptr_value"]
    ):
        raise LiveError("oracle outer allocation bracket is not fixed")
    if any(
        row["heap_name_value"] != start["heap_name_value"]
        for row in allocation
        if row["event"] != "ion_rbin_partial_alloc_end"
    ):
        raise LiveError("oracle RBIN heap-name value binding differs")
    calibration_points: list[tuple[int, int]] = []
    expected_calibration_counts = (1, 2, 3)
    for index, row in enumerate(calibration):
        # Private C rows may carry concrete values in addition to these
        # presence markers; tests and alternate backends can supply them here.
        raw = bytes.fromhex(str(row["raw_hex"]))
        pfn = row.get("pfn_value")
        if not isinstance(pfn, int):
            raise LiveError("oracle calibration PFN value is not retained")
        calibration_points.append((row["page_ptr_value"], pfn))
        count = row.get("count_value")
        if count != expected_calibration_counts[index] or row["size_bytes"] != count * 4096:
            raise LiveError("oracle calibration count/size/order differs")
        if sha256(raw) != row["raw_sha256"]:
            raise LiveError("oracle calibration raw hash differs")
    slope, intercept = derive_affine_page_relation(calibration_points)
    if summary["affine_slope"] != slope or _u64(summary["affine_intercept"], "oracle affine intercept") != intercept:
        raise LiveError("oracle affine projection differs from calibration")
    partial_rows = [
        row for row in allocation if row["event"] == "ion_rbin_partial_alloc_end"
    ]
    rbin_segments: list[dict[str, object]] = []
    partial_index = 0
    for allocation_index, row in enumerate(allocation):
        if row["event"] != "ion_rbin_pool_alloc_end":
            continue
        page = row["page_ptr_value"]
        size = row["size_bytes"]
        if page == 0 and size == 0:
            # C emits exactly one successful partial record immediately after
            # each pool miss.  A partial stream with a different shape is not
            # attributable to this allocation and must not be consumed.
            if (
                allocation_index + 1 >= len(allocation)
                or allocation[allocation_index + 1]["event"]
                != "ion_rbin_partial_alloc_end"
                or partial_index >= len(partial_rows)
            ):
                raise LiveError("oracle RBIN pool miss lacks adjacent partial success")
            replacement = partial_rows[partial_index]
            if replacement["page_ptr_value"] == 0 or replacement["size_bytes"] <= 0:
                raise LiveError("oracle RBIN partial replacement is malformed")
            if replacement is not allocation[allocation_index + 1]:
                raise LiveError("oracle RBIN partial stream order differs")
            rbin_segments.append(replacement)
            partial_index += 1
            continue
        if page == 0 or size <= 0:
            raise LiveError("oracle RBIN pool success is malformed")
        rbin_segments.append(row)
    if partial_index != len(partial_rows):
        raise LiveError("oracle RBIN has an unused or excess partial event")
    segments: list[dict[str, object]]
    if event_counts["event_cma_count"] != 0 or not rbin_segments:
        raise LiveError("oracle RBIN event backend is incomplete")
    segments = rbin_segments
    total = 0
    seen_pages: set[int] = set()
    derived_ranges: list[tuple[int, int]] = []
    for row in segments:
        page = row["page_ptr_value"]
        if page in seen_pages or row["size_bytes"] % 4096 or row["size_bytes"] <= 0:
            raise LiveError("oracle segment identity/size is malformed")
        seen_pages.add(page)
        pfn = row.get("pfn_value")
        if not isinstance(pfn, int):
            delta = page - intercept
            if delta < 0 or delta % slope:
                raise LiveError("oracle segment pointer is outside calibrated relation")
            pfn = delta // slope
        if intercept + slope * pfn != page:
            raise LiveError("oracle segment pointer/PFN relation differs")
        pa = pfn * 4096
        if pa > (1 << 64) - row["size_bytes"]:
            raise LiveError("oracle segment PA arithmetic overflow")
        total += row["size_bytes"]
        derived_ranges.append((pa, pa + row["size_bytes"]))
    if total != EXPECTED_BYTES or len(derived_ranges) != int(summary["nents"]):
        raise LiveError("oracle segment union does not equal one allocation")
    derived_ranges.sort()
    if derived_ranges[0][0] != first_pa or derived_ranges[-1][1] != end_pa or any(
        right[0] != left[1] for left, right in zip(derived_ranges, derived_ranges[1:])
    ):
        raise LiveError("oracle segment union is not contiguous")
    cleanup = cleanups[0]
    if set(cleanup) != {"schema", "type", "allocation_returned", "perf_disabled", "allocation_fd_closed", "ion_fd_closed", "calibration_fds_closed", "perf_unmapped", "perf_closed", "status"} or cleanup.get("schema") != PROBE_SCHEMA or cleanup.get("type") != "cleanup" or cleanup.get("status") != "PASS" or any(cleanup.get(key) is not True for key in ("allocation_returned", "perf_disabled", "allocation_fd_closed", "ion_fd_closed", "calibration_fds_closed", "perf_unmapped", "perf_closed")):
        raise LiveError("oracle cleanup proof is incomplete")
    return {
        "context": context,
        "formats": normalized_formats,
        "calibration": calibration,
        "allocation": allocation,
        "summary": summary,
        "cleanup": cleanup,
        "payload_sha256": sha256(payload),
        "payload_size": len(payload),
    }


def public_projection(
    parsed: Mapping[str, object],
    *,
    completed_utc: str,
    target: Mapping[str, object],
    binary: Mapping[str, object],
    artifact_descriptors: Mapping[str, Mapping[str, object]],
    boot_prefix_sha256: str,
    boot_id_sha256: str,
    final_health_ok: bool,
) -> dict[str, object]:
    if not isinstance(target, Mapping) or any(
        key not in target
        for key in ("model", "soc", "runtime_version", "runtime_build")
    ):
        raise LiveError("V030 public target binding is incomplete")
    if not isinstance(binary, Mapping) or set(binary) != {"basename", "size_bytes", "sha256"}:
        raise LiveError("V030 public binary binding is incomplete")
    if not isinstance(binary.get("basename"), str) or binary.get("basename") != BINARY_BASENAME:
        raise LiveError("V030 public binary basename differs")
    if type(binary.get("size_bytes")) is not int or binary["size_bytes"] <= 0:
        raise LiveError("V030 public binary size differs")
    _hash(binary.get("sha256"), "V030 public binary hash")
    summary = parsed["summary"]
    if not isinstance(summary, Mapping):
        raise LiveError("oracle summary is missing")
    format_provenance = [
        {
            "event": row["event"],
            "id": row["id"],
            "format_size": row["format_size"],
        }
        for row in parsed["formats"]
    ]
    expected_private_names = {
        "receipt": PRIVATE_RECEIPT_NAME,
        "raw_output": RAW_OUTPUT_NAME,
        "transcript": TRANSCRIPT_NAME,
        "journal": JOURNAL_NAME,
        "build_receipt": BUILD_RECEIPT_NAME,
    }
    if not isinstance(artifact_descriptors, Mapping) or set(artifact_descriptors) != set(expected_private_names):
        raise LiveError("V030 public artifact descriptors are incomplete")
    public_artifacts: dict[str, dict[str, object]] = {}
    for key, filename in expected_private_names.items():
        descriptor = artifact_descriptors.get(key)
        if not isinstance(descriptor, Mapping) or set(descriptor) != {"filename", "sha256", "size_bytes"}:
            raise LiveError(f"V030 public {key} descriptor differs")
        if descriptor.get("filename") != filename:
            raise LiveError(f"V030 public {key} filename differs")
        _hash(descriptor.get("sha256"), f"V030 public {key} hash")
        if type(descriptor.get("size_bytes")) is not int or descriptor["size_bytes"] <= 0:
            raise LiveError(f"V030 public {key} size differs")
        public_artifacts[key] = dict(descriptor)
    if _hash(boot_prefix_sha256, "V030 public boot prefix") != BOOT_PREFIX_SHA256:
        raise LiveError("V030 public boot prefix binding differs")
    _hash(boot_id_sha256, "V030 public boot identity")
    if boot_id_sha256 == sha256(b""):
        raise LiveError("V030 public boot identity cannot be empty-hash placeholder")
    if final_health_ok is not True:
        raise LiveError("V030 public final health gate differs")
    return {
        "schema": PUBLIC_SCHEMA,
        "status": "PREPARED_NOT_AUTHORITY",
        "closure_state": "CLOSURE_PREPARED",
        "experiment_id": EXPERIMENT_ID,
        "completed_utc": completed_utc,
        "target": {
            "model": target["model"],
            "soc": target["soc"],
            "runtime_version": target["runtime_version"],
            "runtime_build": target["runtime_build"],
        },
        "trace_backend": "perf_event_open",
        "trace_access": "pid=0,cpu=-1",
        "trace_events": format_provenance,
        "heap": EXPECTED_HEAP,
        "heap_id": EXPECTED_HEAP_ID,
        "heap_type": EXPECTED_HEAP_TYPE,
        "allocation_size_bytes": EXPECTED_BYTES,
        "allocation_flags": EXPECTED_FLAGS,
        "event_counts": {
            "pool": summary["event_pool_count"],
            "partial": summary["event_partial_count"],
            "cma": summary["event_cma_count"],
            "alloc_start": summary["event_start_count"],
            "alloc_end": summary["event_end_count"],
        },
        "nents": summary["nents"],
        "total_bytes": summary["total_bytes"],
        "first_pa": summary["first_pa"],
        "end_pa": summary["end_pa"],
        "contiguous": summary["contiguous"],
        "exact_region_match": summary["exact_region_match"],
        "result_classification": summary["classification"],
        "allocation_backend": summary["allocation_backend"],
        "source_binary": {"basename": binary["basename"], "size_bytes": binary["size_bytes"], "sha256": binary["sha256"]},
        "effect_profile": dict(EFFECT_PROFILE),
        "device_contact": True,
        "boot_prefix_sha256": boot_prefix_sha256,
        "boot_id_sha256": boot_id_sha256,
        "final_health_ok": final_health_ok,
        "private_record": {
            "receipt": public_artifacts["receipt"],
            "raw_output": public_artifacts["raw_output"],
            "transcript": public_artifacts["transcript"],
            "journal": public_artifacts["journal"],
            "build_receipt": public_artifacts["build_receipt"],
        },
    }


def validate_public_projection(
    value: Mapping[str, object], *,
    target: Mapping[str, object] | None = None,
    binary: Mapping[str, object] | None = None,
) -> None:
    """Validate the closed redacted manifest contract independently."""

    expected_keys = {
        "schema", "status", "closure_state", "experiment_id", "completed_utc", "target", "trace_backend",
        "trace_access", "trace_events", "heap", "heap_id", "heap_type",
        "allocation_size_bytes", "allocation_flags", "event_counts", "nents",
        "total_bytes", "first_pa", "end_pa", "contiguous", "exact_region_match",
        "result_classification", "allocation_backend", "source_binary",
        "effect_profile", "device_contact", "boot_prefix_sha256", "boot_id_sha256",
        "final_health_ok", "private_record",
    }
    if (
        set(value) != expected_keys
        or value.get("schema") != PUBLIC_SCHEMA
        or value.get("status") != "PREPARED_NOT_AUTHORITY"
        or value.get("closure_state") != "CLOSURE_PREPARED"
        or value.get("experiment_id") != EXPERIMENT_ID
    ):
        raise LiveError("V030 public manifest fields/schema differ")
    if value.get("trace_backend") != "perf_event_open" or value.get("trace_access") != "pid=0,cpu=-1":
        raise LiveError("V030 public trace access differs")
    if value.get("heap") != EXPECTED_HEAP or value.get("heap_id") != EXPECTED_HEAP_ID or value.get("heap_type") != EXPECTED_HEAP_TYPE or value.get("allocation_size_bytes") != EXPECTED_BYTES or value.get("allocation_flags") != EXPECTED_FLAGS:
        raise LiveError("V030 public allocation identity differs")
    if value.get("device_contact") is not True:
        raise LiveError("V030 public safety fields differ")
    effect_profile = value.get("effect_profile")
    if not isinstance(effect_profile, Mapping) or dict(effect_profile) != EFFECT_PROFILE:
        raise LiveError("V030 effect profile differs")
    if _hash(value.get("boot_prefix_sha256"), "V030 public boot prefix") != BOOT_PREFIX_SHA256:
        raise LiveError("V030 public boot prefix binding differs")
    boot_id_hash = _hash(value.get("boot_id_sha256"), "V030 public boot identity")
    if boot_id_hash == sha256(b""):
        raise LiveError("V030 public boot identity cannot be empty-hash placeholder")
    if value.get("final_health_ok") is not True:
        raise LiveError("V030 public final health gate differs")
    public_target = value.get("target")
    expected_target = target or EXPECTED_TARGET
    if not isinstance(public_target, Mapping) or set(public_target) != {"model", "soc", "runtime_version", "runtime_build"} or any(public_target.get(key) != expected_target.get(key) for key in ("model", "soc", "runtime_version", "runtime_build")):
        raise LiveError("V030 public target differs")
    source_binary = value.get("source_binary")
    if (
        not isinstance(source_binary, Mapping)
        or set(source_binary) != {"basename", "size_bytes", "sha256"}
        or source_binary.get("basename") != BINARY_BASENAME
        or type(source_binary.get("size_bytes")) is not int
        or source_binary["size_bytes"] <= 0
    ):
        raise LiveError("V030 public binary binding differs")
    _hash(source_binary.get("sha256"), "V030 public binary hash")
    expected_binary = {
        "basename": BINARY_BASENAME,
        "size_bytes": EXPECTED_BINARY_SIZE,
        "sha256": EXPECTED_BINARY_SHA256,
    }
    if binary is not None:
        expected_binary = {
            "basename": binary.get("basename"),
            "size_bytes": binary.get("size_bytes"),
            "sha256": binary.get("sha256"),
        }
    if dict(source_binary) != expected_binary:
        raise LiveError("V030 public binary binding differs")
    events = value.get("trace_events")
    if not isinstance(events, list) or len(events) != len(EXPECTED_TRACE_EVENTS):
        raise LiveError("V030 public trace event provenance differs")
    if {item.get("event") for item in events if isinstance(item, Mapping)} != set(EXPECTED_TRACE_EVENTS) or any(not isinstance(item, Mapping) or set(item) != {"event", "id", "format_size"} for item in events):
        raise LiveError("V030 public trace event fields differ")
    counts = value.get("event_counts")
    if not isinstance(counts, Mapping) or set(counts) != {"pool", "partial", "cma", "alloc_start", "alloc_end"}:
        raise LiveError("V030 public event counts differ")
    if any(type(counts[key]) is not int or counts[key] < 0 for key in counts):
        raise LiveError("V030 public event count types differ")
    if value.get("total_bytes") != EXPECTED_BYTES or value.get("contiguous") is not True or type(value.get("nents")) is not int or value["nents"] <= 0:
        raise LiveError("V030 public SG summary differs")
    first = _u64(value.get("first_pa"), "V030 public first_pa")
    end = _u64(value.get("end_pa"), "V030 public end_pa")
    if end <= first or end - first != EXPECTED_BYTES or value.get("exact_region_match") is not (first == EXPECTED_REGION_FIRST and end == EXPECTED_REGION_END):
        raise LiveError("V030 public PA summary differs")
    expected_prefix = "EXACT_CAMERA_PREVIEW_" if value.get("exact_region_match") else "NONEXACT_CAMERA_PREVIEW_"
    if value.get("allocation_backend") != "rbin":
        raise LiveError("V030 public allocation backend differs")
    expected_classification = f"{expected_prefix}{str(value.get('allocation_backend')).upper()}_REGION"
    if value.get("result_classification") != expected_classification:
        raise LiveError("V030 public classification differs")
    private_record = value.get("private_record")
    expected_private_names = {
        "receipt": PRIVATE_RECEIPT_NAME,
        "raw_output": RAW_OUTPUT_NAME,
        "transcript": TRANSCRIPT_NAME,
        "journal": JOURNAL_NAME,
        "build_receipt": BUILD_RECEIPT_NAME,
    }
    if not isinstance(private_record, Mapping) or set(private_record) != set(expected_private_names):
        raise LiveError("V030 public private binding differs")
    for key, filename in expected_private_names.items():
        descriptor = private_record.get(key)
        if not isinstance(descriptor, Mapping) or set(descriptor) != {"filename", "sha256", "size_bytes"}:
            raise LiveError(f"V030 public {key} descriptor differs")
        if descriptor.get("filename") != filename:
            raise LiveError(f"V030 public {key} filename differs")
        _hash(descriptor.get("sha256"), f"V030 public {key} hash")
        if type(descriptor.get("size_bytes")) is not int or descriptor["size_bytes"] <= 0:
            raise LiveError(f"V030 public {key} size differs")
    forbidden = ("page_ptr", "raw_hex", "transcript_base64", "payload_base64", "serial", "cmdline")
    def walk(item: object) -> None:
        if isinstance(item, Mapping):
            if any(key in item for key in forbidden):
                raise LiveError("V030 public projection leaks private evidence")
            for nested in item.values():
                walk(nested)
        elif isinstance(item, list):
            for nested in item:
                walk(nested)
    walk(value)


def _parse_json_document(data: bytes, label: str) -> dict[str, object]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_OUTPUT_BYTES:
        raise LiveError(f"{label} is outside bounded size")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except LiveError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise LiveError(f"{label} is not an object")
    return value


def _validate_artifact_descriptor(
    data: bytes, descriptor: Mapping[str, object], label: str, filename: str
) -> None:
    if set(descriptor) != {"filename", "sha256", "size_bytes"}:
        raise LiveError(f"{label} descriptor fields differ")
    if descriptor.get("filename") != filename:
        raise LiveError(f"{label} descriptor filename differs")
    _hash(descriptor.get("sha256"), f"{label} descriptor hash")
    if type(descriptor.get("size_bytes")) is not int or descriptor["size_bytes"] <= 0:
        raise LiveError(f"{label} descriptor size differs")
    if descriptor["size_bytes"] != len(data) or descriptor["sha256"] != sha256(data):
        raise LiveError(f"{label} descriptor does not bind bytes")


def validate_completed_run(
    journal_data: bytes,
    private_receipt_data: bytes,
    public_manifest_data: bytes,
    artifacts: Mapping[str, bytes],
) -> None:
    """Require exactly one terminal PASS line to close prepared evidence."""

    if not isinstance(artifacts, Mapping):
        raise LiveError("V030 completed-run artifacts are not a mapping")
    if not journal_data.endswith(b"\n"):
        raise LiveError("V030 journal lacks a final line terminator")
    records: list[dict[str, object]] = []
    line_starts: list[int] = []
    line_offset = 0
    for index, line in enumerate(journal_data.splitlines(keepends=True)):
        if not line.endswith(b"\n") or line[:-1].endswith(b"\r") or not line[:-1]:
            raise LiveError("V030 journal is not exactly one JSON object per line")
        line_starts.append(line_offset)
        line_offset += len(line)
        records.append(_parse_json_line(line[:-1], f"V030 journal line {index}"))
    if not records or records[-1].get("state") != "PASS" or records[-1].get("terminal") is not True:
        raise LiveError("V030 journal lacks a terminal PASS authority")
    if any(
        record.get("schema") != PRIVATE_SCHEMA
        or record.get("experiment_id") != EXPERIMENT_ID
        or not isinstance(record.get("state"), str)
        or not isinstance(record.get("effect_profile"), Mapping)
        or dict(record["effect_profile"]) != EFFECT_PROFILE
        for record in records
    ):
        raise LiveError("V030 journal lifecycle binding differs")
    if any(record.get("terminal") is True for record in records[:-1]):
        raise LiveError("V030 journal contains an earlier terminal authority")
    terminal = records[-1]
    terminal_line_start = line_starts[-1]
    prefix = terminal.get("journal_prefix")
    if not isinstance(prefix, Mapping):
        raise LiveError("V030 terminal journal prefix is missing")
    prefix_size = prefix.get("size_bytes")
    if (
        type(prefix_size) is not int
        or prefix_size <= 0
        or prefix_size != terminal_line_start
        or prefix_size >= len(journal_data)
    ):
        raise LiveError("V030 journal prefix size differs")
    prefix_bytes = journal_data[:prefix_size]
    _validate_artifact_descriptor(prefix_bytes, prefix, "V030 journal prefix", JOURNAL_NAME)
    terminal_bytes = journal_data[terminal_line_start:]
    if (
        journal_data[prefix_size:] != terminal_bytes
        or terminal_bytes != _journal_bytes(terminal)
    ):
        raise LiveError("V030 journal has bytes outside the terminal suffix")
    prefix_records: list[dict[str, object]] = []
    for index, line in enumerate(prefix_bytes.splitlines(keepends=True)):
        if not line.endswith(b"\n") or line[:-1].endswith(b"\r") or not line[:-1]:
            raise LiveError("V030 journal prefix is not line-bounded")
        prefix_records.append(_parse_json_line(line[:-1], f"V030 journal prefix line {index}"))
    if b"".join(_journal_bytes(record) for record in prefix_records) != prefix_bytes:
        raise LiveError("V030 journal prefix is not canonical JSONL")
    if not prefix_records or prefix_records[-1].get("state") != "FINAL_HEALTH":
        raise LiveError("V030 journal prefix does not end at final health")
    if any(record.get("terminal") is True for record in prefix_records):
        raise LiveError("V030 journal prefix contains terminal authority")
    expected_terminal_keys = {
        "schema", "experiment_id", "state", "utc", "effect_profile", "terminal",
        "completed_utc", "target", "boot_id_sha256", "source", "binary",
        "journal_prefix", "artifact_descriptors", "remote_binary", "cleanup",
        "final_health", "device_contact", "panic_restore", "sysctl_restore", "rollback",
    }
    if set(terminal) != expected_terminal_keys:
        raise LiveError("V030 terminal PASS fields differ")
    if (
        terminal.get("schema") != PRIVATE_SCHEMA
        or terminal.get("experiment_id") != EXPERIMENT_ID
        or terminal.get("state") != "PASS"
        or terminal.get("terminal") is not True
        or terminal.get("device_contact") is not True
        or terminal.get("panic_restore") != "NOT_APPLICABLE"
        or terminal.get("sysctl_restore") != "NOT_APPLICABLE"
        or terminal.get("rollback") != "NOT_APPLICABLE"
    ):
        raise LiveError("V030 terminal PASS identity/safety differs")
    terminal_target = terminal.get("target")
    if not isinstance(terminal_target, Mapping) or dict(terminal_target) != EXPECTED_TARGET:
        raise LiveError("V030 terminal target binding differs")
    terminal_boot_hash = _hash(terminal.get("boot_id_sha256"), "V030 terminal boot identity")
    private = _parse_json_document(private_receipt_data, "V030 private receipt")
    public = _parse_json_document(public_manifest_data, "V030 public manifest")
    if (
        private.get("schema") != PRIVATE_SCHEMA
        or private.get("experiment_id") != EXPERIMENT_ID
        or private.get("status") != "PREPARED_NOT_AUTHORITY"
        or private.get("closure_state") != "CLOSURE_PREPARED"
    ):
        raise LiveError("V030 private receipt identity/authority differs")
    if public.get("status") != "PREPARED_NOT_AUTHORITY" or public.get("closure_state") != "CLOSURE_PREPARED":
        raise LiveError("V030 public manifest incorrectly claims authority")
    validate_public_projection(public, target=EXPECTED_TARGET)
    private_binary = private.get("binary")
    public_binary = public.get("source_binary")
    if (
        not isinstance(private_binary, Mapping)
        or set(private_binary) != {"basename", "size_bytes", "sha256"}
        or public_binary != dict(private_binary)
        or private_binary.get("basename") != BINARY_BASENAME
        or private_binary.get("size_bytes") != EXPECTED_BINARY_SIZE
        or private_binary.get("sha256") != EXPECTED_BINARY_SHA256
    ):
        raise LiveError("V030 prepared binary projection differs")
    if private.get("journal") != dict(prefix) or private.get("journal_prefix") != dict(prefix):
        raise LiveError("V030 prepared receipt journal prefix differs")
    private_target = private.get("target")
    public_target = public.get("target")
    public_target_expected = {
        "model": EXPECTED_TARGET["model"],
        "soc": EXPECTED_TARGET["soc"],
        "runtime_version": EXPECTED_TARGET["runtime_version"],
        "runtime_build": EXPECTED_TARGET["runtime_build"],
    }
    if not isinstance(private_target, Mapping) or dict(private_target) != EXPECTED_TARGET or public_target != public_target_expected:
        raise LiveError("V030 prepared target binding differs")
    boot_id_before = private.get("boot_id_before")
    if (
        not isinstance(boot_id_before, str)
        or BOOT_ID_RE.fullmatch(boot_id_before) is None
        or private.get("boot_id_attestation_after") != boot_id_before
        or private.get("boot_id_after") != boot_id_before
        or terminal_boot_hash != sha256(boot_id_before.encode("ascii"))
        or public.get("boot_id_sha256") != terminal_boot_hash
    ):
        raise LiveError("V030 terminal boot identity differs")
    private_source = private.get("source")
    if (
        not isinstance(private_source, Mapping)
        or set(private_source) != {"basename", "size_bytes", "sha256"}
        or private_source.get("basename") != SOURCE_BASENAME
        or private_source.get("size_bytes") != EXPECTED_SOURCE_SIZE
        or private_source.get("sha256") != EXPECTED_SOURCE_SHA256
        or terminal.get("source") != private_source
        or terminal.get("binary") != private_binary
    ):
        raise LiveError("V030 terminal source/binary binding differs")
    remote_binary = terminal.get("remote_binary")
    if (
        not isinstance(remote_binary, Mapping)
        or remote_binary != private.get("remote_binary")
        or remote_binary.get("path") != REMOTE_BINARY
        or remote_binary.get("before_sha256") != EXPECTED_BINARY_SHA256
        or remote_binary.get("after_sha256") != EXPECTED_BINARY_SHA256
        or remote_binary.get("unchanged") is not True
    ):
        raise LiveError("V030 terminal remote binary binding differs")
    cleanup = terminal.get("cleanup")
    if (
        not isinstance(cleanup, Mapping)
        or cleanup != private.get("cleanup")
        or cleanup.get("ok") is not True
        or cleanup.get("absence_proved") is not True
        or cleanup.get("errors") != []
    ):
        raise LiveError("V030 terminal cleanup proof differs")
    final_health = terminal.get("final_health")
    if (
        not isinstance(final_health, Mapping)
        or final_health != private.get("final_health")
        or final_health.get("attempted") is not True
        or final_health.get("ok") is not True
        or final_health.get("target") != EXPECTED_TARGET
        or final_health.get("boot_id_sha256") != terminal_boot_hash
    ):
        raise LiveError("V030 terminal final-health proof differs")
    terminal_artifacts = terminal.get("artifact_descriptors")
    if not isinstance(terminal_artifacts, Mapping):
        raise LiveError("V030 terminal artifact descriptors are missing")
    expected_names = {
        "receipt": PRIVATE_RECEIPT_NAME,
        "raw_output": RAW_OUTPUT_NAME,
        "transcript": TRANSCRIPT_NAME,
        "journal": JOURNAL_NAME,
        "build_receipt": BUILD_RECEIPT_NAME,
        "public_manifest": PUBLIC_MANIFEST_NAME,
    }
    if set(terminal_artifacts) != set(expected_names):
        raise LiveError("V030 terminal artifact descriptor set differs")
    data_by_key: dict[str, bytes] = {
        "receipt": private_receipt_data,
        "transcript": artifacts.get("transcript", b""),
        "raw_output": artifacts.get("raw_output", b""),
        "build_receipt": artifacts.get("build_receipt", b""),
        "journal": prefix_bytes,
        "public_manifest": public_manifest_data,
    }
    for key, filename in expected_names.items():
        descriptor = terminal_artifacts.get(key)
        if not isinstance(descriptor, Mapping):
            raise LiveError(f"V030 terminal {key} descriptor is malformed")
        _validate_artifact_descriptor(data_by_key[key], descriptor, f"V030 terminal {key}", filename)
    build_document = _parse_json_document(
        data_by_key["build_receipt"], "V030 build receipt"
    )
    if (
        build_document.get("source") != private_source
        or build_document.get("binary") != private_binary
        or build_document.get("binary_reproducible") is not True
        or build_document.get("static") is not True
        or not isinstance(build_document.get("compiler_identity"), Mapping)
        or not isinstance(build_document.get("static_elf"), Mapping)
        or build_document["static_elf"].get("pt_interp") is not False
    ):
        raise LiveError("V030 build receipt provenance differs")
    private_descriptors = {
        "receipt": {"filename": PRIVATE_RECEIPT_NAME, "sha256": sha256(private_receipt_data), "size_bytes": len(private_receipt_data)},
        "raw_output": private.get("raw_output"),
        "transcript": private.get("transcript"),
        "journal": private.get("journal"),
        "build_receipt": private.get("build_receipt_file"),
    }
    for key in ("receipt", "raw_output", "transcript", "journal", "build_receipt"):
        if private_descriptors[key] != terminal_artifacts.get(key):
            raise LiveError(f"V030 private/terminal {key} descriptor differs")
    private_record = public.get("private_record")
    if not isinstance(private_record, Mapping):
        raise LiveError("V030 public private binding is missing")
    for key in ("receipt", "raw_output", "transcript", "journal", "build_receipt"):
        if private_record.get(key) != terminal_artifacts.get(key):
            raise LiveError(f"V030 public/terminal {key} descriptor differs")


def _validate_args(args: argparse.Namespace) -> None:
    if getattr(args, "execute", False) is not True:
        raise LiveError("V030 requires explicit --execute")
    if getattr(args, "experiment_id", EXPERIMENT_ID) != EXPERIMENT_ID:
        raise LiveError("V030 experiment ID is fixed")
    if hasattr(args, "root") and args.root is not None and Path(args.root).resolve() != REPO_ROOT.resolve():
        raise LiveError("V030 evidence root is fixed")


def preflight(*, root: Path | None = None) -> dict[str, object]:
    """Compile and inspect the fixed oracle without contacting the device."""

    base = REPO_ROOT if root is None else Path(root)
    source_path = (base / "tools" / SOURCE_BASENAME).resolve()
    source = _read_stable(source_path, "V030 oracle source")
    source_descriptor = _pinned_source_descriptor(source_path, source)
    compiler_token = os.environ.get("AARCH64_CC", "aarch64-linux-gnu-gcc")
    compiler_identity = _compiler_descriptor(compiler_token)
    compiler_path = compiler_identity.get("path")
    if not isinstance(compiler_path, str) or not Path(compiler_path).is_absolute():
        raise LiveError("V030 compiler identity lacks an absolute path")
    command = [compiler_path, "-O2", "-static", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", str(source_path)]
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LiveError("V030 oracle compiler is unavailable") from exc
    if completed.returncode != 0:
        raise LiveError(f"V030 oracle syntax check failed: {completed.stderr.decode('utf-8', 'replace')}")
    return {
        "schema": "a90-rbin-phys-oracle-preflight-v1",
        "experiment_id": EXPERIMENT_ID,
        "source": source_descriptor,
        "compiler": command,
        "compiler_identity": compiler_identity,
        "device_contact": False,
    }


def _require_remote_absent(session: object, evidence_id: str, path: str) -> None:
    """Require absence and non-symlink status without deleting anything."""

    for suffix, predicate in (("not_exists", "-e"), ("not_link", "-L")):
        check_id = f"{evidence_id}_{suffix}"
        frame = session.invoke(
            check_id,
            ("run", TOYBOX, "test", "!", predicate, path),
            allow_error=True,
        )
        transport.require_frame_ok(frame, check_id)
        try:
            transport.require_child_exit_zero(frame.payload, check_id)
        except BaseException as exc:
            raise LiveError(f"V030 remote path already exists or is linked: {path}") from exc


def _upload_binary(
    session: object, binary: bytes, created_paths: set[str] | None = None
) -> dict[str, object]:
    if created_paths is None:
        created_paths = set()
    header = f"begin-base64 700 {BINARY_BASENAME}\n"
    encoded = base64.b64encode(binary).decode("ascii")
    chunks = [encoded[offset : offset + transport.MAX_LEGACY_CHUNK] for offset in range(0, len(encoded), transport.MAX_LEGACY_CHUNK)]
    # Establish ownership before dispatching the create operation.  A lost
    # response after the remote open is still eligible for cleanup, while the
    # preceding absence checks prove this path belonged to this run.
    created_paths.add(REMOTE_ENVELOPE)
    frame = session.invoke("envelope_header", ("appendfile", REMOTE_ENVELOPE, header), extended=True, allow_error=True)
    transport.require_frame_ok(frame, "V030 envelope header")
    for index, chunk in enumerate(chunks):
        frame = session.invoke(f"payload_{index:04d}", ("appendfile", REMOTE_ENVELOPE, chunk), allow_error=True)
        transport.require_frame_ok(frame, "V030 envelope payload")
    frame = session.invoke("envelope_footer", ("appendfile", REMOTE_ENVELOPE, "\n====\n"), extended=True, allow_error=True)
    transport.require_frame_ok(frame, "V030 envelope footer")
    created_paths.add(REMOTE_BINARY)
    frame = session.invoke("decode", ("run", TOYBOX, "uudecode", "-o", REMOTE_BINARY, REMOTE_ENVELOPE), allow_error=True)
    transport.require_frame_ok(frame, "V030 decode")
    transport.require_child_exit_zero(frame.payload, "V030 decode")
    frame = session.invoke("chmod_binary", ("run", TOYBOX, "chmod", "700", REMOTE_BINARY), allow_error=True)
    transport.require_frame_ok(frame, "V030 chmod")
    transport.require_child_exit_zero(frame.payload, "V030 chmod")
    return {"chunk_count": len(chunks), "sha256": sha256(binary), "size_bytes": len(binary)}


def _parse_remote_hash_v030(payload: bytes, label: str) -> str:
    """Parse exactly one V030 remote hash line bound to the fixed binary."""

    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise LiveError(f"{label} payload is outside the bounded hash contract")
    transport.require_child_exit_zero(payload, label)
    lines = payload.replace(b"\r\n", b"\n").splitlines()
    if not lines:
        raise LiveError(f"{label} output is empty")
    if re.fullmatch(rb"run: pid=[0-9]+, q/Ctrl-C cancels", lines[0]):
        if len(lines) != 3 or re.fullmatch(rb"\[exit 0\]", lines[-1]) is None:
            raise LiveError(f"{label} framing is not exact")
        lines = lines[1:-1]
    elif len(lines) != 1:
        raise LiveError(f"{label} output contains unexpected framing")
    path_pattern = re.escape(REMOTE_BINARY).encode("ascii")
    match = re.fullmatch(rb"([0-9a-f]{64})  " + path_pattern, lines[0])
    if match is None:
        raise LiveError(f"{label} output is malformed or names an unexpected path")
    return match.group(1).decode("ascii")


def _remote_hash(session: object, evidence_id: str) -> str:
    frame = session.invoke(evidence_id, ("run", TOYBOX, "sha256sum", REMOTE_BINARY), allow_error=True)
    transport.require_frame_ok(frame, evidence_id)
    return _parse_remote_hash_v030(frame.payload, evidence_id)


def run(args: argparse.Namespace) -> Path:
    """Perform one fixed V030 allocation and publish private/public evidence."""

    _validate_args(args)
    base = REPO_ROOT
    started = utc_now()
    output_root = transport.ensure_private_output(
        base / "evidence" / "private" / OUTPUT_DIR_NAME
    )
    journal_path = output_root / JOURNAL_NAME
    # The first lifecycle byte is exclusive and durable.  It is written before
    # source/build, bridge validation, target reads, or any remote command.
    _write_exclusive(
        journal_path,
        _journal_bytes(
            {
                "schema": PRIVATE_SCHEMA,
                "experiment_id": EXPERIMENT_ID,
                "state": "OWNERSHIP_CLAIM",
                "utc": started,
                "started_utc": started,
                "device_contact": False,
                "effect_profile": dict(EFFECT_PROFILE),
                "panic_restore": "NOT_APPLICABLE",
                "sysctl_restore": "NOT_APPLICABLE",
                "rollback": "NOT_APPLICABLE",
            }
        ),
        0o600,
    )
    _fsync_directory(output_root)

    def journal(state: str, **fields: object) -> None:
        record: dict[str, object] = {
            "schema": PRIVATE_SCHEMA,
            "experiment_id": EXPERIMENT_ID,
            "state": state,
            "utc": utc_now(),
            "effect_profile": dict(EFFECT_PROFILE),
        }
        record.update(fields)
        _append_journal(journal_path, record)

    source_path = base / "tools" / SOURCE_BASENAME
    compiler_token = os.environ.get("AARCH64_CC", "aarch64-linux-gnu-gcc")
    compiler_identity: dict[str, object] | None = None
    command: list[str] = []
    build_outputs: list[bytes] = []
    elf_descriptor: dict[str, object] | None = None
    try:
        source = _read_stable(source_path, "V030 oracle source")
        _pinned_source_descriptor(source_path, source)
        compiler_identity = _compiler_descriptor(compiler_token)
        compiler_path = compiler_identity.get("path")
        if not isinstance(compiler_path, str) or not Path(compiler_path).is_absolute():
            raise LiveError("V030 compiler identity lacks an absolute path")
        with tempfile.TemporaryDirectory(prefix="v030-build-") as temporary:
            immutable_source_path = Path(temporary) / SOURCE_BASENAME
            _write_exclusive(immutable_source_path, source, 0o600)
            _fsync_directory(Path(temporary))
            for build_index in (1, 2):
                binary_path = Path(temporary) / f"{BINARY_BASENAME}.{build_index}"
                command = [
                    compiler_path,
                    "-O2",
                    "-static",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-o",
                    str(binary_path),
                    str(immutable_source_path),
                ]
                try:
                    built = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=180,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise LiveError("V030 oracle build failed") from exc
                if built.returncode != 0:
                    raise LiveError(
                        "V030 oracle build failed: "
                        + built.stderr.decode("utf-8", "replace")
                    )
                built_bytes = _read_stable(binary_path, "V030 oracle binary")
                if not built_bytes or len(built_bytes) > MAX_PAYLOAD_BYTES:
                    raise LiveError("V030 oracle binary is outside the bounded contract")
                build_outputs.append(built_bytes)
                elf_descriptor = _validate_static_aarch64_elf(built_bytes)
            if len(build_outputs) != 2 or build_outputs[0] != build_outputs[1]:
                raise LiveError("V030 deterministic builds differ")
            binary = build_outputs[0]
        if (
            len(binary) != EXPECTED_BINARY_SIZE
            or sha256(binary) != EXPECTED_BINARY_SHA256
        ):
            raise LiveError("V030 deterministic binary does not match the reviewed pin")
        # Re-read the reviewed path before creating the bridge session.  A
        # source replacement after the initial pin must never be allowed to
        # reach a later device contact/effect, even if the compiler succeeded.
        source_after_build = _read_stable(source_path, "V030 oracle source")
        if source_after_build != source:
            raise LiveError("V030 oracle source changed after pin/build")
        _pinned_source_descriptor(source_path, source_after_build)
        if compiler_identity is None or elf_descriptor is None:
            raise LiveError("V030 build provenance is incomplete")
    except BaseException as exc:
        journal(
            "INCIDENT",
            terminal=True,
            device_contact=False,
            effect_profile=dict(EFFECT_PROFILE),
            error=f"{type(exc).__name__}: {exc}",
        )
        raise

    source_descriptor = _pinned_source_descriptor(source_path, source)
    binary_descriptor = {
        "basename": BINARY_BASENAME,
        "size_bytes": len(binary),
        "sha256": sha256(binary),
    }
    raw_path = output_root / RAW_OUTPUT_NAME
    transcript_path = output_root / TRANSCRIPT_NAME
    receipt_path = output_root / PRIVATE_RECEIPT_NAME
    build_receipt_path = output_root / BUILD_RECEIPT_NAME
    session = transport._Session(transport.BRIDGE_HOST, transport.BRIDGE_PORT, 30.0)
    target: dict[str, object] | None = None
    parsed: dict[str, object] | None = None
    bridge_binding: Mapping[str, object] | None = None
    boot_record: dict[str, object] | None = None
    boot_frames: list[dict[str, object]] = []
    boot_id_before: str | None = None
    boot_id_attestation_after: str | None = None
    boot_id_after: str | None = None
    final_health: dict[str, object] = {"attempted": False, "ok": False, "errors": []}
    cleanup: dict[str, object] = {
        "attempted": False,
        "node_removed": False,
        "files_removed": False,
        "absence_node": False,
        "absence_envelope": False,
        "absence_binary": False,
        "absence_proved": False,
        "errors": [],
    }
    payload: bytes | None = None
    probe_frame: object | None = None
    partial_transcript: bytes | None = None
    remote_before: str | None = None
    remote_after: str | None = None
    cancel_result: dict[str, object] | None = None
    probe_returned = False
    dispatched = False
    channel_ready = bool(getattr(session, "prompt_ready", False))
    remote_cleanup_needed = False
    created_paths: set[str] = set()
    primary_error: BaseException | None = None
    incident_recorded = False
    terminal_recorded = False

    def transcript_snapshot(fallback: object | None = None) -> bytes:
        parts = getattr(session, "transcript_parts", ())
        if isinstance(parts, (list, tuple)):
            data = b"".join(item for item in parts if isinstance(item, bytes))
        else:
            data = b""
        if not data and isinstance(fallback, bytes):
            data = fallback
        elif not data and fallback is not None:
            candidate = getattr(fallback, "transcript", None)
            if isinstance(candidate, bytes):
                data = candidate
        if len(data) > MAX_TRANSCRIPT_BYTES:
            raise LiveError("V030 transcript exceeds bounded size")
        return data

    def persist_sidecars(
        fallback: object | None = None, *, include_transcript: bool = False
    ) -> None:
        if payload is not None:
            if len(payload) > MAX_PAYLOAD_BYTES:
                raise LiveError("V030 oracle payload exceeds bounded size")
            _write_or_verify(raw_path, payload, 0o600)
        if include_transcript:
            transcript_data = transcript_snapshot(fallback)
            if transcript_data:
                _write_or_verify(transcript_path, transcript_data, 0o600)

    def record_incident(where: str, exc: BaseException) -> None:
        nonlocal incident_recorded
        if incident_recorded:
            return
        incident_recorded = True
        journal(
            "INCIDENT",
            terminal=False,
            where=where,
            dispatched=dispatched,
            probe_returned=probe_returned,
            device_contact=True,
            effect_profile=dict(EFFECT_PROFILE),
            error=f"{type(exc).__name__}: {exc}",
        )

    try:
        bridge_binding = transport.validate_bridge_binding()
        journal("BRIDGE_BOUND", bridge_binding=dict(bridge_binding), device_contact=False)

        version = session.invoke("version", ("version",))
        cmdline = session.invoke(
            "cmdline", ("run", TOYBOX, "cat", "/proc/cmdline")
        )
        transport.require_child_exit_zero(cmdline.payload, "V030 cmdline")
        target = transport.validate_target(version.payload, cmdline.payload)
        journal("TARGET_BOUND", target=target, device_contact=True)

        # Bracket the delegated boot-prefix reader with the exact current boot
        # UUID.  Attestation itself is allowed to perform bridge reads, so a
        # reboot/drift during that window must invalidate the run before any
        # staging mutation can occur.
        bridge_binding = transport.revalidate_bridge_binding(bridge_binding)
        boot_id_before = _read_boot_id(session, "boot_id_before_attestation")
        boot_record = _validate_boot_record(
            boot_attestation.attest_current_boot(
                transport.BRIDGE_HOST,
                transport.BRIDGE_PORT,
                30.0,
                BOOT_PREFIX_SHA256,
                boot_frames,
                bridge_binding=bridge_binding,
                exchange_fn=transport._local_exchange,
                revalidate_fn=transport.revalidate_bridge_binding,
            )
        )
        boot_record["frames"] = boot_frames
        bridge_binding = transport.revalidate_bridge_binding(bridge_binding)
        boot_id_attestation_after = _read_boot_id(
            session, "boot_id_after_attestation"
        )
        if boot_id_attestation_after != boot_id_before:
            raise LiveError("V030 boot_id changed during attestation")
        journal(
            "BOOT_BOUND",
            boot_prefix_sha256=BOOT_PREFIX_SHA256,
            boot_prefix_size=BOOT_PREFIX_SIZE,
            boot_id=boot_id_before,
            boot_id_sha256=sha256(boot_id_before.encode("ascii")),
            boot_id_attestation_after=boot_id_attestation_after,
            boot_id_attestation_after_sha256=sha256(
                boot_id_attestation_after.encode("ascii")
            ),
            attestation=boot_record,
            device_contact=True,
        )

        ion = session.invoke(
            "ion_dev", ("run", TOYBOX, "cat", ION_DEV_PATH), allow_error=True
        )
        transport.require_frame_ok(ion, "V030 ion_dev")
        if transport.parse_run_value(ion.payload, "V030 ion_dev") != EXPECTED_ION_DEV:
            raise LiveError("V030 ION device identity differs")
        remote_cleanup_needed = True
        # Bind the exact listener again immediately before the first remote
        # mutation group.  Every fixed path must be proven absent before this
        # run is allowed to create it; preclean-by-rm would erase ownership.
        bridge_binding = transport.revalidate_bridge_binding(bridge_binding)
        journal(
            "REMOTE_MUTATION_BOUND",
            bridge_binding=dict(bridge_binding),
            device_contact=True,
        )
        for evidence_id, path, key in (
            ("precheck_node", REMOTE_ION, "absence_node"),
            ("precheck_envelope", REMOTE_ENVELOPE, "absence_envelope"),
            ("precheck_binary", REMOTE_BINARY, "absence_binary"),
        ):
            _require_remote_absent(session, evidence_id, path)
            cleanup[key] = True
        _upload_binary(session, binary, created_paths)
        # mknod may create the character node before its framed response is
        # received.  Mark it owned before dispatch so a lost/error response
        # cannot bypass cleanup and reconciliation.
        created_paths.add(REMOTE_ION)
        node = session.invoke(
            "ion_node_create",
            ("run", TOYBOX, "mknod", REMOTE_ION, "c", "10", "94"),
            allow_error=True,
        )
        transport.require_frame_ok(node, "V030 ion node create")
        transport.require_child_exit_zero(node.payload, "V030 ion node create")
        chmod = session.invoke(
            "ion_node_chmod",
            ("run", TOYBOX, "chmod", "600", REMOTE_ION),
            allow_error=True,
        )
        transport.require_frame_ok(chmod, "V030 ion node chmod")
        transport.require_child_exit_zero(chmod.payload, "V030 ion node chmod")
        remote_before = _remote_hash(session, "remote_hash_before_run")
        if remote_before != binary_descriptor["sha256"]:
            raise LiveError("V030 remote binary hash-before differs")

        # This revalidation is intentionally the last operation before the
        # durable dispatch intent and the one-and-only probe invocation.
        bridge_binding = transport.revalidate_bridge_binding(bridge_binding)
        journal(
            "EFFECT_DISPATCHED",
            target=target,
            bridge_binding=dict(bridge_binding),
            boot_id=boot_id_before,
            boot_id_sha256=sha256(boot_id_before.encode("ascii")),
            source=dict(source_descriptor),
            binary=dict(binary_descriptor),
            remote_binary={
                "path": REMOTE_BINARY,
                "sha256": remote_before,
                "size_bytes": binary_descriptor["size_bytes"],
            },
            probe_argv=["run", REMOTE_BINARY],
            dispatch_count=1,
            device_contact=True,
            effect_profile=dict(EFFECT_PROFILE),
        )
        dispatched = True
        try:
            probe = session.invoke(
                "probe", ("run", REMOTE_BINARY), allow_error=True
            )
        except BaseException as exc:
            channel_ready = False
            partial = None
            try:
                partial = session.partial_payload("probe")
            except BaseException:
                partial = None
            try:
                partial_transcript = session.partial_transcript("probe")
            except BaseException:
                partial_transcript = None
            if isinstance(partial, bytes):
                payload = partial
            # The bounded transport cancellation path is the sole recovery
            # action for an ambiguous dispatched child.  It validates the
            # original BEGIN/PID and bridge binding and never replays probe.
            try:
                cancel_result = transport.cancel_probe_raw(
                    session,
                    partial_transcript,
                    expected_binding=bridge_binding,
                    timeout=30.0,
                )
            except BaseException as cancel_exc:
                cancel_result = {
                    "proved": False,
                    "channel_ready": False,
                    "errors": [
                        f"{type(cancel_exc).__name__}: {cancel_exc}"
                    ],
                }
            expected_pid = transport.child_pid(partial_transcript or b"")
            cancel_pid = cancel_result.get("pid") if isinstance(cancel_result, Mapping) else None
            if expected_pid is not None and cancel_pid != expected_pid:
                raise LiveError("V030 cancellation child PID differed") from exc
            if isinstance(cancel_result, Mapping) and cancel_result.get("channel_ready") is True:
                channel_ready = True
                # cancel_probe_raw reconnects outside Session.invoke, so make
                # its proved prompt state visible to the cleanup gate.  This
                # is a proof-derived transport bit, not a stale local guess.
                try:
                    session.prompt_ready = True
                except BaseException:
                    pass
                terminal_payload = cancel_result.get("terminal_payload")
                if isinstance(terminal_payload, bytes):
                    payload = terminal_payload
                cancel_journal = dict(cancel_result)
                cancel_journal.pop("terminal_payload", None)
                persist_sidecars(partial_transcript)
                journal(
                    "PROBE_RETURNED",
                    returned=True,
                    ambiguous_dispatch=True,
                    cancelled=True,
                    cancel=cancel_journal,
                    payload_sha256=sha256(payload) if payload is not None else None,
                    payload_size=len(payload) if payload is not None else None,
                )
            else:
                try:
                    session.prompt_ready = False
                except BaseException:
                    pass
                persist_sidecars(partial_transcript)
                cancel_journal = dict(cancel_result) if isinstance(cancel_result, Mapping) else {}
                cancel_journal.pop("terminal_payload", None)
                journal(
                    "PROBE_RETURNED",
                    returned=False,
                    ambiguous_dispatch=True,
                    cancelled=True,
                    cancel=cancel_journal,
                    payload_sha256=sha256(payload) if payload is not None else None,
                    payload_size=len(payload) if payload is not None else None,
                )
            raise LiveError("V030 probe dispatch became ambiguous; replay forbidden") from exc
        probe_returned = True
        channel_ready = True
        probe_frame = probe
        payload = probe.payload
        # Sidecars are durable before frame/child/payload validation so a
        # malformed or nonzero child result cannot erase returned evidence.
        persist_sidecars(probe)
        journal(
            "PROBE_RETURNED",
            returned=True,
            ambiguous_dispatch=False,
            frame_rc=probe.end.get("rc"),
            frame_status=probe.end.get("status"),
            payload_sha256=sha256(payload),
            payload_size=len(payload),
        )
        transport.require_frame_ok(probe, "V030 oracle")
        transport.require_child_exit_zero(payload, "V030 oracle")
        parsed = validate_oracle_payload(_normalise_probe_payload(payload))
        remote_after = _remote_hash(session, "remote_hash_after_run")
        if remote_after != remote_before:
            raise LiveError("V030 remote binary changed")
    except BaseException as exc:
        primary_error = (
            exc
            if isinstance(exc, LiveError)
            else LiveError(f"V030 acquisition failed: {type(exc).__name__}: {exc}")
        )
        try:
            persist_sidecars()
        except BaseException as sidecar_exc:
            if primary_error is None:
                primary_error = sidecar_exc
            record_incident("sidecar_persistence", sidecar_exc)
        record_incident("acquisition", primary_error)
    finally:
        # Every remote staging path is cleaned once, and only after a fresh
        # exact bridge binding.  Errors remain visible and prevent PASS.
        if remote_cleanup_needed and bridge_binding is not None:
            cleanup["attempted"] = True
            current_prompt_ready = getattr(session, "prompt_ready", None)
            if current_prompt_ready is None:
                # Minimal test doubles predating the transport readiness bit
                # are allowed to inherit the returned-frame proof only when
                # they expose no readiness attribute at all.
                current_prompt_ready = channel_ready
            channel_ready = bool(current_prompt_ready)
            cleanup_binding_ok = False
            # A transport failure after EFFECT_DISPATCHED may leave the child
            # occupying the shell.  Never send framed cleanup into that
            # ambiguous channel; preserve the incident for a later operator
            # recovery instead of risking a second command/effect.
            if dispatched and not channel_ready:
                cleanup["attempted"] = False
                cleanup["errors"].append(
                    "cleanup skipped: probe channel did not return to prompt"
                )
                cleanup["ok"] = False
                journal("CLEANUP", cleanup=dict(cleanup), device_contact=True)
            else:
                try:
                    transport.revalidate_bridge_binding(bridge_binding)
                except BaseException as exc:
                    cleanup_binding_ok = False
                    cleanup["errors"].append(
                        f"cleanup bridge: {type(exc).__name__}: {exc}"
                    )
                else:
                    cleanup_binding_ok = True
                if cleanup_binding_ok:
                    # Never remove a fixed path merely because it is the
                    # configured V030 name.  A path is eligible for removal
                    # only after this run has created it; paths proven absent
                    # by the preflight remain untouched.
                    node_created = REMOTE_ION in created_paths
                    file_paths = tuple(
                        path
                        for path in (REMOTE_ENVELOPE, REMOTE_BINARY)
                        if path in created_paths
                    )
                    cleanup["node_removed"] = not node_created
                    cleanup["files_removed"] = not file_paths
                    cleanup_commands: list[tuple[str, tuple[str, ...], str]] = []
                    if node_created:
                        cleanup_commands.append(
                            (
                                "cleanup_node",
                                ("run", TOYBOX, "rm", "-f", REMOTE_ION),
                                "node_removed",
                            )
                        )
                    if file_paths:
                        cleanup_commands.append(
                            (
                                "cleanup_files",
                                ("run", TOYBOX, "rm", "-f", *file_paths),
                                "files_removed",
                            )
                        )
                    for evidence_id, argv, key in cleanup_commands:
                        try:
                            frame = session.invoke(evidence_id, argv, allow_error=True)
                            transport.require_frame_ok(frame, evidence_id)
                            transport.require_child_exit_zero(frame.payload, evidence_id)
                            cleanup[key] = True
                        except BaseException as exc:
                            cleanup["errors"].append(
                                f"{evidence_id}: {type(exc).__name__}: {exc}"
                            )
                    for evidence_id, path, key in (
                        ("absence_node", REMOTE_ION, "absence_node"),
                        ("absence_envelope", REMOTE_ENVELOPE, "absence_envelope"),
                        ("absence_binary", REMOTE_BINARY, "absence_binary"),
                    ):
                        if path not in created_paths:
                            # The pre-effect absence proof is the only
                            # authority for paths this run did not create.
                            continue
                        try:
                            _require_remote_absent(session, evidence_id, path)
                            cleanup[key] = True
                        except BaseException as exc:
                            cleanup["errors"].append(
                                f"{evidence_id}: {type(exc).__name__}: {exc}"
                            )
                    cleanup["absence_proved"] = all(
                        cleanup[key]
                        for key in ("absence_node", "absence_envelope", "absence_binary")
                    )
                    cleanup_ok = not cleanup["errors"] and cleanup["node_removed"] and cleanup["files_removed"] and cleanup["absence_proved"]
                    cleanup["ok"] = cleanup_ok
                    journal("CLEANUP", cleanup=dict(cleanup), device_contact=True)
            # Cleanup command failures do not by themselves suppress an
            # independently safe final-health attempt.  The current prompt
            # readiness and freshly revalidated bridge are the authority.
            current_prompt_ready = getattr(session, "prompt_ready", None)
            if current_prompt_ready is None:
                current_prompt_ready = channel_ready
            channel_ready = bool(current_prompt_ready)
            if (dispatched or probe_returned) and cleanup_binding_ok and channel_ready:
                final_health["attempted"] = True
                try:
                    transport.revalidate_bridge_binding(bridge_binding)
                    final_version = session.invoke("final_version", ("version",))
                    final_cmdline = session.invoke(
                        "final_cmdline", ("run", TOYBOX, "cat", "/proc/cmdline"),
                        allow_error=True,
                    )
                    transport.require_frame_ok(final_cmdline, "V030 final cmdline")
                    transport.require_child_exit_zero(
                        final_cmdline.payload, "V030 final cmdline"
                    )
                    final_target = transport.validate_target(
                        final_version.payload, final_cmdline.payload
                    )
                    if target is None or final_target != target:
                        raise LiveError("V030 final target identity changed")
                    final_selftest = session.invoke(
                        "final_selftest", ("selftest", "status"), allow_error=True
                    )
                    transport.require_frame_ok(final_selftest, "V030 final selftest")
                    selftest = transport.parse_selftest(final_selftest.payload)
                    boot_id_after = _read_boot_id(session, "boot_id_after")
                    if boot_id_before is None or boot_id_after != boot_id_before:
                        raise LiveError("V030 boot_id changed after probe")
                    final_health.update(
                        {
                            "ok": True,
                            "target": final_target,
                            "selftest": selftest,
                            "boot_id_sha256": sha256(boot_id_after.encode("ascii")),
                            "version_frame": {
                                "sha256": sha256(final_version.transcript),
                                "size_bytes": len(final_version.transcript),
                            },
                            "cmdline_frame": {
                                "sha256": sha256(final_cmdline.transcript),
                                "size_bytes": len(final_cmdline.transcript),
                            },
                            "selftest_frame": {
                                "sha256": sha256(final_selftest.transcript),
                                "size_bytes": len(final_selftest.transcript),
                            },
                        }
                    )
                except BaseException as exc:
                    final_health["errors"].append(
                        f"{type(exc).__name__}: {exc}"
                    )
            elif dispatched or probe_returned:
                final_health["attempted"] = False
                final_health["errors"].append(
                    "final health skipped: bridge/channel not safely bound"
                )
            journal("FINAL_HEALTH", final_health=dict(final_health), device_contact=True)
            if not cleanup.get("ok") and primary_error is None:
                primary_error = LiveError("V030 cleanup did not prove absence")
                record_incident("cleanup", primary_error)
            if final_health["attempted"] and not final_health["ok"] and primary_error is None:
                primary_error = LiveError("V030 final health did not pass")
                record_incident("final_health", primary_error)

        # The transcript is intentionally snapshotted only after all safe
        # cleanup and final-health frames have completed (or been skipped due
        # to an unsafe/ambiguous channel).
        try:
            persist_sidecars(
                probe_frame if probe_frame is not None else partial_transcript,
                include_transcript=True,
            )
        except BaseException as exc:
            if primary_error is None:
                primary_error = exc
            record_incident("transcript_persistence", exc)

        if primary_error is not None and not terminal_recorded:
            journal(
                "INCIDENT",
                terminal=True,
                dispatched=dispatched,
                probe_returned=probe_returned,
                cleanup=dict(cleanup),
                final_health=dict(final_health),
                device_contact=True,
                effect_profile=dict(EFFECT_PROFILE),
                error=f"{type(primary_error).__name__}: {primary_error}",
            )
            terminal_recorded = True

    if primary_error is not None:
        raise primary_error
    if target is None or payload is None or parsed is None or bridge_binding is None:
        raise LiveError("V030 did not produce a complete target-bound result")
    if not cleanup.get("ok") or final_health.get("ok") is not True:
        raise LiveError("V030 cleanup/final health gates are incomplete")

    # The transcript was persisted only after cleanup/final-health.  Build and
    # raw descriptors are read back now, while the journal still contains no
    # terminal record.  Keep every fallible preparation operation under the
    # same terminal-incident guard as publication.
    journal_prefix_meta: dict[str, object] | None = None
    try:
        raw_data = payload
        transcript_data = _read_stable(transcript_path, "V030 transcript")
        build_receipt = {
            "schema": "a90-rbin-phys-oracle-build-v1",
            "source": source_descriptor,
            "binary": binary_descriptor,
            "compiler": command,
            "compiler_identity": compiler_identity,
            "build_hashes": [sha256(data) for data in build_outputs],
            "binary_reproducible": len(build_outputs) == 2 and build_outputs[0] == build_outputs[1],
            "static_elf": elf_descriptor,
            "static": True,
        }
        build_receipt_data = json_bytes(build_receipt)
        raw_meta = {
            "filename": RAW_OUTPUT_NAME,
            "sha256": sha256(raw_data),
            "size_bytes": len(raw_data),
        }
        transcript_meta = {
            "filename": TRANSCRIPT_NAME,
            "sha256": sha256(transcript_data),
            "size_bytes": len(transcript_data),
        }
        build_meta = {
            "filename": BUILD_RECEIPT_NAME,
            "sha256": sha256(build_receipt_data),
            "size_bytes": len(build_receipt_data),
        }
    except BaseException as exc:
        try:
            journal(
                "INCIDENT",
                terminal=True,
                where="publication_prepare",
                device_contact=True,
                effect_profile=dict(EFFECT_PROFILE),
                error=f"{type(exc).__name__}: {exc}",
            )
            terminal_recorded = True
        except BaseException:
            pass
        raise
    # Persist every non-journal sidecar before recording a terminal PASS.  The
    # journal prefix is intentionally captured after final-health and before
    # publication, so a consumer can verify the exact prefix independently.
    try:
        _write_or_verify(raw_path, raw_data, 0o600)
        _write_or_verify(transcript_path, transcript_data, 0o600)
        _write_or_verify(build_receipt_path, build_receipt_data, 0o600)
        _fsync_directory(output_root)
        journal_prefix_data = _read_stable(journal_path, "V030 journal prefix")
    except BaseException as exc:
        try:
            journal(
                "INCIDENT",
                terminal=True,
                where="publication",
                device_contact=True,
                effect_profile=dict(EFFECT_PROFILE),
                error=f"{type(exc).__name__}: {exc}",
            )
            terminal_recorded = True
        except BaseException:
            pass
        raise
    journal_prefix_meta = {
        "filename": JOURNAL_NAME,
        "sha256": sha256(journal_prefix_data),
        "size_bytes": len(journal_prefix_data),
    }
    completed = utc_now()
    private = {
        "schema": PRIVATE_SCHEMA,
        "status": "PREPARED_NOT_AUTHORITY",
        "closure_state": "CLOSURE_PREPARED",
        "experiment_id": EXPERIMENT_ID,
        "started_utc": started,
        "completed_utc": completed,
        "target": target,
        "bridge_binding": dict(bridge_binding),
        "source": source_descriptor,
        "binary": binary_descriptor,
        "remote_binary": {
            "path": REMOTE_BINARY,
            "before_sha256": remote_before,
            "after_sha256": remote_after,
            "unchanged": remote_before == remote_after == binary_descriptor["sha256"],
        },
        "oracle": parsed,
        "commands": getattr(session, "commands", []),
        "boot_attestation": boot_record,
        "boot_id_before": boot_id_before,
        "boot_id_attestation_after": boot_id_attestation_after,
        "boot_id_after": boot_id_after,
        "raw_output": raw_meta,
        "transcript": transcript_meta,
        "build_receipt": build_receipt,
        "build_receipt_file": build_meta,
        # Both names are retained for consumers that used the earlier private
        # shape; each is the same immutable prefix descriptor.
        "journal": journal_prefix_meta,
        "journal_prefix": journal_prefix_meta,
        "cleanup": cleanup,
        "final_health": final_health,
        "effect_profile": dict(EFFECT_PROFILE),
        "device_contact": True,
        "panic_restore": "NOT_APPLICABLE",
        "sysctl_restore": "NOT_APPLICABLE",
        "rollback": "NOT_APPLICABLE",
    }
    public_dir = base / "evidence" / "manifests"
    try:
        # Directory creation is part of the guarded publication transaction;
        # a failure here must leave a terminal INCIDENT rather than escaping
        # with prepared state that appears complete.
        public_dir.mkdir(parents=True, exist_ok=True)
        # The private receipt is published first.  Its exact bytes are then
        # represented in the public projection without a hash cycle.
        private_data = json_bytes(private)
        _write_or_verify(receipt_path, private_data, 0o600)
        receipt_meta = {
            "filename": PRIVATE_RECEIPT_NAME,
            "sha256": sha256(private_data),
            "size_bytes": len(private_data),
        }
        _fsync_directory(output_root)
        public_artifacts = {
            "receipt": receipt_meta,
            "raw_output": raw_meta,
            "transcript": transcript_meta,
            "journal": journal_prefix_meta,
            "build_receipt": build_meta,
        }
        public = public_projection(
            parsed,
            completed_utc=completed,
            target=target,
            binary=binary_descriptor,
            artifact_descriptors=public_artifacts,
            boot_prefix_sha256=BOOT_PREFIX_SHA256,
            boot_id_sha256=sha256(boot_id_before.encode("ascii")),
            final_health_ok=True,
        )
        validate_public_projection(public, target=target, binary=binary_descriptor)
        public_data = json_bytes(public)
        public_path = public_dir / PUBLIC_MANIFEST_NAME
        _write_or_verify(public_path, public_data, 0o644)
        _fsync_directory(public_dir)
        public_meta = {
            "filename": PUBLIC_MANIFEST_NAME,
            "sha256": sha256(public_data),
            "size_bytes": len(public_data),
        }
        terminal_fields = {
            "terminal": True,
            "completed_utc": completed,
            "target": target,
            "boot_id_sha256": sha256(boot_id_before.encode("ascii")) if boot_id_before else None,
            "source": dict(source_descriptor),
            "binary": dict(binary_descriptor),
            "journal_prefix": journal_prefix_meta,
            "artifact_descriptors": {
                **public_artifacts,
                "public_manifest": public_meta,
            },
            "remote_binary": {
                "path": REMOTE_BINARY,
                "before_sha256": remote_before,
                "after_sha256": remote_after,
                "unchanged": remote_before == remote_after == binary_descriptor["sha256"],
            },
            "cleanup": dict(cleanup),
            "final_health": dict(final_health),
            "device_contact": True,
            "effect_profile": dict(EFFECT_PROFILE),
            "panic_restore": "NOT_APPLICABLE",
            "sysctl_restore": "NOT_APPLICABLE",
            "rollback": "NOT_APPLICABLE",
        }
        # Validate the exact prospective terminal record before appending it.
        # The prefix descriptor deliberately excludes that record, avoiding a
        # self-referential hash while making PASS the sole authority.
        prospective_terminal = {
            "schema": PRIVATE_SCHEMA,
            "experiment_id": EXPERIMENT_ID,
            "state": "PASS",
            "utc": utc_now(),
            "effect_profile": dict(EFFECT_PROFILE),
        }
        prospective_terminal.update(terminal_fields)
        validate_completed_run(
            journal_prefix_data + _journal_bytes(prospective_terminal),
            private_data,
            public_data,
            {
                "raw_output": raw_data,
                "transcript": transcript_data,
                "build_receipt": build_receipt_data,
            },
        )
        # Only after all receipt/public bytes, directory entries, and the
        # completed-run binding are durable may the terminal PASS be appended.
        journal("PASS", **terminal_fields)
        terminal_recorded = True
    except BaseException as exc:
        # Publication failure is terminal incident evidence, never a silent
        # partial PASS.  The prefix descriptor remains useful even if only
        # the private receipt was durably created.
        try:
            journal(
                "INCIDENT",
                terminal=True,
                where="publication",
                journal_prefix=journal_prefix_meta,
                device_contact=True,
                effect_profile=dict(EFFECT_PROFILE),
                error=f"{type(exc).__name__}: {exc}",
            )
            terminal_recorded = True
        except BaseException:
            pass
        raise
    return output_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", default=EXPERIMENT_ID)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--execute", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.preflight:
        print(json.dumps(preflight(), sort_keys=True))
        return 0
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXPECTED_BYTES",
    "EXPECTED_BINARY_SHA256",
    "EXPECTED_BINARY_SIZE",
    "EXPECTED_REGION_END",
    "EXPECTED_REGION_FIRST",
    "EXPERIMENT_ID",
    "LiveError",
    "build_parser",
    "compute_segment_union",
    "derive_affine_page_relation",
    "main",
    "_parse_remote_hash_v030",
    "parse_perf_raw_record",
    "parse_perf_ring_bytes",
    "parse_trace_format",
    "preflight",
    "public_projection",
    "run",
    "validate_completed_run",
    "validate_public_projection",
    "validate_oracle_payload",
]
