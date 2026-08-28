#!/usr/bin/env python3
"""Bounded arbitration for the device-side A90P1 ``autohud`` holder.

The runtime can answer a fixed command with ``rc=-16 status=busy`` while its
autohud owns the command channel.  That response means the command was not
executed, so this module may retry only that exact refusal.  No transport
exception, non-busy error, or measurement/effect command is retried here.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

try:
    from tools.a90_acm_snapshot import BEGIN_RE, END_RE, Command, parse_last_frame
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import BEGIN_RE, END_RE, Command, parse_last_frame  # type: ignore


STOPHUD_ARGV = ("stophud",)
STOPHUD_MAX_ATTEMPTS = 3
STOPHUD_RETRY_DELAY_SEC = 0.05
STOPHUD_SUCCESS_PAYLOADS = frozenset(
    {
        b"autohud: stopped",
        b"autohud: not running",
    }
)
STOPHUD_BUSY_PAYLOAD = b""
# The two source-defined success strings are at most 20 bytes.  The complete
# stophud receipt (framing, terminal line, and optional native prompt tail)
# remains a small control receipt rather than a general command transcript.
STOPHUD_MAX_PAYLOAD_BYTES = 20
STOPHUD_MAX_TRANSCRIPT_BYTES = 4096
# Invalid complete returns retain bounded transport provenance.  This cap is
# deliberately independent of the much tighter acceptance bound above.
STOPHUD_PROVENANCE_MAX_BYTES = 1024 * 1024

_CANONICAL_UNSIGNED_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_STOPHUD_BEGIN_KEYS = frozenset({"cmd", "seq", "argc", "flags"})
_STOPHUD_END_KEYS = frozenset(
    {"cmd", "seq", "rc", "errno", "duration_ms", "flags", "status"}
)
_STOPHUD_TERMINAL_RE = re.compile(
    rb"(?:^|\r?\n)\[(?P<kind>done|busy)\] "
    rb"(?P<text>[^\r\n]*)(?:\r\n|\n|\Z)"
)
_STOPHUD_BUSY_TEXTS = frozenset(
    {
        b"power menu active; send hide/q before commands",
        b"auto menu active; hide/q before dangerous command",
        b"auto menu active; send hide/q before command",
    }
)
_STOPHUD_ALLOWED_TAILS = frozenset(
    {b"", b"a90:/# ", b"a90:/# \n", b"a90:/# \r\n"}
)


class StopHudError(RuntimeError):
    """The fixed stophud arbitration did not close successfully."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_stophud_payload(payload: object, rc: object, status: object) -> bytes:
    """Validate the fixed wire payload for one parsed stophud terminal."""

    if type(payload) is not bytes:
        raise StopHudError("stophud payload is not exact bytes")
    if type(rc) is not int or type(status) is not str:
        raise StopHudError("stophud terminal rc/status types are not exact")
    if rc == 0 and status == "ok":
        allowed = STOPHUD_SUCCESS_PAYLOADS
    elif rc == -16 and status == "busy":
        allowed = frozenset({STOPHUD_BUSY_PAYLOAD})
    else:
        raise StopHudError(f"stophud terminal is unsupported: rc={rc} status={status!r}")
    if payload not in allowed:
        raise StopHudError(
            f"stophud payload is not exact for rc={rc} status={status!r}"
        )
    return payload


def validate_stophud_evidence_sizes(payload: object, transcript: object) -> tuple[bytes, bytes]:
    """Validate the shared stophud payload/transcript acceptance bounds."""

    if type(payload) is not bytes:
        raise StopHudError("stophud payload is not exact bytes")
    if len(payload) > STOPHUD_MAX_PAYLOAD_BYTES:
        raise StopHudError("stophud payload exceeds the fixed evidence bound")
    if type(transcript) is not bytes:
        raise StopHudError("stophud transcript is not exact bytes")
    if len(transcript) > STOPHUD_MAX_TRANSCRIPT_BYTES:
        raise StopHudError("stophud transcript exceeds the fixed evidence bound")
    return payload, transcript


def _frame_provenance(evidence_id: str, argv: tuple[str, ...], frame: Any) -> dict[str, object]:
    # Missing wire data is absence, not an empty successful payload.  In
    # particular, a malformed busy return must not acquire the SHA-256 of
    # ``b""`` and thereby look like the canonical busy wire payload.
    payload = getattr(frame, "payload", None)
    transcript = getattr(frame, "transcript", None)
    begin = getattr(frame, "begin", None)
    end = getattr(frame, "end", None)
    payload_exact = type(payload) is bytes
    transcript_exact = type(transcript) is bytes
    payload_b64 = (
        base64.b64encode(payload).decode("ascii")
        if payload_exact and len(payload) <= STOPHUD_PROVENANCE_MAX_BYTES
        else None
    )
    transcript_b64 = (
        base64.b64encode(transcript).decode("ascii")
        if transcript_exact and len(transcript) <= STOPHUD_PROVENANCE_MAX_BYTES
        else None
    )
    return {
        "evidence_id": evidence_id,
        "argv": list(argv),
        "payload_size": len(payload) if payload_exact else None,
        "payload_sha256": _sha256(payload) if payload_exact else None,
        "payload_base64": payload_b64,
        "transcript_size": len(transcript) if transcript_exact else None,
        "transcript_sha256": _sha256(transcript) if transcript_exact else None,
        "transcript_base64": transcript_b64,
        "begin": dict(begin) if isinstance(begin, Mapping) else None,
        "end": dict(end) if isinstance(end, Mapping) else None,
    }


def _validation_attempt(
    attempt: int,
    evidence_id: str,
    provenance: Mapping[str, object],
    exc: BaseException,
) -> dict[str, object]:
    return {
        "attempt": attempt,
        "rc": None,
        "status": None,
        "evidence_id": evidence_id,
        "payload_size": provenance["payload_size"],
        "payload_sha256": provenance["payload_sha256"],
        "transcript_size": provenance["transcript_size"],
        "transcript_sha256": provenance["transcript_sha256"],
        "validation_error_type": type(exc).__name__,
        "validation_error": str(exc),
    }


def _canonical_unsigned_decimal(value: object) -> bool:
    return type(value) is str and _CANONICAL_UNSIGNED_DECIMAL_RE.fullmatch(value) is not None


def _validate_stophud_terminal(frame: Any) -> tuple[int, str]:
    """Validate the shared stophud terminal mapping without normalization."""

    begin = getattr(frame, "begin", None)
    end = getattr(frame, "end", None)
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise StopHudError("stophud frame command/sequence fields are not exact")
    if set(begin) != _STOPHUD_BEGIN_KEYS or set(end) != _STOPHUD_END_KEYS:
        raise StopHudError("stophud frame command/sequence/argc/flags fields are not exact")
    if (
        type(begin.get("cmd")) is not str
        or begin.get("cmd") != "stophud"
        or type(end.get("cmd")) is not str
        or end.get("cmd") != "stophud"
        or type(begin.get("seq")) is not str
        or type(end.get("seq")) is not str
        or not _canonical_unsigned_decimal(begin.get("seq"))
        or begin.get("seq") != end.get("seq")
        or type(begin.get("argc")) is not str
        or type(begin.get("flags")) is not str
        or type(end.get("flags")) is not str
        or begin.get("argc") != "1"
        or begin.get("flags") != "0x8"
        or end.get("flags") != "0x8"
    ):
        raise StopHudError("stophud frame command/sequence/argc/flags are not exact")

    raw_rc = end.get("rc")
    if type(raw_rc) is not str or raw_rc not in {"0", "-16"}:
        raise StopHudError(f"stophud frame rc={raw_rc} is not canonical")
    expected_errno = "0" if raw_rc == "0" else "16"
    if type(end.get("errno")) is not str or end.get("errno") != expected_errno:
        raise StopHudError(
            f"stophud frame errno={end.get('errno')} does not match rc={raw_rc}"
        )
    if not _canonical_unsigned_decimal(end.get("duration_ms")):
        raise StopHudError(
            f"stophud frame duration_ms={end.get('duration_ms')} is not canonical"
        )
    expected_status = "ok" if raw_rc == "0" else "busy"
    if type(end.get("status")) is not str or end.get("status") != expected_status:
        raise StopHudError(
            f"stophud frame status={end.get('status')!r} does not match rc={raw_rc}"
        )
    payload = getattr(frame, "payload", None)
    transcript = getattr(frame, "transcript", None)
    validate_stophud_evidence_sizes(payload, transcript)
    begin_matches = list(BEGIN_RE.finditer(transcript))
    end_matches = list(END_RE.finditer(transcript))
    if (
        transcript.count(b"A90P1 BEGIN") != len(begin_matches)
        or transcript.count(b"A90P1 END") != len(end_matches)
        or len(begin_matches) != 1
        or len(end_matches) != 1
        or end_matches[0].start() <= begin_matches[0].end()
    ):
        raise StopHudError("stophud frame transcript count/order is not exact")
    try:
        parsed = parse_last_frame(transcript, "stophud")
    except (TypeError, UnicodeDecodeError, ValueError) as exc:
        raise StopHudError("stophud frame transcript is not complete") from exc
    if (
        parsed.begin != dict(begin)
        or parsed.end != dict(end)
        or parsed.payload != payload
        or parsed.transcript != transcript
    ):
        raise StopHudError("stophud frame transcript/payload binding is not exact")
    if transcript[end_matches[0].end() :] not in _STOPHUD_ALLOWED_TAILS:
        raise StopHudError("stophud frame post-END tail is not exact")
    body = transcript[begin_matches[0].end() : end_matches[0].start()]
    terminals = list(_STOPHUD_TERMINAL_RE.finditer(body))
    if len(terminals) != 1 or terminals[0].end() != len(body):
        raise StopHudError("stophud frame terminal marker is not exact")
    terminal = terminals[0]
    text = terminal.group("text")
    kind = terminal.group("kind")
    if raw_rc == "0":
        if kind != b"done":
            raise StopHudError("stophud frame success terminal kind is not exact")
        if text != b"stophud (" + end["duration_ms"].encode("ascii") + b"ms)":
            raise StopHudError("stophud frame success terminal text is not exact")
    else:
        if kind != b"busy":
            raise StopHudError("stophud frame busy terminal kind is not exact")
        if text not in _STOPHUD_BUSY_TEXTS or end["duration_ms"] != "0":
            raise StopHudError("stophud frame busy terminal text is not exact")
    return (0 if raw_rc == "0" else -16), expected_status


def run_stophud(
    host: str,
    port: int,
    timeout: float,
    exchange_call: Callable[..., Any],
    *,
    frame_records: list[dict[str, object]] | None = None,
    persist: Callable[[list[dict[str, object]]], None] | None = None,
    validate_frame: Callable[[Any], object] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    max_attempts: int = STOPHUD_MAX_ATTEMPTS,
) -> dict[str, object]:
    """Run the fixed ``stophud`` command with a narrow busy-only retry.

    Callers may lower the fixed bound (for example to one attempt when a
    lifecycle phase forbids a busy retry), but transport exceptions are never
    retried at any bound.  Every parsed attempt is returned and optionally
    sent to ``persist`` before another attempt can occur.
    """

    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool):
        raise StopHudError("stophud max_attempts is not an integer")
    if max_attempts < 1 or max_attempts > STOPHUD_MAX_ATTEMPTS:
        raise StopHudError("stophud max_attempts is outside the fixed bound")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(float(timeout))
        or float(timeout) <= 0
    ):
        raise StopHudError("stophud timeout is not finite and positive")
    command = Command("stophud", STOPHUD_ARGV)
    attempts: list[dict[str, object]] = []
    records = frame_records if frame_records is not None else []
    for attempt in range(1, max_attempts + 1):
        # The caller-provided exchange is the already-pinned local transport;
        # this helper never substitutes a second transport or hides errors.
        evidence_id = f"stophud_{attempt}"
        try:
            frame = exchange_call(
                host,
                port,
                command,
                timeout,
                allow_error=True,
            )
        except BaseException as exc:
            partial = getattr(exc, "partial", None)
            partial_payload = getattr(exc, "partial_payload", None)
            partial_transcript = getattr(exc, "partial_transcript", None)
            partial_begin = getattr(exc, "partial_begin", None)
            partial_end = getattr(exc, "partial_end", None)
            if partial is not None:
                partial_payload = getattr(partial, "payload", partial_payload)
                partial_transcript = getattr(partial, "transcript", partial_transcript)
                partial_begin = getattr(partial, "begin", partial_begin)
                partial_end = getattr(partial, "end", partial_end)
            incident: dict[str, object] = {
                "attempt": attempt,
                "evidence_id": evidence_id,
                "argv": list(STOPHUD_ARGV),
                "transport_error_type": type(exc).__name__,
                "transport_error": str(exc),
                "partial_payload_size": (
                    len(partial_payload) if isinstance(partial_payload, bytes) else None
                ),
                "partial_payload_sha256": (
                    _sha256(partial_payload)
                    if isinstance(partial_payload, bytes)
                    else None
                ),
                "partial_transcript_size": (
                    len(partial_transcript)
                    if isinstance(partial_transcript, bytes)
                    else None
                ),
                "partial_transcript_sha256": (
                    _sha256(partial_transcript)
                    if isinstance(partial_transcript, bytes)
                    else None
                ),
                "partial_begin": (
                    dict(partial_begin) if isinstance(partial_begin, Mapping) else None
                ),
                "partial_end": (
                    dict(partial_end) if isinstance(partial_end, Mapping) else None
                ),
            }
            attempts.append(incident)
            records.append(dict(incident))
            if persist is not None:
                persist(list(attempts))
            raise
        provenance = _frame_provenance(evidence_id, STOPHUD_ARGV, frame)
        records.append(provenance)
        try:
            rc, status = _validate_stophud_terminal(frame)
            validate_stophud_payload(getattr(frame, "payload", None), rc, status)
        except BaseException as exc:
            attempts.append(_validation_attempt(attempt, evidence_id, provenance, exc))
            if persist is not None:
                persist(list(attempts))
            if isinstance(exc, StopHudError):
                raise
            raise StopHudError("stophud frame terminal is not exact") from exc
        if validate_frame is not None:
            callback_error: BaseException | None = None
            try:
                validate_frame(frame)
            except BaseException as exc:
                callback_error = exc
            post_callback_provenance = _frame_provenance(
                evidence_id, STOPHUD_ARGV, frame
            )
            if post_callback_provenance != provenance:
                mutation_error = StopHudError(
                    "stophud frame mutated during validation"
                )
                attempts.append(
                    _validation_attempt(
                        attempt, evidence_id, provenance, mutation_error
                    )
                )
                if persist is not None:
                    persist(list(attempts))
                raise mutation_error from callback_error
            if callback_error is not None:
                attempts.append(
                    _validation_attempt(
                        attempt, evidence_id, provenance, callback_error
                    )
                )
                if persist is not None:
                    persist(list(attempts))
                raise StopHudError("stophud frame validation failed") from callback_error
        item: dict[str, object] = {
            "attempt": attempt,
            "rc": rc,
            "status": status,
            "evidence_id": evidence_id,
            "payload_size": provenance["payload_size"],
            "payload_sha256": provenance["payload_sha256"],
            "transcript_size": provenance["transcript_size"],
            "transcript_sha256": provenance["transcript_sha256"],
        }
        attempts.append(item)
        if persist is not None:
            persist(list(attempts))
        if rc == 0 and status == "ok":
            return {
                "accepted": True,
                "attempts": attempts,
                "busy_retries": sum(
                    item["rc"] == -16 and item["status"] == "busy"
                    for item in attempts
                ),
            }
        if rc == -16 and status == "busy":
            if attempt < max_attempts:
                sleep_fn(STOPHUD_RETRY_DELAY_SEC)
                continue
            raise StopHudError("stophud remained busy after bounded retries")
        raise StopHudError(f"stophud failed: rc={rc} status={status!r}")
    raise StopHudError("stophud arbitration exhausted")


__all__ = [
    "STOPHUD_ARGV",
    "STOPHUD_MAX_ATTEMPTS",
    "STOPHUD_RETRY_DELAY_SEC",
    "STOPHUD_SUCCESS_PAYLOADS",
    "STOPHUD_BUSY_PAYLOAD",
    "STOPHUD_MAX_PAYLOAD_BYTES",
    "STOPHUD_MAX_TRANSCRIPT_BYTES",
    "STOPHUD_PROVENANCE_MAX_BYTES",
    "StopHudError",
    "validate_stophud_payload",
    "validate_stophud_evidence_sizes",
    "run_stophud",
]
