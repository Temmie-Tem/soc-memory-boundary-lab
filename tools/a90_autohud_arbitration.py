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
import time
from collections.abc import Callable, Mapping
from typing import Any

try:
    from tools.a90_acm_snapshot import Command
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command  # type: ignore


STOPHUD_ARGV = ("stophud",)
STOPHUD_MAX_ATTEMPTS = 3
STOPHUD_RETRY_DELAY_SEC = 0.05


class StopHudError(RuntimeError):
    """The fixed stophud arbitration did not close successfully."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _frame_provenance(evidence_id: str, argv: tuple[str, ...], frame: Any) -> dict[str, object]:
    payload = getattr(frame, "payload", b"")
    transcript = getattr(frame, "transcript", b"")
    return {
        "evidence_id": evidence_id,
        "argv": list(argv),
        "payload_size": len(payload) if isinstance(payload, bytes) else None,
        "payload_sha256": _sha256(payload) if isinstance(payload, bytes) else None,
        "payload_base64": (
            base64.b64encode(payload).decode("ascii")
            if isinstance(payload, bytes)
            else None
        ),
        "transcript_size": len(transcript) if isinstance(transcript, bytes) else None,
        "transcript_sha256": _sha256(transcript) if isinstance(transcript, bytes) else None,
        "transcript_base64": (
            base64.b64encode(transcript).decode("ascii")
            if isinstance(transcript, bytes)
            else None
        ),
        "begin": dict(getattr(frame, "begin", {})),
        "end": dict(getattr(frame, "end", {})),
    }


def run_stophud(
    host: str,
    port: int,
    timeout: float,
    exchange_call: Callable[..., Any],
    *,
    frame_records: list[dict[str, object]] | None = None,
    persist: Callable[[list[dict[str, object]]], None] | None = None,
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
            begin = getattr(frame, "begin", {})
            end = getattr(frame, "end", {})
            if (
                not isinstance(begin, Mapping)
                or not isinstance(end, Mapping)
                or begin.get("cmd") != "stophud"
                or end.get("cmd") != "stophud"
                or begin.get("seq") != end.get("seq")
            ):
                raise StopHudError("stophud frame command/sequence is not exact")
            rc = int(frame.end["rc"], 0)
            status = str(frame.end["status"])
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise StopHudError("stophud frame lacks exact rc/status") from exc
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
    "StopHudError",
    "run_stophud",
]
