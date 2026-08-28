#!/usr/bin/env python3
"""Dependency-injected one-shot DLOW effect coordinator.

The live recovery owner supplies already-bound callbacks for the native bridge
and partition helpers.  This module owns only the effect state machine: it
stages the fixed DLOW payload, proves the regular-file ``dd`` semantics,
durably arms one fixed write, dispatches it once, and verifies a complete
stable-range LOW image (retaining its full hash as an observation).  It never imports a transport, bridge, socket, subprocess,
or device-facing helper.

The coordinator intentionally never performs cleanup.  A successful return
authorizes the caller to run its separately-bound cleanup group; every
ambiguous or failed outcome returns no cleanup authorization and leaves the
caller with a durable reconciliation state.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, MutableMapping
from typing import Any

from tools import a90_param_debug_recovery as core


RECOVERABLE_MID = core.RECOVERABLE_MID
RECOVERABLE_TORN = core.RECOVERABLE_TORN
ALREADY_LOW = core.ALREADY_LOW

FIXED_DD_ARGS = core.FIXED_DD_ARGS
FIXED_EFFECT_ARGV = core.FIXED_EFFECT_ARGV
DLOW_PAYLOAD = core.DLOW_PAYLOAD
DLOW_PAYLOAD_SHA256 = core.DLOW_PAYLOAD_SHA256
DLOW_PAYLOAD_SIZE = core.DLOW_PAYLOAD_SIZE
LOW_SHA256 = core.ROLLBACK_SHA256
LOW_STABLE_SHA256 = core.PARAM_STABLE_LOW_SHA256
STABLE_MASK = core.PARAM_STABLE_MASK

EFFECT_DISPATCH_STARTED = "EFFECT_DISPATCH_STARTED"
EFFECT_RETURNED_VERIFYING_FULL_HASH = "EFFECT_RETURNED_VERIFYING_FULL_HASH"
PASS_EFFECT_LOW_VERIFIED = "PASS_EFFECT_LOW_VERIFIED"
AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED = core.AMBIGUOUS_STATUS
AMBIGUOUS_STATUS = AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED

RECOVERY_EFFECT_SCHEMA = "sdm855-a90-param-debug-recovery-effect-v1"
EFFECT_SCHEMA = RECOVERY_EFFECT_SCHEMA


class ParamDebugRecoveryEffectError(RuntimeError):
    """A refused, ambiguous, or non-successful one-shot effect."""


RecoveryEffectError = ParamDebugRecoveryEffectError
EffectCoordinatorError = ParamDebugRecoveryEffectError


def _call_noarg(function: Callable[..., Any], label: str) -> Any:
    """Call one injected seam once, without speculative retry.

    Production seams are zero-argument closures.  A required single argument
    is accepted as a small test/owner convenience and receives the fixed
    command tuple; this is decided from the signature before invocation so an
    internal callback ``TypeError`` is never mistaken for a signature mismatch
    and retried.
    """

    try:
        parameters = list(inspect.signature(function).parameters.values())
    except (TypeError, ValueError):
        parameters = []
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    has_varargs = any(
        parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters
    )
    required = [
        parameter
        for parameter in positional
        if parameter.default is inspect.Parameter.empty
    ]
    if required and len(required) == 1 and not has_varargs:
        return function(tuple(FIXED_EFFECT_ARGV))
    return function()


def _call_persist(function: Callable[..., Any], journal: MutableMapping[str, object]) -> Any:
    """Invoke the durable persist seam once, supporting closure or journal forms."""

    try:
        parameters = list(inspect.signature(function).parameters.values())
    except (TypeError, ValueError):
        parameters = []
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    has_varargs = any(
        parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters
    )
    required = [
        parameter
        for parameter in positional
        if parameter.default is inspect.Parameter.empty
    ]
    if has_varargs or required:
        return function(journal)
    return function()


def _journal_snapshot(journal: MutableMapping[str, object]) -> dict[str, object]:
    """Take a shallow snapshot sufficient to roll back a failed pre-arm persist."""

    return dict(journal)


def _restore_snapshot(
    journal: MutableMapping[str, object], snapshot: Mapping[str, object]
) -> None:
    journal.clear()
    journal.update(snapshot)


def _set_ambiguous(journal: MutableMapping[str, object], error: BaseException) -> None:
    journal.update(
        {
            "status": AMBIGUOUS_STATUS,
            "current_state": "UNKNOWN",
            "effect_armed": True,
            "effect_dispatched": True,
            "effect_dispatched_count": 1,
            "write_count": 1,
            "partition_writes": True,
            "effect_replayed": False,
            "reconcile_required": True,
            "cleanup_deferred": True,
            "error": f"{type(error).__name__}: {error}",
        }
    )


def _persist_ambiguous(
    journal: MutableMapping[str, object],
    persist: Callable[..., Any],
    error: BaseException,
) -> None:
    """Persist an ambiguity marker once; preserve the original failure."""

    _set_ambiguous(journal, error)
    try:
        _call_persist(persist, journal)
    except BaseException:
        # The in-memory journal remains explicitly ambiguous even if the host
        # cannot publish the next revision.  Do not retry the effect or invoke
        # any later device callback.
        pass


def _effect_end(result: object) -> Mapping[str, object]:
    begin: object | None = None
    direct_end = False
    if isinstance(result, Mapping):
        # A mapping with begin/end is an actual frame-shaped result and must
        # carry both sides of the protocol receipt.  The only direct-END
        # seam retained for unit tests is a mapping containing exactly rc and
        # status; it cannot masquerade as a partial frame.
        if "begin" in result or "end" in result:
            begin = result.get("begin")
            end = result.get("end")
        elif set(result) == {"rc", "status"}:
            end = result
            direct_end = True
        else:
            end = None
    else:
        begin = getattr(result, "begin", None)
        end = getattr(result, "end", None)
    if not isinstance(end, Mapping):
        raise ParamDebugRecoveryEffectError(
            "fixed DLOW effect returned no valid A90P1 end record"
        )
    if not direct_end:
        if (
            not isinstance(begin, Mapping)
            or begin.get("cmd") != "run"
            or end.get("cmd") != "run"
            or "seq" not in begin
            or "seq" not in end
            or begin.get("seq") != end.get("seq")
        ):
            raise ParamDebugRecoveryEffectError(
                "fixed DLOW effect begin/end frame is not exact"
            )
    return end


def _validate_stage_receipt(value: object) -> dict[str, object]:
    expected: dict[str, object] = {
        "path": core.PAYLOAD_PATH,
        "size": core.DLOW_PAYLOAD_SIZE,
        "sha256": core.DLOW_PAYLOAD_SHA256,
        "readback_base64": "RExPVw==",
    }
    if not isinstance(value, Mapping) or dict(value) != expected:
        raise ParamDebugRecoveryEffectError(
            "fixed DLOW stage receipt is not exact"
        )
    return expected


def _validate_smoke_receipt(value: object) -> dict[str, object]:
    expected: dict[str, object] = {
        "args": list(core.SMOKE_DD_ARGS),
        "passed": True,
        "expected_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
        "readback_sha256": core.SMOKE_EXPECTED_SHA256[core.LOW_BYTES],
    }
    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryEffectError(
            "fixed DLOW dd smoke receipt is not exact"
        )
    if any(value.get(key) != item for key, item in expected.items()):
        raise ParamDebugRecoveryEffectError(
            "fixed DLOW dd smoke receipt is not exact"
        )
    unexpected = set(value) - set(expected) - {"a90p1_end"}
    if unexpected:
        raise ParamDebugRecoveryEffectError(
            "fixed DLOW dd smoke receipt contains unexpected fields"
        )
    if "a90p1_end" in value:
        end = value["a90p1_end"]
        if (
            not isinstance(end, Mapping)
            or end.get("cmd") != "run"
            or end.get("status") != "ok"
            or end.get("rc") not in {0, "0"}
        ):
            raise ParamDebugRecoveryEffectError(
                "fixed DLOW dd smoke A90P1 receipt is not successful"
            )
    return dict(expected)


def _require_successful_effect(result: object) -> Mapping[str, object]:
    end = _effect_end(result)
    raw_rc = end.get("rc")
    status = end.get("status")
    try:
        if isinstance(raw_rc, bool):
            raise ValueError("boolean rc")
        rc = int(raw_rc, 0) if isinstance(raw_rc, str) else int(raw_rc)
    except (TypeError, ValueError) as exc:
        raise ParamDebugRecoveryEffectError(
            "fixed DLOW effect returned a malformed rc"
        ) from exc
    if rc != 0 or status != "ok":
        raise ParamDebugRecoveryEffectError(
            f"fixed DLOW effect was not successful: rc={raw_rc!r} status={status!r}"
        )
    return end


def _require_classification(classification: object) -> str:
    if not isinstance(classification, str) or classification not in {
        RECOVERABLE_MID,
        RECOVERABLE_TORN,
    }:
        raise ParamDebugRecoveryEffectError(
            "fixed DLOW effect requires RECOVERABLE_MID or RECOVERABLE_TORN"
        )
    return str(classification)


def _validate_image_capture(value: object, *, expected_stable: str, expected_state: str) -> dict[str, object]:
    """Validate a complete binary image and return JSON-safe observations."""

    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryEffectError(
            "post-effect capture must include complete stable-image evidence"
        )
    image = value.get("image")
    if type(image) is not bytes or len(image) != core.PARAM_PARTITION_BYTES:
        raise ParamDebugRecoveryEffectError(
            "post-effect capture lacks the exact 10 MiB image"
        )
    if value.get("size") != len(image):
        raise ParamDebugRecoveryEffectError("post-effect capture size is not exact")
    full_hash = core.sha256(image)
    stable_hash = core.stable_param_sha256(image)
    if value.get("full_sha256", value.get("sha256")) != full_hash:
        raise ParamDebugRecoveryEffectError("post-effect full hash does not match capture bytes")
    if value.get("sha256", full_hash) != full_hash:
        raise ParamDebugRecoveryEffectError("post-effect sha256 observation is not exact")
    if value.get("stable_sha256") != stable_hash or stable_hash != expected_stable:
        raise ParamDebugRecoveryEffectError("post-effect stable hash is not the fixed LOW hash")
    expected_range = {
        "start": core.PARAM_STABLE_OFFSET,
        "end": core.PARAM_STABLE_END,
        "size": core.PARAM_STABLE_SIZE,
        "sha256": stable_hash,
    }
    if value.get("stable_range") != expected_range:
        raise ParamDebugRecoveryEffectError("post-effect stable range/hash evidence is not exact")
    if value.get("stable_mask") != STABLE_MASK:
        raise ParamDebugRecoveryEffectError("post-effect stable mask is not the fixed [0,1) exclusion")
    if (
        type(value.get("volatile_byte0")) is not int
        or not 0 <= value["volatile_byte0"] <= 255
        or value["volatile_byte0"] != image[0]
    ):
        raise ParamDebugRecoveryEffectError("post-effect volatile byte-0 observation is not exact")
    if (
        "observed_boot_cycle_volatile_byte0" in value
        and value["observed_boot_cycle_volatile_byte0"] != image[0]
    ):
        raise ParamDebugRecoveryEffectError(
            "post-effect observed volatile byte-0 is not bound to capture bytes"
        )
    fields = value.get("decoded_fields")
    if not isinstance(fields, Mapping):
        raise ParamDebugRecoveryEffectError("post-effect decoded debug fields are missing")
    try:
        expected_fields = core.decode_fields(image)
    except BaseException as exc:
        raise ParamDebugRecoveryEffectError(
            "post-effect capture fields cannot be decoded from bytes"
        ) from exc
    if fields != expected_fields:
        raise ParamDebugRecoveryEffectError(
            "post-effect decoded fields are not bound to capture bytes"
        )
    debug = image[core.PARAM_DEBUG_OFFSET : core.PARAM_DEBUG_OFFSET + core.PARAM_DEBUG_SIZE]
    debug_record = fields.get("debuglevel")
    if (
        not isinstance(debug_record, Mapping)
        or debug != core.LOW_BYTES
        or debug_record.get("label") != expected_state
    ):
        raise ParamDebugRecoveryEffectError("post-effect image is not the exact stable LOW state")
    if core.classify_live_image(image) != core.ALREADY_LOW:
        raise ParamDebugRecoveryEffectError("post-effect image classification is not ALREADY_LOW")
    return {
        "size": len(image),
        "sha256": full_hash,
        "full_sha256": full_hash,
        "stable_sha256": stable_hash,
        "stable_range": expected_range,
        "stable_mask": {
            "excluded_ranges": [list(item) for item in core.PARAM_VOLATILE_RANGES],
            "stable_ranges": [list(core.PARAM_STABLE_RANGE)],
            "stable_size": core.PARAM_STABLE_SIZE,
        },
        "volatile_byte0": value["volatile_byte0"],
        "decoded_fields": dict(fields),
        "classification": expected_state,
    }


def coordinate_dlow_effect(
    classification: str,
    journal: MutableMapping[str, object],
    persist: Callable[..., Any],
    fresh_bind: Callable[..., Any],
    stage_fixed_dlow: Callable[..., Any],
    verify_dd_smoke: Callable[..., Any],
    dispatch_fixed_effect: Callable[..., Any],
    full_device_hash: Callable[..., Any] | None = None,
    *,
    capture_device_image: Callable[..., Any] | None = None,
) -> dict[str, object]:
    """Run the dependency-injected one-shot DLOW effect state machine.

    ``classification`` must be the pure core's ``RECOVERABLE_MID`` or
    ``RECOVERABLE_TORN`` result.  Every callback is called at most once per
    stage, except ``fresh_bind`` which is intentionally called exactly twice:
    once before staging and once immediately before the durable effect arm.
    """

    selected = _require_classification(classification)
    if not isinstance(journal, MutableMapping):
        raise ParamDebugRecoveryEffectError("effect journal must be mutable")
    for key, expected in (
        ("effect_dispatched", False),
        ("effect_replayed", False),
        ("write_count", 0),
        ("effect_dispatched_count", 0),
        ("partition_writes", False),
    ):
        actual = journal.get(key, expected)
        if type(actual) is not type(expected) or actual != expected:
            raise ParamDebugRecoveryEffectError(
                f"effect journal is not fresh at {key}: {actual!r}"
            )
    before_byte0 = journal.get("volatile_byte0_before")
    if type(before_byte0) is not int or not 0 <= before_byte0 <= 255:
        raise ParamDebugRecoveryEffectError(
            "effect journal lacks an exact pre-effect volatile byte-0 observation"
        )
    if capture_device_image is None or not callable(capture_device_image):
        raise ParamDebugRecoveryEffectError(
            "exact capture_device_image callback is required; full-only hash callbacks are refused"
        )

    # Keep the in-memory journal explicitly pre-effect without persisting a
    # revision.  If any pre-arm seam fails, the caller still observes zero
    # writes and zero dispatches.
    journal.setdefault("effect_armed", False)
    journal.setdefault("current_state", "UNKNOWN")
    journal.setdefault("reconcile_required", True)
    journal.setdefault("cleanup_deferred", False)
    journal.setdefault("effect_argv", list(FIXED_EFFECT_ARGV))

    try:
        first_binding = _call_noarg(fresh_bind, "pre_stage_bind")
        staged = _validate_stage_receipt(
            _call_noarg(stage_fixed_dlow, "stage_fixed_dlow")
        )
        smoke = _validate_smoke_receipt(
            _call_noarg(verify_dd_smoke, "verify_dd_smoke")
        )
        second_binding = _call_noarg(fresh_bind, "pre_effect_bind")
    except BaseException as exc:
        # No durable effect marker has been written and no effect callback was
        # reached; do not manufacture an armed/write count in this branch.
        journal["effect_armed"] = False
        journal["effect_dispatched"] = False
        journal["effect_dispatched_count"] = 0
        journal["write_count"] = 0
        journal["partition_writes"] = False
        journal["effect_replayed"] = False
        raise

    if first_binding is not None:
        journal["pre_stage_bridge_binding"] = first_binding
    if second_binding is not None:
        journal["pre_effect_bridge_binding"] = second_binding
    if staged is not None:
        journal["payload"] = staged
    if smoke is not None:
        journal["regular_file_dd_smoke"] = smoke

    marker_snapshot = _journal_snapshot(journal)
    journal.update(
        {
            "status": EFFECT_DISPATCH_STARTED,
            "effect_armed": True,
            "effect_dispatched": True,
            "effect_dispatched_count": 1,
            "write_count": 1,
            "partition_writes": True,
            "effect_argv": list(FIXED_EFFECT_ARGV),
            "effect_replayed": False,
            "current_state": "UNKNOWN",
            "reconcile_required": True,
            "cleanup_deferred": False,
            "classification": selected,
        }
    )
    try:
        _call_persist(persist, journal)
    except BaseException:
        _restore_snapshot(journal, marker_snapshot)
        # Preserve the explicitly pre-arm invariant even if the snapshot came
        # from a caller that omitted one of the zero-valued fields.
        journal["effect_armed"] = False
        journal["effect_dispatched"] = False
        journal["effect_dispatched_count"] = 0
        journal["write_count"] = 0
        journal["partition_writes"] = False
        journal["effect_replayed"] = False
        raise

    # The marker is durable: from here there is exactly one dispatch attempt,
    # and every failure path is permanently no-replay.
    try:
        dispatch_result = _call_noarg(dispatch_fixed_effect, "dispatch_fixed_effect")
        end = _require_successful_effect(dispatch_result)
    except BaseException as exc:
        _persist_ambiguous(journal, persist, exc)
        raise

    journal.update(
        {
            "status": EFFECT_RETURNED_VERIFYING_FULL_HASH,
            "effect_receipt": {
                "end": dict(end),
            },
        }
    )
    try:
        _call_persist(persist, journal)
    except BaseException as exc:
        _persist_ambiguous(journal, persist, exc)
        raise

    try:
        # Full-only hash callbacks are intentionally insufficient: recovery
        # must receive the complete bounded image and prove the stable mask,
        # debug fields, and byte-0 preservation in one receipt.
        raw_capture = _call_noarg(capture_device_image, "post_effect_capture")
        capture = _validate_image_capture(
            raw_capture,
            expected_stable=LOW_STABLE_SHA256,
            expected_state="LOW",
        )
        after_hash = str(capture["full_sha256"])
        if capture["volatile_byte0"] != before_byte0:
            raise ParamDebugRecoveryEffectError(
                "post-effect volatile byte 0 changed during the live transition"
            )
    except BaseException as exc:
        _persist_ambiguous(journal, persist, exc)
        raise
    journal.update(
        {
            "status": PASS_EFFECT_LOW_VERIFIED,
            "current_state": "LOW",
            "device_sha256_after": after_hash,
            "device_stable_sha256_after": capture["stable_sha256"],
            "stable_range_after": capture["stable_range"],
            "stable_mask": capture["stable_mask"],
            "volatile_byte0_after": capture["volatile_byte0"],
            "observed_boot_cycle_volatile_byte0_after": capture["volatile_byte0"],
            "decoded_fields_after": capture["decoded_fields"],
            "post_effect_capture": capture,
            "reconcile_required": False,
            "cleanup_deferred": False,
            "effect_replayed": False,
            "effect_dispatched_count": 1,
            "write_count": 1,
            "partition_writes": True,
        }
    )
    try:
        _call_persist(persist, journal)
    except BaseException as exc:
        _persist_ambiguous(journal, persist, exc)
        raise
    return {
        "status": PASS_EFFECT_LOW_VERIFIED,
        "classification": selected,
        "device_sha256_after": after_hash,
        "device_stable_sha256_after": capture["stable_sha256"],
        "stable_mask": capture["stable_mask"],
        "volatile_byte0_after": capture["volatile_byte0"],
        "observed_boot_cycle_volatile_byte0_after": capture["volatile_byte0"],
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "cleanup_authorized": True,
    }


run_effect = coordinate_dlow_effect
dispatch_effect = coordinate_dlow_effect
recover_effect = coordinate_dlow_effect
run_once = coordinate_dlow_effect
coordinate_effect = coordinate_dlow_effect


__all__ = [
    "ALREADY_LOW",
    "AMBIGUOUS_STATUS",
    "DLOW_PAYLOAD",
    "DLOW_PAYLOAD_SHA256",
    "DLOW_PAYLOAD_SIZE",
    "EFFECT_DISPATCH_STARTED",
    "EFFECT_RETURNED_VERIFYING_FULL_HASH",
    "FIXED_DD_ARGS",
    "FIXED_EFFECT_ARGV",
    "LOW_SHA256",
    "LOW_STABLE_SHA256",
    "STABLE_MASK",
    "PASS_EFFECT_LOW_VERIFIED",
    "ParamDebugRecoveryEffectError",
    "RecoveryEffectError",
    "coordinate_dlow_effect",
    "dispatch_effect",
    "recover_effect",
    "run_effect",
]
