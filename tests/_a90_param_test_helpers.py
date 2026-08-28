from __future__ import annotations

import hashlib
from collections.abc import Callable
from types import SimpleNamespace


BOOT_ID_PAYLOAD = b"11111111-1111-4111-8111-111111111111\n"
BOOT_ID_SHA256 = hashlib.sha256(BOOT_ID_PAYLOAD[:-1]).hexdigest()


def boot_id_frame(payload: bytes = BOOT_ID_PAYLOAD) -> SimpleNamespace:
    return SimpleNamespace(payload=payload)


def make_preflight_exchange(
    calls: list[str],
    frame_factory: Callable[[bytes, str], object],
    *,
    version_payload: bytes,
    cmdline_payload: bytes,
) -> Callable[[str, int, object, float], object]:
    """Build one strict fake for the shared preflight evidence sequence."""

    payloads = {
        "version": (version_payload, "version"),
        "proc_cmdline": (cmdline_payload, "cat"),
        "download_mode": (b"1\n", "cat"),
        "boot_id_before_effect": (BOOT_ID_PAYLOAD, "cat"),
    }

    def fake_exchange(host: str, port: int, command: object, timeout: float) -> object:
        del host, port, timeout
        evidence_id = command.evidence_id
        calls.append(evidence_id)
        try:
            payload, command_name = payloads[evidence_id]
        except KeyError:
            raise AssertionError(evidence_id) from None
        return frame_factory(payload, command_name)

    return fake_exchange
