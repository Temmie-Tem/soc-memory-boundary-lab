# Verification 024 — exact remapper page at DMID

**Status: `PRE_REGISTERED / HOST_IMPLEMENTATION_PENDING / DEVICE_NOT_RUN`.**

Verification 023 executed a fixed MID load from the SHRM snapshot page after
the originally proposed remapper flash path was unavailable. This follow-up
does not repeat that load: it tests the exact special remapper page
`0x09248080` with its paired no-load control at the same `DMID` state.

The immutable artifacts and one-shot sequence are specified in
[`docs/VERIFICATION024_CONTRACT_2026-08-27.md`](../../docs/VERIFICATION024_CONTRACT_2026-08-27.md).
The bounded boot/param effects and rollback are covered by
[`docs/WRITE_GATE_A90_REMAPPER_DMID_READ.md`](../../docs/WRITE_GATE_A90_REMAPPER_DMID_READ.md).

Pre-registered expectation: the control returns `0xc071`; the read returns no
value and produces the same non-secure watchdog/TZ reset classification as the
LOW observation. A returned value immediately changes status to
`POTENTIAL_SECURITY_BOUNDARY_BYPASS` and stops further probing.

No result is claimed yet. `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` remains
unchanged.
