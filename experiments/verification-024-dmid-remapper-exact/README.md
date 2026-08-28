# Verification 024 — exact remapper page at DMID

**Status: `LIVE_CONTROL_BOOTED / PARAM_EFFECT_NOT_DISPATCHED /
PARSER_REPAIR_GO / RESUME_READY`.**

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

The hostile-review repair requires a live current-boot prefix hash immediately
before each op; a historical flash receipt alone is insufficient. It also
preserves the historical comparison condition by journaling and verifying the
temporary `panic_on_oops: 1 -> 0` transition, restoring `1` on every returning
op and verifying `1` after recovery when the read disconnects.

Because `autohud` can return device-side `busy/-16` immediately after boot,
each native lifecycle tool must run bounded fixed `stophud` arbitration before
its substantive work. Only explicit non-executed busy refusals may be retried;
the retained source proves repeated already-stopped calls are idempotent. The
fixed op and every state-changing experiment effect remain one-shot.

The fixed op and `panic_on_oops` transition use a repository-local,
self-contained A90P1 path. The generic external REPL and its mutable transport
dependencies are not in the execution closure. Current-boot hashing routes
non-native file applets through the retained Toybox, and every Recovery/ADB
subprocess is time-bounded.

The live closure now has separate no-replay recovery owners for a torn
boot-prefix write and for an ambiguous `param` transition. The former can only
write the pinned V2321 rollback; the latter can only restore pinned DLOW after
a complete-image classification. Neither path authorizes replay of a candidate
or of the original ambiguous transition.

Host verification on 2026-08-28 passed 1,891 serial tests (one skip), with
890,136 KiB maximum RSS, no test-process swap and no OOM event. Exact artifact
and op-buffer hashes matched the pre-registered values. The final independent
hostile pass exercised 743 frame-contract rows and 156 stable-`param`/static
rows with no P0/P1 finding. The live `param` predicate now excludes exactly
boot-volatile byte `[0,1)` while retaining full before/host/after hashes; LOW
is the fixed `[1,0xA00000)` hash `c0c71474...` plus exact decoded fields and
cmdline. No Verification 024 device command has yet been issued; a fresh exact
A90 binding is still required. The control image has since been written and
booted once. Two `param` transactions refused before their effect (zero
partition writes); the live double-space cmdline parser defect is repaired and
independently reviewed. See
[`docs/VERIFICATION024_LIVE_EXECUTION_LOG_2026-08-28.md`](../../docs/VERIFICATION024_LIVE_EXECUTION_LOG_2026-08-28.md).

No result is claimed yet. `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` remains
unchanged.
