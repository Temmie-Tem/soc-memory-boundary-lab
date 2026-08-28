# Verification 024 live-gate review — 2026-08-28

## Current disposition

**`HOST_REVIEW_GO / LIVE_CONTROL_BOOTED / PARAM_EFFECT_NOT_DISPATCHED /
RESUME_READY`.**

This record covers the host execution closure for the exact
`SM-A908N`/`SM8150` remapper control/read experiment. It grants no authority to
another target and records no device result.

## Root primary audit

The first implementation review returned `NO_GO`. The repaired closure now
addresses these bounded defects:

1. every boot-prefix effect has a durable one-shot journal and a separate
   source-bound rollback owner for an unknown partial state;
2. every `param` effect has complete before/after hashing and a source-bound
   LOW/MID/torn recovery owner;
3. legacy unjournaled System-boot dispatch is not reachable from the V024 CLI;
4. fresh exact bridge/Recovery binding is adjacent to state mutations;
5. the fixed op uses a non-destructive dmesg cursor rather than `dmesg -c`;
6. subprocess, socket, per-command and outer transaction waits are finite;
7. public receipts bind the final private bytes, and the host finalizer checks
   control/read/reset/rollback/param/health chronology.

The final param-recovery audit found and returned four additional defects to
the Luna Max implementation worker. The repaired version accepts only the
known real A90 bare cmdline flags (`skip_initramfs`, `rootwait`, `ro`), performs
fresh binding before live identity and each full-image capture phase, stops all
cleanup commands after a typed binding failure, exposes a bounded effect
timeout, and no longer documents the obsolete prepare-only behavior.

## Independent root verification

The following immutable inputs were re-read:

| Input | Size | SHA-256 |
|---|---:|---|
| control boot | 60,882,944 | `dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247` |
| read boot | 60,882,944 | `6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed` |
| V2321 rollback boot | 60,882,944 | `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb` |
| retained LOW param | 10,485,760 | `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345` |
| derived MID param | 10,485,760 | `50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256` |
| fixed op buffer | 88 | `7cb5cf5aa907dce3b48ddc5dce8f296782ac2d1b24d18cb55fa54d45cb86c6b4` |

Independent AArch64 disassembly reconfirmed that both bodies map
`0x09248080` for `0x5c` bytes. The control body performs no load from the
mapping; the read body performs one `ldr w20, [x19]`. Neither body contains an
MMIO store. Stack saves are not controller writes.

The final param-recovery core/effect/live set passed 97/97 focused tests. The
current six-module V024 gate set passed 177/177. The complete `tests/test_*.py`
suite passed 1,883 tests with one skip in 195.473 seconds. After the live
cmdline, public-claim redaction, live-stat and journal repairs, the final full
suite passed 1,895 tests with one skip in 198.129 seconds. Both ran serially
under `ulimit -v 4194304`; the final maximum RSS was 893,252 KiB, test-process swaps
were zero, and the kernel recorded no
OOM event during either run.

## Independent hostile review result

Earlier independent passes returned `NO_GO` and kept the live gate closed
while replay, frame, payload and final-`param` contracts were repaired. The
final frozen-hash review returned `GO`: 743/743 adversarial frame rows and 156
stable-`param`/static rows passed with `P0=0` and `P1=0`. The exact six-module
suite independently passed 177/177 with 99,172 KiB peak RSS and zero swaps.

The decisive findings were:

- boot and `param` recovery sources were not consumed by a fixed no-replay
  claim, so a new output ID could reuse an old ambiguous source;
- torn-boot rollback did not pre-clean, rehash and rebind its staging object at
  all required boundaries;
- several reboot/Recovery/System effects retained an unjournaled or
  non-adjacent dispatch surface, and caller-selected output roots created
  replay namespaces;
- final `param` geometry and producer evidence were not exact enough;
- read authorization and finalization did not require the full current-boot,
  panic-transition and transport-no-value evidence chain;
- final rollback could be cross-spliced from the control predecessor;
- `A90R` and last-kmsg regexes accepted garbage suffixes; and
- the read incident and captured last-kmsg had no exact boot-session/source
  join, permitting stale evidence to close a negative.

The final stable-`param` matrix accepted eleven byte-0 variants with coherent
full-image bindings and rejected stable-byte, gate-offset, expanded-exclusion,
historical-full-hash, projection, type, decoded/raw and cmdline attacks. The
fixed state predicate is `[1,0xA00000)`, size `0x9fffff`, with LOW hash
`c0c7147418cf13145a44369a960c81647d347f317cb35baed1d85b286253c68a`.
Full-image before/host/after equality remains mandatory.

Two non-live P2 observations remain: an unused version-parser return label
uses the full banner, and caller-added `triple_hash_match:false` aliases at
locations the producer never emits are ignored. Neither value is consumed as
authority; required public `capture.triple_hash_match` remains exact `true`.

The subsequent live-derived parser review passed 870/870 whitespace rows and
repeated all 743 frame rows. The affected tests passed 112/112 and the exact
six-module gate passed 180/180, again with `P0=0` and `P1=0`.

Public physical-claim redaction then passed 87 hostile assertions and 19/19
focused tests with `P0=P1=P2=0`. Raw boot UUIDs remain in the private causal
journal; public manifests contain only their exact ASCII/no-newline SHA-256.

The live-stat/journal review then passed 48/48 four-path parser cases, 24/24
transition state-machine scenarios, 835/835 frame attacks and 204/204 cmdline
attacks with `P0=P1=P2=0`.

## Remaining gate

Host repair and independent review are complete. Before the next V024 device
command the runner must freshly enumerate and bind the exact A90 in its current
native or Recovery state, rehash the fixed candidate/rollback inputs, and
refuse any unexpected endpoint or predecessor. No historical receipt grants
live authority.

Until the complete live sequence closes, the scientific classification remains
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` and the exact remapper read at DMID
remains `UNKNOWN`.

## Post-live parser and evidence amendment

The first control probe stopped before target attestation, panic transition or
fixed op 4 because the host wrapper incorrectly required an empty successful
`stophud` payload. Exact native source and live receipts refute that assumption:
success is exactly `autohud: stopped` or `autohud: not running`; only
`-16/busy` is empty. The original control ID is consumed immutable incident
evidence with fixed-op/panic/partition/MMIO effects all zero. Its exact frame
bytes are unrecoverable and the possible idempotent HUD state change remains
`UNKNOWN_IDEMPOTENT`.

Hostile rounds 24 and 25 found duplicate validation/transport records,
noncanonical return-code acceptance, missing-wire empty-hash confusion,
terminal-kind drift, callback mutation and inconsistent transcript limits.
Round 26 verified the repaired 20-byte payload and 4,096-byte transcript
contract with `P0=P1=P2=0`. The exact eleven-module set is 319/319 PASS,
maximum RSS 349,056 KiB and process swap zero. After the last compatibility
fixture repair, the complete suite finished 1,916 tests with 1,915 passed and
one skipped in 198.868 seconds, maximum RSS 893,116 KiB, process swap zero and
no kernel OOM event.

The control-reboot public v1 also exposed a transient raw boot UUID. A bounded
host-only repair preserved the exact 1,884-byte v1 privately, revalidated the
22,905-byte journal and 663-byte one-shot claim, and emitted a UUID-redacted,
source-bound public v2 of 2,140 bytes, SHA-256
`fbe92a29ba66f282e15c79fc4344d2b8a96c6cece44dba29326be656137bd248`.
No source inode or content changed, no open writer existed, and idempotent
reverification was byte-identical. Under that immutable-evidence operational
precondition the independent result is `P0=P1=P2=0`; an adversarial
non-cooperating same-UID writer is explicitly outside this authority model.
The retained pre/post projection is recorded in
`docs/VERIFICATION024_REBOOT_PUBLIC_REPAIR_RECEIPT_2026-08-28.md`; its
no-open-writer observation is `SUPPORTED`, not an atomic program receipt.

The live gate is therefore not reopened under the old identifier. The next
host task is the independently reviewed, predecessor-bound
`verification-024-control-r2` owner described in the live execution log.
