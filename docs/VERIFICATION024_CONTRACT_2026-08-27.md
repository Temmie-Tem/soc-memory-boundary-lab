# Verification 024 contract — exact remapper page at DMID

## Status and question

**Status: `LIVE_CONTROL_BOOTED / PARAM_EFFECT_NOT_DISPATCHED /
PARSER_REPAIR_GO / RESUME_READY`.**

Verification 023 answered a nearby but different question. Its executed load
was the SHRM snapshot word at `0x0906566c`, protected by the SHRM policy stack,
after the originally proposed remapper candidate lacked a fixed flash tool.
The special `DC_NOC_BROADCAST_MPU` page containing remapper instance 0 at
`0x09248080` has still been tested only at `DLOW`.

Verification 024 asks exactly:

> Does the already-pinned single 32-bit EL1 load from `0x09248080` remain
> refused when the exact A90 boots with `androidboot.debug_level=0x494d`
> (`DMID`), after a same-state map/unmap-only control succeeds?

This is a reachability/access-control discriminator for one known aperture. It
does not write a controller, infer register semantics, or test a protected
memory destination.

## Why this is the next experiment

| Candidate | Information | Cost/risk | Decision |
|---|---|---|---|
| exact remapper page at DMID | Directly closes the address substitution in Verification 023 and tests the special page named by the XPU evidence | Three reversible boot-prefix writes, up to two reversible four-byte `param` apply transitions, likely one watchdog/upload recovery | **Selected** |
| another 020 static-trace extension | Adds one more bounded XBL edge but cannot establish Normal-World reachability | Low risk, low discriminator | Deferred |
| `DHIG`, force-upload, or alternate dump-sink state | Tests less source-backed configurations after DMID already enabled dumps | More configuration ambiguity and recovery cost | Deferred |
| complete row/channel reconstruction | Scientifically useful normal-RAM mapping work but does not test transform mutability or aperture reachability | Large implementation/measurement cost | Later |

`HYPOTHESIS`: the control returns `0xc071` and the read produces no value,
followed by the same non-secure watchdog/TZ reset reason observed at `DLOW` and
on the separate SHRM page at `DMID`.

The opposite observation is intentionally decisive: a returned 32-bit value
at `DMID` is a `POTENTIAL_SECURITY_BOUNDARY_BYPASS` indicator. Broad probing
then stops; only rollback, final health, the returned value, exact configuration
and minimum root-cause evidence may be retained.

## Exact immutable artifacts

| Profile | Bytes | SHA-256 | Effect |
|---|---:|---|---|
| remapper control | 60,882,944 | `dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247` | `__ioremap(0x09248080,0x5c)`; no load; unmap; return `0xc071` |
| remapper read | 60,882,944 | `6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed` | same map; one 32-bit load at offset zero; barriers; unmap if the load returns |
| V2321 rollback | 60,882,944 | `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb` | known healthy native research boot |
| retained `param` LOW full image | 10,485,760 | `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345` | rollback provenance and one known byte-0 state; not an eligibility hash |
| derived `param` MID full image | 10,485,760 | `50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256` | host-derived transition artifact; not a post-reboot eligibility hash |
| `param` stable LOW range `[1,0xA00000)` | 10,485,759 | `c0c7147418cf13145a44369a960c81647d347f317cb35baed1d85b286253c68a` | authoritative LOW eligibility identity |
| `param` stable MID range `[1,0xA00000)` | 10,485,759 | `9b85da06e4e4b1adb330c7169049a313ee5b0aa68014a2915a470f034c08f53f` | authoritative MID eligibility identity |

The remapper builder and historical evidence already pin the body hashes,
hook, `__ioremap`, `__iounmap`, barriers, fixed address/width and absence of an
MMIO store. Every complete artifact file must be re-read by size and SHA-256
before the first device effect. For live `param` eligibility, the complete
10-MiB image is still captured and triple-hashed, but the state predicate is
the fixed stable range plus decoded gate fields and cmdline, not either
historical full-image hash.

## Host implementation evidence — 2026-08-28

`PROVED`: the control, read, rollback and LOW images were re-read from their
fixed paths. Their sizes and SHA-256 values equal the table above. The derived
MID image is exactly 10,485,760 bytes, differs from LOW only in the four-byte
debug field (three byte values differ), and hashes to
`50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256`.
The fixed op buffer is 88 bytes and hashes to
`7cb5cf5aa907dce3b48ddc5dce8f296782ac2d1b24d18cb55fa54d45cb86c6b4`.

`PROVED`: after the replay, frame, payload and stable-`param` repairs, the
current host execution closure compiled and passed 1,895 serial tests with one
intentional skip. The run used a 4-GiB virtual-memory ceiling, reached 885,132
KiB maximum RSS before the live parser repair; the post-repair full run reached
893,252 KiB. Both performed zero test-process swaps and produced no kernel OOM
event. Independent hostile review exercised 743 frame-contract rows, 156
stable-`param`/static rows and 870 live-derived whitespace rows with `P0=0`
and `P1=0`. This is host qualification; fresh exact live target binding
remains mandatory before every device effect.

`SUPPORTED`: live boot/recovery cycles can change `param` byte 0 independently
of the debug record. The observed post-reboot full image differed from the
retained LOW image only at offset `0x0` (`00 -> 02`), while the complete
`[1,0xA00000)` hash remained the LOW stable hash. The writer and semantics of
byte 0 remain `UNKNOWN`; the contract excludes exactly `[0,1)` and no caller
may expand that exclusion.

The exact A90 kernel source is commit
`510d909eff0fe10e48f3bfff573bc17f59f0656a`. Its
`drivers/samsung/sec_param.c` hashes to
`86c03620a8c517dd3111006a15bc777a5d7cfedff75eebc4004e8d0e1bcd99c2`,
and `include/linux/samsung/sec_param.h` hashes to
`58b6963e9e45e8b60fa41a5997f4e2ca8f8a0002e302a8a4df765f345b6b892f`.
Those sources place `struct sec_param_data` at `SEC_PARAM_FILE_OFFSET`
(`0x900000`) and do not identify byte 0's writer.

## Target and pre-state gates

Before every device effect, enumerate and bind exactly one target appropriate
to the current state:

- native: `SM-A908N` / `SM8150`, V2321 userspace, bootloader
  `A908NKSU5EWA3`, exact A90 ACM by-id identity;
- recovery: exact `SM-A908N` / `r3q`, TWRP `3.7.0_12-0`, pinned serial hash;
- no S20+, S22+, or unmatched ADB/ACM endpoint may be selected.

The native `autohud` client can transiently own A90P1 after every boot and
return `rc=-16 status=busy`. Every native lifecycle tool must therefore run the
same fixed, bounded `stophud` arbitration before its first substantive command.
The post-reboot observer may first obtain one complete read-only `version`
frame to prove that the new command channel is available, then it must stop the
HUD before identity and health reads. Only an explicit `busy/-16` refusal may
be retried, at most three attempts total, because that frame proves the command
did not execute. Every refusal and accepted stop is retained. A non-busy error
or ambiguous `stophud` transport outcome stops that tool without retry.

The exact retained native source makes this repeated entry-point qualification
safe: `cmd_stophud()` returns zero after `stop_auto_hud()`, including the
already-stopped `autohud: not running` path. Consequently two lifecycle tools
in one boot may each record an accepted idempotent stop. This exception never
applies to op 4, flash, `param`, sysctl, or reboot. Reboot restores the normal
HUD lifecycle.

The wire contract is exact. A `0/ok` terminal must carry either
`autohud: stopped` or `autohud: not running` after transport line-delimiter
removal; a `-16/busy` terminal must carry zero payload bytes. Success with an
empty payload is `REFUTED` by the retained source and live receipts. The shared
arbiter and every V024 consumer bind canonical BEGIN/END mappings, terminal
text, prompt tail and payload, with a 20-byte payload bound and 4,096-byte
transcript bound. A complete invalid frame is one validation incident, not a
transport failure, and may not be retried.

Initial state must be a complete V2321 boot-prefix hash and complete 10-MiB
`param` capture whose fixed `[1,0xA00000)` hash is stable LOW, whose decoded
gate fields are exact LOW/zero/zero/zero, and whose cmdline has
`debug_level=0x4f4c`, force-upload `0`, and dump-sink `0`. Native self-test
must be `11/1/0/12` and `panic_on_oops=1`. A mismatch stops before an
experiment effect.

The flash journal alone does not attest which candidate is currently running.
Immediately before each fixed op, the native runner must source-bind
`sda24/PARTNAME=boot`, copy exactly the first 60,882,944 bytes through a fixed
experiment-owned temporary block node/file, verify its size and SHA-256 against
the selected candidate, then remove both objects and prove absence. Non-native
file operations in this attestation use the retained `/bin/toybox` through the
fixed `run` command; unsupported direct applet names are forbidden. A valid old
flash journal with a different live boot must fail before op 4.

The fixed op transport is self-contained in this repository. It constructs one
88-byte command buffer with magic `0xa90c0de5deadbeef`, op `4`, and zero
arguments, sends one fixed newline-safe A90P1 `run /bin/busybox sh -c ...`
command, and parses only the resulting bounded `A90R` record. It does not load
the mutable external generic REPL driver or its transport modules. The sysctl
transition likewise uses a fixed native command. After current-boot
attestation cleanup, the bridge is re-bound and that binding is made durable
before the `1 -> 0` sysctl write; a second rebind remains immediately before
the op arm.

## Fixed execution sequence

### Live amendment: consumed control identifier

`verification-024-control` is now immutable pre-dispatch incident evidence.
It proves zero fixed-op dispatch and zero panic/partition/MMIO effect, but its
complete `stophud` frame bytes were discarded by the old host wrapper. The
HUD state change is therefore `UNKNOWN_IDEMPOTENT`; the incident is not a
successful control and the identifier must not be reused.

Any continuation must use the single fixed identifier
`verification-024-control-r2`. Before device contact it must claim its journal
with O_EXCL, validate the exact original public/raw/journal hashes plus producer
commit/source/helper/transport pins, and durably bind that predecessor capsule.
It must retain the same semantic-claim key `(mode,candidate,boot_id)`. The old
identifier is predecessor-only in the producer, finalizer, READ authorizer and
last-kmsg validator. There is no caller-selected retry flag, old-ID fallback,
or r3; an r2 failure terminates this route for explicit reconciliation.

1. Rebuild or recheck the control/read/rollback images and all tool/test pins.
2. Enter exact TWRP using the existing one-shot recovery journal.
3. Flash `rollback -> control`; verify the complete 60,882,944-byte readback;
   remove staging; boot System once without replay.
4. On the safe LOW control candidate, apply exactly one `DLOW -> DMID`
   four-byte transition with complete 10-MiB before/after hashes; reboot the
   same candidate once and validate the consumed MID cmdline.
5. Prove that the current boot prefix equals the control candidate. Durably
   record the fixed `panic_on_oops` transition, change `1 -> 0`, and verify
   immediate readback. Invoke fixed op 4 once. It must return exactly `0xc071`;
   restore `panic_on_oops` to `1`, verify it, then pass exact
   version/cmdline/final-health checks. Any other control outcome aborts the
   read phase and rolls back.
6. Enter exact TWRP once. Flash `control -> read`; verify complete readback and
   staging absence; boot System once. Capture the complete resulting `param`
   image and accept only stable LOW or stable MID plus exact decoded fields and
   cmdline. The full hash remains bound as transfer evidence but is not the
   post-reboot state predicate.
7. If and only if that state is LOW, apply exactly one `DLOW -> DMID`
   transition and reboot the same read candidate once. If it is already the
   exact MID state, do not rewrite or reboot. In either branch validate exact
   MID/force-upload/dump-sink state immediately before the read.
8. Prove that the current boot prefix equals the read candidate. Durably record
   and verify `panic_on_oops: 1 -> 0`, record `PREPARED`, then dispatch fixed op
   4 once. There is no retry. If the op returns, restore and verify
   `panic_on_oops=1` before any other action. If it times out or disconnects,
   send no further device command and defer verification to post-reset recovery.
9. If a value returns, record `READABLE_SECURITY_INDICATOR` and go directly to
   rollback. If the transport disconnects or times out, retain it as an
   incident candidate; collect the exact upload state and `/proc/last_kmsg`
   once after recovery. The probe tool alone may not call it a negative.
10. Enter exact TWRP once, flash `read -> rollback`, verify the full boot-prefix
    readback, remove staging, and boot System once.
11. Capture and classify the complete current `param` image with the same
    fixed stable-range predicate used at entry. If it is stable MID,
    perform the one-shot `DMID -> DLOW` restoration and reboot once to consume
    LOW; if it is already stable LOW, do not rewrite it. Capture the final
    complete stable-LOW image with full before/host/after hash equality, then
    verify V2321 LOW cmdline, force-upload `0`,
    dump-sink `0`, boot hash, temporary-path absence, `panic_on_oops=1`, and
    self-test `11/1/0/12`.

All host subprocesses used for Recovery/ADB transfer have a fixed finite
timeout. A timeout before the partition effect is a refusal; a timeout after
the durable `dd` marker is ambiguous and forbids automated replay.

An ambiguous boot-prefix write is recovered only by
`tools/a90_twrp_boot_rollback_recovery.py`. It consumes the stable, no-follow
ambiguous flash journal, rebinds the exact A90/TWRP endpoint and current boot
state, and either closes without a write when rollback is already exact or
dispatches one fixed V2321 rollback write. It never replays the experimental
candidate.

An ambiguous `param` transition is recovered only by
`tools/a90_param_debug_recovery_live.py`. It consumes the exact ambiguous
transition journal, captures and triple-hashes the complete 10-MiB image, and
accepts only pinned LOW, pinned MID, or a four-byte-field-only torn image. MID
or torn state permits one fixed `DLOW` effect after a durable no-replay marker;
all other image differences are refused.

Entering Samsung Upload may require the operator's physical power-button
action, as Verification 023 did. That is the only anticipated manual gate; it
does not authorize replay of the read.

## Classification rules

- `CONTROL_FAILED`: no read is dispatched; rollback only.
- `READABLE_SECURITY_INDICATOR`: stop broad probing, set
  `POTENTIAL_SECURITY_BOUNDARY_BYPASS`, retain minimum evidence, rollback, and
  enter disclosure review.
- `REFUSED_AT_MID_CANDIDATE`: no value plus disconnect/timeout; not promoted
  until exact MID attribution, watchdog/TZ reset evidence, rollback and final
  health all pass.
- `REFUSED_AT_MID`: the promoted bounded negative after those gates pass.
- `INCIDENT`: ambiguous effect, wrong target/state, missing log, failed
  rollback, or incomplete health. Never replay.

A device-side `busy/-16` on the bounded `stophud` qualification is an
instrument condition, not `CONTROL_FAILED`; exhaustion without one accepted
stop is a pre-dispatch incident.

Even `REFUSED_AT_MID` proves only this one address, load and configuration. It
does not prove global XPU state, writer absence, transform immutability, a
complete physical-to-DRAM map, or structural impossibility. Unless a value is
returned, classification stays `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`.

## Forbidden effects

No controller/XPU/SMMU/SCM write, security ownership mutation, secure or
protected-memory access, firmware partition write, XBL/ABL/TZ/HYP change, GPT,
RPMB or QFPROM access is permitted. The only writes are the three exact boot
prefixes, one or two exact `DLOW -> DMID` transitions, a conditional final
`DMID -> DLOW` restoration, a fixed temporary `panic_on_oops: 1 -> 0`
transition before each op with same-boot restoration when the op returns,
bounded idempotent `stophud` arbitration at each native lifecycle entry point,
durable host journals, and experiment-owned temporary staging/boot-attestation
files. A watchdog branch must verify the default `1` only after recovery; it
must not send a post-timeout command.
