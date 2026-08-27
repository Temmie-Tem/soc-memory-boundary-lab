# Verification 024 contract — exact remapper page at DMID

## Status and question

**Status: `PRE_REGISTERED / HOST_IMPLEMENTATION_PENDING / DEVICE_NOT_RUN`.**

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
| `param` LOW image | 10,485,760 | `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345` | exact retained rollback |
| `param` MID image | 10,485,760 | `50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256` | host-derived image differing only in the debug field |

The remapper builder and historical evidence already pin the body hashes,
hook, `__ioremap`, `__iounmap`, barriers, fixed address/width and absence of an
MMIO store. All five complete files must be re-read by size and SHA-256 before
the first device effect.

## Target and pre-state gates

Before every device effect, enumerate and bind exactly one target appropriate
to the current state:

- native: `SM-A908N` / `SM8150`, V2321 userspace, bootloader
  `A908NKSU5EWA3`, exact A90 ACM by-id identity;
- recovery: exact `SM-A908N` / `r3q`, TWRP `3.7.0_12-0`, pinned serial hash;
- no S20+, S22+, or unmatched ADB/ACM endpoint may be selected.

Initial state must be a complete V2321 boot-prefix hash and complete LOW
`param` hash, cmdline `debug_level=0x4f4c`, force-upload `0`, dump-sink `0`,
and native self-test `11/1/0/12`. A mismatch stops before a write.

## Fixed execution sequence

1. Rebuild or recheck the control/read/rollback images and all tool/test pins.
2. Enter exact TWRP using the existing one-shot recovery journal.
3. Flash `rollback -> control`; verify the complete 60,882,944-byte readback;
   remove staging; boot System once without replay.
4. On the safe LOW control candidate, apply exactly one `DLOW -> DMID`
   four-byte transition with complete 10-MiB before/after hashes; reboot the
   same candidate once and validate the consumed MID cmdline.
5. Invoke fixed op 4 once. It must return exactly `0xc071`, then pass exact
   version/cmdline/final-health checks. Any other control outcome aborts the
   read phase and rolls back.
6. Enter exact TWRP once. Flash `control -> read`; verify complete readback and
   staging absence; boot System once. Capture the resulting state and accept
   only the exact LOW or exact MID full-partition/cmdline state.
7. If and only if that state is LOW, apply exactly one `DLOW -> DMID`
   transition and reboot the same read candidate once. If it is already the
   exact MID state, do not rewrite or reboot. In either branch validate exact
   MID/force-upload/dump-sink state immediately before the read.
8. Durably record `PREPARED`, then dispatch fixed op 4 once. There is no retry.
9. If a value returns, record `READABLE_SECURITY_INDICATOR` and go directly to
   rollback. If the transport disconnects or times out, retain it as an
   incident candidate; collect the exact upload state and `/proc/last_kmsg`
   once after recovery. The probe tool alone may not call it a negative.
10. Enter exact TWRP once, flash `read -> rollback`, verify the full boot-prefix
    readback, remove staging, and boot System once.
11. Capture/verify the complete LOW `param` image. If it is still MID, perform
    the already-proven one-shot `DMID -> DLOW` restoration before the final
    boot. Verify V2321 LOW cmdline, force-upload `0`, dump-sink `0`, boot hash,
    temporary-path absence, and self-test `11/1/0/12`.

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

Even `REFUSED_AT_MID` proves only this one address, load and configuration. It
does not prove global XPU state, writer absence, transform immutability, a
complete physical-to-DRAM map, or structural impossibility. Unless a value is
returned, classification stays `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`.

## Forbidden effects

No controller/XPU/SMMU/SCM write, security ownership mutation, secure or
protected-memory access, firmware partition write, XBL/ABL/TZ/HYP change, GPT,
RPMB or QFPROM access is permitted. The only writes are the three exact boot
prefixes, one or two exact `DLOW -> DMID` transitions, a conditional final
`DMID -> DLOW` restoration, durable host journals, and experiment-owned
temporary staging files.
