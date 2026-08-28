# Verification 020A setter/base trace integration review — 2026-08-27

## Boundary and snapshot

This iteration is host-only and read-only for the exact A90/SM8150 evidence
line.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory or partition
operation was performed.  Live repetitions, rollback, recovery and target
health receipts are `NOT_APPLICABLE` because no device state was contacted.

The retained XBL input is `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.  The
pre-iteration repository HEAD was `dd357ef` on branch
`codex/config-cdt-integration`; the output is sanitized and contains no private
absolute paths or raw firmware bytes.  The host tool is interpreted Python
3.14.4 on Linux x86_64.

## Exact static checks

The candidate setter `[0x9fc06410,0x9fc0643c)` is pinned to 44 bytes and hash
`4f90392f2e5c34415ad0bb4709227445f3cad1d2444b57a90fa645f1488e063a`.  Its five
stores are decoded as one `XZR` zero plus argument-sourced values from `X0`,
`X1`, `X2` and `W3`, reaching static globals `0x9fc38360`, `0x9fc38370`,
`0x9fc38378` and `0x9fc38350` (the slot interpretation remains a prior
candidate-segment inference).

The exact XBL has one direct `BL` caller at `0x9fc023f0`.  The 20-byte
pre-call block `[0x9fc023e0,0x9fc023f4)` is pinned to hash
`2c33e795998978ddc8ddd01c1b168abb24033aa78f168ea73ef73ac4c335bef5`; its
linear model resolves:

```text
W3 = MEMORY[incoming X0 + 0x10]  (32-bit)
X0 = MEMORY[incoming X0 + 0x18]  (64-bit)
X1 = MEMORY[incoming X0 + 0x20]  (64-bit)
X2 = MEMORY[incoming X0 + 0x28]  (64-bit)
```

The 92-byte surrounding context is also hash-pinned.  The `LDP X0,X1,[X0,#0x18]`
case is evaluated with the address base read before destination registers are
updated.  Unsupported forms, unresolved origins, changed range hashes and a
non-singleton direct-caller census fail closed.

## Classification

`PROVED`: exact input/range identity, five-store setter shape, singleton direct
caller and symbolic field origins above.  `SUPPORTED`: the setter/caller edge
is reproducible in the bounded linear model and is compatible with the prior
candidate DDR-segment inference.  `HYPOTHESIS`: the incoming object may be a
runtime configuration object.  `UNKNOWN`: runtime origin and values, boot
execution/currentness, field type and register semantics, alternate/indirect
callers, post-boot mutability/locks, physical-to-DRAM mapping, protected reach
and alias/bypass.

`CLASS C (TRANSFORM ONLY)` remains unchanged; this host result is
`NOT_ELIGIBLE` for numbered 015/016 and does not authorize any live write.

## Artifacts and verification

The sanitized manifest is
`evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json`, 9,171
bytes, mode `0644`, SHA-256
`edf62eb6c1d97a8113f5ba0894548e9d5fafc83eeefbc7976c808b0f7886c051`.

Focused tests: 9/9 PASS.  The full serial repository suite is 1,160/1,160 PASS
(`skipped=1`) in 116.197 seconds, maximum RSS 290,560 KiB, with zero swap.
Python byte-compilation, public JSON parse, no-private-path scan, no-clobber
publication and byte-identical regeneration all PASS.  The final independent
hostile review is recorded below before the artifact is committed.

## Independent hostile review

`PASS`.  The independent review confirmed the decoder masks, symbolic
overwrite ordering (including LDP base-before-destination semantics), exact
pins, public/private split, and the preserved `CLASS C`/`UNKNOWN` boundaries;
no device action occurred.
