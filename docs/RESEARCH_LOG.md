# Research Log

## 2026-08-25 — Phase 0/1 reconnaissance

1. `PROVED`: Read the existing project `AGENTS.md`, A90 target/goal contracts,
   and the six requested reports. The old repository was not modified. Its
   currently observed HEAD was `510d909eff0fe10e48f3bfff573bc17f59f0656a`;
   exact private artifacts are additionally bound by SHA-256 because they are
   not assumed to be tracked by that commit.
2. `PROVED`: Initialized this repository on local branch `main`; it has no Git
   remote, and raw evidence/device identifiers/firmware patterns are ignored.
3. `PROVED`: Revalidated RKP/UH/KDP config, exact `rkp_init()` callsite,
   `uh_call -> smc #0`, secure-buffer/SCM physical-range assignment, exact
   rebuild symbols and independently extracted stock symbols.
4. `REFUTED`: “The A90 self-built kernel disabled all RKP.” Only treating
   CFP/JOPP/ROPP as separately discussed is insufficient; all named RKP paths
   are enabled in the exact defconfig.
5. `PROVED`: Read AMD primary repository and pinned observed `main` to
   `6363c2e9721eae82e93ff2e6035e01ee6b01c463`; recorded its Family 16h
   registers, critical section and GF(2) solver without importing those
   implementation details into Qualcomm.
6. `PROVED`: Reconstructed source-visible SM8150 LLCC, LLCC-to-EBI, DDRSS CNOC,
   bandwidth monitor and AOP paths. No SM8150-specific Linux source found that
   programs CPU-PA to channel/rank/bank/row/column mapping.
7. `SUPPORTED`: Final mapping initialization is outside the inspected Linux
   source. This is not `PROVED` until the exact XBL/AOP/DDR firmware artifact and
   write call graph are acquired.
8. `REFUTED`: `mc_virt-base 0x09680000` is automatically the final memory
   controller MMIO base. The provider is virtual/bypass and upstream describes
   the range as unused/arbitrary for that driver.
9. Implemented dependency-free GF(2) tools and a binary-safe read-only A90
   snapshot collector. Ten unit tests passed. Collector SHA-256 at capture time:
   `e05fd1667c23888be743123f6b3791fbec8cbac24adcb4e296bc6b495f672084`.
   The committed EOF-normalized file is
   `aa6eaf9f2595dddb7e79ee4b6627dacdf95768a51ea3b2ca7b94475881f632b5`;
   the only byte difference is removal of one trailing blank line.
10. `PROVED`: Experiment 001 captured 12 successful read-only frames. Raw data is
   mode `0600`, ignored by Git, and represented by a redacted hash manifest.
11. A single transient UI `hide` command had been used before the new collector
    to release a busy automatic menu. It did not access memory/controller state.
    Experiment 001 itself issued only its fixed read-only allowlist.
12. `PROVED`: The temporary A90-pinned bridge on port 54322 was stopped after
    collection. The other attached Samsung endpoint received no command.

## Missing artifacts

- `REFUTED`: Exact on-device XBL/AOP/hyp/tz/config firmware is unavailable.
  Experiment 004 captured nine exact live artifacts with triple hash agreement.
- `PROVED`: QHEE/hyp firmware bytes and provider provenance are now bound to the
  live `hyp` partition and live `hyp_mem` load range.
- `UNKNOWN`: Live boot image and DTB byte hashes.

## 2026-08-25 — Experiment 004 live firmware acquisition

1. Rebound the exact A90 USB ACM endpoint and started a dedicated loopback-only
   bridge. The other attached Samsung endpoint was untouched.
2. Implemented a fixed-allowlist collector. It rejects arbitrary partition names,
   requires GPT/sysfs identity, exact expected size and `ro=1`, and parses binary
   frames by advertised byte count rather than delimiter search.
3. One initial smoke stopped before block data access because the host parser did
   not accept a successful zero-payload `mknodb` frame. The possible temporary
   node was immediately removed and absence verified. The parser and unconditional
   cleanup path were repaired and covered by a regression test.
4. A 128 KiB `devcfg` smoke then passed with equal device-before, host and
   device-after hashes and verified node cleanup.
5. Full capture acquired nine artifacts totaling 26,779,648 bytes. All triple
   hashes matched; five historical hashes also matched.
6. Post-capture `/dev` contained no temporary node, native selftest reported
   `fail=0`, and the bridge was stopped.
7. First-pass static analysis proved XBL DDR/DSF/DCB ownership, exact AOP DDR
   management, `hyp`-partition QHEE provenance, and concrete TrustZone names for
   BIMC/MEMNOC/LLCC MPUs. No transform register or bypass was claimed.
8. Exact loader disassembly and a reproducible DCB inventory proved four
   `0x3404` DCBs at DSF `0x00650000`. XBL consumes five section indexes and
   copies section 16 to `0x09065100`; SHRM consumption and final-map semantics
   remain `UNKNOWN`.
