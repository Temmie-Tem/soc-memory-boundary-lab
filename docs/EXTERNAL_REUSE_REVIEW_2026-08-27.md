# External reuse review — BadRAM, DisARMed, PMPlease, Battering RAM

A proposal reached this project recommending that three external artifacts be
ported into it: DisARMed's alias scanner and QEMU patch, PMPlease's
alias-reversing tools, and BadRAM's methodology, with DisARMed and PMPlease
rated "very high" reusability. This is the verification of that proposal
against the primary sources and against what this repository already contains.

## What was checked, and how

| Source | Route | Retrieved |
|---|---|---|
| PMPlease paper | `vanbulck.net/files/uasc26-pmplease.pdf` | full text |
| PMPlease artifact | `github.com/dnet-tee/PMPlease` + GitHub API | README, tree, license |
| DisARMed artifact | `raw.githubusercontent.com/bhamsec/disarmed` | README verbatim, tree, license |
| DisARMed paper | Durham repository, USENIX WOOT '26 | **not retrieved** — both HTTP 403 |
| Battering RAM | search results only | not fetched |

Everything below that rests on the DisARMed paper rather than its README is
marked `UNVERIFIED`.

## `REFUTED`: that these are four different primitives

They are one. Every alias in all four works is created by tampering with the
DRAM topology metadata of a **socketed module**, or by interposing on its bus.

- **PMPlease** is BadRAM applied to RISC-V PMP. Louka, De Meulemeester,
  Keuchel, Verbauwhede and Van Bulck, uASC '26, KU Leuven. The paper describes
  BadRAM as leveraging "limited one-time physical access to configure malicious
  DRAM topologies" by "deliberately modifying DRAM size metadata reported by
  individual Dual In-line Memory Modules (DIMMs) during system boot". The
  artifact ships scripts for a Raspberry Pi Pico wired to a DDR4/DDR5 socket.
- **DisARMed** is the same primitive on ARMv8-A. Its README states that
  `uefi-scan` exists "to help determine the outcomes of **SPD modification** on
  ARMv8-A platforms", and that all three test platforms — ARM Morello SDP,
  Ampere Altra DP, NXP LS1046ARDB — have "16GB of memory installed, **modified
  to appear as 32GB**".
- **Battering RAM** is a DDR4 interposer.

SM8150 on this target has soldered LPDDR4X. There is no DIMM, no socket, no SPD
EEPROM and no bus to interpose on. The alias-**creation** side of all four works
is not transferable, and the proposal's "very high" ratings for DisARMed and
PMPlease do not survive.

## `REFUTED`: that a marker sweep is an oracle for the question this project asks

The proposal's central claim is that these works supply an "actual-alias oracle"
this project lacks, and that it is a stronger instrument than timing for the
same question. The second half is right about instruments and wrong about the
question.

A BadRAM alias is a **non-injective** map: two physical addresses resolve to one
cell, statically, within a single state. A marker sweep detects exactly that.

Skitter-class remapping is a **permutation**. `docs/PRIOR_ART.md` already states
the model: an alias candidate `a` must satisfy `Me a = Mf t` across two states
`Me` and `Mf`. XOR of an address bit is a bijection, so in **any single state**
every marker reads back precisely where it was written. A single-state marker
sweep is blind to a permutation by construction, no matter how large the sweep.

`docs/NORMAL_RAM_ALIAS_DESIGN.md` has said this since it was written: under
unchanged state `S0`, distinct PAs "must remain distinct", and the alias is
expected only under a candidate state `S1`. The marker oracle is a **baseline
control** in this project's own design, not a discovery instrument.

## `REFUTED`: that the alias-detection artifacts fill a gap this repository has

`docs/NORMAL_RAM_ALIAS_DESIGN.md` already specifies a marker-based alias
protocol with a control set strictly stronger than DisARMed's or PMPlease's:
PFN-proved distinct pages, a same-PA virtual-alias positive control, a
distinct-PA negative control, alternating marker/inverse trials, explicit
cache-artifact exclusion via clean/invalidate and fences, cacheable and
non-cacheable agreement, and DMA/IOMMU exclusion. Neither external scanner
carries any of the last four, because a boot-time firmware scanner does not
need them.

What is missing here is an **implementation**, not a design, and not a design
that had to be imported.

## `SUPPORTED`, in the proposal's favour: one point stands

A cross-state **marker** test would be strictly stronger than the cross-state
**timing** test Verification 015 ran. Row-conflict timing observes only the
rank-3 bank class — three bits. A state change that permuted rows or columns but
left the bank class alone would read `INVARIANT` to Verification 015 and be
caught by markers. That is a real gap in 015 and the proposal identified it.

It is nonetheless blocked, and at the far end rather than the near end. A reboot
destroys the allocation, so no marker survives it, and `pagemap` is `BLIND` for
dma-buf so the physical backing cannot be re-identified. The only runtime state
change this project can cause was retracted in `b2b5068` as vacuous — the DDR
OPP never moved, because `disp_rsc_ebi` votes 12.8 GB/s statically from boot.
There is no surviving pair of distinct states to compare, so there is nothing
for the stronger instrument to measure.

## The transfer that does exist, and where it lands

The reusable idea in this body of work is not a scanner. It is one sentence of
threat model. PMPlease §7.1: the root cause is "the system's blind trust in the
memory controller configuration, which trusts the topology information reported
by the DIMM's SPD chip", and §7.1.3 extends it explicitly — "firmware must
accurately report the memory topology, thus a compromised or tampered firmware
could misreport these parameters to induce comparable aliasing effects". Its
attacker model covers "scenarios where aliases are introduced entirely by a
privileged software adversary".

On this target the SPD-equivalent is not an EEPROM. Experiment 008 `PROVED` that
retained XBL records select DCB `/6003_0200_1_dcb.bin`, report two 3072-MiB
ranks, and that mask `0x3` with total 6144 MiB uniquely chooses remapper row 7
with destinations `0x80000000` and `0x140000000`. The topology metadata this
memory controller blindly trusts is **a file in a flash partition**. No physical
access, no socket, no Pico.

That is a genuine structural transfer, and it lands squarely inside the
forbidden set. The DCB is carried in the XBL config image, and
`docs/THREAT_MODEL.md` lists `xbl_config` among the partitions that stay
forbidden. The reason is exactly the one the standing authorization carves out:
a misreported DDR topology fails training inside XBL, before any recovery path
exists, and that failure has no route back that does not require a signed
programmer.

`UNKNOWN` and to stay that way: whether a modified DCB would in fact produce a
BadRAM-class alias on SM8150. It is not eligible for testing under this
project's contract and should not be designed for.

One consistency note, weak but worth recording. Experiment 011 `PROVED` XBL's
own rank-relative bit partition to be complete, non-overlapping and invertible,
and `REFUTED` that it admits two PAs for one coordinate. Firmware's model of its
own DRAM contains no alias under the shipped DCB. That is a statement about the
model, not about silicon.

## Licensing blocks vendoring either artifact

Both repositories carry **no license**. GitHub's API returns `license: null` for
`bhamsec/disarmed` and for `dnet-tee/PMPlease`. Absent a license, all rights are
reserved and neither may be copied into this repository. The proposal's
`tools/alias_oracle/` layout would have vendored unlicensed code.

Algorithms 1 and 2 are published in the PMPlease paper and may be reimplemented
from its description with citation. That is the only permitted route, and it is
also the cheaper one — Algorithm 2 is roughly ten lines.

## The QEMU positive control is disproportionate

`qemu.patch` targets QEMU 9.2.3 and emulates the aliasing observed on DisARMed's
own platforms. Any detector this project runs targets an ION dma-buf on SM8150
through the V2321 bridge. Nothing is shared between the two except the
comparison loop. The proposal's claim that the *same* detector could be pointed
at both is not accurate.

An in-process fake backend with an injectable alias gives the identical
guarantee — a detector that must fire on a known-positive and must not fire on a
known-negative — in about thirty lines, with no QEMU build, no patch against a
specific QEMU version, and no unlicensed code.

## One recommendation

Add an Algorithm-2 marker mode to `tools/a90_region_probe_r.c`.

Same allocation Verification 016 already proved — `camera_preview`, 256 MiB —
same offset loop, different oracle. Write a random 64-bit marker at offset `A`,
then read at `A xor (1 << i)` for `i = 6..27` and compare. Twenty-two reads. The
buffer is mapped write-combine, so the cache-artifact class
`NORMAL_RAM_ALIAS_DESIGN.md` warns about is largely sidestepped rather than
argued away. Positive and negative controls come from a fake in-process backend.

It is worth doing despite an expected null result, for four reasons:

1. It implements the baseline control that `NORMAL_RAM_ALIAS_DESIGN.md` makes a
   **precondition** of any future alias claim. That control is currently
   unimplemented, so no alias claim could presently be defended.
2. It is this project's first **storage-identity** evidence. Everything to date
   is row-conflict timing, which cannot distinguish two addresses in one bank
   class from two addresses in one cell.
3. Verification 017's argument assumes the map is injective over the measured
   span. This measures that assumption instead.
4. It costs one allocation, no new device capability, and no new risk class.

Its limit should be stated before it runs, not after: it covers PA6..PA27 at one
physical base. A density-inflation alias puts its ghost bit at the **top** of the
address space — PA32/PA33 for this 6 GiB target — and 256 MiB cannot vary those.
This is the same wall Verification 016 hit at PA28, for the same reason.

## Ranking

`REFUTED`: that the alias-creation primitive of BadRAM, DisARMed, PMPlease or
Battering RAM transfers to this target. All four require a socketed module or
its bus.

`REFUTED`: that a single-state marker sweep is an oracle for Skitter-class
remapping. It is blind to a permutation by construction.

`REFUTED`: that these artifacts supply an alias protocol this repository lacked.
`docs/NORMAL_RAM_ALIAS_DESIGN.md` predates them and is stricter.

`PROVED`: that neither artifact repository carries a license, so neither may be
vendored.

`SUPPORTED`: that a cross-state marker test would be a stronger instrument than
Verification 015's cross-state timing test. Blocked for want of a state change,
not for want of an instrument.

`SUPPORTED`: that DCB topology metadata is this target's structural analogue of
SPD, and is software rather than an EEPROM. Forbidden, and recorded rather than
pursued.

`UNKNOWN`: DisARMed's paper text, including the proposal's claim of a ~1 second
scan of 32 GB. The page-granular figure is plausible on arithmetic — roughly
8M row activations per pass — but both retrieval routes returned 403 and it is
`UNVERIFIED` here.

Class C `TRANSFORM ONLY` is unchanged. Nothing in this review is a bypass, an
alias or a mutation.
