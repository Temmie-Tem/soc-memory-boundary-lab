# Verification 001 — Independent Claim Audit

## Question

Every `PROVED` statement in this repository is one agent's interpretation of the
exact retained firmware bytes, and Experiments 008–013 consume the conclusions
of 004 and 006 as pinned inputs. A wrong early interpretation would be inherited
by everything downstream.

Do the load-bearing static claims survive independent re-derivation from the raw
bytes?

This is not a forward experiment and does not take an Experiment number; 014–016
are already allocated in `docs/EXPERIMENT_MATRIX.md`. It is host-only and
performs no device, SMC, MMIO, partition, EL2, EL3, or protected-memory access.

## Why the existing evidence did not already answer this

The repository's three strongest internal quality signals verify the wrong
property for this question:

| Signal | Proves | Does not prove |
|---|---|---|
| 91 passing unit tests | the parsers are deterministic | the parse is correct |
| SHA-256 input pins | the inputs did not change | the interpretation is right |
| byte-identical regeneration | the tool is reproducible | the claim is true |

The audit therefore re-derives each claim from raw bytes without importing,
calling, or reusing any module in `tools/`. Structures are located by name and
value search and then walked, so a claim can fail here even when the original
tool reproduces byte-identically.

No disassembler for AArch64 or Xtensa was available on the host, so minimal
subset decoders were written for the audit (`ADRP`/`LDR`/`BL`/`RET`, and the
Xtensa RRR format).

## Exact inputs

- XBL: `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- TrustZone: `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`

Both measured hashes equal the values pinned by the prior experiments.

The public structural output is
`evidence/manifests/verification-001-independent-claim-audit-20260825-01.manifest.json`.

## Result

`7/7 CONFIRMED`. No substantive error was found in any audited claim.

| # | Audited claim | Source | Verdict |
|---|---|---|---|
| 1 | XBL/TZ artifacts match their pinned SHA-256 | Exp 006/012 metadata | `CONFIRMED` |
| 2 | `icbcfg_info` resolves to four `qhs_llcc + 0x8080` bases | Exp 006 | `CONFIRMED` |
| 3 | `DC_NOC_BROADCAST_MPU` region 11 covers `0x09248080` | Exp 009 | `CONFIRMED` |
| 4 | `DC_NOC_NON_BROADCAST_MPU` region 5 covers the SHRM workspace | Exp 013 | `CONFIRMED` |
| 5 | XPU disable SMC allowed-base count is zero | Exp 010 | `CONFIRMED` |
| 6 | SMC `0x0200030f` handler is a single `RET` | Exp 010 | `CONFIRMED` |
| 7 | SHRM helper computes `(base_page << 12) + (offset_token << 2)` | Exp 012 | `CONFIRMED` |

### Claim 3 resolved end to end

The full chain was walked rather than assumed:

```text
registry record   {id=0x3c, base=0x090e0000, name -> "DC_NOC_BROADCAST_MPU"}
      | matched by low 16 bits of the policy entry id 0x0001003c
policy entry      {base=0x090e0000, region_count=0x28=40, table -> 0x1c2f3b80}
      |
region 11 (32-byte record)
  index=0x0b  flags=0x09  read=0x80000000  write=0x00000000
  start=0x09248000  end_exclusive=0x09249000
      |
0x09248000 <= 0x09248080 < 0x09249000
```

Branch entries `0x1c1217a0` and `0x1c122628` produce byte-identical region
records. The 40-region count was confirmed by walking regions 0–39.

### Claim 7 resolved to the instruction encoding

```text
+0x24: 40 99 11  ->  slli  a9, a9, 12        ; base_page << 12
+0x3e: 90 cc a0  ->  addx4 a12, a12, a9      ; (offset_token << 2) + a9
```

Xtensa `ADDX4 ar, as, at` is `ar = (as << 2) + at`, so the pair is exactly the
claimed formula, and the four-byte scaling is carried by the instruction itself.

### Claim 5 is a compile-time constant

The handler at `0x1c0a9a44` calls the leaf query helper at `0x1c0a2630`, which
returns both the count and the array pointer from the fixed address
`0x1c122a90`. That location holds `0` in this exact image, so the handler's
`cbz` on the count is always taken and the disable path always returns `-16`.
The empty allowlist is static, not a runtime lookup result.

## Discrepancies found

No substantive error. Two notation issues worth recording:

1. The helper range `0x2d8dc..0x2d959` is **end-exclusive** (125 bytes). The
   pinned helper SHA-256 matches only at that length; it was located by
   exhaustive search over the blob rather than by assuming the convention.
2. `0x09248fff` does not exist as a stored value. The raw record holds
   end-exclusive `0x09249000`. The repository's inclusive rendering is correct
   but is an interpretation, not a raw field.

## Fact the prior write-ups underweight

Region 11's **write access word is `0x00000000`**: no client class holds write
permission, not merely no ordinary HLOS VMID. `DC_NOC_NON_BROADCAST_MPU`
region 5 is the same (`read=0x40000000`, `write=0x00000000`).

Neighbouring records in the same table show this is a deliberate configuration
rather than a default:

| Region | Range | read | write |
|---|---|---|---|
| 11 | `0x09248000..0x09248fff` | `0x80000000` | `0x00000000` |
| 12 | `0x09249000..0x0924bfff` | `0x40000000` | `0x40000000` |
| 13 | `0x0924e000..0x0924ffff` | `0xf0000000` | `0xf0000000` |

This is a stronger statement than the one the experiments recorded.

## Not audited

- QHEE `hyp_assign` stage-2/SMMU ownership path (Experiment 010).
- TrustZone dynamic `BIMC_MPU0..3` initializer (Experiment 010).
- XBL Quest DDR coordinate reporter formula (Experiment 011).
- SHRM section-16 callsites `0x288a9`/`0x28e15` and their 430/64 counts
  (Experiment 012).
- The permission-conversion routine mapping access words to VMID classes.

These need sustained function-level disassembly and were out of scope for a
bounded audit on a host without a disassembler.

## Interpretation

`PROVED`, bounded to the seven audited claims: the static facts recorded by
Experiments 006–013 are accurate to the exact bytes. The provenance concern that
motivated this audit — a single-source analysis chain consuming its own
conclusions — is substantially reduced for the checked claims.

`UNKNOWN`, unchanged: this audit verifies static facts, not their security
interpretation. It does not touch protection ordering relative to the final DRAM
transform, post-boot mutability, or lock state. The distinction that matters
remains that the confirmed evidence is about **reachability** — Normal World
cannot reach the controller apertures — and not about whether a mutable
transform sits downstream of the protection decision.

## Result line

```text
INDEPENDENT AUDIT — 7/7 CHECKED CLAIMS CONFIRMED
NO SUBSTANTIVE ERROR FOUND / SECURITY INTERPRETATION NOT AUDITED
```

## Reproduce

```sh
python3 tools/independent_claim_audit.py            # prints per-check verdicts
python3 tools/independent_claim_audit.py --replace  # regenerates the manifest
python3 -m unittest discover -s tests -q            # 125 tests
```

The tool exits non-zero if any audited claim stops matching the bytes.
