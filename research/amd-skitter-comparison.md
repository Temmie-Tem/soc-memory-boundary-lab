# AMD Skitter vs. SM8150: Attack-Class Comparison

| Property | AMD primary PoC | SM8150 current evidence |
|---|---|---|
| Tested silicon | `PROVED`: AMD Family 16h | `PROVED`: target is SM8150; no alias test yet |
| Transform state | `PROVED`: named bank-map/swizzle/swap registers | `UNKNOWN`: exact register/state |
| Normal-world visibility | `PROVED`: PoC reads PCI config state | `UNKNOWN`: no final-map register identified |
| Normal-world mutation | `PROVED`: PoC changes and restores state | `UNKNOWN`: no relevant write attempted |
| Transform math | `PROVED`: XOR constraints/GF(2) solver | `HYPOTHESIS`: GF(2) may fit; Qualcomm patents are not chip proof |
| Cache control | `PROVED`: UC mapping, flushes, fences, one core | `SUPPORTED`: equivalent controls can be built in EL1; not run |
| Security decision ordering | Attack premise demonstrated for AMD target | `UNKNOWN`: SCM consumes PA ranges, enforcement placement unknown |
| Deterministic alias | `PROVED` for the AMD test platform | `UNKNOWN` on SM8150 |

The structurally common question is whether mutable decode state lies after the
address used for ownership/security decisions. Everything below that abstraction
must be rediscovered.

`REFUTED`: Similar existence of channel/bank hashing implies the same
vulnerability. A transform may be immutable, secure-only, integrity checked, or
followed by a second protection check.
