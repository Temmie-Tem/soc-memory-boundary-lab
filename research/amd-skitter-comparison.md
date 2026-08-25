# AMD Skitter vs. SM8150: Attack-Class Comparison

| Property | AMD primary PoC | SM8150 current evidence |
|---|---|---|
| Tested silicon | `PROVED`: AMD Family 16h | `PROVED`: exact SM-A908N/SM8150; normal-RAM transform measured, complete-coordinate alias not tested |
| Transform state | `PROVED`: named bank-map/swizzle/swap registers | `PROVED`: live low-24 XOR bank-selection relation plus coherent MCCC/MC SHRM words; mapping from relation to a named register remains `UNKNOWN` |
| Normal-world visibility | `PROVED`: PoC reads PCI config state | `PROVED` behaviorally through non-secure ION timing; direct EL1 register/SHRM load is blocked. XBL can export SHRM after reset, not as a normal-HLOS runtime API |
| Normal-world mutation | `PROVED`: PoC changes and restores state | `REFUTED` for the observed section-16 SHRM path: both direct consumers pass read direction; Normal-World mutation remains `UNKNOWN` by other routes |
| Transform math | `PROVED`: XOR constraints/GF(2) solver | `PROVED`: diagnostic model is direct/no-XOR, but live silicon bank row space has XOR terms from PA16..23; one equivalent basis is `0x9d2000/0xa74000/0x4e8000` |
| Cache control | `PROVED`: UC mapping, flushes, fences, one core | `PROVED`: non-secure write-combine ION mapping, one pinned CPU, fixed DDR governor and symmetric baselines; cached/DC-CIVAC-only path `REFUTED` as sufficient |
| Security decision ordering | Attack premise demonstrated for AMD target | `UNKNOWN`: SCM consumes PA ranges, enforcement placement unknown |
| Deterministic alias | `PROVED` for the AMD test platform | `REFUTED` for the bounded XBL formula; the observed bank hash does not itself establish full-coordinate alias; silicon alias remains `UNKNOWN` |

The structurally common question is whether mutable decode state lies after the
address used for ownership/security decisions. Everything below that abstraction
must be rediscovered.

`REFUTED`: Similar existence of channel/bank hashing implies the same
vulnerability. A transform may be immutable, secure-only, integrity checked, or
followed by a second protection check.
