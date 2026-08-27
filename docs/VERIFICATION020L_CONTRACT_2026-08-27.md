# Verification 020L contract — branch-target landing words

Re-derive the exact 020K caller-context barrier inventory from the pinned A90
XBL and inspect exactly one word at each of seven unique conditional target
VAs. Decode only strict ADRP, unsigned LDR, logical-immediate, MOV-register,
and scalar LDP/STP fields. Require `va % 4 == 0` before reading or decoding a
landing word, then require an executable file-backed segment; reject unknown or reserved encodings. No trace, runtime
claim, device access, SMC, MMIO, normal/protected-memory or firmware write is
permitted.

Inputs are XBL `xbl--sdb1.bin` (4,194,304 bytes,
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`), the
020K manifest (9,961 bytes,
`90a0cf4d264c64d0d2836b567a2dc8ac5abff7809be839e5131fc7e91e32975a`), and
020K source (19,309 bytes,
`efe1a4dd062bd76adfe3f535f441e86fc74a36c105433c884296f648ae5e4ae1`).
Imported decoder sources are independently pinned: 020D (21,053 bytes,
`5a315f8735c38c86147367a1ad7c953d263d58c4bc63251473fa565e15efb332`) and
020F (23,772 bytes,
`b1f12fb516b52e3b15168e61930d407f08788dd2379fa330b9f2220fc2cf3a53`).
All are regular-file, no-follow, stable size/hash checked; public output is
redacted to per-word hashes. Missing, changed, ambiguous, non-executable, or
unsupported inputs fail closed. Outcome is `CLASS C (TRANSFORM ONLY)` and
`NOT_ELIGIBLE`; rollback/recovery are not applicable.
