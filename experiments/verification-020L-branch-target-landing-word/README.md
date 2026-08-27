# Verification 020L — branch-target landing-word inventory

This bounded, host-only pass re-derives the exact 020K result and inspects one
little-endian instruction word at each of its seven unique conditional target
VAs. Its `va % 4 == 0` gate runs before the landing word is read or decoded;
the word must also be in the same executable file-backed segment before strict
family/operand decoders run. It does not
trace beyond a landing word or contact a device, SMC, MMIO, RAM, or firmware.

The exact inputs are the pinned 4,194,304-byte A90/SM8150 XBL
(`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`), the
020K manifest (`90a0cf4d264c64d0d2836b567a2dc8ac5abff7809be839e5131fc7e91e32975a`),
and the 020K producer source (`efe1a4dd062bd76adfe3f535f441e86fc74a36c105433c884296f648ae5e4ae1`).

Expected landing families are ADRP at `0x9fc264d0` and `0x9fc26ca4`,
LDR_UNSIGNED at `0x9fc26594`, logical-immediate at `0x9fc26b64` and
`0x9fc280e4`, MOV_REGISTER at `0x9fc282b4`, and scalar LDP at `0x9fc2c3bc`.
Raw words are published only as hashes. Classification remains `CLASS C
(TRANSFORM ONLY)` / `NOT_ELIGIBLE`; runtime meaning, execution, pointer/PA,
MMIO/DRAM identity, mutability and protected reach remain unknown.

The focused suite is 7/7 PASS, including a negative proving an unaligned
landing VA is rejected before the image word read. No device command or write
is part of this experiment.
