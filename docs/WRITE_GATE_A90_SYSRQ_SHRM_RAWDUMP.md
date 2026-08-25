# WRITE GATE — A90 one-shot SysRq panic to filtered SHRM rawdump

Date: 2026-08-25

Target: `SM-A908N` / `SM8150`, bootloader `A908NKSU5EWA3`
Operator authorization: explicitly approved rapid live testing on the owned A90.

## Decision

`APPROVED_FOR_ONE_SYSRQ_C_EFFECT_WITH_QDL_ALREADY_WAITING`

## Exact target and action

- Kernel pseudo-file: `/proc/sysrq-trigger`
- Payload: one ASCII byte `c`
- A90P1 action: `writefile /proc/sysrq-trigger c`
- Dispatch count: one; no retry after any accepted BEGIN frame or disconnect.
- Required persistent state before dispatch: captured `param.debuglevel=MID`,
  `force_upload_flag=0`, `FMM_lock=0`, `dump_sink=0`.

## Source provenance and expected effect

- Exact A90 defconfig has `CONFIG_MAGIC_SYSRQ=y` and default enable `0x1`.
- Exact `drivers/tty/sysrq.c` maps `c` to `panic("sysrq triggered crash")`.
- Exact `sec_debug_panic_handler` writes restart reason `0x776655ee`, enables
  dload through `set_dload_mode(1)`, and performs the Samsung hardware reset.
- Exact `msm-poweroff.c` uses full-dump type `0x10`; live download mode is `1`.
- Exact main XBL selects dload on saved cookie bits `4/5` or restart reason
  `0x776655ee`; exact XBLRamDump then admits MID with force-upload zero.
- Exact rawdump table index 19 exports 64 KiB as `SHRM_MEM.BIN`.

## Collector and measurement

- The official linux-msm/qdl `v2.8` release binary is pinned by SHA-256
  `8066d34f2aefdfa64afa43a44c630a5e43a6b9da991d2b0b4dae5acaf0da26e5`.
- QDL must be running before dispatch with exactly one filter:
  `SHRM_MEM.BIN`.
- The output must be exactly 65,536 bytes and reproduce the proved section-16
  workspace header before any controller word is interpreted.
- USB identity and the complete qdl transcript are retained privately.

## Risks

- Brick risk: low; no bootloader, firmware, GPT, RPMB, QFPROM, XPU, SMMU, EL2,
  or EL3 state is written. Panic/reset behavior itself is intentional.
- Data-loss risk: low but non-zero from an abrupt reset. Native root is the
  existing research environment; no unrelated user-data operation is running.
- Operational risk: transport may be non-Sahara or qdl may fail. The device may
  remain at the rawdump screen and require its documented `RDX EXIT` key path.
- Security-boundary risk: only the allowlisted 64-KiB SHRM descriptor is
  requested. No full RAM, keys, credentials, or unrelated protected data is
  collected.

## Rollback and recovery

1. On successful qdl collection, qdl sends the Sahara reset; the dload cookie
   bits are consumed and cleared by main XBL.
2. When native init returns, restore `param.debuglevel` MID→LOW once and require
   the full original partition SHA-256
   `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345`.
3. If USB uses an unsupported protocol, do not repeat the panic. Record the
   enumerated identity and use XBL's displayed `RDX EXIT` (`VOL_DOWN + POWER`
   for three seconds) or the established Download/TWRP recovery route.
4. If the effect outcome is ambiguous, inspect USB/native state first; ambiguity
   is never a replay trigger.

## Why necessary

Static analysis and normal-reboot validation prove both gates and MID
consumption, but only an actual bootloader dump can determine whether the exact
retail transport exports the descriptor and whether SHRM populated its staged
controller words at collection time.

## Recorded outcome

`PROVED`: the one-shot panic entered `04e8:685d / MSM_UPLOAD`, not Qualcomm
`05c6` Sahara, so the already-waiting qdl process captured no file and was
terminated without touching the Samsung endpoint.

The existing authorization covered the same already-triggered, recoverable
dump session. A pinned upstream Samsung Upload client was then used to select
only catalog record 19. It acquired exactly one 65,536-byte `SHRM_MEM.BIN`,
SHA-256
`409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7`.
No second panic and no full-memory collection occurred. The device was sent
the protocol power-down command, returned to native runtime, and was restored
to LOW with full-partition hash and post-reboot health verification.
