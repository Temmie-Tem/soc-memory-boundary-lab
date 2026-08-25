# Verification 003/004 — A90 Raw-Dump Eligibility

## Question

Does the current exact V2321 A90 boot expose positive entry signals for the XBL
`SHRM_MEM.BIN` raw-dump path recovered by Verification 002?

This is a property-free A90 counterpart to the upper project's S22+ read-only
reset-reason probe. Target profiles and transports were not transferred:

- S22+ precedent:
  `/home/temmie/dev/android-native-init-lab/workspace/public/src/scripts/revalidation/s22plus_reset_reason_readonly_probe.py`
- A90 transport: the existing target-pinned loopback A90P1 ACM bridge
- Android `getprop`: absent from this design and never invoked

The first pass used the five precedent paths exactly. Host analysis of the exact
A90 4.14 source then identified the generation-specific download-mode owner,
and one second read added only that fixed source-backed path.

## Safety and binding

Both passes first required the exact response:

```text
version: 0.9.285 build=v2321-usb-clean-identity-rodata
kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64
```

The host bridge was already listening on `127.0.0.1:54321`, pinned to
`/dev/ttyACM0`, whose stable by-id target was `A90-LNX / A90 Linux ARM64` and
USB role `04e8:6861`. A separate Samsung `04e8:6860` endpoint existed but
received no command: the probe does not invoke ADB.

Each command was compile-time fixed. No command was retried. There was no
write, reboot, service action, property lookup, MMIO, SMC, payload, partition,
EL2/EL3 runtime, or protected-memory access.

## Verification 003 — exact S22+ surface pass

Public manifest:
`evidence/manifests/verification-003-a90-rawdump-eligibility-20260825-01.manifest.json`

`PROVED` live:

| Surface | Result |
|---|---|
| `/proc/cmdline` | `androidboot.debug_level=0x4f4c`, `androidboot.force_upload=0x0`, `androidboot.boot_recovery=0` |
| `/sys/module/qcom_dload_mode/parameters/download_mode` | absent, `rc=-2` |
| `/sys/module/ramoops/parameters/max_reason` | absent, `rc=-2` |
| `/sys/module/kernel/parameters/panic` | `-1` |
| `/sys/module/kernel/parameters/panic_on_warn` | `0` |

The preliminary classification was `DUMP_ENTRY_SIGNALS_INCOMPLETE`: debug
level is `LOW`, force-upload is disabled, and the S22+ download-mode path is not
the A90 path.

## Why the S22+ module path is absent

The exact Samsung A90 4.14 source file
`Kernel/drivers/power/reset/msm-poweroff.c`, SHA-256
`0a2b20ecc358936d5a55a9936210345823ffe767768e9287a916502a3abc3d79`,
contains:

- line 87: `static int download_mode = 1;`
- lines 124–125: `module_param_call(download_mode, ...)`
- Makefile line 17: `msm-poweroff.o`

The source-backed parameter is therefore
`/sys/module/msm_poweroff/parameters/download_mode`, not the newer S22+
`qcom_dload_mode` path.

The previously captured live `/proc/config.gz`, payload SHA-256
`ff2543fee33573e8efe34110598e963d7ddc9c44fbbf5dc1256cd6edec0f8fde`,
independently contains:

```text
CONFIG_QCOM_DLOAD_MODE=y
# CONFIG_QCOM_MINIDUMP is not set
CONFIG_PSTORE=y
CONFIG_PSTORE_RAM=y
CONFIG_PANIC_ON_OOPS=y
CONFIG_PANIC_TIMEOUT=-1
```

Thus absence of the S22+ module path is generation/owner drift, not proof that
Qualcomm dload support is absent. Likewise, absence of the newer ramoops
`max_reason` module parameter does not refute A90 pstore/last-kmsg retention.

## Verification 004 — A90 source-backed continuation

Public manifest:
`evidence/manifests/verification-004-a90-rawdump-eligibility-sourcebacked-20260825-01.manifest.json`

The continuation repeated the exact target bind and fixed reads, adding only:

```text
cat /sys/module/msm_poweroff/parameters/download_mode
```

It returned `1`.

### Final observed signals

| Dimension | Exact value | Verdict |
|---|---:|---|
| debug level | `0x4f4c` = `LOW` | `NEGATIVE` |
| force upload | `0x0` | `NEGATIVE` |
| A90 dload master switch | `1` | `POSITIVE` |
| FMM/policy/token | not exposed by bounded surfaces | `UNKNOWN` |

Final classification:

```text
DUMP_ENTRY_SIGNALS_INCOMPLETE
actual_xbl_rawdump_eligibility = UNKNOWN
```

`PROVED`: current visible signals do not justify a reset/dump collection
attempt. This does not prove XBL could never dump; it proves the current boot is
not positively qualified by the available entry signals.

## Panic and retention interpretation

`PROVED` from exact live value plus exact kernel source: `panic=-1` skips the
positive delay loop and reaches `emergency_restart()` because the timeout is
nonzero (`kernel/panic.c:277–303`). A deliberate panic would therefore reboot
immediately, which is compatible with a dump-entry experiment only after its
gates are qualified.

`PROVED`: `panic_on_warn=0`, so a WARN is not currently a panic trigger.

`UNKNOWN`: actual FMM/token state and whether the workspace is populated when
XBL collects it. Prior-boot preservation is not required: freshly repopulated,
stale, or zero staged words are all experimentally distinguishable outcomes.

## Relation to Experiment 014 and the completed decoder

The tracks remain complementary:

```text
SHRM_MEM.BIN decoder/export     -> direct 494 controller-word values
Experiment 014 conflict timing -> behavioural PA-to-bank/channel row space
```

Experiment 014 is already `HOST_READY / DEVICE PHASE NOT RUN`; its model and
synthetic controls are committed independently. Commit `9fdd5d6` completed the
host-only decoder: its 20 focused tests prove the `430/64` plan, ordered labels,
bounds, value placement and invalid/zero-dump rejection. The plan does not
cover the separate remapper `+0x8080` window. Verification 012 later decoded a
real dump and qualified set 0; this paragraph records the earlier eligibility
state. Neither track substitutes for the other. Agreement would strongly
support the recovered mapping; disagreement would identify either an
unlabelled register interpretation or a hidden transform term.

## Next discriminator

Do not trigger a reset from the current state. The next cheapest work is
host-only recovery of the exact producers and reversible control path for
`androidboot.debug_level` and `androidboot.force_upload`, plus the FMM/token
gate. Only a separately bounded state change with a readback/rollback path can
make a later dump attempt informative.

## Reproduce parser tests

```sh
python3 -m unittest tests.test_a90_rawdump_eligibility_probe -v
```
