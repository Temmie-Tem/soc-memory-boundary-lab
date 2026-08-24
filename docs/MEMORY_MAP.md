# A90 Memory Map — Static and Live Evidence

Live snapshot: `001-baseline-live-20260825-01`

Raw private SHA-256:
`977320c895c0098d6de5ff6bead3baf1cf654b203687a60f804078a4b1305a18`

Redacted manifest:
`evidence/manifests/001-baseline-live-20260825-01.manifest.json`

## Exact live identity

- `PROVED`: runtime `v2321-usb-clean-identity-rodata`, init `0.9.285`.
- `PROVED`: `Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64`, Clang
  `10.0.7` as reported by live `/proc/version`.
- `PROVED`: live target model was operator-pinned `SM-A908N`; no command was
  sent to the other attached Samsung endpoint.
- `UNKNOWN`: hash of the boot image bytes actually executing. Host candidate
  `boot_linux_v2321_usb_clean_identity_rodata.img` has SHA-256
  `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb`,
  but it was not read back from the running boot chain.
- `UNKNOWN`: exact hash of the live flattened DT bytes. Live properties match
  several exact-source ranges, but equality is not inferred.
- `PROVED`: the live `hyp` partition is SHA-256
  `646f8fca08b0eff56b1d8415d81c3041a775c1871400dc57448cb5103405a8e1`;
  its ELF load/entry addresses fall inside the advertised `hyp_mem` range.
- `PROVED`: live SoC sysfs reports ID `339`, revision `2.2`, platform `MTP`,
  subtype `charm`, SMEM raw ID `165`, and raw version `3`.
- `REFUTED`: using those Linux SMEM raw fields as XBL's DCB selector. They do
  not match any exact `6003_{0100,0200}_{0,1}` CFGL entry.
- `PROVED`: live `/proc/config.gz`, compressed SHA-256
  `ff2543fee33573e8efe34110598e963d7ddc9c44fbbf5dc1256cd6edec0f8fde`,
  contains `# CONFIG_DEVMEM is not set`.

## Fixed reserved ranges

| Range | Size | Role | Evidence/status |
|---|---:|---|---|
| `0x85700000–0x85cfffff` | 6 MiB | `hyp_mem` | `PROVED` live DT `reg`; exact base DTS also has `no-map`. |
| `0xb0000000–0xb01fffff` | 2 MiB | TIMA | `PROVED` live DT; Samsung overlay has `no-map`. |
| `0xb0200000–0xb03fffff` | 2 MiB | RKP | `PROVED` live DT; Samsung overlay lacks explicit `no-map`. |
| `0xb0400000–0xb17fffff` | 20 MiB | `uh_heap_region` | `PROVED` live DT; node is boot-chain supplied relative to the inspected base source. |
| `0xa6000000–0xa83fffff` | 36 MiB | `qseecom_region` | `PROVED` live DT. It supersedes the generic base-DTS value for this target. |

Exact generic SM8150 source also declares XBL/AOP, SMEM, modem, ADSP, CDSP,
SLPI, WLAN, video, GPU, SPSS and other carveouts at
`sm8150.dtsi:578-757`. `SUPPORTED`: these nodes are part of the target's live
reserved-memory tree because their names were observed live. Each uncollected
live `reg` value remains `UNKNOWN` rather than copied from the base DTS.

## `/proc/iomem` observations

`PROVED`: general `System RAM` spans observed fragments including:

```text
0x80000000-0x80000fff
0x80002000-0x856fffff
0x85d00000-0x85dfffff
0x85f40000-0x85ffffff
0x9c400000-0x9fffffff
0xa8400000-0xafffffff
0xb0200000-0xbcbfffff
0xc0000000-0xc10fffff
0xc1300000-0xc13fffff
0xc1c01000-0x1ffffffff
```

`PROVED`: `hyp_mem` is absent from the listed `System RAM`; the advertised RKP
range lies inside the broad `0xb0200000–0xbcbfffff System RAM` resource.

`REFUTED`: `/proc/iomem` labeling alone proves that RKP memory is normally
readable or unprotected. Resource-tree presentation is not an access test, and
RKP can impose runtime permission changes independently of `no-map`.

`PROVED`: live `MemTotal` was `5,504,940 kB`; this is a point-in-time software
accounting observation, not proof of physical DRAM topology.

## Boot-time SHRM and remapper landmarks

Experiment 006 adds exact firmware-backed physical landmarks:

| Range/address | Role | Evidence/status |
|---|---|---|
| `0x09050000` | `qhs_shrm_csr` | `PROVED` exact XBL topology. |
| `0x09060000` | `qhs_shrm_mem` | `PROVED`; DCB section 16 lands at `0x09065100` (`+0x5100`). |
| `0x09102000` | `qhs_shrm_mpu_cfg` | `PROVED` exact XBL topology; active policy `UNKNOWN`. |
| `0x09248080–0x092480d8` | qhs_llcc remapper instance 0 | `PROVED` exact XBL ICB writer. |
| `0x092c8080–0x092c80d8` | qhs_llcc remapper instance 1 | `PROVED` exact XBL ICB writer. |
| `0x09348080–0x093480d8` | qhs_llcc remapper instance 2 | `PROVED` exact XBL ICB writer. |
| `0x093c8080–0x093c80d8` | qhs_llcc remapper instance 3 | `PROVED` exact XBL ICB writer. |

The ranges describe 32-bit registers at four-byte offsets, not a license to
treat intervening or adjacent MMIO as discovered. Post-boot EL1 accessibility
and lock state remain `UNKNOWN`.
