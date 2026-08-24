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
