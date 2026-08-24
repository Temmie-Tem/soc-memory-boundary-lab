# Experiment 004 — Live Boot-Firmware Read-Only Acquisition

Result: `PROVED`.

On 2026-08-25 KST, the exact owner-controlled `SM-A908N` was pinned by its
stable USB ACM identity. Live GPT/sysfs metadata selected only the following
`ro=1` partitions:

- `xbl`: `sdb1`, `sdc1`
- `xbl_config`: `sdb2`, `sdc2`
- `aop`: `sdd7`
- `devcfg`: `sdd22`
- `tz`: `sdd5`
- `hyp`: `sdd33`
- `abl`: `sdd8`

For each artifact the collector created a temporary block node under `/dev`,
ran device-side SHA-256, streamed the exact advertised byte count with A90P1
`cat`, ran device-side SHA-256 again, required all three hashes to match, and
removed the node. No partition was opened for write.

The nine raw files total `26,779,648` bytes. They are mode `0600` under
`evidence/private/004-live-firmware-readonly-20260825-01/` and are ignored by
Git. The redacted manifest is
`../../evidence/manifests/004-live-firmware-readonly-20260825-01.manifest.json`,
SHA-256
`1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247`.

The earlier hashes for `xbl` A/B, `aop`, `devcfg`, and `abl` all matched their
2026-06-02 measurements. Post-capture `/dev` inventory contained no
`sdm855_mblab_*` node, native selftest reported `pass=11 warn=1 fail=0`, and the
dedicated bridge was stopped.
