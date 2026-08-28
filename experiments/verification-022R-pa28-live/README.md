# Verification 022R - provenance-complete PA28 normal-RAM repeat

**Status: `EXECUTED / ACQUISITION_PASS / SUPPORTED_MODEL_EXTENSION`.** The
private same-run receipt and raw evidence are retained under `evidence/private/`
and the deterministic redacted manifest is public. `CLASS C (TRANSFORM ONLY)`
remains unchanged.

The purpose of 022R is to replace Verification 022's missing same-run
provenance with one exact A90 `SM-A908N`/`SM8150` V2321 acquisition. The
measurement remains a bounded normal-RAM timing/model experiment. It is not an
alias proof, a physical-address map, a controller test, a protected-memory
test, a mutability test, or a bypass route.

The full contract is
[`docs/VERIFICATION022R_CONTRACT_2026-08-27.md`](../../docs/VERIFICATION022R_CONTRACT_2026-08-27.md);
the hostile-review gate is
[`docs/VERIFICATION022R_INTEGRATION_REVIEW_2026-08-27.md`](../../docs/VERIFICATION022R_INTEGRATION_REVIEW_2026-08-27.md).

## One fixed identification invocation

There is exactly one remote probe invocation. It is an identification pass,
not a second existence pass. The prior retained `0x10000000` existence result
is not replayed here. The controls bracket the seven rank-3 candidates in the
remote argv and in the raw receipt:

```text
run /tmp/a90-native/v022r-pa28-probe \
  camera_preview 320 201 256 7 spread 0xc2000000 \
  /tmp/a90-native/v022r-ion \
  0x16000 0x2000 \
  0x10002000 0x10004000 0x10006000 0x10008000 \
  0x1000a000 0x1000c000 0x1000e000 \
  0x16000 0x2000
```

The fixed context is `camera_preview` ION type 10/id 30, 320 MiB, 201
repetitions, 256 requested pairs per difference, CPU 7, `spread`, declared
base `0xc2000000`, 17 warmups, alternating order, `dsb_ld`,
`kept_times_two`, and `cntfrq=19200000`. The seven candidate vectors are
`001`, `010`, `011`, `100`, `101`, `110`, and `111` for the recovered
PA13/PA14/PA15 rank-3 basis. No caller may add, remove, reorder, or replace a
difference. The runner must prove `dispatch_count=1`; a timeout or partial
response is an incident and is never retried.

The probe may use only the named non-secure normal-RAM allocation and its own
process mappings. It must verify range, base overflow/carry, and
`pa_a XOR pa_b` before timing a pair. It must close descriptors and unmap on
all paths. `/proc/self/pagemap` is an observation only and cannot turn the
declared base into a physical-page claim.

## Exact target and provenance

The only bridge binding is the unique loopback A90P1 bridge at
`127.0.0.1:54321`, using `/dev/ttyACM0` and the exact by-id path
`/dev/serial/by-id/usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00`. The by-id
path must resolve to `/dev/ttyACM0`; the bridge process must carry the exact
device, host, port, `--expect-realpath`, and device-glob binding. The bridge
PID/argv, serial identity, bridge source identity, frame metadata, command
argv, timestamps, and transcript hashes remain private evidence.

Before pre-clean/upload, the runner must bind the target with the exact V2321
runtime/build/kernel and these unique cmdline tokens:

```text
androidboot.em.model=SM-A908N
androidboot.bootloader=A908NKSU5EWA3
androidboot.debug_level=0x4f4c
androidboot.force_upload=0x0
sec_debug.dump_sink=0x0
```

It must also read `/sys/class/misc/ion/dev` and require `10:94`. A final
version/cmdline/self-test health check after cleanup must revalidate the same
identity and require `pass=11 warn=1 fail=0 entries=12`.

The implementation provides exact source, build-receipt, binary,
runner, bridge-script, dependency, and remote before/after SHA-256 descriptors
and byte sizes. The source and binary must be independently stable-read;
the build receipt must bind compiler identity and byte-identical static
reproducibility; and the remote binary hash before and after the child must
equal the local binary hash. No unverified digest is accepted by this design.

## Lifecycle and evidence

The only remote objects are the upload envelope
`/tmp/a90-native/v022r-pa28-probe.b64u`, binary
`/tmp/a90-native/v022r-pa28-probe`, and temporary ION node
`/tmp/a90-native/v022r-ion`. After exact target binding, each is pre-cleaned
once, and after the one probe the node/files are removed once and all three
paths are checked absent. Cleanup and final health are mandatory after any
probe/parser failure once target binding succeeded.

Every command must retain exact argv, UTC start/end timestamps, A90P1 frame
begin/end and sequence, transcript digest, and child exit information. The
runner must record probe PID and exit, dispatch time, hash-before/hash-after,
cleanup/absence results, and final-health times. There is no retry,
reconnect-and-replay, alternate binary, or second probe after dispatch. If
the bridge is lost, the run remains an incident with cleanup/health unresolved;
it cannot be relabeled as a negative.

Raw JSONL, framed output, full bridge transcript, command log, build receipt,
and lifecycle receipt are private (`0700` directory, `0600` files). A public
manifest may expose only sanitized basenames, sizes, hashes, fixed parameters,
recomputed statistics, status, and explicit unknowns. It must exclude raw
payloads, private paths, PIDs, unredacted bridge/cmdline data, and secrets.
Publication is fresh, fsynced, `O_EXCL`/`O_NOFOLLOW`, and no-clobber. An
incomplete or incident receipt is never publicly promoted.

## Safety and result gate

The runner/probe performed only bridge identity/version/cmdline/ION
queries, experiment-owned temporary-file/node operations, one non-secure ION
allocation and mapping, reads/writes inside its own normal-RAM mapping, and
cleanup. It must contain no MMIO, `devmem`, `/dev/mem`, controller, SMC/SCM,
EL2/EL3, secure/protected/remote heap, partition, firmware, reboot, suspend,
reset, or unrelated-device operation.

The implementation, exact artifact pins, focused hostile tests, and independent
review were complete before the single live dispatch.

## Executed result

The exact V2321 A90 run completed with 317 commands, one probe dispatch, child
exit zero, 1,802 records, complete C cleanup, remote cleanup/absence, and final
self-test `11/1/0/12`. The strict reducer independently rechecked all 1,787
pair records and 11 ordered summaries. Leading and trailing thresholds were
both `369`, the widest gap was `336`, and only `0x10004000` was a conflict in
both brackets. The resulting model extension is
`f(PA28)=010=f(PA14)`.

Public evidence:

- `evidence/manifests/verification-022r-pa28-live-20260827-01.manifest.json`
  — 11,989 bytes, SHA-256
  `f88a81bd3aabbd76cf2bcb8575f45d1cca7c29433a0279403d76d3affbfa2ca2`.
- Private receipt — 1,314,648 bytes, SHA-256
  `83adc32fe8c75ae81af22abffb4a3a173d8eb33ac7c92d97dfa39a4cb85c6956`.
- Private raw JSONL — 294,218 bytes, SHA-256
  `75e762b8e66dc96ef00d14401483aa27107cba890c29c9b797e3d1a7b65399a8`.

`PROVED`: exact-target acquisition lifecycle, one-dispatch execution, raw
arithmetic integrity, cleanup, and final health. `SUPPORTED`: the normal-RAM
timing/model extension. `UNKNOWN`: physical page identity, physical alias,
complete DRAM coordinates, transform mutability, protected-memory reach, and
bypass. No controller, MMIO, SMC, protected-memory, partition, firmware,
reboot, or reset action occurred; result remains `NOT_ELIGIBLE` for numbered
Experiments 015/016.
