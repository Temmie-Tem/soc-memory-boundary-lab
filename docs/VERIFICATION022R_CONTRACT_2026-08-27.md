# Verification 022R contract - provenance-complete PA28 normal-RAM repeat

## Status and disposition

**Status: `EXECUTED / ACQUISITION_PASS / SUPPORTED_MODEL_EXTENSION`.** This
file preserves the pre-execution acquisition and reduction contract and records
the executed result below. The new 022R receipt supplies its own same-run
provenance; it does not retroactively upgrade the older Verification 022
receipts.

`CLASS C (TRANSFORM ONLY)` is unchanged. A host self-test, a `PASS_GO` label,
or a complete-looking manifest is not device authority and does not authorize
Experiment 015/016, a controller action, or a protected-boundary action.

The run had one purpose: repeat the Verification 022 identification
measurement on the exact `SM-A908N`/`SM8150` V2321 runtime with a complete
same-run target, bridge, artifact, command, lifecycle, cleanup, and health
receipt. The result can speak only to the tested normal-RAM timing/model
surface. It cannot prove a physical alias, complete DRAM coordinates,
transform mutability, protected-memory reach, or a bypass.

## Fixed measurement and invocation

The run is one identification invocation. There is no separate existence,
smoke, inventory, or retry invocation. The prior `0x10000000` existence
observation is a dependency/result of retained Verification 022; it is not a
second dispatch in 022R.

The probe context is fixed and must be emitted and rechecked by the host
reducer:

| Field | Required value |
|---|---|
| allocation | `camera_preview`, 320 MiB (`335544320` bytes), ION flags `0` |
| heap identity | name `camera_preview`, type `10`, id `30` |
| timing | 201 repetitions, 256 requested pairs per difference, CPU `7` |
| offsets | `spread`, page-aligned offsets, declared base `0xc2000000` |
| timing core | 17 warmups, alternating order, `dsb_ld`, `kept_times_two` |
| counter | `cntfrq=19200000` |
| pagemap | record the observation; it is not physical-address authority; a non-blind or PFN-bearing result cannot be promoted without a new review |

The fixed difference sequence is exactly the following eleven values, in
order. The first two controls and last two controls bracket the seven PA28
rank-3 candidates; the repeated controls are required and are not optional
deduplication:

```text
0x16000 0x2000
0x10002000 0x10004000 0x10006000 0x10008000
0x1000a000 0x1000c000 0x1000e000
0x16000 0x2000
```

The seven candidate vectors are, respectively, `001`, `010`, `011`, `100`,
`101`, `110`, and `111` in the recovered rank-3 basis
`f(PA13)=001`, `f(PA14)=010`, `f(PA15)=100`. The run must preserve this order
in the remote argv and in the raw receipt. It must reject an omitted,
reordered, duplicated, or added difference, including `0x10000000`.

The exact remote probe argv is a vector, never a shell string:

```text
run /tmp/a90-native/v022r-pa28-probe \
  camera_preview 320 201 256 7 spread 0xc2000000 \
  /tmp/a90-native/v022r-ion \
  0x16000 0x2000 \
  0x10002000 0x10004000 0x10006000 0x10008000 \
  0x1000a000 0x1000c000 0x1000e000 \
  0x16000 0x2000
```

The runner must dispatch this probe exactly once after all preflight and
artifact gates pass. It must not expose caller-selectable heap, allocation,
CPU, base, difference, or remote path arguments that can change this surface.
The reducer requires eleven ordered difference summaries. Each summary must
account for exactly 256 requested pairs, including used pairs and range/carry
rejects; every accepted pair must independently recompute `pa_a`, `pa_b`, and
`pa_a XOR pa_b` from the declared base, offset, and named difference. An
emitted `pa_xor` field is never trusted by itself.

The probe may allocate and map only the named non-secure heap and may read or
write only its own mapped normal-RAM allocation plus its process-owned timing
eviction mapping. It must close the ION and allocation descriptors and unmap
all mappings on every normal and error path, with a terminal cleanup record on
the successful path. It must not use `/dev/mem`, `devmem`, controller
registers, firmware interfaces, secure/remote/protected heaps, or any
physical-address write path.

## Exact target and bridge binding

The host must create a fresh private evidence directory and complete all local
artifact checks before opening the bridge. The only accepted bridge binding is:

```text
listener:       127.0.0.1:54321
serial device:  /dev/ttyACM0
serial identity: /dev/serial/by-id/usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00
```

The by-id path must resolve to exactly `/dev/ttyACM0`, that path must be one
character device, and exactly one running `serial_tcp_bridge.py` process must
be found. Its process argv must bind the exact host, port, serial device,
`--expect-realpath /dev/ttyACM0`, and a `--device-glob` containing the exact
serial identity token. The bridge process PID, complete argv, script path and
source hash, serial `stat` identity, and validation timestamp belong in the
private receipt. A missing, duplicate, changing, or differently bound process
fails closed before target-dependent commands.

Every A90P1 frame must retain matching BEGIN/END command names, matching
sequence values, successful frame status, and a complete prompt/terminal
condition. The command receipt must contain the exact argv vector, host send
and receive timestamps, frame metadata, transcript size and hash, and child
exit information for every child-producing command. There must be no hidden
bridge command.

After bridge binding and immediately before pre-clean/upload, the runner must
read and validate the exact V2321 target with one `version` command and one
`run /bin/toybox cat /proc/cmdline` command. The version response must contain
unique, non-conflicting lines equivalent to:

```text
A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)
version: 0.9.285 build=v2321-usb-clean-identity-rodata
kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64
```

The cmdline parser must require exactly one value for each identity key and
these exact tokens:

```text
androidboot.em.model=SM-A908N
androidboot.bootloader=A908NKSU5EWA3
androidboot.debug_level=0x4f4c
androidboot.force_upload=0x0
sec_debug.dump_sink=0x0
```

Unrelated cmdline tokens may remain, but a duplicate or conflicting identity
key is a failure. The runner must read `/sys/class/misc/ion/dev` read-only and
require `10:94` before creating the temporary node. The heap name/type/id
check is repeated inside the probe; the separate 020M run cannot substitute
for this same-run binding.

## Artifact, build, and remote hash contract

The code agent must supply exact byte descriptors before any future device
run. No value is pre-approved by this design; each descriptor consists of an
exact basename, byte size, and lowercase SHA-256 digest and is read through a
stable regular-file descriptor with `O_NOFOLLOW`. Source, binary, build
receipt, runner, and bridge-script bytes must be rechecked for identity and
mutation before bridge contact.

The required private build receipt must bind:

* the implementation-resolved, versioned source
  `tools/a90_pa28_probe_v022r.c` as the exact source;
* the exact static probe binary basename `v022r-pa28-probe` and its bytes;
* compiler triple/version and the complete build command;
* static-linking status and byte-identical reproducibility; and
* source and binary descriptors that agree with the runner's independent
  reads.

The code agent must later provide the concrete source, build-receipt, binary,
runner, and bridge-script sizes and hashes in the implementation and hostile
review. This contract deliberately records no unverified digest.

The only remote objects are:

```text
/tmp/a90-native/v022r-pa28-probe.b64u   upload envelope
/tmp/a90-native/v022r-pa28-probe       uploaded binary
/tmp/a90-native/v022r-ion               temporary ION node, c 10:94
```

After exact target binding, the runner may remove stale instances once, upload
the pinned binary, decode it, set its mode, and verify a remote
`sha256sum` before creating the node or dispatching the probe. The remote
before-dispatch digest must equal the local binary digest. After the one probe
child has exited, a second remote `sha256sum` must again name the exact path
and equal the same digest. A mismatch, malformed hash output, missing child
exit, or remote path substitution is an incident and blocks interpretation.

## Fixed lifecycle, timestamps, and no-replay rule

The future receipt must retain RFC3339 UTC timestamps (with sub-second
precision) for acquisition start, bridge validation, target preflight,
pre-clean, upload completion, remote-hash-before, node creation, probe
dispatch, child exit, remote-hash-after, cleanup start/end, each absence
check, final-health start/end, and receipt/publication completion. It must also
retain a monotonic duration where available. Every command entry carries its
exact argv, its start/end timestamps, A90P1 frame sequence, and child exit
code or `NOT_APPLICABLE` for non-child protocol writes.

The fixed command order is:

1. local bridge/artifact checks;
2. target `version`, target `/proc/cmdline`, and ION-device identity reads;
3. one target-bound pre-clean of the three temporary paths;
4. envelope header/payload/footer, decode, chmod, and remote hash-before;
5. temporary ION-node creation and mode `0600`;
6. exactly one `probe` dispatch using the argv above;
7. remote hash-after, once the child exit is received;
8. one cleanup of the node and uploaded files;
9. one absence check for each temporary path; and
10. final `version`, final `/proc/cmdline`, and final `selftest status`.

The upload payload chunk count is derived from the already pinned binary and
every chunk argv is recorded. No command may be silently inserted, omitted,
reordered, or repeated. A transport timeout, disconnect, malformed frame,
partial JSONL, nonzero child exit, or missing child PID after dispatch is an
`INCIDENT`, never a negative measurement and never a reason to resend. There
is no retry, reconnect-and-replay, alternate binary, second probe, or second
identification invocation after dispatch. If the session is still usable,
each cleanup and health command is attempted at most once; if it is not
usable, cleanup/absence/final health remain unproven and the run cannot pass.

If target binding fails before it is established, the runner must not send
target-dependent cleanup commands to a potentially different device. It must
retain a local incident and stop. Once exact target binding succeeds, cleanup
and final health are mandatory even if the probe or parser fails.

## Cleanup, absence, and final health

The private receipt must prove all of the following for a pass:

* the probe emitted its terminal cleanup record and exited with child code 0;
* the temporary ION node was removed successfully;
* the envelope and uploaded binary were removed successfully;
* `test ! -e` (or an equivalently strict no-follow absence check) returned
  child exit 0 for all three paths;
* the post-run remote binary hash was collected before cleanup and matched the
  local digest; and
* final target health was collected after cleanup.

Final health must revalidate the exact V2321 version and cmdline identity and
must parse the native self-test summary with `fail=0`. The healthy baseline
expected by this contract is `pass=11 warn=1 fail=0 entries=12`; the duration
is recorded, not used as a result claim. Any target drift, self-test failure,
missing final frame, cleanup failure, residual path, or incomplete probe
cleanup yields an incident and prevents public promotion.

## Private evidence and redacted publication

The fresh private directory is mode `0700`; raw and receipt files are mode
`0600` and are never copied verbatim to a public path. It must retain, as
available, the exact probe JSONL, raw framed probe payload, complete bridge
transcript, acquisition receipt, build receipt, and command/lifecycle data.
The receipt may contain remote paths, PIDs, full argv, frame payload hashes,
and host-local absolute paths because it is private.

The public manifest is generated only from a validated private receipt. It is
mode `0644`, written with `O_EXCL`/`O_NOFOLLOW`, fsynced, and refuses to
clobber an existing output. It may contain sanitized basenames, byte sizes,
hashes supplied by the private receipt, fixed parameters, recomputed
statistics, lifecycle status, and explicit unknowns. It must not contain raw
JSONL, raw bridge frames, private absolute paths, unredacted cmdline payloads,
PIDs, device secrets, or an upload envelope. A partial or incident receipt
may remain private, but it cannot be published as a negative or a successful
result.

The host reducer must reopen every supplied input as a regular file without
following symlinks, verify the exact descriptor, and perform an independent
size/hash-stable read. A same-schema replacement, same-size digest mutation,
symlink, duplicate JSON key, non-finite number, extra record, or stale public
output fails closed.

## Safety boundary and claim gate

Permitted future device effects are limited to read-only bridge/version/cmdline
and ION identity queries, creation/removal of the three experiment-owned
temporary paths, one non-secure `camera_preview` allocation, mapping and
initialization of that allocation, timing reads/writes inside the process's
own normal-RAM mapping, and process-owned cleanup. `/proc/self/pagemap` may be
read only as an explicitly bounded provenance observation.

The runner and probe must have no MMIO, `devmem`, `/dev/mem`, register,
controller, SMC/SCM, EL2/EL3, protected-memory, secure/remote-heap,
partition, firmware, reboot, suspend, reset, or unrelated-device path. No
follow-up action is implied by a candidate winner or by a clean final health
receipt.

Only a future receipt satisfying every gate may be analyzed as a
provenance-complete normal-RAM repeat. Even then, the admissible claim is
bounded to the tested allocation, offsets, controls, and timing/model
relation. Physical page identity, complete DRAM coordinates, aliasing,
mutability, protection ordering, and bypass remain `UNKNOWN`; `CLASS C
(TRANSFORM ONLY)` remains unchanged.

## Required host validation

Before this contract could move beyond design status, the code agent had to add a
runner/reducer and focused hostile tests covering fixed argv and candidate
order, exact bridge/V2321 binding, source/build/binary/remote hash mismatch,
frame and timestamp/child-exit accounting, one-dispatch/no-retry behavior,
pair range/carry recomputation, probe cleanup, remote absence, final health,
private/public redaction, no-clobber publication, symlink/non-regular input,
and every forbidden action surface. The implementation supplied concrete
artifact pins and test output to the integration review before the device run.
Those gates are recorded as satisfied in the executed-result addendum.

## Executed result

`PROVED`: one exact-bound `SM-A908N`/`SM8150` V2321 acquisition completed with
`dispatch_count=1`, child exit zero, 317 framed commands, 1,802 probe records,
terminal C cleanup, removal and absence of all three remote temporary objects,
and final native self-test `pass=11 warn=1 fail=0 entries=12`.  The target
remained at debug level `0x4f4c`, force-upload `0`, and dump-sink `0`.

The exact implementation pins are:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `a90_pa28_probe_v022r.c` | 27,415 | `d66e8930fdf8456cb99ee6d4e6d9b8386d3f645d3a902091c39b814b3f73b315` |
| `v022r-pa28-probe` | 776,408 | `ed826cc75dee1eafad3b1b1ea4b0b779147364a330201e284b9e24c92adf1b92` |
| `build-receipt.json` | 819 | `ee76191dcdd594060b1ec22a40dfe4db935ea8c92210dfd2feb16f0daa2361cd` |
| `a90_pa28_live.py` | 150,104 | `0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66` |
| `a90_pa28_live_analysis.py` | 82,202 | `1188670fd46be4cdfc060dc66d2cdd9241ddd03a100e69fef9f87b851fcacb5b` |
| `serial_tcp_bridge.py` | 21,170 | `febfb95f408f62f516c2e4f6c25f5da61535f7b75366c3f73cc47bfd91fba077` |

The private receipt is 1,314,648 bytes, SHA-256
`83adc32fe8c75ae81af22abffb4a3a173d8eb33ac7c92d97dfa39a4cb85c6956`;
the raw JSONL is 294,218 bytes, SHA-256
`75e762b8e66dc96ef00d14401483aa27107cba890c29c9b797e3d1a7b65399a8`.
Both leading and trailing reductions produced threshold `369`, widest gap
`336`, runner-up gap `34`, and the unique candidate `0x10004000`, yielding
`f(PA28)=010=f(PA14)`.  Control drift was `3` and `12`, below the fixed limit
`84`.

`SUPPORTED`: the result is a same-run extension of the recovered normal-RAM
timing/model surface. `UNKNOWN`: physical page identity, physical aliasing,
complete DRAM coordinates, transform mutability, protected-memory reach, and
access-control bypass. No MMIO, controller, SMC, protected-memory, partition,
firmware, reboot, or reset action occurred. The final disposition remains
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`.
