# Verification 018 — bounded non-secure allocation-local storage-identity marker oracle

This is a Verification record in the `verification-` lane, not the numbered
Experiment 018 XBL MC-writer cross-reference.  It is a host-hardening record
and acquisition description for one reversible, allocation-local test on the
A90.  The README was authored before the live run; the retained result is now
recorded in the public manifest named below.  The live operation did not touch
MMIO, SMC, secure/protected memory, partitions, or reboot state.

## Question

For one exact A90 normal-world, non-secure `camera_preview` allocation and one
tested runtime state, can a marker written at an anchor be observed through an offset that
received only a sentinel, thereby detecting a non-injective storage mapping at
that exact pair of allocation offsets?

The answer is deliberately narrower than a physical-alias claim.  The probe
tests storage identity in one state through two mappings of one allocation.  A
candidate marker read is `ALIAS`; an unchanged sentinel is `DISTINCT`; any
other value is `DISTURBED`.  An anchor readback mismatch is retained as anchor
clobbering.  The analyzer recomputes these labels and the summary from the
retained records; it never trusts a producer's verdict or count.

## Fixed bounded scope

The intended target is the exact A90 `SM-A908N` / `SM8150` V2321 runtime
(`0.9.285`, build `v2321-usb-clean-identity-rodata`, with the runner's pinned
kernel/bootloader/debug-level identity).  The probe selects the ION heap named
`camera_preview`, requires the retained exact type `10` / id `30`, requests one `256 MiB` allocation with
`flags=0` (the write-combine mapping request), and creates two distinct virtual
mappings of the same dma-buf.  All writes and reads remain inside that
allocation.  The probe does not touch MMIO, controller registers, SMC, EL2,
EL3, partitions, protected memory, secure heaps, or any other allocation.

The exact marker sweep is:

| Item | Fixed contract |
|---|---|
| Allocation | `256 MiB` (`268435456` bytes), `camera_preview` |
| Anchors | `0x0000000`, `0x0410b000`, `0x0713a000`, `0x0bcc0000` |
| Candidate relation | `candidate = anchor XOR (1 << bit)` |
| Tested bits | `6..27` inclusive (22 bits) |
| Trials | 2 (`trial=0`, then `trial=1`) |
| Same-storage control | write marker at offset `0x0` through map 1, read through map 2; expected `ALIAS` |
| Distinct-offset control | marker at `0x1000`, sentinel at `0x3008`; read `0x3008`; expected `DISTINCT` |
| Ordering | sentinel writes, barrier, anchor marker write, barrier, anchor/candidate reads |
| Default seed | `0x5da9f0e3c17b2846` |

The same-storage control is a virtual/same-dma-buf positive control.  It proves
that the two virtual mappings expose the same backing allocation; it is not a
positive control for a DRAM or topology alias.  The distinct-offset control
must not return the marker and protects against a broken instrument that
aliases ordinary offsets.

The strict JSONL count is exactly:

```text
1 context + 1 ion_heap + 1 pa_provenance + 2 controls
+ 4 anchors * 2 trials * (1 anchor record + 22 candidates)
+ 1 summary = 190 records
```

The parser requires this order and exact record shapes.  It rejects malformed,
blank, non-UTF-8, foreign-schema, duplicate-key, missing, trailing, reordered,
or duplicate records and rejects fields that do not recompute from the fixed
context, seed, offset, and trial.  A valid transcript therefore contains 8
anchor records and 176 candidate records in addition to the metadata, controls,
and summary.

## Provenance and limits

The probe prefaults the mapping and records `/proc/self/pagemap` provenance,
but pagemap may be `BLIND`, `PARTIAL`, or `OPEN_FAILED`.  `reported_contiguous`
is retained as an observation only.  `effective_contiguity` and
`physical_mapping` remain `UNKNOWN`; no PFN, physical-page, allocation-base,
channel, bank, rank, or DRAM-coordinate claim is derived from this record.

The strongest possible clean result is `NO_ALIAS` over the exact retained
candidate pairs in one tested state, with both controls firing, all anchors
intact, and no disturbance.  It is not a proof of global injectivity.  The
single-state marker sweep is deliberately blind to an injective Skitter-style
permutation that changes between states: each state can be injective while a
cross-state comparison would still matter, and this record performs no such
comparison.  It also does not test transform mutation, protected-boundary
reach, bypass, or any numbered conceptual Experiment 015/016 eligibility.

This record does not satisfy or promote numbered Experiments 015 or 016, and
it does not establish a protected-memory boundary result.  `ALIAS_DETECTED`
means only a potential non-injective storage result in this bounded
non-secure allocation-local model; it is not authority for a physical alias or a security
boundary conclusion.

## Host validation and probe build

Run all host checks from the repository root.  The focused suite is synthetic
and never invokes the live runner or a device:

```sh
python3 -m unittest discover -s tests \
  -p 'test_a90_alias_marker_analysis.py' -v
python3 -m py_compile \
  tools/a90_alias_marker_analysis.py \
  tools/a90_alias_marker_live.py \
  tests/test_a90_alias_marker_analysis.py
```

The probe is built as a static AArch64 binary from the exact checked-out
source.  The output path must be fresh and private; the retained build receipt
records the compiler identity and binary hash after a successful build:

```sh
build_dir="$(mktemp -d -t verification018-build.XXXXXX)"
trap 'rm -f -- "$build_dir/v018-alias-probe"; rmdir -- "$build_dir" 2>/dev/null || true' EXIT
aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra \
  -o "$build_dir/v018-alias-probe" \
  tools/a90_alias_marker_probe.c
file -- "$build_dir/v018-alias-probe"
sha256sum -- "$build_dir/v018-alias-probe"
```

The build receipt must retain the compiler/toolchain identity, source bytes,
binary bytes, executable architecture, size, and SHA-256.  A source or binary
change requires a fresh build and fresh receipt; a stale binary is never
silently reused.

## Fixed live command and reversible resources

The canonical live runner accepts only the loopback A90P1 bridge
`127.0.0.1:54321`, the exact target identity, a fresh output directory below
`evidence/private`, a build receipt matching the runner's predeclared source /
binary hashes, and the fixed probe arguments.  Its command-line template
is:

```sh
python3 tools/a90_alias_marker_live.py \
  --experiment-id verification-018-a90-YYYYMMDD-01 \
  --binary <private-built>/v018-alias-probe \
  --build-receipt <private-built>/build-receipt.json \
  --source tools/a90_alias_marker_probe.c \
  --output-dir evidence/private/verification-018-a90-YYYYMMDD-01 \
  --host 127.0.0.1 --port 54321 \
  --timeout 20 --probe-timeout 300
```

The runner's remote probe argv is fixed and is not caller-selectable:

```text
run /tmp/a90-native/v018-alias-probe \
  --ion-node /tmp/a90-native/v018-ion \
  --seed 0x5da9f0e3c17b2846
```

Before the probe, the runner removes stale instances of the three temporary
remote objects and verifies the exact ION character identity before creating
it.  During the one bounded run it may create only:

```text
/tmp/a90-native/v018-alias-probe.b64u   base64 upload envelope
/tmp/a90-native/v018-alias-probe       uploaded probe binary
/tmp/a90-native/v018-ion               temporary ION node, major:minor 10:94
```

The runner verifies the exact checked-in source hash and predeclared binary
hash against the private build receipt before opening the bridge.  It uploads
that pinned binary, verifies its remote SHA-256 before the run, creates the
node with the fixed identity, runs the probe once, and checks
the remote binary SHA-256 again.  It never retries a failed probe or replays a
one-shot effect.  The allocation is unmapped and its descriptor is closed by
the probe on every exit path.

After target binding, cleanup is mandatory: remove the temporary node, remove
the upload envelope and binary, prove absence of all three paths, and perform
the final exact target/self-test health check.  Cleanup and final-health
receipts are required even when the probe, parser, or hash check fails.  If
target binding fails, the runner stops before sending target-dependent cleanup
commands and records the identity incident locally.

## Stop conditions and statuses

The following conditions stop the run or keep it from being interpreted:

* bridge host/port, target version/cmdline, model, bootloader, debug level,
  force-upload, dump-sink, runtime, or ION identity differs;
* the heap is absent, duplicated, differs from exact type 10/id 30, the allocation/mapping
  fails, or the two virtual mappings are not distinct;
* the child exits nonzero, the transport framing is not exact, the JSONL is not
  exactly 190 records, or any strict parser/recomputation check fails;
* the same-storage or distinct-offset control fails, an anchor is clobbered,
  trials disagree, or any candidate is `DISTURBED`;
* the binary hash changes across upload/run, cleanup or remote absence proof
  fails, final health is incomplete, or the receipt is not a complete PASS;
* a probe transport timeout occurs without a retained child PID and bounded
  termination proof; this is an `INCIDENT`, never an admissible negative;
* any supplied raw/source/binary/receipt artifact is missing, unstable,
  mismatched to its exact basename/size/SHA-256 pin, or contains private data
  that cannot be sanitized.

The status vocabulary keeps readiness, acquisition, and interpretation
separate:

| Layer | Status/disposition | Meaning |
|---|---|---|
| Host self-test | `HOST_SELFTEST_ONLY` | Synthetic positives, injective negative, and Skitter blind-spot checks only; no device claim. |
| Host analyzer | `HOST_TOOL_READY_DEVICE_ACQUISITION_PENDING` | Strict tool and publication path are ready, but no validated live receipt is supplied. |
| Live runner | `PASS` / `INCIDENT` | `PASS` requires target binding, one exact probe, stable upload hash, complete cleanup/absence proof, and final health; `INCIDENT` is never interpreted as a negative. |
| Analyzer run | `NO_ALIAS` | Controls pass and no alias/disturbance/clobber is found over the exact one-state offset pairs; only then can the exact-scope negative be admissible. |
| Analyzer run | `ALIAS_DETECTED` | A candidate read the anchor marker after receiving a sentinel; potential single-state non-injective storage result. |
| Analyzer run | `INSTRUMENT_FAILED`, `ANCHOR_CLOBBERED`, `DISTURBANCE`, or `REPEAT_REQUIRED` | Stop and review/reacquire; never publish an admissible negative. |
| Publication | `NOT_PROMOTED` | Any missing pin, receipt, cleanup/final-health gate, or scope boundary keeps the result from promotion. |
| Analyzer publication | `DEVICE_ACQUISITION_VALIDATED` | The exact live receipt, source/binary/build pins, sidecars and strict raw transcript validate the bounded one-state result; this remains allocation-local. |

A failed control is fail-closed even if every candidate reads as distinct.  A
stale or inconsistent summary is rejected rather than rewritten into a clean
negative.  `PASS_GO` or host self-test success is not device authority.

## Private evidence and public output

The runner's fresh private directory is mode `0700`; its generated artifacts
are mode `0600` and are never copied into a public manifest:

```text
alias-marker.jsonl   exact strict JSONL candidate transcript, when available
probe-output.bin     raw framed probe output, when available
transcript.bin       exact bridge command/response transcript
receipt.json         target, command, artifact, cleanup, and final-health receipt
build-receipt.json   source/binary/compiler identity and byte-identical build receipt
```

The receipt binds the exact probe source, probe binary, runner, bridge script,
raw transcript, and remote before/after binary hashes.  The host analyzer reads
the raw JSONL and all supplied artifacts through stable regular-file,
no-follow reads and requires an independent identical re-read.  Its future
analysis command is:

```sh
python3 tools/a90_alias_marker_analysis.py \
  --raw evidence/private/verification-018-a90-YYYYMMDD-01/alias-marker.jsonl \
  --probe-source tools/a90_alias_marker_probe.c \
  --probe-binary <private-built>/v018-alias-probe \
  --build-receipt <private-built>/build-receipt.json \
  --acquisition-receipt evidence/private/verification-018-a90-YYYYMMDD-01/receipt.json \
  --pin raw=<size>:<sha256> \
  --pin probe_source=<size>:<sha256> \
  --pin probe_binary=<size>:<sha256> \
  --pin build_receipt=<size>:<sha256> \
  --pin acquisition_receipt=<size>:<sha256> \
  --output <fresh-public-output>/verification-018-a90.json
```

The public result carries only sanitized basenames, byte sizes, SHA-256
digests, recomputed bounded summaries, scope limits, and publication metadata.
It contains no raw transcript bytes, private absolute paths, device secrets,
or unredacted bridge transcript.  Publication is atomic, fresh, mode `0644`,
and no-clobber: an existing public output is a stop condition.  The analyzer's
helper pin and all live artifact pins are retained in the private receipt and
sanitized public manifest.

## Current disposition

The retained run has the exact target binding, build/transfer receipt,
190-record raw transcript, cleanup receipt, final-health receipt, and stable
artifact hashes described above.  Its verified result is:

```text
DEVICE_ACQUISITION_VALIDATED
DEVICE_NEGATIVE_CLAIM = PROVED_NO_ALIAS_IN_EXACT_TESTED_OFFSET_PAIRS
PHYSICAL_MAPPING = UNKNOWN_PAGEMAP_BLIND
EFFECTIVE_CONTIGUITY = UNKNOWN_PAGEMAP_BLIND
TRANSPORT_TIMEOUT_WITHOUT_PID = UNKNOWN_NOT_EXERCISED
NUMBERED EXPERIMENTS 015/016 = NOT_ELIGIBLE
PROTECTED-BOUNDARY RESULT = NOT_TESTED
```

The first parser-only target-format incident remains a private negative
receipt; it had no allocation or write effect and was not replayed as an
effect.  The canonical public manifest is
`evidence/manifests/verification-018-a90-20260827-03.manifest.json`.
