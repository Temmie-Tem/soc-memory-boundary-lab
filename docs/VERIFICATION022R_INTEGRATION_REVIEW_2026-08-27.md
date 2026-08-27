# Verification 022R integration review - final, 2026-08-27

## Current disposition

**Disposition: `PASS`.** The checklist below was applied first to the
implementation and then independently to the retained live acquisition. The
022R run supplies a same-run exact-target receipt and deterministic redacted
manifest. `CLASS C (TRANSFORM ONLY)` is unchanged.

## Questions the hostile reviewer must answer

### 1. Exact device and bridge identity

- Does the runner prove exactly one bridge process, with listener
  `127.0.0.1:54321`, `/dev/ttyACM0`, the exact A90 by-id identity, strict
  realpath checking, and the required device-glob token?
- Are the bridge process PID/argv, serial character-device identity, bridge
  script identity, and validation timestamp retained privately?
- Is there a race or rebind between local bridge validation, target preflight,
  upload, and probe dispatch? If so, does the runner fail closed?
- Does every A90P1 frame have matching command/sequence/status and a complete
  transcript, with no hidden or implicit command?

### 2. Exact V2321 target binding

- Are the runtime, build, and kernel lines uniquely and exactly bound to
  `A90 Linux init 0.9.285`, `v2321-usb-clean-identity-rodata`, and the
  A908N V2321 kernel?
- Does `/proc/cmdline` require unique, non-conflicting values for model,
  bootloader, debug level, force-upload, and dump-sink, including the exact
  `SM-A908N` tokens?
- Is the ION misc identity read and required to be `10:94`, with the probe
  independently checking `camera_preview` type 10/id 30?
- Is the same target identity revalidated after cleanup and before a pass is
  published?

### 3. One fixed identification invocation

- Is there exactly one remote `probe` dispatch after all preflight and hash
  gates, with no separate existence, smoke, inventory, or retry invocation?
- Is the remote argv exactly the fixed `v022r-pa28-probe` command from the
  contract, including 320 MiB, 201 repetitions, 256 pairs, CPU 7, spread,
  base `0xc2000000`, and the fixed ION path?
- Are the differences exactly controls `0x16000`, `0x2000`, seven candidates
  `0x10002000` through `0x1000e000` in the specified rank-3 order, then the
  same two controls? Are omission, reorder, duplicate, extra, and
  `0x10000000` substitutions rejected?
- Does the receipt prove dispatch count one even when the transport fails?

### 4. Source, build, binary, and remote bytes

- Does the runner independently pin the exact source bytes, build receipt,
  static binary, runner, and bridge-script bytes before bridge contact?
- Does the build receipt bind source and binary descriptors, compiler
  triple/version/command, static linking, and byte-identical reproducibility?
- Are concrete source/build/binary hashes supplied by the code agent rather
  than inferred from a self-consistent receipt?
- Is the uploaded remote binary hashed before dispatch and after child exit,
  with both remote hashes equal to the locally pinned binary hash and naming
  the exact remote path?
- Does any source, build, local binary, remote hash, path, size, or digest
  mutation fail closed before probe dispatch?

### 5. Probe safety and scope

- Does the C source enforce fixed heap, allocation, CPU, base, timing, and
  difference arguments before opening or allocating anything?
- Does it use only the non-secure `camera_preview` allocation and process-owned
  mappings, with complete close/unmap/free cleanup on every exit path?
- Are pair range, base-overflow, carry, and physical-XOR checks performed
  before pointer formation and timing, and independently recomputed by the
  host reducer?
- Is pagemap treated as an observation only, with no promotion of a PFN or
  virtual address into a physical/DRAM claim?
- Does source and runner review demonstrate absence of MMIO, `devmem`,
  `/dev/mem`, controller, SMC/SCM, EL2/EL3, protected/secure/remote heap,
  partition, firmware, reboot, suspend, reset, and unrelated-device paths?

### 6. Protocol, timestamps, and child exit

- Does every command receipt retain exact argv, host timestamps, frame
  metadata, transcript digest, and child exit code where applicable?
- Are acquisition, target preflight, dispatch, child exit, hash-after,
  cleanup, absence, final-health, and publication times all present and
  ordered in UTC with sufficient precision?
- Is a missing/duplicate/out-of-order command, malformed frame, missing child
  PID, nonzero child exit, partial JSONL, or timeout an incident rather than a
  negative?
- After dispatch, does the runner refuse all probe retries, reconnect-and-
  replay paths, alternate binaries, and second identification invocations?

### 7. Cleanup, absence, and final health

- Does the successful probe emit a terminal cleanup record and exit zero?
- Are the temporary node, upload envelope, and remote binary each removed
  once, with a strict absence result for every path?
- Does the runner collect the post-run remote binary hash before cleanup and
  reject any change?
- Is cleanup/final-health attempted after probe/parser failure once exact target
  binding has succeeded, while avoiding cleanup commands on an unbound target?
- Does final health revalidate V2321 identity and require the healthy native
  self-test (`pass=11 warn=1 fail=0 entries=12` under the contract)?
- Does any leftover, health drift, cleanup error, or incomplete lifecycle
  prevent public promotion?

### 8. Private raw and public redacted evidence

- Are private directories/files created with the required restrictive modes,
  and do they retain the exact raw JSONL, framed payload, transcript, command
  log, build receipt, and lifecycle receipt?
- Does the public output contain only sanitized basenames, sizes, hashes,
  fixed parameters, recomputed summaries, status, and explicit unknowns?
- Are raw payloads, bridge frames, private absolute paths, PIDs, device
  secrets, and upload envelopes excluded from public output?
- Do stable `O_NOFOLLOW` reads, regular-file checks, duplicate-key/non-finite
  JSON rejection, exact pins, fsync, `O_EXCL`, and no-clobber publication all
  exist and have hostile negative coverage?
- Is an incident kept private and prevented from being rewritten as a clean
  negative or a public success?

### 9. Dependency and claim boundaries

- Are the exact 020M and 021 public dependencies pinned by concrete
  code-agent-supplied size/hash descriptors and checked for their required
  semantics before reduction?
- Does the implementation keep those separate runs from substituting for
  022R's same-run target, bridge, argv, artifact, cleanup, or health evidence?
- Does a future winner remain bounded to the tested normal-RAM timing/model
  surface, without claiming physical mapping, complete DRAM coordinates,
  aliasing, mutability, protected reach, or bypass?
- Does the implementation preserve `CLASS C (TRANSFORM ONLY)` and avoid
  authorizing Experiments 015/016 or any protected-boundary follow-up?

### 10. Required host evidence before disposition

- Has the code agent supplied the implementation file list and exact source,
  build, binary, runner, bridge, dependency, and remote hash descriptors?
- Has the code agent supplied focused test output covering every fixed-surface,
  provenance, no-retry, safety, cleanup, redaction, and hostile mutation gate?
- Has an independent reviewer inspected the code and tests rather than
  accepting a `PASS_GO` label or self-generated manifest as authority?
- Are all unresolved items explicitly marked `PENDING_CODE_AGENT` instead of
  being filled from an older retained run?

## Final evidence status

The implementation review closed all identified P1 findings before the live
dispatch, including bridge ownership and revalidation, timeout cancellation,
deadline reservation, no-replay, terminal cleanup, fixed SHA pins, forged
publication input, strict statistics, and deterministic redaction. Focused
tests are 36/36 PASS; the source passes AArch64 `-fsyntax-only`, and both Python
tools pass bytecode compilation.

Independent review of the executed receipt found 317 transcript sections and
1,802 probe records: 1,787 pair rows, 11 ordered difference summaries, one
terminal cleanup record, and three metadata records. Every transcript
size/hash/frame/sequence and every recomputed pair address/XOR matched; there
were zero percentile mismatches. The payload-extracted JSONL is byte-identical
to the retained raw JSONL. Remote binary hashes before and after execution both
equal `ed826cc75dee1eafad3b1b1ea4b0b779147364a330201e284b9e24c92adf1b92`.

The private evidence descriptors are:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `receipt.json` | 1,314,648 | `83adc32fe8c75ae81af22abffb4a3a173d8eb33ac7c92d97dfa39a4cb85c6956` |
| `pa28-identification.jsonl` | 294,218 | `75e762b8e66dc96ef00d14401483aa27107cba890c29c9b797e3d1a7b65399a8` |
| `probe-output.bin` | 294,258 | `ef9dd40a16bd67724e99d35c043aa1e4fc74ff615338b76c330eebaef03161da` |
| `transcript.bin` | 1,422,411 | `fedd2157cc03f60ecfa524b7bdacf43e2cc8952b8d159a52a20dc30810f02d4f` |
| `build-receipt.json` | 819 | `ee76191dcdd594060b1ec22a40dfe4db935ea8c92210dfd2feb16f0daa2361cd` |

The 11,989-byte public manifest hashes to
`f88a81bd3aabbd76cf2bcb8575f45d1cca7c29433a0279403d76d3affbfa2ca2`
and regenerates byte-identically. It contains no private path, PID, argv, raw
cmdline, frame, or secret. Both brackets select only `0x10004000`, with equal
threshold `369`; therefore `f(PA28)=010=f(PA14)` is
`SUPPORTED_MODEL_EXTENSION`. Physical identity, aliasing, mutability,
protected reach, and bypass remain `UNKNOWN_NOT_TESTED`. Final result:
`PASS / CLASS C (TRANSFORM ONLY) / NOT_ELIGIBLE`.
