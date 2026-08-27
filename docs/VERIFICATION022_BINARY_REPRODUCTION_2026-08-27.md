# Verification 022 binary reproduction — 2026-08-27

## What this closes

The Verification 022 integration review recorded two provenance gaps:

1. the executed probe binary is not retained, and its hash is a producer
   attestation that no reader could check; and
2. the raw receipts carry no same-run target, bridge, or command binding.

Gap 1 is now closed by reproduction.  Gap 2 remains open and is the reason
Verification 022R exists.

## The executed source was retained after all — in version control

`tools/a90_pa28_probe.c` in the working tree is the *repaired* source, correctly
labelled `RETAINED_REPAIRED_SOURCE_NOT_EXECUTED` in the public manifest.  The
source that actually produced the two retained receipts is still retained, in
git, at commit `5289ec8`:

| artifact | bytes | SHA-256 |
|---|---:|---|
| `5289ec8:tools/a90_pa28_probe.c` (executed) | 20,530 | `7ee1cbf5264babd571b11acf4a586068ca7baaf9dee5fcea8af9b2332881f617` |
| `tools/a90_pa28_probe.c` (repaired, never executed) | 25,030 | `b324c1c3332c61b00f6d6e5c75891721be4a5fb2a998c7f0222900d4eba5e199` |

Neither hash appeared in any manifest or document before this one.  The public
manifest pinned the repaired source and left the executed source unnamed.

## The attested binary hash reproduces byte-for-byte

Building the git-retained executed source with the command recorded in
`experiments/verification-022-pa28-relation/README.md`:

```
aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror \
  -o a90_pa28_probe a90_pa28_probe.c
```

with `aarch64-linux-gnu-gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0` produces

```
9959674add623891a80be57d1f139d6af1cc622359e4972a08b61133500afa51  776256 bytes
```

which is exactly the value the manifest carries at `inputs/probe_binary.sha256`
with `size_bytes: 776256` and `status: NOT_RETAINED`.  The build must use the
basename `a90_pa28_probe.c`, because gcc embeds the source basename; this is the
same basename sensitivity recorded for Verification 020.

## Negative control

The reproduction is specific to the executed source, not an artifact of the
toolchain producing the same output for any input.  Building the repaired
in-tree source with the identical command and toolchain gives a different
binary:

| source | binary SHA-256 | bytes |
|---|---|---:|
| executed (`7ee1cbf5…`) | `9959674add623891a80be57d1f139d6af1cc622359e4972a08b61133500afa51` | 776,256 |
| repaired (`b324c1c3…`) | `0d8839bd72798649793d72efe71eae440648e0ebb809776e056869b280513dc7` | 776,408 |

## Exactly what this proves, and what it does not

`PROVED`: the source that the producer states was executed is retained in
version control, and it builds byte-identically to the binary hash the producer
attested at run time.  The source→binary link is now independently checkable by
any reader with the toolchain, and no longer rests on the producer's word.

`UNKNOWN`, unchanged: that this binary is the process that wrote
`pa28-existence.jsonl` and `pa28-identification.jsonl`.  The run emitted no
binary hash into its own receipts, so the binary→data link is still a producer
attestation.  Target identity, bridge binding, command argv and timestamps
remain `UNKNOWN_UNRETAINED`; this reproduction does not touch them.

`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` are unchanged.  No device, USB,
bridge, ION, MMIO, SMC, SCM, protected-memory or partition action was performed:
this was a host-only `git show`, one cross-compilation, and two hashes.

## Suggested manifest amendment

`inputs/probe_binary.status` can move from `NOT_RETAINED` to
`REPRODUCED_BYTE_IDENTICAL_FROM_VCS_SOURCE`, and `inputs` can gain an
`executed_probe_source` entry pinning `7ee1cbf5…` at 20,530 bytes with its
commit.  The reduction, the verdict, and every bounded claim are unaffected.
