# Verification 020N - normal-RAM PA28 timing candidate

020N is the selected next discriminator after 020M and 021.  It is currently
host-only: the new fixed probe has not been built for or executed on a device,
and no live 020N result or public evidence manifest exists.

The candidate would allocate the exact non-secure `camera_preview` ION heap
(type 10/id 30) at its measured full size of 320 MiB, then compare reopen
timing for eight fixed offset pairs separated by exactly `0x10000000`.  It
also emits a same-offset control, two fixed bank-bit negative controls, and a
one-page cached `dc civac` instrumentation control.  All offsets are checked
against the allocation before pointer formation.  The probe accepts no
arguments, uses no pagemap, and forms no physical address.

The host analyzer requires both independent preconditions before accepting a
raw probe receipt:

- 020M manifest `verification-020m-pa28-dt-20260827-03.manifest.json`,
  8,246 bytes, SHA-256
  `69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a`, with
  raw receipt pin `40a3207d3f822775c4506415a579e993c07a6a7f9ff998e41a6f76cb6216a2ec`;
- independent 021 v2 manifest `verification-021-carveout-exhaustion-20260827-01.manifest.json`,
  4,586 bytes, SHA-256
  `82471b458f87e1ed86596ab08c97bab743ee868edf98d7d272c1d131046c168b`, proving
  the 320-MiB hold and 5/5 before/after allocation controls.

The 020N source is [a90_pa28_timing_probe.c](../../tools/a90_pa28_timing_probe.c)
and the host reducer is
[a90_pa28_timing_analysis.py](../../tools/a90_pa28_timing_analysis.py).  The
source pin is 18,809 bytes,
`281528d45040bc3174aefc5dba957d74d3a04203c65af4413dc34e695708f167`.

Run host validation only:

```sh
gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only \
  tools/a90_pa28_timing_probe.c
python3 -m unittest -v tests.test_a90_pa28_timing_analysis
```

The reducer's possible output status `PA28_TIMING_CANDIDATE` is a bounded
timing label, not a proof of `f(PA28)` or an alias.  Physical page identity,
complete DRAM coordinates, transform mutability, ownership, protection
ordering, and protected reach remain `UNKNOWN`; classification stays `CLASS C
(TRANSFORM ONLY)` / `NOT_ELIGIBLE`.

`tools/a90_pa28_probe.c` is Verification 022's separate future candidate.  It
is intentionally not modified or promoted here; it has a different dynamic
surface and remains outside the 020N ownership and execution boundary until
its own wrapper, receipt schema, and review are complete.
