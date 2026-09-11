# Contributing

This is a single-owner research repository. Issues, corrections, and questions
are welcome; large unsolicited feature work probably is not the best use of your
time without asking first.

## The one rule that matters

**Never let a claim outrun its evidence.** Every finding carries one label:

| Label | Means |
| --- | --- |
| `PROVED` | An exact input, source, or artifact plus a reproducible check establishes it directly. |
| `SUPPORTED` | Independent conventions, models, or repeated observation back it, but this iteration did not prove it. |
| `HYPOTHESIS` | An explicit prediction, stated so the next discriminator can test it. |
| `UNKNOWN` | Not yet measured, recovered, or verified — or out of scope. |
| `REFUTED` | Negated within a stated model, range, and conditions. Not a claim of global absence. |

A correction that moves a claim *down* a level is as valuable as a new result,
and is never treated as an embarrassment.

## What must not enter a contribution

- Raw firmware, extracted binaries, boot images, or raw device output. Manifests
  bind an input by hash; they do not carry it. See [`NOTICE`](NOTICE).
- Private absolute paths, device serials, or any other private identifier.
- A device-effect claim without the artifacts that back it — the command, the
  build, the hashes, the negative control, and the repetition count.

## Reporting a security-sensitive finding

See [`SECURITY.md`](SECURITY.md). Do not open a public issue with the details.

## Device safety

Procedures described here can render a phone unbootable if performed
incorrectly. The device-safety method is inherited from the upstream project,
[android-native-init-lab](https://github.com/Temmie-Tem/android-native-init-lab),
and nothing in this repository grants device authority or overrides it.
