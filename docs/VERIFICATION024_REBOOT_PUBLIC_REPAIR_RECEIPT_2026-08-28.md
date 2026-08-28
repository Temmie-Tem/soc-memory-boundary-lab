# Verification 024 reboot-public host repair receipt — 2026-08-28

## Scope and evidence grade

This receipt records the host-only replacement of the UUID-bearing derived
reboot public v1 with a source-bound public v2. It records no device command.
The private journal, physical-effect claim and archived v1 remain gitignored.

`PROVED`: the currently retained public v2, private v1 archive, journal and
claim have the exact hashes, sizes and modes below; the repair verifier accepts
the completed state byte-identically.

`SUPPORTED`: the retained operator transcript observed no open descriptor on
the three sources immediately before or after repair, and observed unchanged
journal/claim inode, owner, mode, size, mtime, ctime and hash. This observation
was captured by the Codex exec transcript and transcribed here after execution;
it was not emitted atomically by the repair program.

`UNKNOWN`: a malicious non-cooperating same-UID process could write after any
last sequential check or perform a write-and-restore. Such a writer was not
observed and is outside this repair authority model. Every later consumer must
still revalidate the pinned content hashes.

## Fixed inputs and tool

| Item | Size | Mode | SHA-256 |
|---|---:|---:|---|
| legacy public v1 | 1,884 | 0644 | `3a91e6eac449663c75d3ba4b1e7d6d681db30cee86c5b5f2e5986241ef0d80ca` |
| private reboot journal | 22,905 | 0600 | `8760aa1f64372b8c572396d37b9a6a72952330d1e339d5c2bc55a19547200cf8` |
| private physical claim | 663 | 0600 | `03d1f63e5c16cc9f887e6993004bad1b75d3bae0507a02db8922d287008b1802` |
| repair source | 33,009 | host 0664 / Git 100644 | `db7369a8ddca559422418f32ba9ed2d633aca211752ac9b1e1dd21ff661756f9` |
| `/usr/bin/lsof` 4.99.4 | — | — | `89db9b9a7748dbc98a20d10fbfe29e4e5f59f095e6a7f700bf49220fa40d26e9` |

The repair accepts no path or experiment-ID selector. It fixes the exact
Verification-024 filenames, validates no-follow stable reads and hard-coded
hash/size/mode/owner pins, archives v1 with O_EXCL and fsync, atomically
replaces the public file, and revalidates the completed state.

## Retained operator transcript projection

The preflight command was `lsof --` followed by the exact public, journal and
claim paths. It returned no descriptor rows. `stat` and `sha256sum` then
recorded:

| Item | Device | Inode | UID:GID | Size | mtime | ctime | SHA-256 |
|---|---:|---:|---:|---:|---:|---:|---|
| public v1, pre | 66306 | 9319385 | 1000:1000 | 1,884 | 1787893161 | 1787893161 | `3a91e6ea...` |
| journal, pre | 66306 | 9319383 | 1000:1000 | 22,905 | 1787893161 | 1787893161 | `8760aa1f...` |
| claim, pre | 66306 | 9319384 | 1000:1000 | 663 | 1787893109 | 1787893109 | `03d1f63e...` |

`python3 tools/a90_native_reboot_public_repair.py` completed once. The same
`lsof` check again returned no descriptor rows. The post-state was:

| Item | Device | Inode | Mode | UID:GID | Size | mtime | ctime | SHA-256 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| public v2 | 66306 | 9319392 | 0644 | 1000:1000 | 2,140 | 1787896939 | 1787896939 | `fbe92a29ba66f282e15c79fc4344d2b8a96c6cece44dba29326be656137bd248` |
| journal, post | 66306 | 9319383 | 0600 | 1000:1000 | 22,905 | 1787893161 | 1787893161 | `8760aa1f64372b8c572396d37b9a6a72952330d1e339d5c2bc55a19547200cf8` |
| claim, post | 66306 | 9319384 | 0600 | 1000:1000 | 663 | 1787893109 | 1787893109 | `03d1f63e5c16cc9f887e6993004bad1b75d3bae0507a02db8922d287008b1802` |
| private v1 archive | 66306 | 9319390 | 0600 | 1000:1000 | 1,884 | 1787896939 | 1787896939 | `3a91e6eac449663c75d3ba4b1e7d6d681db30cee86c5b5f2e5986241ef0d80ca` |

The public privacy predicate found zero raw boot UUID, private absolute path,
serial-device field or claim path. A second invocation returned the same public
path and the same `fbe92a29...` hash without changing the public inode or bytes.

## Verification

- Focused native-reboot/repair tests: 26/26 PASS before the final doc update.
- Independent hostile review: conditional `P0=P1=P2=0` under the immutable-
  evidence/no-concurrent-writer precondition.
- Complete repository suite: 1,916 tests finished, 1,915 passed and one
  skipped; 198.868 seconds, maximum RSS 893,116 KiB, process swap zero, no
  kernel OOM event.
- Classification: `CLASS C (TRANSFORM ONLY)`; remapper result remains
  `UNKNOWN`.
