# Verification 012 — Live Samsung Upload `SHRM_MEM.BIN`

## Result

`PROVED`: the exact retail A90 exported one real 64-KiB `SHRM_MEM.BIN` through
Samsung Upload after the bounded MID-plus-SysRq sequence.

```text
size    65,536 bytes
SHA-256 409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7
range   0x09060000..0x0906ffff
```

Raw bytes and the complete labelled-value report are mode `0600`, below
`evidence/private/`, and ignored by Git. The redacted public result is
`evidence/manifests/verification-012-a90-samsung-upload-shrm-20260825-01.manifest.json`.

## Acquisition chain

- `PROVED`: host journal records `04e8:685d`, `MSM_UPLOAD`, manufacturer
  Samsung, followed by disconnect and return of native `04e8:6861`.
- `PROVED`: the pinned `qdl v2.8` 05c6/Sahara collector captured no file.
- `SUPPORTED`: the live Samsung Upload catalog presented 56 entries and record
  19 as `SHRM_MEM.BIN (0x09060000..0x0906ffff)`. That console transcript was
  observed but not separately persisted, so the record count is not promoted
  to a pinned fact.
- `PROVED`: exact XBL static evidence independently fixes record 19, its name,
  and its physical range.
- `PROVED`: the acquired file has the exact section-16 header
  `0008/0230/01b8/08e8` at dump offset `0x5100` and decodes into the expected
  430 + 64 staged entries (470 distinct source addresses).

The host selected only record 19. No DRAM, CP, hyp, TZ, log, key, credential,
or unrelated memory entry was collected.

## Set qualification

The two buffers are not treated as equally trustworthy.

### Set 0 — `SUPPORTED_POPULATED_COHERENT_SNAPSHOT`

- 430 words; 220 zero and 210 nonzero; 71 distinct values.
- Four exact `qhs_mc` instances expose 18 common offsets.
- 17/18 offset groups are bit-identical across all four instances.
- The remaining `+0x4d0` group has a stable two-by-two split.

This structure strongly supports populated controller state. It does not prove
that every set-0 word was sampled simultaneously or that any particular word
controls an address transform.

### Set 1 — `REFUTED_AS_COHERENT_CURRENT_SNAPSHOT`

- 64/64 words are nonzero and all 64 values are distinct.
- Its four `qhs_mc +0x80` values are all different.
- It overlaps set 0 at 24 exact register addresses; zero values agree.

`REFUTED`: set 1 is safe to use as a coherent current register snapshot for
this acquisition. Whether it is stale, unpopulated, or uninitialized remains
`UNKNOWN`, so its values are excluded from architectural conclusions.

## Controller follow-up candidates

These are ranked for semantic recovery and conflict-timing cross-check, not
claimed transform registers:

| Rank | Exact topology/offset | Set-0 value pattern | Semantic status |
|---:|---|---|---|
| 1 | four `qhs_mc +0x400` | all `0xc003ffff` | `UNKNOWN` |
| 2 | four `qhs_mc +0x404` | all `0x00003333` | `UNKNOWN` |
| 3 | four `qhs_mccc +0x118` | all `0x00111111` | `UNKNOWN` |
| 4 | four `qhs_mc +0x4d0` | `0x00300014` ×2, `0x00300033` ×2 | `UNKNOWN` |
| 5 | `qhs_mccc_master +0x294` | `0x00001111` | `UNKNOWN` |

### Why `+0x400` is not named from another Qualcomm generation

A comparative Qualcomm BIMC header at commit
`53a3bb52a45ca92b6bf2d1aa0ba6936d9ff156bc` names SCMO `+0x400` as
`SLV_INTERLEAVE_CFG` with valid mask `0xff`, and `+0x420` as
`ADDR_MAP_CSn`. Its source SHA-256 is
`90174317f1745ac0e38672a280af75eee9682847ab9c1fa27c43957aa372348d`.

The exact A90 values are `qhs_mc +0x400 = 0xc003ffff` and `+0x420 = 0` on
all four instances. That is incompatible with directly transferring the
comparative layout and mask. Therefore the generic label is rejected for
SM8150 until exact register source or an exact firmware write call graph names
it.

Primary comparative source:
<https://github.com/arzekrasr/BOOT.XF.4.1/blob/53a3bb52a45ca92b6bf2d1aa0ba6936d9ff156bc/QcomPkg/Library/ICBLib/HALbimcHwioGeneric.h>

## Limits and security conclusion

`PROVED`: this snapshot does not reach the separate remapper controls at
`0x09248080`, `0x092c8080`, `0x09348080`, or `0x093c8080`; it samples lower
addresses on the same 4-KiB pages only.

`PROVED`: the protected SHRM workspace can be exported by a post-reset
bootloader diagnostic path after an authorized crash. This is not a normal
EL1 read primitive: the earlier fixed EL1 load remained blocked and caused a
watchdog.

`UNKNOWN`: exact candidate semantics, post-boot writability/lock state, final
transform ownership, and whether protection is applied before or after any
hidden transform.

`REFUTED`: this acquisition itself demonstrates a PA alias or protected-memory
isolation bypass.

Current classification:

```text
REAL_SHRM_DUMP_ACQUIRED_SET0_QUALIFIED_NO_BYPASS
```

## Cheapest next discriminator

Experiment 014 has now proved a low-24 GF(2) bank row space. The cheapest next
discriminator is host-only exact XBL/AOP/SHRM xref recovery for writes to the
ranked MC/MCCC words and a semantic comparison with that row space. A second
cold-boot `SHRM_MEM.BIN` remains a low-cost repeatability control.

Unknown MC/MCCC/remapper writes remain outside this verification.

## Reproduce

```sh
python3 tools/shrm_dump_decode.py --dump \
  evidence/private/verification-012-a90-samsung-upload-shrm-20260825-01/memory/SHRM_MEM.BIN
python3 tools/sm8150_shrm_live_dump_analysis.py \
  --journal /path/to/pinned-eight-line-journal-excerpt --replace
python3 -m unittest tests.test_sm8150_shrm_live_dump_analysis -v
```
