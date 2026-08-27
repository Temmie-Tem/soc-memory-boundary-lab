# Codex handoff — Verification 024 device-side `busy`, and one 022R wording fix

This document reports one blocking defect that should be fixed **before** the
024 live sequence runs, and one wording imprecision in the 022R review. It is a
review handoff, not a consensus request; the reviewer should check the cited
lines and the retained 023 receipts rather than this summary alone.

Nothing here disputes the 022R result. That result was independently
reconfirmed — see the verification section at the end.

## 1. Blocking before the 024 run — device-side `busy` is unhandled

### The condition

There are two distinct `busy` conditions on this transport, and only one of
them is handled.

| Layer | Signal | Meaning | Handled? |
|---|---|---|---|
| Host bridge | `[bridge] busy: another client is active` | a second TCP client attached | **yes** — `CANCEL_BUSY_TEXT` in `tools/a90_pa28_live.py`, with the greeting classified in `_observe_cancel_connection` |
| Device runtime | `A90P1 END … rc=-16 status=busy` | a command is already in flight on the A90 | **no** |

The device-side condition is caused by `autohud`, which starts on every boot and
intermittently holds the A90P1 command channel. `status` reports it directly:

```text
adbd: stopped
autohud: running
```

### Why it lands on 024 specifically

`tools/a90_inline_remapper_mid_probe.py` calls `exchange()` bare at nine sites.
Line numbers are deliberately omitted below because the file was still being
edited during this review; the evidence-id strings are stable identifiers:

```text
Command("version_before",  …)   Command("version_after",  …)
Command("cmdline_before",  …)   Command("cmdline_after",  …)
Command("soc_id_before",   …)   Command("selftest_after", …)
Command("selftest_before", …)
Command("panic_before",    …)
```

The three `*_after` commands run **immediately after a reboot**, which is
exactly when `autohud` has just restarted.

`exchange()` treats any non-`ok` END frame as a hard failure with no tolerance
(`exchange` in `tools/a90_acm_snapshot.py`):

```python
if not allow_error and (
    int(frame.end["rc"], 0) != 0 or frame.end["status"] != "ok"
):
    raise RuntimeError(...)
```

`[busy]` is already a recognised END marker in the frame regex
(`(?:done|err|busy)`), so the frame parses cleanly and then raises.

Note this is **not** the `safe_op_retries=0, retry_delay_sec=0` setting passed
to `driver.ReplConfig`. That governs the REPL effect and is correct as
written — the fixed op must never be replayed. The gap is in the read-only
preflight and postflight commands around it.

### Cost if it fires

Read against `docs/VERIFICATION024_CONTRACT_2026-08-27.md`:

- **Step 5** — the control must return `0xc071` and then pass exact
  version/cmdline/final-health checks, and *"Any other control outcome aborts
  the read phase and rolls back."* A transient channel contention is therefore
  recorded as a **control failure**, aborting the experiment on an instrument
  artifact rather than a device fact.
- **Step 11** — final health. A `busy` there leaves the lifecycle incomplete,
  which under the write gate *"prevent[s] public promotion"* of a run that
  actually succeeded.

The sequence costs three boot-prefix writes, up to two `param` transitions,
several reboots and one likely physical power-button recovery. Losing it to a
channel race is expensive and avoidable.

### Observed frequency

Verification 023 hit the device-side `busy` **three times** across its reboot
sequence, at every stage that polled after a boot:

- `tools/a90_native_reboot_observe.py` `_preflight` — before dispatch
- the same tool's `wait_for_new_boot` — after the MID reboot, which failed the
  run with `new native boot not observed: … rc=-16 status=busy` even though the
  reboot had succeeded
- two direct observation reads afterwards

In every case a single `stophud` cleared it and every subsequent `exchange()`
succeeded on the first attempt.

### Recommended fix

**Preferred — remove the contention source.** Issue `stophud` once immediately
after each boot, before any validation read. It is listed in the runtime's own
`help` output, it is not an effect on the measurement surface, and it is what
actually worked in 023.

**Alternative — tolerate the refusal.** For read-only preflight/postflight
commands only, accept `status=busy` as "not executed" and re-attempt a bounded
number of times with a short delay.

The second option does not weaken the no-retry rule, and the distinction should
be stated explicitly wherever it is implemented: **`busy` means the command
never ran.** The one-shot guarantee binds effects that were dispatched. A
read-only command that the runtime refused before executing has not been
dispatched, so re-attempting it is not a replay. This reasoning must not be
extended to the fixed op, to any flash, or to any `param` write.

### Suggested contract amendment

Whichever fix is chosen, the contract should say that a `busy` END frame on a
read-only validation command is an **instrument condition, not a control
outcome**, so step 5 cannot mistake it for `CONTROL_FAILED`.

## 2. Non-blocking — one 022R review sentence to tighten

`docs/VERIFICATION022R_INTEGRATION_REVIEW_2026-08-27.md` states:

> The payload-extracted JSONL is byte-identical to the retained raw JSONL.

The two files are not byte-identical:

| File | Bytes |
|---|---:|
| `probe-output.bin` | 294,258 |
| `pa28-identification.jsonl` | 294,218 |

The JSONL is *contained* in the framed output at offset 32, wrapped by the
runner banner and the exit marker:

```text
prefix  b'run: pid=763, q/Ctrl-C cancels\r\n'   32 bytes
suffix  b'[exit 0]'                              8 bytes
32 + 294,218 + 8 = 294,258
```

The substance is sound and the extraction is exact — this is a *stronger*
statement than the one written, since it identifies precisely what was stripped.
But a reader who runs `sha256sum` on both files finds them different and has
reason to distrust the rest of the review. Suggested replacement:

> The retained raw JSONL is exactly the payload of the framed probe output, with
> the runner banner (32 bytes) and the `[exit 0]` marker (8 bytes) removed;
> `32 + 294,218 + 8 = 294,258` accounts for the framed file in full.

## 3. What was independently reconfirmed, and what was not disputed

Verified here by direct recomputation, not by reading the review:

| Check | Result |
|---|---|
| Public manifest | 11,989 bytes, `f88a81bd3aabbd76cf2bcb8575f45d1cca7c29433a0279403d76d3affbfa2ca2` — matches |
| Five private receipt hashes | 5/5 match the review's table |
| Retained binary | `ed826cc75dee1eafad3b1b1ea4b0b779147364a330201e284b9e24c92adf1b92` — equals the pre- and post-execution remote hash |
| Source → binary | `tools/a90_pa28_probe_v022r.c` `d66e8930…` rebuilds byte-identically to the retained binary with the recorded command |
| Manifest regeneration | byte-identical |
| Focused tests | 36/36 |
| Redaction | no PID, private path, serial, cmdline, argv or transcript in the public manifest |

Independent reduction of `pa28-identification.jsonl`, without the 022R analyzer:

| Difference | Median | | Difference | Median |
|---|---:|---|---|---:|
| `0x16000` control | 540.0 | | `0x10008000` | 201.0 |
| `0x2000` control | 143.5 | | `0x1000a000` | 164.0 |
| `0x10002000` | 152.0 | | `0x1000c000` | 164.0 |
| **`0x10004000`** | **537.0** | | `0x1000e000` | 198.0 |
| `0x10006000` | 136.0 | | trailing controls | 543.0 / 133.0 |

Sorted-median widest gap `537 − 201 = 336`, threshold `(201 + 537) / 2 = 369` —
the review's threshold exactly. `f(PA28) = 010 = f(PA14)` follows from the raw
receipt without the analyzer. The `source → binary → device → data` chain that
Verification 022 lacked is complete in 022R.

Also noted, and better than expected: `ALLOWED_PREDECESSORS` in
`tools/a90_twrp_remapper_boot_flash.py` admits `read` only from `control`, so the paired control is not merely permitted but **required** to
have run first. That is stronger than the SHRM flash tool it derives from.

## 4. Not reviewed

`tools/a90_inline_remapper_mid_probe.py` was still being edited during this
review — it grew between two reads minutes apart, and the line numbers this
document originally cited had already shifted by the time they were checked,
which is why symbol names are used throughout. Only its `exchange()` call surface,
argv surface and fixed-constant sourcing were examined; the probe body,
lifecycle and failure paths were not. This handoff is therefore a partial
review, and the remaining pass is still owed before the live run.
