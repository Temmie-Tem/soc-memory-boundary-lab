"""Decode an XBL `SHRM_MEM.BIN` rawdump into labelled controller-register words.

Verification 002 proved that exact XBL registers raw-dump table index 19, which
exports physical `0x09060000..0x0906ffff` as `SHRM_MEM.BIN` and therefore
contains the whole section-16 workspace and both staged snapshot buffers.
Experiment 012 proved what those buffers hold: 430 and 64 32-bit words, read by
the SHRM helper from addresses `(base_page << 12) + (offset_token << 2)`.

Together those two results make the dump interpretable in advance. This module
carries the mapping from staged word index back to source controller register,
so a dump becomes labelled data the moment it exists rather than after a fresh
analysis pass.

It is useful before any dump exists: with no input it emits the *plan* — exactly
which registers the two buffers will contain, in order, with their topology
targets. That plan is also the honest scope statement for the dump route, and it
records one structural limitation callers must not misread (see
`remapper_coverage`).

The register plan is loaded from the committed Experiment 012 public manifest
rather than restated here, so this decoder cannot drift from the evidence it
depends on.

Host-only. Reads a local file if given one; performs no device, SMC, MMIO, or
protected-memory access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SECTION16_MANIFEST = (
    REPO_ROOT
    / "evidence"
    / "manifests"
    / "012-shrm-section16-inventory-20260825-01.manifest.json"
)

# Verification 002: rawdump table index 19.
DUMP_BASE = 0x09060000
DUMP_SIZE = 0x10000

# Experiment 012: workspace physical address and size.
WORKSPACE_PA = 0x09065100
WORKSPACE_OFFSET = WORKSPACE_PA - DUMP_BASE
WORKSPACE_SIZE = 0xF00
EXPECTED_HEADER = (0x0008, 0x0230, 0x01B8, 0x08E8)

# Experiment 006/008: the ICB remapper window and its control register.
REMAPPER_WINDOWS = (0x09248080, 0x092C8080, 0x09348080, 0x093C8080)
REMAPPER_WINDOW_SPAN = 0x5C


class DumpError(ValueError):
    """Raised when a dump is structurally inconsistent with the proved layout."""


@dataclass(frozen=True)
class StagedWord:
    index: int
    dump_offset: int
    register: int
    topology: tuple[str, ...]
    value: int | None = None


@dataclass(frozen=True)
class DecodedSet:
    destination_offset: int
    words: tuple[StagedWord, ...]

    @property
    def count(self) -> int:
        return len(self.words)


def _load_section16() -> dict:
    if not SECTION16_MANIFEST.exists():
        raise DumpError(f"missing Experiment 012 manifest: {SECTION16_MANIFEST}")
    return json.loads(SECTION16_MANIFEST.read_text(encoding="utf-8"))


def load_plan() -> tuple[DecodedSet, ...]:
    """Return the ordered staged-word plan for both section-16 sets.

    Order follows the helper's iteration: for each record, base pages outer and
    offset tokens inner, which is what produces the manifest's flattened
    ``register_addresses`` sequence.
    """
    manifest = _load_section16()
    interpreter = manifest["section16_interpreter"]
    classification = manifest.get("section16_page_classification", {}).get("sets", [])

    plans = []
    for set_index, entry in enumerate(interpreter["sets"]):
        targets = {}
        if set_index < len(classification):
            targets = classification[set_index].get("base_page_topology_targets", {})

        destination = int(entry["destination_offset"], 16)
        words = []
        index = 0
        for record in entry["records"]:
            pages = [int(page, 16) for page in record["base_pages"]]
            addresses = [int(address, 16) for address in record["register_addresses"]]
            offsets_per_page = len(addresses) // len(pages) if pages else 0
            for page_index, page in enumerate(pages):
                key = f"{page:#06x}".replace("0x", "0x")
                topology = tuple(targets.get(f"0x{page:04x}", ()))
                for slot in range(offsets_per_page):
                    address = addresses[page_index * offsets_per_page + slot]
                    words.append(
                        StagedWord(
                            index=index,
                            dump_offset=WORKSPACE_OFFSET + destination + index * 4,
                            register=address,
                            topology=topology,
                        )
                    )
                    index += 1
        plans.append(DecodedSet(destination_offset=destination, words=tuple(words)))
    return tuple(plans)


def validate_dump(data: bytes) -> None:
    """Check a dump against the proved layout before trusting any word.

    The workspace is inside the dumped range, so its section-16 header is a
    self-check: a genuine, correctly aligned `SHRM_MEM.BIN` must reproduce the
    exact header Experiment 012 parsed from the selected DCB.
    """
    if len(data) != DUMP_SIZE:
        raise DumpError(f"dump is {len(data)} bytes, expected {DUMP_SIZE}")
    header = struct.unpack_from("<4H", data, WORKSPACE_OFFSET)
    if header != EXPECTED_HEADER:
        raise DumpError(
            "workspace header "
            + "/".join(f"{value:#06x}" for value in header)
            + " does not match the proved section-16 header "
            + "/".join(f"{value:#06x}" for value in EXPECTED_HEADER)
        )


def decode(data: bytes) -> tuple[DecodedSet, ...]:
    """Attach dump values to the staged-word plan."""
    validate_dump(data)
    decoded = []
    for plan in load_plan():
        words = []
        for word in plan.words:
            if word.dump_offset + 4 > len(data):
                raise DumpError(f"staged word {word.index} falls outside the dump")
            value = struct.unpack_from("<I", data, word.dump_offset)[0]
            words.append(
                StagedWord(
                    index=word.index,
                    dump_offset=word.dump_offset,
                    register=word.register,
                    topology=word.topology,
                    value=value,
                )
            )
        decoded.append(DecodedSet(plan.destination_offset, tuple(words)))
    return tuple(decoded)


def remapper_coverage(plans: tuple[DecodedSet, ...]) -> dict:
    """Report whether the snapshot reaches the ICB remapper window. It does not.

    This is the limitation most likely to be misread. The snapshot does read
    nine words from each remapper's 4-KiB page, which invites the conclusion
    that a dump answers the open remapper questions. It does not: Experiment 006
    places the window at `qhs_llcc + 0x8080` and Experiment 008 places the
    control register with its enable bit at window `+0x00`, so the control
    register is `0x09248080` — the exact address whose EL1 read produced the
    Experiment 007 watchdog. Every staged word on those pages lies strictly
    below `0x09248080`.

    So the dump route does not recover boot remapper values, the active-slot
    mask, or lock state. It does carry MCCC/MC/DDRSS/LLCC state, which is where
    an interleave or hash configuration would live, so it remains on target for
    the hidden-transform question and off target for the remapper question.
    """
    staged = {word.register for plan in plans for word in plan.words}
    same_page = sorted(
        register
        for register in staged
        if any(
            (register & ~0xFFF) == (window & ~0xFFF) for window in REMAPPER_WINDOWS
        )
    )
    inside_window = sorted(
        register
        for register in staged
        if any(
            window <= register < window + REMAPPER_WINDOW_SPAN
            for window in REMAPPER_WINDOWS
        )
    )
    return {
        "control_registers": [f"{window:#010x}" for window in REMAPPER_WINDOWS],
        "staged_on_remapper_pages": [f"{value:#010x}" for value in same_page],
        "staged_inside_remapper_window": [f"{value:#010x}" for value in inside_window],
        "covers_remapper_window": bool(inside_window),
        "note": (
            "Staged words share the remapper's 4-KiB page but lie strictly below "
            "the window at +0x8080. Boot remapper values, active-slot mask and "
            "lock state are NOT recoverable from this dump."
        ),
    }


def topology_summary(plans: tuple[DecodedSet, ...]) -> dict:
    counts: dict[str, int] = {}
    unlabelled = 0
    for plan in plans:
        for word in plan.words:
            if not word.topology:
                unlabelled += 1
                continue
            for name in word.topology:
                counts[name] = counts.get(name, 0) + 1
    return {"labelled": dict(sorted(counts.items())), "unlabelled_words": unlabelled}


def build_manifest(plans: tuple[DecodedSet, ...], dump_path: Path | None, data: bytes | None) -> dict:
    has_values = data is not None
    return {
        "schema": "sdm855-shrm-dump-decode-public-v1",
        "mode": "HOST_ONLY_READ_ONLY",
        "state": "DECODED" if has_values else "PLAN_ONLY_NO_DUMP_PRESENT",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "register_values_emitted": False,
        "dump": {
            "base": f"{DUMP_BASE:#010x}",
            "size": DUMP_SIZE,
            "filename": dump_path.name if dump_path else None,
            "sha256": hashlib.sha256(data).hexdigest() if has_values else None,
            "workspace_pa": f"{WORKSPACE_PA:#010x}",
            "workspace_dump_offset": f"{WORKSPACE_OFFSET:#06x}",
        },
        "sets": [
            {
                "destination_offset": f"{plan.destination_offset:#06x}",
                "staged_words": plan.count,
                "first_register": f"{plan.words[0].register:#010x}" if plan.words else None,
                "last_register": f"{plan.words[-1].register:#010x}" if plan.words else None,
                "distinct_registers": len({word.register for word in plan.words}),
            }
            for plan in plans
        ],
        "topology": topology_summary(plans),
        "remapper_coverage": remapper_coverage(plans),
        "provenance": {
            "register_plan": SECTION16_MANIFEST.name,
            "export_path": "Verification 002 rawdump table index 19 (SHRM_MEM.BIN)",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dump",
        type=Path,
        default=None,
        help="path to SHRM_MEM.BIN; omit to emit the register plan only",
    )
    parser.add_argument(
        "--values",
        action="store_true",
        help="print decoded register values to stdout (never written to a manifest)",
    )
    args = parser.parse_args(argv)

    data = None
    if args.dump is not None:
        data = args.dump.read_bytes()
        plans = decode(data)
    else:
        plans = load_plan()

    manifest = build_manifest(plans, args.dump, data)
    print(json.dumps(manifest, indent=2, sort_keys=True))

    if args.values and data is not None:
        print("\n# staged register values", file=sys.stderr)
        for plan in plans:
            for word in plan.words:
                names = ",".join(word.topology) or "-"
                print(
                    f"{word.register:#010x} = {word.value:#010x}  [{names}]",
                    file=sys.stderr,
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
