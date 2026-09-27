#!/usr/bin/env python3
"""Exploratory SECItem-shaped TLS 1.2 candidate ranking; no reference input."""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import time

from core_memory import CoreMemory


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def rank(core, layout="secitem48"):
    candidates = {}
    structures = 0
    # Proposed NSS SECItem ABI: uint32 type; padding; pointer data; uint32 length.
    # This shape is only a heuristic, not proof that an object is an NSS secret.
    for length_address in core.find(struct.pack("<I", 48)):
        item = length_address - 16
        if item % 8:
            continue
        try:
            if layout == "cka-value48":
                # PKCS #11 CK_ATTRIBUTE on this Linux x86-64 ABI:
                # CK_ULONG type; void *pValue; CK_ULONG ulValueLen.
                kind, pointer, length = struct.unpack("<QQQ", core.read(item, 24))
                valid_kind = kind == 0x11  # CKA_VALUE, not an arbitrary entropy window.
            else:
                kind, pointer, length = struct.unpack("<I4xQI", core.read(item, 20))
                valid_kind = kind <= 15
            if not valid_kind or pointer < 4096 or length != 48:
                continue
            value = core.read(pointer, length)
        except (ValueError, struct.error):
            continue
        structures += 1
        entropy = -sum((n / 48) * math.log2(n / 48) for n in Counter(value).values())
        zeros = value.count(0)
        score = 40 + (25 if entropy >= 4 else 0) + (10 if zeros <= 6 else 0)
        if score < 65:
            continue
        identity = hashlib.sha256(value).hexdigest()
        row = candidates.setdefault(identity, {"id": identity, "hex": value.hex(), "score": score,
                                               "length": 48, "entropy": entropy, "zero_bytes": zeros,
                                               "locations": []})
        row["locations"].append({"item": hex(item), "data": hex(pointer), "type": kind})
        if len(candidates) > 100000:
            raise RuntimeError("Candidate budget exceeded; no successful selection claimed")
    rows = sorted(candidates.values(), key=lambda row: (-row["score"], row["id"]))
    top = [row for row in rows if row["score"] == rows[0]["score"]] if rows else []
    selected = top[0] if len(top) == 1 else None
    return rows, {"status": "selected" if selected else "ambiguous" if top else "no_candidate",
                  "candidate_count": len(rows), "plausible_structures": structures,
                  "top_tie_count": len(top), "selected_id": selected["id"] if selected else None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--layout", choices=("secitem48", "cka-value48"), default="secitem48")
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic()
    with CoreMemory(args.core) as core:
        rows, summary = rank(core, args.layout)
        summary["captured_segments"] = len(core.segments)
    summary.update({"method": "experimental_" + args.layout + "_single_snapshot", "protocol": "TLS1.2",
                    "original_arg_ranker_D": False, "reference_input": False,
                    "core_sha256": digest(args.core), "elapsed_seconds": time.monotonic() - start})
    private = args.output / "ranked-candidates.private.json"
    private.write_text(json.dumps(rows, indent=2) + "\n")
    private.chmod(0o400)
    summary["candidate_file_sha256"] = digest(private)
    (args.output / "selection-seal.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.output / "selection-seal.json").chmod(0o400)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
