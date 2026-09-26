#!/usr/bin/env python3
"""Create non-secret static-to-dynamic fingerprint provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_id(path: Path) -> str | None:
    output = subprocess.run(
        ["readelf", "-n", str(path)], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    ).stdout
    match = re.search(r"Build ID: ([0-9a-f]+)", output)
    return match.group(1) if match else None


def parse_masked_pattern(value: str) -> list[int | None]:
    tokens: list[int | None] = []
    for token in value.split():
        if token in {"?", "??"}:
            tokens.append(None)
        else:
            tokens.append(int(token, 16))
    if not tokens:
        raise ValueError("fingerprint pattern is empty")
    return tokens


def count_masked_pattern(data: bytes, pattern: list[int | None]) -> int:
    width = len(pattern)
    return sum(
        all(expected is None or data[offset + index] == expected
            for index, expected in enumerate(pattern))
        for offset in range(0, max(0, len(data) - width + 1))
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--analysis-log", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--hook", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    masked_pattern = policy.get("hook_pattern_mask", policy["hook_pattern_hex"])
    pattern = parse_masked_pattern(masked_pattern)
    count = count_masked_pattern(args.binary.read_bytes(), pattern)
    if count != policy["required_pattern_matches"]:
        raise SystemExit(
            f"fingerprint count {count} != {policy['required_pattern_matches']}"
        )
    log_text = args.analysis_log.read_text(errors="replace")
    if policy.get("static_function_offset") and policy["static_function_offset"].lower().replace("0x", "") not in log_text.lower():
        raise SystemExit("frozen function offset was not found in the Ghidra analysis log")
    artifact_name = policy.get("hook_module")
    expected_artifact = policy.get("artifacts", {}).get(artifact_name, {})
    actual_hash = sha256(args.binary)
    actual_build_id = build_id(args.binary)
    if expected_artifact.get("sha256") and expected_artifact["sha256"] != actual_hash:
        raise SystemExit("binary SHA-256 does not match the fingerprint policy")
    if expected_artifact.get("build_id") and expected_artifact["build_id"] != actual_build_id:
        raise SystemExit("binary Build ID does not match the fingerprint policy")
    record = {
        "schema_version": 1,
        "binary": str(args.binary.resolve()),
        "binary_sha256": actual_hash,
        "binary_build_id": actual_build_id,
        "analysis_log": str(args.analysis_log.resolve()),
        "analysis_log_sha256": sha256(args.analysis_log),
        "label_reference": policy.get("label_reference"),
        "static_function_offset": policy.get("static_function_offset"),
        "function_or_pattern_id": policy["hook_pattern_id"],
        "exact_pattern_hex": policy["hook_pattern_hex"],
        "masked_pattern": masked_pattern,
        "pattern_match_count": count,
        "required_pattern_matches": policy["required_pattern_matches"],
        "associated_frida_hook": str(args.hook.resolve()),
        "associated_frida_hook_sha256": sha256(args.hook),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    args.output.chmod(0o600)
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
