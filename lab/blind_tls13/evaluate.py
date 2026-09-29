#!/usr/bin/env python3
"""Private study preparation, sealed-output verification, and scoring."""

import argparse
from bisect import bisect_right
import json
import mmap
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "offline_memory"))
from core_memory import CoreMemory
from tls13_packets import directional_records, inspect_connections
from recover import digest
from record_auth import authenticate_application_epoch


def reference_secrets(path):
    result = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"):
            key = (parts[1].lower(), "client" if parts[0].startswith("CLIENT") else "server")
            value = bytes.fromhex(parts[2])
            if key in result and result[key] != value:
                raise ValueError("Conflicting reference secret")
            result[key] = value
    return result


def flow_truth(pcap, workload, keylog):
    connections = inspect_connections(pcap)
    by_port = {row["client_port"]: row for row in connections}
    references = reference_secrets(keylog)
    targets = {}
    for flow in json.loads(workload.read_text())["flows"]:
        if len(flow["client_messages"]) < 2 or len(flow["server_messages"]) < 2:
            raise ValueError("Workload lacked two messages in each direction")
        connection = by_port.get(flow["peer_port"])
        if connection is None or connection["cipher_suite"] != "0x1302":
            raise ValueError("Cannot bind controlled flow to PCAP handshake")
        flow_records = directional_records(pcap, connection["stream"], connection["server_port"])
        for direction in ("client", "server"):
            key = (connection["client_random"], direction)
            if key not in references:
                raise ValueError("Missing isolated reference secret")
            records = flow_records[direction]
            if not authenticate_application_epoch(records, references[key], connection["cipher_suite"], 3):
                raise ValueError("Complete PCAP lacks three authenticated application records per direction")
            targets[key] = references[key]
    return targets


def redact_core(source, destination, reference):
    """Evaluator-only negative control; preserve the ELF layout and sparse core."""
    if len(reference) != 48:
        raise ValueError("Expected 48-byte pinned-suite secret")
    subprocess.run(["cp", "--sparse=always", "--reflink=auto", str(source), str(destination)], check=True)
    destination.chmod(0o600)
    with CoreMemory(destination) as core:
        locations = list(core.find(reference))
        segments = list(core.segments)
        bases = list(core.bases)
    if not locations:
        destination.unlink()
        raise ValueError("Withheld reference was not literally present in source core")
    with destination.open("r+b") as stream:
        mapped = mmap.mmap(stream.fileno(), 0)
        try:
            for address in locations:
                index = bisect_right(bases, address) - 1
                base, size, offset, _ = segments[index]
                if address + len(reference) > base + size:
                    raise ValueError("Cross-segment reference redaction requires a separate case")
                replacement = secrets.token_bytes(len(reference))
                while replacement == reference:
                    replacement = secrets.token_bytes(len(reference))
                file_offset = offset + address - base
                mapped[file_offset:file_offset + len(reference)] = replacement
            mapped.flush()
        finally:
            mapped.close()
    with CoreMemory(destination) as core:
        if next(core.find(reference), None) is not None:
            raise RuntimeError("Reference remained after redaction")
    destination.chmod(0o444)
    return {"literal_occurrences_removed": len(locations), "redacted_core_sha256": digest(destination)}


def stage_input(inbox, core, pcap, metadata):
    """Expose only the declared recovery inputs through a researcher-readable inbox."""
    inbox.mkdir(parents=True, exist_ok=False)
    inbox.chmod(0o755)
    for source, name in ((core, "memory.core"), (pcap, "traffic.pcap")):
        target = inbox / name
        os.link(source, target)
        target.chmod(0o444)
    target = inbox / "target.json"
    target.write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    target.chmod(0o444)
    return {"core": inbox / "memory.core", "pcap": inbox / "traffic.pcap", "metadata": target}


def verify_seal(folder):
    seal = json.loads((folder / "seal.json").read_text())
    for filename, field in (("candidates.private.json", "candidates_sha256"),
                            ("decisions.json", "decisions_sha256")):
        if digest(folder / filename) != seal[field]:
            raise ValueError("Recovery output seal mismatch")
    return json.loads((folder / "decisions.json").read_text()), json.loads((folder / "candidates.private.json").read_text())


def score_method(report, rows, targets, kind, withheld=None):
    candidates = {row["id"]: bytes.fromhex(row["hex"]) for row in rows}
    decisions = {(row["client_random"], row["direction"]): row for row in report["decisions"]}
    if len(decisions) != len(report["decisions"]):
        raise ValueError("Duplicate connection/direction decision")
    missing = set(targets) - set(decisions)
    if missing:
        raise ValueError("Recovery omitted captured target connections")
    correct, false, abstained = 0, 0, 0
    details = {}
    for key, decision in decisions.items():
        selected = decision["status"] == "selected"
        value = candidates.get(decision["candidate_id"]) if selected else None
        if selected and value is None:
            raise ValueError("Selected candidate missing from sealed list")
        expected = targets.get(key)
        is_correct = bool(selected and expected is not None and value == expected and key != withheld and kind == "positive")
        if kind == "withheld":
            is_correct = bool(selected and expected is not None and value == expected and key != withheld)
        if is_correct:
            correct += 1
        elif selected:
            false += 1
        else:
            abstained += 1
        details[f"{key[0]}:{key[1]}"] = {"correct": is_correct, "false_assignment": selected and not is_correct,
                                           "unresolved": not selected,
                                           "reference_in_candidate_set": expected in candidates.values() if expected else False}
    target_count = len(targets)
    if kind in ("mismatch", "unrelated"):
        passed = false == 0 and abstained == len(decisions)
    elif kind == "withheld":
        passed = correct == target_count - 1 and false == 0 and decisions[withheld]["status"] == "unresolved"
    else:
        passed = correct == target_count and false == 0
    return {"case_success": passed, "correct_targets": correct, "false_assignments": false,
            "abstentions": abstained, "target_count": target_count, "decision_count": len(decisions),
            "details": details, "wall_seconds": report["wall_seconds"], "cpu_seconds": report["cpu_seconds"],
            "peak_rss_kib": report["peak_rss_kib"], "candidate_count": report["candidate_count"]}


def score_pair(structured_folder, entropy_folder, core, pcap, workload, keylog, kind, withheld=None):
    # The evaluator opens its answer files only after both independent seals pass.
    reports = {"structured": verify_seal(structured_folder), "entropy": verify_seal(entropy_folder)}
    expected_core, expected_pcap = digest(core), digest(pcap)
    metadata_hashes = set()
    for method, (report, rows) in reports.items():
        if report["method"] != method or report["candidate_count"] != len(rows):
            raise ValueError("Sealed method identity or candidate count mismatch")
        if report["input_sha256"]["core"] != expected_core or report["input_sha256"]["pcap"] != expected_pcap:
            raise ValueError("Sealed recovery inputs differ from evaluator inputs")
        metadata_hashes.add(report["input_sha256"]["metadata"])
    if len(metadata_hashes) != 1:
        raise ValueError("The two methods received different target metadata")
    targets = flow_truth(pcap, workload, keylog)
    if kind == "withheld" and withheld not in targets:
        raise ValueError("Withheld target is not in evaluator truth")
    return {method: score_method(report, rows, targets, kind, withheld)
            for method, (report, rows) in reports.items()}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--structured", type=Path, required=True)
    parser.add_argument("--entropy", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--keylog", type=Path, required=True)
    parser.add_argument("--kind", choices=("positive", "mismatch", "unrelated", "withheld"), required=True)
    parser.add_argument("--withheld-random")
    parser.add_argument("--withheld-direction", choices=("client", "server"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    withheld = ((args.withheld_random, args.withheld_direction) if args.kind == "withheld" else None)
    result = score_pair(args.structured, args.entropy, args.core, args.pcap,
                        args.workload, args.keylog, args.kind, withheld)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({method: {k: value[k] for k in ("case_success", "correct_targets", "false_assignments")}
                      for method, value in result.items()}))


if __name__ == "__main__":
    main()
