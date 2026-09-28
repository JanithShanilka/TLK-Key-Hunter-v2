#!/usr/bin/env python3
"""Reference-free TLS 1.3 candidate assignment by direct record authentication."""
import argparse
import json
import os
import shutil
from pathlib import Path

from check_tls13_scenario import check_case
from rank_core import digest
from tls13_packets import SUITES, authenticate_marker, directional_records


LABELS = ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--offline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    condition = check_case(args.case)
    if not condition["condition_ok"]:
        raise RuntimeError("scenario_condition_failed:" + ",".join(condition["condition_failures"]))
    memory_seal = json.loads((args.offline / "selection-seal.json").read_text())
    raw = args.offline / "ranked-candidates.private.json"
    if digest(raw) != memory_seal["candidate_file_sha256"]:
        raise RuntimeError("Candidate seal mismatch")
    rows = json.loads(raw.read_text())
    if len(rows) > 100:
        raise RuntimeError("Pilot budget exceeds 100 candidates")
    args.output.mkdir(parents=True, exist_ok=False)

    streams = {}
    trials = []
    selected_ids = {}
    pass_counts = {}
    for target in condition["targets"]:
        stream = target["stream"]
        if stream not in streams:
            streams[stream] = directional_records(args.case / "traffic.pcap", stream, target["server_port"])
        winners = []
        expected_length = SUITES[target["cipher_suite"]]["secret_bytes"]
        for row in rows:
            if row["length"] != expected_length:
                continue
            matches = authenticate_marker(streams[stream][target["direction"]], bytes.fromhex(row["hex"]),
                                          target["cipher_suite"], target["marker"])
            trials.append({"target_id": target["id"], "candidate_id": row["id"],
                           "authenticated_marker": bool(matches), "match_count": len(matches)})
            if matches:
                winners.append(row["id"])
        pass_counts[target["id"]] = len(winners)
        selected_ids[target["id"]] = winners[0] if len(winners) == 1 else None

    chosen = [identity for identity in selected_ids.values() if identity]
    assignment_unique = (len(chosen) == len(condition["targets"]) and len(set(chosen)) == len(chosen))
    by_id = {row["id"]: row for row in rows}
    if assignment_unique:
        key_lines = []
        for target in condition["targets"]:
            row = by_id[selected_ids[target["id"]]]
            key_lines.append(f"{target['label']} {target['client_random']} {row['hex']}")
        selected_file = args.output / "selected.private.keys"
        selected_file.write_text("\n".join(key_lines) + "\n")
        selected_file.chmod(0o400)

    output = {**memory_seal, "scenario": condition["scenario"], "condition_check": condition,
              "selection_uses_pcap": True, "selection_uses_direct_tls13_record_authentication": True,
              "reference_input": False, "pcap_sha256": digest(args.case / "traffic.pcap"),
              "targets": condition["targets"], "trials": trials, "selected_ids": selected_ids,
              "target_pass_counts": pass_counts, "assignment_unique": assignment_unique}
    shutil.copyfile(raw, args.output / raw.name)
    (args.output / "selection-seal.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"scenario": output["scenario"], "candidate_count": output["candidate_count"],
                      "target_pass_counts": pass_counts, "assignment_unique": assignment_unique}))


if __name__ == "__main__":
    main()
