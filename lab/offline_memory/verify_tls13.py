#!/usr/bin/env python3
"""Post-selection TLS 1.3 reference comparison and independent controls."""
import argparse
import json
import os
from pathlib import Path

from core_memory import CoreMemory
from rank_core import digest
from tls13_packets import authenticate_keyupdate, authenticate_marker, directional_records


def read_references(path):
    references = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) != 3 or "TRAFFIC_SECRET_" not in parts[0]:
            continue
        label = parts[0]
        if label in ("CLIENT_TRAFFIC_SECRET_N", "SERVER_TRAFFIC_SECRET_N"):
            label = label.replace("_N", "_1")
        key = (label, parts[1].lower())
        value = bytes.fromhex(parts[2])
        if key in references and references[key] != value:
            raise RuntimeError("Conflicting duplicate reference entry")
        references[key] = value
    return references


def keyupdate_packet_evidence(targets, streams, references):
    client = next(target for target in targets if target["direction"] == "client")
    server = next(target for target in targets if target["direction"] == "server")
    client_secret = references[("CLIENT_TRAFFIC_SECRET_0", client["client_random"])]
    server_secret = references[("SERVER_TRAFFIC_SECRET_0", server["client_random"])]
    server_requested = bool(authenticate_keyupdate(
        streams[server["stream"]]["server"], server_secret, server["cipher_suite"], 1))
    client_responded = bool(authenticate_keyupdate(
        streams[client["stream"]]["client"], client_secret, client["cipher_suite"], 0))
    return {"server_requested_peer_update": server_requested,
            "client_sent_update_response": client_responded,
            "packet_condition_ok": server_requested and client_responded}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    offline = args.case / "offline-tls13-pcap"
    seal = json.loads((offline / "selection-seal.json").read_text())
    raw = offline / "ranked-candidates.private.json"
    if (digest(raw) != seal["candidate_file_sha256"] or
            digest(args.case / "firefox.core") != seal["core_sha256"] or
            digest(args.case / "traffic.pcap") != seal["pcap_sha256"]):
        raise RuntimeError("Evidence hash mismatch")
    rows = json.loads(raw.read_text())
    by_id = {row["id"]: row for row in rows}
    references = read_references(args.reference)
    output = args.case / "verification-tls13"
    output.mkdir(exist_ok=False)

    streams = {}
    comparisons = {}
    reference_markers = {}
    selected_markers = {}
    one_bit_controls = {}
    with CoreMemory(args.case / "firefox.core") as core:
        for target in seal["targets"]:
            target_id = target["id"]
            reference = references.get((target["label"], target["client_random"]))
            if reference is None:
                raise RuntimeError(f"Missing target reference: {target_id}")
            selected = by_id.get(seal["selected_ids"].get(target_id))
            value = bytes.fromhex(selected["hex"]) if selected else None
            comparisons[target_id] = {
                "bits": len(reference) * 8,
                "literal_occurrences": sum(1 for _ in core.find(reference)),
                "reference_in_candidate_set": any(bytes.fromhex(row["hex"]) == reference for row in rows),
                "exact_match": value == reference,
                "hamming_distance_bits": (sum((left ^ right).bit_count()
                                                for left, right in zip(value, reference))
                                          if value is not None else None),
            }
            stream = target["stream"]
            if stream not in streams:
                streams[stream] = directional_records(args.case / "traffic.pcap", stream, target["server_port"])
            records = streams[stream][target["direction"]]
            reference_markers[target_id] = bool(authenticate_marker(
                records, reference, target["cipher_suite"], target["marker"]))
            selected_markers[target_id] = bool(value and authenticate_marker(
                records, value, target["cipher_suite"], target["marker"]))
            corrupted = bytearray(reference)
            corrupted[0] ^= 1
            one_bit_controls[target_id] = {"target_marker_rejected": not authenticate_marker(
                records, bytes(corrupted), target["cipher_suite"], target["marker"])}

    cross_flow_controls = {}
    cross_generation_controls = {}
    for target in seal["targets"]:
        records = streams[target["stream"]][target["direction"]]
        flow_peers = [other for other in seal["targets"]
                      if other["id"] != target["id"] and other["label"] == target["label"]]
        for other in flow_peers:
            selected = by_id.get(seal["selected_ids"].get(other["id"]))
            if selected:
                key = f"{other['id']}=>{target['id']}"
                cross_flow_controls[key] = not authenticate_marker(
                    records, bytes.fromhex(selected["hex"]), target["cipher_suite"], target["marker"])
        generation_peers = [other for other in seal["targets"]
                            if other["id"] != target["id"] and other["flow_index"] == target["flow_index"]
                            and other["direction"] == target["direction"]
                            and other["generation"] != target["generation"]]
        for other in generation_peers:
            selected = by_id.get(seal["selected_ids"].get(other["id"]))
            if selected:
                key = f"{other['id']}=>{target['id']}"
                cross_generation_controls[key] = not authenticate_marker(
                    records, bytes.fromhex(selected["hex"]), target["cipher_suite"], target["marker"])

    if seal["scenario"] == "keyupdate":
        for target in seal["targets"]:
            generation_zero_label = ("CLIENT_TRAFFIC_SECRET_0" if target["direction"] == "client"
                                     else "SERVER_TRAFFIC_SECRET_0")
            generation_zero = references[(generation_zero_label, target["client_random"])]
            key = f"flow{target['flow_index']}:{generation_zero_label}=>{target['id']}"
            cross_generation_controls[key] = not authenticate_marker(
                streams[target["stream"]][target["direction"]], generation_zero,
                target["cipher_suite"], target["marker"])

    packet_condition = {"packet_condition_ok": True}
    if seal["scenario"] == "keyupdate":
        packet_condition = keyupdate_packet_evidence(seal["targets"], streams, references)
    exact_ok = all(value["exact_match"] for value in comparisons.values())
    markers_ok = all(reference_markers.values()) and all(selected_markers.values())
    controls_ok = (all(value["target_marker_rejected"] for value in one_bit_controls.values()) and
                   all(cross_flow_controls.values()) and all(cross_generation_controls.values()))
    complete = bool(seal["condition_check"]["condition_ok"] and packet_condition["packet_condition_ok"] and
                    seal["assignment_unique"] and exact_ok and markers_ok and controls_ok)
    report = {
        "case_id": args.case.name, "scenario": seal["scenario"], "protocol": "TLS1.3",
        "candidate_count": len(rows), "target_count": len(seal["targets"]),
        "condition_check": seal["condition_check"], "reference_comparison_after_seal": True,
        "selection_uses_pcap": True, "selection_uses_direct_tls13_record_authentication": True,
        "reference_used_for_selection": False, "presence_audit_uses_reference": True,
        "core_sha256": seal["core_sha256"], "pcap_sha256": seal["pcap_sha256"],
        "target_pass_counts": seal["target_pass_counts"], "assignment_unique": seal["assignment_unique"],
        "directional_comparisons": comparisons, "reference_marker_checks": reference_markers,
        "selected_marker_checks": selected_markers, "one_bit_controls": one_bit_controls,
        "cross_flow_controls": cross_flow_controls, "cross_generation_controls": cross_generation_controls,
        "packet_condition": packet_condition, "exact_match_all_targets": exact_ok,
        "controlled_markers_all_targets": markers_ok, "wrong_secret_controls_all_pass": controls_ok,
        "complete_offline_recovery": complete,
    }
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
