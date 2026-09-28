#!/usr/bin/env python3
"""Reference-free checks for the claimed TLS 1.3 scenario condition."""
import argparse
import json
import os
from pathlib import Path

from tls13_packets import inspect_connections


def targets_for(scenario, flows, connections):
    by_port = {item["client_port"]: item for item in connections}
    targets = []
    # Resumption flow zero establishes the ticket; the live resumed flow is the
    # memory-recovery target. KeyUpdate generation zero establishes and
    # authenticates the transition; generation one is the post-update target.
    target_flows = flows[1:] if scenario == "resumption" else flows
    for flow in target_flows:
        connection = by_port.get(flow["peer_port"])
        if connection is None:
            raise RuntimeError(f"No captured handshake for flow {flow['index']}")
        generations = (1,) if scenario == "keyupdate" else (0,)
        for generation in generations:
            for direction in ("CLIENT", "SERVER"):
                label = f"{direction}_TRAFFIC_SECRET_{generation}"
                if generation == 0:
                    marker = flow["request_path"] if direction == "CLIENT" else flow["response_marker"]
                else:
                    marker = flow["post_request_path"] if direction == "CLIENT" else flow["post_response_marker"]
                targets.append({
                    "id": f"flow{flow['index']}:{label}",
                    "flow_index": flow["index"],
                    "stream": connection["stream"],
                    "client_port": connection["client_port"],
                    "server_port": connection["server_port"],
                    "client_random": connection["client_random"],
                    "cipher_suite": connection["cipher_suite"],
                    "label": label,
                    "direction": direction.lower(),
                    "generation": generation,
                    "marker": marker,
                })
    return targets


def evaluate(scenario, flows, connections, acquisition):
    reasons = []
    if scenario in ("before-response", "delayed", "keyupdate") and len(flows) != 1:
        reasons.append("expected_one_flow")
    if scenario in ("resumption", "concurrency") and len(flows) != 2:
        reasons.append("expected_two_flows")
    if len(connections) != len(flows):
        reasons.append("handshake_flow_count_mismatch")
    if any(flow.get("protocol") != "TLSv1.3" for flow in flows):
        reasons.append("protocol_not_tls13")
    if any(flow.get("cipher") != "TLS_AES_256_GCM_SHA384" for flow in flows):
        reasons.append("unexpected_cipher")

    if scenario == "before-response" and flows:
        flow = flows[0]
        if acquisition["capture_started_monotonic"] < flow["request_monotonic"]:
            reasons.append("capture_started_before_request")
        if acquisition["capture_ended_monotonic"] > flow["response_monotonic"]:
            reasons.append("capture_ended_after_response")
    elif scenario == "delayed" and flows:
        delay = acquisition["capture_started_monotonic"] - flows[0]["response_monotonic"]
        if delay < 30:
            reasons.append("capture_delay_below_30_seconds")
    elif scenario == "resumption" and len(flows) == 2 and len(connections) == 2:
        if flows[0].get("session_reused") or not flows[1].get("session_reused"):
            reasons.append("server_resumption_state_invalid")
        by_port = {item["client_port"]: item for item in connections}
        first = by_port.get(flows[0]["peer_port"], {})
        second = by_port.get(flows[1]["peer_port"], {})
        if 41 in first.get("server_extensions", []):
            reasons.append("first_connection_used_psk")
        if 41 not in second.get("client_extensions", []) or 41 not in second.get("server_extensions", []):
            reasons.append("second_connection_missing_psk_packet_evidence")
    elif scenario == "concurrency" and len(flows) == 2 and len(connections) == 2:
        if len({flow["peer_port"] for flow in flows}) != 2:
            reasons.append("peer_ports_not_distinct")
        if len({item["client_random"] for item in connections}) != 2:
            reasons.append("client_randoms_not_distinct")
        if flows[0].get("closed_monotonic", 0) <= flows[1].get("accepted_monotonic", float("inf")):
            reasons.append("flows_did_not_overlap")
    elif scenario == "keyupdate" and flows:
        required = ("update_requested_monotonic", "post_request_path", "post_response_marker", "post_response_monotonic")
        if any(name not in flows[0] for name in required):
            reasons.append("keyupdate_workload_incomplete")

    targets = targets_for(scenario, flows, connections) if not reasons else []
    return {"scenario": scenario, "condition_ok": not reasons, "condition_failures": reasons,
            "flow_count": len(flows), "connection_count": len(connections),
            "connections": connections, "targets": targets}


def check_case(case):
    events = json.loads((case / "scenario-events.json").read_text())
    acquisition = json.loads((case / "acquisition-seal.json").read_text())
    scenario = events["scenario"]
    if acquisition.get("scenario") != scenario:
        raise RuntimeError("Acquisition/scenario mismatch")
    connections = inspect_connections(case / "traffic.pcap")
    return evaluate(scenario, events["flows"], connections, acquisition)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    report = check_case(args.case)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"scenario": report["scenario"], "condition_ok": report["condition_ok"],
                      "flow_count": report["flow_count"], "target_count": len(report["targets"])}))
    if not report["condition_ok"]:
        raise RuntimeError("scenario_condition_failed:" + ",".join(report["condition_failures"]))


if __name__ == "__main__":
    main()
