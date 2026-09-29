#!/usr/bin/env python3
"""Blind saved-memory TLS 1.3 recovery: core, PCAP, pinned metadata only."""

import argparse
from collections import Counter
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import resource
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "offline_memory"))
from core_memory import CoreMemory
from rank_tls13 import rank as structured_rank
from tls13_packets import SUITES, directional_records, inspect_connections
from record_auth import authenticate_application_epoch

SECRET_BYTES = 48
MAX_CANDIDATES = 100
SEARCH_SECONDS = 180
AUTH_SECONDS = 300
PINNED_HASHES = {
    "firefox": "385265da8818d293afd50ce410b678e3cf2079bb4e2d60231dfb818cd12b8b55",
    "libssl3.so": "41b76c48fff44d62e34b463e52d1a4842f1b8c39711e6e1ac77ae6dbc3906f57",
    "libsoftokn3.so": "064c24743abe22bc8c9b87c6f8c4d7e8facc66d94a73b7ed9702e1d2733d2fe7",
}


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(value):
    count = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in count.values())


def entropy_rank(core, deadline, maximum=MAX_CANDIDATES):
    """Entropy-only baseline over every readable 48-byte window in address order.

    The bounded top-k heap and deterministic digest tie-break avoid a baseline
    that depends on which high-entropy window happened to appear first.
    """
    selected = {}
    heap = []
    windows = 0
    skipped_zero_windows = 0
    timed_out = False
    for base, size, offset, _flags in core.segments:
        if size < SECRET_BYTES:
            continue
        position = 0
        zero_block = None
        zero_block_end = 0
        while position <= size - SECRET_BYTES:
            if position % 4096 == 0 and time.monotonic() >= deadline:
                timed_out = True
                break
            block_start = (position // 4096) * 4096
            if zero_block != block_start:
                zero_block = block_start
                zero_block_end = min(size, block_start + 4096)
                block = core.data[offset + block_start:offset + zero_block_end]
                block_is_zero = block.count(0) == len(block)
            if block_is_zero and position < zero_block_end - 6:
                destination = min(zero_block_end - 6, size - SECRET_BYTES + 1)
                skipped_zero_windows += destination - position
                position = destination
                continue
            value = core.data[offset + position:offset + position + SECRET_BYTES]
            windows += 1
            position += 1
            if value.count(0) > 6:
                continue
            score = entropy(value)
            if score < 4:
                continue
            identity = hashlib.sha256(value).hexdigest()
            if identity in selected:
                continue
            # Prefer higher entropy; use the digest as a stable tie-break.
            priority = (score, identity)
            row = {"id": identity, "hex": value.hex(), "length": SECRET_BYTES,
                   "score": score, "entropy": score, "zero_bytes": value.count(0),
                   "locations": [{"data": hex(base + position)}]}
            if len(heap) < maximum:
                heapq.heappush(heap, (priority, identity))
                selected[identity] = row
            elif priority > heap[0][0]:
                _, removed = heapq.heapreplace(heap, (priority, identity))
                del selected[removed]
                selected[identity] = row
        if timed_out:
            break
    rows = sorted(selected.values(), key=lambda row: (-row["entropy"], row["id"]))
    return rows, {"windows_scanned": windows, "zero_page_windows_skipped": skipped_zero_windows,
                  "search_exhausted": not timed_out}


def bounded_structured_rank(core, seconds):
    def expired(_signum, _frame):
        raise TimeoutError("Structured candidate search exceeded its budget")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, seconds))
    try:
        rows = [row for row in structured_rank(core) if row["length"] == SECRET_BYTES]
        return rows[:MAX_CANDIDATES], {"search_exhausted": len(rows) <= MAX_CANDIDATES,
                                       "windows_scanned": None,
                                       "candidate_budget_exceeded": len(rows) > MAX_CANDIDATES}
    except TimeoutError:
        return [], {"search_exhausted": False, "windows_scanned": None,
                    "search_timed_out": True}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def assign(rows, connections, pcap, deadline):
    results = []
    trial_count = 0
    timed_out = False
    for connection in connections:
        records = directional_records(pcap, connection["stream"], connection["server_port"])
        for direction in ("client", "server"):
            winners = []
            for row in rows:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                if row["length"] != SUITES[connection["cipher_suite"]]["secret_bytes"]:
                    continue
                trial_count += 1
                evidence = authenticate_application_epoch(
                    records[direction], bytes.fromhex(row["hex"]), connection["cipher_suite"])
                if evidence:
                    winners.append({"candidate_id": row["id"], "evidence": evidence})
            results.append({"stream": connection["stream"], "client_random": connection["client_random"],
                            "direction": direction, "status": "selected" if len(winners) == 1 and not timed_out else "unresolved",
                            "candidate_id": winners[0]["candidate_id"] if len(winners) == 1 and not timed_out else None,
                            "reason": (None if len(winners) == 1 and not timed_out else
                                       "time_budget" if timed_out else
                                       "no_authenticated_candidate" if not winners else "ambiguous_candidates"),
                            "winner_count": len(winners),
                            "evidence": winners[0]["evidence"] if len(winners) == 1 and not timed_out else []})
            if timed_out:
                break
        if timed_out:
            break
    if timed_out:
        existing = {(row["stream"], row["direction"]) for row in results}
        for connection in connections:
            for direction in ("client", "server"):
                if (connection["stream"], direction) not in existing:
                    results.append({"stream": connection["stream"], "client_random": connection["client_random"],
                                    "direction": direction, "status": "unresolved", "candidate_id": None,
                                    "reason": "time_budget", "winner_count": 0, "evidence": []})
    # A single secret cannot be assigned to distinct connection/direction roles.
    chosen = [row["candidate_id"] for row in results if row["status"] == "selected"]
    repeated = {identity for identity in chosen if chosen.count(identity) > 1}
    for row in results:
        if row["candidate_id"] in repeated:
            row.update(status="unresolved", candidate_id=None, reason="candidate_reused_across_roles", evidence=[])
    return results, {"authentication_trials": trial_count, "authentication_exhausted": not timed_out}


def run(core_path, pcap_path, metadata_path, method, output):
    metadata = json.loads(metadata_path.read_text())
    if (metadata.get("architecture") != "linux-x86_64" or
            metadata.get("firefox_version") != "136.0.2" or
            metadata.get("cipher_suite") != "0x1302" or
            metadata.get("target_hashes") != PINNED_HASHES):
        raise ValueError("Target metadata does not match the pinned study")
    start = time.monotonic()
    cpu_start = time.process_time()
    with CoreMemory(core_path) as core:
        if method == "structured":
            rows, search = bounded_structured_rank(core, SEARCH_SECONDS - (time.monotonic() - start))
        else:
            rows, search = entropy_rank(core, start + SEARCH_SECONDS)
    search_elapsed = time.monotonic() - start
    if search_elapsed > SEARCH_SECONDS:
        search["search_exhausted"] = False
    connections = inspect_connections(pcap_path)
    if not connections:
        raise ValueError("PCAP has no completed TLS 1.3 handshake")
    if any(connection["cipher_suite"] != "0x1302" for connection in connections):
        raise ValueError("PCAP contains a suite outside the pinned study")
    auth_start = time.monotonic()
    decisions, auth = assign(rows, connections, pcap_path, auth_start + AUTH_SECONDS)
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    private = output / "candidates.private.json"
    private.write_text(json.dumps(rows, sort_keys=True) + "\n")
    private.chmod(0o400)
    report = {"method": method, "input_sha256": {"core": digest(core_path), "pcap": digest(pcap_path),
              "metadata": digest(metadata_path)}, "candidate_count": len(rows), "search": search,
              "authentication": auth, "connections": connections, "decisions": decisions,
              "wall_seconds": time.monotonic() - start, "cpu_seconds": time.process_time() - cpu_start,
              "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
              "input_contract": ["core", "pcap", "target_metadata"]}
    decision_file = output / "decisions.json"
    decision_file.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    seal = {"candidates_sha256": digest(private), "decisions_sha256": digest(decision_file),
            "sealed_at_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()}
    (output / "seal.json").write_text(json.dumps(seal, sort_keys=True, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--method", choices=("structured", "entropy"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    report = run(args.core, args.pcap, args.metadata, args.method, args.output)
    print(json.dumps({"method": report["method"], "candidate_count": report["candidate_count"],
                      "decisions": report["decisions"]}))


if __name__ == "__main__":
    main()
