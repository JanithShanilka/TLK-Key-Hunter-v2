#!/usr/bin/env python3
"""Freeze and run separate ten-case pilot or 100-case blind evaluation."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import random
import resource
import shutil
import subprocess
import time

from capture_blind import PINNED_HASHES
from evaluate import flow_truth, redact_core, score_pair, stage_input, verify_seal
from recover import AUTH_SECONDS, MAX_CANDIDATES, SEARCH_SECONDS, digest
from summarize import summarize

GIB = 1024 ** 3
MAX_VIRTUAL_MEMORY_BYTES = 16 * GIB
MAX_CPU_SECONDS = SEARCH_SECONDS + AUTH_SECONDS + 60
BLIND_SCRIPTS = ("blind_server.py", "capture_blind.py", "capture_decoy.py", "record_auth.py",
                 "recover.py", "evaluate.py", "run_study.py", "summarize.py")
OFFLINE_SCRIPTS = ("capture_firefox.py", "core_memory.py", "rank_tls13.py", "rank_core.py", "tls13_packets.py")


def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    path.chmod(0o600)


def design(mode, seed):
    rng = random.Random(int(seed, 16))
    if mode == "pilot":
        kinds = ([{"kind": "positive", "connections": 2} for _ in range(3)] +
                 [{"kind": "positive", "connections": 3} for _ in range(3)] +
                 [{"kind": "mismatch", "connections": 2}, {"kind": "unrelated", "connections": 3}] +
                 [{"kind": "withheld", "connections": 2}, {"kind": "withheld", "connections": 3}])
    else:
        kinds = ([{"kind": "positive", "connections": 2} for _ in range(35)] +
                 [{"kind": "positive", "connections": 3} for _ in range(35)] +
                 [{"kind": "mismatch", "connections": 2 + (n % 2)} for n in range(10)] +
                 [{"kind": "unrelated", "connections": 2 + (n % 2)} for n in range(10)] +
                 [{"kind": "withheld", "connections": 2 + (n % 2)} for n in range(10)])
    rng.shuffle(kinds)
    for item in kinds:
        item["case_id"] = "B" + f"{rng.getrandbits(64):016x}"
        item["status"] = "planned"
    mismatch = [item for item in kinds if item["kind"] == "mismatch"]
    if len(mismatch) == 1:  # The pilot mismatch uses a positive pilot as its donor.
        donor = next(item for item in kinds if item["kind"] == "positive" and item["connections"] == 2)
        mismatch[0]["donor"] = donor["case_id"]
    else:
        for index, item in enumerate(mismatch):
            item["donor"] = mismatch[(index + 1) % len(mismatch)]["case_id"]
    return kinds


def retained_nine(cases, seed):
    rng = random.Random(int(seed, 16) ^ 0xA51D)
    groups = [([row for row in cases if row["kind"] == "positive" and row["connections"] == 2], 3),
              ([row for row in cases if row["kind"] == "positive" and row["connections"] == 3], 3)]
    groups += [([row for row in cases if row["kind"] == kind], 1)
               for kind in ("mismatch", "unrelated", "withheld")]
    return sorted(row["case_id"] for group, count in groups for row in rng.sample(group, count))


def pilot_check(path):
    pilot = json.loads(path.read_text())
    rows = pilot["cases"]
    if len(rows) != 10 or any(row["status"] != "scored" for row in rows):
        raise ValueError("Final freeze requires ten scored pilot cases")
    if any(not row["score"]["structured"]["case_success"] for row in rows):
        raise ValueError("Final freeze requires successful structured-method pilot conditions and controls")
    sizes = [row["core_allocated_bytes"] for row in rows]
    if not sizes or min(sizes) <= 0:
        raise ValueError("Pilot has no measured core allocation")
    return max(sizes)


def snapshot_tools(study):
    source = Path(__file__).resolve().parent
    tools = study / "tools"
    (tools / "blind_tls13").mkdir(parents=True, mode=0o755)
    (tools / "offline_memory").mkdir(mode=0o755)
    tools.chmod(0o755)
    (tools / "blind_tls13").chmod(0o755)
    (tools / "offline_memory").chmod(0o755)
    hashes = {}
    for name in BLIND_SCRIPTS:
        target = tools / "blind_tls13" / name
        shutil.copyfile(source / name, target)
        target.chmod(0o444)
        hashes["blind_tls13/" + name] = digest(target)
    for name in OFFLINE_SCRIPTS:
        target = tools / "offline_memory" / name
        shutil.copyfile(source.parent / "offline_memory" / name, target)
        target.chmod(0o444)
        hashes["offline_memory/" + name] = digest(target)
    return hashes


def create(study, mode, seed, pilot_summary=None):
    study.mkdir(parents=True, exist_ok=False)
    study.chmod(0o755)
    (study / "cases").mkdir(mode=0o711)
    (study / "inboxes").mkdir(mode=0o755)
    (study / "results").mkdir(mode=0o755)
    (study / "cases").chmod(0o711)
    (study / "inboxes").chmod(0o755)
    (study / "results").chmod(0o755)
    maximum_core = pilot_check(pilot_summary) if mode == "final" else None
    free = shutil.disk_usage(study).free
    projected = int(110 * maximum_core * 1.25) + 20 * GIB if maximum_core else None
    retention = "all" if mode == "pilot" or free >= projected else "nine"
    cases = design(mode, seed)
    hashes = snapshot_tools(study)
    manifest = {"mode": mode, "created_utc": utc(), "seed": seed, "cases": cases,
                "preserved_baseline_commit": "fdcbbef", "preserved_baseline_result": "docs/offline-memory/TLS13_EXTENDED_RESULTS.md",
                "retention": retention, "retained_case_ids": retained_nine(cases, seed) if retention == "nine" else None,
                "pilot_max_core_allocated_bytes": maximum_core, "projected_required_free_bytes": projected,
                "free_bytes_at_freeze": free, "spacing_seconds": 600 if mode == "final" else 0,
                "search_seconds": SEARCH_SECONDS, "authentication_seconds": AUTH_SECONDS,
                "max_candidate_trials": MAX_CANDIDATES, "max_virtual_memory_bytes": MAX_VIRTUAL_MEMORY_BYTES,
                "max_cpu_seconds": MAX_CPU_SECONDS, "minimum_free_bytes": 20 * GIB,
                "target_hashes": PINNED_HASHES, "script_sha256": hashes,
                "policy": "No replacement of attempted cases; both outputs sealed before scoring; private answers are evaluator-only."}
    save(study / "manifest.json", manifest)
    save(study / "state.json", {"state": "frozen", "cases": cases})
    return manifest


def check_snapshot(study, manifest):
    for name, expected in manifest["script_sha256"].items():
        if digest(study / "tools" / name) != expected:
            raise RuntimeError("Frozen study script hash changed: " + name)
    if digest(Path(__file__).resolve()) != manifest["script_sha256"]["blind_tls13/run_study.py"]:
        raise RuntimeError("Running campaign controller differs from frozen snapshot")


def command(argv, log, timeout, bounded=False):
    def apply_limits():
        resource.setrlimit(resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY_BYTES, MAX_VIRTUAL_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    with log.open("w") as stream:
        subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=timeout,
                       preexec_fn=apply_limits if bounded else None)


def input_sources(study, row):
    cases = study / "cases"
    references = Path("/root/tlkh-blind-reference") / study.name
    source = cases / row["case_id"]
    if row["kind"] == "mismatch":
        donor = row["donor"]
        return source / "firefox.core", cases / donor / "traffic.pcap", references / donor
    if row["kind"] == "unrelated":
        return source / "firefox.core", cases / (row["case_id"] + "-decoy") / "traffic.pcap", references / (row["case_id"] + "-decoy")
    return source / "firefox.core", source / "traffic.pcap", references / row["case_id"]


def process(study, manifest, row, index):
    case_id = row["case_id"]
    core, pcap, reference = input_sources(study, row)
    if not core.exists() or not pcap.exists():
        raise RuntimeError("Required core or paired PCAP is missing")
    if row["kind"] == "withheld":
        truth = flow_truth(pcap, reference / "workload-reference.json", reference / "server-reference.keys")
        withheld = sorted(truth)[0]
        redacted = core.with_name("redacted.core")
        row["redaction"] = redact_core(core, redacted, truth[withheld])
        row["withheld"] = list(withheld)
        core = redacted
    inbox = study / "inboxes" / case_id
    metadata = {"architecture": "linux-x86_64", "firefox_version": "136.0.2",
                "cipher_suite": "0x1302", "target_hashes": PINNED_HASHES}
    paths = stage_input(inbox, core, pcap, metadata)
    result = study / "results" / case_id
    result.mkdir(mode=0o755)
    account = pwd.getpwnam("researcher")
    os.chown(result, account.pw_uid, account.pw_gid)
    methods = ("structured", "entropy") if index % 2 == 0 else ("entropy", "structured")
    try:
        for method in methods:
            destination = result / method
            argv = ["runuser", "-u", "researcher", "--", "/usr/bin/python3",
                    str(study / "tools/blind_tls13/recover.py"), "--core", str(paths["core"]),
                    "--pcap", str(paths["pcap"]), "--metadata", str(paths["metadata"]),
                    "--method", method, "--output", str(destination)]
            command(argv, result / (method + ".log"), SEARCH_SECONDS + AUTH_SECONDS + 90, bounded=True)
            verify_seal(destination)
        # The two seals above must exist before opening either reference file.
        score = score_pair(result / "structured", result / "entropy", core, pcap,
                           reference / "workload-reference.json", reference / "server-reference.keys",
                           row["kind"], tuple(row["withheld"]) if row.get("withheld") else None)
        row["score"] = score
        row["status"] = "scored"
        save(result / "score.json", score)
    finally:
        for child in inbox.iterdir():
            child.unlink()
        inbox.rmdir()
        os.chown(result, 0, 0)
        result.chmod(0o700)
    retain = manifest["retention"] == "all" or case_id in (manifest["retained_case_ids"] or [])
    if not retain:
        core_source = study / "cases" / case_id
        for name in ("firefox.core", "redacted.core"):
            path = core_source / name
            if path.exists():
                path.unlink()
        for name in ("profile", "runtime"):
            path = core_source / name
            if path.exists():
                shutil.rmtree(path)
    row["raw_core_retained"] = retain


def run(study):
    if os.geteuid() != 0:
        raise RuntimeError("Controlled study runner requires root")
    manifest = json.loads((study / "manifest.json").read_text())
    state_path = study / "state.json"
    state = json.loads(state_path.read_text())
    check_snapshot(study, manifest)
    cases = state["cases"]
    references = Path("/root/tlkh-blind-reference") / study.name
    references.mkdir(parents=True, exist_ok=True)
    state["state"] = "running"
    save(state_path, state)
    for index, row in enumerate(cases):
        if row["status"] != "planned":
            continue
        prior_starts = [datetime.fromisoformat(item["started_utc"]).timestamp()
                        for item in cases if item.get("started_utc")]
        if prior_starts:
            wait_seconds = max(prior_starts) + manifest["spacing_seconds"] - time.time()
            while wait_seconds > 0:
                time.sleep(min(wait_seconds, 1))
                wait_seconds = max(prior_starts) + manifest["spacing_seconds"] - time.time()
        if shutil.disk_usage(study).free < manifest["minimum_free_bytes"]:
            state["state"] = "stopped_storage_guard"
            save(state_path, state)
            return state
        started = time.monotonic()
        case_id = row["case_id"]
        row.update(status="attempted", started_utc=utc())
        save(state_path, state)
        try:
            case = study / "cases" / case_id
            reference = references / case_id
            capture = ["/home/researcher/.venv/bin/python", str(study / "tools/blind_tls13/capture_blind.py"),
                       "--case", str(case), "--reference", str(reference),
                       "--connections", str(row["connections"]), "--lab-disable-socket-sandbox",
                       "--lab-accept-insecure-certs"]
            command(capture, study / "results" / (case_id + "-capture.log"), 300)
            acquisition = json.loads((case / "acquisition.json").read_text())
            row["core_allocated_bytes"] = acquisition["core_allocated_bytes"]
            row["status"] = "captured"
            save(state_path, state)
            if row["kind"] == "unrelated":
                decoy = ["/home/researcher/.venv/bin/python", str(study / "tools/blind_tls13/capture_decoy.py"),
                         "--case", str(study / "cases" / (case_id + "-decoy")),
                         "--reference", str(references / (case_id + "-decoy")),
                         "--port", "18453", "--connections", str(row["connections"])]
                command(decoy, study / "results" / (case_id + "-decoy.log"), 180)
            if row["kind"] != "mismatch":
                process(study, manifest, row, index)
            row["ended_utc"] = utc()
            save(state_path, state)
        except Exception as error:
            row.update(status="failed", failure=str(error), ended_utc=utc())
            state["state"] = "stopped_stage_failure"
            save(state_path, state)
            return state
        if index < len(cases) - 1:
            while time.monotonic() - started < manifest["spacing_seconds"]:
                time.sleep(1)
    # Mismatched pairs must be captured before their donor PCAP is revealed.
    for index, row in enumerate(cases):
        if row["kind"] == "mismatch" and row["status"] == "captured":
            try:
                process(study, manifest, row, index)
                row["ended_utc"] = utc()
                save(state_path, state)
            except Exception as error:
                row.update(status="failed", failure=str(error), ended_utc=utc())
                state["state"] = "stopped_stage_failure"
                save(state_path, state)
                return state
    state["state"] = "completed" if all(row["status"] == "scored" for row in cases) else "incomplete"
    state["ended_utc"] = utc()
    save(state_path, state)
    save(study / "summary.json", summarize(manifest, state))
    return state


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--create", choices=("pilot", "final"))
    parser.add_argument("--pilot-summary", type=Path)
    parser.add_argument("--seed", default=None)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.create:
        if args.create == "final" and args.pilot_summary is None:
            parser.error("Final freeze requires --pilot-summary")
        seed = args.seed or __import__("secrets").token_hex(16)
        create(args.study, args.create, seed, args.pilot_summary)
    if args.run:
        print(json.dumps(run(args.study)["state"]))
    if not args.create and not args.run:
        parser.error("Choose --create and/or --run")


if __name__ == "__main__":
    main()
