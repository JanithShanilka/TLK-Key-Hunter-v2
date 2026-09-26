#!/usr/bin/env python3
"""Run the fixed 40-session OpenSSL/wolfSSL A-versus-D live study."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


CAMPAIGN_ID = "ARG-RANKER-LIVE-FINAL-001"
LIBRARIES = ("openssl", "wolfssl")
PROTOCOLS = ("12", "13")
METHODS = ("A", "D")
SESSIONS_PER_CELL = 5


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> dict[str, float]:
    if total == 0:
        return {"lower": 0.0, "upper": 1.0}
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = proportion + z * z / (2 * total)
    margin = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    )
    return {
        "lower": max(0.0, min(1.0, (centre - margin) / denominator)),
        "upper": max(0.0, min(1.0, (centre + margin) / denominator)),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo", type=Path, default=Path.home() / "research" / "TLSKeyHunter"
    )
    parser.add_argument("--terminal-mode", choices=("summary", "teaching"), default="summary")
    parser.add_argument("--stream-output", action="store_true")
    return parser.parse_args()


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def verify_manifest(case_dir: Path) -> bool:
    manifest = case_dir / "evidence-manifest.sha256"
    if not manifest.exists():
        return False
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        digest, relative = line.split("  ", 1)
        path = case_dir / relative
        if not path.is_file() or sha256_path(path) != digest:
            return False
    return True


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    campaign_dir = repo / "cases" / CAMPAIGN_ID
    if campaign_dir.exists():
        print(f"refusing to overwrite existing campaign: {campaign_dir}", file=sys.stderr)
        return 2
    sessions_dir = campaign_dir / "sessions"
    reports_dir = campaign_dir / "reports"
    metrics_dir = campaign_dir / "metrics"
    for path in (sessions_dir, reports_dir, metrics_dir):
        path.mkdir(parents=True, exist_ok=False)

    transcript = reports_dir / "terminal-transcript.log"

    def emit(kind: str, message: str) -> None:
        line = f"[{kind}] [{CAMPAIGN_ID}] {message}"
        with transcript.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if args.stream_output:
            print(line, flush=True)

    started_at = utc_now()
    emit("STEP", "Begin fixed 2 libraries × 2 protocols × 2 methods × 5 sessions study")
    runner = repo / "lab/live/run_live_case.py"
    python_executable = Path("/home/researcher/.venv/bin/python")
    if not python_executable.exists():
        python_executable = Path(sys.executable)
    rows: list[dict] = []
    attempt = 0
    for library in LIBRARIES:
        for protocol in PROTOCOLS:
            for method in METHODS:
                for session_number in range(1, SESSIONS_PER_CELL + 1):
                    attempt += 1
                    session_id = (
                        f"{library.upper()}-TLS{protocol}-{method}-S{session_number:02d}"
                    )
                    session_dir = sessions_dir / session_id
                    emit(
                        "STEP",
                        f"attempt={attempt:02d}/40 session={session_id}",
                    )
                    command = [
                        str(python_executable), str(runner), "--repo", str(repo),
                        "--case-id", session_id, "--case-root", str(session_dir),
                        "--run-id", f"RUN-{session_number:02d}",
                        "--library", library, "--protocol", protocol,
                        "--ranker-mode", method,
                        "--terminal-mode", args.terminal_mode,
                    ]
                    if args.stream_output:
                        command.append("--stream-output")
                    process = subprocess.Popen(
                        command,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    )
                    output_lines = []
                    assert process.stdout is not None
                    for line in process.stdout:
                        output_lines.append(line)
                        if args.stream_output and line.startswith(
                            ("[STEP]", "[OK]", "[FAIL]", "[METRIC]", "[ARTIFACT]")
                        ):
                            print(f"[{session_id}] {line.rstrip()}", flush=True)
                    runner_exit = process.wait()
                    (session_dir / "reports/runner-output.log").write_text(
                        "".join(output_lines), encoding="utf-8"
                    )
                    verification = read_json(session_dir / "verification/verification.json")
                    metrics = read_json(session_dir / "metrics/metrics.json")
                    manifest_valid = verify_manifest(session_dir)
                    row = {
                        "attempt": attempt,
                        "session_id": session_id,
                        "library": library,
                        "protocol": f"TLS1.{protocol[-1]}",
                        "method": method,
                        "runner_exit": runner_exit,
                        "status": verification.get("status", "runner_failure"),
                        "acquisition_status": verification.get("acquisition_status", "unknown"),
                        "candidate_selection_success": metrics.get("candidate_selection_success", 0),
                        "exact_secret_match": metrics.get("exact_secret_match", 0),
                        "authenticated_pcap_decryption": metrics.get("authenticated_pcap_decryption", 0),
                        "complete_end_to_end_recovery": metrics.get("complete_end_to_end_recovery", 0),
                        "no_candidate": metrics.get("no_candidate", 0),
                        "ambiguous": metrics.get("ambiguous", 0),
                        "false_candidate": metrics.get("false_candidate", 0),
                        "manifest_valid": manifest_valid,
                    }
                    rows.append(row)
                    emit(
                        "OK" if row["complete_end_to_end_recovery"] and manifest_valid else "FAIL",
                        f"session={session_id} status={row['status']} manifest_valid={manifest_valid}",
                    )

    csv_path = metrics_dir / "sessions.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "schema": "tlskh-live-ad-study-v1",
        "campaign_id": CAMPAIGN_ID,
        "started_at": started_at,
        "completed_at": utc_now(),
        "design": {
            "libraries": list(LIBRARIES),
            "protocols": [f"TLS1.{value[-1]}" for value in PROTOCOLS],
            "methods": list(METHODS),
            "sessions_per_cell": SESSIONS_PER_CELL,
            "planned_attempts": 40,
        },
        "attempted_sessions": len(rows),
        "manifest_valid_sessions": sum(bool(row["manifest_valid"]) for row in rows),
        "overall": {},
        "by_method": {},
    }
    for metric in (
        "candidate_selection_success", "exact_secret_match",
        "authenticated_pcap_decryption", "complete_end_to_end_recovery",
        "no_candidate", "ambiguous", "false_candidate",
    ):
        successes = sum(int(row[metric]) for row in rows)
        summary["overall"][metric] = {
            "count": successes,
            "rate": successes / len(rows),
            "wilson_95": wilson(successes, len(rows)),
        }
    for method in METHODS:
        method_rows = [row for row in rows if row["method"] == method]
        summary["by_method"][method] = {}
        for metric in (
            "candidate_selection_success", "exact_secret_match",
            "authenticated_pcap_decryption", "complete_end_to_end_recovery",
            "no_candidate", "ambiguous", "false_candidate",
        ):
            successes = sum(int(row[metric]) for row in method_rows)
            summary["by_method"][method][metric] = {
                "count": successes,
                "rate": successes / len(method_rows),
                "wilson_95": wilson(successes, len(method_rows)),
            }
    write_path = metrics_dir / "summary.json"
    write_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (reports_dir / "campaign-report.md").write_text(
        "\n".join(
            (
                f"# {CAMPAIGN_ID}", "",
                f"- Attempted sessions: {len(rows)}/40",
                f"- Valid session manifests: {summary['manifest_valid_sessions']}/40",
                f"- A complete recovery: {summary['by_method']['A']['complete_end_to_end_recovery']['count']}/20",
                f"- D complete recovery: {summary['by_method']['D']['complete_end_to_end_recovery']['count']}/20",
                "- Failures and no-candidate sessions remain in the denominator.",
                "- Raw secret material is excluded from campaign summaries and transcripts.", "",
            )
        )
    )
    complete = len(rows) == 40 and summary["manifest_valid_sessions"] == 40
    emit("OK" if complete else "FAIL", f"campaign_complete={complete} attempted={len(rows)}")
    manifest = campaign_dir / "evidence-manifest.sha256"
    manifest.write_text(
        "\n".join(
            f"{sha256_path(path)}  {path.relative_to(campaign_dir)}"
            for path in sorted(campaign_dir.rglob("*"))
            if path.is_file() and path != manifest
        ) + "\n"
    )
    print(json.dumps(summary, indent=2))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
