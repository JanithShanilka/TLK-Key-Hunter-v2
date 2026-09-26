#!/usr/bin/env python3
"""Run and aggregate independent controlled Firefox/NSS TLS 1.2/1.3 cases."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wilson(successes: int, total: int) -> dict[str, float | int]:
    if total == 0:
        return {"successes": 0, "total": 0, "lower": 0.0, "upper": 0.0}
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    spread = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    ) / denominator
    return {
        "successes": successes,
        "total": total,
        "lower": max(0.0, center - spread),
        "upper": min(1.0, center + spread),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--runs", default=1, type=int)
    parser.add_argument("--sessions-per-run", default=5, type=int)
    parser.add_argument("--mode", choices=["development", "measurement"], default="measurement")
    parser.add_argument("--protocol", choices=["12", "13"], default="13")
    parser.add_argument("--terminal-mode", choices=["summary", "teaching"], default="summary")
    parser.add_argument("--stream-output", action="store_true")
    parser.add_argument("--certificate-dir", required=True, type=Path)
    parser.add_argument(
        "--firefox",
        type=Path,
        default=Path("/opt/tlskeyhunter/firefox-136.0.2-pristine/firefox"),
    )
    args = parser.parse_args()

    repo = args.repo.resolve()
    output_dir = repo / "results" / args.campaign_id
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite campaign output: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    runner = repo / "lab/firefox/phase18a_firefox_nss_runner.py"
    hook = repo / (
        "lab/firefox/nss_firefox_136.0.2_tls12.js"
        if args.protocol == "12"
        else "lab/firefox/nss_firefox_136.0.2.js"
    )
    fingerprints = repo / (
        "lab/firefox/firefox_nss_tls12_fingerprints.json"
        if args.protocol == "12"
        else "lab/firefox/firefox_nss_fingerprints.json"
    )
    transcript_path = output_dir / "terminal-transcript.log"
    transcript_path.write_text(
        f"[STEP] campaign={args.campaign_id} protocol=TLS1.{args.protocol[-1]} "
        f"runs={args.runs} sessions_per_run={args.sessions_per_run}\n",
        encoding="utf-8",
    )

    git_status = subprocess.run(
        ["git", "status", "--short"],
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.strip()
    if git_status:
        raise RuntimeError("repository must be clean before a campaign")
    git_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()

    sessions = []
    for run_number in range(1, args.runs + 1):
        for session_number in range(1, args.sessions_per_run + 1):
            case_id = f"{args.campaign_id}-R{run_number:02d}-S{session_number:03d}"
            case_dir = repo / "cases" / case_id
            command = [
                sys.executable,
                str(runner),
                "--mode",
                args.mode,
                "--protocol",
                args.protocol,
                "--terminal-mode",
                args.terminal_mode,
                "--certificate-dir",
                str(args.certificate_dir.resolve()),
                "--case-dir",
                str(case_dir),
                "--case-id",
                case_id,
                "--run-id",
                f"RUN-{run_number:02d}",
                "--firefox",
                str(args.firefox),
                "--hook",
                str(hook),
                "--fingerprints",
                str(fingerprints),
            ]
            if args.stream_output:
                with transcript_path.open("a", encoding="utf-8") as transcript:
                    prefix = f"[{case_id}]"
                    rendered = " ".join(command)
                    print(f"[COMMAND] {rendered}", flush=True)
                    transcript.write(f"[COMMAND] {rendered}\n")
                    process = subprocess.Popen(
                        command,
                        cwd=repo,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        bufsize=1,
                    )
                    assert process.stdout is not None
                    for line in process.stdout:
                        safe_line = line.rstrip("\n")
                        print(f"{prefix} {safe_line}", flush=True)
                        transcript.write(f"{prefix} {safe_line}\n")
                    process.wait()
                    return_code = process.returncode
            else:
                result = subprocess.run(
                    command,
                    cwd=repo,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                return_code = result.returncode
            verification_path = case_dir / "verification/verification.json"
            metrics_path = case_dir / "metrics/metrics.json"
            verification = (
                json.loads(verification_path.read_text()) if verification_path.is_file() else {}
            )
            metrics = json.loads(metrics_path.read_text()) if metrics_path.is_file() else {}
            manifest_path = case_dir / "evidence-manifest.sha256"
            manifest_valid = False
            if manifest_path.is_file():
                manifest_valid = subprocess.run(
                    ["sha256sum", "-c", "--quiet", manifest_path.name],
                    cwd=case_dir,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode == 0
            sessions.append(
                {
                    "case_id": case_id,
                    "run_number": run_number,
                    "session_number": session_number,
                    "runner_exit_code": return_code,
                    "status": verification.get("status", "Runner failure"),
                    "fully_recovered": verification.get("status")
                    == "Eligible and fully recovered",
                    "acquisition_status": verification.get("acquisition_status"),
                    "acquisition_sealed": verification.get("acquisition_sealed", False),
                    "exact_server_reference_match": verification.get(
                        "exact_server_reference_match", False
                    ),
                    "authenticated_decryption": verification.get("tshark_decryption", False),
                    "frida_events": metrics.get("frida_events", 0),
                    "verified_candidate_groups": metrics.get("verified_candidate_groups", 0),
                    "manifest_sha256": sha256(manifest_path) if manifest_path.is_file() else None,
                    "manifest_valid": manifest_valid,
                }
            )
            print(
                json.dumps(
                    {
                        "case_id": case_id,
                        "exit_code": return_code,
                        "status": sessions[-1]["status"],
                    }
                ),
                flush=True,
            )

    run_summaries = []
    for run_number in range(1, args.runs + 1):
        run_sessions = [item for item in sessions if item["run_number"] == run_number]
        recovered = sum(bool(item["fully_recovered"]) for item in run_sessions)
        run_summaries.append(
            {
                "run_number": run_number,
                "eligible_sessions": len(run_sessions),
                "fully_recovered_sessions": recovered,
                "session_recovery_coverage": recovered / len(run_sessions),
            }
        )
    total = len(sessions)
    recovered = sum(bool(item["fully_recovered"]) for item in sessions)
    exact_matches = sum(bool(item["exact_server_reference_match"]) for item in sessions)
    decryptions = sum(bool(item["authenticated_decryption"]) for item in sessions)
    sealed = sum(bool(item["acquisition_sealed"]) for item in sessions)
    summary = {
        "campaign_id": args.campaign_id,
        "git_commit": git_commit,
        "mode": args.mode,
        "protocol": f"TLS1.{args.protocol[-1]}",
        "runs": args.runs,
        "sessions_per_run": args.sessions_per_run,
        "eligible_sessions": total,
        "fully_recovered_sessions": recovered,
        "session_recovery_coverage": recovered / total if total else 0.0,
        "sealed_acquisitions": sealed,
        "exact_secret_matches": exact_matches,
        "exact_secret_match_rate": exact_matches / total if total else 0.0,
        "authenticated_decryptions": decryptions,
        "authenticated_decryption_rate": decryptions / total if total else 0.0,
        "wilson_95": wilson(recovered, total),
        "run_summaries": run_summaries,
        "sessions": sessions,
    }
    summary_path = output_dir / "campaign-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.chmod(0o600)
    with (output_dir / "sessions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(sessions[0].keys()))
        writer.writeheader()
        writer.writerows(sessions)
    (output_dir / "sessions.csv").chmod(0o600)
    manifest = output_dir / "evidence-manifest.sha256"
    manifest_inputs = [summary_path, output_dir / "sessions.csv", transcript_path]
    manifest.write_text(
        "\n".join(f"{sha256(path)}  {path.name}" for path in manifest_inputs)
        + "\n",
        encoding="utf-8",
    )
    manifest.chmod(0o600)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if recovered == total else 2


if __name__ == "__main__":
    raise SystemExit(main())
