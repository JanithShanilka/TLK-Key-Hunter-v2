#!/usr/bin/env python3
"""Run and verify one controlled wolfSSL TLSKeyHunter baseline session."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


KEY_LINE = re.compile(
    r"((?:CLIENT_RANDOM|CLIENT_[A-Z0-9_]+|SERVER_[A-Z0-9_]+)"
    r"\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def command_output(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return completed.stdout.strip()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def contains_text_or_hex(output: str, expected: str) -> bool:
    if expected in output:
        return True
    compact = re.sub(r"[^0-9A-Fa-f]", "", output).lower()
    return expected.encode("utf-8").hex().lower() in compact


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=("12", "13"), required=True)
    parser.add_argument("--case-id")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path.home() / "research" / "TLSKeyHunter",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    if os.geteuid() != 0:
        print(
            "this VPS requires root for the short dumpcap capture; "
            "run this controlled baseline through the root SSH account",
            file=sys.stderr,
        )
        return 2
    repo_owner = repo.stat()
    frida_path = Path("/home/researcher/.venv/bin/frida")
    if not frida_path.exists():
        frida_path = Path.home() / ".venv/bin/frida"
    protocol_label = f"TLS1.{args.protocol[-1]}"
    compact_protocol = f"TLS{args.protocol}"
    case_id = args.case_id or f"BASELINE-WOLFSSL-{compact_protocol}-001"
    port = 4432 if args.protocol == "12" else 4433
    case_dir = repo / "cases" / case_id
    if case_dir.exists():
        print(f"refusing to overwrite existing case: {case_dir}", file=sys.stderr)
        return 2

    directories = (
        "environment",
        "target-artifacts",
        "capture",
        "server",
        "frida",
        "secrets",
        "verification",
        "metrics",
        "reports",
    )
    for directory in directories:
        (case_dir / directory).mkdir(parents=True, exist_ok=False)

    started_at = utc_now()
    (case_dir / "environment" / "start-time-utc.txt").write_text(
        started_at + "\n", encoding="utf-8"
    )
    (case_dir / "case.yaml").write_text(
        "\n".join(
            (
                f"case_id: {case_id}",
                "run_id: RUN-01",
                f"protocol: {protocol_label}",
                f"target: 127.0.0.1:{port}",
                "library: wolfSSL",
                "authorized_scope: controlled_local_lab",
                "",
            )
        ),
        encoding="utf-8",
    )

    environment = {
        "timestamp": started_at,
        "uname": command_output(["uname", "-a"]),
        "python": command_output(["python3", "--version"]),
        "frida": command_output([str(frida_path), "--version"]),
        "tshark": command_output(["tshark", "--version"]).splitlines()[0],
        "dumpcap": command_output(["dumpcap", "--version"]).splitlines()[0],
        "openssl": command_output(["openssl", "version"]),
        "git_commit": command_output(["git", "-C", str(repo), "rev-parse", "HEAD"]),
        "git_branch": command_output(
            ["git", "-C", str(repo), "branch", "--show-current"]
        ),
    }
    write_json(case_dir / "environment" / "environment.json", environment)

    client_dir = repo / "ground_truth" / "wolfssl" / "compiled_clients"
    library_dir = client_dir / "libs"
    client = client_dir / f"test_client_{args.protocol}_wolfssl_key_export_dl"
    library = library_dir / "libwolfssl.so.43"
    hook = repo / "tlsKeyExtraction" / "wolfssl_key_dump_linux_x86_64.js"
    workload = repo / "lab" / "baseline" / "wolfssl_workload.js"
    server_program = repo / "lab" / "baseline" / "tls_server.py"
    artifacts = {}
    for path in (client, library, hook, workload, server_program):
        artifacts[str(path.relative_to(repo))] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
    write_json(case_dir / "target-artifacts" / "hashes.json", artifacts)

    certificate = case_dir / "server" / "server.cert.pem"
    private_key = case_dir / "server" / "server.key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.chmod(private_key, 0o600)

    server_events = case_dir / "server" / "server-events.jsonl"
    ready_file = case_dir / "server" / "ready"
    server_log = (case_dir / "server" / "server.log").open("w", encoding="utf-8")
    server = subprocess.Popen(
        [
            "python3",
            str(server_program),
            "--protocol",
            args.protocol,
            "--port",
            str(port),
            "--case-id",
            case_id,
            "--cert",
            str(certificate),
            "--key",
            str(private_key),
            "--events",
            str(server_events),
            "--ready",
            str(ready_file),
        ],
        stdout=server_log,
        stderr=subprocess.STDOUT,
        text=True,
    )

    for _ in range(100):
        if ready_file.exists():
            break
        if server.poll() is not None:
            break
        time.sleep(0.05)
    if not ready_file.exists():
        server_log.close()
        print("controlled TLS server failed to start", file=sys.stderr)
        return 1

    capture_path = case_dir / "capture" / "traffic.pcapng"
    capture_staging = Path("/tmp") / (
        f"tlskh-{case_id.lower()}-{os.getpid()}.pcapng"
    )
    capture_log = (case_dir / "capture" / "capture-diagnostics.log").open(
        "w", encoding="utf-8"
    )
    capture_command = [
        "/usr/bin/dumpcap",
        "-i",
        "lo",
        "-f",
        f"tcp port {port}",
        "-a",
        "duration:8",
        "-w",
        str(capture_staging),
    ]
    (case_dir / "capture" / "capture-command.txt").write_text(
        " ".join(capture_command) + "\n", encoding="utf-8"
    )
    capture = subprocess.Popen(
        capture_command,
        stdout=capture_log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    # dumpcap can take more than a second to finish privilege setup and attach
    # to the loopback interface on this VPS.
    time.sleep(2.5)

    frida_log_path = case_dir / "frida" / "frida-events.log"
    frida_environment = os.environ.copy()
    frida_environment["LD_LIBRARY_PATH"] = str(library_dir)
    frida_command = [
        str(frida_path),
        "-f",
        str(client),
        "-l",
        str(hook),
        "-l",
        str(workload),
        "--runtime=v8",
    ]
    (case_dir / "frida" / "frida-command.txt").write_text(
        " ".join(frida_command) + "\n", encoding="utf-8"
    )
    with frida_log_path.open("w", encoding="utf-8") as frida_log:
        frida = subprocess.Popen(
            frida_command,
            cwd=case_dir / "secrets",
            env=frida_environment,
            stdin=subprocess.PIPE,
            stdout=frida_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            frida.communicate(input="\n\n", timeout=20)
            frida_exit = frida.returncode
        except subprocess.TimeoutExpired:
            frida.terminate()
            frida_exit = frida.wait(timeout=5)

    try:
        server_exit = server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.terminate()
        server_exit = server.wait(timeout=5)
    server_log.close()

    try:
        capture_exit = capture.wait(timeout=12)
    except subprocess.TimeoutExpired:
        capture.send_signal(signal.SIGINT)
        capture_exit = capture.wait(timeout=5)
    capture_log.close()
    if capture_staging.exists():
        shutil.move(capture_staging, capture_path)
    os.chmod(capture_path, 0o600)

    generated_ground_truth = case_dir / "secrets" / "sslkeylog.log"
    ground_truth_path = case_dir / "secrets" / "dev-ground-truth.keys"
    if generated_ground_truth.exists():
        generated_ground_truth.replace(ground_truth_path)
    if not ground_truth_path.exists():
        print("ground-truth client produced no key log", file=sys.stderr)
        return 1
    os.chmod(ground_truth_path, 0o600)

    ground_truth = {
        line.strip().upper()
        for line in ground_truth_path.read_text(errors="replace").splitlines()
        if KEY_LINE.fullmatch(line.strip())
    }
    extracted = set()
    for line in frida_log_path.read_text(errors="replace").splitlines():
        if "[TLSKH_KEY]" not in line:
            continue
        match = KEY_LINE.search(line)
        if match:
            extracted.add(match.group(1).upper())

    candidates_path = case_dir / "secrets" / "candidates.keys"
    candidates_path.write_text(
        "\n".join(sorted(extracted)) + ("\n" if extracted else ""),
        encoding="utf-8",
    )
    os.chmod(candidates_path, 0o600)
    exact_matches = ground_truth & extracted
    verified_path = case_dir / "secrets" / "verified.keys"
    verified_path.write_text(
        "\n".join(sorted(exact_matches)) + ("\n" if exact_matches else ""),
        encoding="utf-8",
    )
    os.chmod(verified_path, 0o600)

    if server_events.exists():
        server_event = json.loads(server_events.read_text(encoding="utf-8").splitlines()[0])
    else:
        server_event = {}
    request_path = server_event.get("request_path", "")
    response_marker = server_event.get("response_marker", "")

    # Ubuntu's TShark confinement cannot read captures below /home even when
    # the invoking researcher owns them. Verify owner-only temporary copies in
    # /tmp, while keeping the authoritative evidence files mode 600.
    verification_scratch = tempfile.TemporaryDirectory(
        prefix="tlskh-tshark-", dir="/tmp"
    )
    scratch_dir = Path(verification_scratch.name)
    scratch_capture = scratch_dir / "traffic.pcapng"
    scratch_keys = scratch_dir / "verified.keys"
    shutil.copy2(capture_path, scratch_capture)
    shutil.copy2(verified_path, scratch_keys)
    os.chmod(scratch_capture, 0o600)
    os.chmod(scratch_keys, 0o600)

    tshark_command = [
        "tshark",
        "-r",
        str(scratch_capture),
        "-o",
        f"tls.keylog_file:{scratch_keys}",
        "-Y",
        "http || tls.alert_message",
        "-V",
    ]
    (case_dir / "verification" / "tshark-command.txt").write_text(
        " ".join(tshark_command) + "\n", encoding="utf-8"
    )
    tshark = subprocess.run(
        tshark_command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    (case_dir / "verification" / "tshark-output.log").write_text(
        tshark.stdout, encoding="utf-8"
    )
    client_hellos = [
        line
        for line in command_output(
        [
            "tshark",
            "-r",
            str(scratch_capture),
            "-Y",
            "tls.handshake.type == 1",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]
        ).splitlines()
        if line.isdigit()
    ]
    server_hellos = [
        line
        for line in command_output(
        [
            "tshark",
            "-r",
            str(scratch_capture),
            "-Y",
            "tls.handshake.type == 2",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]
        ).splitlines()
        if line.isdigit()
    ]
    verification_scratch.cleanup()

    checks = {
        "complete_tls_handshake": bool(client_hellos and server_hellos),
        "server_event": bool(server_event),
        "frida_candidate_event": bool(extracted),
        "exact_candidate_equality": bool(exact_matches),
        "all_ground_truth_labels_matched": ground_truth == exact_matches,
        "tshark_decryption": "Hypertext Transfer Protocol" in tshark.stdout,
        "exact_request_path_recovered": bool(request_path)
        and contains_text_or_hex(tshark.stdout, request_path),
        "exact_response_marker_recovered": bool(response_marker)
        and contains_text_or_hex(tshark.stdout, response_marker),
    }
    status = "Accepted" if all(checks.values()) else "Unverified"
    verification = {
        "case_id": case_id,
        "run_id": "RUN-01",
        "protocol": protocol_label,
        "status": status,
        "checks": checks,
        "client_hello_frames": client_hellos,
        "server_hello_frames": server_hellos,
        "ground_truth_label_count": len(ground_truth),
        "frida_candidate_count": len(extracted),
        "verified_candidate_count": len(exact_matches),
        "frida_exit": frida_exit,
        "server_exit": server_exit,
        "capture_exit": capture_exit,
    }
    write_json(case_dir / "verification" / "verification.json", verification)

    metrics = {
        "eligible_sessions": 1,
        "fully_recovered_sessions": 1 if status == "Accepted" else 0,
        "session_recovery_coverage": 1.0 if status == "Accepted" else 0.0,
        "ground_truth_candidate_count": len(ground_truth),
        "frida_candidate_count": len(extracted),
        "verified_candidate_count": len(exact_matches),
    }
    write_json(case_dir / "metrics" / "metrics.json", metrics)
    report = "\n".join(
        (
            f"# TLSKeyHunter wolfSSL {protocol_label} baseline — {case_id}",
            "",
            f"- Status: {status}",
            f"- Exact candidate equality: {checks['exact_candidate_equality']}",
            f"- All ground-truth labels matched: {checks['all_ground_truth_labels_matched']}",
            f"- Complete TLS handshake: {checks['complete_tls_handshake']}",
            f"- TShark decryption: {checks['tshark_decryption']}",
            f"- Exact request path recovered: {checks['exact_request_path_recovered']}",
            f"- Exact response marker recovered: {checks['exact_response_marker_recovered']}",
            f"- Verified candidates: {len(exact_matches)}",
            "- Raw secrets: excluded from this report and stored in mode-600 evidence files.",
            "",
        )
    )
    (case_dir / "reports" / "run-report.md").write_text(report, encoding="utf-8")
    (case_dir / "environment" / "end-time-utc.txt").write_text(
        utc_now() + "\n", encoding="utf-8"
    )

    manifest_path = case_dir / "evidence-manifest.sha256"
    manifest_lines = []
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path == manifest_path:
            continue
        relative = path.relative_to(case_dir)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_lines.append(f"{digest}  {relative}")
    manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

    # The capture needs root on this VPS, but the resulting research evidence
    # remains owned by the normal research account.
    for path in [case_dir, *case_dir.rglob("*")]:
        os.chown(path, repo_owner.st_uid, repo_owner.st_gid)

    print(json.dumps({"case_dir": str(case_dir), **verification}, indent=2))
    return 0 if status == "Accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
