#!/usr/bin/env python3
"""Run one sealed A-or-D live TLS-library acquisition and verification case."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


KEY_LINE = re.compile(
    r"((?:CLIENT_RANDOM|CLIENT_[A-Z0-9_]+|SERVER_[A-Z0-9_]+)"
    r"\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+)"
)
SECRET_TEXT = re.compile(
    r"((?:CLIENT_RANDOM|CLIENT_[A-Z0-9_]+|SERVER_[A-Z0-9_]+)\s+)"
    r"([0-9A-Fa-f]{32,})\s+([0-9A-Fa-f]{32,})"
)
SECRET_ONLY_TEXT = re.compile(
    r"(\[TLSKH_CANDIDATE\]\s+[A-Z0-9_]+\s+)([0-9A-Fa-f]{32,})"
)
SECRET_ONLY_LINE = re.compile(
    r"\[TLSKH_CANDIDATE\]\s+([A-Z0-9_]+)\s+([0-9A-Fa-f]{32,})"
)
TLS13_REQUIRED = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command_output(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return result.stdout.strip()


def redact(value: str) -> str:
    value = SECRET_TEXT.sub(r"\1<redacted-random> <redacted-secret>", value)
    return SECRET_ONLY_TEXT.sub(r"\1<redacted-secret>", value)


def contains_text_or_hex(output: str, expected: str) -> bool:
    if expected in output:
        return True
    compact = re.sub(r"[^0-9A-Fa-f]", "", output).lower()
    return expected.encode("utf-8").hex().lower() in compact


def parse_key_lines(text: str) -> list[str]:
    values: list[str] = []
    for line in text.splitlines():
        match = KEY_LINE.search(line)
        if match:
            canonical = " ".join(match.group(1).upper().split())
            if canonical not in values:
                values.append(canonical)
    return values


def split_key_line(line: str) -> tuple[str, str, str]:
    label, random_value, secret = line.split()
    return label, random_value, secret


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


class Reporter:
    def __init__(self, transcript: Path, stream: bool) -> None:
        self.transcript = transcript
        self.stream = stream

    def emit(self, kind: str, message: str) -> None:
        line = redact(f"[{kind}] {message}")
        with self.transcript.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if self.stream:
            print(line, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", choices=("openssl", "wolfssl"), required=True)
    parser.add_argument("--protocol", choices=("12", "13"), required=True)
    parser.add_argument("--ranker-mode", choices=("A", "D"), required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--case-root",
        type=Path,
        help="explicit evidence directory used by a parent campaign runner",
    )
    parser.add_argument("--run-id", default="RUN-01")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the runner's repository)",
    )
    parser.add_argument("--terminal-mode", choices=("summary", "teaching"), default="summary")
    parser.add_argument("--stream-output", action="store_true")
    return parser.parse_args()


def select_paths(repo: Path, library: str, protocol: str) -> tuple[Path, Path | None, Path]:
    if library == "wolfssl":
        client_dir = repo / "ground_truth" / library / "compiled_clients_no_keylog"
    else:
        client_dir = repo / "ground_truth" / library / "compiled_clients"
    client = client_dir / f"test_client_{protocol}_{library}_dl"
    library_dir = client_dir / "libs" if library == "wolfssl" else None
    hook = repo / "tlsKeyExtraction" / f"{library}_key_dump_linux_x86_64.js"
    return client, library_dir, hook


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    if os.geteuid() != 0:
        print("root is required for the short loopback dumpcap capture", file=sys.stderr)
        return 2

    case_dir = args.case_root.resolve() if args.case_root else repo / "cases" / args.case_id
    if case_dir.exists():
        print(f"refusing to overwrite existing case: {case_dir}", file=sys.stderr)
        return 2

    for relative in (
        "environment", "target-artifacts", "capture", "server", "frida",
        "secrets", "verification", "metrics", "reports",
    ):
        (case_dir / relative).mkdir(parents=True, exist_ok=False)

    reporter = Reporter(case_dir / "reports/terminal-transcript.log", args.stream_output)
    resources: dict[str, subprocess.Popen[str] | None] = {
        "server": None,
        "capture": None,
    }
    frida_resources: dict[str, object | None] = {
        "device": None,
        "session": None,
        "script": None,
        "pid": None,
    }
    open_handles: list[object] = []

    def emergency_cleanup() -> None:
        script_resource = frida_resources["script"]
        if script_resource is not None:
            try:
                script_resource.unload()  # type: ignore[attr-defined]
            except Exception:
                pass
        session_resource = frida_resources["session"]
        if session_resource is not None:
            try:
                session_resource.detach()  # type: ignore[attr-defined]
            except Exception:
                pass
        device_resource = frida_resources["device"]
        pid_resource = frida_resources["pid"]
        if device_resource is not None and pid_resource is not None:
            try:
                device_resource.kill(pid_resource)  # type: ignore[attr-defined]
            except Exception:
                pass
        for name in ("capture", "server"):
            stop_process(resources[name])
        for handle in open_handles:
            try:
                handle.close()  # type: ignore[attr-defined]
            except Exception:
                pass

    atexit.register(emergency_cleanup)
    started_at = utc_now()
    reporter.emit("STEP", "Prepare a controlled live-memory acquisition case")

    client, library_dir, hook = select_paths(repo, args.library, args.protocol)
    ranker = repo / "tlsKeyExtraction/arg_ranker.js"
    workload = repo / "lab/live/live_workload.js"
    server_program = repo / "lab/baseline/tls_server.py"
    required_paths = [client, hook, ranker, workload, server_program]
    if library_dir is not None:
        required_paths.append(library_dir / "libwolfssl.so.43")
    missing = [str(path) for path in required_paths if not path.exists()]
    if missing:
        reporter.emit("FAIL", "Missing prerequisites: " + ", ".join(missing))
        return 2

    port = 4432 if args.protocol == "12" else 4433
    protocol_label = f"TLS1.{args.protocol[-1]}"
    (case_dir / "environment/start-time-utc.txt").write_text(started_at + "\n")
    (case_dir / "case.yaml").write_text(
        "\n".join(
            (
                f"case_id: {args.case_id}",
                f"run_id: {args.run_id}",
                f"protocol: {protocol_label}",
                f"library: {args.library}",
                f"ranker_mode: {args.ranker_mode}",
                "acquisition_before_verification: true",
                "client_sslkeylogfile: disabled",
                "reference_source: isolated_controlled_server",
                "authorized_scope: controlled_local_lab",
                "",
            )
        ),
        encoding="utf-8",
    )

    frida_path = Path("/home/researcher/.venv/bin/frida")
    environment = {
        "timestamp": started_at,
        "uname": command_output(["uname", "-a"]),
        "python": command_output(["python3", "--version"]),
        "frida": command_output([str(frida_path), "--version"]),
        "tshark": command_output(["tshark", "--version"]).splitlines()[0],
        "dumpcap": command_output(["dumpcap", "--version"]).splitlines()[0],
        "git_commit": command_output(["git", "-C", str(repo), "rev-parse", "HEAD"]),
        "git_branch": command_output(["git", "-C", str(repo), "branch", "--show-current"]),
        "sslkeylogfile_in_runner_environment": "SSLKEYLOGFILE" in os.environ,
    }
    write_json(case_dir / "environment/environment.json", environment)
    artifacts = {
        str(path.relative_to(repo)): {"sha256": sha256_path(path), "size": path.stat().st_size}
        for path in required_paths
        if path.is_file()
    }
    write_json(case_dir / "target-artifacts/hashes.json", artifacts)

    certificate = case_dir / "server/server.cert.pem"
    private_key = case_dir / "server/server.key.pem"
    reporter.emit("COMMAND", "openssl req -x509 ... (ephemeral localhost certificate)")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-keyout", str(private_key),
            "-out", str(certificate), "-days", "1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.chmod(private_key, 0o600)

    server_reference = case_dir / "secrets/server-reference.keys"
    server_events = case_dir / "server/server-events.jsonl"
    ready_file = case_dir / "server/ready"
    server_log = (case_dir / "server/server.log").open("w", encoding="utf-8")
    open_handles.append(server_log)
    server_command = [
        "python3", str(server_program), "--protocol", args.protocol,
        "--port", str(port), "--case-id", args.case_id,
        "--cert", str(certificate), "--key", str(private_key),
        "--events", str(server_events), "--ready", str(ready_file),
        "--keylog", str(server_reference),
    ]
    reporter.emit("COMMAND", "Start controlled TLS server with private server-only reference export")
    resources["server"] = subprocess.Popen(
        server_command, stdout=server_log, stderr=subprocess.STDOUT, text=True
    )
    for _ in range(120):
        if ready_file.exists() or resources["server"].poll() is not None:
            break
        time.sleep(0.05)
    if not ready_file.exists():
        reporter.emit("FAIL", "Controlled TLS server did not become ready")
        return 1
    reporter.emit("OK", "Controlled TLS server is ready; reference remains unread")

    capture_staging = Path("/tmp") / f"tlskh-{args.case_id.lower()}-{os.getpid()}.pcapng"
    capture_path = case_dir / "capture/traffic.pcapng"
    capture_log = (case_dir / "capture/capture-diagnostics.log").open("w", encoding="utf-8")
    open_handles.append(capture_log)
    capture_command = [
        "/usr/bin/dumpcap", "-i", "lo", "-f", f"tcp port {port}",
        "-a", "duration:10", "-w", str(capture_staging),
    ]
    (case_dir / "capture/capture-command.txt").write_text(" ".join(capture_command) + "\n")
    reporter.emit("COMMAND", f"dumpcap loopback TCP port {port}")
    resources["capture"] = subprocess.Popen(
        capture_command, stdout=capture_log, stderr=subprocess.STDOUT, text=True
    )
    time.sleep(2.5)

    prelude = case_dir / "frida/case-prelude.js"
    prelude.write_text(
        "\n".join(
            (
                f"globalThis.TLSKH_RANKER_MODE = {json.dumps(args.ranker_mode)};",
                f"globalThis.TLSKH_LIBRARY = {json.dumps(args.library)};",
                f"globalThis.TLSKH_CASE_ID = {json.dumps(args.case_id)};",
                f"globalThis.TLSKH_PROTOCOL = {json.dumps(protocol_label)};",
                f"globalThis.TLSKH_RUN_ID = {json.dumps(args.run_id)};",
                "",
            )
        ),
        encoding="utf-8",
    )
    frida_log_path = case_dir / "frida/frida-private.log"
    frida_log = frida_log_path.open("w", encoding="utf-8")
    open_handles.append(frida_log)
    client_environment = os.environ.copy()
    client_environment.pop("SSLKEYLOGFILE", None)
    if library_dir is not None:
        client_environment["LD_LIBRARY_PATH"] = str(library_dir)
    frida_command = [
        str(Path("/home/researcher/.venv/bin/python")), str(Path(__file__).resolve()),
        "--spawn-suspended", str(client), "--combined-script", "prelude+ranker+hook+workload",
    ]
    (case_dir / "frida/frida-command.txt").write_text(
        "Python Frida API: spawn suspended; attach; load prelude+ranker+hook+workload; resume\n"
    )
    reporter.emit("STEP", f"Attach Frida and acquire with method {args.ranker_mode}")
    reporter.emit("COMMAND", "Frida Python API spawn → attach → load one combined script → resume")
    try:
        import frida  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError(
            "run with /home/researcher/.venv/bin/python so the frozen Frida binding is available"
        ) from error
    log_lock = threading.Lock()
    workload_sent = threading.Event()
    process_ended = threading.Event()

    def record_private(line: str) -> None:
        with log_lock:
            frida_log.write(line.rstrip("\n") + "\n")
            frida_log.flush()
        if "[TLSKH_WORKLOAD] status=request_sent" in line:
            workload_sent.set()

    def on_message(message: dict, data: bytes | None) -> None:
        if message.get("type") in {"log", "send"}:
            record_private(str(message.get("payload", "")))
        else:
            record_private(json.dumps(message, sort_keys=True))

    def on_output(pid: int, file_descriptor: int, data: bytes) -> None:
        record_private(
            f"[TARGET_OUTPUT pid={pid} fd={file_descriptor}] "
            + data.decode("utf-8", errors="replace")
        )

    def on_process_crashed(crash: object) -> None:
        record_private(f"[TARGET_CRASH] {crash}")
        process_ended.set()

    def on_log(level: str, message: str) -> None:
        for line in message.splitlines() or [message]:
            record_private(line)
            if args.terminal_mode == "teaching" and not any(
                marker in line for marker in ("[TLSKH_KEY]", "[TLSKH_CANDIDATE]")
            ):
                reporter.emit("OBSERVE", line)

    device = frida.get_local_device()
    frida_resources["device"] = device
    device.on("output", on_output)
    device.on("process-crashed", on_process_crashed)
    pid = device.spawn(
        [str(client)],
        envp=client_environment,
        cwd=str(case_dir / "secrets"),
        stdio="pipe",
    )
    frida_resources["pid"] = pid
    session = device.attach(pid)
    frida_resources["session"] = session
    combined_source = "\n".join(
        (
            prelude.read_text(encoding="utf-8"),
            ranker.read_text(encoding="utf-8"),
            hook.read_text(encoding="utf-8"),
            workload.read_text(encoding="utf-8"),
        )
    )
    script = session.create_script(combined_source, runtime="v8")
    frida_resources["script"] = script
    script.on("message", on_message)
    script.set_log_handler(on_log)
    script.load()
    device.resume(pid)
    device.input(pid, b"\n")
    workload_observed = workload_sent.wait(15)
    device.input(pid, b"\n")
    for _ in range(120):
        if not Path(f"/proc/{pid}").exists():
            process_ended.set()
            break
        time.sleep(0.1)
    if Path(f"/proc/{pid}").exists():
        device.kill(pid)
    frida_exit = 0 if process_ended.is_set() else 1
    try:
        session.detach()
    except Exception:
        pass
    frida_resources["session"] = None
    frida_resources["script"] = None
    frida_resources["pid"] = None
    frida_log.flush()
    reporter.emit("OK" if workload_observed else "FAIL", f"workload_request_observed={workload_observed}")
    reporter.emit("OBSERVE", "The raw Frida evidence is private; terminal output contains hashes only")

    try:
        server_exit = resources["server"].wait(timeout=5)
    except subprocess.TimeoutExpired:
        stop_process(resources["server"])
        server_exit = resources["server"].returncode
    try:
        capture_exit = resources["capture"].wait(timeout=12)
    except subprocess.TimeoutExpired:
        resources["capture"].send_signal(signal.SIGINT)
        capture_exit = resources["capture"].wait(timeout=5)
    server_log.close()
    capture_log.close()
    if capture_staging.exists():
        shutil.move(capture_staging, capture_path)
    if capture_path.exists():
        os.chmod(capture_path, 0o600)

    private_text = frida_log_path.read_text(errors="replace")
    pattern_name = {
        ("openssl", "12"): "pattern_prf_secret",
        ("openssl", "13"): "derive_secret",
        ("wolfssl", "12"): "pattern_wc_PRF_TLSt",
        ("wolfssl", "13"): "pattern_Tls13DeriveKey",
    }[(args.library, args.protocol)]
    explicit_count = re.findall(
        rf"\[TLSKH_FINGERPRINT\]\s+id={re.escape(pattern_name)}\s+matches=(\d+)",
        private_text,
    )
    if explicit_count:
        fingerprint_match_count = int(explicit_count[-1])
    else:
        fingerprint_match_count = len(
            re.findall(
                rf"Pattern found at \({re.escape(pattern_name)}\):",
                private_text,
            )
        )
    unexpected_client_keylog = case_dir / "secrets/sslkeylog.log"
    unexpected_client_reference = {
        "exists": unexpected_client_keylog.exists(),
        "sha256": sha256_path(unexpected_client_keylog)
        if unexpected_client_keylog.exists()
        else None,
        "contents_read_by_runner": False,
    }
    write_json(
        case_dir / "verification/unexpected-client-reference.json",
        unexpected_client_reference,
    )
    if unexpected_client_reference["exists"]:
        reporter.emit(
            "FAIL",
            "Instrumented target generated sslkeylog.log; this build is not eligible for final measurement",
        )
    candidate_lines = parse_key_lines(
        "\n".join(line for line in private_text.splitlines() if "[TLSKH_KEY]" in line)
    )
    client_randoms: set[str] = set()
    if capture_path.exists():
        with tempfile.TemporaryDirectory(prefix="tlskh-random-", dir="/tmp") as scratch:
            scratch_capture = Path(scratch) / "traffic.pcapng"
            shutil.copy2(capture_path, scratch_capture)
            os.chmod(scratch_capture, 0o600)
            random_output = command_output(
                [
                    "tshark", "-r", str(scratch_capture), "-Y",
                    "tls.handshake.type == 1", "-d", f"tcp.port=={port},tls",
                    "-T", "fields", "-e", "tls.handshake.random",
                ]
            )
        client_randoms = {
            value.strip().upper()
            for value in random_output.splitlines()
            if re.fullmatch(r"[0-9A-Fa-f]{64}", value.strip())
        }
    secret_only_matches = SECRET_ONLY_LINE.findall(private_text)
    if len(client_randoms) == 1:
        associated_random = next(iter(client_randoms))
        for label, secret in secret_only_matches:
            line = f"{label.upper()} {associated_random} {secret.upper()}"
            if line not in candidate_lines:
                candidate_lines.append(line)
    out_of_scope_candidate_labels: list[str] = []
    if args.protocol == "13":
        in_scope_lines: list[str] = []
        for line in candidate_lines:
            label, _random_value, _secret = split_key_line(line)
            if label in TLS13_REQUIRED:
                in_scope_lines.append(line)
            else:
                out_of_scope_candidate_labels.append(label)
        candidate_lines = in_scope_lines
        if out_of_scope_candidate_labels:
            reporter.emit(
                "OBSERVE",
                "Excluded fixed out-of-scope TLS 1.3 labels before verification: "
                + ",".join(sorted(set(out_of_scope_candidate_labels))),
            )
    by_identity: dict[tuple[str, str], set[str]] = {}
    for line in candidate_lines:
        label, random_value, secret = split_key_line(line)
        by_identity.setdefault((label, random_value), set()).add(secret)
    ambiguity = any(len(secrets) != 1 for secrets in by_identity.values())
    labels = {label for label, _random in by_identity}
    randoms = {random_value for _label, random_value in by_identity}
    if not candidate_lines:
        acquisition_status = "no_candidate"
    elif ambiguity or len(randoms) != 1:
        acquisition_status = "ambiguous"
    elif args.protocol == "12" and (labels != {"CLIENT_RANDOM"} or len(candidate_lines) != 1):
        acquisition_status = "ambiguous"
    elif args.protocol == "13" and not TLS13_REQUIRED.issubset(labels):
        acquisition_status = "no_candidate"
    else:
        acquisition_status = "selected"

    sealed_lines = sorted(candidate_lines) if acquisition_status == "selected" else []
    candidate_path = case_dir / "secrets/candidates.keys"
    candidate_path.write_text("\n".join(sealed_lines) + ("\n" if sealed_lines else ""))
    os.chmod(candidate_path, 0o400)
    candidate_metadata = []
    for number, line in enumerate(sealed_lines, 1):
        label, random_value, secret = split_key_line(line)
        candidate_metadata.append(
            {
                "candidate_id": f"CANDIDATE-{number:02d}",
                "label": label,
                "client_random_sha256": sha256_bytes(bytes.fromhex(random_value)),
                "secret_sha256": sha256_bytes(bytes.fromhex(secret)),
                "secret_length": len(secret) // 2,
            }
        )
    seal = {
        "case_id": args.case_id,
        "sealed_at": utc_now(),
        "acquisition_sealed": True,
        "acquisition_status": acquisition_status,
        "candidate_file_sha256": sha256_path(candidate_path),
        "candidate_count": len(sealed_lines),
        "candidates": candidate_metadata,
        "client_hello_random_count": len(client_randoms),
        "candidate_association_source": "captured_client_hello" if secret_only_matches else "hook_event",
        "out_of_scope_candidate_labels": sorted(set(out_of_scope_candidate_labels)),
        "ground_truth_consulted_before_seal": False,
        "tshark_attempted_before_seal": False,
    }
    write_json(case_dir / "secrets/acquisition-seal.json", seal)
    reporter.emit(
        "ARTIFACT",
        f"Acquisition sealed status={acquisition_status} hash={seal['candidate_file_sha256']}",
    )

    # Verification begins only after the selected candidate file is sealed.
    reference_lines = parse_key_lines(
        server_reference.read_text(errors="replace") if server_reference.exists() else ""
    )
    os.chmod(server_reference, 0o400) if server_reference.exists() else None
    reference_set = set(reference_lines)
    exact_lines = [line for line in sealed_lines if line in reference_set]
    exact_match = bool(sealed_lines) and len(exact_lines) == len(sealed_lines)
    if args.protocol == "13":
        exact_match = exact_match and TLS13_REQUIRED.issubset(
            {split_key_line(line)[0] for line in exact_lines}
        )
    comparisons = []
    for metadata, line in zip(candidate_metadata, sealed_lines):
        comparisons.append(
            {
                **metadata,
                "exact_server_reference_match": line in reference_set,
                "hamming_distance_bits": 0 if line in reference_set else None,
            }
        )
    write_json(case_dir / "verification/reference-comparisons.json", comparisons)
    reporter.emit("METRIC", f"exact_server_reference_match={exact_match}")

    server_event = {}
    if server_events.exists() and server_events.read_text().strip():
        server_event = json.loads(server_events.read_text().splitlines()[0])
    request_path = server_event.get("request_path", "")
    response_marker = server_event.get("response_marker", "")
    tshark_output = ""
    client_hellos: list[str] = []
    server_hellos: list[str] = []
    if capture_path.exists():
        with tempfile.TemporaryDirectory(prefix="tlskh-tshark-", dir="/tmp") as scratch:
            scratch_dir = Path(scratch)
            scratch_capture = scratch_dir / "traffic.pcapng"
            scratch_keys = scratch_dir / "sealed-candidates.keys"
            shutil.copy2(capture_path, scratch_capture)
            shutil.copy2(candidate_path, scratch_keys)
            tshark_command = [
                "tshark", "-r", str(scratch_capture), "-o",
                f"tls.keylog_file:{scratch_keys}", "-d", f"tcp.port=={port},tls",
                "-Y", "http || tls.alert_message", "-V",
            ]
            (case_dir / "verification/tshark-command.txt").write_text(
                " ".join(tshark_command) + "\n"
            )
            reporter.emit("COMMAND", "TShark decrypt using the sealed candidate file only")
            tshark_result = subprocess.run(
                tshark_command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            tshark_output = tshark_result.stdout
            (case_dir / "verification/tshark-output.log").write_text(tshark_output)
            for handshake_type, destination in (("1", client_hellos), ("2", server_hellos)):
                frames = command_output(
                    [
                        "tshark", "-r", str(scratch_capture), "-Y",
                        f"tls.handshake.type == {handshake_type}", "-d",
                        f"tcp.port=={port},tls", "-T", "fields",
                        "-e", "frame.number",
                    ]
                )
                destination.extend(line for line in frames.splitlines() if line.isdigit())

    checks = {
        "browser_or_client_workload_event": "status=request_sent" in private_text,
        "matching_server_event": bool(server_event),
        "unique_static_fingerprint": fingerprint_match_count == 1,
        "complete_tls_handshake": bool(client_hellos and server_hellos),
        "relevant_frida_event": bool(candidate_lines),
        "acquisition_sealed_before_verification": seal["acquisition_sealed"],
        "unique_candidate_selected": acquisition_status == "selected",
        "instrumented_target_key_export_disabled": not unexpected_client_reference["exists"],
        "exact_server_reference_match": exact_match,
        "authenticated_tshark_decryption": "Hypertext Transfer Protocol" in tshark_output,
        "exact_request_path_recovered": bool(request_path) and contains_text_or_hex(tshark_output, request_path),
        "exact_response_marker_recovered": bool(response_marker) and contains_text_or_hex(tshark_output, response_marker),
    }
    status = "Accepted" if all(checks.values()) else "ClassifiedFailure"
    verification = {
        "case_id": args.case_id,
        "run_id": args.run_id,
        "library": args.library,
        "protocol": protocol_label,
        "ranker_mode": args.ranker_mode,
        "status": status,
        "checks": checks,
        "acquisition_status": acquisition_status,
        "candidate_count": len(candidate_lines),
        "fingerprint_pattern_id": pattern_name,
        "fingerprint_match_count": fingerprint_match_count,
        "sealed_candidate_count": len(sealed_lines),
        "server_reference_count": len(reference_lines),
        "frida_exit": frida_exit,
        "server_exit": server_exit,
        "capture_exit": capture_exit,
    }
    write_json(case_dir / "verification/verification.json", verification)
    metrics = {
        "attempted_sessions": 1,
        "candidate_selection_success": int(acquisition_status == "selected"),
        "exact_secret_match": int(exact_match),
        "authenticated_pcap_decryption": int(checks["authenticated_tshark_decryption"]),
        "complete_end_to_end_recovery": int(status == "Accepted"),
        "no_candidate": int(acquisition_status == "no_candidate"),
        "ambiguous": int(acquisition_status == "ambiguous"),
        "false_candidate": int(acquisition_status == "selected" and not exact_match),
    }
    write_json(case_dir / "metrics/metrics.json", metrics)
    (case_dir / "reports/run-report.md").write_text(
        "\n".join(
            (
                f"# Live-memory acquisition case — {args.case_id}", "",
                f"- Status: {status}",
                f"- Library/protocol/method: {args.library} / {protocol_label} / {args.ranker_mode}",
                f"- Acquisition status: {acquisition_status}",
                f"- Acquisition sealed before verification: {checks['acquisition_sealed_before_verification']}",
                f"- Exact server-reference equality: {exact_match}",
                f"- Authenticated TShark decryption: {checks['authenticated_tshark_decryption']}",
                f"- Exact request and response recovered: {checks['exact_request_path_recovered'] and checks['exact_response_marker_recovered']}",
                "- Raw secret material is restricted to private evidence files and excluded from this report.", "",
            )
        )
    )
    (case_dir / "environment/end-time-utc.txt").write_text(utc_now() + "\n")
    reporter.emit("OK" if status == "Accepted" else "FAIL", f"Case classified as {status}")

    manifest_path = case_dir / "evidence-manifest.sha256"
    manifest_lines = []
    for path in sorted(case_dir.rglob("*")):
        if path.is_file() and path != manifest_path:
            manifest_lines.append(f"{sha256_path(path)}  {path.relative_to(case_dir)}")
    manifest_path.write_text("\n".join(manifest_lines) + "\n")
    owner = repo.stat()
    for path in [case_dir, *case_dir.rglob("*")]:
        os.chown(path, owner.st_uid, owner.st_gid)
    for private_path in (candidate_path, server_reference, private_key, frida_log_path):
        if private_path.exists():
            os.chmod(private_path, 0o400)
    atexit.unregister(emergency_cleanup)
    emergency_cleanup()
    print(json.dumps(verification, indent=2))
    return 0 if status == "Accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
