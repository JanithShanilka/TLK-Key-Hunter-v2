#!/usr/bin/env python3
"""Controlled Firefox/NSS TLS 1.2/1.3 runner with Phase 18A evidence logging."""

from __future__ import annotations

import argparse
import atexit
import csv
import datetime as dt
import hashlib
import html
import http.server
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import ssl
import subprocess
import threading
import time
import urllib.parse

import frida
from websockets.sync.client import connect as websocket_connect


KEYLOG_RE = re.compile(
    r"^(CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|"
    r"CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|EXPORTER_SECRET|"
    r"EARLY_TRAFFIC_SECRET|RESUMPTION_MASTER_SECRET) "
    r"([0-9A-Fa-f]{64}) ([0-9A-Fa-f]+)$"
)
TLS12_SECRET_RE = re.compile(
    r"^TLSKH_TLS12_SECRET (master secret|extended master secret) ([0-9A-Fa-f]{96})$"
)
KEYLOG_INLINE_RE = re.compile(
    r"(CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|"
    r"CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|EXPORTER_SECRET|"
    r"EARLY_TRAFFIC_SECRET|RESUMPTION_MASTER_SECRET)\s+"
    r"[0-9A-Fa-f]{64}\s+[0-9A-Fa-f]+"
)
TLS12_SECRET_INLINE_RE = re.compile(
    r"TLSKH_TLS12_SECRET\s+(?:master secret|extended master secret)\s+[0-9A-Fa-f]{96}"
)
RESEARCHER_UID = 1000
RESEARCHER_GID = 1000


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_text(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(mode)


def write_json(path: Path, value: object) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


class TerminalReporter:
    """Emit a sanitized, chronological learning transcript."""

    def __init__(self, path: Path, mode: str) -> None:
        self.path = path
        self.mode = mode
        write_text(path, "")

    def emit(self, category: str, message: str) -> None:
        # Never permit an NSS key-log line or a bare TLS 1.2 secret into the
        # public terminal transcript.
        sanitized = KEYLOG_INLINE_RE.sub("[REDACTED KEY-LOG LINE]", message)
        sanitized = TLS12_SECRET_INLINE_RE.sub("[REDACTED TLS 1.2 SECRET]", sanitized)
        line = f"[{category}] {sanitized}"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if self.mode == "teaching" or category in {"OK", "FAIL", "METRIC", "ARTIFACT"}:
            print(line, flush=True)


def append_jsonl(path: Path, value: object, lock: threading.Lock) -> None:
    with lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True) + "\n")
        path.chmod(0o600)


def run(
    command: list[str],
    *,
    check: bool = True,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        timeout=timeout,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def bidi_request(websocket, command_id: int, method: str, params: dict) -> dict:
    websocket.send(json.dumps({"id": command_id, "method": method, "params": params}))
    while True:
        response = json.loads(websocket.recv())
        if response.get("id") != command_id:
            continue
        if response.get("type") == "error":
            raise RuntimeError(f"WebDriver BiDi {method} failed: {json.dumps(response, sort_keys=True)}")
        return response


def researcher_command(command: list[str], env: dict[str, str] | None = None) -> list[str]:
    result = ["sudo", "-u", "researcher", "env", "-u", "SSLKEYLOGFILE"]
    if env:
        result += [f"{key}={value}" for key, value in env.items()]
    return result + command


def command_log(path: Path, command: list[str]) -> str:
    result = run(command, check=False)
    write_text(path, result.stdout)
    return result.stdout


def chown_case(case_dir: Path) -> None:
    for current, dirs, files in os.walk(case_dir):
        try:
            os.chown(current, RESEARCHER_UID, RESEARCHER_GID)
            os.chmod(current, 0o700)
        except FileNotFoundError:
            continue
        for name in files:
            target = Path(current) / name
            try:
                os.chown(target, RESEARCHER_UID, RESEARCHER_GID)
                os.chmod(target, 0o600)
            except FileNotFoundError:
                continue


def hamming_distance_hex(left: str, right: str) -> int | None:
    try:
        left_bytes = bytes.fromhex(left)
        right_bytes = bytes.fromhex(right)
    except ValueError:
        return None
    if len(left_bytes) != len(right_bytes):
        return None
    return sum((a ^ b).bit_count() for a, b in zip(left_bytes, right_bytes))


def stop_process(
    process: subprocess.Popen | None,
    *,
    first_signal: signal.Signals = signal.SIGTERM,
    process_group: bool = False,
    timeout: int = 8,
) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        if process_group:
            os.killpg(process.pid, first_signal)
        else:
            process.send_signal(first_signal)
        process.wait(timeout=timeout)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            if process_group:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=4)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass


def build_id(path: Path) -> str | None:
    output = run(["readelf", "-n", str(path)], check=False).stdout
    match = re.search(r"Build ID: ([0-9a-f]+)", output)
    return match.group(1) if match else None


def find_firefox_main(executable: Path, profile: Path) -> int | None:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = [part.decode(errors="replace") for part in (entry / "cmdline").read_bytes().split(b"\0") if part]
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if argv and argv[0] == str(executable) and "--profile" in argv:
            profile_index = argv.index("--profile")
            if profile_index + 1 < len(argv) and argv[profile_index + 1] == str(profile):
                return int(entry.name)
    return None


def find_firefox_socket_process(firefox_root: Path, parent_pid: int) -> int | None:
    executable = str(firefox_root / "firefox-bin")
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = [part.decode(errors="replace") for part in (entry / "cmdline").read_bytes().split(b"\0") if part]
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if not argv or argv[0] != executable or "-contentproc" not in argv or "socket" not in argv:
            continue
        if "-parentPid" not in argv:
            continue
        parent_index = argv.index("-parentPid")
        if parent_index + 1 < len(argv) and argv[parent_index + 1] == str(parent_pid):
            return int(entry.name)
    return None


def write_simple_pdf(path: Path, lines: list[str]) -> None:
    def esc(value: str) -> str:
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content = ["BT", "/F1 10 Tf", "50 790 Td"]
    for line in lines[:55]:
        content += [f"({esc(line[:105])}) Tj", "0 -13 Td"]
    content.append("ET")
    stream = "\n".join(content).encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    path.write_bytes(output)
    path.chmod(0o600)


def wilson(successes: int, total: int) -> dict[str, float | int]:
    if total == 0:
        return {"successes": 0, "total": 0, "lower": 0.0, "upper": 0.0}
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return {
        "successes": successes,
        "total": total,
        "lower": max(0.0, center - spread),
        "upper": min(1.0, center + spread),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--run-id", default="RUN-01")
    parser.add_argument("--mode", choices=["development", "measurement"], default="development")
    parser.add_argument("--protocol", choices=["12", "13"], default="13")
    parser.add_argument("--port", type=int)
    parser.add_argument("--terminal-mode", choices=["summary", "teaching"], default="summary")
    parser.add_argument("--stream-output", action="store_true")
    parser.add_argument("--visual-evidence", action="store_true")
    parser.add_argument("--firefox", type=Path, default=Path("/opt/tlskeyhunter/firefox-136.0.2-pristine/firefox"))
    parser.add_argument("--hook", required=True, type=Path)
    parser.add_argument("--certificate-dir", type=Path)
    parser.add_argument(
        "--fingerprints",
        type=Path,
        default=(
            Path(__file__).resolve().parent / "firefox_nss_fingerprints.json"
            if (Path(__file__).resolve().parent / "firefox_nss_fingerprints.json").exists()
            else Path(__file__).resolve().parents[1] / "lab/firefox/firefox_nss_fingerprints.json"
        ),
    )
    args = parser.parse_args()

    protocol = f"TLS1.{args.protocol[-1]}"
    protocol_slug = f"tls{args.protocol}"
    args.port = args.port or (8442 if args.protocol == "12" else 8443)

    case_dir = args.case_dir.resolve()
    if (case_dir / "evidence-manifest.sha256").exists():
        raise SystemExit("refusing to overwrite a finalized evidence case")
    directories = [
        "environment", "target-artifacts", "browser", "capture", "server",
        "frida", "secrets", "verification", "metrics", "visual", "reports",
    ]
    for directory in directories:
        (case_dir / directory).mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(case_dir, 0o700)
    chown_case(case_dir)
    terminal = TerminalReporter(case_dir / "reports/terminal-transcript.log", args.terminal_mode)
    terminal.emit("STEP", f"Start controlled Firefox/NSS {protocol} case {args.case_id}")
    terminal.emit("COMMAND", f"protocol={args.protocol} port={args.port} mode={args.mode}")

    resources: dict[str, object] = {
        "server": None,
        "capture_proc": None,
        "capture_handle": None,
        "xvfb_proc": None,
        "xvfb_log": None,
        "wm_proc": None,
        "wm_log": None,
        "vnc_proc": None,
        "vnc_log": None,
        "ffmpeg_proc": None,
        "ffmpeg_log": None,
        "browser_proc": None,
        "firefox_stdout": None,
        "firefox_stderr": None,
        "frida_script": None,
        "frida_session": None,
    }

    def emergency_cleanup() -> None:
        script_resource = resources.get("frida_script")
        if script_resource is not None:
            try:
                script_resource.unload()
            except Exception:
                pass
        session_resource = resources.get("frida_session")
        if session_resource is not None:
            try:
                session_resource.detach()
            except Exception:
                pass
        stop_process(resources.get("browser_proc"), process_group=True)
        stop_process(resources.get("ffmpeg_proc"), first_signal=signal.SIGINT, process_group=True)
        stop_process(resources.get("vnc_proc"), process_group=True)
        stop_process(resources.get("wm_proc"), process_group=True)
        stop_process(resources.get("xvfb_proc"), process_group=True)
        stop_process(resources.get("capture_proc"), first_signal=signal.SIGINT, process_group=True)
        server_resource = resources.get("server")
        if server_resource is not None:
            try:
                server_resource.shutdown()
                server_resource.server_close()
            except Exception:
                pass
        for key in (
            "capture_handle", "xvfb_log", "wm_log", "vnc_log", "ffmpeg_log",
            "firefox_stdout", "firefox_stderr",
        ):
            handle = resources.get(key)
            if handle is not None and not getattr(handle, "closed", True):
                try:
                    handle.close()
                except Exception:
                    pass

    atexit.register(emergency_cleanup)

    event_lock = threading.Lock()
    start_time = utc()
    request_id = "REQUEST-0001"
    nonce = hashlib.sha256(f"{args.case_id}|{args.run_id}|{start_time}".encode()).hexdigest()[:8].upper()
    marker = f"TLSKH|{args.case_id}|{args.run_id}|{protocol}|{request_id}|NONCE-{nonce}"
    request_path = f"/lab?case={args.case_id}&run={args.run_id}&request_id={request_id}&nonce={nonce}"
    target_url = f"https://localhost:{args.port}{request_path}"
    bidi_port = 9200 + (int(hashlib.sha256(f"{args.case_id}|bidi".encode()).hexdigest()[:4], 16) % 400)
    bidi_endpoint = f"ws://127.0.0.1:{bidi_port}/session"

    write_text(case_dir / "environment/start-time-utc.txt", start_time + "\n")
    write_text(
        case_dir / "case.yaml",
        f"case_id: {args.case_id}\nrun_id: {args.run_id}\nprotocol: {protocol}\n"
        f"target: localhost:{args.port}\nauthorized_scope: controlled_local_lab\n",
    )
    command_log(case_dir / "environment/uname.txt", ["uname", "-a"])
    command_log(case_dir / "environment/os-release.txt", ["lsb_release", "-a"])
    command_log(
        case_dir / "environment/installed-packages.txt",
        ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"],
    )
    command_log(case_dir / "environment/process-list-before.txt", ["ps", "auxww"])
    network_before = run(["ip", "addr", "show"], check=False).stdout
    network_before += run(["ip", "route", "show"], check=False).stdout
    network_before += run(["ss", "-tulpn"], check=False).stdout
    write_text(case_dir / "environment/network-before.txt", network_before)

    versions = {
        "timestamp": start_time,
        "python": run(["python3", "--version"], check=False).stdout.strip(),
        "firefox": run([str(args.firefox), "--version"], check=False).stdout.strip(),
        "frida": frida.__version__,
        "tshark": run(["tshark", "--version"], check=False).stdout.splitlines()[0],
        "openssl": run(["openssl", "version"], check=False).stdout.strip(),
    }
    if args.visual_evidence:
        versions.update({
            "ffmpeg": run(["ffmpeg", "-version"], check=False).stdout.splitlines()[0],
            "x11vnc": run(["x11vnc", "-version"], check=False).stdout.splitlines()[0],
            "imagemagick": run(["import", "-version"], check=False).stdout.splitlines()[0],
        })
    write_json(case_dir / "environment/environment.json", versions)

    ca_key = case_dir / "server/ca.key.pem"
    ca_cert = case_dir / "server/ca.cert.pem"
    server_key = case_dir / "server/server.key.pem"
    server_csr = case_dir / "server/server.csr.pem"
    server_cert = case_dir / "server/server.cert.pem"
    server_ext = case_dir / "server/server.ext.cnf"
    if args.certificate_dir:
        certificate_dir = args.certificate_dir.resolve()
        for source_name, destination in [
            ("ca.cert.pem", ca_cert),
            ("server.cert.pem", server_cert),
            ("server.key.pem", server_key),
        ]:
            source = certificate_dir / source_name
            if not source.is_file():
                raise RuntimeError(f"fixed certificate artifact is missing: {source}")
            shutil.copy2(source, destination)
        certificate_source = str(certificate_dir)
    else:
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "2", "-nodes",
            "-subj", "/CN=TLSKeyHunter Lab CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca_cert),
        ])
        run([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-subj", "/CN=localhost", "-keyout", str(server_key), "-out", str(server_csr),
        ])
        write_text(
            server_ext,
            "[server_cert]\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )
        run([
            "openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256",
            "-extfile", str(server_ext), "-extensions", "server_cert", "-out", str(server_cert),
        ])
        ca_key.chmod(0o600)
        certificate_source = "generated-per-development-case"
    server_key.chmod(0o600)
    for public_file in [ca_cert, server_cert]:
        public_file.chmod(0o600)
        os.chown(public_file, RESEARCHER_UID, RESEARCHER_GID)
    write_json(
        case_dir / "server/certificate-fingerprints.json",
        {
            "source": certificate_source,
            "ca_certificate_sha256": sha256(ca_cert),
            "server_certificate_sha256": sha256(server_cert),
            "server_private_key_sha256": sha256(server_key),
        },
    )
    cert_info = "LAB CA\n" + run(["openssl", "x509", "-in", str(ca_cert), "-noout", "-text"]).stdout
    cert_info += "\nLOCALHOST LEAF\n" + run(["openssl", "x509", "-in", str(server_cert), "-noout", "-text"]).stdout
    write_text(case_dir / "server/certificate-info.txt", cert_info)

    profile = case_dir / "browser/firefox-profile"
    profile.mkdir(mode=0o700, exist_ok=True)
    os.chown(profile, RESEARCHER_UID, RESEARCHER_GID)
    run(researcher_command(["certutil", "-N", "--empty-password", "-d", f"sql:{profile}"]))
    run(researcher_command([
        "certutil", "-A", "-n", "TLSKeyHunter Lab CA", "-t", "CT,,",
        "-i", str(ca_cert), "-d", f"sql:{profile}",
    ]))
    run(researcher_command([
        "certutil", "-A", "-n", "TLSKeyHunter localhost", "-t", "P,,",
        "-i", str(server_cert), "-d", f"sql:{profile}",
    ]))
    prefs = {
        "app.update.auto": False,
        "app.update.enabled": False,
        "browser.shell.checkDefaultBrowser": False,
        "browser.startup.homepage_override.mstone": "ignore",
        "browser.safebrowsing.downloads.enabled": False,
        "browser.safebrowsing.malware.enabled": False,
        "browser.safebrowsing.phishing.enabled": False,
        "datareporting.healthreport.uploadEnabled": False,
        "dom.push.enabled": False,
        "extensions.update.enabled": False,
        "network.http.http3.enable": False,
        "network.http.max-connections-per-server": 1,
        "network.http.max-persistent-connections-per-server": 1,
        "network.http.speculative-parallel-limit": 0,
        "network.captive-portal-service.enabled": False,
        "network.connectivity-service.enabled": False,
        "network.dns.disablePrefetch": True,
        "network.predictor.enabled": False,
        "network.prefetch-next": False,
        "browser.urlbar.speculativeConnect.enabled": False,
        "security.sandbox.socket.process.level": 0,
        "security.tls.version.min": 3 if args.protocol == "12" else 4,
        "security.tls.version.max": 3 if args.protocol == "12" else 4,
        "toolkit.telemetry.enabled": False,
    }
    user_js = "".join(f"user_pref({json.dumps(k)}, {json.dumps(v).lower()});\n" for k, v in prefs.items())
    write_text(profile / "user.js", user_js)
    os.chown(profile / "user.js", RESEARCHER_UID, RESEARCHER_GID)
    write_json(case_dir / "browser/profile-settings.json", prefs)

    firefox_root = args.firefox.parent
    artifacts = {
        "firefox": args.firefox,
        "firefox-bin": firefox_root / "firefox-bin",
        "libssl3": firefox_root / "libssl3.so",
        "libnss3": firefox_root / "libnss3.so",
        "libsoftokn3": firefox_root / "libsoftokn3.so",
        "hook": args.hook,
    }
    artifact_hashes = {
        name: {"path": str(path), "sha256": sha256(path)}
        for name, path in artifacts.items()
    }
    artifact_build_ids = {
        name: build_id(path) for name, path in artifacts.items() if path.suffix == ".so"
    }
    write_json(
        case_dir / "target-artifacts/hashes.json",
        artifact_hashes,
    )
    write_json(
        case_dir / "target-artifacts/build-ids.json",
        artifact_build_ids,
    )
    fingerprint_policy = json.loads(args.fingerprints.read_text(encoding="utf-8"))
    fingerprint_failures: list[str] = []
    for name, expected in fingerprint_policy["artifacts"].items():
        if name not in artifact_hashes:
            fingerprint_failures.append(f"missing artifact: {name}")
            continue
        if artifact_hashes[name]["sha256"] != expected["sha256"]:
            fingerprint_failures.append(f"SHA-256 mismatch: {name}")
        if "build_id" in expected and artifact_build_ids.get(name) != expected["build_id"]:
            fingerprint_failures.append(f"ELF Build ID mismatch: {name}")
    hook_module = fingerprint_policy.get("hook_module", "libssl3")
    hook_pattern = bytes.fromhex(fingerprint_policy["hook_pattern_hex"])
    pattern_matches = artifacts[hook_module].read_bytes().count(hook_pattern)
    if pattern_matches != fingerprint_policy["required_pattern_matches"]:
        fingerprint_failures.append(
            "hook pattern match count "
            f"{pattern_matches} != {fingerprint_policy['required_pattern_matches']}"
        )
    write_json(
        case_dir / "target-artifacts/fingerprint-validation.json",
        {
            "policy": str(args.fingerprints),
            "hook_pattern_id": fingerprint_policy["hook_pattern_id"],
            "pattern_matches": pattern_matches,
            "accepted": not fingerprint_failures,
            "failures": fingerprint_failures,
        },
    )
    if fingerprint_failures:
        raise RuntimeError("NSS fingerprint policy rejected the target: " + "; ".join(fingerprint_failures))
    write_json(
        case_dir / "target-artifacts/firefox-nss-profile.json",
        {
            "firefox_version": versions["firefox"],
            "profile": str(profile),
            "tls_min": f"1.{args.protocol[-1]}",
            "tls_max": f"1.{args.protocol[-1]}",
        },
    )

    server_events = case_dir / "server/server-events.jsonl"
    server_access = case_dir / "server/server-access.log"
    server_error = case_dir / "server/server-error.log"
    workload_events = case_dir / "browser/workload-events.jsonl"
    for path in [server_events, server_access, server_error, workload_events]:
        write_text(path, "")
    request_seen = threading.Event()
    handshake_gate = threading.Event()
    connection_lock = threading.Lock()
    connection_state = {"claimed": False, "rejected_before_tls": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *values: object) -> None:
            with event_lock, server_access.open("a", encoding="utf-8") as handle:
                handle.write(f"{utc()} {self.client_address[0]} {fmt % values}\n")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/event":
                query = urllib.parse.parse_qs(parsed.query)
                append_jsonl(
                    workload_events,
                    {
                        "timestamp": utc(), "case": args.case_id, "run": args.run_id,
                        "protocol": protocol, "request_id": request_id,
                        "state": query.get("state", ["browser_event"])[0], "marker": marker,
                    },
                    event_lock,
                )
                self.send_response(204)
                self.end_headers()
                return
            if parsed.path != "/lab":
                self.send_error(404)
                return
            request_seen.set()
            append_jsonl(
                server_events,
                {
                    "timestamp": utc(), "case": args.case_id, "run": args.run_id,
                    "protocol": protocol, "request_id": request_id,
                    "state": "request_received", "path": self.path,
                    "tls_version": self.connection.version(), "cipher": self.connection.cipher()[0],
                },
                event_lock,
            )
            body = (
                "<!doctype html><meta charset=utf-8><title>TLSKeyHunter Lab</title>"
                "<style>body{font:24px system-ui;margin:60px;background:#10141b;color:#e8f0ff}"
                ".ok{color:#62d39b}code{font-size:15px}</style>"
                f"<h1 class=ok>Controlled {protocol} response received</h1><p>{html.escape(marker)}</p>"
                f"<code>{html.escape(self.path)}</code>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            append_jsonl(
                server_events,
                {
                    "timestamp": utc(), "case": args.case_id, "run": args.run_id,
                    "protocol": protocol, "request_id": request_id,
                    "state": "response_sent", "marker": marker, "bytes": len(body),
                },
                event_lock,
            )
            append_jsonl(
                workload_events,
                {
                    "timestamp": utc(), "case": args.case_id, "run": args.run_id,
                    "protocol": protocol, "request_id": request_id,
                    "state": "response_received", "marker": marker,
                },
                event_lock,
            )

    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    selected_tls_version = (
        ssl.TLSVersion.TLSv1_2 if args.protocol == "12" else ssl.TLSVersion.TLSv1_3
    )
    tls_context.minimum_version = selected_tls_version
    tls_context.maximum_version = selected_tls_version
    if args.protocol == "12":
        tls_context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
        tls_context.options |= ssl.OP_NO_TICKET
    tls_context.load_cert_chain(server_cert, server_key)

    class GatedTLSHTTPServer(http.server.ThreadingHTTPServer):
        def get_request(self):
            plain_socket, client_address = super().get_request()
            if not handshake_gate.wait(30):
                plain_socket.close()
                raise TimeoutError("TLS handshake gate was not released within 30 seconds")
            with connection_lock:
                if connection_state["claimed"]:
                    connection_state["rejected_before_tls"] += 1
                    plain_socket.close()
                    raise ConnectionAbortedError(
                        "controlled case permits exactly one TLS connection"
                    )
                connection_state["claimed"] = True
            try:
                tls_socket = tls_context.wrap_socket(plain_socket, server_side=True)
            except Exception:
                plain_socket.close()
                raise
            return tls_socket, client_address

    server = GatedTLSHTTPServer(("127.0.0.1", args.port), Handler)
    resources["server"] = server
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    write_text(case_dir / "server/server-application.log", f"{utc()} listening 127.0.0.1:{args.port} {protocol}\n")
    terminal.emit("OK", f"Controlled {protocol} server listening on 127.0.0.1:{args.port}")

    capture_path = case_dir / "capture/traffic.pcapng"
    capture_temp = Path("/tmp") / f"tlskh-{args.case_id}-{os.getpid()}.pcapng"
    if capture_temp.exists():
        raise RuntimeError(f"refusing to reuse capture staging file: {capture_temp}")
    capture_diag = case_dir / "capture/capture-diagnostics.log"
    capture_command = ["dumpcap", "-i", "lo", "-f", f"tcp port {args.port}", "-w", str(capture_temp)]
    write_text(
        case_dir / "capture/capture-command.txt",
        " ".join(capture_command) + f"\nclosed capture moved to {capture_path}\n",
    )
    capture_handle = capture_diag.open("w", encoding="utf-8")
    resources["capture_handle"] = capture_handle
    capture_proc = subprocess.Popen(capture_command, stdout=capture_handle, stderr=subprocess.STDOUT, start_new_session=True)
    resources["capture_proc"] = capture_proc
    write_text(case_dir / "capture/dumpcap.pid", f"{capture_proc.pid}\n")
    time.sleep(1.5)
    if capture_proc.poll() is not None:
        capture_handle.flush()
        raise RuntimeError(f"dumpcap exited before the run; see {capture_diag}")

    server_reference = case_dir / "secrets/server-reference.keys"
    candidates = case_dir / "secrets/candidates.keys"
    verified = case_dir / "secrets/verified.keys"
    secret_outputs = [candidates, server_reference]
    for path in secret_outputs:
        write_text(path, "")
        path.chmod(0o600)
    # The controlled server exports an independent reference for every case.
    # Firefox never receives SSLKEYLOGFILE, and the reference is not read until
    # after Frida acquisition has been stopped and sealed.
    tls_context.keylog_filename = str(server_reference)
    terminal.emit(
        "OBSERVE",
        "Independent server reference enabled; target Firefox key logging remains disabled",
    )

    display_number = 90 + (int(hashlib.sha256(args.case_id.encode()).hexdigest()[:2], 16) % 9)
    display = f":{display_number}"
    display_socket = Path(f"/tmp/.X11-unix/X{display_number}")
    if display_socket.exists():
        raise RuntimeError(f"private Xvfb display already exists: {display}")
    xvfb_log = (case_dir / "browser/xvfb.log").open("w", encoding="utf-8")
    resources["xvfb_log"] = xvfb_log
    xvfb_proc = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", "1280x800x24", "-nolisten", "tcp", "-ac"],
        stdout=xvfb_log, stderr=subprocess.STDOUT, start_new_session=True,
    )
    resources["xvfb_proc"] = xvfb_proc
    write_text(case_dir / "browser/xvfb.pid", f"{xvfb_proc.pid}\n")
    write_text(case_dir / "browser/display.txt", display + "\n")
    for _ in range(40):
        if display_socket.exists():
            break
        if xvfb_proc.poll() is not None:
            raise RuntimeError(f"Xvfb exited before creating {display}")
        time.sleep(0.1)
    else:
        raise RuntimeError(f"Xvfb did not create {display} within four seconds")

    wm_log = (case_dir / "browser/twm.log").open("w", encoding="utf-8")
    resources["wm_log"] = wm_log
    wm_env = {"HOME": "/home/researcher", "DISPLAY": display}
    twm_config = case_dir / "browser/twmrc"
    write_text(twm_config, "RandomPlacement\n", mode=0o600)
    os.chown(twm_config, RESEARCHER_UID, RESEARCHER_GID)
    wm_proc = subprocess.Popen(
        researcher_command(["twm", "-f", str(twm_config)], wm_env),
        stdout=wm_log, stderr=subprocess.STDOUT, start_new_session=True,
    )
    resources["wm_proc"] = wm_proc
    write_text(case_dir / "browser/twm.pid", f"{wm_proc.pid}\n")
    time.sleep(1)
    if wm_proc.poll() is not None:
        wm_log.flush()
        raise RuntimeError("twm exited before Firefox launch; see browser/twm.log")

    vnc_proc = None
    ffmpeg_proc = None
    vnc_log = None
    ffmpeg_log = None
    recording_started_monotonic: float | None = None
    visual_stage_offsets: list[tuple[str, float]] = []

    def capture_visual_stage(stem: str, detail: str) -> None:
        if not args.visual_evidence:
            return
        if recording_started_monotonic is not None:
            # Do not open a second X11 client while Firefox and x11grab are
            # active.  The controlled response page supplies the mid-run marker.
            visual_stage_offsets.append(
                (stem, max(0.0, time.monotonic() - recording_started_monotonic))
            )
            return
        message = f"TLSKeyHunter {args.case_id}\nProtocol: {protocol}\n{detail}"
        status_proc = subprocess.Popen(
            ["xmessage", "-display", display, "-geometry", "1000x190+140+30", "-timeout", "2", message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)
        screenshot = case_dir / f"visual/{stem}.png"
        result = run(
            ["import", "-display", display, "-window", "root", str(screenshot)],
            check=False,
            timeout=15,
        )
        try:
            status_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            status_proc.terminate()
        if not screenshot.exists():
            write_text(case_dir / f"visual/{stem}.error.log", result.stdout)

    if args.visual_evidence:
        vnc_port = 5900 + display_number
        vnc_log = (case_dir / "visual/x11vnc.log").open("w", encoding="utf-8")
        resources["vnc_log"] = vnc_log
        vnc_command = [
            "x11vnc", "-display", display, "-localhost", "-rfbport", str(vnc_port),
            "-forever", "-shared", "-nopw", "-noshm",
        ]
        vnc_proc = subprocess.Popen(
            vnc_command, stdout=vnc_log, stderr=subprocess.STDOUT, start_new_session=True
        )
        resources["vnc_proc"] = vnc_proc
        write_text(case_dir / "visual/x11vnc-command.txt", " ".join(vnc_command) + "\n")
        write_text(
            case_dir / "visual/vnc-access.txt",
            f"localhost-only VNC port {vnc_port}\nSSH tunnel: ssh -L {vnc_port}:127.0.0.1:{vnc_port} researcher@<vps>\n",
        )
        ffmpeg_log = (case_dir / "visual/ffmpeg.log").open("w", encoding="utf-8")
        resources["ffmpeg_log"] = ffmpeg_log
        recording = case_dir / "visual/run-screen-recording.mp4"
        ffmpeg_command = [
            "ffmpeg", "-nostdin", "-n", "-loglevel", "warning", "-f", "x11grab",
            # Two frames per second preserves the complete GUI chronology while
            # leaving Xvfb responsive to Firefox, xdotool, and status overlays.
            "-framerate", "2", "-video_size", "1280x800", "-i", f"{display}.0",
            "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p", str(recording),
        ]
        write_text(case_dir / "visual/ffmpeg-command.txt", " ".join(ffmpeg_command) + "\n")
        capture_visual_stage(
            "01-before-run", "Hook ready: no | Request counter: 0 | Response marker: pending"
        )

    firefox_stdout = (case_dir / "browser/firefox-stdout.log").open("w", encoding="utf-8")
    firefox_stderr = (case_dir / "browser/firefox-stderr.log").open("w", encoding="utf-8")
    resources["firefox_stdout"] = firefox_stdout
    resources["firefox_stderr"] = firefox_stderr
    browser_env = {
        "HOME": "/home/researcher",
        "DISPLAY": display,
        "MOZ_DISABLE_SOCKET_PROCESS_SANDBOX": "1",
    }
    if not args.visual_evidence:
        browser_env["MOZ_HEADLESS"] = "1"
    write_json(
        case_dir / "browser/instrumentation-environment.json",
        {
            "MOZ_DISABLE_SOCKET_PROCESS_SANDBOX": "1",
            "reason": "permit Frida attachment to the isolated Firefox network socket process",
            "scope": "disposable controlled-lab Firefox profile and process tree",
        },
    )
    browser_args = [str(args.firefox)]
    if not args.visual_evidence:
        browser_args.append("--headless")
    browser_args += [
            "--profile",
            str(profile),
            "--remote-debugging-port",
            str(bidi_port),
            "about:blank",
        ]
    browser_command = researcher_command(browser_args, browser_env)
    write_text(case_dir / "browser/webdriver-bidi-endpoint.txt", bidi_endpoint + "\n")
    browser_proc = subprocess.Popen(
        browser_command, stdout=firefox_stdout, stderr=firefox_stderr, start_new_session=True
    )
    resources["browser_proc"] = browser_proc
    write_text(case_dir / "browser/firefox-launcher.pid", f"{browser_proc.pid}\n")
    browser_pid = None
    for _ in range(40):
        browser_pid = find_firefox_main(args.firefox, profile)
        if browser_pid is not None:
            break
        if browser_proc.poll() is not None:
            raise RuntimeError(f"Firefox exited before parent PID discovery: {browser_proc.returncode}")
        time.sleep(0.25)
    else:
        raise RuntimeError("Firefox parent PID was not discovered within 10 seconds")

    assert browser_pid is not None
    write_text(case_dir / "browser/firefox.pid", f"{browser_pid}\n")

    socket_pid = None
    for _ in range(80):
        socket_pid = find_firefox_socket_process(firefox_root, browser_pid)
        maps_path = Path(f"/proc/{socket_pid}/maps") if socket_pid else None
        if maps_path and maps_path.exists() and "libssl3.so" in maps_path.read_text(errors="replace"):
            break
        if not Path(f"/proc/{browser_pid}").exists():
            raise RuntimeError("Firefox exited before its network socket process loaded NSS")
        time.sleep(0.25)
    else:
        raise RuntimeError("Firefox socket process did not load libssl3.so within 20 seconds")

    assert socket_pid is not None
    write_text(case_dir / "browser/firefox-socket.pid", f"{socket_pid}\n")
    parent_maps = Path(f"/proc/{browser_pid}/maps").read_text(errors="replace")
    socket_maps = Path(f"/proc/{socket_pid}/maps").read_text(errors="replace")
    write_text(case_dir / "browser/firefox-parent-memory-maps.txt", parent_maps)
    write_text(case_dir / "browser/firefox-socket-memory-maps.txt", socket_maps)
    process_output = run(["ps", "-eo", "pid,ppid,user,stat,lstart,args"], check=False).stdout
    firefox_lines = [line for line in process_output.splitlines() if str(firefox_root) in line]
    write_json(
        case_dir / "browser/process-map.json",
        {"main_pid": browser_pid, "network_socket_pid": socket_pid, "processes": firefox_lines},
    )
    # TLS 1.3 HKDF derivation is performed in the Firefox parent in the
    # accepted baseline. TLS 1.2 PKCS#11/softoken derivation is performed by
    # the dedicated socket process, which owns the controlled connection.
    instrumented_pid = browser_pid
    write_json(
        case_dir / "frida/attached-processes.json",
        [
            {
                "pid": instrumented_pid,
                "role": "nss_tls_secret_derivation_process",
                "protocol": protocol,
                "network_socket_pid_observed": socket_pid,
            }
        ],
    )

    frida_events_path = case_dir / "frida/frida-events.jsonl"
    frida_diag_path = case_dir / "frida/frida-diagnostics.log"
    browser_console = case_dir / "browser/browser-console.log"
    for path in [frida_events_path, frida_diag_path, browser_console]:
        write_text(path, "")
    candidate_lines: list[str] = []
    tls12_candidates: list[tuple[str, str]] = []
    duplicate_events = 0
    preworkload_events = 0
    measurement_active = False
    hook_ready = threading.Event()
    hook_address: str | None = None

    def process_payload(payload: object) -> None:
        nonlocal duplicate_events, preworkload_events, hook_address
        payload = str(payload).strip()
        tls12_match = TLS12_SECRET_RE.fullmatch(payload)
        if tls12_match:
            if not measurement_active:
                preworkload_events += 1
                return
            item = (tls12_match.group(1), tls12_match.group(2).upper())
            if item in tls12_candidates:
                duplicate_events += 1
                return
            tls12_candidates.append(item)
            candidate_id = hashlib.sha256(item[1].encode()).hexdigest()[:16]
            append_jsonl(
                frida_events_path,
                {
                    "timestamp": utc(), "pid": instrumented_pid, "thread_id": None,
                    "module": "libsoftokn3.so", "hook_id": "nss136_tls12_p_hash",
                    "hook_address": hook_address,
                    "pattern_id": fingerprint_policy["hook_pattern_id"],
                    "tls_label": item[0], "candidate_id": candidate_id,
                    "candidate_length": 48, "connection_token": None,
                    "argument_index": 3, "rank_score": None, "rejection_reason": None,
                },
                event_lock,
            )
            return
        match = KEYLOG_RE.fullmatch(payload.strip())
        if match:
            if not measurement_active:
                preworkload_events += 1
                return
            line = f"{match.group(1)} {match.group(2).upper()} {match.group(3).upper()}"
            if line in candidate_lines:
                duplicate_events += 1
                return
            candidate_lines.append(line)
            with candidates.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            candidate_id = hashlib.sha256(line.encode()).hexdigest()[:16]
            append_jsonl(
                frida_events_path,
                {
                    "timestamp": utc(), "pid": instrumented_pid, "thread_id": None,
                    "module": f"{hook_module}.so", "hook_id": f"nss136_{protocol_slug}_derive",
                    "hook_address": hook_address, "pattern_id": fingerprint_policy["hook_pattern_id"],
                    "tls_label": match.group(1), "candidate_id": candidate_id,
                    "candidate_length": len(match.group(3)) // 2,
                    "connection_token": hashlib.sha256(match.group(2).upper().encode()).hexdigest()[:16],
                    "argument_index": 5, "rank_score": None, "rejection_reason": None,
                },
                event_lock,
            )
            return
        if payload.startswith("Pattern found at (derive_secret):") or payload.startswith(
            "Pattern found at (tls12_p_hash):"
        ):
            hook_address = payload.rsplit(" ", 1)[-1]
            hook_ready.set()
            terminal.emit("OK", f"Frida hook ready in {hook_module}.so at {hook_address}")
        with event_lock, frida_diag_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{utc()} {payload}\n")

    def on_message(message: dict, data: bytes | None) -> None:
        if message.get("type") == "send":
            process_payload(message.get("payload"))
        else:
            process_payload(json.dumps(message, sort_keys=True))

    def on_log(level: str, text: str) -> None:
        for line in text.splitlines() or [text]:
            process_payload(line)

    # Queue navigation while Firefox's parent process is responsive. The server
    # accepts the TCP connection but holds the TLS handshake at handshake_gate,
    # so no measured key derivation can occur before Frida is attached below.
    time.sleep(3)
    if not Path(f"/proc/{browser_pid}").exists():
        raise RuntimeError("Firefox exited before Frida could attach")
    if not args.visual_evidence:
        bidi = None
        bidi_error: Exception | None = None
        for _ in range(40):
            try:
                bidi = websocket_connect(bidi_endpoint, open_timeout=2, close_timeout=2)
                break
            except Exception as error:
                bidi_error = error
                time.sleep(0.25)
        if bidi is None:
            raise RuntimeError(f"Firefox WebDriver BiDi endpoint was unavailable: {bidi_error}")
        try:
            bidi_session = bidi_request(
                bidi,
                1,
                "session.new",
                {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": True}}},
            )
            bidi_tree = bidi_request(bidi, 2, "browsingContext.getTree", {})
            contexts = bidi_tree["result"]["contexts"]
            if not contexts:
                raise RuntimeError("Firefox WebDriver BiDi returned no browsing contexts")
            context_id = contexts[0]["context"]
            bidi_navigation = bidi_request(
                bidi,
                3,
                "browsingContext.navigate",
                {"context": context_id, "url": target_url, "wait": "none"},
            )
            write_json(
                case_dir / "browser/navigation-command.json",
                {
                    "transport": "WebDriver BiDi over loopback",
                    "endpoint": bidi_endpoint,
                    "session_id": bidi_session["result"]["sessionId"],
                    "accept_insecure_certs": True,
                    "context": context_id,
                    "target_url": target_url,
                    "navigation": bidi_navigation["result"],
                },
            )
        finally:
            bidi.close()

    session = frida.get_local_device().attach(instrumented_pid)
    resources["frida_session"] = session
    script = session.create_script(args.hook.read_text(encoding="utf-8"))
    resources["frida_script"] = script
    script.on("message", on_message)
    script.set_log_handler(on_log)
    script.load()
    if not hook_ready.wait(10):
        raise RuntimeError(f"Frida did not report a {protocol} pattern match")
    write_json(
        case_dir / "frida/hook-summary.json",
        {"installed": True, "module": f"{hook_module}.so", "address": hook_address, "pattern_matches": 1},
    )
    capture_visual_stage(
        "02-hooks-ready", f"Hook ready: yes ({hook_module}) | Request counter: 0 | Response marker: pending"
    )

    measurement_active = True
    append_jsonl(
        workload_events,
        {
            "timestamp": utc(), "case": args.case_id, "run": args.run_id,
            "protocol": protocol, "request_id": request_id,
            "state": "request_started", "url": target_url,
        },
        event_lock,
    )
    if args.visual_evidence:
        x11_env = {"HOME": "/home/researcher", "DISPLAY": display}
        window_tree = run(
            researcher_command(["xwininfo", "-root", "-tree"], x11_env),
            check=False,
            timeout=5,
        )
        write_text(case_dir / "browser/x-window-tree.txt", window_tree.stdout)
        window_ids: list[str] = []
        for _ in range(80):
            window_search = run(
                researcher_command(
                    ["xdotool", "search", "--onlyvisible", "--name", "Mozilla Firefox"],
                    x11_env,
                ),
                check=False,
                timeout=2,
            )
            window_ids = [line.strip() for line in window_search.stdout.splitlines() if line.strip()]
            if window_search.returncode == 0 and window_ids:
                break
            time.sleep(0.25)
        if not window_ids:
            raise RuntimeError("xdotool could not resolve the visible Mozilla Firefox window by title")
        window_id = window_ids[0]
        focus = run(
            researcher_command(
                ["xdotool", "windowfocus", "--sync", window_id], x11_env
            ),
            check=False,
            timeout=5,
        )
        if focus.returncode != 0:
            raise RuntimeError("xdotool could not focus the visible Firefox window")
        visual_bidi = None
        visual_bidi_error: Exception | None = None
        for _ in range(40):
            try:
                visual_bidi = websocket_connect(bidi_endpoint, open_timeout=2, close_timeout=2)
                break
            except Exception as error:
                visual_bidi_error = error
                time.sleep(0.25)
        if visual_bidi is None:
            raise RuntimeError(f"visual Firefox WebDriver BiDi unavailable: {visual_bidi_error}")
        try:
            visual_session = bidi_request(
                visual_bidi,
                1,
                "session.new",
                {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": True}}},
            )
            visual_tree = bidi_request(visual_bidi, 2, "browsingContext.getTree", {})
            visual_contexts = visual_tree["result"]["contexts"]
            if not visual_contexts:
                raise RuntimeError("visual Firefox WebDriver BiDi returned no browsing contexts")
            visual_context = visual_contexts[0]["context"]
            visual_navigation = bidi_request(
                visual_bidi,
                3,
                "browsingContext.navigate",
                {"context": visual_context, "url": target_url, "wait": "none"},
            )
        finally:
            visual_bidi.close()
        write_json(
            case_dir / "browser/navigation-command.json",
            {
                "transport": "WebDriver BiDi over loopback with visible-window xdotool focus",
                "display": display,
                "window_id": window_id,
                "window_pid": browser_pid,
                "target_url": target_url,
                "xdotool_focus_exit_code": focus.returncode,
                "endpoint": bidi_endpoint,
                "session_id": visual_session["result"]["sessionId"],
                "accept_insecure_certs": True,
                "context": visual_context,
                "navigation": visual_navigation["result"],
            },
        )
        ffmpeg_proc = subprocess.Popen(
            ffmpeg_command, stdout=ffmpeg_log, stderr=subprocess.STDOUT, start_new_session=True
        )
        recording_started_monotonic = time.monotonic()
        resources["ffmpeg_proc"] = ffmpeg_proc
    handshake_gate.set()
    request_seen.wait(20)
    capture_visual_stage(
        "03-mid-run",
        f"Hook ready: yes | Request counter: {int(request_seen.is_set())} | "
        f"Response marker hash: {hashlib.sha256(marker.encode()).hexdigest()[:16]}",
    )
    time.sleep(7)
    measurement_active = False

    script.unload()
    session.detach()
    if Path(f"/proc/{browser_pid}").exists():
        os.kill(browser_pid, signal.SIGTERM)
    if browser_proc.poll() is None:
        try:
            browser_proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            browser_proc.terminate()
            browser_proc.wait(timeout=5)
    firefox_stdout.close()
    firefox_stderr.close()
    if not args.visual_evidence:
        if wm_proc.poll() is None:
            os.killpg(wm_proc.pid, signal.SIGTERM)
            try:
                wm_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(wm_proc.pid, signal.SIGKILL)
                wm_proc.wait(timeout=4)
        wm_log.close()
        xvfb_proc.terminate()
        try:
            xvfb_proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            xvfb_proc.kill()
            xvfb_proc.wait(timeout=4)
        xvfb_log.close()

    capture_proc.send_signal(signal.SIGINT)
    try:
        capture_proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        capture_proc.terminate()
        capture_proc.wait(timeout=5)
    capture_handle.close()
    if not capture_temp.exists():
        raise RuntimeError("dumpcap closed without producing the staged PCAP")
    capture_temp.chmod(0o600)
    os.chown(capture_temp, RESEARCHER_UID, RESEARCHER_GID)
    server.shutdown()
    server.server_close()

    client_hello_output = run(researcher_command([
        "tshark", "-r", str(capture_temp), "-d", f"tcp.port=={args.port},tls",
        "-Y", "tls.handshake.type==1", "-T", "fields", "-E", "separator=\t",
        "-e", "tcp.stream", "-e", "tls.handshake.random",
    ]), check=False).stdout
    server_hello_streams = {
        value.strip()
        for value in run(researcher_command([
            "tshark", "-r", str(capture_temp), "-d", f"tcp.port=={args.port},tls",
            "-Y", "tls.handshake.type==2", "-T", "fields", "-e", "tcp.stream",
        ]), check=False).stdout.splitlines()
        if value.strip().isdigit()
    }
    client_hellos: list[tuple[str, str]] = []
    for row in client_hello_output.splitlines():
        columns = row.split("\t")
        if len(columns) != 2:
            continue
        stream, random_value = (column.strip() for column in columns)
        if stream.isdigit() and re.fullmatch(r"[0-9A-Fa-f]{64}", random_value):
            client_hellos.append((stream, random_value.upper()))
    completed_client_hellos = [
        (stream, random_value)
        for stream, random_value in client_hellos
        if stream in server_hello_streams
    ]
    captured_randoms = {random_value for _stream, random_value in completed_client_hellos}
    write_json(
        case_dir / "capture/clienthello-association.json",
        {
            "policy": "ClientHello from a TCP stream containing a ServerHello",
            "selection_performed_before_reference_read": True,
            "all_client_hello_streams": [stream for stream, _random in client_hellos],
            "completed_handshake_streams": sorted(server_hello_streams),
            "selected_streams": [stream for stream, _random in completed_client_hellos],
            "selected_random_sha256": [
                hashlib.sha256(bytes.fromhex(random_value)).hexdigest()
                for _stream, random_value in completed_client_hellos
            ],
            "server_connections_rejected_before_tls": connection_state["rejected_before_tls"],
        },
    )

    acquisition_status = "selected"
    acquisition_failure_reason = None
    acquired_candidate_lines = list(dict.fromkeys(candidate_lines))
    if args.protocol == "12":
        unique_secrets = sorted({secret for _label, secret in tls12_candidates})
        if not unique_secrets:
            acquisition_status = "no_candidate"
            acquisition_failure_reason = "no TLS 1.2 master-secret candidate was acquired"
            acquired_candidate_lines = []
        elif len(unique_secrets) != 1:
            acquisition_status = "ambiguous"
            acquisition_failure_reason = "multiple distinct TLS 1.2 secrets were acquired"
            acquired_candidate_lines = []
        elif len(captured_randoms) != 1:
            acquisition_status = "ambiguous" if captured_randoms else "no_candidate"
            acquisition_failure_reason = (
                "expected exactly one captured ClientHello random; "
                f"observed {len(captured_randoms)}"
            )
            acquired_candidate_lines = []
        else:
            acquired_candidate_lines = [
                f"CLIENT_RANDOM {next(iter(captured_randoms))} {unique_secrets[0]}"
            ]
        terminal.emit(
            "OBSERVE",
            f"TLS 1.2 acquisition candidates={len(unique_secrets)} "
            f"client_randoms={len(captured_randoms)} status={acquisition_status}",
        )

    required_labels = (
        {"CLIENT_RANDOM"}
        if args.protocol == "12"
        else {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
        }
    )
    if args.protocol == "13" and acquisition_status == "selected":
        grouped: dict[tuple[str, str], set[str]] = {}
        for line in acquired_candidate_lines:
            parts = line.split()
            if len(parts) != 3:
                acquisition_status = "ambiguous"
                acquisition_failure_reason = "malformed TLS 1.3 candidate line"
                break
            grouped.setdefault((parts[0], parts[1].upper()), set()).add(parts[2].upper())
        conflicting = [key for key, values in grouped.items() if len(values) != 1]
        if conflicting:
            acquisition_status = "ambiguous"
            acquisition_failure_reason = "multiple candidate secrets share a TLS label/random"
        elif len(captured_randoms) != 1:
            acquisition_status = "ambiguous" if captured_randoms else "no_candidate"
            acquisition_failure_reason = (
                "expected exactly one captured ClientHello random; "
                f"observed {len(captured_randoms)}"
            )
        elif not required_labels.issubset({line.split()[0] for line in acquired_candidate_lines}):
            acquisition_status = "no_candidate"
            acquisition_failure_reason = "required TLS 1.3 traffic-secret labels were not all acquired"

    candidate_lines = acquired_candidate_lines if acquisition_status == "selected" else []
    write_text(candidates, "".join(line + "\n" for line in acquired_candidate_lines))
    candidates.chmod(0o400)
    acquisition_sealed_at = utc()
    acquisition_seal = {
        "schema_version": 1,
        "case_id": args.case_id,
        "protocol": protocol,
        "acquisition_sealed": True,
        "acquisition_sealed_at": acquisition_sealed_at,
        "status": acquisition_status,
        "failure_reason": acquisition_failure_reason,
        "candidate_count": len(acquired_candidate_lines),
        "selected_candidate_count": len(candidate_lines),
        "candidate_file": "secrets/candidates.keys",
        "candidate_file_sha256": sha256(candidates),
        "candidate_ids": [
            hashlib.sha256(line.encode()).hexdigest()[:16]
            for line in acquired_candidate_lines
        ],
        "ground_truth_consulted_before_seal": False,
        "tshark_decryption_attempted_before_seal": False,
        "server_reference_access_during_acquisition": "root-only mode-0600",
    }
    write_json(case_dir / "secrets/acquisition-seal.json", acquisition_seal)
    terminal.emit(
        "OK" if acquisition_status == "selected" else "FAIL",
        f"Acquisition sealed status={acquisition_status} candidates={len(candidate_lines)} "
        f"seal_sha256={acquisition_seal['candidate_file_sha256']}",
    )

    # Verification starts only after the acquisition file and metadata have
    # been sealed. The controlled server reference was never available to the
    # Firefox process or Frida hook.
    server_reference_lines = {
        line.strip().upper()
        for line in server_reference.read_text(errors="replace").splitlines()
        if KEYLOG_RE.fullmatch(line.strip())
    }
    verified_lines = [
        line for line in candidate_lines if line.upper() in server_reference_lines
    ]
    exact_reference_match = bool(
        candidate_lines
        and len(verified_lines) == len(candidate_lines)
        and required_labels.issubset({line.split()[0] for line in verified_lines})
    )

    reference_by_key: dict[tuple[str, str], list[str]] = {}
    for line in server_reference_lines:
        label, client_random, secret = line.split()
        reference_by_key.setdefault((label, client_random), []).append(secret)
    reference_comparisons = []
    for line in acquired_candidate_lines:
        label, client_random, secret = line.split()
        references = reference_by_key.get((label, client_random.upper()), [])
        distances = [
            distance for distance in (
                hamming_distance_hex(secret, reference) for reference in references
            )
            if distance is not None
        ]
        reference_comparisons.append({
            "candidate_id": hashlib.sha256(line.encode()).hexdigest()[:16],
            "label": label,
            "reference_available": bool(references),
            "exact_reference_match": line.upper() in server_reference_lines,
            "minimum_hamming_distance_bits": min(distances) if distances else None,
        })
    write_json(
        case_dir / "verification/reference-comparisons.json",
        reference_comparisons,
    )
    verified_labels = {line.split()[0] for line in candidate_lines}
    verification_keylog = Path("/tmp") / f"tlskh-{args.case_id}-verified.keys"
    if verification_keylog.exists():
        raise RuntimeError(f"refusing to reuse verification keylog staging file: {verification_keylog}")
    write_text(verification_keylog, "".join(line + "\n" for line in candidate_lines))
    os.chown(verification_keylog, RESEARCHER_UID, RESEARCHER_GID)
    candidate_hashes = [
        {
            "candidate_id": hashlib.sha256(line.encode()).hexdigest()[:16],
            "line_sha256": hashlib.sha256(line.encode()).hexdigest(),
            "label": line.split()[0],
            "acquisition_status": acquisition_status,
            "selected_before_verification": line in candidate_lines,
            "exact_server_reference_match": line in verified_lines,
            "eligible_for_functional_validation": line in candidate_lines,
        }
        for line in acquired_candidate_lines
    ]
    write_json(case_dir / "secrets/candidate-hashes.json", candidate_hashes)

    tshark_command = [
        "tshark", "-r", str(capture_temp), "-d", f"tcp.port=={args.port},tls",
        "-o", f"tls.keylog_file:{verification_keylog}", "-Y", "http || tls.alert_message", "-V",
    ]
    write_text(case_dir / "verification/tshark-command.txt", " ".join(tshark_command) + "\n")
    tshark = run(researcher_command(tshark_command), check=False)
    write_text(case_dir / "verification/tshark-output.log", tshark.stdout)
    fields = run(researcher_command([
        "tshark", "-r", str(capture_temp), "-d", f"tcp.port=={args.port},tls",
        "-o", f"tls.keylog_file:{verification_keylog}", "-T", "fields", "-E", "separator=\t",
        "-e", "frame.number", "-e", "tcp.stream", "-e", "http.request.full_uri", "-e", "http.file_data",
    ]), check=False)
    write_text(case_dir / "verification/decrypted-streams.tsv", fields.stdout)
    decrypted_http_bodies = bytearray()
    for row in fields.stdout.splitlines():
        columns = row.split("\t")
        if len(columns) < 4 or not columns[3].strip():
            continue
        for encoded_body in columns[3].split(","):
            compact_hex = re.sub(r"[^0-9A-Fa-f]", "", encoded_body)
            if compact_hex and len(compact_hex) % 2 == 0:
                try:
                    decrypted_http_bodies.extend(bytes.fromhex(compact_hex))
                except ValueError:
                    continue
    request_ok = request_path in tshark.stdout or request_path in fields.stdout
    marker_ok = (
        marker in tshark.stdout
        or marker in fields.stdout
        or marker.encode() in decrypted_http_bodies
    )
    write_json(
        case_dir / "verification/decrypted-body-evidence.json",
        {
            "decoded_bytes": len(decrypted_http_bodies),
            "body_sha256": hashlib.sha256(decrypted_http_bodies).hexdigest(),
            "exact_marker_present": marker_ok,
        },
    )
    handshake_frames = [
        value for value in run(researcher_command([
        "tshark", "-r", str(capture_temp), "-d", f"tcp.port=={args.port},tls", "-Y", "tls.handshake",
        "-T", "fields", "-e", "frame.number",
        ]), check=False).stdout.split()
        if value.isdigit()
    ]
    shutil.move(str(capture_temp), str(capture_path))
    capture_path.chmod(0o600)
    os.chown(capture_path, RESEARCHER_UID, RESEARCHER_GID)
    complete_tls_handshake = bool(handshake_frames and required_labels.issubset(verified_labels))
    accepted = bool(
        request_seen.is_set()
        and acquisition_status == "selected"
        and candidate_lines
        and complete_tls_handshake
        and exact_reference_match
        and request_ok
        and marker_ok
    )
    if accepted:
        shutil.move(str(verification_keylog), str(verified))
        verified.chmod(0o600)
        os.chown(verified, RESEARCHER_UID, RESEARCHER_GID)
    else:
        verification_keylog.unlink(missing_ok=True)
    validated_candidate_count = len(verified_lines)
    status = "Eligible and fully recovered" if accepted else "Unverified"
    verification = {
        "case_id": args.case_id, "run_id": args.run_id, "protocol": protocol,
        "mode": args.mode, "status": status,
        "target_sslkeylogfile_enabled": False,
        "independent_server_reference_enabled": True,
        "acquisition_sealed": acquisition_seal["acquisition_sealed"],
        "acquisition_sealed_at": acquisition_sealed_at,
        "acquisition_status": acquisition_status,
        "acquisition_failure_reason": acquisition_failure_reason,
        "browser_workload_event": request_seen.is_set(), "server_event": request_seen.is_set(),
        "complete_tls_handshake": complete_tls_handshake, "handshake_frames": handshake_frames,
        "frida_candidate_event": bool(acquired_candidate_lines),
        "exact_server_reference_match": exact_reference_match,
        "tshark_decryption": request_ok and marker_ok,
        "exact_request_path_recovered": request_ok, "exact_response_marker_recovered": marker_ok,
        "verified_candidate_count": validated_candidate_count,
    }
    write_json(case_dir / "verification/verification.json", verification)
    write_json(
        case_dir / "verification/candidate-associations.json",
        [
            {
                "candidate_id": item["candidate_id"],
                "request_id": request_id,
                "verified": (
                    item["selected_before_verification"]
                    and item["exact_server_reference_match"]
                    and accepted
                ),
                "verification_basis": (
                    "sealed acquisition plus exact independent server-reference equality "
                    "plus authenticated request/response decryption"
                ),
            }
            for item in candidate_hashes
        ],
    )
    write_json(case_dir / "verification/streams.json", {"request_id": request_id, "request_path": request_path, "marker_sha256": hashlib.sha256(marker.encode()).hexdigest()})
    exclusions = [] if accepted else [{"request_id": request_id, "reason": "one or more Phase 18A acceptance checks failed", "checks": verification}]
    exclusions.append({"control": "negative_controls", "reason": "not run in single-session pilot; required before measured campaign"})
    write_json(case_dir / "verification/exclusions.json", exclusions)

    observed_labels = sorted({line.split()[0] for line in acquired_candidate_lines})
    metrics = {
        "eligible_sessions": 1,
        "fully_recovered_sessions": int(accepted),
        "session_recovery_coverage": float(int(accepted)),
        "frida_events": len(acquired_candidate_lines),
        "acquired_candidate_count": len(acquired_candidate_lines),
        "selected_candidate_count": len(candidate_lines),
        "acquisition_status": acquisition_status,
        "syntactically_valid_candidate_groups": len(acquired_candidate_lines),
        "verified_candidate_groups": validated_candidate_count,
        "exact_secret_match": exact_reference_match,
        "exact_secret_match_rate": float(exact_reference_match),
        "candidate_validation_rate": validated_candidate_count / len(candidate_lines) if candidate_lines else 0.0,
        "tls_labels": observed_labels,
        f"{protocol_slug}_labels": observed_labels,
        "duplicate_events": duplicate_events,
        "preworkload_events_excluded": preworkload_events,
        "pattern_scan_failures": 0,
        "browser_or_frida_failures": 0 if request_seen.is_set() else 1,
    }
    write_json(case_dir / "metrics/metrics.json", metrics)
    write_json(case_dir / "metrics/confidence-interval.json", wilson(int(accepted), 1))
    with (case_dir / "metrics/run-summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["case_id", "run_id", "protocol", "eligible", "recovered", "status"])
        writer.writerow([args.case_id, args.run_id, protocol, 1, int(accepted), status])

    if args.visual_evidence:
        if ffmpeg_proc is not None and ffmpeg_proc.poll() is None:
            ffmpeg_proc.send_signal(signal.SIGINT)
            try:
                ffmpeg_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                ffmpeg_proc.terminate()
                ffmpeg_proc.wait(timeout=5)
        if ffmpeg_log is not None:
            ffmpeg_log.close()
        for stem, offset in visual_stage_offsets:
            screenshot = case_dir / f"visual/{stem}.png"
            result = run(
                [
                    "ffmpeg", "-nostdin", "-y", "-loglevel", "error",
                    "-ss", f"{offset:.3f}", "-i", str(recording),
                    "-frames:v", "1", str(screenshot),
                ],
                check=False,
                timeout=15,
            )
            if not screenshot.exists():
                write_text(case_dir / f"visual/{stem}.error.log", result.stdout)
        recording_started_monotonic = None
        capture_visual_stage(
            "04-run-complete",
            f"Hook ready: yes | Request counter: {int(request_seen.is_set())} | "
            f"Response marker hash: {hashlib.sha256(marker.encode()).hexdigest()[:16]} | "
            f"Verification: {'PASS' if accepted else 'FAIL'}",
        )
        if vnc_proc is not None and vnc_proc.poll() is None:
            vnc_proc.terminate()
            try:
                vnc_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                vnc_proc.kill()
                vnc_proc.wait(timeout=4)
        if vnc_log is not None:
            vnc_log.close()
        if wm_proc.poll() is None:
            os.killpg(wm_proc.pid, signal.SIGTERM)
            try:
                wm_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(wm_proc.pid, signal.SIGKILL)
                wm_proc.wait(timeout=4)
        wm_log.close()
        xvfb_proc.terminate()
        try:
            xvfb_proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            xvfb_proc.kill()
            xvfb_proc.wait(timeout=4)
        xvfb_log.close()

    command_log(case_dir / "environment/process-list-after.txt", ["ps", "auxww"])
    network_after = run(["ip", "addr", "show"], check=False).stdout
    network_after += run(["ip", "route", "show"], check=False).stdout
    network_after += run(["ss", "-tulpn"], check=False).stdout
    write_text(case_dir / "environment/network-after.txt", network_after)
    end_time = utc()
    write_text(case_dir / "environment/end-time-utc.txt", end_time + "\n")

    report_lines = [
        f"# TLSKeyHunter controlled Firefox/NSS {protocol} case — {args.case_id}",
        "", f"- Run: {args.run_id}", f"- Start UTC: {start_time}", f"- End UTC: {end_time}",
        f"- Status: {status}", f"- Firefox parent PID: {browser_pid}",
        f"- Firefox network socket PID: {socket_pid}",
        f"- Firefox: {versions['firefox']}", f"- Hook installed: yes, one match ({hook_address})",
        f"- Eligible sessions: 1", f"- Fully recovered sessions: {int(accepted)}",
        f"- Frida candidate events: {len(acquired_candidate_lines)}",
        f"- Acquisition status: {acquisition_status}",
        "- Acquisition sealed before verification: true",
        f"- Exact server-reference match: {exact_reference_match}",
        f"- Verified candidates: {len(verified_lines)}",
        f"- Duplicate events: {duplicate_events}", f"- {protocol} labels: {', '.join(observed_labels) or 'none'}",
        f"- Exact request path recovered: {request_ok}", f"- Exact response marker recovered: {marker_ok}",
        "- Negative controls: not run in this pilot; required before measured campaign.",
        "- Raw secret bytes: excluded from this report; stored only in owner-readable evidence files.",
        "- Evidence manifest: evidence-manifest.sha256 (self-excluded to avoid recursion).", "",
        "This run is accepted only if verification/verification.json records all Phase 18A checks as true.",
    ]
    report_md = "\n".join(report_lines) + "\n"
    write_text(case_dir / "reports/run-report.md", report_md)
    report_html = "<!doctype html><meta charset=utf-8><title>TLSKeyHunter run report</title>" \
        "<style>body{font:16px system-ui;max-width:900px;margin:40px auto;line-height:1.5}pre{white-space:pre-wrap}</style>" \
        f"<pre>{html.escape(report_md)}</pre>"
    write_text(case_dir / "reports/run-report.html", report_html)
    write_simple_pdf(case_dir / "reports/run-report.pdf", [line.lstrip("#- ") for line in report_lines])

    chown_case(case_dir)

    terminal.emit(
        "METRIC",
        f"{protocol} recovered={int(accepted)}/1 acquired={len(acquired_candidate_lines)} "
        f"exact_match={int(exact_reference_match)} acquisition={acquisition_status}",
    )
    terminal.emit("ARTIFACT", str(case_dir))

    manifest_lines = []
    for path in sorted(case_dir.rglob("*")):
        if path.is_file() and path.name not in {"evidence-manifest.sha256", "runner-console.log"}:
            manifest_lines.append(f"{sha256(path)}  {path.relative_to(case_dir)}")
    write_text(case_dir / "evidence-manifest.sha256", "\n".join(manifest_lines) + "\n")
    chown_case(case_dir)
    candidates.chmod(0o400)
    server_reference.chmod(0o400)
    print(json.dumps({"case_dir": str(case_dir), "status": status, "metrics": metrics}, indent=2))
    return 0 if accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
