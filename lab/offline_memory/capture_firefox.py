#!/usr/bin/env python3
"""Development-only TLS 1.2 core capture; never reads the server key reference."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_for(predicate, seconds=40):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    raise TimeoutError("Timed out waiting for the controlled lab event")


def argv_for(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace").split("\0")
    except (OSError, ProcessLookupError):
        return []


def firefox_pids(profile):
    parent = None
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        argv = argv_for(entry.name)
        if argv and "--profile" in argv and str(profile) in argv and Path(argv[0]).name in {"firefox", "firefox-bin"}:
            parent = int(entry.name)
            break
    if parent is None:
        return None
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        argv = argv_for(entry.name)
        if "socket" in argv and "-parentPid" in argv:
            index = argv.index("-parentPid")
            if argv[index + 1] == str(parent):
                return parent, int(entry.name)
    return None


def serve(args):
    """Separate root process: reference stays outside the researcher's permissions."""
    private = args.reference
    case = args.case
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = (ssl.TLSVersion.TLSv1_3 if args.tls_version == "1.3" else ssl.TLSVersion.TLSv1_2)
    if args.tls_version == "1.2":
        context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    else:
        context.num_tickets = 0
    context.load_cert_chain(private / "server.cert.pem", private / "server.key.pem")
    context.keylog_filename = str(private / "server-reference.keys")
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.port))
        listener.listen(1)
        listener.settimeout(60)
        (case / "server.ready").write_text(utc())
        raw, address = listener.accept()
        with context.wrap_socket(raw, server_side=True) as connection:
            connection.settimeout(30)
            request = b""
            while b"\r\n\r\n" not in request and len(request) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    raise RuntimeError("Connection ended before the request")
                request += chunk
            path = request.split(b"\r\n", 1)[0].decode().split(" ")[1]
            marker = f"TLSKH-OFFLINE|{case.name}|TLS{args.tls_version}|CONTROLLED-RESPONSE"
            body = marker.encode()
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" + f"{len(body):x}\r\n".encode() + body + b"\r\n")
            write_json(case / "server-event.json", {
                "time": utc(), "protocol": connection.version(), "cipher": connection.cipher()[0],
                "request_path": path, "response_marker": marker,
                "peer_address": address[0], "peer_port": address[1],
                "session_reused": connection.session_reused,
                "capture_condition": "after first response chunk; connection held open",
            })
            wait_for(lambda: (case / "release-server").exists(), 180)
            connection.sendall(b"0\r\n\r\n")


def main(args):
    if os.geteuid() != 0:
        raise RuntimeError("Acquisition requires root in the controlled lab")
    def stop_capture(signum, frame):
        raise RuntimeError("Capture interrupted by campaign guard")
    signal.signal(signal.SIGTERM, stop_capture)
    os.umask(0o077)
    case = args.case.resolve()
    private = args.reference.resolve()
    case.mkdir(parents=True, exist_ok=False)
    private.mkdir(parents=True, exist_ok=False)
    account = pwd.getpwnam("researcher")
    # The server reference is under /root; only capture artifacts are given to researcher.
    profile = case / "profile"
    profile.mkdir()
    for path in (case, profile):
        os.chown(path, account.pw_uid, account.pw_gid)
    processes = []
    handles = []
    socket_pid = None
    bidi = None
    record = {"case_id": case.name, "started": utc(), "status": "started",
              "kind": "development_capture", "target_key_logging": False,
              "requested_tls_version": args.tls_version,
              "scenario": args.scenario, "frida_loaded": False, "key_export_api_called": False,
              "socket_sandbox_exception": args.lab_disable_socket_sandbox,
              "accept_insecure_certs": args.lab_accept_insecure_certs,
              "capture_script_sha256": sha256(Path(__file__).resolve()),
              "server_reference_path": str(private / "server-reference.keys")}

    def run(command, logname):
        with (case / logname).open("w") as out:
            subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, check=True, timeout=30)

    def launch(command, logname):
        out = (case / logname).open("w")
        handles.append(out)
        proc = subprocess.Popen(command, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(proc)
        return proc

    try:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=Offline Pilot CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(private / "ca.key.pem"), "-out", str(private / "ca.cert.pem")], "ca-generation.log")
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", str(private / "server.key.pem"), "-out", str(private / "server.csr.pem")], "server-csr.log")
        extensions = private / "server.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        run(["openssl", "x509", "-req", "-in", str(private / "server.csr.pem"), "-CA", str(private / "ca.cert.pem"),
             "-CAkey", str(private / "ca.key.pem"), "-CAcreateserial", "-days", "2", "-sha256",
             "-extfile", str(extensions), "-out", str(private / "server.cert.pem")], "certificate-generation.log")
        cert = case / "ca.cert.pem"
        shutil.copyfile(private / "ca.cert.pem", cert)
        os.chown(cert, account.pw_uid, account.pw_gid)
        run(["runuser", "-u", "researcher", "--", "certutil", "-N", "--empty-password", "-d", f"sql:{profile}"], "profile-init.log")
        run(["runuser", "-u", "researcher", "--", "certutil", "-A", "-n", "Offline localhost pilot CA", "-t", "CT,,", "-i", str(cert), "-d", f"sql:{profile}"], "profile-trust.log")
        leaf = case / "server.cert.pem"
        shutil.copyfile(private / "server.cert.pem", leaf)
        os.chown(leaf, account.pw_uid, account.pw_gid)
        run(["runuser", "-u", "researcher", "--", "certutil", "-A", "-n", "Offline localhost leaf", "-t", "P,,", "-i", str(leaf), "-d", f"sql:{profile}"], "leaf-trust.log")
        prefs = {"security.tls.version.min": 4 if args.tls_version == "1.3" else 3,
                 "security.tls.version.max": 4 if args.tls_version == "1.3" else 3,
                 "security.tls.enable_0rtt_data": False,
                 "network.http.http3.enable": False, "network.http.speculative-parallel-limit": 0,
                 "network.http.max-persistent-connections-per-server": 2 if args.scenario == "concurrency" else 1,
                 "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
                 "network.dns.disablePrefetch": True, "network.prefetch-next": False,
                 "datareporting.healthreport.uploadEnabled": False, "toolkit.telemetry.enabled": False,
                 "browser.shell.checkDefaultBrowser": False, "browser.startup.homepage_override.mstone": "ignore"}
        if args.lab_disable_socket_sandbox:
            prefs["security.sandbox.socket.process.level"] = 0
        (profile / "user.js").write_text("".join(f"user_pref({json.dumps(k)}, {json.dumps(v)});\n" for k, v in prefs.items()))
        os.chown(profile / "user.js", account.pw_uid, account.pw_gid)
        runtime = case / "runtime"
        runtime.mkdir()
        os.chown(runtime, account.pw_uid, account.pw_gid)
        launch(["tcpdump", "-i", "lo", "-s", "0", "-U", "-w", str(case / "traffic.pcap"), "tcp", "port", str(args.port)], "tcpdump.log")
        wait_for(lambda: "listening on" in (case / "tcpdump.log").read_text(), 10)
        server = launch([sys.executable, str(Path(__file__).resolve()), "--server", "--case", str(case), "--reference", str(private), "--port", str(args.port), "--tls-version", args.tls_version, "--scenario", args.scenario], "server.log")
        wait_for(lambda: (case / "server.ready").exists(), 10)
        browser_environment = ["HOME=/home/researcher", f"XDG_RUNTIME_DIR={runtime}"]
        if args.lab_disable_socket_sandbox:
            browser_environment.append("MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1")
        navigation_url = f"https://localhost:{args.port}/offline/{case.name}"
        browser_args = ["--headless", "--no-remote", "--profile", str(profile)]
        if args.lab_accept_insecure_certs:
            browser_args.extend(["--remote-debugging-port", str(args.port + 1), "about:blank"])
        else:
            browser_args.append(navigation_url)
        browser = launch(["runuser", "-u", "researcher", "--", "env", "-u", "SSLKEYLOGFILE", "-u", "MOZ_LOG", "-u", "MOZ_LOG_FILE", "-u", "DBUS_SESSION_BUS_ADDRESS",
                          *browser_environment, str(args.firefox), *browser_args], "firefox.log")
        if args.lab_accept_insecure_certs:
            from websockets.sync.client import connect
            def connect_bidi():
                try:
                    return connect(f"ws://127.0.0.1:{args.port + 1}/session", open_timeout=1, close_timeout=1)
                except (OSError, TimeoutError):
                    return None
            bidi = wait_for(connect_bidi, 30)
            def command(number, method, params):
                bidi.send(json.dumps({"id": number, "method": method, "params": params}))
                while True:
                    response = json.loads(bidi.recv(timeout=20))
                    if response.get("id") == number:
                        if "error" in response:
                            raise RuntimeError("BiDi " + response["error"] + ": " + response.get("message", ""))
                        return response["result"]
            command(1, "session.new", {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": True}}})
            tree = command(2, "browsingContext.getTree", {})
            context = tree["contexts"][0]["context"]
            command(3, "browsingContext.navigate", {"context": context, "url": navigation_url, "wait": "none"})
        if args.scenario == "concurrency":
            def first_phase_complete():
                if (case / "first-complete").exists():
                    return True
                if server.poll() is not None:
                    raise RuntimeError("Scenario server exited during its first phase")
                return False
            wait_for(first_phase_complete, 60)
            if args.scenario == "concurrency":
                context = command(4, "browsingContext.create", {"type": "tab"})["context"]
            command(5, "browsingContext.navigate", {"context": context, "url": navigation_url + "/second", "wait": "none"})
        def request_arrived():
            if (case / ("server-event.json" if args.scenario == "baseline" else "capture.ready")).exists():
                return True
            if server.poll() is not None or browser.poll() is not None:
                raise RuntimeError("Server or browser exited before the controlled request; inspect private logs")
            return False
        wait_for(request_arrived, 60)
        parent_pid, observed_socket_pid = wait_for(lambda: firefox_pids(profile), 20)
        connections = subprocess.check_output(["ss", "-tnp"], text=True)
        relevant = [line for line in connections.splitlines() if f":{args.port}" in line]
        (case / "connection-ownership.txt").write_text("\n".join(relevant) + "\n")
        owners = {int(pid) for line in relevant for pid in re.findall(r"pid=(\d+),", line)} & {parent_pid, observed_socket_pid}
        if len(owners) != 1:
            raise RuntimeError("Could not uniquely identify the Firefox connection owner")
        socket_pid = owners.pop()
        maps = Path(f"/proc/{socket_pid}/maps").read_text()
        environment = Path(f"/proc/{socket_pid}/environ").read_bytes().split(b"\0")
        if any(item.startswith(b"SSLKEYLOGFILE=") for item in environment) or "frida" in maps.lower():
            raise RuntimeError("Unexpected target key logging or Frida instrumentation")
        if "libssl3.so" not in maps or "libsoftokn3.so" not in maps:
            raise RuntimeError("Selected process does not have required NSS modules")
        (case / "captured-process.maps").write_text(maps)
        record.update({"firefox_pid": parent_pid, "observed_socket_process_pid": observed_socket_pid,
                       "captured_pid": socket_pid, "socket_ownership_verified": True,
                       "captured_argv": argv_for(socket_pid), "target_hashes": {name: sha256(args.firefox.parent / name) for name in ("firefox", "libssl3.so", "libsoftokn3.so")}})
        dump = case / "firefox.core"
        command = ["gdb", "-nx", "-nh", "-batch", "-iex", "set auto-load off", "-iex", "set debuginfod enabled off",
                   "-p", str(socket_pid), "-ex", "set use-coredump-filter off", "-ex", "set dump-excluded-mappings on",
                   "-ex", f"generate-core-file {dump}", "-ex", "detach", "-ex", "quit"]
        record["capture_command"] = command
        record["capture_started"] = utc()
        record["capture_started_monotonic"] = time.monotonic()
        capture = launch(command, "gdb-capture.log")
        capture.wait(timeout=120)
        if capture.returncode or not dump.exists():
            raise RuntimeError(f"GDB capture failed with status {capture.returncode}")
        record["capture_ended_monotonic"] = time.monotonic()
        record.update({"capture_ended": utc(), "dump_sha256": sha256(dump), "dump_bytes": dump.stat().st_size,
                       "status": "captured", "server_reference_read_by_acquirer": False})
        dump.chmod(0o400)
        os.chown(dump, account.pw_uid, account.pw_gid)
        (case / "release-server").touch()
        server.wait(timeout=10)
        if server.returncode: raise RuntimeError("Scenario server failed")
        write_json(case / "acquisition-seal.json", record)
        for evidence_name in ("acquisition-seal.json", "scenario-events.json"):
            evidence = case / evidence_name
            if evidence.exists():
                os.chown(evidence, account.pw_uid, account.pw_gid)
                evidence.chmod(0o444)
        print(json.dumps({k: record[k] for k in ("case_id", "status", "dump_bytes", "dump_sha256")}))
    except Exception as error:
        record.update({"status": "failed", "error": str(error)})
        write_json(case / "acquisition-failure.json", record)
        raise
    finally:
        (case / "release-server").touch()
        if bidi is not None:
            bidi.close()
        for process in reversed(processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except ProcessLookupError:
                    pass
        if socket_pid and Path(f"/proc/{socket_pid}").exists():
            try:
                os.kill(socket_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        for out in handles:
            out.close()
        pcap = case / "traffic.pcap"
        if pcap.exists():
            os.chown(pcap, account.pw_uid, account.pw_gid)
            pcap.chmod(0o400)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--firefox", type=Path, default=Path("/opt/tlskeyhunter/firefox-136.0.2-pristine/firefox"))
    parser.add_argument("--tls-version", choices=("1.2", "1.3"), default="1.2")
    parser.add_argument("--scenario", choices=("baseline", "before-response", "delayed", "resumption", "keyupdate", "concurrency"), default="baseline")
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--lab-disable-socket-sandbox", action="store_true", help="Explicitly authorized disposable-profile compatibility exception")
    parser.add_argument("--lab-accept-insecure-certs", action="store_true", help="Explicitly authorized localhost automation-session certificate exception")
    arguments = parser.parse_args()
    if arguments.server:
        os.umask(0o077)
        if arguments.scenario == "baseline":
            serve(arguments)
        else:
            from extended_server import serve as extended_serve
            extended_serve(arguments)
    else:
        main(arguments)
