#!/usr/bin/env python3
"""Acquire one complete controlled Firefox core and WSS PCAP."""

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "offline_memory"))
from capture_firefox import argv_for, firefox_pids, sha256, utc, wait_for, write_json


PINNED_HASHES = {
    "firefox": "385265da8818d293afd50ce410b678e3cf2079bb4e2d60231dfb818cd12b8b55",
    "libssl3.so": "41b76c48fff44d62e34b463e52d1a4842f1b8c39711e6e1ac77ae6dbc3906f57",
    "libsoftokn3.so": "064c24743abe22bc8c9b87c6f8c4d7e8facc66d94a73b7ed9702e1d2733d2fe7",
}


def capture(args):
    if os.geteuid() != 0:
        raise RuntimeError("Controlled acquisition requires root")
    os.umask(0o077)
    case, private = args.case.resolve(), args.reference.resolve()
    case.mkdir(parents=True, exist_ok=False)
    private.mkdir(parents=True, exist_ok=False)
    researcher = pwd.getpwnam("researcher")
    case.chmod(0o711)  # Firefox needs to traverse to its disposable profile.
    profile = case / "profile"
    profile.mkdir()
    os.chown(profile, researcher.pw_uid, researcher.pw_gid)
    processes, handles = [], []
    bidi = None
    socket_pid = None
    evidence = {"case_id": case.name, "started_utc": utc(), "status": "started",
                "firefox_version": "136.0.2", "architecture": "linux-x86_64",
                "cipher_suite": "0x1302", "connections_requested": args.connections,
                "target_key_logging": False, "frida_loaded": False,
                "socket_sandbox_exception": args.lab_disable_socket_sandbox,
                "accept_insecure_certs": args.lab_accept_insecure_certs}

    def run(command, name):
        with (case / name).open("w") as out:
            subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, check=True, timeout=30)

    def launch(command, name):
        out = (case / name).open("w")
        handles.append(out)
        process = subprocess.Popen(command, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        return process

    try:
        actual_hashes = {name: sha256(args.firefox.parent / name) for name in PINNED_HASHES}
        if actual_hashes != PINNED_HASHES:
            raise RuntimeError("Pinned Firefox/NSS target hash mismatch")
        evidence["target_hashes"] = actual_hashes
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=Blind Study CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(private / "ca.key.pem"), "-out", str(private / "ca.cert.pem")], "ca-generation.log")
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", str(private / "server.key.pem"), "-out", str(private / "server.csr.pem")], "server-csr.log")
        (private / "server.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        run(["openssl", "x509", "-req", "-in", str(private / "server.csr.pem"), "-CA", str(private / "ca.cert.pem"),
             "-CAkey", str(private / "ca.key.pem"), "-CAcreateserial", "-days", "2", "-sha256",
             "-extfile", str(private / "server.ext"), "-out", str(private / "server.cert.pem")], "certificate-generation.log")
        cert = profile / "ca.cert.pem"
        shutil.copyfile(private / "ca.cert.pem", cert)
        os.chown(cert, researcher.pw_uid, researcher.pw_gid)
        run(["runuser", "-u", "researcher", "--", "certutil", "-N", "--empty-password", "-d", f"sql:{profile}"], "profile-init.log")
        run(["runuser", "-u", "researcher", "--", "certutil", "-A", "-n", "Blind localhost CA", "-t", "CT,,",
             "-i", str(cert), "-d", f"sql:{profile}"], "profile-trust.log")
        prefs = {"security.tls.version.min": 4, "security.tls.version.max": 4,
                 "security.tls.enable_0rtt_data": False, "network.http.http3.enable": False,
                 "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
                 "network.dns.disablePrefetch": True, "network.prefetch-next": False,
                 "datareporting.healthreport.uploadEnabled": False, "toolkit.telemetry.enabled": False,
                 "browser.shell.checkDefaultBrowser": False}
        if args.lab_disable_socket_sandbox:
            prefs["security.sandbox.socket.process.level"] = 0
        (profile / "user.js").write_text("".join(f"user_pref({json.dumps(k)}, {json.dumps(v)});\n" for k, v in prefs.items()))
        os.chown(profile / "user.js", researcher.pw_uid, researcher.pw_gid)
        runtime = case / "runtime"
        runtime.mkdir()
        os.chown(runtime, researcher.pw_uid, researcher.pw_gid)
        pcap = case / "traffic.pcap"
        tcpdump = launch(["tcpdump", "-i", "lo", "-s", "0", "-U", "-w", str(pcap), "tcp", "port", str(args.port)], "tcpdump.log")
        wait_for(lambda: "listening on" in (case / "tcpdump.log").read_text(), 10)
        server = launch([sys.executable, str(Path(__file__).with_name("blind_server.py")), "--case", str(case),
                         "--reference", str(private), "--port", str(args.port),
                         "--connections", str(args.connections)], "server.log")
        wait_for(lambda: (case / "server.ready").exists(), 10)
        browser_environment = ["HOME=/home/researcher", f"XDG_RUNTIME_DIR={runtime}"]
        if args.lab_disable_socket_sandbox:
            browser_environment.append("MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1")
        browser = launch(["runuser", "-u", "researcher", "--", "env", "-u", "SSLKEYLOGFILE", "-u", "MOZ_LOG",
                          "-u", "MOZ_LOG_FILE", "-u", "DBUS_SESSION_BUS_ADDRESS", *browser_environment,
                          str(args.firefox), "--headless", "--no-remote", "--profile", str(profile),
                          "--remote-debugging-port", str(args.port + 1), "about:blank"], "firefox.log")
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
        command(1, "session.new", {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": args.lab_accept_insecure_certs}}})
        context = command(2, "browsingContext.getTree", {})["contexts"][0]["context"]
        expression = """(() => {
          window.studySockets = [];
          window.studyErrors = [];
          for (let i = 0; i < COUNT; i++) {
            const ws = new WebSocket('wss://localhost:PORT/channel/' + i + '-' + Date.now());
            ws.binaryType = 'arraybuffer';
            let received = 0;
            const send = () => { try { const data = new Uint8Array(128 + Math.floor(Math.random() * 384));
              crypto.getRandomValues(data); ws.send(data); }
              catch (error) { window.studyErrors.push({index: i, error: String(error)}); } };
            ws.onopen = send;
            ws.onmessage = () => { received++; if (received < 2) send(); };
            ws.onerror = () => window.studyErrors.push({index: i, state: ws.readyState});
            window.studySockets.push(ws);
          }
          return window.studySockets.length;
        })()""".replace("COUNT", str(args.connections)).replace("PORT", str(args.port))
        launch_result = command(3, "script.evaluate", {"expression": expression,
                                                       "target": {"context": context}, "awaitPromise": False})
        write_json(case / "bidi-launch.json", launch_result)
        if launch_result.get("type") != "success" or launch_result.get("result", {}).get("value") != args.connections:
            raise RuntimeError("WebDriver BiDi did not start the requested WebSocket workload")
        def exchange_complete():
            if (case / "server.failure.json").exists():
                raise RuntimeError("Controlled server failed; inspect private log")
            if server.poll() is not None or browser.poll() is not None:
                raise RuntimeError("Server or Firefox exited before exchange")
            return (case / "capture.ready").exists()
        try:
            wait_for(exchange_complete, 90)
        except Exception:
            try:
                diagnostic = command(4, "script.evaluate", {"expression": "({errors:window.studyErrors,states:window.studySockets.map(s=>s.readyState)})",
                                                            "target": {"context": context}, "awaitPromise": False})
                write_json(case / "bidi-diagnostic.json", diagnostic)
            except Exception as diagnostic_error:
                write_json(case / "bidi-diagnostic-failure.json", {"error": str(diagnostic_error)})
            raise
        parent_pid, socket_pid_observed = wait_for(lambda: firefox_pids(profile), 20)
        connections = subprocess.check_output(["ss", "-tnp"], text=True)
        relevant = [line for line in connections.splitlines() if f":{args.port}" in line]
        owners = {int(pid) for line in relevant for pid in re.findall(r"pid=(\d+),", line)} & {parent_pid, socket_pid_observed}
        if len(owners) != 1:
            raise RuntimeError("Could not uniquely identify Firefox socket owner")
        socket_pid = owners.pop()
        maps = Path(f"/proc/{socket_pid}/maps").read_text()
        environment = Path(f"/proc/{socket_pid}/environ").read_bytes().split(b"\0")
        if any(item.startswith(b"SSLKEYLOGFILE=") for item in environment) or "frida" in maps.lower():
            raise RuntimeError("Target had unexpected key logging or instrumentation")
        if "libssl3.so" not in maps or "libsoftokn3.so" not in maps:
            raise RuntimeError("Selected process lacks pinned NSS modules")
        evidence.update({"captured_pid": socket_pid, "firefox_pid": parent_pid,
                         "socket_ownership_verified": True, "captured_argv": argv_for(socket_pid)})
        core = case / "firefox.core"
        gdb = ["gdb", "-nx", "-nh", "-batch", "-iex", "set auto-load off", "-iex", "set debuginfod enabled off",
               "-p", str(socket_pid), "-ex", "set use-coredump-filter off", "-ex", "set dump-excluded-mappings on",
               "-ex", f"generate-core-file {core}", "-ex", "detach", "-ex", "quit"]
        evidence["capture_started_utc"] = utc()
        process = launch(gdb, "gdb-capture.log")
        process.wait(timeout=120)
        if process.returncode or not core.exists():
            raise RuntimeError("GDB core capture failed")
        evidence["capture_ended_utc"] = utc()
        core.chmod(0o444)
        (case / "release-server").touch()
        server.wait(timeout=15)
        if server.returncode:
            raise RuntimeError("Controlled server failed after capture")
        bidi.close()
        bidi = None
        if browser.poll() is None:
            os.killpg(browser.pid, signal.SIGTERM)
            browser.wait(timeout=10)
        if tcpdump.poll() is None:
            os.killpg(tcpdump.pid, signal.SIGTERM)
            tcpdump.wait(timeout=10)
        evidence.update({"status": "captured", "core_sha256": sha256(core), "pcap_sha256": sha256(pcap),
                         "core_allocated_bytes": core.stat().st_blocks * 512})
        write_json(case / "acquisition.json", evidence)
        case.chmod(0o700)
        return evidence
    except Exception as error:
        evidence.update(status="failed", error=str(error))
        write_json(case / "acquisition-failure.json", evidence)
        raise
    finally:
        (case / "release-server").touch()
        if bidi is not None:
            bidi.close()
        if socket_pid is not None and Path(f"/proc/{socket_pid}").exists():
            try:
                os.kill(socket_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        for process in reversed(processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    os.killpg(process.pid, signal.SIGKILL)
        for stream in handles:
            stream.close()
        case.chmod(0o700)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--connections", type=int, choices=(2, 3), required=True)
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--firefox", type=Path, default=Path("/opt/tlskeyhunter/firefox-136.0.2-pristine/firefox"))
    parser.add_argument("--lab-disable-socket-sandbox", action="store_true")
    parser.add_argument("--lab-accept-insecure-certs", action="store_true")
    args = parser.parse_args()
    print(json.dumps(capture(args)))


if __name__ == "__main__":
    main()
