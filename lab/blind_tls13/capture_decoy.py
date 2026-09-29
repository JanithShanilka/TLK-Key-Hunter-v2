#!/usr/bin/env python3
"""Capture independent WSS traffic for an unrelated-traffic control."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import signal
import shutil
import ssl
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "offline_memory"))
from capture_firefox import sha256, wait_for
from tls13_packets import directional_records, inspect_connections


def read_exact(connection, count):
    result = bytearray()
    while len(result) < count:
        part = connection.recv(count - len(result))
        if not part:
            raise EOFError("Unrelated WebSocket closed")
        result.extend(part)
    return bytes(result)


def send_masked(connection, payload):
    mask = secrets.token_bytes(4)
    count = len(payload)
    header = bytes((0x82, 0x80 | count)) if count < 126 else bytes((0x82, 0xfe)) + count.to_bytes(2, "big")
    connection.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))


def receive_frame(connection):
    _, second = read_exact(connection, 2)
    if second & 0x80:
        raise ValueError("Server WebSocket frame was masked")
    count = second & 0x7f
    if count == 126:
        count = int.from_bytes(read_exact(connection, 2), "big")
    elif count == 127:
        count = int.from_bytes(read_exact(connection, 8), "big")
    return read_exact(connection, count)


def capture(case, private, port, count):
    if os.geteuid() != 0:
        raise RuntimeError("Controlled capture requires root")
    os.umask(0o077)
    case.mkdir(parents=True, exist_ok=False)
    private.mkdir(parents=True, exist_ok=False)
    # A distinct reference file is produced for these independent connections.
    source = private.parent / private.name.removesuffix("-decoy")
    for name in ("server.cert.pem", "server.key.pem"):
        shutil.copyfile(source / name, private / name)
    pcap = case / "traffic.pcap"
    tcp_log = (case / "tcpdump.log").open("w")
    server_log = (case / "server.log").open("w")
    tcpdump = subprocess.Popen(["tcpdump", "-i", "lo", "-s", "0", "-U", "-w", str(pcap),
                                "tcp", "port", str(port)], stdout=tcp_log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    server = None
    try:
        wait_for(lambda: "listening on" in (case / "tcpdump.log").read_text(), 10)
        server = subprocess.Popen([sys.executable, str(Path(__file__).with_name("blind_server.py")),
                                   "--case", str(case), "--reference", str(private),
                                   "--port", str(port), "--connections", str(count)],
                                  stdout=server_log, stderr=subprocess.STDOUT, start_new_session=True)
        wait_for(lambda: (case / "server.ready").exists(), 10)
        context = ssl._create_unverified_context()
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        connections = []
        for _ in range(count):
            raw = __import__("socket").create_connection(("127.0.0.1", port), timeout=30)
            conn = context.wrap_socket(raw, server_hostname="localhost")
            key = base64.b64encode(secrets.token_bytes(16))
            conn.sendall(b"GET /channel/" + secrets.token_hex(8).encode() + b" HTTP/1.1\r\n"
                         b"Host: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + b"\r\n\r\n")
            response = bytearray()
            while b"\r\n\r\n" not in response:
                response.extend(conn.recv(4096))
            if b"101 Switching Protocols" not in response:
                raise RuntimeError("Unrelated WebSocket upgrade failed")
            connections.append(conn)
        for conn in connections:
            for _ in range(2):
                send_masked(conn, secrets.token_bytes(128 + secrets.randbelow(384)))
                receive_frame(conn)
        wait_for(lambda: (case / "capture.ready").exists(), 30)
        (case / "release-server").touch()
        server.wait(timeout=10)
        for conn in connections:
            conn.close()
        # The unrelated workload is short. Give tcpdump time to drain the
        # kernel capture buffer before terminating it, then verify the PCAP.
        wait_for(lambda: pcap.stat().st_size > 24, 10)
        time.sleep(1)
        os.killpg(tcpdump.pid, signal.SIGTERM)
        tcpdump.wait(timeout=10)
        observed = inspect_connections(pcap)
        if len(observed) != count:
            raise RuntimeError(f"Unrelated PCAP has {len(observed)} of {count} completed handshakes")
        for flow in observed:
            records = directional_records(pcap, flow["stream"], flow["server_port"])
            if any(len(records[direction]) < 4 for direction in ("client", "server")):
                raise RuntimeError("Unrelated PCAP lacks complete bidirectional TLS records")
        result = {"pcap_sha256": sha256(pcap), "connections": count, "independent_client": True}
        (case / "acquisition.json").write_text(json.dumps(result, indent=2) + "\n")
        case.chmod(0o700)
        return result
    finally:
        (case / "release-server").touch()
        for process in (server, tcpdump):
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
        tcp_log.close()
        server_log.close()
        case.chmod(0o700)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--connections", type=int, choices=(2, 3), required=True)
    args = parser.parse_args()
    print(json.dumps(capture(args.case, args.reference, args.port, args.connections)))


if __name__ == "__main__":
    main()
