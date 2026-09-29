#!/usr/bin/env python3
"""Private controlled WSS server; never shares references with recovery."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import threading
import time


def read_exact(connection, count):
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise EOFError("WebSocket closed before expected messages")
        data.extend(part)
    return bytes(data)


def read_frame(connection):
    first, second = read_exact(connection, 2)
    if first & 0x0f not in (1, 2) or not second & 0x80:
        raise ValueError("Expected masked client text or binary frame")
    count = second & 0x7f
    if count == 126:
        count = int.from_bytes(read_exact(connection, 2), "big")
    elif count == 127:
        count = int.from_bytes(read_exact(connection, 8), "big")
    if count > 65536:
        raise ValueError("Frame exceeds study limit")
    mask = read_exact(connection, 4)
    payload = read_exact(connection, count)
    return bytes(value ^ mask[index % 4] for index, value in enumerate(payload))


def send_frame(connection, payload, opcode=2):
    if len(payload) < 126:
        header = bytes((0x80 | opcode, len(payload)))
    else:
        header = bytes((0x80 | opcode, 126)) + len(payload).to_bytes(2, "big")
    connection.sendall(header + payload)


def serve(case, private, port, count):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0
    context.set_ciphersuites("TLS_AES_256_GCM_SHA384") if hasattr(context, "set_ciphersuites") else None
    context.load_cert_chain(private / "server.cert.pem", private / "server.key.pem")
    context.keylog_filename = str(private / "server-reference.keys")
    lock = threading.Lock()
    flows = []
    failures = []
    complete = threading.Event()
    release = threading.Event()

    def worker(raw, address, number):
        try:
            with context.wrap_socket(raw, server_side=True) as conn:
                conn.settimeout(60)
                if conn.cipher()[0] != "TLS_AES_256_GCM_SHA384":
                    raise ValueError("Negotiated suite differs from pinned study")
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    request.extend(conn.recv(4096))
                    if len(request) > 16384:
                        raise ValueError("WebSocket request too large")
                lines = bytes(request).split(b"\r\n")
                key = next(line.split(b":", 1)[1].strip() for line in lines if line.lower().startswith(b"sec-websocket-key:"))
                accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                incoming, outgoing = [], []
                for _ in range(2):
                    payload = read_frame(conn)
                    incoming.append({"length": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
                    answer = secrets.token_bytes(128 + secrets.randbelow(384))
                    send_frame(conn, answer)
                    outgoing.append({"length": len(answer), "sha256": hashlib.sha256(answer).hexdigest()})
                with lock:
                    flows.append({"index": number, "peer_port": address[1], "server_port": port,
                                  "protocol": conn.version(), "cipher": conn.cipher()[0],
                                  "client_messages": incoming, "server_messages": outgoing})
                    if len(flows) == count:
                        (case / "capture.ready").touch()
                        complete.set()
                release.wait(180)
                send_frame(conn, b"", opcode=8)
        except Exception as error:
            with lock:
                failures.append({"index": number, "error": str(error)})
                (case / "server.failure.json").write_text(json.dumps(failures) + "\n")
                complete.set()

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(8)
        listener.settimeout(60)
        (case / "server.ready").touch()
        threads = []
        try:
            for number in range(count):
                raw, address = listener.accept()
                thread = threading.Thread(target=worker, args=(raw, address, number))
                thread.start()
                threads.append(thread)
            complete.wait(90)
            if failures or len(flows) != count:
                raise RuntimeError("Controlled WebSocket exchange failed")
            while not (case / "release-server").exists():
                time.sleep(0.1)
        finally:
            release.set()
            for thread in threads:
                thread.join(timeout=5)
            (private / "workload-reference.json").write_text(json.dumps({"flows": sorted(flows, key=lambda row: row["index"]),
                "failures": failures}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--connections", type=int, choices=(2, 3), required=True)
    args = parser.parse_args()
    os.umask(0o077)
    serve(args.case, args.reference, args.port, args.connections)


if __name__ == "__main__":
    main()
