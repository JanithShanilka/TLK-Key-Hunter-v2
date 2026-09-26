#!/usr/bin/env python3
"""Single-session controlled TLS server for TLSKeyHunter baseline evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=("12", "13"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument(
        "--keylog",
        type=Path,
        help=(
            "private server-side reference output; the instrumented client must "
            "not receive this path"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    protocol_label = f"TLS1.{args.protocol[-1]}"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    if args.keylog is not None:
        args.keylog.parent.mkdir(parents=True, exist_ok=True)
        context.keylog_filename = str(args.keylog)
    if args.protocol == "12":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.port))
        listener.listen(1)
        args.ready.write_text(utc_now() + "\n", encoding="utf-8")

        raw_connection, address = listener.accept()
        with raw_connection:
            with context.wrap_socket(raw_connection, server_side=True) as connection:
                connection.settimeout(5)
                request = bytearray()
                while b"\r\n\r\n" not in request and len(request) < 65536:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    request.extend(chunk)

                first_line = bytes(request).split(b"\r\n", 1)[0].decode(
                    "ascii", errors="replace"
                )
                parts = first_line.split(" ")
                request_path = parts[1] if len(parts) >= 2 else ""
                request_id = next(
                    (
                        segment
                        for segment in request_path.replace("?", "/").split("/")
                        if segment.startswith("REQUEST-")
                    ),
                    "REQUEST-UNKNOWN",
                )
                marker = (
                    f"TLSKH|{args.case_id}|RUN-01|{protocol_label}|"
                    f"{request_id}|VERIFIED-RESPONSE"
                )
                body = marker.encode("utf-8")
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                connection.sendall(response)

                event = {
                    "timestamp": utc_now(),
                    "case_id": args.case_id,
                    "run_id": "RUN-01",
                    "request_id": request_id,
                    "source_address": address[0],
                    "source_port": address[1],
                    "tls_version": connection.version(),
                    "cipher_suite": connection.cipher()[0],
                    "request_path": request_path,
                    "response_marker": marker,
                    "response_marker_sha256": hashlib.sha256(body).hexdigest(),
                    "response_status": 200,
                    "response_bytes": len(response),
                }
                args.events.write_text(
                    json.dumps(event, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
