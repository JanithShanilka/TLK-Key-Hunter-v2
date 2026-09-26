#!/usr/bin/env python3
"""Create a fixed localhost CA/leaf certificate bundle for frozen lab runs."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--days", default=365, type=int)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty certificate directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    ca_key = output_dir / "ca.key.pem"
    ca_cert = output_dir / "ca.cert.pem"
    server_key = output_dir / "server.key.pem"
    server_csr = output_dir / "server.csr.pem"
    server_cert = output_dir / "server.cert.pem"
    server_ext = output_dir / "server.ext.cnf"

    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            str(args.days),
            "-nodes",
            "-subj",
            "/CN=TLSKeyHunter Frozen Lab CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
        ]
    )
    run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(server_key),
            "-out",
            str(server_csr),
        ]
    )
    server_ext.write_text(
        "[server_cert]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        encoding="utf-8",
    )
    run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(server_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            str(args.days),
            "-sha256",
            "-extfile",
            str(server_ext),
            "-extensions",
            "server_cert",
            "-out",
            str(server_cert),
        ]
    )
    for path in output_dir.iterdir():
        path.chmod(0o600)
    output_dir.chmod(0o700)
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
