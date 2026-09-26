#!/usr/bin/env python3
"""Freeze the controlled TLSKeyHunter experiment configuration and evidence hashes."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_id(path: Path) -> str | None:
    output = command(["readelf", "-n", str(path)])["output"]
    match = re.search(r"Build ID: ([0-9a-f]+)", str(output))
    return match.group(1) if match else None


def command(command: list[str], cwd: Path | None = None) -> dict[str, object]:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
    )
    return {"command": command, "exit_code": result.returncode, "output": result.stdout.strip()}


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def write_json(path: Path, value: object) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--certificate-dir", required=True, type=Path)
    parser.add_argument(
        "--firefox",
        type=Path,
        default=Path("/opt/tlskeyhunter/firefox-136.0.2-pristine/firefox"),
    )
    parser.add_argument("--reference-case", action="append", default=[])
    parser.add_argument("--static-analysis", action="append", default=[], type=Path)
    args = parser.parse_args()

    repo = args.repo.resolve()
    output_dir = args.output_dir.resolve()
    certificate_dir = args.certificate_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty freeze directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    git_status = command(["git", "status", "--short"], repo)
    if git_status["exit_code"] != 0 or git_status["output"]:
        raise RuntimeError(f"repository must be clean before freezing: {git_status}")

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    write_text(output_dir / "timestamp-utc.txt", timestamp + "\n")
    write_text(output_dir / "uname.txt", command(["uname", "-a"])["output"] + "\n")
    write_text(output_dir / "os-release.txt", Path("/etc/os-release").read_text())
    write_text(
        output_dir / "installed-packages.txt",
        command(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])["output"] + "\n",
    )

    version_commands = {
        "java": ["java", "-version"],
        "python": ["/home/researcher/.venv/bin/python", "--version"],
        "frida": ["/home/researcher/.venv/bin/frida", "--version"],
        "tshark": ["tshark", "--version"],
        "firefox": [str(args.firefox), "--version"],
        "node": ["node", "--version"],
        "openssl": ["openssl", "version"],
    }
    versions = {name: command(invocation) for name, invocation in version_commands.items()}
    prerequisite = command([str(repo / "ensure_prerequisites.sh"), "--print-analyze-headless"], repo)
    analyze_headless = Path(prerequisite["output"].splitlines()[-1]) if prerequisite["exit_code"] == 0 else None
    ghidra_home = analyze_headless.parent.parent if analyze_headless and analyze_headless.is_file() else None
    ghidra_properties = ghidra_home / "Ghidra/application.properties" if ghidra_home else None
    ghidra_version = None
    if ghidra_properties and ghidra_properties.is_file():
        match = re.search(r"^application\.version=(.+)$", ghidra_properties.read_text(), re.MULTILINE)
        ghidra_version = match.group(1) if match else None
    versions["ghidra"] = {
        "detected": bool(analyze_headless and analyze_headless.is_file()),
        "analyze_headless": str(analyze_headless) if analyze_headless else None,
        "analyze_headless_resolved": (
            str(analyze_headless.resolve()) if analyze_headless and analyze_headless.is_file() else None
        ),
        "headless_analyzer_executable": bool(
            analyze_headless and analyze_headless.is_file() and os.access(analyze_headless, os.X_OK)
        ),
        "status": (
            "ready"
            if analyze_headless and analyze_headless.is_file() and os.access(analyze_headless, os.X_OK)
            else "unavailable"
        ),
        "home": str(ghidra_home) if ghidra_home else None,
        "version": ghidra_version,
        "application_properties_sha256": (
            sha256(ghidra_properties) if ghidra_properties and ghidra_properties.is_file() else None
        ),
        "probe": prerequisite,
    }
    write_json(output_dir / "tool-versions.json", versions)

    git_record = {
        "commit": command(["git", "rev-parse", "HEAD"], repo)["output"],
        "branch": command(["git", "branch", "--show-current"], repo)["output"],
        "status": git_status["output"],
    }
    write_json(output_dir / "git.json", git_record)

    source_paths = [
        "ghidra_analysis.sh",
        "TLSKeyHunter.java",
        "tlsKeyExtraction/arg_ranker.js",
        "tlsKeyExtraction/openssl_key_dump_linux_x86_64.js",
        "tlsKeyExtraction/wolfssl_key_dump_linux_x86_64.js",
        "lab/baseline/run_wolfssl_baseline.py",
        "lab/baseline/tls_server.py",
        "lab/firefox/phase18a_firefox_nss_runner.py",
        "lab/firefox/nss_firefox_136.0.2.js",
        "lab/firefox/nss_firefox_136.0.2_tls12.js",
        "lab/firefox/firefox_nss_fingerprints.json",
        "lab/firefox/firefox_nss_tls12_fingerprints.json",
        "lab/firefox/run_campaign.py",
        "lab/firefox/run_negative_controls.py",
        "lab/firefox/create_static_provenance.py",
        "lab/arg_ranker/native_abi_harness.c",
        "lab/arg_ranker/run_native_abi_benchmark.py",
        "lab/live/live_workload.js",
        "lab/live/run_live_case.py",
        "lab/live/run_live_ad_study.py",
        "lab/live/build_wolfssl_no_keylog.sh",
    ]
    source_hashes = {
        relative: sha256(repo / relative)
        for relative in source_paths
        if (repo / relative).is_file()
    }
    write_json(output_dir / "source-hashes.json", source_hashes)

    firefox_root = args.firefox.parent
    binary_paths = {
        "firefox": args.firefox,
        "firefox-bin": firefox_root / "firefox-bin",
        "libssl3": firefox_root / "libssl3.so",
        "libnss3": firefox_root / "libnss3.so",
        "libsoftokn3": firefox_root / "libsoftokn3.so",
    }
    write_json(
        output_dir / "target-artifact-hashes.json",
        {
            name: {
                "path": str(path),
                "sha256": sha256(path),
                "build_id": build_id(path) if path.suffix == ".so" else None,
            }
            for name, path in binary_paths.items()
        },
    )

    certificate_paths = {
        "ca_certificate": certificate_dir / "ca.cert.pem",
        "server_certificate": certificate_dir / "server.cert.pem",
        "server_private_key": certificate_dir / "server.key.pem",
    }
    if not all(path.is_file() for path in certificate_paths.values()):
        raise RuntimeError("fixed certificate bundle is incomplete")
    certificate_record = {
        name: {"path": str(path), "sha256": sha256(path)}
        for name, path in certificate_paths.items()
    }
    certificate_record["ca_fingerprint"] = command(
        ["openssl", "x509", "-in", str(certificate_paths["ca_certificate"]), "-noout", "-fingerprint", "-sha256"]
    )
    certificate_record["server_fingerprint"] = command(
        ["openssl", "x509", "-in", str(certificate_paths["server_certificate"]), "-noout", "-fingerprint", "-sha256"]
    )
    write_json(output_dir / "certificate-fingerprints.json", certificate_record)

    write_json(
        output_dir / "scoring-policy.json",
        {
            "arg_ranker_source_sha256": source_hashes["tlsKeyExtraction/arg_ranker.js"],
            "minimum_scores": {
                "secret": 65,
                "label": 60,
                "client_random": 50,
                "integer": 50,
                "structure": 50,
            },
            "methods": {
                "A": "original per-hook hardcoded secret argument position",
                "D": "readability + expected length + entropy/zero-count + consistency",
            },
            "features": ["readability", "expected_length", "entropy", "zero_count", "consistency"],
            "preferred_index_scoring_for_D": False,
            "no_candidate_below_threshold": True,
            "native_abi_generation": {
                "positions": 12,
                "calls_per_position": 10,
                "methods": ["A", "D"],
                "expected_observations": 240,
                "deterministic_byte_formula": "(index*73 + seed*29 + 17) & 0xff",
            },
            "live_library_design": {
                "libraries": ["OpenSSL", "wolfSSL"],
                "protocols": ["TLS1.2", "TLS1.3"],
                "methods": ["A", "D"],
                "sessions_per_cell": 5,
                "expected_attempts": 40,
            },
        },
    )
    write_json(
        output_dir / "methodology.json",
        {
            "principal_protocol": "TLS1.2",
            "supporting_protocol": "TLS1.3",
            "browser_mode": "headless WebDriver BiDi over loopback",
            "measurement_mode": True,
            "target_sslkeylogfile_enabled": False,
            "reference_source": "isolated controlled TLS server",
            "acquisition_sequence": [
                "capture and target start",
                "unique static fingerprint validation",
                "Frida hook ready",
                "controlled handshake release",
                "candidate selection",
                "candidate file and metadata sealed",
                "server-reference exact comparison",
                "TShark authenticated decryption",
            ],
            "firefox_tls12_final_design": {"runs": 3, "sessions_per_run": 10, "attempts": 30},
            "required_tls13_labels": [
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0",
                "SERVER_TRAFFIC_SECRET_0",
            ],
            "acceptance": [
                "controlled browser workload event",
                "controlled server event",
                "complete TLS handshake",
                "Frida candidate event",
                "candidate ClientHello-random association",
                "sealed candidate exact server-reference equality",
                "authenticated TShark HTTP decryption",
                "exact request path recovery",
                "exact response marker and nonce recovery",
            ],
            "exclusion": [
                "fingerprint policy rejection",
                "pattern count other than one",
                "browser or Frida failure",
                "missing controlled server event",
                "incomplete handshake",
                "no candidate",
                "candidate validation failure",
            ],
        },
    )

    reference_evidence = {}
    for case_name in args.reference_case:
        case_dir = repo / "cases" / case_name
        manifest = case_dir / "evidence-manifest.sha256"
        verification = case_dir / "verification/verification.json"
        if not manifest.is_file():
            raise RuntimeError(f"reference case has no evidence manifest: {case_name}")
        manifest_check = command(["sha256sum", "-c", "--quiet", manifest.name], case_dir)
        reference_evidence[case_name] = {
            "manifest_sha256": sha256(manifest),
            "manifest_valid": manifest_check["exit_code"] == 0,
            "verification": json.loads(verification.read_text()) if verification.is_file() else None,
        }
    write_json(output_dir / "reference-evidence.json", reference_evidence)

    static_records = []
    for source in args.static_analysis:
        source = source.resolve()
        if not source.is_file():
            raise RuntimeError(f"static-analysis artifact is missing: {source}")
        destination = output_dir / "static-analysis" / source.name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(source, destination)
        destination.chmod(0o600)
        static_records.append({"file": destination.name, "sha256": sha256(destination)})
    write_json(output_dir / "static-analysis/index.json", static_records)

    manifest_lines = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path.name != "evidence-manifest.sha256":
            manifest_lines.append(f"{sha256(path)}  {path.relative_to(output_dir)}")
    write_text(output_dir / "evidence-manifest.sha256", "\n".join(manifest_lines) + "\n")
    for current, dirs, files in os.walk(output_dir):
        os.chmod(current, 0o700)
        for name in files:
            os.chmod(Path(current) / name, 0o600)
    print(json.dumps({"output_dir": str(output_dir), "git_commit": git_record["commit"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
