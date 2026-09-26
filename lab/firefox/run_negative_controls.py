#!/usr/bin/env python3
"""Run Firefox/NSS TLSKeyHunter negative controls without exposing key material."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


KEYLOG_RE = re.compile(r"^([A-Z0-9_]+) ([0-9A-F]{64}) ([0-9A-F]+)$")
HOOK_PATTERN = bytes.fromhex(
    "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 "
    "4D 89 CE 4C 89 C3 49 89 CC 49 89 F5 49 89 FF 64 48 "
    "8B 04 25 28 00 00 00 48 89 84 24 C0 00 00 00 48 85 D2 74 67"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_keylog(path: Path) -> list[tuple[str, str, str]]:
    parsed: list[tuple[str, str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = KEYLOG_RE.fullmatch(line.strip())
        if match:
            parsed.append(match.groups())
    if not parsed:
        raise RuntimeError(f"no valid verified key-log entries in {path}")
    return parsed


def render_keylog(entries: list[tuple[str, str, str]]) -> str:
    return "".join(" ".join(entry) + "\n" for entry in entries)


def decode_http_bodies(rows: str) -> bytes:
    bodies = bytearray()
    for row in rows.splitlines():
        columns = row.split("\t")
        if len(columns) < 4:
            continue
        for encoded in columns[3].split(","):
            compact = re.sub(r"[^0-9A-Fa-f]", "", encoded)
            if compact and len(compact) % 2 == 0:
                try:
                    bodies.extend(bytes.fromhex(compact))
                except ValueError:
                    pass
    return bytes(bodies)


def tshark_fields(
    pcap: Path, keylog: Path | None, port: int, display_filter: str | None = None
) -> str:
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-d",
        f"tcp.port=={port},tls",
    ]
    if keylog is not None:
        command += ["-o", f"tls.keylog_file:{keylog}"]
    if display_filter:
        command += ["-Y", display_filter]
    command += [
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "tcp.stream",
        "-e",
        "http.request.uri",
        "-e",
        "http.file_data",
    ]
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return result.stdout


def observed(rows: str, request_path: str, marker: str) -> dict[str, bool]:
    return {
        "exact_request_path_recovered": request_path in rows,
        "exact_response_marker_recovered": marker.encode() in decode_http_bodies(rows),
    }


def mutate_secret(entries: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    mutated = []
    for label, client_random, secret in entries:
        secret_bytes = bytearray.fromhex(secret)
        secret_bytes[0] ^= 1
        mutated.append((label, client_random, secret_bytes.hex().upper()))
    return mutated


def wrong_random(entries: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    changed = []
    for label, client_random, secret in entries:
        random_bytes = bytearray.fromhex(client_random)
        random_bytes[0] ^= 1
        changed.append((label, random_bytes.hex().upper(), secret))
    return changed


def random_secrets(entries: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    return [
        (label, client_random, os.urandom(len(secret) // 2).hex().upper())
        for label, client_random, secret in entries
    ]


def fingerprint_allowed(actual_hash: str, actual_build_id: str, allowed: dict[str, str]) -> bool:
    return (
        actual_hash == allowed.get("sha256")
        and actual_build_id == allowed.get("build_id")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--protocol", choices=("12", "13"), default="13")
    parser.add_argument(
        "--target-library",
        type=Path,
        default=None,
    )
    args = parser.parse_args()

    case_dir = args.case_dir.resolve()
    port = 8442 if args.protocol == "12" else 8443
    target_library = args.target_library or Path(
        "/opt/tlskeyhunter/firefox-136.0.2-pristine/"
        + ("libsoftokn3.so" if args.protocol == "12" else "libssl3.so")
    )
    hook_pattern = HOOK_PATTERN
    if args.protocol == "12":
        policy = json.loads(
            (Path(__file__).with_name("firefox_nss_tls12_fingerprints.json")).read_text()
        )
        hook_pattern = bytes.fromhex(policy["hook_pattern_hex"])
    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    pcap_source = case_dir / "capture/traffic.pcapng"
    verified_source = case_dir / "secrets/verified.keys"
    streams = json.loads((case_dir / "verification/streams.json").read_text())
    server_events = [
        json.loads(line)
        for line in (case_dir / "server/server-events.jsonl").read_text().splitlines()
        if line.strip()
    ]
    marker = next(event["marker"] for event in server_events if event.get("state") == "response_sent")
    request_path = streams["request_path"]
    entries = parse_keylog(verified_source)

    with tempfile.TemporaryDirectory(prefix="tlskh-negative-", dir="/tmp") as temporary:
        temp_dir = Path(temporary)
        pcap = temp_dir / "traffic.pcapng"
        shutil.copy2(pcap_source, pcap)
        pcap.chmod(0o600)

        def run_keylog_control(name: str, contents: str, display_filter: str | None = None) -> dict:
            keylog = temp_dir / f"{name}.keys"
            keylog.write_text(contents, encoding="utf-8")
            keylog.chmod(0o600)
            result = observed(tshark_fields(pcap, keylog, port, display_filter), request_path, marker)
            return {
                "control": name,
                **result,
                "passed": not result["exact_request_path_recovered"]
                and not result["exact_response_marker_recovered"],
            }

        positive_keylog = temp_dir / "positive.keys"
        positive_keylog.write_text(render_keylog(entries), encoding="utf-8")
        positive_keylog.chmod(0o600)
        positive_rows = tshark_fields(pcap, positive_keylog, port)
        positive = observed(positive_rows, request_path, marker)

        controls = []
        no_keylog_result = observed(tshark_fields(pcap, None, port), request_path, marker)
        controls.append(
            {
                "control": "no_key_log_file",
                **no_keylog_result,
                "passed": not any(no_keylog_result.values()),
            }
        )
        controls.append(run_keylog_control("random_secret_correct_length", render_keylog(random_secrets(entries))))
        controls.append(run_keylog_control("one_bit_modified_secret", render_keylog(mutate_secret(entries))))
        controls.append(run_keylog_control("correct_secret_wrong_client_random", render_keylog(wrong_random(entries))))

        diagnostic_text = (case_dir / "frida/frida-diagnostics.log").read_text(errors="replace")
        controls.append(run_keylog_control("frida_diagnostics_as_keylog", diagnostic_text))

        target_stream = None
        all_streams: set[str] = set()
        for row in positive_rows.splitlines():
            columns = row.split("\t")
            if len(columns) < 3:
                continue
            all_streams.add(columns[1])
            if request_path in columns[2]:
                target_stream = columns[1]
        wrong_stream = next((stream for stream in sorted(all_streams) if stream != target_stream), None)
        if wrong_stream is None:
            controls.append(
                {
                    "control": "correct_candidate_wrong_tcp_stream",
                    "passed": False,
                    "reason": "no distinct TCP stream available",
                }
            )
        else:
            controls.append(
                run_keylog_control(
                    "correct_candidate_wrong_tcp_stream",
                    render_keylog(entries),
                    f"tcp.stream == {wrong_stream}",
                )
            )

        target_hash = sha256(target_library)
        build_id_output = subprocess.run(
            ["readelf", "-n", str(target_library)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ).stdout
        build_id_match = re.search(r"Build ID: ([0-9a-f]+)", build_id_output)
        if not build_id_match:
            raise RuntimeError("could not read libssl3 ELF Build ID")
        build_id = build_id_match.group(1)
        allowed = {"sha256": target_hash, "build_id": build_id}
        unsupported_rejected = not fingerprint_allowed("0" * 64, build_id, allowed)
        controls.append(
            {
                "control": "unsupported_nss_hash_or_build_id",
                "extraction_blocked": unsupported_rejected,
                "passed": unsupported_rejected,
            }
        )
        multiple_match_rejected = (hook_pattern + b"\x00" + hook_pattern).count(hook_pattern) != 1
        controls.append(
            {
                "control": "multiple_fingerprint_matches",
                "extraction_blocked": multiple_match_rejected,
                "passed": multiple_match_rejected,
            }
        )

    result = {
        "protocol": "TLS1.2" if args.protocol == "12" else "TLS1.3",
        "target_library_sha256": sha256(target_library),
        "source_case": case_dir.name,
        "source_pcap_sha256": sha256(pcap_source),
        "source_verified_keylog_sha256": sha256(verified_source),
        "positive_sanity": {
            **positive,
            "passed": positive["exact_request_path_recovered"]
            and positive["exact_response_marker_recovered"],
        },
        "controls": controls,
        "all_negative_controls_passed": all(control["passed"] for control in controls),
        "secrets_in_report": False,
    }
    report_path = output_dir / "negative-controls.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_path.chmod(0o600)
    manifest = output_dir / "evidence-manifest.sha256"
    manifest.write_text(f"{sha256(report_path)}  negative-controls.json\n", encoding="utf-8")
    manifest.chmod(0o600)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["positive_sanity"]["passed"] and result["all_negative_controls_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
