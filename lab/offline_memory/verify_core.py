#!/usr/bin/env python3
"""Post-selection verifier. Reference-guided presence is NOT extraction success."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile

from core_memory import CoreMemory
from rank_core import digest


def verify(case, reference, scratch, offline_name="offline", report_name="verification"):
    output = case / report_name
    output.mkdir(exist_ok=False)
    seal = json.loads((case / offline_name / "selection-seal.json").read_text())
    private = case / offline_name / "ranked-candidates.private.json"
    if digest(private) != seal["candidate_file_sha256"] or digest(case / "firefox.core") != seal["core_sha256"]:
        raise RuntimeError("Sealed evidence hash mismatch")
    rows = json.loads(private.read_text())
    lines = [line.split() for line in reference.read_text().splitlines() if line.startswith("CLIENT_RANDOM ")]
    if len(lines) != 1 or len(lines[0]) != 3 or len(bytes.fromhex(lines[0][2])) != 48:
        raise RuntimeError("Expected exactly one valid TLS 1.2 reference")
    label, random_value, secret_hex = lines[0]
    secret = bytes.fromhex(secret_hex)
    identity = hashlib.sha256(secret).hexdigest()
    event = json.loads((case / "server-event.json").read_text())
    if event["protocol"] != "TLSv1.2":
        raise RuntimeError("Server did not negotiate TLS 1.2")
    # TShark denied the private case path in this lab; the confinement cause
    # is unresolved. A private temporary copy of the small PCAP works.
    scratch_capture = scratch / "traffic.pcap"
    shutil.copyfile(case / "traffic.pcap", scratch_capture)
    tshark_base = ["tshark", "-r", str(scratch_capture)]
    client_randoms = subprocess.check_output(tshark_base + ["-Y", "tls.handshake.type == 1", "-T", "fields", "-e", "tls.handshake.random"], text=True, stderr=subprocess.DEVNULL).split()
    if {value.lower() for value in client_randoms} != {random_value.lower()}:
        raise RuntimeError("PCAP does not uniquely match reference connection")
    with CoreMemory(case / "firefox.core") as core:
        locations = list(core.find(secret))
    match = next((row for row in rows if row["id"] == identity and bytes.fromhex(row["hex"]) == secret), None)
    selected = next((row for row in rows if row["id"] == seal["selected_id"]), None)
    exact = bool(selected and bytes.fromhex(selected["hex"]) == secret)

    def decrypt(keyfile, name):
        scratch_key = scratch / (name + ".keys")
        shutil.copyfile(keyfile, scratch_key)
        result = subprocess.run(tshark_base + ["-o", f"tls.keylog_file:{scratch_key}", "-Y", "http", "-V"], capture_output=True, text=True, timeout=30)
        (output / (name + ".private.txt")).write_text(result.stdout + "\n" + result.stderr)
        content = result.stdout
        def contains(value):
            return value in content or value.encode().hex() in content.lower().replace(":", "")
        return {"tshark_exit": result.returncode, "request": contains(event["request_path"]),
                "response": contains(event["response_marker"])}

    positive = decrypt(reference, "reference-sanity")
    selected_decryption = None
    if selected:
        keyfile = output / "selected.private.keys"
        keyfile.write_text(f"{label} {random_value} {selected['hex']}\n")
        selected_decryption = decrypt(keyfile, "selected-decryption")
    corrupted = bytearray(secret)
    corrupted[0] ^= 1
    wrong = output / "one-bit-control.private.keys"
    wrong.write_text(f"{label} {random_value} {corrupted.hex()}\n")
    negative = decrypt(wrong, "one-bit-control")
    report = {"case_id": case.name, "kind": "exploratory_single_case",
              "reference_comparison_after_selection_seal": True,
              "selection_method": seal["method"],
              "selection_uses_pcap": seal.get("selection_uses_pcap", False),
              "core_sha256": seal["core_sha256"], "pcap_sha256": digest(case / "traffic.pcap"),
              "reference_literal_present_in_captured_segments": bool(locations),
              "reference_literal_occurrences": len(locations),
              "presence_audit_uses_reference": True,
              "candidate_count": len(rows), "reference_in_candidate_set": match is not None,
              "reference_score": match["score"] if match else None,
              "candidates_strictly_above_reference": sum(row["score"] > match["score"] for row in rows) if match else None,
              "candidates_tied_with_reference": sum(row["score"] == match["score"] for row in rows) if match else None,
              "selection_status": seal["status"], "selected_exact_match": exact,
              "selected_hamming_distance_bits": sum((a ^ b).bit_count() for a, b in zip(bytes.fromhex(selected["hex"]), secret)) if selected else None,
              "selected_decryption": selected_decryption,
              "reference_only_decryption_sanity": positive,
              "one_bit_reference_control": negative,
              "complete_offline_recovery": bool(exact and selected_decryption and selected_decryption["tshark_exit"] == 0 and selected_decryption["request"] and selected_decryption["response"])}
    (output / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--offline-name", default="offline")
    parser.add_argument("--report-name", default="verification")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="tlkh-offline-verify-") as scratch:
        verify(args.case, args.reference, Path(scratch), args.offline_name, args.report_name)
