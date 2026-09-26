#!/usr/bin/env python3
"""Run the argument-ranker against a real x86-64 Frida ABI harness."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import time

import frida


CONFIGURATIONS = ("A_hardcoded", "D_full_ranker")
EXPECTED_OBSERVATIONS = 12 * 10 * len(CONFIGURATIONS)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def deterministic_bytes(length: int, seed: int) -> bytes:
    return bytes((index * 73 + seed * 29 + 17) & 0xFF for index in range(length))


class TerminalReporter:
    def __init__(self, path: Path, mode: str) -> None:
        self.path = path
        self.mode = mode
        path.write_text("", encoding="utf-8")

    def emit(self, category: str, message: str) -> None:
        line = f"[{category}] {message}"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if self.mode == "teaching" or category in {"OK", "FAIL", "METRIC", "ARTIFACT"}:
            print(line, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--benchmark-id", default="ARG-RANKER-ABI-FINAL-001")
    parser.add_argument("--terminal-mode", choices=["summary", "teaching"], default="teaching")
    parser.add_argument("--stream-output", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    output = repo / "results" / args.benchmark_id
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"refusing to overwrite benchmark: {output}")
    output.mkdir(parents=True, mode=0o700)
    terminal = TerminalReporter(output / "terminal-transcript.log", args.terminal_mode)
    build_dir = repo / "build/native-abi"
    build_dir.mkdir(parents=True, exist_ok=True)
    source = repo / "lab/arg_ranker/native_abi_harness.c"
    binary = build_dir / "native_abi_harness"
    compile_command = [
        "gcc", "-O0", "-g", "-fno-omit-frame-pointer", "-rdynamic",
        str(source), "-o", str(binary),
    ]
    terminal.emit("STEP", "Compile controlled x86-64 ABI harness")
    terminal.emit("COMMAND", " ".join(compile_command))
    subprocess.run(compile_command, check=True)

    ranker_source = (repo / "tlsKeyExtraction/arg_ranker.js").read_text()
    observations: list[dict] = []
    device = frida.get_local_device()
    for configuration in CONFIGURATIONS:
        for true_index in range(12):
            terminal.emit(
                "STEP", f"configuration={configuration} true_argument_index={true_index}"
            )
            events: list[dict] = []
            pid = device.spawn([str(binary), str(true_index)])
            session = device.attach(pid)
            listener = f"""
            const ABI_CONFIGURATION = {json.dumps(configuration)};
            let abiCall = 0;
            const target = Module.getExportByName(null, 'tlskh_probe');
            Interceptor.attach(target, {{
              onEnter(args) {{
                abiCall += 1;
                let selected = null;
                let candidates = [];
                let selectionStatus = 'no_candidate';
                let tiedIndexes = [];
                if (ABI_CONFIGURATION === 'A_hardcoded') {{
                  let selectedHex = '';
                  try {{ selectedHex = ArgRanker.bytesToHex(Memory.readByteArray(args[9], 32)); }} catch (_) {{}}
                  selected = {{index: 9, score: null, reasons: ['original_hardcoded'], length: 32, hex: selectedHex}};
                  selectionStatus = selectedHex ? 'selected' : 'unreadable_hardcoded';
                }} else {{
                  const context = {{maxArgs: 12, callSite: 'native-abi-' + {true_index}}};
                  candidates = ArgRanker.rankSecretCandidates(args, [32], context);
                  const decision = ArgRanker.selectUniqueCandidate(candidates);
                  selected = decision.candidate;
                  selectionStatus = decision.status;
                  tiedIndexes = decision.tiedIndexes;
                }}
                send({{
                  kind: 'abi_observation', call: abiCall,
                  selection_status: selectionStatus,
                  tied_indexes: tiedIndexes,
                  selected_index: selected ? selected.index : null,
                  selected_hex: selected ? selected.hex : '',
                  score: selected ? selected.score : null,
                  reasons: selected ? selected.reasons : [],
                  ranked: candidates.map(c => ({{
                    index: c.index, score: c.score, reasons: c.reasons,
                    length: c.length, hex: c.hex
                  }}))
                }});
              }}
            }});
            """
            script = session.create_script(ranker_source + "\n" + listener)
            script.on("message", lambda message, data: events.append(message["payload"]) if message.get("type") == "send" else None)
            script.load()
            device.resume(pid)
            # The harness performs ten 20 ms calls and then exits.  Frida's
            # Device.get_process API resolves names rather than numeric PIDs,
            # so wait for the bounded harness duration instead of polling it.
            time.sleep(0.75)
            try:
                session.detach()
            except frida.InvalidOperationError:
                pass
            for event in events:
                if event.get("kind") != "abi_observation":
                    continue
                call = int(event["call"])
                selected_hex = event.get("selected_hex") or ""
                try:
                    selected_bytes = bytes.fromhex(selected_hex)
                except ValueError:
                    selected_bytes = b""
                expected = deterministic_bytes(
                    32, true_index * 31 + true_index + call
                )
                ranked = []
                for candidate in event.get("ranked", []):
                    candidate_hex = candidate.pop("hex", "")
                    try:
                        candidate_bytes = bytes.fromhex(candidate_hex)
                    except ValueError:
                        candidate_bytes = b""
                    ranked.append({
                        **candidate,
                        "candidate_sha256": sha256_bytes(candidate_bytes) if candidate_bytes else None,
                    })
                exact = selected_bytes == expected
                observations.append({
                    "configuration": configuration,
                    "true_argument_index": true_index,
                    "call": call,
                    "selection_status": event.get("selection_status", "no_candidate"),
                    "tied_indexes": event.get("tied_indexes", []),
                    "selected_argument_index": event["selected_index"],
                    "selected_candidate_sha256": (
                        sha256_bytes(selected_bytes) if selected_bytes else None
                    ),
                    "expected_candidate_sha256": sha256_bytes(expected),
                    "expected_length": 32,
                    "selected_length": len(selected_bytes) if selected_bytes else None,
                    "score": event["score"],
                    "reasons": event["reasons"],
                    "ranked": ranked,
                    "exact": exact,
                    "failure_reason": None if exact else event.get("selection_status", "no_candidate"),
                })

    summary = []
    for configuration in CONFIGURATIONS:
        rows = [row for row in observations if row["configuration"] == configuration]
        correct = sum(row["exact"] for row in rows)
        summary.append({
            "configuration": configuration,
            "correct": correct,
            "total": len(rows),
            "argument_identification_accuracy": correct / len(rows) if rows else 0.0,
        })
    result = {
        "schema_version": 2,
        "benchmark_id": args.benchmark_id,
        "source_sha256": sha256(source),
        "binary_sha256": sha256(binary),
        "ranker_sha256": sha256(repo / "tlsKeyExtraction/arg_ranker.js"),
        "configurations": list(CONFIGURATIONS),
        "expected_observations": EXPECTED_OBSERVATIONS,
        "observed": len(observations),
        "summary": summary,
    }
    (output / "observations.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in observations)
    )
    (output / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with (output / "summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        writer.writerows(summary)
    terminal.emit("METRIC", json.dumps(result["summary"], sort_keys=True))
    terminal.emit("ARTIFACT", str(output))
    exit_code = 0
    if len(observations) != EXPECTED_OBSERVATIONS:
        terminal.emit(
            "FAIL", f"expected {EXPECTED_OBSERVATIONS} observations; got {len(observations)}"
        )
        exit_code = 2
    else:
        terminal.emit("OK", f"recorded all {EXPECTED_OBSERVATIONS} A/D observations")
    # The transcript is an evidence input, so finalize it before hashing the
    # directory.  No output may be appended after the manifest is written.
    for path in output.iterdir():
        path.chmod(0o600)
    manifest_inputs = sorted(path for path in output.iterdir() if path.name != "evidence-manifest.sha256")
    (output / "evidence-manifest.sha256").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in manifest_inputs)
    )
    (output / "evidence-manifest.sha256").chmod(0o600)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
