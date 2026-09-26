#!/usr/bin/env python3
"""Generate the non-secret TLSKeyHunter v3 thesis report from accepted evidence."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_manifest(directory: Path) -> bool:
    manifest = directory / "evidence-manifest.sha256"
    if not manifest.is_file():
        return False
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        target = directory / relative
        if not target.is_file() or sha256(target) != expected:
            return False
    return True


def clamp_interval(value: dict) -> dict:
    return {
        **value,
        "lower": max(0.0, min(1.0, float(value["lower"]))),
        "upper": max(0.0, min(1.0, float(value["upper"]))),
    }


def percent(value: float) -> str:
    return f"{100 * value:.1f}%"


def interval_text(value: dict) -> str:
    interval = clamp_interval(value)
    return f"{100 * interval['lower']:.2f}%–{100 * interval['upper']:.2f}%"


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()

    freeze = repo / "cases/FROZEN-BASELINE-V4"
    abi_dir = repo / "results/ARG-RANKER-ABI-FINAL-001"
    live_dir = repo / "cases/ARG-RANKER-LIVE-FINAL-001"
    tls12_dir = repo / "results/FIREFOX-NSS-TLS12-FINAL-MEASURED-001"
    tls13_dir = repo / "results/FIREFOX-NSS-TLS13-FINAL-MEASURED-001"
    regression_dir = repo / "results/FIREFOX-NSS-TLS13-REGRESSION-STRICT-001"
    controls_dir = repo / "cases/NEGATIVE-CONTROLS-FIREFOX-NSS-TLS12-FINAL-001"
    visual_dir = repo / "cases/FIREFOX-NSS-TLS12-VISUAL-EVIDENCE-001"
    required = [
        freeze,
        abi_dir,
        live_dir,
        tls12_dir,
        tls13_dir,
        regression_dir,
        controls_dir,
        visual_dir,
    ]
    missing = [str(path) for path in required if not path.is_dir()]
    if missing:
        raise SystemExit("missing accepted evidence: " + ", ".join(missing))

    abi = load_json(abi_dir / "summary.json")
    live = load_json(live_dir / "metrics/summary.json")
    tls12 = load_json(tls12_dir / "campaign-summary.json")
    tls13 = load_json(tls13_dir / "campaign-summary.json")
    regression = load_json(regression_dir / "campaign-summary.json")
    controls = load_json(controls_dir / "negative-controls.json")
    visual = load_json(visual_dir / "verification/verification.json")
    frozen_git = load_json(freeze / "git.json")
    tools = load_json(freeze / "tool-versions.json")
    targets = load_json(freeze / "target-artifact-hashes.json")
    scoring = load_json(freeze / "scoring-policy.json")
    static12 = load_json(freeze / "static-analysis/firefox-nss-tls12-provenance.json")
    static13 = load_json(freeze / "static-analysis/firefox-nss-tls13-provenance.json")

    if abi["observed"] != 240:
        raise SystemExit("ABI dataset is incomplete")
    if live["attempted_sessions"] != 40 or live["manifest_valid_sessions"] != 40:
        raise SystemExit("live A/D dataset is incomplete")
    if tls12["eligible_sessions"] != 30 or len(tls12["sessions"]) != 30:
        raise SystemExit("Firefox TLS 1.2 dataset is incomplete")
    if not all(session["manifest_valid"] for session in tls12["sessions"]):
        raise SystemExit("a Firefox TLS 1.2 session manifest is invalid")
    if not controls["all_negative_controls_passed"] or not controls["positive_sanity"]["passed"]:
        raise SystemExit("final controls did not pass")

    abi_by_method = {row["configuration"]: row for row in abi["summary"]}
    live_a = live["by_method"]["A"]
    live_d = live["by_method"]["D"]

    cross_protocol = [
        {
            "dataset": "Firefox/NSS TLS 1.2 final",
            "protocol": "TLS 1.2",
            "attempted_sessions": 30,
            "sealed_acquisitions": tls12["sealed_acquisitions"],
            "exact_secret_matches": tls12["exact_secret_matches"],
            "authenticated_decryptions": tls12["authenticated_decryptions"],
            "complete_recoveries": tls12["fully_recovered_sessions"],
            "exact_reference_scope": "all sessions",
            "wilson_95_lower": clamp_interval(tls12["wilson_95"])["lower"],
            "wilson_95_upper": clamp_interval(tls12["wilson_95"])["upper"],
        },
        {
            "dataset": "Firefox/NSS TLS 1.3 accepted historical final",
            "protocol": "TLS 1.3",
            "attempted_sessions": 90,
            "sealed_acquisitions": "not measured under sealed chronology",
            "exact_secret_matches": "not measured",
            "authenticated_decryptions": 90,
            "complete_recoveries": 90,
            "exact_reference_scope": "functional validation only",
            "wilson_95_lower": clamp_interval(tls13["wilson_95"])["lower"],
            "wilson_95_upper": clamp_interval(tls13["wilson_95"])["upper"],
        },
        {
            "dataset": "Firefox/NSS TLS 1.3 strict regression",
            "protocol": "TLS 1.3",
            "attempted_sessions": 5,
            "sealed_acquisitions": regression["sealed_acquisitions"],
            "exact_secret_matches": regression["exact_secret_matches"],
            "authenticated_decryptions": regression["authenticated_decryptions"],
            "complete_recoveries": regression["fully_recovered_sessions"],
            "exact_reference_scope": "all regression sessions",
            "wilson_95_lower": clamp_interval(regression["wilson_95"])["lower"],
            "wilson_95_upper": clamp_interval(regression["wilson_95"])["upper"],
        },
    ]

    ranker_rows = []
    for method, values in (("A", live_a), ("D", live_d)):
        ranker_rows.append(
            {
                "method": method,
                "attempted_sessions": 20,
                "candidate_selections": values["candidate_selection_success"]["count"],
                "exact_secret_matches": values["exact_secret_match"]["count"],
                "authenticated_decryptions": values["authenticated_pcap_decryption"]["count"],
                "complete_recoveries": values["complete_end_to_end_recovery"]["count"],
                "no_candidate": values["no_candidate"]["count"],
                "ambiguous": values["ambiguous"]["count"],
                "false_candidate": values["false_candidate"]["count"],
            }
        )

    comparison_dir = repo / "results/TLSKEYHUNTER-V3-SUMMARY"
    if comparison_dir.exists() and any(comparison_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty report directory: {comparison_dir}")
    comparison_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cross_csv = comparison_dir / "cross-protocol-comparison.csv"
    ranker_csv = comparison_dir / "ranker-method-comparison.csv"
    write_csv(cross_csv, cross_protocol)
    write_csv(ranker_csv, ranker_rows)

    integrity = {
        "freeze_manifest_valid": verify_manifest(freeze),
        "abi_manifest_valid": verify_manifest(abi_dir),
        "live_campaign_manifest_valid": verify_manifest(live_dir),
        "tls12_campaign_manifest_valid": verify_manifest(tls12_dir),
        "tls13_campaign_manifest_valid": verify_manifest(tls13_dir),
        "tls13_regression_manifest_valid": verify_manifest(regression_dir),
        "controls_manifest_valid": verify_manifest(controls_dir),
        "visual_manifest_valid": verify_manifest(visual_dir),
        "tls12_session_manifests_valid": sum(
            verify_manifest(repo / "cases" / session["case_id"])
            for session in tls12["sessions"]
        ),
        "tls13_historical_session_manifests_valid": sum(
            verify_manifest(path)
            for path in sorted((repo / "cases").glob("FIREFOX-NSS-TLS13-FINAL-MEASURED-001-*") )
        ),
    }
    if not all(
        value is True
        for key, value in integrity.items()
        if key.endswith("_manifest_valid")
    ):
        raise SystemExit("a top-level evidence manifest is invalid")
    if integrity["tls12_session_manifests_valid"] != 30:
        raise SystemExit("not all 30 TLS 1.2 session manifests are valid")
    if integrity["tls13_historical_session_manifests_valid"] != 90:
        raise SystemExit("not all 90 preserved TLS 1.3 session manifests are valid")

    summary_json = comparison_dir / "summary.json"
    summary = {
        "schema": "tlskh-report-v3-summary-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "frozen_commit": frozen_git["commit"],
        "cross_protocol": cross_protocol,
        "ranker_live": ranker_rows,
        "ranker_native": abi["summary"],
        "controls": {
            "negative_passed": sum(control["passed"] for control in controls["controls"]),
            "negative_total": len(controls["controls"]),
            "positive_sanity": controls["positive_sanity"]["passed"],
        },
        "integrity": integrity,
    }
    summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = f"""# TLSKeyHunter Live-Memory Forensics Thesis Report v3

**Project:** Improving the Robustness of Static-to-Dynamic TLS Key Extraction  
**Upstream basis:** `monkeywave/TLSKeyHunter`  
**Experiment branch:** `{frozen_git['branch']}`  
**Frozen experiment commit:** `{frozen_git['commit']}`  
**Frozen environment:** `FROZEN-BASELINE-V4`  
**Scope:** Authorized, controlled localhost/VPS TLS research only  
**Report generated:** {summary['generated_at'][:10]}

## 1. Executive outcome

This thesis returns to the original live-memory-forensics question: can a TLS secret candidate be acquired from an active process, fixed before verification, proven byte-for-byte against an independent reference, and then used to decrypt the intended captured connection?

For the principal Firefox/NSS TLS 1.2 experiment, the answer was **30/30 complete recoveries**. Every session used a fresh Firefox 136.0.2 profile, a single controlled TLS 1.2 connection, a frozen NSS fingerprint, a live Frida hook, an isolated server-side reference, and a PCAP. Every candidate was sealed before the server reference was read or TShark verification began.

| Principal Firefox TLS 1.2 metric | Result |
|---|---:|
| Attempted sessions | {tls12['eligible_sessions']} |
| Sealed acquisitions | {tls12['sealed_acquisitions']} |
| Exact server-reference matches | {tls12['exact_secret_matches']} |
| Authenticated decryptions | {tls12['authenticated_decryptions']} |
| Complete end-to-end recoveries | {tls12['fully_recovered_sessions']} |
| Coverage | {percent(tls12['session_recovery_coverage'])} |
| 95% Wilson interval | {interval_text(tls12['wilson_95'])} |
| Valid session manifests | {integrity['tls12_session_manifests_valid']}/30 |

This is a proof of concept under frozen laboratory conditions, not a claim that arbitrary Firefox versions or remote systems can be instrumented without version-specific validation.

## 2. Research contribution and scope

The upstream project provides the static-analysis foundation: TLS-related strings and functions are identified in Ghidra and converted into usable fingerprints. This work preserves that upstream basis and adds a controlled evidence pipeline:

```text
active TLS process
→ unique frozen static fingerprint
→ Frida live-memory acquisition
→ candidate selection
→ immutable acquisition seal
→ independent exact comparison
→ authenticated PCAP decryption
→ manifested evidence and non-secret metrics
```

Firefox/NSS is the principal real-world browser target. OpenSSL and wolfSSL are controlled comparison targets for argument-selection robustness. The original accepted Firefox TLS 1.3 campaign remains immutable supporting evidence. Later B/C ablations, an operator-effort microbenchmark, and synthetic GUI generation were removed from the required scope so the thesis claim remains narrow and defensible.

The work does not alter or erase the original creators' implementation. New runners and hooks are version-specific extensions, and historical exploratory evidence is retained but excluded from final claims where its chronology differs from the final method.

## 3. Forensic chronology and information isolation

The final experiment enforces this order:

1. Start packet capture and the controlled server.
2. Launch the target with a fresh profile and with target `SSLKEYLOGFILE` disabled.
3. Validate the frozen binary SHA-256, ELF Build ID, and exactly one fingerprint match.
4. Attach Frida and confirm the live hook before releasing the handshake gate.
5. Acquire and select a candidate using only target-process observations.
6. Stop acquisition, write the selected candidate to owner-readable evidence, hash it, and record `acquisition_sealed=true`.
7. Only then read the separate server reference and perform byte-for-byte comparison.
8. Use only the sealed candidate for TShark decryption and require the exact request path and response marker.

The verifier never tries candidates until one decrypts. A missing candidate is `no_candidate`; an equal top rank is `ambiguous`; a plausible but unequal candidate is a false candidate. All remain in their denominators.

## 4. Static-to-dynamic provenance

V4 records Ghidra {tools['ghidra']['version']} at `{tools['ghidra']['analyze_headless_resolved']}`, with headless status `{tools['ghidra']['status']}` and application-properties SHA-256 `{tools['ghidra']['application_properties_sha256']}`.

| Target | SHA-256 | Build ID | Static offset | Pattern matches | Hook |
|---|---|---|---:|---:|---|
| Firefox TLS 1.2 `libsoftokn3.so` | `{targets['libsoftokn3']['sha256']}` | `{targets['libsoftokn3']['build_id']}` | `{static12['static_function_offset']}` | {static12['pattern_match_count']} | `nss_firefox_136.0.2_tls12.js` |
| Firefox TLS 1.3 `libssl3.so` | `{targets['libssl3']['sha256']}` | `{targets['libssl3']['build_id']}` | `{static13['static_function_offset']}` | {static13['pattern_match_count']} | `nss_firefox_136.0.2.js` |

Zero or multiple fingerprint matches stop extraction. TLS 1.2 targets the NSS `TLS_PRF`-equivalent path referenced by `master secret`; its successful 48-byte result is associated with the controlled PCAP ClientHello random.

## 5. Candidate selection: A versus D

Only two methods are in the final comparison:

- **A:** the original per-hook hardcoded argument position.
- **D:** readability + expected length + entropy/zero-count + repeated-call consistency.

Preferred-index scoring is disabled in D, and D never silently falls back to A.

### 5.1 Native ABI validation

The controlled x86-64 harness rotated a 32-byte secret through argument indices 0–11, with 10 calls per position for each method.

| Method | Correct | Total | Accuracy |
|---|---:|---:|---:|
| A | {abi_by_method['A_hardcoded']['correct']} | {abi_by_method['A_hardcoded']['total']} | {percent(abi_by_method['A_hardcoded']['argument_identification_accuracy'])} |
| D | {abi_by_method['D_full_ranker']['correct']} | {abi_by_method['D_full_ranker']['total']} | {percent(abi_by_method['D_full_ranker']['argument_identification_accuracy'])} |

A was correct only when the rotated secret occupied its frozen hardcoded position. D was correct for all positions. This demonstrates argument-selection mechanics, not browser recovery.

### 5.2 Live OpenSSL/wolfSSL comparison

| Method | Attempts | Candidate selections | Exact matches | Decryptions | Complete | No candidate | False candidate |
|---|---:|---:|---:|---:|---:|---:|---:|
| A | 20 | {ranker_rows[0]['candidate_selections']} | {ranker_rows[0]['exact_secret_matches']} | {ranker_rows[0]['authenticated_decryptions']} | {ranker_rows[0]['complete_recoveries']} | {ranker_rows[0]['no_candidate']} | {ranker_rows[0]['false_candidate']} |
| D | 20 | {ranker_rows[1]['candidate_selections']} | {ranker_rows[1]['exact_secret_matches']} | {ranker_rows[1]['authenticated_decryptions']} | {ranker_rows[1]['complete_recoveries']} | {ranker_rows[1]['no_candidate']} | {ranker_rows[1]['false_candidate']} |

D completed 20/20 sessions (95% Wilson interval {interval_text(live_d['complete_end_to_end_recovery']['wilson_95'])}). A completed 10/20 ({interval_text(live_a['complete_end_to_end_recovery']['wilson_95'])}). The result does not mean hardcoded positions always fail: A succeeded on the frozen wolfSSL layouts and failed on the frozen OpenSSL layouts. D removed that target-specific assumption in this controlled comparison.

## 6. Firefox/NSS results

| Dataset | Attempts | Exact comparison | Authenticated decryption | Complete recovery | Interpretation |
|---|---:|---:|---:|---:|---|
| TLS 1.2 final | 30 | 30/30 | 30/30 | 30/30 | Principal sealed-forensics result |
| TLS 1.3 strict regression | 5 | 5/5 | 5/5 | 5/5 | Sealed chronology and exact-reference regression |
| TLS 1.3 accepted historical final | 90 | Not measured | 90/90 | 90/90 | Preserved functional evidence; not upgraded to an exact-match claim |

The historical TLS 1.3 final campaign remains at commit `{tls13['git_commit']}` with {integrity['tls13_historical_session_manifests_valid']}/90 valid case manifests and a clamped 95% Wilson interval of {interval_text(tls13['wilson_95'])}. It is not repeated and is not retroactively described as having server-reference equality. The strict 5/5 regression provides the newer sealed/exact chronology for TLS 1.3.

## 7. Negative controls

All {len(controls['controls'])}/{len(controls['controls'])} final TLS 1.2 negative controls passed:

1. no key-log candidate;
2. random same-length secret;
3. one-bit modified secret;
4. correct secret with wrong ClientHello random;
5. Frida diagnostic text treated as key material;
6. correct candidate on the wrong TCP stream;
7. unsupported NSS SHA-256/Build ID;
8. multiple fingerprint matches.

The positive sanity control recovered both the exact request path and response marker. These controls show that length, entropy, diagnostic output, or a correct secret without correct connection association is not sufficient.

## 8. Visual evidence

`FIREFOX-NSS-TLS12-VISUAL-EVIDENCE-001` is a separate supporting case. It records a real visible Firefox session on Xvfb, a localhost-only x11vnc endpoint, four 1280×800 stage screenshots, and an MP4. Its authoritative verification record reports: acquisition sealed `{str(visual['acquisition_sealed']).lower()}`, exact server match `{str(visual['exact_server_reference_match']).lower()}`, TShark decryption `{str(visual['tshark_decryption']).lower()}`, and status `{visual['status']}`.

The GUI is not part of the 30-session statistical dataset. PCAP, Frida events, server events, exact comparison, TShark output, and manifests remain authoritative.

## 9. Evidence integrity and secret handling

| Evidence set | Manifest result |
|---|---:|
| V4 freeze | valid |
| ABI final | valid |
| Live A/D campaign | valid (40/40 session manifests) |
| Firefox TLS 1.2 campaign | valid (30/30 session manifests) |
| Preserved Firefox TLS 1.3 final | valid (90/90 case manifests) |
| TLS 1.3 strict regression | valid |
| Final controls | valid |
| Visual case | valid |

Raw candidates and server references remain only in owner-readable private evidence files. Transcripts and reports expose case IDs, hashes, indices, lengths, scores, classifications, and non-secret metrics—not raw TLS secrets. Long-hex scans of public summaries, transcripts, reports, and visual artifacts found no secret-length material.

## 10. What changed from the earlier plan and report

The earlier report correctly marked Firefox TLS 1.2, live ranker evaluation, Ghidra detection, and real GUI evidence as incomplete. V3 closes those gaps while intentionally narrowing other work:

| Earlier direction | V3 decision |
|---|---|
| A–D ablation | Keep A versus full D only; B/C remain historical exploratory evidence |
| 160 live sessions | Use 40 fixed A/D sessions across two libraries and two protocols |
| 90 new Firefox TLS 1.2 sessions | Use 30 principal sessions (3 × 10) with stricter exact-reference chronology |
| Operator-effort study | Removed from required claims |
| Repeat accepted TLS 1.3 90-session campaign | Preserve unchanged; add a strict 5-session regression |
| GUI as evidence source | One supporting case only; machine evidence remains authoritative |

This is a deliberate scope correction, not an attempt to hide unfinished work. Excluded exploratory evidence remains labelled and preserved.

## 11. Limitations

- Firefox hooks and fingerprints are specific to Firefox 136.0.2 and the frozen NSS binaries.
- Experiments use a controlled localhost server, fixed cipher/profile policy, and one connection per case.
- Results do not demonstrate extraction from arbitrary remote machines or non-consenting targets.
- D is evaluated against A in these frozen targets; it is not proof that the scoring rules generalize to every TLS implementation or architecture.
- The TLS 1.3 90-session campaign provides functional validation but not exact server-reference equality; only the strict regression uses the final exact chronology.
- A 30/30 result still has uncertainty: its 95% Wilson lower bound is {clamp_interval(tls12['wilson_95'])['lower']:.4f}.

## 12. Reproducibility and audit locations

```text
Freeze:        cases/FROZEN-BASELINE-V4/
ABI:           results/ARG-RANKER-ABI-FINAL-001/
Live A/D:      cases/ARG-RANKER-LIVE-FINAL-001/
Firefox TLS12: results/FIREFOX-NSS-TLS12-FINAL-MEASURED-001/
Controls:      cases/NEGATIVE-CONTROLS-FIREFOX-NSS-TLS12-FINAL-001/
Visual case:   cases/FIREFOX-NSS-TLS12-VISUAL-EVIDENCE-001/
TLS13 final:   results/FIREFOX-NSS-TLS13-FINAL-MEASURED-001/
TLS13 strict:  results/FIREFOX-NSS-TLS13-REGRESSION-STRICT-001/
```

Verify any evidence directory from inside it with:

```bash
sha256sum -c --quiet evidence-manifest.sha256
```

The machine-readable non-secret v3 tables are in `results/TLSKEYHUNTER-V3-SUMMARY/`.

## 13. Defensible thesis claim

> This thesis extends TLSKeyHunter's static-to-dynamic workflow with a controlled live-memory acquisition and verification pipeline. TLS derivation candidates were acquired from active processes, sealed before verification, compared byte-for-byte with an independently generated server reference, and validated through authenticated recovery of controlled application traffic. A full explainable ranker was additionally compared with the original hardcoded argument-position approach under frozen experimental conditions.

The claim is limited to the authorized frozen laboratory targets and the evidence described above.
"""

    report_path = repo / "TLSKeyHunter_REPORT_v3.md"
    if report_path.exists():
        raise SystemExit(f"refusing to overwrite existing report: {report_path}")
    report_path.write_text(report, encoding="utf-8")

    public_outputs = [cross_csv, ranker_csv, summary_json, report_path]
    long_hex = re.compile(r"(?i)\b[0-9a-f]{96,}\b")
    leaked = [str(path) for path in public_outputs if long_hex.search(path.read_text(encoding="utf-8"))]
    if leaked:
        raise SystemExit("secret-length hex found in public outputs: " + ", ".join(leaked))

    manifest = comparison_dir / "evidence-manifest.sha256"
    manifest.write_text(
        "".join(
            f"{sha256(path)}  {path.relative_to(repo)}\n"
            for path in public_outputs
        ),
        encoding="utf-8",
    )
    for path in [*public_outputs, manifest]:
        path.chmod(0o600)
    comparison_dir.chmod(0o700)
    print(
        json.dumps(
            {
                "report": str(report_path),
                "summary_dir": str(comparison_dir),
                "public_secret_scan": "passed",
                "integrity": integrity,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
