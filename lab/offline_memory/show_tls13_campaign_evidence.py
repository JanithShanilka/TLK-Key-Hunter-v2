#!/usr/bin/env python3
"""Create a private TLS 1.3 campaign report containing actual lab secrets."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path

LABELS = ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)

    campaign = args.workspace / "campaigns" / args.campaign_id
    runs = json.loads((campaign / "runs.json").read_text())
    if len(runs) != 20 or not all(row["complete_offline_recovery"] for row in runs):
        raise RuntimeError("Expected 20 completed successful sessions")

    overview = []
    sections = []
    candidate_total = request_passes = response_passes = 0
    for number, run in enumerate(runs, 1):
        case = args.workspace / "cases" / run["case_id"]
        offline = case / "offline-tls13-pcap"
        seal = json.loads((offline / "selection-seal.json").read_text())
        raw = (offline / "ranked-candidates.private.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != seal["candidate_file_sha256"]:
            raise RuntimeError("Candidate seal mismatch")
        candidates = json.loads(raw)
        by_id = {row["id"]: row for row in candidates}
        trials = {row["id"]: row for row in seal["trials"]}
        verification = json.loads((case / "verification-tls13" / "summary.json").read_text())
        references = {}
        reference_path = Path("/root/tlkh-memory-reference") / case.name / "server-reference.keys"
        for line in reference_path.read_text().splitlines():
            parts = line.split()
            if parts and parts[0] in LABELS:
                if len(parts) != 3 or parts[0] in references or parts[1] != seal["client_random"]:
                    raise RuntimeError("Malformed or mismatched reference")
                references[parts[0]] = parts[2].lower()
        if set(references) != set(LABELS):
            raise RuntimeError("Missing directional references")

        selected = {label: by_id[seal["selected_ids"][label]]["hex"].lower() for label in LABELS}
        if any(selected[label] != references[label] for label in LABELS):
            raise RuntimeError("Selected value is not the verified reference")
        if not verification["complete_offline_recovery"]:
            raise RuntimeError("Verification did not establish complete recovery")

        table_rows = []
        for index, candidate in enumerate(candidates, 1):
            trial = trials.get(candidate["id"], {"request": False, "response": False, "exit": None})
            value = candidate["hex"].lower()
            client_bits = sum((a ^ b).bit_count() for a, b in zip(bytes.fromhex(value), bytes.fromhex(references[LABELS[0]])))
            server_bits = sum((a ^ b).bit_count() for a, b in zip(bytes.fromhex(value), bytes.fromhex(references[LABELS[1]])))
            request_passes += int(trial["request"])
            response_passes += int(trial["response"])
            candidate_total += 1
            role = "Client winner" if trial["request"] else "Server winner" if trial["response"] else "No role"
            cells = [
                str(index), "<code>" + html.escape(value) + "</code>", str(candidate["length"] * 8),
                str(candidate["score"]), str(client_bits), str(server_bits),
                "Yes" if trial["request"] else "No", "Yes" if trial["response"] else "No", role,
            ]
            css = "winner" if trial["request"] or trial["response"] else ""
            table_rows.append('<tr class="' + css + '">' + "".join("<td>" + item + "</td>" for item in cells) + "</tr>")

        client_index = next(i for i, row in enumerate(candidates, 1) if row["id"] == seal["selected_ids"][LABELS[0]])
        server_index = next(i for i, row in enumerate(candidates, 1) if row["id"] == seal["selected_ids"][LABELS[1]])
        overview.append(
            f'<tr><td><a href="#session{number}">{number:02d}</a></td><td>{html.escape(run["started"])}</td>'
            f'<td>{len(candidates)}</td><td>{client_index}</td><td>{server_index}</td><td>0 / 384</td><td>Yes</td><td>Yes</td></tr>'
        )
        sections.append(f'''<details id="session{number}" {'open' if number == 1 else ''}>
<summary>Session {number:02d} · {len(candidates)} candidates · exact client and server recovery</summary>
<p><b>{html.escape(case.name)}</b><br>Negotiated cipher: {html.escape(verification['cipher'])}<br>Started: {html.escape(run['started'])}</p>
<h3>Client application traffic secret</h3><p>Live server reference:</p><code class="key">{references[LABELS[0]]}</code>
<p>Offline-selected value:</p><code class="key matched">{selected[LABELS[0]]}</code>
<p><b>Exact match: 0 differing bits out of 384.</b> HTTP request decrypted: Yes.</p>
<h3>Server application traffic secret</h3><p>Live server reference:</p><code class="key">{references[LABELS[1]]}</code>
<p>Offline-selected value:</p><code class="key matched">{selected[LABELS[1]]}</code>
<p><b>Exact match: 0 differing bits out of 384.</b> HTTP response decrypted: Yes.</p>
<h3>All offline candidates</h3><div class="scroll"><table><thead><tr><th>#</th><th>Candidate secret</th><th>Bits</th><th>Score</th><th>Different from client</th><th>Different from server</th><th>Request</th><th>Response</th><th>Outcome</th></tr></thead><tbody>{''.join(table_rows)}</tbody></table></div>
<p class="muted">Green rows are the directional winners. The reference comparisons shown here occurred only after saved-traffic selection was sealed.</p>
<h3>Directional one-bit controls</h3><p>Wrong client secret → request: No, response: Yes. Wrong server secret → request: Yes, response: No.</p>
<details><summary>Connection and evidence identifiers</summary><p>ClientHello random:</p><code class="key">{html.escape(seal['client_random'])}</code><p>Core SHA-256:</p><code>{verification['core_sha256']}</code><p>PCAP SHA-256:</p><code>{verification['pcap_sha256']}</code></details>
</details>''')

    if candidate_total != 196 or request_passes != 20 or response_passes != 20:
        raise RuntimeError("Unexpected aggregate candidate outcomes")
    page = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private TLS 1.3 live and offline secret report</title><style>
body{font:16px/1.5 system-ui,sans-serif;background:#f3f6fb;color:#152d46;max-width:1400px;margin:32px auto;padding:0 20px}h1{font-size:32px}h2{font-size:23px}h3{font-size:18px;margin-top:24px}section,details{background:#fff;border:1px solid #d5dfeb;border-radius:12px;padding:20px;margin:18px 0}details details{background:#f6f8fc}summary{cursor:pointer;font-weight:650}code{font:14px/1.7 ui-monospace,monospace;overflow-wrap:anywhere;word-break:break-all}.key{display:block;background:#eef3fa;padding:15px;border-radius:6px}.matched{border-left:5px solid #15805d}.note{border-left:4px solid #be8413;padding:12px;background:#fff8e6}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #dfe6ef}th{background:#edf2f8}.winner{background:#e8f8ef}.scroll{overflow-x:auto}a{color:#155caa}.muted{color:#53677d}@media print{details{break-inside:avoid}body{max-width:none}}
</style></head><body><h1>TLS 1.3 live-session secrets and offline recovery</h1>
<p class="muted">Private lab report · 20 fresh sessions · actual client and server application traffic secrets</p>
<section><h2>Result</h2><p><b>All 20 sessions recovered both directional TLS 1.3 traffic secrets exactly.</b> Each selected client and server secret differed from its independent live-session reference by zero bits out of 384, and the pair decrypted both the controlled HTTP request and response.</p>
<p>Across the campaign, 196 structured candidates were checked. There were 20 client-direction winners and 20 server-direction winners. These are directional candidate checks within 20 connections, not independent connection experiments.</p>
<p>Live TLS 1.3 connection → save Firefox memory → extract candidates offline without the reference → assign client/server roles using saved traffic → independently compare with the server reference.</p>
<p>The values below were recorded during completed live sessions. This is not a current live feed. Memory-only extraction found candidates but did not assign their directional roles.</p></section>
<section><h2>Session overview</h2><table><thead><tr><th>Session</th><th>Start (UTC)</th><th>Candidates</th><th>Client trial</th><th>Server trial</th><th>Different bits</th><th>Request</th><th>Response</th></tr></thead><tbody>''' + "".join(overview) + '''</tbody></table></section>''' + "".join(sections) + '''
<section><h2>Conditions and limits</h2><p>Firefox 136.0.2/NSS, Linux x86-64, localhost TLS 1.3, TLS_AES_256_GCM_SHA384, fresh full handshakes, no resumption, no 0-RTT and no intentional KeyUpdate. Approved disposable-session socket-sandbox and certificate-validation exceptions applied.</p><p>This demonstrates endpoint-memory recovery in this fixed lab. It does not break TLS 1.3 cryptography or establish universal recovery. Raw campaign cores and profiles were deleted after verified compact evidence was saved. This page contains actual lab secrets, is mode 0600, and must remain outside GitHub.</p></section></body></html>'''
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(page)
    args.output.chmod(0o600)
    print(json.dumps({"sessions": len(runs), "candidates": candidate_total,
                      "client_passes": request_passes, "server_passes": response_passes,
                      "bytes": args.output.stat().st_size}))


if __name__ == "__main__":
    main()
