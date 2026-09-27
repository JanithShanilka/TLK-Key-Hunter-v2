#!/usr/bin/env python3
"""Private post-verification report. Reveals lab secrets; never an extractor input."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', type=Path, required=True)
    p.add_argument('--reference', type=Path, required=True)
    args = p.parse_args()
    os.umask(0o077)
    case = args.case
    offline = case / 'offline-cka-pcap-v1'
    seal = json.loads((offline / 'selection-seal.json').read_text())
    raw = (offline / 'ranked-candidates.private.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != seal['candidate_file_sha256']:
        raise ValueError('Candidate seal mismatch')
    candidates = json.loads(raw)
    report = json.loads((case / 'verification-cka-pcap-v1/summary.json').read_text())
    references = [line.split() for line in args.reference.read_text().splitlines() if line.startswith('CLIENT_RANDOM ')]
    if len(references) != 1:
        raise ValueError('Expected one TLS 1.2 reference')
    _, random, secret = references[0]
    results = {row['id']: row for row in seal['packet_validation']}
    selected = next(row for row in candidates if row['id'] == seal['selected_id'])
    if selected['hex'].lower() != secret.lower() or not report['complete_offline_recovery']:
        raise ValueError('Expected previously verified exact recovery')
    rows = []
    for index, row in enumerate(candidates, 1):
        trial = results[row['id']]
        different = sum((a ^ b).bit_count() for a, b in zip(bytes.fromhex(row['hex']), bytes.fromhex(secret)))
        cells = [str(index), '<code>' + html.escape(row['hex']) + '</code>', str(row['score']) + ' (tied)',
                 'YES' if different == 0 else 'NO', str(different),
                 'Yes' if trial['http_request'] else 'No', 'Yes' if trial['http_response'] else 'No',
                 'PASS' if trial['passes'] else 'FAIL']
        rows.append('<tr>' + ''.join('<td>' + cell + '</td>' for cell in cells) + '</tr>')
    page = '''<!doctype html><meta charset="utf-8"><title>Private TLS lab evidence</title>
<style>body{font:16px system-ui;max-width:1350px;margin:32px auto;padding:20px;color:#182e45;background:#f4f7fa}section{background:white;padding:24px;margin:20px 0;border:1px solid #ccd7e2;border-radius:10px}code{font:14px monospace;overflow-wrap:anywhere}.key{display:block;padding:16px;background:#edf2f7}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #ddd;vertical-align:top}small{color:#52657a}</style>
<h1>Firefox TLS 1.2: live-session reference vs offline candidates</h1>
<p>Private lab evidence · CASE · One fresh validation trial</p>
<section><h2>1. Secret recorded during the live connection</h2>
<p>The independent localhost server recorded this 48-byte master secret during the handshake. This is the saved record of that session, not a currently running live feed. Firefox key logging and Frida export hooks were not used.</p>
<code class="key">SECRET</code><p>Public ClientHello random identifying the connection:</p><code class="key">RANDOM</code></section>
<section><h2>2. Five candidates from saved Firefox memory</h2>
<p>The extractor received only the dump and could not read the reference. The memory scores tied. A separate step tried each candidate against the saved PCAP without using the reference secret.</p>
<table><thead><tr><th>Trial order</th><th>Candidate secret (hex)</th><th>Memory score</th><th>Exact match</th><th>Bits different / 384</th><th>HTTP request</th><th>HTTP response</th><th>Packet result</th></tr></thead><tbody>ROWS</tbody></table>
<p><small>Trial order is the sealed file order, not a ranking within the tie. Score 75 is not 75% correctness. Exact-match and differing-bit columns were calculated after selection, using the reference. A wrong key with fewer differing bits is still unusable. FAIL means the required request/response pair was not recovered; it does not necessarily mean the reader process failed.</small></p></section>
<section><h2>3. Independently verified recovered secret</h2><code class="key">RECOVERED</code>
<p><b>Exact match · 0 differing bits · Controlled request and response decrypted</b></p>
<p>The one-bit-corrupted reference failed to recover both markers. Memory-only ranking abstained; packet validation resolved the tie. One fresh validation success is not a general success-rate estimate. TLS 1.3 is untested.</p></section>
<section><h2>Evidence and conditions</h2><p>Firefox 136.0.2/NSS, Linux x86-64, localhost TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256. Approved disposable-session socket-sandbox and certificate-validation exceptions were used. Reference verification followed sealed packet-assisted selection.</p>
<p>Core SHA-256: <code>COREHASH</code></p><p>PCAP SHA-256: <code>PCAPHASH</code></p><p>Generated from retained evidence. No new dump or connection.</p></section>'''
    for token, value in [('CASE', html.escape(case.name)), ('SECRET', html.escape(secret)), ('RANDOM', html.escape(random)),
                         ('ROWS', ''.join(rows)), ('RECOVERED', html.escape(selected['hex'])),
                         ('COREHASH', report['core_sha256']), ('PCAPHASH', report['pcap_sha256'])]:
        page = page.replace(token, value)
    output = case / 'private-lab-view.private.html'
    output.write_text(page)
    output.chmod(0o600)
    print(json.dumps({'created': str(output), 'tried': len(candidates), 'passed': sum(r['passes'] for r in results.values()),
                      'winning_trial': next(i for i, r in enumerate(candidates, 1) if r['id'] == seal['selected_id'])}))


if __name__ == '__main__':
    main()
