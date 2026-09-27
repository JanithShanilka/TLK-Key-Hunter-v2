#!/usr/bin/env python3
"""Resolve memory-candidate ties using a controlled single-connection TLS 1.2 PCAP.

No reference-secret input. This is packet-assisted validation, not memory-only ranking.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from rank_core import digest


def main(scratch):
    parser = argparse.ArgumentParser()
    parser.add_argument('--offline', type=Path, required=True)
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    seal = json.loads((args.offline / 'selection-seal.json').read_text())
    source = args.offline / 'ranked-candidates.private.json'
    if digest(source) != seal['candidate_file_sha256']:
        raise RuntimeError('Candidate seal mismatch')
    rows = json.loads(source.read_text())
    if len(rows) > 100:
        raise RuntimeError('Pilot packet-validation budget is 100 candidates')
    scratch_capture = scratch / 'traffic.pcap'
    shutil.copyfile(args.pcap, scratch_capture)
    base = ['tshark', '-r', str(scratch_capture)]
    randoms = set(subprocess.check_output(base + ['-Y', 'tls.handshake.type == 1', '-T', 'fields', '-e', 'tls.handshake.random'], text=True, stderr=subprocess.DEVNULL).split())
    if len(randoms) != 1:
        raise RuntimeError('Expected exactly one ClientHello random')
    random_value = randoms.pop()
    if len(bytes.fromhex(random_value)) != 32:
        raise RuntimeError('Invalid ClientHello random')
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    with tempfile.TemporaryDirectory(prefix='tlkh-candidate-') as directory:
        keyfile = Path(directory) / 'candidate.keys'
        for row in rows:
            if len(bytes.fromhex(row['hex'])) != 48:
                raise RuntimeError('Unexpected candidate length')
            keyfile.write_text(f"CLIENT_RANDOM {random_value} {row['hex']}\n")
            result = subprocess.run(base + ['-o', f'tls.keylog_file:{keyfile}', '-Y', 'http', '-T', 'fields', '-e', 'http.request.method', '-e', 'http.response.code'], capture_output=True, text=True, timeout=30)
            fields = [line.split('\t') for line in result.stdout.splitlines()]
            request = any(parts[0] for parts in fields)
            response = any(len(parts) > 1 and parts[1].isdigit() for parts in fields)
            results.append({'id': row['id'], 'tshark_exit': result.returncode, 'http_request': request, 'http_response': response, 'passes': result.returncode == 0 and request and response})
    passing = [result['id'] for result in results if result['passes']]
    shutil.copyfile(source, args.output / source.name)
    (args.output / source.name).chmod(0o400)
    summary = dict(seal)
    summary.update({'method': seal['method'] + '_pcap_validation', 'memory_only_selection_status': seal['status'], 'status': 'selected' if len(passing) == 1 else 'ambiguous' if passing else 'no_candidate', 'selected_id': passing[0] if len(passing) == 1 else None, 'selection_uses_pcap': True, 'reference_input': False, 'pcap_sha256': digest(args.pcap), 'packet_validation': results})
    (args.output / 'selection-seal.json').write_text(json.dumps(summary, indent=2) + '\n')
    (args.output / 'selection-seal.json').chmod(0o400)
    print(json.dumps({'candidate_count': len(rows), 'packet_validation_pass_count': len(passing), 'selection_status': summary['status'], 'reference_input': False}))


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='tlkh-packet-validation-') as scratch:
        main(Path(scratch))
