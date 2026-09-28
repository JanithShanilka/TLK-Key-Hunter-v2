#!/usr/bin/env python3
"""Post-seal independent TLS 1.3 reference comparison and two-direction controls."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
from core_memory import CoreMemory
from rank_core import digest
from validate_tls13 import LABELS


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',type=Path,required=True);p.add_argument('--reference',type=Path,required=True)
    a=p.parse_args();os.umask(0o077)
    offline=a.case/'offline-tls13-pcap'
    seal=json.loads((offline/'selection-seal.json').read_text())
    raw=offline/'ranked-candidates.private.json'
    if digest(raw)!=seal['candidate_file_sha256'] or digest(a.case/'firefox.core')!=seal['core_sha256'] or digest(a.case/'traffic.pcap')!=seal['pcap_sha256']:raise RuntimeError('Evidence hash mismatch')
    refs={}
    for line in a.reference.read_text().splitlines():
        parts=line.split()
        if parts and parts[0] in LABELS:
            if len(parts)!=3 or parts[1]!=seal['client_random'] or parts[0] in refs:raise RuntimeError('Reference connection/role mismatch')
            value=bytes.fromhex(parts[2])
            if len(value)!=seal['secret_bytes']:raise RuntimeError('Reference length mismatch')
            refs[parts[0]]=value
    if set(refs)!=set(LABELS):raise RuntimeError('Missing directional reference')
    event=json.loads((a.case/'server-event.json').read_text())
    if event['protocol']!='TLSv1.3' or event['session_reused']:raise RuntimeError('Expected full TLS 1.3 session')
    rows=json.loads(raw.read_text());byid={r['id']:r for r in rows}
    output=a.case/'verification-tls13';output.mkdir(exist_ok=False)
    comparisons={}
    with CoreMemory(a.case/'firefox.core') as core:
        for role,reference in refs.items():
            selected=byid.get(seal['selected_ids'][role])
            value=bytes.fromhex(selected['hex']) if selected else None
            matches=[r for r in rows if bytes.fromhex(r['hex'])==reference]
            comparisons[role]={'bits':len(reference)*8,'literal_occurrences':sum(1 for _ in core.find(reference)),
                'reference_in_candidate_set':bool(matches),'exact_match':value==reference,
                'hamming_distance_bits':sum((x^y).bit_count() for x,y in zip(value,reference)) if value is not None else None}
    with tempfile.TemporaryDirectory(prefix='tlkh13-verify-') as directory:
        scratch=Path(directory);pcap=scratch/'traffic.pcap';shutil.copyfile(a.case/'traffic.pcap',pcap)
        def decrypt(text,name):
            key=scratch/(name+'.keys');key.write_text(text)
            result=subprocess.run(['tshark','-r',str(pcap),'-o',f'tls.keylog_file:{key}','-Y','http','-V'],capture_output=True,text=True,timeout=30)
            (output/(name+'.private.txt')).write_text(result.stdout+'\n'+result.stderr)
            def contains(value):return value in result.stdout or value.encode().hex() in result.stdout.lower().replace(':','')
            return {'exit':result.returncode,'request':contains(event['request_path']),'response':contains(event['response_marker'])}
        def keys(values):return ''.join(f'{role} {seal["client_random"]} {value.hex()}\n' for role,value in values.items())
        positive=decrypt(a.reference.read_text(),'reference-sanity')
        selected_result=None
        if all(seal['selected_ids'].values()):
            selected_values={role:bytes.fromhex(byid[identity]['hex']) for role,identity in seal['selected_ids'].items()}
            selected_result=decrypt(keys(selected_values),'selected')
        controls={}
        for role in LABELS:
            changed=dict(refs);bad=bytearray(changed[role]);bad[0]^=1;changed[role]=bytes(bad)
            controls[role]=decrypt(keys(changed),'wrong-'+role)
    negative_ok=not controls[LABELS[0]]['request'] and not controls[LABELS[1]]['response']
    complete=bool(all(v['exact_match'] for v in comparisons.values()) and selected_result and selected_result['exit']==0 and selected_result['request'] and selected_result['response'] and negative_ok)
    report={'case_id':a.case.name,'protocol':'TLS1.3','cipher':event['cipher'],'candidate_count':len(rows),
        'memory_only_selection':seal['memory_only_selection'],'reference_comparison_after_seal':True,'selection_uses_pcap':True,
        'reference_used_for_selection':False,'presence_audit_uses_reference':True,'core_sha256':seal['core_sha256'],'pcap_sha256':seal['pcap_sha256'],
        'directional_comparisons':comparisons,'reference_sanity':positive,'selected_decryption':selected_result,
        'one_bit_controls':controls,'complete_offline_recovery':complete}
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if __name__=='__main__':main()
