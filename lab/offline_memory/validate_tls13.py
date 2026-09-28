#!/usr/bin/env python3
"""Reference-free, directional TLS 1.3 candidate validation on one saved connection."""
import argparse,json,os,shutil,subprocess,tempfile
from pathlib import Path
from rank_core import digest

LABELS=('CLIENT_TRAFFIC_SECRET_0','SERVER_TRAFFIC_SECRET_0')
SUITES={'0x1301':32,'0x1302':48,'0x1303':32}


def fields(pcap,display,field):
    return subprocess.check_output(['tshark','-r',str(pcap),'-Y',display,'-T','fields','-e',field],text=True,stderr=subprocess.DEVNULL).split()


def decrypt(pcap,keyfile):
    result=subprocess.run(['tshark','-r',str(pcap),'-o',f'tls.keylog_file:{keyfile}','-Y','http','-T','fields','-e','http.request.method','-e','http.response.code'],capture_output=True,text=True,timeout=30)
    cells=[line.split('\t') for line in result.stdout.splitlines()]
    return {'exit':result.returncode,'request':any(x[0] for x in cells),'response':any(len(x)>1 and x[1].isdigit() for x in cells)}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--offline',type=Path,required=True);p.add_argument('--pcap',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();os.umask(0o077)
    seal=json.loads((a.offline/'selection-seal.json').read_text())
    raw=a.offline/'ranked-candidates.private.json'
    if digest(raw)!=seal['candidate_file_sha256']:raise RuntimeError('Candidate seal mismatch')
    rows=json.loads(raw.read_text())
    if len(rows)>100:raise RuntimeError('Pilot budget exceeds 100 candidates')
    a.output.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='tlkh13-validation-') as temp:
        scratch=Path(temp);pcap=scratch/'traffic.pcap';shutil.copyfile(a.pcap,pcap)
        randoms=set(fields(pcap,'tls.handshake.type == 1','tls.handshake.random'))
        suites=set(fields(pcap,'tls.handshake.type == 2','tls.handshake.ciphersuite'))
        versions=set(fields(pcap,'tls.handshake.type == 2','tls.handshake.extensions.supported_version'))
        if len(randoms)!=1 or len(suites)!=1 or versions!={'0x0304'}:raise RuntimeError('Expected unique TLS 1.3 handshake')
        random=randoms.pop();suite=suites.pop()
        if suite not in SUITES:raise RuntimeError('Unsupported TLS 1.3 suite')
        trials=[];winners={label:[] for label in LABELS};key=scratch/'candidate.keys'
        for row in rows:
            if row['length']!=SUITES[suite]:continue
            # Same candidate tested independently for both directional roles; no reference.
            key.write_text(''.join(f'{label} {random} {row["hex"]}\n' for label in LABELS))
            outcome=decrypt(pcap,key)
            trials.append({'id':row['id'],**outcome})
            for label,field in zip(LABELS,('request','response')):
                if outcome['exit']==0 and outcome[field]:winners[label].append(row['id'])
        selected={label:ids[0] if len(ids)==1 else None for label,ids in winners.items()}
        joint=None
        if all(selected.values()):
            byid={x['id']:x for x in rows}
            key.write_text(''.join(f'{label} {random} {byid[identity]["hex"]}\n' for label,identity in selected.items()))
            joint=decrypt(pcap,key)
            shutil.copyfile(key,a.output/'selected.private.keys')
        output={**seal,'selection_uses_pcap':True,'reference_input':False,'pcap_sha256':digest(a.pcap),'client_random':random,
                'cipher_suite':suite,'secret_bytes':SUITES[suite],'trials':trials,'selected_ids':selected,
                'directional_pass_counts':{k:len(v) for k,v in winners.items()},'joint_decryption':joint}
        shutil.copyfile(raw,a.output/raw.name)
        (a.output/'selection-seal.json').write_text(json.dumps(output,indent=2)+'\n')
        print(json.dumps({k:output[k] for k in ('candidate_count','cipher_suite','directional_pass_counts','joint_decryption')}))

if __name__=='__main__':main()
