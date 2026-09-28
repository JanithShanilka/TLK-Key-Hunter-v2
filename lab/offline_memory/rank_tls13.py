#!/usr/bin/env python3
"""TLS 1.3 development candidate discovery; no reference or packet input."""
import argparse
from collections import Counter
import hashlib,json,math,os,struct,time
from pathlib import Path
from core_memory import CoreMemory
from rank_core import digest


def rank(core):
    values={}
    for size in (32,48):
        for address in core.find(struct.pack('<Q',size)):
            item=address-16
            if item%8: continue
            try:
                kind,pointer,length=struct.unpack('<QQQ',core.read(item,24))
                if kind!=0x11 or length!=size or pointer<4096: continue
                value=core.read(pointer,size)
            except (ValueError,struct.error): continue
            entropy=-sum(n/size*math.log2(n/size) for n in Counter(value).values())
            zeros=value.count(0)
            score=40+(25 if entropy>=4 else 0)+(10 if zeros<=size//8 else 0)
            if score<65: continue
            identity=hashlib.sha256(value).hexdigest()
            row=values.setdefault(identity,{'id':identity,'hex':value.hex(),'length':size,'score':score,'entropy':entropy,'zero_bytes':zeros,'locations':[]})
            row['locations'].append({'item':hex(item),'data':hex(pointer)})
            if len(values)>10000: raise RuntimeError('Candidate budget exceeded')
    return sorted(values.values(),key=lambda x:(-x['score'],x['id']))


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--core',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();os.umask(0o077)
    a.output.mkdir(parents=True,exist_ok=False)
    start=time.monotonic()
    with CoreMemory(a.core) as core: rows=rank(core)
    private=a.output/'ranked-candidates.private.json'
    private.write_text(json.dumps(rows,indent=2)+'\n');private.chmod(0o400)
    seal={'method':'tls13_cka_value_32_48_v1','protocol':'TLS1.3','reference_input':False,'packet_input':False,
          'memory_only_selection':'unassigned_candidates','candidate_count':len(rows),'elapsed_seconds':time.monotonic()-start,
          'core_sha256':digest(a.core),'candidate_file_sha256':digest(private)}
    (a.output/'selection-seal.json').write_text(json.dumps(seal,indent=2)+'\n')
    print(json.dumps(seal))

if __name__=='__main__': main()
