import sys,struct,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lab/offline_memory'))
from core_memory import CoreMemory
from rank_tls13 import rank
from test_offline_memory import make_core
from validate_tls13 import LABELS, SUITES

class TLS13Tests(unittest.TestCase):
    def test_directional_labels_and_suite_hash_lengths(self):
        self.assertEqual(LABELS, ('CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0'))
        self.assertEqual(SUITES, {'0x1301': 32, '0x1302': 48, '0x1303': 32})

    def test_mixed_hash_lengths_and_reject_other_shapes(self):
        payload=bytearray(1024)
        for index,(kind,size,offset) in enumerate(((0x11,32,256),(0x11,48,512),(0x12,32,768),(0x11,16,900))):
            payload[offset:offset+size]=bytes(range(size))
            struct.pack_into('<QQQ',payload,index*24,kind,0x10000+offset,size)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'test.core';make_core(path,payload)
            with CoreMemory(path) as core:rows=rank(core)
        self.assertEqual(sorted(x['length'] for x in rows),[32,48])
        self.assertTrue(all(len(x['locations'])==1 for x in rows))

if __name__=='__main__':unittest.main(verbosity=2)
