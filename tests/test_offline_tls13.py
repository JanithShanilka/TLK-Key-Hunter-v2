import sys,struct,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lab/offline_memory'))
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None
from core_memory import CoreMemory
from rank_tls13 import rank
from test_offline_memory import make_core
from validate_tls13 import LABELS
from check_tls13_scenario import evaluate
from tls13_packets import (SUITES, authenticate_keyupdate, authenticate_marker,
                           inspect_connections, parse_follow_output, traffic_key_iv)
from verify_tls13 import read_references

class TLS13Tests(unittest.TestCase):
    def test_directional_labels_and_suite_hash_lengths(self):
        self.assertEqual(LABELS, ('CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0'))
        self.assertEqual({key: value['secret_bytes'] for key, value in SUITES.items()},
                         {'0x1301': 32, '0x1302': 48, '0x1303': 32})

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

    @unittest.skipIf(AESGCM is None, 'cryptography is required for direct TLS record authentication')
    def test_direct_record_authentication_and_wrong_secret(self):
        secret=bytes(range(48));marker=b'/controlled/request'
        key,iv=traffic_key_iv(secret,'0x1302')
        plaintext=marker+b' HTTP/1.1\r\n'+bytes([23])
        header=bytes([23,3,3])+ (len(plaintext)+16).to_bytes(2,'big')
        record=header+AESGCM(key).encrypt(iv,plaintext,header)
        self.assertEqual(len(authenticate_marker([record],secret,'0x1302',marker)),1)
        changed=bytearray(secret);changed[0]^=1
        self.assertEqual(authenticate_marker([record],bytes(changed),'0x1302',marker),[])

    @unittest.skipIf(AESGCM is None, 'cryptography is required for direct TLS record authentication')
    def test_direct_keyupdate_packet_evidence(self):
        secret=bytes(range(48));key,iv=traffic_key_iv(secret,'0x1302')
        plaintext=bytes([24,0,0,1,1,22])
        header=bytes([23,3,3])+(len(plaintext)+16).to_bytes(2,'big')
        record=header+AESGCM(key).encrypt(iv,plaintext,header)
        self.assertTrue(authenticate_keyupdate([record],secret,'0x1302',1))
        self.assertFalse(authenticate_keyupdate([record],secret,'0x1302',0))

    def test_parse_follow_output_preserves_directions(self):
        output='''Node 0: 127.0.0.1:50123
Node 1: 127.0.0.1:18443
1603030001aa
\t1603030001bb
'''
        nodes,data=parse_follow_output(output)
        self.assertEqual(nodes,{0:50123,1:18443})
        self.assertEqual(data[0],bytes.fromhex('1603030001aa'))
        self.assertEqual(data[1],bytes.fromhex('1603030001bb'))

    def test_incomplete_extra_client_hello_is_not_a_connection(self):
        client_rows=[
            ['0','5000','18443','a'*64,'0x1301,0x1302','0x0304','0,43'],
            ['1','5001','18443','b'*64,'0x1301,0x1302','0x0304','0,43,41']]
        server_rows=[['0','18443','5000','c'*64,'0x1302','0x0304','43,51']]
        with patch('tls13_packets.tshark_fields',side_effect=[client_rows,server_rows]):
            connections=inspect_connections(Path('/unused.pcap'))
        self.assertEqual(len(connections),1)
        self.assertEqual(connections[0]['client_port'],5000)

    def test_openssl_updated_secret_aliases_map_to_generation_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'reference.keys'
            path.write_text('CLIENT_TRAFFIC_SECRET_N '+'a'*64+' '+'01'*48+'\n'+
                            'SERVER_TRAFFIC_SECRET_N '+'a'*64+' '+'02'*48+'\n')
            references=read_references(path)
        self.assertIn(('CLIENT_TRAFFIC_SECRET_1','a'*64),references)
        self.assertIn(('SERVER_TRAFFIC_SECRET_1','a'*64),references)

    def test_scenario_conditions_are_distinct(self):
        connection=lambda stream,port,random:{'stream':stream,'client_port':port,'server_port':18443,
            'client_random':random,'cipher_suite':'0x1302','supported_version':'0x0304',
            'client_extensions':[0,41],'server_extensions':[43,41]}
        flow=lambda index,port:{'index':index,'peer_port':port,'protocol':'TLSv1.3',
            'cipher':'TLS_AES_256_GCM_SHA384','request_path':f'/flow/{index}',
            'response_marker':f'response-{index}','accepted_monotonic':10+index,
            'request_monotonic':11+index,'response_monotonic':12+index,'closed_monotonic':20}
        acquisition={'capture_started_monotonic':42.5,'capture_ended_monotonic':43}
        delayed=evaluate('delayed',[flow(0,5000)],[connection(0,5000,'a'*64)],acquisition)
        self.assertTrue(delayed['condition_ok'])
        first,second=flow(0,5000),flow(1,5001)
        first['session_reused']=False;second['session_reused']=True
        connections=[connection(0,5000,'a'*64),connection(1,5001,'b'*64)]
        connections[0]['server_extensions']=[43]
        resumed=evaluate('resumption',[first,second],connections,acquisition)
        self.assertTrue(resumed['condition_ok'])
        self.assertEqual({target['flow_index'] for target in resumed['targets']},{1})
        self.assertEqual({target['label'] for target in resumed['targets']},
                         {'CLIENT_TRAFFIC_SECRET_0','SERVER_TRAFFIC_SECRET_0'})
        second['session_reused']=False
        self.assertIn('server_resumption_state_invalid',
                      evaluate('resumption',[first,second],connections,acquisition)['condition_failures'])
        updated=flow(0,5000)
        updated.update({'update_requested_monotonic':13,'post_request_path':'/post-update',
                        'post_response_marker':'post-update-response','post_response_monotonic':14})
        keyupdate=evaluate('keyupdate',[updated],[connection(0,5000,'a'*64)],acquisition)
        self.assertTrue(keyupdate['condition_ok'])
        self.assertEqual({target['label'] for target in keyupdate['targets']},
                         {'CLIENT_TRAFFIC_SECRET_1','SERVER_TRAFFIC_SECRET_1'})

if __name__=='__main__':unittest.main(verbosity=2)
