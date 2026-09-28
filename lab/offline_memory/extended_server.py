"""Controlled localhost workload. References are emitted only by the root server."""
import ctypes as C
import ctypes.util
import json
import socket
import ssl
import time
from pathlib import Path
from capture_firefox import utc, wait_for, write_json


class OpenSSLConnection:
    """Minimal checked libssl harness; never instruments the Firefox target."""
    def __init__(self, raw, private):
        self.raw = raw
        self.lib = L = C.CDLL(ctypes.util.find_library('ssl'))
        signatures = {
            'TLS_server_method': (C.c_void_p, []),
            'SSL_CTX_new': (C.c_void_p, [C.c_void_p]),
            'SSL_CTX_ctrl': (C.c_long, [C.c_void_p, C.c_int, C.c_long, C.c_void_p]),
            'SSL_CTX_use_certificate_file': (C.c_int, [C.c_void_p, C.c_char_p, C.c_int]),
            'SSL_CTX_use_PrivateKey_file': (C.c_int, [C.c_void_p, C.c_char_p, C.c_int]),
            'SSL_CTX_set_ciphersuites': (C.c_int, [C.c_void_p, C.c_char_p]),
            'SSL_CTX_set_num_tickets': (C.c_long, [C.c_void_p, C.c_size_t]),
            'SSL_new': (C.c_void_p, [C.c_void_p]),
            'SSL_set_fd': (C.c_int, [C.c_void_p, C.c_int]),
            'SSL_accept': (C.c_int, [C.c_void_p]),
            'SSL_read': (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
            'SSL_write': (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
            'SSL_key_update': (C.c_int, [C.c_void_p, C.c_int]),
            'SSL_do_handshake': (C.c_int, [C.c_void_p]),
            'SSL_free': (None, [C.c_void_p]),
            'SSL_CTX_free': (None, [C.c_void_p]),
        }
        for name, (restype, argtypes) in signatures.items():
            f = getattr(L, name); f.restype = restype; f.argtypes = argtypes
        self.ctx = L.SSL_CTX_new(L.TLS_server_method())
        if not self.ctx: raise RuntimeError('SSL_CTX_new failed')
        # SSL_CTRL_SET_MIN/MAX_PROTO_VERSION from public OpenSSL ssl.h.
        for command in (123, 124): self.check(L.SSL_CTX_ctrl(self.ctx, command, 0x0304, None))
        self.check(L.SSL_CTX_set_ciphersuites(self.ctx, b'TLS_AES_256_GCM_SHA384'))
        self.check(L.SSL_CTX_set_num_tickets(self.ctx, 0))
        self.check(L.SSL_CTX_use_certificate_file(self.ctx, str(private/'server.cert.pem').encode(), 1))
        self.check(L.SSL_CTX_use_PrivateKey_file(self.ctx, str(private/'server.key.pem').encode(), 1))
        callback_type = C.CFUNCTYPE(None, C.c_void_p, C.c_char_p)
        self.reference = (private/'server-reference.keys').open('a')
        def keylog(_, line):
            self.reference.write(line.decode()+'\n'); self.reference.flush()
        self.callback = callback_type(keylog)
        L.SSL_CTX_set_keylog_callback.argtypes = [C.c_void_p, callback_type]
        L.SSL_CTX_set_keylog_callback(self.ctx, self.callback)
        self.ssl = L.SSL_new(self.ctx)
        if not self.ssl: raise RuntimeError('SSL_new failed')
        self.check(L.SSL_set_fd(self.ssl, raw.fileno()))
        self.check(L.SSL_accept(self.ssl))
    @staticmethod
    def check(result):
        if result != 1: raise RuntimeError('Controlled OpenSSL operation failed')
    def recv(self, size):
        buf = C.create_string_buffer(size)
        n = self.lib.SSL_read(self.ssl, buf, size)
        if n <= 0: raise RuntimeError('Controlled SSL_read failed')
        return buf.raw[:n]
    def sendall(self, data):
        while data:
            payload = C.create_string_buffer(data)
            n = self.lib.SSL_write(self.ssl, payload, len(data))
            if n <= 0: raise RuntimeError('Controlled SSL_write failed')
            data = data[n:]
    def update(self):
        self.check(self.lib.SSL_key_update(self.ssl, 1))
        self.check(self.lib.SSL_do_handshake(self.ssl))
    def close(self):
        self.lib.SSL_free(self.ssl); self.lib.SSL_CTX_free(self.ctx)
        self.reference.close(); self.raw.close()


def serve(args):
    case, private = args.case, args.reference
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 2 if args.scenario == 'resumption' else 0
    context.load_cert_chain(private/'server.cert.pem', private/'server.key.pem')
    context.keylog_filename = str(private/'server-reference.keys')
    flows, connections = [], []
    def publish(): write_json(case/'scenario-events.json', {'scenario':args.scenario,'flows':flows})
    def request(conn):
        data = b''
        while b'\r\n\r\n' not in data:
            data += conn.recv(4096)
            if len(data)>65536: raise RuntimeError('Request exceeds limit')
        return data.split(b'\r\n')[0].decode().split(' ')[1]
    def response(conn, marker, complete=False, close=False, location=None):
        body = marker.encode()
        status = b'302 Found' if location else b'200 OK'
        redirect = b'Location: ' + location.encode() + b'\r\n' if location else b''
        conn.sendall(b'HTTP/1.1 '+status+b'\r\n'+redirect+b'Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: '+(b'close' if close else b'keep-alive')+b'\r\n\r\n'+f'{len(body):x}\r\n'.encode()+body+b'\r\n'+(b'0\r\n\r\n' if complete else b''))
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',args.port)); listener.listen(4); listener.settimeout(60)
        (case/'server.ready').write_text(utc())
        count = 2 if args.scenario in ('resumption','concurrency') else 1
        try:
            for index in range(count):
                raw, address = listener.accept(); raw.settimeout(60)
                if args.scenario == 'keyupdate':
                    raw.settimeout(None); raw.setsockopt(socket.SOL_SOCKET,socket.SO_RCVTIMEO, __import__('struct').pack('ll',60,0))
                    conn=OpenSSLConnection(raw,private)
                else: conn=context.wrap_socket(raw,server_side=True)
                connections.append(conn)
                flow={'index':index,'peer_port':address[1],'server_port':args.port,'accepted_monotonic':time.monotonic(),
                      'protocol':'TLSv1.3' if args.scenario=='keyupdate' else conn.version(),
                      'cipher':'TLS_AES_256_GCM_SHA384' if args.scenario=='keyupdate' else conn.cipher()[0],
                      'session_reused':False if args.scenario=='keyupdate' else conn.session_reused,
                      'request_path':request(conn),'request_monotonic':time.monotonic(),
                      'response_marker':f'TLSKH-EXT|{case.name}|flow{index}|RESPONSE'}
                flows.append(flow); publish()
                if args.scenario=='before-response':
                    (case/'capture.ready').touch()
                    wait_for(lambda:(case/'release-server').exists(),180)
                if args.scenario=='keyupdate':
                    conn.update(); flow['update_requested_monotonic']=time.monotonic();publish()
                    (case/'first-complete').touch()
                first = args.scenario=='resumption' and index==0
                redirect = (f'https://localhost:{args.port}/offline/{case.name}/second'
                            if first or args.scenario == 'keyupdate' else None)
                response(conn,flow['response_marker'],complete=first or args.scenario=='keyupdate',
                         close=first,location=redirect)
                flow['response_monotonic']=time.monotonic(); publish()
                if first:
                    conn.close(); connections.remove(conn); flow['closed_monotonic']=time.monotonic();publish()
                    (case/'first-complete').touch()
                elif args.scenario=='concurrency' and index==0:
                    (case/'first-complete').touch()
                elif args.scenario=='keyupdate':
                    flow['post_request_path']=request(conn)
                    flow['post_response_marker']=f'TLSKH-EXT|{case.name}|flow0|POST-UPDATE'
                    response(conn,flow['post_response_marker'])
                    flow['post_response_monotonic']=time.monotonic();publish()
            if args.scenario=='delayed': time.sleep(30)
            (case/'capture.ready').touch()
            wait_for(lambda:(case/'release-server').exists(),180)
            for conn in connections: conn.sendall(b'0\r\n\r\n')
            for f in flows:
                if 'closed_monotonic' not in f:f['closed_monotonic']=time.monotonic()
            publish()
        finally:
            for conn in connections: conn.close()
