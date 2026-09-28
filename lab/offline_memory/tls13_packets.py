#!/usr/bin/env python3
"""TLS 1.3 packet helpers used without reference secrets during selection."""
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

SUITES = {
    "0x1301": {"secret_bytes": 32, "key_bytes": 16, "hash": "sha256"},
    "0x1302": {"secret_bytes": 48, "key_bytes": 32, "hash": "sha384"},
    "0x1303": {"secret_bytes": 32, "key_bytes": 32, "hash": "sha256"},
}


def tshark_fields(pcap, display, fields, keylog=None):
    with tempfile.TemporaryDirectory(prefix="tlkh13-fields-") as directory:
        readable_pcap = Path(directory) / "traffic.pcap"
        shutil.copyfile(pcap, readable_pcap)
        command = ["tshark", "-r", str(readable_pcap)]
        if keylog is not None:
            command += ["-o", f"tls.keylog_file:{keylog}"]
        command += ["-Y", display, "-T", "fields", "-E", "separator=|",
                    "-E", "occurrence=a", "-E", "aggregator=,"]
        for field in fields:
            command += ["-e", field]
        output = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    return [line.split("|") for line in output.splitlines() if line]


def inspect_connections(pcap):
    fields = ["tcp.stream", "tcp.srcport", "tcp.dstport", "tls.handshake.random",
              "tls.handshake.ciphersuite", "tls.handshake.extensions.supported_version",
              "tls.handshake.extension.type"]
    clients = tshark_fields(pcap, "tls.handshake.type == 1", fields)
    servers = tshark_fields(pcap, "tls.handshake.type == 2", fields)
    by_stream = {}
    for row in clients:
        if len(row) != len(fields) or not row[0]:
            continue
        stream = int(row[0])
        if stream in by_stream:
            raise RuntimeError(f"Multiple ClientHello records for tcp.stream {stream}")
        by_stream[stream] = {
            "stream": stream,
            "client_port": int(row[1]),
            "server_port": int(row[2]),
            "client_random": row[3].lower(),
            "client_extensions": extension_types(row[6]),
        }
    for row in servers:
        if len(row) != len(fields) or not row[0]:
            continue
        stream = int(row[0])
        if stream not in by_stream or "cipher_suite" in by_stream[stream]:
            raise RuntimeError(f"Unmatched or duplicate ServerHello for tcp.stream {stream}")
        by_stream[stream].update({
            "cipher_suite": row[4].lower(),
            "supported_version": row[5].lower(),
            "server_extensions": extension_types(row[6]),
        })
    # A browser may begin another connection while the controlled server is
    # deliberately holding its accepted flows. Only completed handshakes can
    # be bound to a server event and counted as scenario connections.
    connections = sorted((item for item in by_stream.values() if "cipher_suite" in item),
                         key=lambda item: item["stream"])
    for item in connections:
        if not item.get("client_random") or len(item["client_random"]) != 64:
            raise RuntimeError("Missing TLS ClientHello random")
        if item.get("supported_version") != "0x0304":
            raise RuntimeError("Expected TLS 1.3 ServerHello")
        if item.get("cipher_suite") not in SUITES:
            raise RuntimeError("Unsupported TLS 1.3 cipher suite")
    return connections


def extension_types(value):
    result = []
    for token in value.split(",") if value else []:
        token = token.strip().lower()
        if token:
            result.append(int(token, 16) if token.startswith("0x") else int(token))
    return result


def parse_follow_output(output):
    nodes = {}
    streams = {0: bytearray(), 1: bytearray()}
    for line in output.splitlines():
        match = re.match(r"Node ([01]): .*:(\d+)$", line.strip())
        if match:
            nodes[int(match.group(1))] = int(match.group(2))
            continue
        data = line.strip()
        if not data or not re.fullmatch(r"[0-9a-fA-F]+", data) or len(data) % 2:
            continue
        node = 1 if line.startswith("\t") else 0
        streams[node].extend(bytes.fromhex(data))
    if set(nodes) != {0, 1} or not all(streams.values()):
        raise RuntimeError("Could not parse TShark TCP follow output")
    return nodes, {key: bytes(value) for key, value in streams.items()}


def follow_stream(pcap, stream):
    with tempfile.TemporaryDirectory(prefix="tlkh13-follow-") as directory:
        readable_pcap = Path(directory) / "traffic.pcap"
        shutil.copyfile(pcap, readable_pcap)
        output = subprocess.check_output(
            ["tshark", "-r", str(readable_pcap), "-q", "-z", f"follow,tcp,raw,{stream}"],
            text=True, stderr=subprocess.DEVNULL)
    return parse_follow_output(output)


def tls_records(data):
    records = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 5:
            raise RuntimeError("Truncated TLS record header in reassembled TCP stream")
        content_type = data[offset]
        version = data[offset + 1:offset + 3]
        length = int.from_bytes(data[offset + 3:offset + 5], "big")
        end = offset + 5 + length
        if content_type not in range(20, 24) or version not in (b"\x03\x01", b"\x03\x03"):
            raise RuntimeError("Unexpected bytes in reassembled TLS stream")
        if end > len(data):
            raise RuntimeError("Truncated TLS record payload in reassembled TCP stream")
        records.append(data[offset:end])
        offset = end
    return records


def directional_records(pcap, stream, server_port):
    nodes, data = follow_stream(pcap, stream)
    server_nodes = [node for node, port in nodes.items() if port == server_port]
    if len(server_nodes) != 1:
        raise RuntimeError("Could not identify server direction in TCP stream")
    server_node = server_nodes[0]
    client_node = 1 - server_node
    return {"client": tls_records(data[client_node]), "server": tls_records(data[server_node])}


def hkdf_expand_label(secret, label, length, hash_name):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    hash_type = {"sha256": hashes.SHA256, "sha384": hashes.SHA384}[hash_name]
    full_label = b"tls13 " + label
    info = (length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + b"\x00")
    return HKDFExpand(algorithm=hash_type(), length=length, info=info).derive(secret)


def traffic_key_iv(secret, suite):
    parameters = SUITES[suite]
    return (
        hkdf_expand_label(secret, b"key", parameters["key_bytes"], parameters["hash"]),
        hkdf_expand_label(secret, b"iv", 12, parameters["hash"]),
    )


def decrypt_record(record, key, iv, sequence):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if record[0] != 23 or len(record) < 22:
        return None
    nonce = bytearray(iv)
    sequence_bytes = sequence.to_bytes(8, "big")
    for index, value in enumerate(sequence_bytes):
        nonce[4 + index] ^= value
    try:
        plaintext = AESGCM(key).decrypt(bytes(nonce), record[5:], record[:5])
    except Exception:
        return None
    unpadded = plaintext.rstrip(b"\x00")
    if not unpadded:
        return None
    return {"content": unpadded[:-1], "inner_type": unpadded[-1]}


def authenticate_marker(records, secret, suite, marker):
    """Directly authenticate a controlled marker, without another traffic secret."""
    key, iv = traffic_key_iv(secret, suite)
    marker = marker.encode() if isinstance(marker, str) else marker
    matches = []
    sequence_limit = len(records) + 8
    for record_index, record in enumerate(records):
        for sequence in range(sequence_limit):
            result = decrypt_record(record, key, iv, sequence)
            if result and marker in result["content"]:
                matches.append({"record_index": record_index, "sequence": sequence,
                                "inner_type": result["inner_type"],
                                "plaintext_sha256": hashlib.sha256(result["content"]).hexdigest()})
    return matches


def authenticate_keyupdate(records, secret, suite, request_update):
    """Authenticate a KeyUpdate handshake message under the old directional key."""
    key, iv = traffic_key_iv(secret, suite)
    expected = bytes([24, 0, 0, 1, request_update])
    matches = []
    sequence_limit = len(records) + 8
    for record_index, record in enumerate(records):
        for sequence in range(sequence_limit):
            result = decrypt_record(record, key, iv, sequence)
            if result and result["inner_type"] == 22 and expected in result["content"]:
                matches.append({"record_index": record_index, "sequence": sequence})
    return matches
