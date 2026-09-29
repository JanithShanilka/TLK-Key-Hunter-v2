"""Synthetic blind-study tests; no Firefox recovery claim follows from these."""

import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import shutil
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab/blind_tls13"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab/offline_memory"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from blind_server import send_frame, serve
from capture_decoy import receive_frame, send_masked
from evaluate import flow_truth, redact_core, score_method, score_pair
from record_auth import authenticate_application_epoch
from recover import assign, entropy_rank
from run_study import create, design, retained_nine
from summarize import paired_interval, summarize
from test_offline_memory import make_core
from core_memory import CoreMemory
from tls13_packets import traffic_key_iv


def encrypted(secret, sequence, content, inner_type=23):
    key, iv = traffic_key_iv(secret, "0x1302")
    nonce = bytearray(iv)
    for index, value in enumerate(sequence.to_bytes(8, "big")):
        nonce[4 + index] ^= value
    plaintext = content + bytes((inner_type,))
    header = bytes((23, 3, 3)) + (len(plaintext) + 16).to_bytes(2, "big")
    return header + AESGCM(key).encrypt(bytes(nonce), plaintext, header)


class BlindTLS13Tests(unittest.TestCase):
    def test_two_sequenced_application_records_without_marker(self):
        secret = bytes(range(48))
        other = bytes(range(48, 96))
        records = [encrypted(other, 0, b"encrypted handshake", 22),
                   encrypted(secret, 0, b"first arbitrary payload"),
                   encrypted(secret, 1, b"second varied payload")]
        matches = authenticate_application_epoch(records, secret, "0x1302")
        self.assertEqual(len(matches), 1)
        self.assertEqual([x["sequence"] for x in matches[0]["application_records"]], [0, 1])
        self.assertEqual(matches[0]["first_record_index"], 1)
        self.assertEqual(authenticate_application_epoch(records, other, "0x1302"), [])
        self.assertEqual(authenticate_application_epoch(records[1:2], secret, "0x1302"), [])

    def test_wrong_sequence_or_later_failure_is_unresolved(self):
        secret = bytes(range(48))
        self.assertEqual(authenticate_application_epoch(
            [encrypted(secret, 0, b"one"), encrypted(secret, 2, b"two")], secret, "0x1302"), [])
        self.assertEqual(authenticate_application_epoch(
            [encrypted(secret, 0, b"one"), encrypted(secret, 1, b"two"),
             encrypted(bytes(range(48, 96)), 2, b"wrong")], secret, "0x1302"), [])

    def test_assigns_each_direction_and_abstains_on_missing_candidate(self):
        client = bytes(range(48))
        server = bytes(range(48, 96))
        records = {"client": [encrypted(client, 0, b"one"), encrypted(client, 1, b"two")],
                   "server": [encrypted(server, 0, b"alpha"), encrypted(server, 1, b"beta")]}
        connection = {"stream": 4, "client_random": "a" * 64, "server_port": 18443,
                      "cipher_suite": "0x1302"}
        rows = [{"id": "c", "hex": client.hex(), "length": 48},
                {"id": "s", "hex": server.hex(), "length": 48}]
        with patch("recover.directional_records", return_value=records):
            decisions, _ = assign(rows, [connection], Path("unused.pcap"), float("inf"))
            partial, _ = assign(rows[:1], [connection], Path("unused.pcap"), float("inf"))
        self.assertEqual([x["candidate_id"] for x in decisions], ["c", "s"])
        self.assertEqual([x["status"] for x in partial], ["selected", "unresolved"])

    def test_entropy_baseline_is_content_only_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            core_path = Path(directory) / "sample.core"
            payload = bytearray(1024)
            payload[200:248] = bytes(range(48))
            make_core(core_path, payload)
            with CoreMemory(core_path) as core:
                rows, status = entropy_rank(core, float("inf"), maximum=10)
        self.assertTrue(status["search_exhausted"])
        self.assertIn(bytes(range(48)).hex(), {row["hex"] for row in rows})
        self.assertLessEqual(len(rows), 10)

    def test_design_and_preselected_retention(self):
        seed = "0123456789abcdef0123456789abcdef"
        cases = design("final", seed)
        self.assertEqual(len(cases), 100)
        self.assertEqual(sum(x["kind"] == "positive" and x["connections"] == 2 for x in cases), 35)
        self.assertEqual(sum(x["kind"] == "positive" and x["connections"] == 3 for x in cases), 35)
        self.assertEqual({x["kind"]: sum(y["kind"] == x["kind"] for y in cases)
                          for x in cases if x["kind"] != "positive"},
                         {"mismatch": 10, "unrelated": 10, "withheld": 10})
        self.assertEqual(len(retained_nine(cases, seed)), 9)
        self.assertEqual(cases, design("final", seed))

    def test_scoring_partial_and_abstention(self):
        random = "b" * 64
        a, b = bytes(range(48)), bytes(range(48, 96))
        targets = {(random, "client"): a, (random, "server"): b}
        rows = [{"id": "a", "hex": a.hex()}, {"id": "b", "hex": b.hex()}]
        report = {"decisions": [
            {"client_random": random, "direction": "client", "status": "unresolved", "candidate_id": None},
            {"client_random": random, "direction": "server", "status": "selected", "candidate_id": "b"}],
            "wall_seconds": 1, "cpu_seconds": 1, "peak_rss_kib": 100, "candidate_count": 2}
        partial = score_method(report, rows, targets, "withheld", (random, "client"))
        self.assertTrue(partial["case_success"])
        self.assertEqual(partial["correct_targets"], 1)
        mismatch = score_method(report, rows, targets, "mismatch")
        self.assertFalse(mismatch["case_success"])
        self.assertEqual(mismatch["false_assignments"], 1)

    def test_evaluator_checks_seals_before_opening_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ("structured", "entropy"):
                folder = base / name
                folder.mkdir()
                (folder / "seal.json").write_text(json.dumps({"candidates_sha256": "wrong",
                    "decisions_sha256": "wrong"}))
                (folder / "candidates.private.json").write_text("[]")
                (folder / "decisions.json").write_text("{}")
            with patch("evaluate.flow_truth") as truth:
                with self.assertRaises(ValueError):
                    score_pair(base / "structured", base / "entropy", base / "core", base / "pcap",
                               base / "workload", base / "keylog", "positive")
                truth.assert_not_called()

    def test_evaluator_checks_full_capture_record_count(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            random = "c" * 64
            client, server = bytes(range(48)), bytes(range(48, 96))
            (base / "keylog").write_text(
                f"CLIENT_TRAFFIC_SECRET_0 {random} {client.hex()}\n"
                f"SERVER_TRAFFIC_SECRET_0 {random} {server.hex()}\n")
            (base / "workload").write_text(json.dumps({"flows": [{"peer_port": 51000,
                "client_messages": [{}, {}], "server_messages": [{}, {}]}]}))
            connection = {"client_port": 51000, "server_port": 18443, "stream": 2,
                          "client_random": random, "cipher_suite": "0x1302"}
            records = {"client": [encrypted(client, n, bytes((n,))) for n in range(3)],
                       "server": [encrypted(server, n, bytes((n,))) for n in range(3)]}
            with patch("evaluate.inspect_connections", return_value=[connection]), \
                 patch("evaluate.directional_records", return_value=records):
                truth = flow_truth(base / "pcap", base / "workload", base / "keylog")
                self.assertEqual(len(truth), 2)
                with patch("evaluate.directional_records", return_value={"client": records["client"][:2],
                                                                       "server": records["server"]}):
                    with self.assertRaises(ValueError):
                        flow_truth(base / "pcap", base / "workload", base / "keylog")

    def test_redaction_removes_all_literal_copies_in_derivative(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, destination = base / "source.core", base / "redacted.core"
            value = bytes(range(48))
            payload = bytearray(512)
            payload[128:176] = value
            payload[256:304] = value
            make_core(source, payload)
            with patch("evaluate.subprocess.run", side_effect=lambda argv, check: shutil.copyfile(argv[-2], argv[-1])):
                result = redact_core(source, destination, value)
            self.assertEqual(result["literal_occurrences_removed"], 2)
            self.assertEqual(source.read_bytes().count(value), 2)
            self.assertEqual(destination.read_bytes().count(value), 0)

    def test_pilot_creation_freezes_distinct_cases_and_script_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            study = Path(directory) / "pilot"
            manifest = create(study, "pilot", "2" * 32)
            self.assertEqual(len({row["case_id"] for row in manifest["cases"]}), 10)
            self.assertIn("blind_tls13/recover.py", manifest["script_sha256"])
            self.assertEqual((study / "state.json").stat().st_mode & 0o777, 0o600)

    def test_unmasked_websocket_frame_writer(self):
        left, right = socket.socketpair()
        try:
            send_frame(left, b"hello")
            self.assertEqual(right.recv(7), b"\x82\x05hello")
        finally:
            left.close()
            right.close()

    def test_controlled_server_exchanges_two_messages_on_two_tls_flows(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            case, private = base / "case", base / "private"
            case.mkdir()
            private.mkdir()
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=localhost", "-keyout",
                            str(private / "server.key.pem"), "-out", str(private / "server.cert.pem")],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            with socket.socket() as probe:
                try:
                    probe.bind(("127.0.0.1", 0))
                except PermissionError:
                    self.skipTest("Local socket creation is blocked by this test sandbox")
                port = probe.getsockname()[1]
            thread = threading.Thread(target=serve, args=(case, private, port, 2))
            thread.start()
            deadline = time.monotonic() + 5
            while not (case / "server.ready").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue((case / "server.ready").exists())
            context = ssl._create_unverified_context()
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            connections = []
            try:
                for _ in range(2):
                    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
                    conn = context.wrap_socket(raw, server_hostname="localhost")
                    conn.sendall(b"GET /test HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                                 b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
                    response = bytearray()
                    while b"\r\n\r\n" not in response:
                        response.extend(conn.recv(4096))
                    self.assertIn(b"101 Switching Protocols", response)
                    connections.append(conn)
                for conn in connections:
                    for payload in (b"first", b"second different"):
                        send_masked(conn, payload)
                        self.assertGreater(len(receive_frame(conn)), 100)
                deadline = time.monotonic() + 5
                while not (case / "capture.ready").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue((case / "capture.ready").exists())
            finally:
                (case / "release-server").touch()
                for conn in connections:
                    conn.close()
                thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            flows = json.loads((private / "workload-reference.json").read_text())["flows"]
            self.assertEqual(len(flows), 2)
            self.assertTrue(all(len(flow["client_messages"]) == 2 and
                                len(flow["server_messages"]) == 2 for flow in flows))
            self.assertTrue((private / "server-reference.keys").exists())

    def test_paired_interval_and_failed_attempt_denominator(self):
        self.assertEqual(paired_interval([(1, 0)] * 70, "1" * 32, 100), [1.0, 1.0])
        rows = design("pilot", "1" * 32)
        rows[0]["status"] = "failed"
        result = summarize({"mode": "pilot", "seed": "1" * 32}, {"cases": rows})
        self.assertEqual(result["attempted"], 1)
        self.assertEqual(result["scored"], 0)


if __name__ == "__main__":
    unittest.main()
