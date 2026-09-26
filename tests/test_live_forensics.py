#!/usr/bin/env python3
"""Regression tests for the sealed live-memory acquisition workflow."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


live_case = load_module("run_live_case", ROOT / "lab/live/run_live_case.py")
live_study = load_module("run_live_ad_study", ROOT / "lab/live/run_live_ad_study.py")


class LiveForensicsTests(unittest.TestCase):
    def test_transcript_redacts_keylog_material(self) -> None:
        value = "CLIENT_RANDOM " + "A" * 64 + " " + "B" * 96
        redacted = live_case.redact(value)
        self.assertNotIn("A" * 64, redacted)
        self.assertNotIn("B" * 96, redacted)
        self.assertIn("<redacted-secret>", redacted)

    def test_key_parser_deduplicates_canonical_lines(self) -> None:
        value = "CLIENT_RANDOM " + "a" * 64 + " " + "b" * 96
        parsed = live_case.parse_key_lines(value + "\nnoise\n" + value.upper())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0], value.upper())

    def test_wilson_interval_is_clamped(self) -> None:
        for successes, total in ((0, 1), (1, 1), (0, 40), (40, 40)):
            interval = live_study.wilson(successes, total)
            self.assertGreaterEqual(interval["lower"], 0.0)
            self.assertLessEqual(interval["upper"], 1.0)

    def test_campaign_design_is_exactly_forty_attempts(self) -> None:
        total = (
            len(live_study.LIBRARIES)
            * len(live_study.PROTOCOLS)
            * len(live_study.METHODS)
            * live_study.SESSIONS_PER_CELL
        )
        self.assertEqual(live_study.METHODS, ("A", "D"))
        self.assertEqual(total, 40)

    def test_source_seals_before_reference_read_and_tshark(self) -> None:
        source = (ROOT / "lab/live/run_live_case.py").read_text()
        seal_write = source.index('write_json(case_dir / "secrets/acquisition-seal.json"')
        reference_read = source.index("server_reference.read_text")
        tshark_run = source.index("tshark_result = subprocess.run")
        self.assertLess(seal_write, reference_read)
        self.assertLess(reference_read, tshark_run)

    def test_client_environment_removes_sslkeylogfile(self) -> None:
        source = (ROOT / "lab/live/run_live_case.py").read_text()
        self.assertIn('client_environment.pop("SSLKEYLOGFILE", None)', source)

    def test_server_reference_is_server_side_only(self) -> None:
        source = (ROOT / "lab/baseline/tls_server.py").read_text()
        self.assertIn('context.keylog_filename = str(args.keylog)', source)

    def test_firefox_seals_before_reading_root_only_reference(self) -> None:
        source = (ROOT / "lab/firefox/phase18a_firefox_nss_runner.py").read_text()
        seal_write = source.index(
            'write_json(case_dir / "secrets/acquisition-seal.json"'
        )
        reference_read = source.index("server_reference.read_text")
        self.assertLess(seal_write, reference_read)
        self.assertIn('"server_reference_access_during_acquisition": "root-only mode-0600"', source)
        self.assertNotIn("os.chown(path, RESEARCHER_UID, RESEARCHER_GID)", source)

    def test_firefox_uses_one_connection_and_completed_handshake_association(self) -> None:
        source = (ROOT / "lab/firefox/phase18a_firefox_nss_runner.py").read_text()
        self.assertIn('"network.http.speculative-parallel-limit": 0', source)
        self.assertIn("controlled case permits exactly one TLS connection", source)
        association = source.index(
            '"policy": "ClientHello from a TCP stream containing a ServerHello"'
        )
        reference_read = source.index("server_reference.read_text")
        self.assertLess(association, reference_read)

    def test_tls13_scope_filter_precedes_reference_read(self) -> None:
        source = (ROOT / "lab/live/run_live_case.py").read_text()
        scope_filter = source.index("out_of_scope_candidate_labels")
        reference_read = source.index("server_reference.read_text")
        self.assertLess(scope_filter, reference_read)


if __name__ == "__main__":
    unittest.main(verbosity=2)
