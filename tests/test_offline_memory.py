"""Synthetic memory tests; these do not establish Firefox recovery."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab/offline_memory"))
from core_memory import CoreMemory
from rank_core import rank


def make_core(path, payload, memsize=None):
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01" + bytes(10), 4, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 6, 120, 0x10000, 0, len(payload), memsize or len(payload), 4096)
    path.write_bytes(header + segment + payload)


class OfflineMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.core"

    def test_virtual_address_read_and_omitted_pages(self):
        make_core(self.path, b"abcd", memsize=4096)
        with CoreMemory(self.path) as core:
            self.assertEqual(core.read(0x10001, 2), b"bc")
            with self.assertRaises(ValueError):
                core.read(0x10002, 4)

    def test_truncated_core_rejected(self):
        make_core(self.path, bytes(64))
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            CoreMemory(self.path)

    def test_search_crosses_adjacent_segments_but_not_gaps(self):
        for second_base, expected in ((0x10003, [0x10001]), (0x20000, [])):
            header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01" + bytes(10), 4, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            first = struct.pack("<IIQQQQQQ", 1, 6, 176, 0x10000, 0, 3, 3, 4096)
            second = struct.pack("<IIQQQQQQ", 1, 6, 179, second_base, 0, 3, 3, 4096)
            self.path.write_bytes(header + first + second + b"abcdef")
            with CoreMemory(self.path) as core:
                self.assertEqual(list(core.find(b"bcde")), expected)

    def test_unique_candidate_and_duplicate_object(self):
        data = bytearray(512)
        data[128:176] = bytes(range(48))
        for item in (0, 24):
            struct.pack_into("<I4xQI", data, item, 0, 0x10080, 48)
        make_core(self.path, data)
        with CoreMemory(self.path) as core:
            rows, summary = rank(core)
        self.assertEqual(summary["status"], "selected")
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["locations"]), 2)

    def test_equal_entropy_candidates_abstain(self):
        data = bytearray(512)
        for item, offset, value in ((0, 128, bytes(range(48))), (24, 256, bytes(range(48, 96)))):
            data[offset:offset + 48] = value
            struct.pack_into("<I4xQI", data, item, 0, 0x10000 + offset, 48)
        make_core(self.path, data)
        with CoreMemory(self.path) as core:
            _, summary = rank(core)
        self.assertEqual(summary["status"], "ambiguous")
        self.assertIsNone(summary["selected_id"])

    def test_zero_buffers_and_invalid_pointers_rejected(self):
        data = bytearray(512)
        struct.pack_into("<I4xQI", data, 0, 0, 0x10080, 48)
        struct.pack_into("<I4xQI", data, 24, 0, 0x30000, 48)
        make_core(self.path, data)
        with CoreMemory(self.path) as core:
            rows, summary = rank(core)
        self.assertEqual(rows, [])
        self.assertEqual(summary["status"], "no_candidate")

    def test_cka_value_layout_excludes_other_attributes_and_full_width_length(self):
        data = bytearray(512)
        data[128:176] = bytes(range(48))
        struct.pack_into("<QQQ", data, 0, 0x11, 0x10080, 48)
        struct.pack_into("<QQQ", data, 24, 0x12, 0x10080, 48)
        struct.pack_into("<QQQ", data, 48, 0x11, 0x10080, (1 << 32) + 48)
        make_core(self.path, data)
        with CoreMemory(self.path) as core:
            rows, summary = rank(core, "cka-value48")
        self.assertEqual(summary["status"], "selected")
        self.assertEqual(len(rows[0]["locations"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
