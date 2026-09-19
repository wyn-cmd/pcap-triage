"""Tests for reading capture files."""

import os
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from pcaptriage import pcap  # noqa: E402
import capture_builder as build  # noqa: E402


class CaptureTestCase(unittest.TestCase):
    def write(self, data, name="capture.pcap"):
        path = os.path.join(self.work, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="pcap-triage-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.work, ignore_errors=True))

    def frame(self, payload=b"payload"):
        return build.ethernet(build.ipv4("10.0.0.1", "10.0.0.2", 6,
                                         build.tcp(1234, 80, payload)))


class ReadTests(CaptureTestCase):
    def test_reads_a_packet_and_its_timestamp(self):
        path = self.write(build.pcap([(1_700_000_000.5, self.frame())]))
        packets = list(pcap.read_packets(path))
        self.assertEqual(len(packets), 1)
        self.assertAlmostEqual(packets[0].timestamp, 1_700_000_000.5, places=5)
        self.assertEqual(packets[0].linktype, 1)
        self.assertTrue(packets[0].data.endswith(b"payload"))

    def test_reads_a_big_endian_capture(self):
        path = self.write(build.pcap([(1000.25, self.frame())], byte_order=">"))
        packets = list(pcap.read_packets(path))
        self.assertEqual(len(packets), 1)
        self.assertAlmostEqual(packets[0].timestamp, 1000.25, places=5)

    def test_reads_nanosecond_timestamps(self):
        path = self.write(build.pcap([(1000.125, self.frame())], nanosecond=True))
        packets = list(pcap.read_packets(path))
        self.assertAlmostEqual(packets[0].timestamp, 1000.125, places=6)

    def test_a_capture_cut_off_mid_record_keeps_what_came_before(self):
        data = build.pcap([(1.0, self.frame(b"one")), (2.0, self.frame(b"two"))])
        path = self.write(data[:-4], name="cut.pcap")
        packets = list(pcap.read_packets(path))
        self.assertEqual(len(packets), 1)

    def test_sniff_format_names_the_two_formats(self):
        path = self.write(build.pcap([]))
        self.assertEqual(pcap.sniff_format(path), "pcap")
        other = self.write(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32, name="other.pcapng")
        self.assertEqual(pcap.sniff_format(other), "pcapng")

    def test_sniff_format_rejects_something_else(self):
        path = self.write(b"this is a text file, not a capture", name="notes.txt")
        self.assertIsNone(pcap.sniff_format(path))

    def test_a_file_that_is_not_a_capture_is_refused(self):
        path = self.write(b"nope" * 20, name="junk.bin")
        with self.assertRaises(pcap.CaptureError):
            list(pcap.read_packets(path))

    def test_a_file_too_short_for_a_header_is_refused(self):
        path = self.write(b"\xd4\xc3\xb2\xa1\x02\x00", name="short.pcap")
        with self.assertRaises(pcap.CaptureError):
            list(pcap.read_packets(path))

    def test_an_empty_capture_yields_nothing(self):
        path = self.write(build.pcap([]))
        self.assertEqual(list(pcap.read_packets(path)), [])

    def test_the_link_type_comes_from_the_file_not_the_reader(self):
        path = self.write(build.pcap([(1.0, b"\x45" + b"\x00" * 19)], linktype=101))
        packets = list(pcap.read_packets(path))
        self.assertEqual(packets[0].linktype, 101)


if __name__ == "__main__":
    unittest.main(verbosity=2)
