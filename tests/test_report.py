"""Tests for turning packets into a report."""

import os
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from pcaptriage import pcap, report  # noqa: E402
import capture_builder as build  # noqa: E402

CLIENT = "10.0.0.5"
SERVER = "93.184.216.34"


def frames():
    """A small capture with dns, http, tls and a broad port sweep in it."""
    out = []

    def add_tcp(payload, sport, dport, at, src=CLIENT, dst=SERVER, protocol=6):
        segment = (build.tcp(sport, dport, payload) if protocol == 6
                   else build.udp(sport, dport, payload))
        out.append((at, build.ethernet(build.ipv4(src, dst, protocol, segment))))

    add_tcp(build.dns_query("example.org")[8:], 40000, 53, 1000.0, protocol=17)
    add_tcp(build.tls_client_hello("example.org"), 51000, 443, 1000.5)
    add_tcp(build.http_request("example.org", "/index.html"), 51001, 80, 1001.0)
    add_tcp(build.http_request("example.org", "/admin", auth="dXNlcjpwYXNz"),
            51002, 80, 1001.5)
    add_tcp(build.tls_client_hello("cdn.example.net"), 51003, 443, 1002.0)
    # Twenty different ports from one source looks like a sweep.
    for index in range(22):
        add_tcp(b"", 52000 + index, 1000 + index, 1003.0 + index * 0.1)
    return out


def summary_from(frames, path):
    with open(path, "wb") as handle:
        handle.write(build.pcap(frames))
    return report.summarise(pcap.read_packets(path))


class SummaryTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.work = tempfile.mkdtemp(prefix="pcap-report-test-")
        self.path = os.path.join(self.work, "sample.pcap")
        self.summary = summary_from(frames(), self.path)

    def test_counters(self):
        self.assertEqual(self.summary.packets, 27)
        self.assertGreater(self.summary.total_bytes, 0)
        self.assertAlmostEqual(self.summary.duration, 5.1, places=1)

    def test_talkers_and_protocols(self):
        self.assertEqual(self.summary.talkers[(CLIENT, SERVER)], 27)
        self.assertEqual(self.summary.protocols["TCP"], 26)
        self.assertEqual(self.summary.protocols["UDP"], 1)

    def test_services(self):
        self.assertEqual(self.summary.services["TCP/443"], 2)
        self.assertEqual(self.summary.services["TCP/80"], 2)
        self.assertEqual(self.summary.services["UDP/53"], 1)

    def test_names(self):
        self.assertEqual(self.summary.dns_names["example.org"], 1)
        self.assertEqual(self.summary.tls_names["example.org"], 1)
        self.assertEqual(self.summary.tls_names["cdn.example.net"], 1)
        self.assertEqual(self.summary.http_hosts["example.org"], 2)

    def test_http_requests(self):
        self.assertEqual(self.summary.http_requests[("GET", "/index.html")], 1)
        self.assertEqual(self.summary.http_requests[("GET", "/admin")], 1)

    def test_a_name_is_not_counted_twice(self):
        # The tls counters are separate from the dns ones, and each counts once.
        self.assertEqual(sum(self.summary.tls_names.values()), 2)


class NotableTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.work = tempfile.mkdtemp(prefix="pcap-report-test-")
        self.path = os.path.join(self.work, "sample.pcap")
        self.summary = summary_from(frames(), self.path)

    def test_cleartext_credentials_are_flagged(self):
        text = report.render(self.summary)
        self.assertIn("credentials in the clear", text)
        self.assertIn("/admin", text)

    def test_a_broad_sweep_of_ports_is_flagged(self):
        text = report.render(self.summary)
        self.assertIn("different ports", text)

    def test_a_quiet_capture_has_nothing_to_flag(self):
        path = os.path.join(self.work, "quiet.pcap")
        quiet = summary_from([(1.0, build.ethernet(build.ipv4(
            CLIENT, SERVER, 6, build.tcp(50000, 443, build.tls_client_hello("example.org")))))],
            path)
        self.assertIn("nothing obvious", report.render(quiet))

    def test_a_capture_with_no_names_says_so(self):
        path = os.path.join(self.work, "nonames.pcap")
        blind = summary_from([(1.0, build.ethernet(build.ipv4(
            CLIENT, SERVER, 6, build.tcp(50000, 443, b"\x16\x03\x01\x00\x05\x02\x00\x00"))))],
            path)
        self.assertIn("no names were asked for", report.render(blind))


class RenderTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.work = tempfile.mkdtemp(prefix="pcap-report-test-")
        self.path = os.path.join(self.work, "sample.pcap")
        self.summary = summary_from(frames(), self.path)
        self.text = report.render(self.summary)

    def test_the_sections_are_all_there(self):
        for heading in ("top talkers", "protocols", "busiest services",
                        "names asked for", "tls server names", "http hosts",
                        "http requests", "what stands out"):
            self.assertIn(heading, self.text)

    def test_the_header_counts_packets(self):
        self.assertIn("27 packets", self.text)

    def test_top_limits_the_rows_and_says_how_many_are_hidden(self):
        text = report.render(self.summary, top=1)
        self.assertIn("and 1 more", text)

    def test_an_empty_summary_still_renders(self):
        empty = report.Summary()
        text = report.render(empty)
        self.assertIn("0 packets", text)


class FormattingTests(unittest.TestCase):
    def test_bytes_are_readable(self):
        self.assertEqual(report.human_bytes(512), "512 B")
        self.assertEqual(report.human_bytes(2048), "2.0 KB")
        self.assertEqual(report.human_bytes(5 * 1024 ** 2), "5.0 MB")

    def test_durations_are_readable(self):
        self.assertEqual(report.human_duration(0.5), "under a second")
        self.assertEqual(report.human_duration(30), "30 seconds")
        self.assertEqual(report.human_duration(90), "1.5 minutes")
        self.assertEqual(report.human_duration(7200), "2.0 hours")


if __name__ == "__main__":
    unittest.main(verbosity=2)
