"""Tests for the command line, driven through main()."""

import io
import os
import sys
import tempfile
import unittest

from contextlib import redirect_stdout, redirect_stderr

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from pcaptriage import cli  # noqa: E402
import capture_builder as build  # noqa: E402


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="pcap-cli-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.work, ignore_errors=True))
        self.path = os.path.join(self.work, "sample.pcap")
        frames = [
            (1.0, build.ethernet(build.ipv4(
                "10.0.0.5", "93.184.216.34", 6,
                build.tcp(51000, 443, build.tls_client_hello("example.org"))))),
            (2.0, build.ethernet(build.ipv4(
                "10.0.0.5", "93.184.216.34", 6,
                build.tcp(51001, 80, build.http_request("example.org"))))),
        ]
        with open(self.path, "wb") as handle:
            handle.write(build.pcap(frames))

    def test_a_report_is_printed(self):
        code, out, _ = run([self.path])
        self.assertEqual(code, 0)
        self.assertIn("top talkers", out)
        self.assertIn("example.org", out)

    def test_top_is_passed_through(self):
        code, out, _ = run([self.path, "--top", "1"])
        self.assertEqual(code, 0)
        self.assertIn("tls server names", out)

    def test_top_of_zero_is_refused(self):
        code, _, err = run([self.path, "--top", "0"])
        self.assertEqual(code, 2)
        self.assertIn("at least 1", err)

    def test_a_missing_file_is_reported(self):
        code, _, err = run([os.path.join(self.work, "absent.pcap")])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_something_that_is_not_a_capture_is_reported(self):
        junk = os.path.join(self.work, "junk.bin")
        with open(junk, "wb") as handle:
            handle.write(b"not a capture at all, just some bytes" * 4)
        code, _, err = run([junk])
        self.assertEqual(code, 2)
        self.assertIn("pcap-triage:", err)

    def test_an_empty_capture_is_reported(self):
        empty = os.path.join(self.work, "empty.pcap")
        with open(empty, "wb") as handle:
            handle.write(build.pcap([]))
        code, _, err = run([empty])
        self.assertEqual(code, 1)
        self.assertIn("no packets", err)

    def test_a_time_window_narrows_the_report(self):
        code, out, _ = run([self.path, "--since", "1.5"])
        self.assertEqual(code, 3)  # the narrowed window has nothing but an unnamed request, itself a finding
        self.assertIn("1 packets", out)

    def test_an_iso_time_is_accepted(self):
        code, out, _ = run([self.path, "--since", "1970-01-01T00:00:00"])
        self.assertEqual(code, 0)
        self.assertIn("2 packets", out)

    def test_a_time_that_makes_no_sense_is_refused(self):
        code, _, err = run([self.path, "--since", "whenever"])
        self.assertEqual(code, 2)
        self.assertIn("as a time", err)

    def test_version_exits_cleanly(self):
        with self.assertRaises(SystemExit) as caught:
            run([self.path, "--version"])
        self.assertEqual(caught.exception.code, 0)


class NotableOnlyTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="pcap-notable-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.work, ignore_errors=True))
        self.path = os.path.join(self.work, "sample.pcap")
        frames = [(1.0, build.ethernet(build.ipv4(
            "10.0.0.5", "93.184.216.34", 6,
            build.tcp(51000, 80, build.http_request(
                "example.org", "/admin", auth="dXNlcjpwYXNz")))))]
        with open(self.path, "wb") as handle:
            handle.write(build.pcap(frames))

    def test_only_the_findings_are_printed(self):
        code, out, _ = run([self.path, "--only-notable"])
        self.assertEqual(code, 3)
        self.assertIn("credentials in the clear", out)
        self.assertNotIn("top talkers", out)

    def test_the_full_report_also_signals_findings_in_its_exit_code(self):
        code, out, _ = run([self.path])
        self.assertEqual(code, 3)
        self.assertIn("top talkers", out)

    def test_a_quiet_capture_prints_nothing(self):
        quiet = os.path.join(self.work, "quiet.pcap")
        with open(quiet, "wb") as handle:
            handle.write(build.pcap([(1.0, build.ethernet(build.ipv4(
                "10.0.0.5", "93.184.216.34", 6,
                build.tcp(51000, 443, build.tls_client_hello("example.org")))))]))
        code, out, _ = run([quiet, "--only-notable"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")

    def test_a_quiet_capture_exits_zero_without_only_notable(self):
        quiet = os.path.join(self.work, "quiet2.pcap")
        with open(quiet, "wb") as handle:
            handle.write(build.pcap([(1.0, build.ethernet(build.ipv4(
                "10.0.0.5", "93.184.216.34", 6,
                build.tcp(51000, 443, build.tls_client_hello("example.org")))))]))
        code, out, _ = run([quiet])
        self.assertEqual(code, 0)
        self.assertIn("top talkers", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
