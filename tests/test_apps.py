"""Tests for the application layer readers."""

import os
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from pcaptriage import apps  # noqa: E402
import capture_builder as build  # noqa: E402


class DnsTests(unittest.TestCase):
    def test_the_question_name_is_read(self):
        datagram = build.dns_query("example.org")
        payload = datagram[8:]
        self.assertEqual(apps.dns_question(payload, 53), "example.org")

    def test_a_multi_label_name_keeps_its_labels(self):
        payload = build.dns_query("a.b.c.internal.example")[8:]
        self.assertEqual(apps.dns_question(payload, 53),
                         "a.b.c.internal.example")

    def test_a_response_is_not_counted_as_a_question(self):
        payload = build.dns_query("example.org", response=True)[8:]
        self.assertIsNone(apps.dns_question(payload, 53))

    def test_another_port_is_not_dns(self):
        payload = build.dns_query("example.org")[8:]
        self.assertIsNone(apps.dns_question(payload, 5353))

    def test_a_compression_pointer_in_the_question_is_refused(self):
        payload = build.dns_query("example.org")[8:]
        broken = payload[:12] + b"\xc0\x0c" + payload[14:]
        self.assertIsNone(apps.dns_question(broken, 53))

    def test_a_truncated_query_is_not_read(self):
        self.assertIsNone(apps.dns_question(b"\x00" * 6, 53))


class TlsTests(unittest.TestCase):
    def test_the_server_name_is_read_from_a_client_hello(self):
        hello = build.tls_client_hello("api.github.com")
        self.assertEqual(apps.tls_server_name(hello, 443), "api.github.com")

    def test_a_hello_without_the_extension_yields_nothing(self):
        self.assertIsNone(apps.tls_server_name(build.tls_client_hello_without_sni(), 443))

    def test_something_that_is_not_a_hello_is_not_read(self):
        self.assertIsNone(apps.tls_server_name(b"GET / HTTP/1.1\r\n\r\n", 443))
        self.assertIsNone(apps.tls_server_name(b"\x16\x03\x01\x00\x05\x02\x00\x00", 443))

    def test_a_truncated_hello_is_not_read(self):
        hello = build.tls_client_hello("example.com")
        self.assertIsNone(apps.tls_server_name(hello[:20], 443))

    def test_a_long_name_is_read_whole(self):
        name = "a-very-long-subdomain." + "x" * 40 + ".example.com"
        self.assertEqual(apps.tls_server_name(build.tls_client_hello(name), 443), name)


class HttpTests(unittest.TestCase):
    def test_the_host_header_is_read(self):
        request = build.http_request("example.org", "/index.html")
        self.assertEqual(apps.http_host(request, 80), "example.org")

    def test_the_request_line_is_read(self):
        request = build.http_request("example.org", "/login", method="POST")
        self.assertEqual(apps.http_request_line(request), ("POST", "/login"))

    def test_a_non_standard_http_port_is_still_read(self):
        request = build.http_request("example.org", "/index.html")
        self.assertEqual(apps.http_host(request, 8080), "example.org")

    def test_a_tls_port_is_not_treated_as_http(self):
        request = build.http_request("example.org")
        self.assertIsNone(apps.http_host(request, 443))

    def test_a_response_is_not_a_request(self):
        response = b"HTTP/1.1 200 OK\r\nHost: example.org\r\n\r\n"
        self.assertIsNone(apps.http_host(response, 80))
        self.assertEqual(apps.http_request_line(response), (None, None))

    def test_credentials_in_the_clear_are_noticed(self):
        request = build.http_request("example.org", "/admin", auth="dXNlcjpwYXNz")
        self.assertTrue(apps.http_basic_auth(request, 80))

    def test_a_request_without_credentials_is_not_flagged(self):
        request = build.http_request("example.org", "/index.html")
        self.assertFalse(apps.http_basic_auth(request, 80))

    def test_a_lower_case_header_name_still_matches(self):
        request = b"GET / HTTP/1.1\r\nhost: example.org\r\n\r\n"
        self.assertEqual(apps.http_host(request, 80), "example.org")

    def test_a_bearer_token_is_its_own_scheme(self):
        request = build.http_request("example.org", "/api", auth="abc123", auth_scheme="Bearer")
        self.assertEqual(apps.http_credential_scheme(request, 80), "bearer")
        self.assertFalse(apps.http_basic_auth(request, 80))

    def test_digest_auth_is_not_flagged(self):
        request = build.http_request("example.org", "/api", auth='realm="x"', auth_scheme="Digest")
        self.assertIsNone(apps.http_credential_scheme(request, 80))


class FtpTests(unittest.TestCase):
    def test_a_username_is_read(self):
        self.assertEqual(apps.ftp_credential(build.ftp_command("USER", "anonymous")),
                         ("USER", "anonymous"))

    def test_a_password_is_read(self):
        self.assertEqual(apps.ftp_credential(build.ftp_command("PASS", "hunter2")),
                         ("PASS", "hunter2"))

    def test_a_lower_case_command_still_matches(self):
        self.assertEqual(apps.ftp_credential(b"user bob\r\n"), ("USER", "bob"))

    def test_an_unrelated_command_is_not_a_credential(self):
        self.assertIsNone(apps.ftp_credential(build.ftp_command("LIST", "/")))

    def test_a_command_with_no_argument_is_not_a_credential(self):
        self.assertIsNone(apps.ftp_credential(b"USER\r\n"))

    def test_empty_payload_is_not_a_credential(self):
        self.assertIsNone(apps.ftp_credential(b""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
