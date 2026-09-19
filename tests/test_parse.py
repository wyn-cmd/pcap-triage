"""Tests for the link, network and transport layers."""

import os
import socket
import struct
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from pcaptriage import parse  # noqa: E402
import capture_builder as build  # noqa: E402


class EthernetTests(unittest.TestCase):
    def test_a_frame_yields_its_ethertype_and_payload(self):
        frame = build.ethernet(b"body", ethertype=0x0800)
        ethertype, payload = parse.ethernet_frame(frame)
        self.assertEqual(ethertype, 0x0800)
        self.assertEqual(payload, b"body")

    def test_a_frame_shorter_than_the_header_is_not_read(self):
        self.assertEqual(parse.ethernet_frame(b"\x00" * 13), (None, None))

    def test_ipv6_is_reported_as_such_by_its_ethertype(self):
        frame = build.ethernet(b"body", ethertype=parse.ETHERTYPE_IPV6)
        ethertype, _ = parse.ethernet_frame(frame)
        self.assertEqual(ethertype, parse.ETHERTYPE_IPV6)


class Ipv4Tests(unittest.TestCase):
    def test_addresses_protocol_and_body(self):
        packet = build.ipv4("192.168.1.10", "8.8.8.8", 17, b"payload")
        src, dst, protocol, body = parse.ipv4_packet(packet)
        self.assertEqual((src, dst, protocol, body),
                         ("192.168.1.10", "8.8.8.8", 17, b"payload"))

    def test_a_header_with_options_is_stepped_over(self):
        packet = build.ipv4("10.0.0.1", "10.0.0.2", 6, b"payload",
                            options=b"\x01\x01\x01\x01")
        src, dst, protocol, body = parse.ipv4_packet(packet)
        self.assertEqual(body, b"payload")

    def test_trailing_padding_is_dropped_using_the_declared_length(self):
        # Small frames arrive padded, and the padding is not part of the packet.
        packet = build.ipv4("10.0.0.1", "10.0.0.2", 6, b"payload")
        padded = packet + b"\x00" * 30
        _, _, _, body = parse.ipv4_packet(padded)
        self.assertEqual(body, b"payload")

    def test_something_that_is_not_ipv4_is_not_read(self):
        self.assertIsNone(parse.ipv4_packet(b"\x60" + b"\x00" * 40))
        self.assertIsNone(parse.ipv4_packet(b"\x45\x00"))

    def test_a_truncated_header_is_not_read(self):
        self.assertIsNone(parse.ipv4_packet(b"\x45" + b"\x00" * 10))


class TransportTests(unittest.TestCase):
    def test_tcp_ports_and_body(self):
        segment = build.tcp(50000, 443, b"hello")
        self.assertEqual(parse.transport(6, segment), (50000, 443, b"hello"))

    def test_tcp_header_options_are_stepped_over(self):
        segment = build.tcp(50000, 443, b"hello", options=b"\x02\x04\x05\xb4")
        self.assertEqual(parse.transport(6, segment), (50000, 443, b"hello"))

    def test_udp_ports_and_body(self):
        datagram = build.udp(53, 40000, b"hello")
        self.assertEqual(parse.transport(17, datagram), (53, 40000, b"hello"))

    def test_other_protocols_are_not_read(self):
        self.assertIsNone(parse.transport(1, b"\x08\x00" + b"\x00" * 10))

    def test_a_segment_shorter_than_its_header_is_not_read(self):
        self.assertIsNone(parse.transport(6, b"\x00\x50"))
        self.assertIsNone(parse.transport(17, b"\x00\x35"))


class FlowTests(unittest.TestCase):
    def packet(self, frame, linktype=1):
        from pcaptriage.pcap import Packet
        return Packet(1.0, frame, linktype)

    def test_a_tcp_packet_becomes_a_flow(self):
        frame = build.ethernet(
            build.ipv4("10.0.0.5", "93.184.216.34", 6,
                       build.tcp(51000, 443, b"client hello")))
        flows = list(parse.flows([self.packet(frame)]))
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].src, "10.0.0.5")
        self.assertEqual(flows[0].dport, 443)
        self.assertEqual(flows[0].payload, b"client hello")

    def test_a_raw_ip_capture_has_no_link_layer(self):
        packet = build.ipv4("10.0.0.5", "10.0.0.6", 17, build.udp(53, 40000, b"x"))
        flows = list(parse.flows([self.packet(packet, linktype=101)]))
        self.assertEqual(len(flows), 1)

    def test_an_ipv6_frame_is_skipped_rather_than_misread(self):
        frame = build.ethernet(b"\x60" + b"\x00" * 40, ethertype=parse.ETHERTYPE_IPV6)
        self.assertEqual(list(parse.flows([self.packet(frame)])), [])

    def test_icmp_is_not_a_flow(self):
        frame = build.ethernet(build.ipv4("10.0.0.1", "10.0.0.2", 1, b"\x08\x00" + b"\x00" * 6))
        self.assertEqual(list(parse.flows([self.packet(frame)])), [])

    def test_protocol_names(self):
        self.assertEqual(parse.protocol_name(6), "TCP")
        self.assertEqual(parse.protocol_name(17), "UDP")
        self.assertEqual(parse.protocol_name(47), "IP/47")


class Ipv6Tests(unittest.TestCase):
    CLIENT = "2001:db8::1"
    SERVER = "2001:db8::2"

    def ipv6(self, protocol, payload, next_header=None):
        header = struct.pack("!IHBB", 6 << 28, len(payload),
                             next_header if next_header is not None else protocol, 64)
        header += socket.inet_pton(socket.AF_INET6, self.CLIENT)
        header += socket.inet_pton(socket.AF_INET6, self.SERVER)
        return header + payload

    def test_addresses_and_protocol_are_read(self):
        packet = self.ipv6(6, build.tcp(51000, 443, b"hello"))
        src, dst, protocol, body = parse.ipv6_packet(packet)
        self.assertEqual(src, self.CLIENT)
        self.assertEqual(dst, self.SERVER)
        self.assertEqual(protocol, 6)
        self.assertEqual(body, packet[40:])

    def test_an_extension_header_is_stepped_over(self):
        # A hop by hop header sits between the ipv6 header and the segment.
        extension = bytes([6, 0]) + b"\x00" * 6
        packet = self.ipv6(6, extension + build.tcp(51000, 443, b"hello"),
                           next_header=0) + b""
        src, dst, protocol, body = parse.ipv6_packet(packet)
        self.assertEqual(protocol, 6)
        self.assertEqual(body, build.tcp(51000, 443, b"hello"))

    def test_a_truncated_packet_is_not_read(self):
        self.assertIsNone(parse.ipv6_packet(b"\x60" + b"\x00" * 20))

    def test_a_flow_comes_out_of_an_ipv6_frame(self):
        from pcaptriage.pcap import Packet
        frame = build.ethernet(self.ipv6(6, build.tcp(51000, 443, b"hi")),
                               ethertype=parse.ETHERTYPE_IPV6)
        flows = list(parse.flows([Packet(1.0, frame, 1)]))
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].src, self.CLIENT)
        self.assertEqual(flows[0].dport, 443)

    def test_the_protocol_after_the_extension_is_used(self):
        # UDP behind a destination options header.
        extension = bytes([17, 0]) + b"\x00" * 6
        packet = self.ipv6(17, extension + build.udp(53, 40000, b"x"),
                           next_header=60)
        _, _, protocol, body = parse.ipv6_packet(packet)
        self.assertEqual(protocol, 17)
        self.assertEqual(parse.transport(protocol, body)[0], 53)


if __name__ == "__main__":
    unittest.main(verbosity=2)
