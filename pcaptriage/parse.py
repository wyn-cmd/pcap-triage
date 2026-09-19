"""Link, network and transport layers.

Each function returns None rather than raising when the bytes are not what it
expected. A capture is a pile of other people's packets, and half of triage is
looking at traffic that is damaged, truncated or simply something else.
"""

import socket
import struct

from collections import namedtuple

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

IPPROTO_TCP = 6
IPPROTO_UDP = 17

ETHERNET_HEADER = 14

Flow = namedtuple("Flow", "src sport dst dport protocol payload")
Flow.__doc__ = """One packet, reduced to the five things triage needs."""


def ethernet_frame(data):
    """Return (ethertype, payload) for an Ethernet frame, or (None, None)."""
    if len(data) < ETHERNET_HEADER:
        return None, None
    ethertype = struct.unpack("!H", data[12:14])[0]
    return ethertype, data[ETHERNET_HEADER:]


def ipv4_packet(payload):
    """Return (src, dst, protocol, body), or None if it is not IPv4."""
    if len(payload) < 20:
        return None
    if payload[0] >> 4 != 4:
        return None
    header_length = (payload[0] & 0x0F) * 4
    if header_length < 20 or len(payload) < header_length:
        return None
    total_length = struct.unpack("!H", payload[2:4])[0]
    protocol = payload[9]
    src = socket.inet_ntoa(payload[12:16])
    dst = socket.inet_ntoa(payload[16:20])
    # A capture often holds more bytes than the IP header claims, because of
    # padding on small frames, so the header length wins over the buffer end.
    body = payload[header_length:total_length] if total_length else payload[header_length:]
    return src, dst, protocol, body


IPV6_HEADER = 40

# Extension headers that can sit between the ipv6 header and the
# segment: hop by hop, routing, fragment and destination options.
IPV6_EXTENSION_HEADERS = (0, 43, 44, 60)


def ipv6_packet(payload):
    """Return (src, dst, protocol, body) for IPv6, or None.

    Extension headers are walked rather than assumed away, because a
    segment can sit behind several of them. Anything unexpected stops
    the walk, which is better than reading an offset as a port number.
    """
    if len(payload) < IPV6_HEADER or payload[0] >> 4 != 6:
        return None
    src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    protocol = payload[6]
    offset = IPV6_HEADER
    while protocol in IPV6_EXTENSION_HEADERS:
        if len(payload) < offset + 8:
            return None
        if protocol == 44:
            # A fragment header is a fixed eight bytes.
            protocol = payload[offset]
            offset += 8
            continue
        following = payload[offset]
        length = (payload[offset + 1] + 1) * 8
        if length < 8 or len(payload) < offset + length:
            return None
        protocol = following
        offset += length
    return src, dst, protocol, payload[offset:]


def transport(protocol, payload):
    """Return (sport, dport, body) for TCP or UDP, or None."""
    if protocol not in (IPPROTO_TCP, IPPROTO_UDP):
        return None
    if len(payload) < 8:
        return None
    sport, dport = struct.unpack("!HH", payload[:4])
    if protocol == IPPROTO_TCP:
        if len(payload) < 13:
            return None
        offset = (payload[12] >> 4) * 4
        if offset < 20 or len(payload) < offset:
            return None
        return sport, dport, payload[offset:]
    return sport, dport, payload[8:]


def flows(packets):
    """Turn raw packets into Flow records, skipping anything unreadable."""
    for packet in packets:
        network = None
        if packet.linktype == 1:
            ethertype, frame = ethernet_frame(packet.data)
            if ethertype == ETHERTYPE_IPV4:
                network = ipv4_packet(frame)
            elif ethertype == ETHERTYPE_IPV6:
                network = ipv6_packet(frame)
        else:
            # Raw IP captures have no link layer to step over, so the
            # version nibble decides which of the two this is.
            frame = packet.data
            if frame[:1] and frame[0] >> 4 == 6:
                network = ipv6_packet(frame)
            else:
                network = ipv4_packet(frame)

        if not network:
            continue
        src, dst, protocol, body = network

        carried = transport(protocol, body)
        if not carried:
            continue
        sport, dport, application = carried

        yield Flow(src, sport, dst, dport, protocol, application)


def protocol_name(protocol):
    if protocol == IPPROTO_TCP:
        return "TCP"
    if protocol == IPPROTO_UDP:
        return "UDP"
    return f"IP/{protocol}"
