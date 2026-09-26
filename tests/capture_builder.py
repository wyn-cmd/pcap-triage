"""Build capture files in memory.

The tests need traffic with known contents, and there is no reason to record any.
Every structure here is written out byte by byte the way the real thing is laid
out, so the parsers are tested against the actual formats rather than against
whatever this tool happens to produce.
"""

import struct

ETHERNET = 14
IPV4 = 20
TCP = 20
UDP = 8

ZERO_MAC = b"\x02\x00\x00\x00\x00\x00"
BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"


def ethernet(payload, ethertype=0x0800, src=ZERO_MAC, dst=BROADCAST_MAC):
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, protocol, payload, ttl=64, options=b"", total_length=None):
    version_and_length = (4 << 4) | ((IPV4 + len(options)) // 4)
    length = total_length if total_length is not None else IPV4 + len(options) + len(payload)
    header = struct.pack("!BBHHHBBH", version_and_length, 0, length, 0, 0, ttl,
                         protocol, 0)
    header += bytes(int(part) for part in src.split("."))
    header += bytes(int(part) for part in dst.split("."))
    return header + options + payload


def tcp(sport, dport, payload=b"", seq=1, ack=0, flags=0x18, options=b""):
    offset = ((TCP + len(options)) // 4) << 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset, flags,
                         8192, 0, 0)
    return header + options + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, UDP + len(payload), 0) + payload


def dns_query(name, txid=0x1234, response=False, port=53):
    flags = 0x8180 if response else 0x0100
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode()
                        for label in name.split("."))
    question += b"\x00" + struct.pack("!HH", 1, 1)
    return udp(40000 + (txid % 1000), port, header + question)


def tls_client_hello(name, version=b"\x03\x03", extra_extensions=b""):
    """A ClientHello carrying a server_name extension, laid out properly."""
    raw_name = name.encode()
    entry = b"\x00" + struct.pack("!H", len(raw_name)) + raw_name
    server_name_list = struct.pack("!H", len(entry)) + entry
    extension = struct.pack("!HH", 0x0000, len(server_name_list)) + server_name_list

    # A no-extension ClientHello is a real case too, so it can be asked for.
    extensions = extension + extra_extensions
    body = (version + b"\x00" * 32
            + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + b"\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_client_hello_without_sni():
    body = (b"\x03\x03" + b"\x00" * 32
            + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00"
            + struct.pack("!H", 0))
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + b"\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def http_request(host, path="/", method="GET", auth=None, auth_scheme="Basic"):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "User-Agent: curl/8.0"]
    if auth:
        lines.append(f"Authorization: {auth_scheme} {auth}")
    lines.append("")
    return ("\r\n".join(lines) + "\r\n").encode()


def ftp_command(command, argument):
    return f"{command} {argument}\r\n".encode()


def pcap(packets, linktype=1, nanosecond=False, byte_order="<", truncated=False):
    """Wrap frames in a classic libpcap file.

    packets: a list of (timestamp, frame bytes).
    """
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    out = struct.pack(byte_order + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for timestamp, frame in packets:
        seconds = int(timestamp)
        fraction = int((timestamp - seconds) * (1_000_000_000 if nanosecond else 1_000_000))
        out += struct.pack(byte_order + "IIII", seconds, fraction, len(frame), len(frame))
        out += frame
    if truncated:
        # A capture cut off in the middle of a record.
        out = out[:-3]
    return out


def pcapng(packets, linktype=1, byte_order="<"):
    """Wrap frames in a pcapng file with one section and one interface."""

    def block(block_type, body):
        length = 12 + len(body)
        raw = struct.pack(byte_order + "II", block_type, length) + body
        return raw + struct.pack(byte_order + "I", length)

    mark = b"\x4d\x3c\x2b\x1a" if byte_order == "<" else b"\x1a\x2b\x3c\x4d"
    out = block(0x0A0D0D0A, mark + struct.pack(byte_order + "HHq", 1, 0, -1))
    out += block(0x00000001, struct.pack(byte_order + "HHI", linktype, 0, 65535))
    for timestamp, frame in packets:
        ticks = int(timestamp * 1_000_000)
        body = struct.pack(byte_order + "IIIII", 0, ticks >> 32,
                           ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame
        # Blocks are padded to a four byte boundary, and the captured
        # length still tells the reader how much of it is real.
        body += b"\x00" * (-len(frame) % 4)
        out += block(0x00000006, body)
    return out
