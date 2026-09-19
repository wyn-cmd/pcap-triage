#!/usr/bin/env python3
"""Write a small capture to look at.

No real traffic is involved: every packet here is assembled in memory, so the
file can be shared, committed or inspected without leaking anything from the
machine that ran it. The result is a capture with dns lookups, a couple of http
requests, two tls handshakes and one source reaching a lot of ports, which is
enough to show every part of the report.

Usage: make-sample.py [output.pcap]
"""

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "tests"))

import capture_builder as build  # noqa: E402

CLIENT = "10.0.0.5"
GATEWAY = "10.0.0.1"
SERVER = "93.184.216.34"
NAMES = ("example.org", "cdn.example.net")


def dns_frame(name, at):
    query = build.dns_query(name, txid=abs(hash(name)) % 60000)
    return (at, build.ethernet(build.ipv4(CLIENT, GATEWAY, 17, query)))


def tcp_frame(payload, sport, dport, at, dst=SERVER):
    segment = build.tcp(sport, dport, payload)
    return (at, build.ethernet(build.ipv4(CLIENT, dst, 6, segment)))


def sample():
    start = time.time() - 600
    packets = []

    for index, name in enumerate(NAMES):
        packets.append(dns_frame(name, start + index))
    for index, name in enumerate(NAMES):
        packets.append(tcp_frame(build.tls_client_hello(name), 51000 + index, 443,
                                 start + 10 + index))
    packets.append(tcp_frame(build.http_request("example.org", "/index.html"),
                             52000, 80, start + 30))
    packets.append(tcp_frame(build.http_request("example.org", "/admin",
                                                auth="YWRtaW46aHVudGVyMg=="),
                             52001, 80, start + 31))
    # One source touching many ports, which the report points out.
    for index in range(24):
        packets.append(tcp_frame(b"", 53000 + index, 2000 + index, start + 60 + index * 0.5))

    packets.sort(key=lambda entry: entry[0])
    return packets


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    with open(target, "wb") as handle:
        handle.write(build.pcap(sample()))
    print(f"wrote {target}")
    print(f"read it with: python3 -m pcaptriage {target}")


if __name__ == "__main__":
    main()
