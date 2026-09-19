"""Turning a capture into something a person can read.

The order of the sections is deliberate. Addresses first, because that is what
most people are looking for, then the shape of the traffic, then the names, then
the handful of things that are actually worth a second look.
"""

import time

from collections import Counter, defaultdict

from . import apps
from . import parse

# A source touching this many different ports on one destination is doing
# something broader than using a service.
SCAN_PORTS = 20


def human_bytes(count):
    for unit, size in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if count >= size:
            return f"{count / size:.1f} {unit}"
    return f"{count} B"


def human_duration(seconds):
    if seconds < 1:
        return "under a second"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    return f"{seconds / 3600:.1f} hours"


def stamp(seconds):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(seconds))


class Summary:
    """Everything the report needs, gathered in one pass over the packets."""

    def __init__(self):
        self.packets = 0
        self.total_bytes = 0
        self.first = None
        self.last = None
        self.talkers = Counter()
        self.talker_bytes = Counter()
        self.protocols = Counter()
        self.services = Counter()
        self.dns_names = Counter()
        self.tls_names = Counter()
        self.http_hosts = Counter()
        self.http_requests = Counter()
        self.credentials = Counter()
        self.destination_ports = defaultdict(set)

    @property
    def duration(self):
        if self.first is None or self.last is None:
            return 0
        return max(0, self.last - self.first)


def summarise(packets):
    """Read a capture into a Summary."""
    summary = Summary()
    for packet in packets:
        summary.packets += 1
        summary.total_bytes += len(packet.data)
        if summary.first is None or packet.timestamp < summary.first:
            summary.first = packet.timestamp
        if summary.last is None or packet.timestamp > summary.last:
            summary.last = packet.timestamp

        for flow in parse.flows([packet]):
            pair = (flow.src, flow.dst)
            summary.talkers[pair] += 1
            # Count whole packets, so this agrees with the size in the header
            # rather than counting only the payload of each one.
            summary.talker_bytes[pair] += len(packet.data)
            summary.protocols[parse.protocol_name(flow.protocol)] += 1
            summary.services[f"{parse.protocol_name(flow.protocol)}/{flow.dport}"] += 1
            summary.destination_ports[flow.src].add(flow.dport)

            name = apps.dns_question(flow.payload, flow.dport)
            if name:
                summary.dns_names[name] += 1

            name = apps.tls_server_name(flow.payload, flow.dport)
            if name:
                summary.tls_names[name] += 1

            host = apps.http_host(flow.payload, flow.dport)
            if host:
                summary.http_hosts[host] += 1

            method, path = apps.http_request_line(flow.payload)
            if method and flow.dport in apps.HTTP_PORTS:
                summary.http_requests[(method, path)] += 1
                if apps.http_basic_auth(flow.payload, flow.dport):
                    summary.credentials[(flow.src, flow.dst, path)] += 1
    return summary


def notable(summary):
    """The lines under "what stands out", in the order they matter."""
    lines = []

    for (src, dst, path), count in summary.credentials.most_common(5):
        plural = "request" if count == 1 else "requests"
        lines.append(f"{count} {plural} from {src} to {dst} carried "
                     f"credentials in the clear ({path})")

    for src, ports in sorted(summary.destination_ports.items()):
        if len(ports) >= SCAN_PORTS:
            lines.append(f"{src} reached {len(ports)} different ports on the "
                         "hosts it talked to")

    if summary.packets and not summary.dns_names and not summary.tls_names:
        lines.append("no names were asked for, so this capture may be encrypted "
                     "beyond the handshakes or filtered to IP addresses")

    return lines


def render(summary, top=10):
    """Render a Summary as the text the command prints."""
    out = []
    span = human_duration(summary.duration)
    out.append(f"{summary.packets:,} packets, {human_bytes(summary.total_bytes)}, "
               f"spanning {span}")
    if summary.first is not None:
        out.append(f"from {stamp(summary.first)} to {stamp(summary.last)}")
    out.append("")

    def section(title, rows, formatter):
        if not rows:
            return
        out.append(title)
        for row in rows[:top]:
            out.append("  " + formatter(row))
        if len(rows) > top:
            out.append(f"  and {len(rows) - top} more")
        out.append("")

    section("top talkers", summary.talkers.most_common(),
            lambda row: f"{row[1]:>7,} packets  "
                        f"{human_bytes(summary.talker_bytes[row[0]]):>9}  "
                        f"{row[0][0]} -> {row[0][1]}")

    section("protocols", summary.protocols.most_common(),
            lambda row: f"{row[1]:>7,}  {row[0]}")

    section("busiest services", summary.services.most_common(),
            lambda row: f"{row[1]:>7,}  {row[0]}")

    section("names asked for", summary.dns_names.most_common(),
            lambda row: f"{row[1]:>7,}  {row[0]}")

    section("tls server names", summary.tls_names.most_common(),
            lambda row: f"{row[1]:>7,}  {row[0]}")

    section("http hosts", summary.http_hosts.most_common(),
            lambda row: f"{row[1]:>7,}  {row[0]}")

    section("http requests", summary.http_requests.most_common(),
            lambda row: f"{row[1]:>7,}  {row[0][0]} {row[0][1]}")

    findings = notable(summary)
    out.append("what stands out")
    if findings:
        for line in findings:
            out.append(f"  - {line}")
    else:
        out.append("  nothing obvious in the layers this tool reads")
    out.append("")

    return "\n".join(out)


def as_dict(summary, top=10):
    """The same counts in a shape another program can read."""
    return {
        "packets": summary.packets,
        "bytes": summary.total_bytes,
        "first_timestamp": summary.first,
        "last_timestamp": summary.last,
        "duration_seconds": summary.duration,
        "talkers": [
            {"src": pair[0], "dst": pair[1], "packets": count,
             "bytes": summary.talker_bytes[pair]}
            for pair, count in summary.talkers.most_common(top)],
        "protocols": dict(summary.protocols.most_common(top)),
        "services": dict(summary.services.most_common(top)),
        "dns_names": dict(summary.dns_names.most_common(top)),
        "tls_names": dict(summary.tls_names.most_common(top)),
        "http_hosts": dict(summary.http_hosts.most_common(top)),
        "http_requests": [
            {"method": key[0], "path": key[1], "count": count}
            for key, count in summary.http_requests.most_common(top)],
        "notable": notable(summary),
    }
