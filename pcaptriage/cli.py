"""Command line entry point.

Kept thin on purpose: read the capture, build the summary, print it. Anything
that grows beyond that belongs in the modules it calls.
"""

import argparse
import json
import sys

from . import __version__
from . import pcap
from . import report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pcap-triage",
        description="Read a capture and print a short triage report.")
    parser.add_argument("capture", help="a .pcap file to read")
    parser.add_argument("-n", "--top", type=int, default=10,
                        help="rows to show per section (default: 10)")
    parser.add_argument("--host", metavar="ADDRESS",
                        help="only count traffic to or from this address")
    parser.add_argument("--json", action="store_true",
                        help="print the counts as JSON instead of a report")
    parser.add_argument("--version", action="version",
                        version=f"pcap-triage {__version__}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.top < 1:
        print("pcap-triage: --top has to be at least 1", file=sys.stderr)
        return 2

    try:
        packets = pcap.read_packets(args.capture)
        summary = report.summarise(packets, host=args.host)
    except FileNotFoundError:
        print(f"pcap-triage: no such file: {args.capture}", file=sys.stderr)
        return 2
    except pcap.CaptureError as error:
        print(f"pcap-triage: {error}", file=sys.stderr)
        return 2

    if not summary.packets:
        print("pcap-triage: the capture holds no packets", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_dict(summary, top=args.top), indent=2))
    else:
        print(report.render(summary, top=args.top), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
