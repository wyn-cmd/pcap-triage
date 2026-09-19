"""Reading capture files.

Only the classic libpcap format is handled for now. It starts with a magic
number and a fixed header, then a run of records, each with a timestamp and a
length. Both byte orders turn up in the wild, and some captures count time in
nanoseconds rather than microseconds, so the header decides how to read the
records rather than a flag on the command line.
"""

import struct

from collections import namedtuple

# The four magic numbers a capture can start with. The first two are microsecond
# captures, the last two nanosecond ones, and the byte order differs between the
# two ends of the list.
MAGIC_USEC_LE = b"\xd4\xc3\xb2\xa1"
MAGIC_USEC_BE = b"\xa1\xb2\xc3\xd4"
MAGIC_NSEC_LE = b"\x4d\x3c\xb2\xa1"
MAGIC_NSEC_BE = b"\xa1\xb2\x3c\x4d"

# A pcapng file is a different format wearing the same idea.
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"

# Link types this tool understands. Ethernet covers almost everything captured
# on a normal machine, raw IP turns up in tunnel captures.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

Packet = namedtuple("Packet", "timestamp data linktype")


class CaptureError(Exception):
    """The file is not a capture this tool can read."""


class Capture:
    """A parsed capture header, and the packets that follow it."""

    def __init__(self, byte_order, nanosecond, linktype, version):
        self.byte_order = byte_order
        self.nanosecond = nanosecond
        self.linktype = linktype
        self.version = version

    @property
    def divisor(self):
        """What to divide the record timestamps by to get seconds."""
        return 1_000_000_000 if self.nanosecond else 1_000_000


def sniff_format(path):
    """Return 'pcap', 'pcapng' or None for a file that is neither."""
    with open(path, "rb") as handle:
        magic = handle.read(4)
    if magic in (MAGIC_USEC_LE, MAGIC_USEC_BE, MAGIC_NSEC_LE, MAGIC_NSEC_BE):
        return "pcap"
    if magic == MAGIC_PCAPNG:
        return "pcapng"
    return None


class PcapReader:
    """Iterate the packets of a classic libpcap capture."""

    def __init__(self, handle):
        self.handle = handle
        self.capture = self._read_header()

    def _read_header(self):
        raw = self.handle.read(24)
        if len(raw) < 24:
            raise CaptureError("the file is too short to hold a capture header")

        magic = raw[:4]
        if magic == MAGIC_USEC_LE:
            byte_order, nanosecond = "<", False
        elif magic == MAGIC_USEC_BE:
            byte_order, nanosecond = ">", False
        elif magic == MAGIC_NSEC_LE:
            byte_order, nanosecond = "<", True
        elif magic == MAGIC_NSEC_BE:
            byte_order, nanosecond = ">", True
        elif magic == MAGIC_PCAPNG:
            raise CaptureError("this is a pcapng file, not a classic pcap one")
        else:
            raise CaptureError("the file does not start with a capture header")

        header = struct.Struct(byte_order + "IHHiIII")
        _, major, minor, _, _, _, linktype = header.unpack(raw)
        return Capture(byte_order, nanosecond, linktype, (major, minor))

    def __iter__(self):
        record = struct.Struct(self.capture.byte_order + "IIII")
        while True:
            raw = self.handle.read(16)
            if len(raw) < 16:
                return
            seconds, fraction, captured, _ = record.unpack(raw)
            data = self.handle.read(captured)
            if len(data) < captured:
                # A capture cut off part way through a record is still worth
                # reading: everything before the truncation is intact.
                return
            yield Packet(seconds + fraction / self.capture.divisor,
                         data, self.capture.linktype)


BLOCK_SECTION_HEADER = 0x0A0D0D0A
BLOCK_INTERFACE_DESCRIPTION = 0x00000001
BLOCK_ENHANCED_PACKET = 0x00000006

BYTE_ORDER_MARK_LE = b"\x4d\x3c\x2b\x1a"

# What a pcapng timestamp counts in when the interface does not say.
DEFAULT_TICKS_PER_SECOND = 1_000_000


class PcapngReader:
    """Iterate the packets of a pcapng capture.

    A pcapng file is a run of blocks, each with a type and a length.
    Only three matter here: the section header, which carries the byte
    order, the interface description, which carries the link type, and
    the enhanced packet blocks, which carry the packets.
    """

    def __init__(self, handle):
        self.handle = handle
        self.byte_order = "<"
        self.linktype = LINKTYPE_ETHERNET
        self.ticks_per_second = DEFAULT_TICKS_PER_SECOND

    def _read(self):
        raw = self.handle.read(8)
        if len(raw) < 8:
            return None
        block_type, length = struct.unpack(self.byte_order + "II", raw)
        if length < 12:
            return None
        body = self.handle.read(length - 12)
        self.handle.read(4)
        if len(body) < length - 12:
            return None
        return block_type, body

    def __iter__(self):
        head = self.handle.read(8)
        if len(head) < 8:
            return
        # The first block is read without knowing the byte order, so
        # its length cannot be trusted yet. The mark inside it decides.
        block_type, length = struct.unpack("<II", head)
        if block_type != BLOCK_SECTION_HEADER:
            raise CaptureError("a pcapng file has to start with a section header")
        mark = self.handle.read(4)
        if mark == BYTE_ORDER_MARK_LE:
            self.byte_order = "<"
        elif mark == BYTE_ORDER_MARK_LE[::-1]:
            self.byte_order = ">"
        else:
            raise CaptureError("the section header has no byte order mark")
        # The length was read before the byte order was known, so it has
        # to be read again now that the mark has settled it.
        length = struct.unpack(self.byte_order + "I", head[4:8])[0]
        self.handle.read(max(0, length - 16))
        self.handle.read(4)

        while True:
            block = self._read()
            if block is None:
                return
            block_type, body = block
            if block_type == BLOCK_INTERFACE_DESCRIPTION and len(body) >= 8:
                self.linktype = struct.unpack(self.byte_order + "H", body[:2])[0]
            elif block_type == BLOCK_ENHANCED_PACKET and len(body) >= 20:
                _, high, low, captured = struct.unpack(
                    self.byte_order + "IIII", body[:16])
                ticks = (high << 32) | low
                yield Packet(ticks / self.ticks_per_second,
                             body[20:20 + captured], self.linktype)


def read_packets(path):
    """Yield every packet in a capture, whatever format it uses.

    The format comes from the first four bytes rather than the file
    name, because a pcapng capture renamed to .pcap is still a pcapng
    capture and reading it as anything else gives nonsense.
    """
    with open(path, "rb") as handle:
        magic = handle.read(4)
        handle.seek(0)
        if magic == MAGIC_PCAPNG:
            reader = PcapngReader(handle)
        else:
            reader = PcapReader(handle)
        for packet in reader:
            yield packet
