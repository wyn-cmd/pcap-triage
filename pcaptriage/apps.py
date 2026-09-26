"""The application layer, only as far as it helps triage.

Nothing here reassembles a stream. A name in a DNS question, a Host header and a
TLS server name all sit inside a single packet, and pulling those out answers
most of the question "what was this machine talking to". Full reassembly would
be a different tool.
"""

import struct

DNS_PORT = 53
HTTP_PORTS = (80, 8080, 8000, 8081)
TLS_PORTS = (443, 8443, 9443)

HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS",
                b"PATCH", b"CONNECT", b"TRACE")

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_EXTENSION_SERVER_NAME = 0x0000


def dns_question(payload, port):
    """The name a DNS query asks about, or None.

    Only the first question is read. That is what a resolver answers, and the
    rare query carrying several questions is not worth the extra parsing.
    """
    if port != DNS_PORT or len(payload) < 13:
        return None
    # Bit 15 of the flags marks a response, and a response repeats a name the
    # query already showed.
    flags = struct.unpack("!H", payload[2:4])[0]
    if flags & 0x8000:
        return None
    question_count = struct.unpack("!H", payload[4:6])[0]
    if question_count == 0:
        return None

    labels = []
    offset = 12
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            break
        # The two top bits set mean a compression pointer, which has no business
        # being in the question of a query.
        if length & 0xC0:
            return None
        offset += 1
        label = payload[offset:offset + length]
        if len(label) < length:
            return None
        labels.append(label.decode("ascii", "replace"))
        offset += length
    if not labels:
        return None
    return ".".join(labels)


def tls_server_name(payload, port):
    """The host name in a TLS ClientHello, or None.

    This is the one useful thing in a TLS handshake: the name the client asked
    for before the connection was encrypted.
    """
    if not payload or payload[0] != TLS_HANDSHAKE:
        return None
    # Record: type(1) version(2) length(2), then the handshake message.
    if len(payload) < 43 or payload[5] != TLS_CLIENT_HELLO:
        return None

    # version(2) random(32) then the session id.
    offset = 43
    if len(payload) < offset + 1:
        return None
    session_length = payload[offset]
    offset += 1 + session_length

    # The cipher suites, then the compression methods.
    if len(payload) < offset + 2:
        return None
    suites_length = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2 + suites_length
    if len(payload) < offset + 1:
        return None
    compression_length = payload[offset]
    offset += 1 + compression_length

    if len(payload) < offset + 2:
        return None
    extensions_length = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2
    end = min(offset + extensions_length, len(payload))

    while offset + 4 <= end:
        kind, length = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
        if offset + length > end:
            return None
        if kind == TLS_EXTENSION_SERVER_NAME:
            return _server_name_entry(payload[offset:offset + length])
        offset += length
    return None


def _server_name_entry(data):
    """Pull the host name out of a server_name extension."""
    if len(data) < 5:
        return None
    # The extension is a list of names; the first is the host name.
    name_type = data[2]
    name_length = struct.unpack("!H", data[3:5])[0]
    if name_type != 0 or len(data) < 5 + name_length:
        return None
    return data[5:5 + name_length].decode("ascii", "replace")


def looks_like_http_request(payload):
    return bool(payload) and payload[:8].split(b" ")[0].strip() in HTTP_METHODS


def http_request_line(payload):
    """Return (method, path) from the start of an HTTP request, or (None, None)."""
    if not looks_like_http_request(payload):
        return None, None
    line = payload.split(b"\r\n", 1)[0]
    parts = line.split(b" ")
    if len(parts) < 2:
        return None, None
    return (parts[0].decode("ascii", "replace"),
            parts[1].decode("ascii", "replace"))


def http_host(payload, port):
    """The Host header of an HTTP request, or None."""
    if port not in HTTP_PORTS or not looks_like_http_request(payload):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"host":
            return value.strip().decode("ascii", "replace")
    return None


def http_basic_auth(payload, port):
    """True when an HTTP request carries Basic credentials in the clear.

    A Basic header is base64, not encryption, so anything carrying one over
    plain HTTP is worth naming in the report.
    """
    return http_credential_scheme(payload, port) == "basic"


def http_credential_scheme(payload, port):
    """The Authorization scheme on a plaintext HTTP request, or None.

    Basic and Bearer are both worth flagging: a Basic header decodes straight
    to a username and password, and a Bearer token is a working credential in
    its own right, no decoding needed. Digest is left alone, since the wire
    value there is a hash of the password rather than the password itself.
    """
    if port not in HTTP_PORTS or not looks_like_http_request(payload):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() != b"authorization":
            continue
        scheme = value.strip().split(b" ", 1)[0].lower()
        if scheme == b"basic":
            return "basic"
        if scheme == b"bearer":
            return "bearer"
        return None
    return None


FTP_PORT = 21


def ftp_credential(payload):
    """A username or password sent as plain FTP control commands, or None.

    FTP has no built-in transport security: authentication is two commands,
    USER then PASS, sent as clear text on the control connection. Either one
    on its own is a finding, since both are read directly off the wire with
    no encoding step to undo.
    """
    if not payload:
        return None
    line = payload.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    parts = line.split(b" ", 1)
    if len(parts) != 2:
        return None
    command = parts[0].strip().upper()
    if command not in (b"USER", b"PASS"):
        return None
    value = parts[1].strip()
    if not value:
        return None
    return command.decode("ascii"), value.decode("ascii", "replace")
