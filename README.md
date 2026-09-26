# pcap-triage

Read a packet capture and print what is in it: who talked to whom, over what, which names were asked for, and the handful of things worth a second look.

This is a tool for the first ten minutes with a capture you did not take yourself. Someone hands you a file, or you pull one off a machine, and before opening it in something heavier you want to know roughly what happened. It reads the file, counts things, and prints a page. It never opens a socket, never touches an interface, and never modifies the capture.

## What it needs

Python 3.8 or newer. Nothing else. There are no dependencies to install and no build step.

## Running it

```
python3 -m pcaptriage capture.pcap
python3 -m pcaptriage capture.pcap --top 5
```

To try it without a capture of your own, generate one:

```
python3 examples/make-sample.py sample.pcap
python3 -m pcaptriage sample.pcap
```

That sample is assembled in memory, packet by packet, so it holds nothing from the machine that made it. It contains two dns lookups, two tls handshakes, two http requests (one carrying credentials) and one source touching a lot of ports, which is enough to exercise every part of the report.

## What the output looks like

This is real output from the sample capture above, not an illustration:

```
30 packets, 1.9 KB, spanning 1.2 minutes
from 2026-09-18 01:30:35 to 2026-09-18 01:31:46

top talkers
       28 packets     1.8 KB  10.0.0.5 -> 93.184.216.34
        2 packets      146 B  10.0.0.5 -> 10.0.0.1

protocols
       28  TCP
        2  UDP

busiest services
        2  UDP/53
        2  TCP/443
        2  TCP/80
        1  TCP/2000
        ...
  and 17 more

names asked for
        1  example.org
        1  cdn.example.net

tls server names
        1  example.org
        1  cdn.example.net

http hosts
        2  example.org

http requests
        1  GET /index.html
        1  GET /admin

what stands out
  - 1 request from 10.0.0.5 to 93.184.216.34 carried credentials in the clear (/admin)
  - 10.0.0.5 reached 27 different ports on the hosts it talked to
```

## The sections, and what each one is for

**top talkers** counts packets and bytes for each pair of addresses, largest first. This is usually the fastest way to spot the machine that is doing all the talking, or the one address everything is talking to. Bytes here are whole packets on the wire, so they add up to the size in the header.

**protocols** is the split between TCP and UDP across the capture. A capture that is almost entirely UDP where you expected TCP is worth noticing.

**busiest services** counts packets per protocol and destination port. It answers "what was actually being used" without needing to know anything about the traffic.

**names asked for** lists the names in dns queries. Responses are ignored, so a name appears once per time it was looked up rather than twice.

**tls server names** lists the host names from TLS ClientHello handshakes. This is the one useful piece of information in an otherwise encrypted conversation: the client says the name it wants before anything is encrypted. Plain HTTP hosts also turn up here.

**http hosts** and **http requests** list the Host header and the method and path of requests sent over HTTP. Only the first packet of a request can be read, which is all that is needed for a Host header.

**what stands out** is the short list of things this tool will say something about rather than just count:

  - HTTP requests carrying an Authorization header with Basic or Bearer credentials. Basic auth is base64, not encryption, and a Bearer token is a working credential on its own; either one over plain HTTP is readable by anything on the path. FTP USER/PASS commands sent on the control connection are the same finding: FTP has no built-in transport security to begin with.
  - One source reaching twenty or more different ports. That is not proof of a sweep, but it is the shape of one, and it is worth a look before dismissing it.
  - A capture with no names in it at all, which usually means the interesting part is encrypted or that only IP addresses were in use.

When none of those apply, it says so rather than padding the section out.

## What it reads

  - Classic libpcap files, in either byte order, with microsecond or nanosecond timestamps.
  - Ethernet and raw IP link layers. The link type is taken from the file header, so a capture from a tunnel works without being told.
  - IPv4 including headers with options, and the declared length is used rather than the buffer end, because small frames arrive padded.
  - TCP and UDP, including TCP headers with options.
  - DNS query names, TLS ClientHello server names, HTTP Host headers, HTTP request lines, Basic/Bearer auth headers, and FTP USER/PASS commands.

Anything it cannot read is skipped rather than guessed at. A capture that is truncated part way through a record still reports everything before the truncation, which matters when the file is the last thing a machine wrote before it died.

## What it deliberately does not do

  - **No stream reassembly.** A name in a DNS question, a Host header and a TLS server name each fit inside one packet, and those answer the question this tool asks. Following a TCP conversation across packets is a different tool and would make this one much larger.
  - **No decryption, and nothing that pretends to be.** Where traffic is encrypted you get the handshake's server name and nothing more.
  - **No live capture.** Tcpdump and dumpcap already do that well. This reads files.
  - **No pcapng, no IPv6, no ARP, no ICMP yet.** These are the next things on the list, in that order.

It also does not try to identify malware, look anything up online, or produce a verdict. It counts, it lists names, and it points at a few things. The judgement is yours.

## Exit codes

```
0  a report was printed, nothing in it stood out
1  the capture was readable but held no packets
2  the capture could not be read, or the options made no sense
3  a report was printed and something in it is worth a second look
```

The separation matters when running it over a directory of captures in a loop: a file that is not a capture is a different problem from a capture with nothing in it.

## Testing

```
bash tests/run-tests.sh
```

Seventy tests across five modules, covering the reader, the protocol parsers, the application readers, the report and the command line. There is no recorded traffic in the repository. Every test builds the packets it needs byte by byte through `tests/capture_builder.py`, so the parsers are checked against the real formats rather than against this tool's own output, and nothing private can leak through a fixture.

## How the code is laid out

```
pcaptriage/pcap.py     reading capture files
pcaptriage/parse.py    link, network and transport layers
pcaptriage/apps.py     dns, tls and http extraction
pcaptriage/report.py   counting, and the text of the report
pcaptriage/cli.py      argument handling and printing
tests/                 the suite, and the packet builder it uses
examples/              a script that writes a capture to look at
```

Each layer returns None rather than raising when the bytes are not what it expected. A capture is a pile of other people's packets, and refusing to continue because one of them is damaged is the wrong behaviour for a triage tool.

## License

MIT. See LICENSE.
