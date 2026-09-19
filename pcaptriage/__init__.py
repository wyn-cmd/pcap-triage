"""Offline triage for a packet capture.

Read a capture, print what happened in it: who talked to whom, what protocols
were in play, which names were asked for, and anything that stands out.

Nothing here opens a socket. The whole point is to look at traffic after the
fact, on a machine that is not part of the incident.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
