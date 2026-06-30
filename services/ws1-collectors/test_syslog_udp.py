"""Tests for the real UDP syslog listener (stdlib unittest, zero infra).

Binds the listener to 127.0.0.1 on an ephemeral port, sends a real syslog
datagram over a UDP socket, and asserts a correctly-shaped raw event lands on
``raw.events`` of an in-memory bus. Deterministic: ephemeral port (0), and the
bus is polled with a short timeout instead of a fixed sleep.
"""
from __future__ import annotations

import os
import socket
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from collectors.syslog_udp_server import SyslogUDPServer, build_raw_event  # noqa: E402

SYSLOG_LINE = "<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root"


def _poll(predicate, timeout=2.0, interval=0.01):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval)
    return predicate()


class TestSyslogUDPServer(unittest.TestCase):
    def setUp(self):
        self.bus = Bus()
        # port 0 -> OS picks an ephemeral free port; .port reflects the real one
        self.server = SyslogUDPServer(
            self.bus, host="127.0.0.1", port=0, deterministic_id=True)
        self.server.start()

    def tearDown(self):
        self.server.stop()

    def test_datagram_becomes_raw_event(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(SYSLOG_LINE.encode("utf-8"),
                        ("127.0.0.1", self.server.port))
        finally:
            sock.close()

        msgs = _poll(lambda: self.bus.drain("raw.events"))
        self.assertTrue(msgs, "no raw event landed on raw.events")
        self.assertEqual(len(msgs), 1)

        msg = msgs[0]
        payload = msg.payload
        self.assertEqual(payload["source_type"], "generic_syslog")
        self.assertEqual(payload["raw"], SYSLOG_LINE)
        self.assertIn("meta", payload)
        self.assertIn("received_at", payload["meta"])
        self.assertIn("ingest_id", payload["meta"])
        self.assertEqual(msg.key, "127.0.0.1")  # peer IP is the partition key

    def test_build_raw_event_shape(self):
        evt = build_raw_event("hello", deterministic_id=True)
        self.assertEqual(evt["source_type"], "generic_syslog")
        self.assertEqual(evt["raw"], "hello")
        self.assertIsInstance(evt["meta"]["received_at"], int)
        # deterministic id is stable for the same line
        self.assertEqual(evt["meta"]["ingest_id"],
                         build_raw_event("hello", deterministic_id=True)["meta"]["ingest_id"])


if __name__ == "__main__":
    unittest.main()
