"""Unit tests for the dns_query parser (v0.5 Track A4).

Run with:
    python services/ws2-normalization/parsers/test_dns_query.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(SERVICES))

from shared.ocsf import validate  # noqa: E402
from parsers.dns_query import DnsQueryParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = DnsQueryParser()


def _raw(line, meta=None):
    return {"source_type": "dns_query", "raw": line, "meta": meta or {}}


class TestDnsQueryParser(unittest.TestCase):

    def test_query_line_parses_to_dns_activity(self):
        event = PARSER.parse(_raw(
            "Jul 20 10:15:03 dnsmasq[123]: query[A] evil-c2.example.com from 10.0.0.5"))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 4002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["src_endpoint"]["ip"], "10.0.0.5")
        self.assertEqual(event["dst_endpoint"]["hostname"], "evil-c2.example.com")
        self.assertEqual(validate(event), [])

    def test_trailing_dot_stripped(self):
        event = PARSER.parse(_raw("query[AAAA] www.example.com. from 10.0.0.6"))
        self.assertEqual(event["dst_endpoint"]["hostname"], "www.example.com")

    def test_non_matching_line_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("dnsmasq[123]: reading /etc/hosts")))

    def test_non_string_raw_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"not": "a string"})))

    def test_content_sniff_routes_query_line_to_dns_query(self):
        parser = resolve({"source_type": "", "raw":
                          "query[A] example.com from 10.0.0.5", "meta": {}})
        self.assertIs(type(parser), DnsQueryParser)


if __name__ == "__main__":
    unittest.main()
