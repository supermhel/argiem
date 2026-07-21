"""DNS query-log parser: dnsmasq/BIND-style query lines -> OCSF DNS/HTTP Activity (4002).

v0.5 Track A4 (unblocks the first class-4002 producer, see
contracts/detection-coverage.md's long-standing gap). Targets the common
`dnsmasq` query-log line shape (BIND's `named` query log is textually very
similar: ``client <ip>#<port>: query: <name> IN <type>``, not separately
handled here since the field extraction is the same).

Typical line::

    Jul 20 10:15:03 dnsmasq[123]: query[A] evil-c2.example.com from 10.0.0.5

Mapping (Contract A / ocsf-classes.md): class 4002, activity_id 1 (best-fit
"query" activity -- Contract A's worked table doesn't enumerate 4002
activity_ids explicitly; 1 follows the same "first/primary activity" pattern
used for 3002 Logon and 6003 Create). The queried domain goes in
``dst_endpoint.hostname`` (the field already mapped in
contracts/opensearch-mappings/events-common.json), so no new schema field is
needed and common_dns_exfil.yml can group/distinct-count on it directly.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import Parser, SEV_INFO

_CLASS = 4002  # DNS / HTTP Activity

# "query[A] evil-c2.example.com from 10.0.0.5" (dnsmasq)
_QUERY = re.compile(
    r"query\[(?P<qtype>[A-Za-z]+)\]\s+(?P<name>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)"
)


class DnsQueryParser(Parser):
    SOURCE_TYPE = "dns_query"
    SECTOR = "common"
    ORIGINAL_FORMAT = "syslog"
    PRODUCT = {"name": "dnsmasq", "vendor_name": "Simon Kelley"}

    def parse(self, raw: dict) -> Optional[dict]:
        line = raw.get("raw")
        if not isinstance(line, str):
            return None
        m = _QUERY.search(line)
        if not m:
            return None
        meta = raw.get("meta") or {}
        name = m.group("name").rstrip(".")
        if not name:
            return None

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=1,
            severity_id=SEV_INFO,
            time_ms=self._time_ms(meta),
            ingest_id=meta.get("ingest_id"),
            message=f"DNS query {m.group('qtype')} {name} from {m.group('ip')}",
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        event["src_endpoint"] = {"ip": m.group("ip")}
        event["dst_endpoint"] = {"hostname": name}
        return event

    @staticmethod
    def _time_ms(meta: dict) -> int:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return int(time.time() * 1000)
