"""DX2-live: in-stack auto-feeder.

On `docker compose up`, inject a realistic SSH brute-force burst into the LIVE
pipeline (Redis stream `raw.events`) so the dashboard shows a REAL alert with no
manual step.

It mirrors exactly how the pipeline expects raw events:
  - bus write shape: shared.bus._RedisBus.produce ->
        XADD raw.events {"key": <ip>, "payload": json.dumps(event)}
  - raw SSH event shape: tools/demo_e2e.py ssh_fail()

>=10 failed logins from one attacker IP within a 60s window trip
common_bruteforce.yml (threshold 10, window 60s, group_by src_endpoint.ip),
which fires a 'brute-force' alert with score 70 that lands in alerts-*.

Idempotency note: `ingest_ids` are deterministic so the INDEXER deduplicates
events (same doc_id -> no duplicate in OpenSearch). However the feeder itself is
NOT idempotent at the Redis stream level — each run XADDs new stream entries.
Downstream dedup (deterministic alert_id) means repeated runs produce the same
alert rather than multiplying it, but the stream will grow.
One-shot: produces the burst, then exits 0.
"""
from __future__ import annotations

import json
import os
import sys
import time

import redis

ATTACKER_IP = os.getenv("FEEDER_ATTACKER_IP", "198.51.100.23")
COUNT = min(int(os.getenv("FEEDER_COUNT", "12")), 59)  # >= threshold (10); cap at 59 (syslog seconds field)
TOPIC = "raw.events"
# Use a fixed minute base so all events share the same 60s window. The syslog
# line's seconds field (:NN) is cosmetic; the detector windows on meta time.
BASE_S = int(os.getenv("FEEDER_BASE_S", "1750000000"))


def ssh_fail(i: int) -> dict:
    """One raw 'Failed password' syslog line from the attacker IP, +i seconds.

    Mirrors tools/demo_e2e.py ssh_fail() exactly (shape + meta fields)."""
    return {
        "source_type": "linux_ssh",
        "raw": (f"Jun 10 13:55:{i:02d} db01 sshd[2154]: "
                f"Failed password for invalid user admin from {ATTACKER_IP} port 51000 ssh2"),
        "meta": {"received_at": BASE_S + i, "ingest_id": f"ssh-{ATTACKER_IP}-{i}"},
    }


def main() -> int:
    url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    # depends_on waits for the redis healthcheck, but keep a short retry loop so a
    # cold start (redis accepting pings before fully ready) can't flake the feed.
    r = redis.Redis.from_url(url, decode_responses=True)
    for attempt in range(30):
        try:
            r.ping()
            break
        except Exception as e:  # noqa: BLE001
            print(f"[feeder] redis not ready ({e}); retry {attempt + 1}/30", flush=True)
            time.sleep(2)
    else:
        print("[feeder] redis never became reachable; giving up", file=sys.stderr)
        return 1

    print(f"[feeder] producing {COUNT} failed-SSH events for {ATTACKER_IP} "
          f"to {TOPIC} within a 60s window", flush=True)
    for i in range(COUNT):
        ev = ssh_fail(i)
        # Mirror _RedisBus.produce exactly: fields {key, payload(json)}.
        r.xadd(TOPIC, {"key": ATTACKER_IP, "payload": json.dumps(ev)})

    print(f"[feeder] done. {COUNT} events queued. The brute-force rule "
          f"(threshold 10/60s) should fire and a score-70 alert should land in "
          f"alerts-*. Idempotent: rerun dedups via deterministic alert_id.",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
