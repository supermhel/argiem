"""WS-3 triage API tests (v0.3, C1). Zero infra: MemoryStore + a real HTTP server
on an ephemeral port, mirroring services/ws6-inventory's test discipline for its
stdlib http.server API.

Run: C:/Python313/python.exe services/ws3-indexer/test_triage_api.py
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
from router import route  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def start_server(store):
    handler_cls = triage_api.make_handler(store)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def http(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def run():
    store = MemoryStore()
    alert = {"alert_id": "a-1", "time": 1750000000000, "level": "high",
            "rule_title": "test rule", "score": 70}
    idx, doc_id = route(alert)
    store.index(idx, doc_id, alert)

    srv, port = start_server(store)
    base = f"http://127.0.0.1:{port}"
    try:
        # --- tolerant default: an alert with no triage field yet -> "new" ---
        status, body = http("GET", f"{base}/alerts/a-1/triage")
        check(status == 200, f"GET existing alert triage should 200, got {status}")
        check(body["status"] == "new", "an alert with no triage field must default to 'new'")

        # --- update: status + note persist, readable back ---
        status, body = http("POST", f"{base}/alerts/a-1/triage",
                           {"status": "triaged", "note": "looks like a real scan"})
        check(status == 200, f"POST update should 200, got {status}: {body}")
        check(body["status"] == "triaged", "status must update")
        check(body["note"] == "looks like a real scan", "note must update")
        check(body["updated_at"] is not None, "updated_at must be set")

        status, body = http("GET", f"{base}/alerts/a-1/triage")
        check(status == 200 and body["status"] == "triaged",
              "triage update must PERSIST (readable back after POST)")
        check(body["note"] == "looks like a real scan", "note must persist")

        # --- underlying alert doc is untouched except for the triage field ---
        _, stored_doc = store.find_alert("a-1")
        check(stored_doc["rule_title"] == "test rule",
              "updating triage must not corrupt the original alert fields")
        check(stored_doc["score"] == 70, "score field must survive a triage update")

        # --- 404: unknown alert_id ---
        status, body = http("GET", f"{base}/alerts/does-not-exist/triage")
        check(status == 404, f"unknown alert_id should 404, got {status}")

        # --- 400s: malformed input never crashes the handler thread ---
        status, body = http("POST", f"{base}/alerts/a-1/triage", {"status": "bogus_status"})
        check(status == 400, f"invalid status enum should 400, got {status}")

        status, body = http("POST", f"{base}/alerts/a-1/triage", {"note": 12345})
        check(status == 400, f"non-string note should 400, got {status}")

        req = urllib.request.Request(
            f"{base}/alerts/a-1/triage", data=b"not json at all", method="POST",
            headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            check(False, "malformed JSON body should raise HTTPError(400)")
        except urllib.error.HTTPError as e:
            check(e.code == 400, f"malformed JSON body should 400, got {e.code}")

        # oversized body -> 400, not a crash / hang
        big_note = "x" * 10_000
        req = urllib.request.Request(
            f"{base}/alerts/a-1/triage",
            data=json.dumps({"note": big_note}).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            check(False, "oversized body should raise HTTPError(400)")
        except urllib.error.HTTPError as e:
            check(e.code == 400, f"oversized body should 400, got {e.code}")

        # server must still be responsive after all the bad input above
        status, body = http("GET", f"{base}/alerts/a-1/triage")
        check(status == 200, "server must still respond after malformed requests "
                             "(handler thread must never crash)")
    finally:
        srv.shutdown()
        srv.server_close()


def main():
    run()
    if FAILS:
        print(f"[FAIL] triage API: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-3 triage API: persistence + tolerant defaults + malformed-input handling")


if __name__ == "__main__":
    main()
