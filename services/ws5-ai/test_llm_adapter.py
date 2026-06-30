"""WS-5 LLM adapter tests — no live Ollama, stdlib unittest only.

Everything network-facing is mocked by monkeypatching urllib.request.urlopen.
We never reach a real server. Covered:

  * OllamaLLM parses a well-formed mocked Ollama HTTP response into the verdict shape.
  * Malformed model output (non-JSON `response`) degrades to a safe default, no raise.
  * Out-of-enum verdict/level get coerced to the safe defaults.
  * A connection failure (urlopen raises) -> FallbackLLM degrades to the stub, no raise.
  * make_llm() with no OLLAMA_URL returns StubLLM (no-regression for the stub path).
"""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

import llm_adapter  # noqa: E402


def _ollama_resp(model_text: str):
    """Build a fake urlopen() context manager returning Ollama's envelope."""
    payload = json.dumps({"response": model_text, "done": True}).encode()
    cm = mock.MagicMock()
    cm.__enter__.return_value = io.BytesIO(payload)
    cm.__exit__.return_value = False
    return cm


SAMPLE_EVENT = {"class_uid": 3002, "severity_id": 5,
                "siem": {"sector": "bank", "score": 85}}
SAMPLE_REASONS = ["brute-force window exceeded"]


class TestOllamaParsing(unittest.TestCase):
    def test_wellformed_response_parsed(self):
        good = json.dumps({"verdict": "malicious", "level": "critical",
                           "summary": "10 failed logins then success"})
        with mock.patch("urllib.request.urlopen", return_value=_ollama_resp(good)):
            out = llm_adapter.OllamaLLM(url="http://x").analyze(SAMPLE_EVENT, SAMPLE_REASONS)
        self.assertEqual(out["verdict"], "malicious")
        self.assertEqual(out["level"], "critical")
        self.assertIn("failed logins", out["summary"])
        self.assertEqual(set(out), {"verdict", "summary", "level"})

    def test_malformed_nonjson_output_degrades_safely(self):
        with mock.patch("urllib.request.urlopen",
                        return_value=_ollama_resp("sorry, I cannot do that")):
            out = llm_adapter.OllamaLLM(url="http://x").analyze(SAMPLE_EVENT, SAMPLE_REASONS)
        self.assertEqual(out["verdict"], "unknown")
        self.assertEqual(out["level"], "low")
        self.assertIn("sorry", out["summary"])

    def test_out_of_enum_values_coerced(self):
        weird = json.dumps({"verdict": "TOTALLY_BAD", "level": "apocalyptic",
                            "summary": "x"})
        with mock.patch("urllib.request.urlopen", return_value=_ollama_resp(weird)):
            out = llm_adapter.OllamaLLM(url="http://x").analyze(SAMPLE_EVENT, SAMPLE_REASONS)
        self.assertEqual(out["verdict"], "unknown")
        self.assertEqual(out["level"], "low")


class TestFallback(unittest.TestCase):
    def test_connection_failure_degrades_to_stub_no_raise(self):
        def boom(*a, **k):
            raise urllib.error.URLError("connection refused")

        llm = llm_adapter.FallbackLLM(llm_adapter.OllamaLLM(url="http://x"),
                                      llm_adapter.StubLLM())
        with mock.patch("urllib.request.urlopen", side_effect=boom):
            out = llm.analyze(SAMPLE_EVENT, SAMPLE_REASONS)
        # stub verdict for score 85 -> malicious/critical
        self.assertEqual(out["verdict"], "malicious")
        self.assertEqual(out["level"], "critical")

    def test_timeout_degrades_to_stub(self):
        def boom(*a, **k):
            raise TimeoutError("timed out")

        llm = llm_adapter.FallbackLLM(llm_adapter.OllamaLLM(url="http://x"),
                                      llm_adapter.StubLLM())
        with mock.patch("urllib.request.urlopen", side_effect=boom):
            out = llm.analyze(SAMPLE_EVENT, SAMPLE_REASONS)
        self.assertEqual(out["verdict"], "malicious")


class TestSelection(unittest.TestCase):
    def test_no_ollama_url_returns_stub(self):
        env = dict(os.environ)
        os.environ.pop("OLLAMA_URL", None)
        try:
            llm = llm_adapter.make_llm()
        finally:
            os.environ.clear()
            os.environ.update(env)
        self.assertIsInstance(llm, llm_adapter.StubLLM)

    def test_ollama_url_set_but_unreachable_returns_stub(self):
        with mock.patch.object(llm_adapter.OllamaLLM, "ping", return_value=False):
            with mock.patch.dict(os.environ, {"OLLAMA_URL": "http://nope:11434"}):
                llm = llm_adapter.make_llm()
        self.assertIsInstance(llm, llm_adapter.StubLLM)

    def test_ollama_url_set_and_reachable_returns_fallback(self):
        with mock.patch.object(llm_adapter.OllamaLLM, "ping", return_value=True):
            with mock.patch.dict(os.environ, {"OLLAMA_URL": "http://ok:11434"}):
                llm = llm_adapter.make_llm()
        self.assertIsInstance(llm, llm_adapter.FallbackLLM)
        self.assertIsInstance(llm.primary, llm_adapter.OllamaLLM)
        self.assertIsInstance(llm.backup, llm_adapter.StubLLM)


class TestStubRegression(unittest.TestCase):
    """The stub must produce exactly what the contract test relied on before."""

    def test_stub_score_bands(self):
        stub = llm_adapter.StubLLM()
        hi = stub.analyze({"siem": {"sector": "bank", "score": 85}}, ["r"])
        self.assertEqual((hi["verdict"], hi["level"]), ("malicious", "critical"))
        mid = stub.analyze({"siem": {"sector": "bank", "score": 65}}, ["r"])
        self.assertEqual((mid["verdict"], mid["level"]), ("suspicious", "high"))
        lo = stub.analyze({"siem": {"sector": "bank", "score": 10}}, [])
        self.assertEqual((lo["verdict"], lo["level"]), ("benign", "low"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
