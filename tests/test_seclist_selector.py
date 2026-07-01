"""
Unit tests for final_code/src/seclist_selector.py.

Mocks the Ollama HTTP call (no network) and verifies:
  1. JSON array extraction tolerates clean / fenced / prefixed output
  2. build_user_prompt embeds the (API, source) pair, finding, and catalog
  3. Happy path — model returns valid catalog paths
  4. Paths outside the catalog are dropped (anti-hallucination)
  5. Model error / no valid path triggers the static-map fallback
  6. Output is deduped and clamped to max_wordlists
  7. PayloadGen-style chat request shape
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

# Make src/ importable
SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import seclist_selector  # noqa: E402
from seclist_selector import (  # noqa: E402
    SecListClient,
    _extract_json_array_of_strings,
    build_user_prompt,
    load_catalog,
    select_wordlists,
)


CATALOG = [
    "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
    "Fuzzing/XSS/XSS-Jhaddix.txt",
    "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    "Discovery/Web-Content/common.txt",
]

SAMPLE_FINDING = {
    "cwe_id": "CWE-89",
    "cwe_name": "SQL Injection",
    "severity": "HIGH",
    "evidence": "f\"SELECT * FROM users WHERE username = '{username}'\"",
    "description": "User input concatenated into SQL.",
}

SAMPLE_SOURCE = '''def get_user(username: str):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return cur.execute(query).fetchall()
'''

SAMPLE_API = {
    "endpoint": "/user/<username>",
    "method": "GET",
    "target_url": "http://host.docker.internal:5055/user/FUZZ",
    "function": "get_user",
}


# ── _extract_json_array_of_strings ─────────────────────────────────────────────


def test_extract_clean_array():
    assert _extract_json_array_of_strings('["a", "b"]') == ["a", "b"]


def test_extract_markdown_fenced():
    assert _extract_json_array_of_strings('```json\n["x", "y"]\n```') == ["x", "y"]


def test_extract_with_leading_text():
    assert _extract_json_array_of_strings('Use these:\n["p1", "p2"]') == ["p1", "p2"]


def test_extract_malformed_returns_empty():
    assert _extract_json_array_of_strings("not json") == []
    assert _extract_json_array_of_strings("[unterminated") == []


# ── build_user_prompt ─────────────────────────────────────────────────────────


def test_build_user_prompt_embeds_api_source_finding_and_catalog():
    p = build_user_prompt(SAMPLE_API, SAMPLE_SOURCE, SAMPLE_FINDING, CATALOG)
    assert "/user/<username>" in p          # API
    assert "def get_user" in p              # source
    assert "CWE-89" in p                    # finding
    assert "Fuzzing/Databases/SQLi/Generic-SQLi.txt" in p  # catalog


# ── select_wordlists ──────────────────────────────────────────────────────────


class _StubClient:
    def __init__(self, response: str = "", exc: Exception | None = None):
        self.response = response
        self.exc = exc
        self.calls = 0

    def chat(self, system, user, **kwargs):
        self.calls += 1
        if self.exc:
            raise self.exc
        return self.response


def test_select_happy_path():
    stub = _StubClient(response='["Fuzzing/Databases/SQLi/Generic-SQLi.txt"]')
    out, source = select_wordlists(
        SAMPLE_FINDING, SAMPLE_SOURCE, SAMPLE_API, catalog=CATALOG, client=stub
    )
    assert source == "model"
    assert out == ["Fuzzing/Databases/SQLi/Generic-SQLi.txt"]
    assert stub.calls == 1


def test_select_drops_paths_not_in_catalog():
    # First path is hallucinated (not in catalog), second is valid.
    stub = _StubClient(response=(
        '["Fuzzing/Made/Up/path.txt", '
        '"Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt"]'
    ))
    out, source = select_wordlists(
        SAMPLE_FINDING, SAMPLE_SOURCE, SAMPLE_API, catalog=CATALOG, client=stub
    )
    assert source == "model"
    assert out == ["Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt"]


def test_select_clamps_to_max_wordlists():
    stub = _StubClient(response=(
        '["Fuzzing/Databases/SQLi/Generic-SQLi.txt", '
        '"Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt", '
        '"Discovery/Web-Content/common.txt"]'
    ))
    out, source = select_wordlists(
        SAMPLE_FINDING, SAMPLE_SOURCE, SAMPLE_API,
        catalog=CATALOG, client=stub, max_wordlists=2,
    )
    assert source == "model"
    assert len(out) == 2


def test_select_dedupes():
    stub = _StubClient(response=(
        '["Fuzzing/Databases/SQLi/Generic-SQLi.txt", '
        '"Fuzzing/Databases/SQLi/Generic-SQLi.txt"]'
    ))
    out, source = select_wordlists(
        SAMPLE_FINDING, SAMPLE_SOURCE, SAMPLE_API, catalog=CATALOG, client=stub
    )
    assert out == ["Fuzzing/Databases/SQLi/Generic-SQLi.txt"]


def test_fallback_when_model_errors():
    stub = _StubClient(exc=requests.ConnectionError("boom"))
    out, source = select_wordlists(
        SAMPLE_FINDING, SAMPLE_SOURCE, SAMPLE_API, catalog=CATALOG, client=stub
    )
    assert source == "fallback"
    assert any("SQLi" in p for p in out)  # CWE-89 entry in the static map


def test_fallback_when_no_valid_path():
    stub = _StubClient(response='["not/in/catalog.txt"]')
    out, source = select_wordlists(
        SAMPLE_FINDING, SAMPLE_SOURCE, SAMPLE_API, catalog=CATALOG, client=stub
    )
    assert source == "fallback"


def test_unknown_cwe_falls_back_to_default():
    finding = dict(SAMPLE_FINDING, cwe_id="CWE-99999-not-real")
    stub = _StubClient(exc=requests.ConnectionError("boom"))
    out, source = select_wordlists(
        finding, SAMPLE_SOURCE, SAMPLE_API, catalog=CATALOG, client=stub
    )
    assert source == "fallback"
    assert any("common.txt" in p for p in out)  # _default in the map


# ── load_catalog ──────────────────────────────────────────────────────────────


def test_load_catalog_reads_and_strips(tmp_path):
    f = tmp_path / "catalog.txt"
    f.write_text("# comment\nFuzzing/a.txt\n\n  Fuzzing/b.txt  \n")
    assert load_catalog(f) == ["Fuzzing/a.txt", "Fuzzing/b.txt"]


def test_load_catalog_missing_returns_empty(tmp_path):
    assert load_catalog(tmp_path / "nope.txt") == []


# ── SecListClient.chat — verify request shape ─────────────────────────────────


def test_chat_request_shape():
    cli = SecListClient(model="qwen3")

    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"role": "assistant", "content": '["x"]'}}

    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResp()

    with patch.object(seclist_selector.requests, "post", side_effect=fake_post):
        out = cli.chat("sys", "user")

    assert out == '["x"]'
    assert captured["url"].endswith("/api/chat")
    assert captured["json"]["model"] == "qwen3"
    assert captured["json"]["think"] is False  # thinking disabled for Qwen 3
    msgs = captured["json"]["messages"]
    assert msgs[0] == {"role": "system", "content": "sys"}
    assert msgs[1] == {"role": "user", "content": "user"}
    assert captured["json"]["stream"] is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
