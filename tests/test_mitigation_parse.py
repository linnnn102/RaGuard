"""Unit tests for agentsec.prompts.parse_mitigation_response.

Covers the server.py:362 bug fix: a response WITHOUT a "fixed_code" field must
not raise UnboundLocalError — it falls through to a normal parse. Also checks the
triple-quote fixer and the fenced/think-block tolerance.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from agentsec.prompts import parse_mitigation_response  # noqa: E402


def test_missing_fixed_code_does_not_raise():
    raw = '{"explanation": "concat into SQL", "hardening": ["use params"], "references": []}'
    parsed = parse_mitigation_response(raw)  # must not raise
    assert parsed["explanation"] == "concat into SQL"
    assert parsed["fixed_code"] == ""          # defaulted, not crashed
    assert parsed["hardening"] == ["use params"]


def test_normal_fixed_code_is_extracted():
    raw = (
        '{"explanation": "x", "fixed_code": "def f():\\n    return 1", '
        '"hardening": [], "references": ["CVE-2021-1234"]}'
    )
    parsed = parse_mitigation_response(raw)
    assert "def f():" in parsed["fixed_code"]
    assert parsed["references"] == ["CVE-2021-1234"]


def test_triple_quoted_fixed_code_is_repaired():
    raw = '{"explanation": "x", "fixed_code": """def g():\n    pass""", "hardening": []}'
    parsed = parse_mitigation_response(raw)
    assert "def g():" in parsed["fixed_code"]


def test_fenced_and_think_block_tolerated():
    raw = (
        "<think>let me think</think>\n```json\n"
        '{"explanation": "y", "hardening": []}\n```'
    )
    parsed = parse_mitigation_response(raw)
    assert parsed["explanation"] == "y"


def test_unparseable_returns_empty():
    assert parse_mitigation_response("not json at all") == {}
