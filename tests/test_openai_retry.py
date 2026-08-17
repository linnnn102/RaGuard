"""OpenAIBackend rate-limit handling: throttle spacing, retry on transient 429,
and fail-fast on daily-cap / balance errors (which retrying can't fix)."""

from __future__ import annotations

import sys
import types
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import agentsec.models.openai_backend as mod  # noqa: E402
from agentsec.models.openai_backend import OpenAIBackend  # noqa: E402


def _resp(content="[]"):
    msg = types.SimpleNamespace(content=content, tool_calls=None)
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)], usage=None)


def _backend_with(create, **kw):
    b = OpenAIBackend(model="m", **kw)
    b._sdk = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create)))
    return b


def test_retries_transient_rate_limit_then_succeeds(monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def create(**kw):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RuntimeError("Error code: 429 - rate limit reached, max RPM: 3")
        return _resp("[]")

    r = _backend_with(create, max_retries=3).chat("s", "u")
    assert r.success and r.text == "[]"
    assert calls["n"] == 3          # failed twice, succeeded on the third


def test_daily_cap_is_not_retried(monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def create(**kw):
        calls["n"] += 1
        raise RuntimeError("Error code: 429 - request reached organization TPD rate limit")

    r = _backend_with(create, max_retries=5).chat("s", "u")
    assert not r.success
    assert calls["n"] == 1          # TPD → fail fast, no wasted retries


def test_throttle_spaces_call_starts(monkeypatch):
    slept = []
    monkeypatch.setattr(mod.time, "sleep", lambda s: slept.append(round(s, 3)))
    monkeypatch.setattr(mod.time, "monotonic", lambda: 100.0)
    b = OpenAIBackend(model="m", min_request_interval_s=20)
    b._throttle()   # first call: nothing due yet → no sleep
    b._throttle()   # second: must wait the full interval
    assert slept == [20.0]


def test_no_throttle_by_default(monkeypatch):
    slept = []
    monkeypatch.setattr(mod.time, "sleep", lambda s: slept.append(s))
    b = OpenAIBackend(model="m")   # min_request_interval_s defaults to 0
    b._throttle()
    b._throttle()
    assert slept == []
