"""Move 1: structured output + per-task decoding options.

Covers the three seams the feature touches: the Ollama backend puts `format`
into the request payload, the registry merges per-task options over the shared
backend options, and a task with neither reproduces the pre-Move-1 request.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from agentsec.config import load_config  # noqa: E402
from agentsec.models.ollama_backend import OllamaBackend  # noqa: E402
from agentsec.models.openai_backend import OpenAIBackend  # noqa: E402
from agentsec.models.registry import ModelRegistry  # noqa: E402


class _FakeResp:
    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {
            "message": {"content": "[]"},
            "prompt_eval_count": 1,
            "eval_count": 1,
        }


def _capture_post(monkeypatch):
    """Patch requests.post in the backend module and return the captured payloads."""
    import agentsec.models.ollama_backend as mod

    captured = []

    def fake_post(url, json=None, timeout=None):  # noqa: A002 — mirror requests' kwarg
        captured.append(json)
        return _FakeResp()

    monkeypatch.setattr(mod.requests, "post", fake_post)
    return captured


def test_format_goes_into_payload(monkeypatch):
    captured = _capture_post(monkeypatch)
    OllamaBackend(model="qwen3:1.7b", response_format="json").chat("sys", "user")
    assert captured[0]["format"] == "json"


def test_schema_format_passes_through(monkeypatch):
    captured = _capture_post(monkeypatch)
    schema = {"type": "array", "items": {"type": "object"}}
    OllamaBackend(model="qwen3:4b", response_format=schema).chat("sys", "user")
    assert captured[0]["format"] == schema


def test_no_format_omits_the_field(monkeypatch):
    """Default path is byte-for-byte the pre-Move-1 request — no `format` key."""
    captured = _capture_post(monkeypatch)
    OllamaBackend(model="qwen3:8b").chat("sys", "user")
    assert "format" not in captured[0]


def _write(tmp_path, text) -> Path:
    p = tmp_path / "agentsec.yaml"
    p.write_text(text)
    return p


def test_registry_merges_options_and_format(tmp_path):
    cfg_path = _write(tmp_path, """
version: v2
logging: {enabled: false}
orchestrator: {backend: openai, model: glm-4.5}
backends: {ollama: {base_url: http://x, num_predict: 1024}}
tasks:
  analyze_code:
    backend: ollama
    model: qwen3:4b
    format: json
    options: {num_predict: 2048}
rag: {}
fuzz: {}
""")
    reg = ModelRegistry(load_config(cfg_path))
    inner = reg.for_task("analyze_code").inner
    assert isinstance(inner, OllamaBackend)
    assert inner.response_format == "json"
    assert inner.num_predict == 2048          # per-task override wins over the shared 1024
    assert inner.base_url == "http://x"       # shared backend option still applied


def test_openai_task_targets_its_own_endpoint(tmp_path):
    """A cloud-teacher task points at its OWN endpoint via options, not the
    orchestrator's — this is what routes analyze_code to Kimi."""
    cfg_path = _write(tmp_path, """
version: teacher
logging: {enabled: false}
orchestrator: {backend: openai, model: qwen3:8b, base_url: http://local/v1, api_key: ollama}
backends: {ollama: {base_url: http://x}}
tasks:
  analyze_code:
    backend: openai
    model: kimi-k2.7-code
    options: {base_url: https://api.moonshot.ai/v1, api_key: KEY123, max_tokens: 4096}
  suggest_mitigations:
    backend: openai
    model: glm-4.5
rag: {}
fuzz: {}
""")
    reg = ModelRegistry(load_config(cfg_path))
    teacher = reg.for_task("analyze_code").inner
    assert isinstance(teacher, OpenAIBackend)
    assert teacher.model == "kimi-k2.7-code"
    assert teacher.base_url == "https://api.moonshot.ai/v1"  # its own, not the orchestrator's
    assert teacher.api_key == "KEY123"
    assert teacher.max_tokens == 4096
    # A task with no options falls back to the orchestrator's endpoint.
    other = reg.for_task("suggest_mitigations").inner
    assert other.base_url == "http://local/v1"
    assert other.max_tokens is None
