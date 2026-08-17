"""Unit tests for agentsec.config — S4 router parsing + env interpolation."""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from agentsec.config import load_config  # noqa: E402


def _write(tmp_path, text) -> Path:
    p = tmp_path / "agentsec.yaml"
    p.write_text(text)
    return p


def test_env_interpolation_with_default(tmp_path, monkeypatch):
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    cfg_path = _write(tmp_path, """
version: v1
orchestrator:
  backend: openai
  model: ${GLM_MODEL:-glm-4.5}
backends:
  ollama:
    base_url: ${OLLAMA_URL:-http://localhost:11434}
tasks:
  analyze_code:
    backend: ollama
    model: ${ANALYZE_MODEL:-qwen3}
rag: {top_k: 6}
fuzz: {}
""")
    cfg = load_config(cfg_path)
    assert cfg.orchestrator.model == "glm-4.5"
    assert cfg.backends["ollama"]["base_url"] == "http://localhost:11434"
    assert cfg.task("analyze_code").model == "qwen3"


def test_env_override_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("ANALYZE_MODEL", "qwen3-analyze-v2")
    cfg_path = _write(tmp_path, """
version: v2
orchestrator: {backend: openai, model: glm-4.5}
backends: {ollama: {base_url: http://x}}
tasks:
  analyze_code: {backend: ollama, model: "${ANALYZE_MODEL:-qwen3}"}
rag: {}
fuzz: {}
""")
    cfg = load_config(cfg_path)
    assert cfg.version == "v2"
    assert cfg.task("analyze_code").model == "qwen3-analyze-v2"


def test_task_options_and_format_parsed(tmp_path):
    cfg_path = _write(tmp_path, """
version: v2
orchestrator: {backend: openai, model: glm-4.5}
backends: {ollama: {base_url: http://x}}
tasks:
  analyze_code:
    backend: ollama
    model: qwen3:4b
    format: json
    options: {num_predict: 2048}
  select_wordlists:
    backend: ollama
    model: qwen3:1.7b
rag: {}
fuzz: {}
""")
    cfg = load_config(cfg_path)
    analyze = cfg.task("analyze_code")
    assert analyze.format == "json"
    assert analyze.options == {"num_predict": 2048}
    # A task that omits both keeps the pre-Move-1 defaults (free text, no overrides).
    wl = cfg.task("select_wordlists")
    assert wl.format is None
    assert wl.options == {}


def test_unknown_task_raises(tmp_path):
    cfg_path = _write(tmp_path, """
version: v1
orchestrator: {backend: openai, model: m}
backends: {}
tasks: {analyze_code: {backend: ollama, model: qwen3}}
rag: {}
fuzz: {}
""")
    cfg = load_config(cfg_path)
    try:
        cfg.task("nope")
        assert False, "expected KeyError"
    except KeyError:
        pass
