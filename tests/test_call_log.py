"""Unit tests for the S1 logging layer (agentsec.models.call_log).

Verifies a record is written, latency is carried through, and a failed call is
logged with success=false. Uses a fake in-memory ModelClient — no network, no
heavy deps.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from agentsec.models.base import ChatResult, ModelClient  # noqa: E402
from agentsec.models.call_log import CallLogSink, LoggingModelClient  # noqa: E402


class _FakeClient(ModelClient):
    backend = "fake"
    model = "fake-model"

    def __init__(self, result: ChatResult):
        self._result = result

    def chat(self, system, user, **kwargs) -> ChatResult:
        return self._result


def _read_records(log_dir: Path, task: str) -> list[dict]:
    path = log_dir / f"{task}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_success_call_is_logged(tmp_path):
    sink = CallLogSink(tmp_path)
    inner = _FakeClient(ChatResult(text="hello", latency_s=0.42, success=True,
                                   usage={"prompt_tokens": 5, "completion_tokens": 2}))
    client = LoggingModelClient(inner, task="analyze_code", sink=sink)

    out = client.chat("sys", "user")
    assert out.text == "hello"

    records = _read_records(tmp_path, "analyze_code")
    assert len(records) == 1
    rec = records[0]
    assert rec["task"] == "analyze_code"
    assert rec["backend"] == "fake"
    assert rec["model"] == "fake-model"
    assert rec["output"] == "hello"
    assert rec["latency_s"] == 0.42
    assert rec["success"] is True
    assert rec["usage"]["prompt_tokens"] == 5


def test_failed_call_is_logged_with_success_false(tmp_path):
    sink = CallLogSink(tmp_path)
    inner = _FakeClient(ChatResult(text="", success=False, error="boom"))
    client = LoggingModelClient(inner, task="suggest_mitigations", sink=sink)

    client.chat("sys", "user")
    rec = _read_records(tmp_path, "suggest_mitigations")[0]
    assert rec["success"] is False
    assert rec["error"] == "boom"


def test_logging_can_be_disabled(tmp_path):
    sink = CallLogSink(tmp_path)
    inner = _FakeClient(ChatResult(text="x"))
    client = LoggingModelClient(inner, task="t", sink=sink, enabled=False)
    client.chat("s", "u")
    assert not (tmp_path / "t.jsonl").exists()


def test_chat_messages_extracts_system_and_user(tmp_path):
    sink = CallLogSink(tmp_path)
    inner = _FakeClient(ChatResult(text="ok"))
    client = LoggingModelClient(inner, task="orchestrator", sink=sink)
    client.chat_messages([
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "U1"},
        {"role": "assistant", "content": "A1"},
        {"role": "user", "content": "U2"},
    ])
    rec = _read_records(tmp_path, "orchestrator")[0]
    assert rec["system_prompt"] == "SYS"
    assert rec["user_prompt"] == "U2"  # most recent user turn
