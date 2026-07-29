"""call_log.py — S1: non-invasive call logging at the model boundary.

``LoggingModelClient`` wraps any ``ModelClient`` and appends one JSONL record
per call. Because the registry hands out *only* wrapped clients, the
orchestrator and all three specialists are captured identically with zero
logging code in any task. Each record is a candidate training row for S2/S5 and
the raw material for the eval latency/token numbers.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .base import ChatResult, ModelClient


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CallLogSink:
    """Append-only JSONL sink, one file per task. Thread-safe."""

    def __init__(self, log_dir: Path):
        self.log_dir = Path(log_dir)
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        task = record.get("task", "unknown")
        path = self.log_dir / f"{task}.jsonl"
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


class LoggingModelClient(ModelClient):
    """Transparent decorator: forwards to the wrapped client, records the call."""

    def __init__(
        self,
        inner: ModelClient,
        task: str,
        sink: Optional[CallLogSink] = None,
        enabled: bool = True,
    ):
        self.inner = inner
        self.task = task
        self.sink = sink
        self.enabled = enabled and sink is not None
        # mirror identity so callers/logging see the real backend + model
        self.backend = getattr(inner, "backend", "base")
        self.model = getattr(inner, "model", "")

    def _log(self, system: str, user: str, result: ChatResult) -> None:
        if not self.enabled:
            return
        record = {
            "ts": _utcnow_iso(),
            "task": self.task,
            "backend": self.backend,
            "model": self.model,
            "system_prompt": system,
            "user_prompt": user,
            "output": result.text,
            "latency_s": result.latency_s,
            "success": result.success,
            "usage": result.usage,
            "tool_calls": result.tool_calls,
            "error": result.error,
        }
        try:
            self.sink.write(record)
        except OSError:
            pass  # logging must never break the pipeline

    def chat(self, system: str, user: str, **kwargs) -> ChatResult:
        result = self.inner.chat(system, user, **kwargs)
        self._log(system, user, result)
        return result

    def chat_messages(self, messages, tools=None, **kwargs) -> ChatResult:
        result = self.inner.chat_messages(messages, tools=tools, **kwargs)
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        user = next(
            (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        self._log(system, user, result)
        return result
