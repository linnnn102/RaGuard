"""base.py — the model-client boundary.

Every model call in the system (orchestrator and all three specialists) goes
through a ``ModelClient``. That single seam is where S1 logging attaches, so no
task code ever contains a logging statement.

``ChatResult`` is the uniform return type. It carries enough to reconstruct a
training row (S2/S5) and to compute the eval numbers (latency, tokens): the
text, wall-clock latency, success flag, token usage, and — for the orchestrator
— any tool calls the model requested.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ChatResult:
    text: str = ""
    latency_s: float = 0.0
    success: bool = True
    usage: dict = field(default_factory=dict)      # {prompt_tokens, completion_tokens, ...}
    tool_calls: list = field(default_factory=list)  # OpenAI-style tool_call dicts
    error: Optional[str] = None
    raw: Any = None                                 # backend-native response, best effort


class ModelClient(ABC):
    """Abstract chat client. Backends implement ``chat`` (single system+user
    turn) and optionally ``chat_messages`` (full message list + tools, for the
    agentic orchestrator loop)."""

    #: backend family name, e.g. "ollama" / "openai"
    backend: str = "base"
    #: model tag / id
    model: str = ""

    @abstractmethod
    def chat(self, system: str, user: str, **kwargs) -> ChatResult:
        ...

    def chat_messages(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        **kwargs,
    ) -> ChatResult:
        """Multi-turn / tool-calling chat. Backends that don't support tool
        calling fall back to a plain system+user turn."""
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        user = next(
            (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
        )
        return self.chat(system, user, **kwargs)


def timed(fn):
    """Small helper for backends: run ``fn`` and stamp latency onto its
    ChatResult, converting exceptions into a failed ChatResult."""
    def wrapper(*args, **kwargs) -> ChatResult:
        t0 = time.time()
        try:
            result = fn(*args, **kwargs)
            result.latency_s = round(time.time() - t0, 4)
            return result
        except Exception as e:  # noqa: BLE001 — surface any backend failure uniformly
            return ChatResult(
                text="",
                latency_s=round(time.time() - t0, 4),
                success=False,
                error=f"{type(e).__name__}: {e}",
            )
    return wrapper
