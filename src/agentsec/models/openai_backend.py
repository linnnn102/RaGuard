"""openai_backend.py — the generalist orchestrator (OpenAI-compatible).

The orchestrator is any OpenAI-compatible chat model. By default that is a
local Qwen3 served through Ollama's ``/v1`` endpoint; optionally it can be the
GLM5 cloud model (see ``config/agentsec.glm.yaml``). Either way we drive it with
the ``openai`` SDK. ``chat`` is the plain single-turn path; ``chat_messages`` is
the one the agent loop uses — it passes the full running message list plus the
tool specs and returns any ``tool_calls`` the model requested.

The ``openai`` package is imported lazily inside ``_client`` so that importing
this module (and the whole ``agentsec`` package) never requires the SDK to be
installed — only actually talking to the orchestrator does.
"""

from __future__ import annotations

import time
from typing import Optional

from .base import ChatResult, ModelClient


class OpenAIBackend(ModelClient):
    backend = "openai"

    def __init__(
        self,
        model: str,
        base_url: str = "",
        api_key: str = "",
        temperature: float = 0.2,
        timeout: int = 120,
    ):
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout
        self._sdk = None

    def _client(self):
        if self._sdk is None:
            from openai import OpenAI  # lazy: keeps the package import-light

            kwargs = {"timeout": self.timeout}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            if self.api_key:
                kwargs["api_key"] = self.api_key
            self._sdk = OpenAI(**kwargs)
        return self._sdk

    def chat(self, system: str, user: str, **kwargs) -> ChatResult:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        return self.chat_messages(messages, **kwargs)

    def chat_messages(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        **kwargs,
    ) -> ChatResult:
        t0 = time.time()
        try:
            params = {
                "model": self.model,
                "messages": messages,
                "temperature": kwargs.get("temperature", self.temperature),
            }
            if tools:
                params["tools"] = tools
                params["tool_choice"] = kwargs.get("tool_choice", "auto")
            resp = self._client().chat.completions.create(**params)
            choice = resp.choices[0]
            msg = choice.message
            tool_calls = []
            for tc in (msg.tool_calls or []):
                tool_calls.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                })
            usage = {}
            if resp.usage is not None:
                usage = {
                    "prompt_tokens": resp.usage.prompt_tokens,
                    "completion_tokens": resp.usage.completion_tokens,
                    "total_tokens": resp.usage.total_tokens,
                }
            return ChatResult(
                text=msg.content or "",
                latency_s=round(time.time() - t0, 4),
                success=True,
                usage=usage,
                tool_calls=tool_calls,
                raw=resp,
            )
        except Exception as e:  # noqa: BLE001 — uniform failure surface
            return ChatResult(
                text="",
                latency_s=round(time.time() - t0, 4),
                success=False,
                error=f"{type(e).__name__}: {e}",
            )
