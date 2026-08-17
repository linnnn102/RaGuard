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

    # Exception classes worth retrying (matched by name so the openai SDK need
    # not be imported here). Rate limits, timeouts, transient server/network.
    _RETRYABLE_NAMES = {"RateLimitError", "APITimeoutError", "APIConnectionError",
                        "InternalServerError", "APIError"}

    def __init__(
        self,
        model: str,
        base_url: str = "",
        api_key: str = "",
        temperature: float = 0.2,
        timeout: int = 120,
        max_tokens: Optional[int] = None,
        min_request_interval_s: float = 0.0,
        max_retries: int = 2,
    ):
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout
        # Cap the completion length. Cloud teachers (e.g. Kimi) can otherwise
        # truncate a long findings array against a low server default, which
        # curation then drops as invalid JSON. None → let the server decide.
        self.max_tokens = max_tokens
        # Client-side rate limiting: keep ≥ this many seconds between call starts
        # (e.g. 21s for a 3-requests/min tier) so we never burst past the RPM cap.
        self.min_request_interval_s = float(min_request_interval_s or 0.0)
        # Retries for transient failures (rate limits, timeouts). Daily-token /
        # balance caps are NOT retried — see _retryable.
        self.max_retries = int(max_retries)
        self._next_allowed = 0.0
        self._sdk = None

    def _throttle(self) -> None:
        """Sleep so call starts are ≥ min_request_interval_s apart. No-op at 0."""
        if self.min_request_interval_s <= 0:
            return
        wait = self._next_allowed - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._next_allowed = time.monotonic() + self.min_request_interval_s

    def _retryable(self, e: Exception) -> bool:
        msg = str(e).lower()
        # Daily-token (TPD) or balance caps won't clear by retrying now — fail
        # fast rather than burn the retry budget waiting.
        if any(k in msg for k in ("insufficient balance", "exceeded_current_quota",
                                  "tpd rate limit", "per day")):
            return False
        if type(e).__name__ in self._RETRYABLE_NAMES:
            return True
        return "429" in msg or "rate limit" in msg or "timeout" in msg

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
        last_err = "unknown error"
        for attempt in range(self.max_retries + 1):
            self._throttle()  # pace call starts (also spaces retries)
            try:
                params = {"model": self.model, "messages": messages}
                # Some models (reasoning/code variants) reject an explicit
                # temperature; set it to None in config to omit the field.
                temp = kwargs.get("temperature", self.temperature)
                if temp is not None:
                    params["temperature"] = temp
                if self.max_tokens:
                    params["max_tokens"] = self.max_tokens
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
                last_err = f"{type(e).__name__}: {e}"
                if attempt < self.max_retries and self._retryable(e):
                    # Exponential backoff so retries are safe even when the
                    # steady-state throttle is 0 (won't hammer a transient 429).
                    time.sleep(min(2 ** attempt, 30))
                    continue
                break
        return ChatResult(
            text="",
            latency_s=round(time.time() - t0, 4),
            success=False,
            error=last_err,
        )
