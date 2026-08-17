"""ollama_backend.py — SLM specialists served locally via Ollama /api/chat.

Absorbs the chat behaviour that was duplicated across
``vuln_scanner.OllamaClient`` and ``seclist_selector.SecListClient``: the
``think=False`` request for reasoning models (Qwen 3 emits ``<think>…</think>``
which bloats output and breaks JSON parsing) with a transparent retry when the
model / Ollama version rejects the flag.

Unlike the legacy ``OllamaClient`` this never calls ``sys.exit`` — failures come
back as ``ChatResult(success=False)`` so the registry/logging layer can record
them and callers can fall back.
"""

from __future__ import annotations

import time
from typing import Optional

import requests

from .base import ChatResult, ModelClient


class OllamaBackend(ModelClient):
    backend = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        temperature: float = 0.1,
        num_predict: int = 1024,
        repeat_penalty: float = 1.15,
        top_p: Optional[float] = None,
        timeout: int = 120,
        max_retries: int = 2,
        response_format: Optional[object] = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.num_predict = num_predict
        self.repeat_penalty = repeat_penalty
        self.top_p = top_p
        self.timeout = timeout
        self.max_retries = max_retries
        # Structured output (S4/Move-1): passed straight to Ollama's `format`
        # field. Either the string "json" (constrain to *any* valid JSON — broad
        # version support) or a JSON-schema dict (strict field/enum enforcement,
        # needs a recent Ollama). This is what lets a small specialist (qwen3:4b
        # / 1.7b) reliably close the findings JSON instead of rambling past its
        # token budget. ``None`` reproduces the pre-Move-1 behaviour exactly.
        self.response_format = response_format

    def _options(self) -> dict:
        opts = {"temperature": self.temperature, "num_predict": self.num_predict}
        if self.repeat_penalty is not None:
            opts["repeat_penalty"] = self.repeat_penalty
        if self.top_p is not None:
            opts["top_p"] = self.top_p
        return opts

    def chat(self, system: str, user: str, **kwargs) -> ChatResult:
        options = self._options()
        use_think_flag = True
        t0 = time.time()
        last_err: Optional[str] = None

        for attempt in range(self.max_retries + 1):
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": options,
            }
            if self.response_format is not None:
                payload["format"] = self.response_format
            if use_think_flag:
                payload["think"] = False
            try:
                r = requests.post(
                    f"{self.base_url}/api/chat", json=payload, timeout=self.timeout
                )
                if r.status_code == 400 and use_think_flag:
                    use_think_flag = False  # model rejects the flag — drop and retry
                    continue
                r.raise_for_status()
                body = r.json()
                text = body.get("message", {}).get("content", "")
                usage = {
                    "prompt_tokens": body.get("prompt_eval_count"),
                    "completion_tokens": body.get("eval_count"),
                }
                return ChatResult(
                    text=text,
                    latency_s=round(time.time() - t0, 4),
                    success=True,
                    usage={k: v for k, v in usage.items() if v is not None},
                    raw=body,
                )
            except requests.Timeout:
                last_err = "Timeout"
                if attempt < self.max_retries:
                    time.sleep(2)
                    continue
            except requests.RequestException as e:
                last_err = f"{type(e).__name__}: {e}"
                break

        return ChatResult(
            text="",
            latency_s=round(time.time() - t0, 4),
            success=False,
            error=last_err or "unknown ollama error",
        )
