"""registry.py — task → logged model client, and the orchestrator client.

The registry is the only place backends are constructed. It reads the S4 config,
builds the right backend for each task route, wraps every client in
``LoggingModelClient`` (S1), and caches them. Task code asks for
``registry.for_task("analyze_code")`` and gets a client that is already routed
*and* logged — swapping a specialist for a fine-tuned adapter tag is a one-line
config edit with no code change.
"""

from __future__ import annotations

from typing import Optional

from ..config import Config, TaskRoute, load_config
from .base import ModelClient
from .call_log import CallLogSink, LoggingModelClient
from .ollama_backend import OllamaBackend
from .openai_backend import OpenAIBackend


class ModelRegistry:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or load_config()
        self._sink: Optional[CallLogSink] = None
        if self.config.logging.enabled:
            self._sink = CallLogSink(self.config.logging.dir)
        self._cache: dict[str, LoggingModelClient] = {}

    # ── backend construction ────────────────────────────────────────────────
    def _build_backend(
        self,
        backend: str,
        model: str,
        options: Optional[dict] = None,
        response_format=None,
    ) -> ModelClient:
        if backend == "ollama":
            opts = self.config.backend_opts("ollama")  # shared (base_url, …)
            if options:
                opts.update(options)                   # per-task decoding overrides
            if response_format is not None:
                opts["response_format"] = response_format
            return OllamaBackend(model=model, **opts)
        if backend == "openai":
            # A task may target its OWN OpenAI-compatible endpoint via `options`
            # (base_url / api_key / max_tokens / temperature) — e.g. routing the
            # analyze_code teacher to Kimi while the orchestrator stays elsewhere.
            # Anything unset falls back to the orchestrator's endpoint.
            o = self.config.orchestrator
            opts = options or {}
            return OpenAIBackend(
                model=model,
                base_url=opts.get("base_url") or o.base_url,
                api_key=opts.get("api_key") or o.api_key,
                temperature=opts.get("temperature", o.temperature),
                max_tokens=opts.get("max_tokens"),
                min_request_interval_s=opts.get("min_request_interval_s", 0.0),
                max_retries=opts.get("max_retries", 2),
            )
        raise ValueError(f"Unknown backend '{backend}'")

    def _wrap(self, inner: ModelClient, task: str) -> LoggingModelClient:
        return LoggingModelClient(
            inner=inner,
            task=task,
            sink=self._sink,
            enabled=self.config.logging.enabled,
        )

    # ── public accessors ────────────────────────────────────────────────────
    def for_task(self, task: str) -> LoggingModelClient:
        if task not in self._cache:
            route: TaskRoute = self.config.task(task)
            inner = self._build_backend(
                route.backend, route.model, route.options, route.format
            )
            self._cache[task] = self._wrap(inner, task)
        return self._cache[task]

    def orchestrator(self) -> LoggingModelClient:
        if "orchestrator" not in self._cache:
            o = self.config.orchestrator
            inner = self._build_backend(o.backend, o.model)
            self._cache["orchestrator"] = self._wrap(inner, "orchestrator")
        return self._cache["orchestrator"]
