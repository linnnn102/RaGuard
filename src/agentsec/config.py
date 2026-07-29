"""config.py — S4 router: parse config/agentsec.yaml into typed objects.

Single source of truth for orchestrator + specialist routing. Collapses the
three scattered ``DEFAULT_MODEL = "qwen3"`` constants and the ``server.py`` env
block into one versioned file. ``${VAR}`` / ``${VAR:-default}`` placeholders are
expanded from the environment at load time so secrets never live in the repo.

Select an active config with ``AGENTSEC_CONFIG=<path>`` for one-variable
rollback between iterations (S6).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "agentsec.yaml"

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(value):
    """Recursively expand ${VAR} / ${VAR:-default} in strings within a tree."""
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            var, default = m.group(1), m.group(2)
            return os.environ.get(var, default if default is not None else "")
        return _ENV_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass
class TaskRoute:
    """Where a single specialist task is served from."""
    name: str
    backend: str
    model: str


@dataclass
class OrchestratorConfig:
    backend: str = "openai"
    model: str = "qwen3:8b"
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.2
    max_steps: int = 12


@dataclass
class LoggingConfig:
    enabled: bool = True
    dir: Path = PROJECT_ROOT / "logs" / "calls"


@dataclass
class Config:
    version: str
    orchestrator: OrchestratorConfig
    logging: LoggingConfig
    backends: dict
    tasks: dict  # name -> TaskRoute
    rag: dict
    fuzz: dict
    source_path: Optional[Path] = None

    def task(self, name: str) -> TaskRoute:
        try:
            return self.tasks[name]
        except KeyError:
            raise KeyError(
                f"No route for task '{name}' in {self.source_path}. "
                f"Known tasks: {sorted(self.tasks)}"
            )

    def backend_opts(self, backend: str) -> dict:
        return dict(self.backends.get(backend, {}))


def _resolve_path(value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (PROJECT_ROOT / p)


def load_config(path: Optional[Path] = None) -> Config:
    """Load and env-expand the router config.

    Resolution order: explicit ``path`` arg → ``AGENTSEC_CONFIG`` env →
    ``config/agentsec.yaml``.
    """
    if path is None:
        env_path = os.environ.get("AGENTSEC_CONFIG")
        path = Path(env_path) if env_path else DEFAULT_CONFIG_PATH
    path = Path(path)
    raw = yaml.safe_load(path.read_text())
    raw = _expand_env(raw)

    orch_raw = raw.get("orchestrator", {})
    orchestrator = OrchestratorConfig(
        backend=orch_raw.get("backend", "openai"),
        model=orch_raw.get("model", "qwen3:8b"),
        base_url=orch_raw.get("base_url", ""),
        api_key=orch_raw.get("api_key", ""),
        temperature=float(orch_raw.get("temperature", 0.2)),
        max_steps=int(orch_raw.get("max_steps", 12)),
    )

    log_raw = raw.get("logging", {})
    logging_cfg = LoggingConfig(
        enabled=bool(log_raw.get("enabled", True)),
        dir=_resolve_path(log_raw.get("dir", "logs/calls")),
    )

    tasks = {
        name: TaskRoute(name=name, backend=t["backend"], model=t["model"])
        for name, t in raw.get("tasks", {}).items()
    }

    return Config(
        version=str(raw.get("version", "v1")),
        orchestrator=orchestrator,
        logging=logging_cfg,
        backends=raw.get("backends", {}),
        tasks=tasks,
        rag=raw.get("rag", {}),
        fuzz=raw.get("fuzz", {}),
        source_path=path,
    )
