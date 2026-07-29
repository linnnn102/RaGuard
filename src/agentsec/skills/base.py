"""base.py — skill registry + OpenAI tool-spec adapter.

A ``Skill`` bundles the name, description, JSON-Schema parameters, and handler
for one specialist tool. ``to_openai_tools()`` renders the registry into the
``tools=`` array the orchestrator consumes; ``dispatch()`` routes a tool call the model
emitted to the right handler with a shared ``SkillContext``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class SkillContext:
    """Shared state handed to every skill handler."""
    config: object                      # agentsec.config.Config
    registry: object                    # agentsec.models.registry.ModelRegistry
    _kb: object = None                  # lazily built KnowledgeBase

    def kb(self):
        if self._kb is None:
            from ..rag.knowledge_base import load_kb
            self._kb = load_kb(self.config)
        return self._kb


@dataclass
class Skill:
    name: str
    description: str
    parameters: dict                    # JSON Schema for the arguments object
    handler: Callable                   # (ctx: SkillContext, **kwargs) -> dict


SKILLS: dict[str, Skill] = {}


def register(skill: Skill) -> Skill:
    SKILLS[skill.name] = skill
    return skill


def to_openai_tools() -> list[dict]:
    """Render all registered skills as OpenAI-style function tool specs."""
    return [
        {
            "type": "function",
            "function": {
                "name": s.name,
                "description": s.description,
                "parameters": s.parameters,
            },
        }
        for s in SKILLS.values()
    ]


def dispatch(name: str, arguments: dict, ctx: SkillContext) -> dict:
    """Invoke a skill by name. Never raises — failures come back as
    ``{"status": "error", ...}`` so the agent loop can keep going."""
    skill = SKILLS.get(name)
    if skill is None:
        return {"status": "error", "message": f"Unknown skill '{name}'"}
    try:
        return skill.handler(ctx, **(arguments or {}))
    except TypeError as e:
        return {"status": "error", "message": f"Bad arguments for {name}: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "message": f"{type(e).__name__}: {e}"}
