"""select_wordlists.py — T2 specialist: SecLists wordlist selection.

The selection *logic* is reused byte-for-byte from
``seclist_selector.select_wordlists`` (catalog anti-hallucination validation +
static-map fallback). This skill only injects a ``client=`` adapter so the call
is routed through the registry (and therefore logged, S1). The adapter re-raises
on a failed call so the selector's existing fallback path still fires.
"""

from __future__ import annotations

import requests

from .base import Skill, SkillContext, register


class _RegistryChatAdapter:
    """Expose a registry ``LoggingModelClient`` as the ``.chat(system,user)->str``
    interface ``seclist_selector`` expects. Raises ``requests.RequestException``
    on failure so the selector falls back to the static map."""

    def __init__(self, client):
        self.client = client

    def chat(self, system: str, user: str, **kwargs) -> str:
        result = self.client.chat(system, user, **kwargs)
        if not result.success:
            raise requests.RequestException(result.error or "model call failed")
        return result.text


def select_wordlists(
    ctx: SkillContext,
    finding: dict,
    function_source: str = "",
    api_info: dict | None = None,
    max_wordlists: int | None = None,
) -> dict:
    from seclist_selector import load_catalog, select_wordlists as _select

    fuzz_cfg = ctx.config.fuzz or {}
    if max_wordlists is None:
        max_wordlists = int(fuzz_cfg.get("max_wordlists", 2))
    catalog_path = fuzz_cfg.get("catalog")
    catalog = load_catalog(__import__("pathlib").Path(catalog_path)) if catalog_path else load_catalog()

    client = _RegistryChatAdapter(ctx.registry.for_task("select_wordlists"))
    paths, source = _select(
        finding=finding,
        function_source=function_source,
        api_info=api_info or {},
        catalog=catalog,
        max_wordlists=max_wordlists,
        client=client,
    )
    return {"status": "ok", "wordlists": paths, "source": source}


register(Skill(
    name="select_wordlists",
    description=(
        "Pick the SecLists wordlist(s) best suited to fuzz-test a specific "
        "vulnerability finding, validated against the real catalog."
    ),
    parameters={
        "type": "object",
        "properties": {
            "finding": {"type": "object", "description": "A finding dict (cwe_id, evidence, …)."},
            "function_source": {"type": "string"},
            "api_info": {"type": "object"},
            "max_wordlists": {"type": "integer"},
        },
        "required": ["finding"],
    },
    handler=select_wordlists,
))
