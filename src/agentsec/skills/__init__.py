"""agentsec.skills — the specialist tools the orchestrator can call.

Importing this package registers all four skills into ``SKILLS``. Skill handlers
import RAG / heavy deps lazily inside the call, so importing the registry (which
the orchestrator does) stays cheap.
"""

from . import analyze_code, fuzz, select_wordlists, suggest_mitigations  # noqa: F401
from .base import SKILLS, SkillContext, dispatch, to_openai_tools  # noqa: F401
