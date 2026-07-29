"""prompts.py — prompt text + LLM-output parsing for the specialists.

Kept import-light on purpose (stdlib + ``re`` only): the mitigation parsing
functions are unit-tested without pulling in numpy/RAG. The analyze-task prompt
constants live in the legacy ``vuln_scanner`` module and are re-exported lazily
via ``analyze_system_prompt`` / ``build_analyze_prompt`` so this module imports
cleanly on its own.
"""

from __future__ import annotations

import json
import re
from typing import Optional


# ── T1 analyze prompts (lazy re-export from the reused vuln_scanner) ───────────

def analyze_system_prompt() -> str:
    from vuln_scanner import SYSTEM_PROMPT
    return SYSTEM_PROMPT


def build_analyze_prompt(fn: dict, context: str) -> str:
    from vuln_scanner import build_prompt
    return build_prompt(fn, context)


# ── T3 mitigation prompts ──────────────────────────────────────────────────────

MITIGATION_SYSTEM_PROMPT = """\
You are an expert application security engineer specialising in Python secure code review.
You are given a vulnerability finding and the relevant CWE/CVE reference context.
Your task is to provide:
  1. A clear explanation of why the code is vulnerable
  2. A concrete, minimal code fix — show the corrected function in full
  3. Any additional hardening recommendations beyond the immediate fix
  4. The CWE and any relevant CVE IDs from the context

Respond ONLY with a valid JSON object with these fields:
  - "cwe_id":        string
  - "explanation":   string — why the code is vulnerable
  - "fixed_code":    string — the corrected function as a code string
  - "hardening":     array of strings — additional recommendations
  - "references":    array of strings — CVE IDs from context if relevant

Do not include any text outside the JSON object.\
"""


def build_mitigation_prompt(
    finding: dict,
    fn_source: str,
    context: str,
    fuzz_hits: Optional[list] = None,
) -> str:
    """User message for a mitigation request. When dynamic fuzz hits are
    supplied, they are appended so the orchestrator/specialist prioritises the
    fuzz-confirmed weakness."""
    hits_block = ""
    if fuzz_hits:
        sample = "\n".join(
            f"  - {h.get('input', '')} → HTTP {h.get('status', '?')}"
            for h in fuzz_hits[:8]
        )
        hits_block = (
            "\n\nThis vulnerability was DYNAMICALLY CONFIRMED by fuzzing. "
            "Payloads that produced a hit:\n" + sample + "\n"
        )
    return (
        f"Vulnerability finding:\n"
        f"  CWE: {finding.get('cwe_id','')} — {finding.get('cwe_name','')}\n"
        f"  Severity: {finding.get('severity','')}\n"
        f"  Description: {finding.get('description','')}\n"
        f"  Evidence: {finding.get('evidence','')}\n"
        f"{hits_block}\n"
        f"Vulnerable function source:\n"
        f"```python\n{fn_source}\n```\n\n"
        f"CWE/CVE reference context:\n{context}\n\n"
        f"Respond ONLY with a JSON object containing: "
        f"explanation, fixed_code, hardening (array), references (array)."
    )


def _raw_parser(s: str) -> str:
    """Normalise LLM output and convert any ``\"\"\"...\"\"\"`` block the model
    emitted (invalid JSON) into a properly escaped JSON string."""
    text = s.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    text = text.strip()

    def replacer(m: re.Match) -> str:
        inner = m.group(1)
        inner = inner.replace("\\", "\\\\")
        inner = inner.replace('"', '\\"')
        inner = inner.replace("\n", "\\n")
        inner = inner.replace("\r", "\\r")
        inner = inner.replace("\t", "\\t")
        return f'"{inner}"'

    return re.sub(r'"""(.*?)"""', replacer, text, flags=re.DOTALL)


def parse_mitigation_response(raw: str) -> dict:
    """Parse a mitigation LLM response into a dict.

    Bug fix over the original ``server.py``: ``parsed_text`` and
    ``fixed_code_raw`` are bound *before* the ``fixed_code`` regex, so a response
    that lacks a ``fixed_code`` field falls through to the normal JSON parse
    instead of raising ``UnboundLocalError``. Returns ``{}`` if nothing parses.
    """
    text_for_parse = _raw_parser(raw)

    # Defaults so a missing "fixed_code" never leaves these unbound.
    parsed_text = text_for_parse
    fixed_code_raw = None

    fc_match = re.search(
        r'"fixed_code"\s*:\s*"(.*?)"(?=\s*,\s*"|\s*})',
        text_for_parse,
        re.DOTALL,
    )
    if fc_match:
        fixed_code_raw = (
            fc_match.group(1)
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace('\\"', '"')
        )
        parsed_text = (
            text_for_parse[: fc_match.start(1)]
            + "__FIXED_CODE__"
            + text_for_parse[fc_match.end(1):]
        )

    try:
        parsed = json.loads(parsed_text)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}

    if fixed_code_raw is not None:
        parsed["fixed_code"] = fixed_code_raw
    parsed.setdefault("fixed_code", "")
    parsed.setdefault("explanation", "")
    parsed.setdefault("hardening", [])
    parsed.setdefault("references", [])
    return parsed
