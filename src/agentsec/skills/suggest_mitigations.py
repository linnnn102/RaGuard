"""suggest_mitigations.py — T3 specialist: RAG-grounded fixes.

Moved out of the deleted ``server.py`` with two fixes carried over from the plan:
  * the ``parsed_text`` ``UnboundLocalError`` is gone (see
    ``prompts.parse_mitigation_response``);
  * fuzz hits are consumed — a finding whose CWE was dynamically confirmed by
    fuzzing is prioritised and marked ``dynamically_confirmed: true``.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import Skill, SkillContext, register


def _load_fuzz_hits(fuzz_report_path: str | None) -> dict:
    """Map cwe_id -> list of hit dicts from a fuzz_report.json (if any)."""
    if not fuzz_report_path:
        return {}
    p = Path(fuzz_report_path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    by_cwe: dict[str, list] = {}
    for job in data.get("jobs", []):
        cwe = job.get("cwe_id")
        if cwe and job.get("hits"):
            by_cwe.setdefault(cwe, []).extend(job["hits"])
    return by_cwe


def suggest_mitigations(
    ctx: SkillContext,
    report_path: str | None = None,
    fuzz_report_path: str | None = None,
    min_severity: str = "MEDIUM",
    top_k: int | None = None,
) -> dict:
    from ..prompts import (
        MITIGATION_SYSTEM_PROMPT,
        build_mitigation_prompt,
        parse_mitigation_response,
    )
    from ..rag.extractor import extract_functions
    from ..rag.parsing import SEVERITY_RANK
    from ..config import PROJECT_ROOT

    rpath = Path(report_path) if report_path else PROJECT_ROOT / "results/reports/vuln_report.json"
    if not rpath.exists():
        return {"status": "error", "message": f"Report not found at {rpath}. Run analyze_code first."}

    if top_k is None:
        top_k = int((ctx.config.rag or {}).get("top_k", 6))

    report = json.loads(rpath.read_text())
    kb = ctx.kb()
    client = ctx.registry.for_task("suggest_mitigations")
    min_rank = SEVERITY_RANK.get(min_severity, 0)
    hits_by_cwe = _load_fuzz_hits(fuzz_report_path)

    mitigations = []
    for result in report.get("results", []):
        fn_name = result.get("function", "unknown")
        fn_source = result.get("source", "")
        if not fn_source:
            target = Path(report.get("meta", {}).get("target", ""))
            if target.exists():
                try:
                    match = next(
                        (f for f in extract_functions(target) if f["name"] == fn_name), None
                    )
                    if match:
                        fn_source = match["source"]
                except Exception:
                    fn_source = f"# source unavailable for {fn_name}"

        # Prioritise fuzz-confirmed findings first.
        findings = [
            f for f in result.get("findings", [])
            if SEVERITY_RANK.get(f["severity"], 0) >= min_rank
        ]
        findings.sort(
            key=lambda f: (f.get("cwe_id") in hits_by_cwe, SEVERITY_RANK.get(f["severity"], 0)),
            reverse=True,
        )

        for finding in findings:
            cwe = finding.get("cwe_id", "")
            fuzz_hits = hits_by_cwe.get(cwe, [])
            rag_query = (
                f"{cwe} {finding.get('cwe_name','')} mitigation fix secure code. "
                f"{finding.get('evidence','')}"
            )
            chunks = kb.retrieve(rag_query, top_k=top_k)
            context = kb.format_context(chunks)
            prompt = build_mitigation_prompt(finding, fn_source, context, fuzz_hits=fuzz_hits)

            res = client.chat(MITIGATION_SYSTEM_PROMPT, prompt)
            if not res.success:
                mitigations.append({"function": fn_name, "cwe_id": cwe, "error": res.error})
                continue

            parsed = parse_mitigation_response(res.text)
            if not parsed:
                mitigations.append({
                    "function": fn_name, "cwe_id": cwe, "severity": finding["severity"],
                    "raw_response": res.text[:1000],
                    "error": "Could not parse LLM response as JSON",
                })
                continue

            mitigations.append({
                "function": fn_name,
                "cwe_id": cwe,
                "severity": finding["severity"],
                "dynamically_confirmed": bool(fuzz_hits),
                "explanation": parsed.get("explanation", ""),
                "fixed_code": parsed.get("fixed_code", ""),
                "hardening": parsed.get("hardening", []),
                "references": parsed.get("references", []),
            })

    return {
        "status": "ok",
        "mitigations": mitigations,
        "total": len(mitigations),
        "min_severity_filter": min_severity,
        "dynamically_confirmed_count": sum(
            1 for m in mitigations if m.get("dynamically_confirmed")
        ),
    }


register(Skill(
    name="suggest_mitigations",
    description=(
        "For each vulnerability in the analyze report, produce a concrete code "
        "fix and hardening advice. If a fuzz report is passed, fuzz-confirmed "
        "findings are prioritised and marked dynamically confirmed. Run last."
    ),
    parameters={
        "type": "object",
        "properties": {
            "report_path": {"type": "string", "description": "Path to vuln_report.json."},
            "fuzz_report_path": {"type": "string", "description": "Path to fuzz_report.json (optional)."},
            "min_severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            },
            "top_k": {"type": "integer"},
        },
    },
    handler=suggest_mitigations,
))
