"""analyze_code.py — T1 specialist: static RAG vulnerability detection.

Same logic as the legacy ``vuln_scanner.scan_file`` / MCP ``analyze_code`` tool,
but each per-function LLM call is routed through the ``analyze_code`` registry
client (routed + logged). Writes the golden ``vuln_report.json`` (schema
preserved) so the fuzz skill can consume ``line_start``/``line_end``.
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

from .base import Skill, SkillContext, register


def analyze_code(
    ctx: SkillContext,
    file_path: str,
    min_severity: str = "LOW",
    top_k: int | None = None,
    progress=None,
) -> dict:
    # `progress`, if given, is called (index, total, fn_name) before each
    # per-function model call — lets a batch driver (build_corpus scan) show
    # live progress inside a function-dense file. The LLM tool path never sets
    # it (it isn't in the parameters schema), so it defaults off.
    from ..prompts import analyze_system_prompt, build_analyze_prompt
    from ..rag.extractor import extract_functions
    from ..rag.parsing import SEVERITY_RANK, extract_json_array, validate_finding
    from ..reporting import save_json_report

    target = Path(file_path)
    if not target.exists():
        return {"status": "error", "message": f"File not found: {file_path}"}

    if top_k is None:
        top_k = int((ctx.config.rag or {}).get("top_k", 6))

    try:
        functions = extract_functions(target)
    except SyntaxError as e:
        return {"status": "error", "message": f"Python syntax error: {e}"}
    if not functions:
        return {"status": "ok", "summary": {}, "findings": [],
                "message": "No functions found in file."}

    kb = ctx.kb()
    client = ctx.registry.for_task("analyze_code")
    system = analyze_system_prompt()
    min_rank = SEVERITY_RANK.get(min_severity, 0)

    all_results = []
    t0 = time.time()
    for idx, fn in enumerate(functions, 1):
        if progress:
            progress(idx, len(functions), fn["name"])
        rag_query = (
            f"Python function '{fn['name']}' vulnerability. "
            f"Args: {', '.join(fn['args'])}. {fn['source'][:400]}"
        )
        chunks = kb.retrieve(rag_query, top_k=top_k, min_severity=min_severity)
        context = kb.format_context(chunks)
        prompt = build_analyze_prompt(fn, context)

        result = client.chat(system, prompt)
        if not result.success:
            all_results.append({"function": fn, "findings": [], "error": result.error})
            continue

        raw_findings = extract_json_array(result.text)
        findings = [validate_finding(f) for f in raw_findings if isinstance(f, dict)]
        findings = [f for f in findings if SEVERITY_RANK.get(f["severity"], 0) >= min_rank]
        findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 0), reverse=True)
        all_results.append({"function": fn, "findings": findings})

    elapsed = time.time() - t0

    report_path = Path(
        (ctx.config.fuzz or {}).get("report_path")
        or ctx.config.rag.get("report_path")
        or "results/reports/vuln_report.json"
    )
    if not report_path.is_absolute():
        from ..config import PROJECT_ROOT
        report_path = PROJECT_ROOT / report_path

    save_json_report(
        target_file=target,
        results=all_results,
        output_path=report_path,
        elapsed=elapsed,
        model=client.model,
    )

    all_findings = [f for r in all_results for f in r["findings"]]
    counts = Counter(f["severity"] for f in all_findings)
    # How many per-function model calls actually succeeded. A run where every
    # call failed (e.g. the model isn't pulled → 404) still parses as status=ok
    # with empty findings; callers use calls_ok to tell "clean" from "dead".
    calls_failed = sum(1 for r in all_results if r.get("error"))
    calls_ok = len(all_results) - calls_failed
    return {
        "status": "ok",
        "summary": dict(counts),
        "findings": all_findings,
        "report_path": str(report_path),
        "functions_scanned": len(functions),
        "calls_ok": calls_ok,
        "calls_failed": calls_failed,
        "duration_s": round(elapsed, 2),
    }


register(Skill(
    name="analyze_code",
    description=(
        "Statically analyze a Python file for security vulnerabilities using "
        "RAG-augmented CWE/CVE retrieval. Returns findings and writes a JSON "
        "report. Run this first."
    ),
    parameters={
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the Python file to scan."},
            "min_severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                "description": "Minimum severity to report (default LOW).",
            },
            "top_k": {"type": "integer", "description": "RAG chunks per function."},
        },
        "required": ["file_path"],
    },
    handler=analyze_code,
))
