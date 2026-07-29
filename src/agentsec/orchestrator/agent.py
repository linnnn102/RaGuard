"""agent.py — the generalist orchestrator loop (replaces client.py + server.py).

The orchestrator (a local Qwen3 by default, or GLM5 — see the router config) is
handed the OpenAI-style tool specs from ``skills.to_openai_tools()`` and runs a
bounded loop: it decides which specialist SLM to call, we dispatch the skill,
append the JSON result as a ``tool`` message, and repeat until the orchestrator
returns a final answer or ``max_steps`` is reached. This is the paper's
Figure-1-Right "code agency": one generalist deciding, cheap specialists doing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..config import Config, load_config
from ..models.registry import ModelRegistry
from ..skills import SkillContext, dispatch, to_openai_tools

MISSION_TEMPLATE = """\
You are the orchestrator of a security-analysis pipeline. You have three
specialist tools. Complete this mission on the target and then summarise:

Target file : {target_file}
Target URL  : {target_url}
Goal        : {goal}

Recommended plan:
  1. Call analyze_code on the target file to find vulnerabilities.
  2. If findings exist, call run_fuzz to generate/execute fuzzing and collect hits.
  3. Call suggest_mitigations, passing the fuzz report path so fuzz-confirmed
     findings are prioritised.
Then give a concise final report of findings, fuzz confirmation, and fixes.
When you are done, reply with plain text (no tool call).
"""


def run_agent(
    target_file: str,
    target_url: Optional[str] = None,
    goal: str = "Find, confirm, and propose fixes for vulnerabilities.",
    config: Optional[Config] = None,
    registry: Optional[ModelRegistry] = None,
    max_steps: Optional[int] = None,
    execute_fuzz: bool = False,
) -> dict:
    config = config or load_config()
    registry = registry or ModelRegistry(config)
    ctx = SkillContext(config=config, registry=registry)
    orchestrator = registry.orchestrator()
    tools = to_openai_tools()
    max_steps = max_steps or config.orchestrator.max_steps
    target_url = target_url or (config.fuzz or {}).get("target_url", "")

    messages = [
        {"role": "system", "content": "You are a precise security orchestrator that calls tools."},
        {"role": "user", "content": MISSION_TEMPLATE.format(
            target_file=target_file, target_url=target_url, goal=goal)},
    ]

    transcript = []
    final_text = ""
    for step in range(max_steps):
        result = orchestrator.chat_messages(messages, tools=tools)
        if not result.success:
            return {"status": "error", "message": result.error, "transcript": transcript}

        if not result.tool_calls:
            final_text = result.text
            messages.append({"role": "assistant", "content": final_text})
            break

        # Record the assistant turn that requested the tool calls.
        messages.append({
            "role": "assistant",
            "content": result.text or None,
            "tool_calls": result.tool_calls,
        })

        for call in result.tool_calls:
            name = call["function"]["name"]
            try:
                args = json.loads(call["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            # Fuzz execution is user-gated: the orchestrator may *request* it,
            # but Docker only runs if the caller permitted it (execute_fuzz).
            # This prevents the model from running a live fuzz without consent.
            if name == "run_fuzz":
                args["execute"] = bool(args.get("execute", execute_fuzz)) and execute_fuzz
            tool_result = dispatch(name, args, ctx)
            transcript.append({"step": step, "tool": name, "args": args, "result": tool_result})
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "name": name,
                "content": json.dumps(tool_result, default=str),
            })

    return {
        "status": "ok",
        "target": target_file,
        "final_report": final_text,
        "transcript": transcript,
        "steps": len(transcript),
    }


def run_sequential(
    target_file: str,
    target_url: Optional[str] = None,
    config: Optional[Config] = None,
    registry: Optional[ModelRegistry] = None,
    execute_fuzz: bool = False,
    min_severity: str = "MEDIUM",
    verbose: bool = False,
) -> dict:
    """Deterministic pipeline: run the three specialists in the fixed order
    analyze → fuzz → mitigate, with NO orchestrator deciding.

    This is both the default ``scan`` engine (predictable, always closes with a
    report) and eval arm 1's homogeneous baseline. Same return shape as
    ``run_agent`` (a ``transcript`` of tool results) so the eval harness scores
    both paths identically. ``verbose`` prints step-by-step progress for CLI use.
    """
    config = config or load_config()
    registry = registry or ModelRegistry(config)
    ctx = SkillContext(config=config, registry=registry)
    target_url = target_url or (config.fuzz or {}).get("target_url", "")

    def _step(msg: str) -> None:
        if verbose:
            print(msg)

    transcript = []

    _step("[1/3] analyze_code   — RAG static analysis…")
    analysis = dispatch("analyze_code", {"file_path": target_file}, ctx)
    transcript.append({"step": 0, "tool": "analyze_code", "args": {"file_path": target_file},
                       "result": analysis})

    # Surface analyzer failures (missing file, syntax error, model down) instead
    # of silently reporting "no vulnerabilities" and running the rest of the
    # pipeline against a stale on-disk report.
    if analysis.get("status") == "error":
        msg = analysis.get("message", "analyze_code failed")
        _step(f"      ✗ analysis failed: {msg}")
        return {
            "status": "error",
            "target": target_file,
            "final_report": f"Analysis failed — pipeline aborted: {msg}",
            "transcript": transcript,
            "steps": len(transcript),
        }

    n_find = len(analysis.get("findings") or [])
    _step(f"      → {n_find} finding(s): {analysis.get('summary') or {}}")

    fuzz_report_path = None
    if analysis.get("findings"):
        fuzz_args = {"target_url": target_url, "execute": execute_fuzz}
        _step(f"[2/3] run_fuzz        — {'executing in Docker' if execute_fuzz else 'generating fuzz.sh (not executing)'}…")
        fuzz = dispatch("run_fuzz", fuzz_args, ctx)
        transcript.append({"step": 1, "tool": "run_fuzz", "args": fuzz_args, "result": fuzz})
        fuzz_report_path = fuzz.get("fuzz_report_path")
        if fuzz.get("executed"):
            _step(f"      → executed, {fuzz.get('total_hits', 0)} hit(s)")
        else:
            _step(f"      → {fuzz.get('message', 'fuzz.sh generated')}")
    else:
        _step("[2/3] run_fuzz        — skipped (no findings to fuzz)")

    mit_args = {"min_severity": min_severity, "fuzz_report_path": fuzz_report_path}
    _step("[3/3] suggest_mitigations — proposing fixes…")
    mitigations = dispatch("suggest_mitigations", mit_args, ctx)
    transcript.append({"step": 2, "tool": "suggest_mitigations", "args": mit_args,
                       "result": mitigations})
    _step(f"      → {len(mitigations.get('mitigations') or [])} mitigation(s)")

    return {
        "status": "ok",
        "target": target_file,
        "final_report": _summarize_sequential(analysis, fuzz_report_path, mitigations, transcript),
        "transcript": transcript,
        "steps": len(transcript),
    }


def _summarize_sequential(analysis: dict, fuzz_report_path, mitigations: dict, transcript: list) -> str:
    """Build a concise human-readable report from the deterministic run."""
    findings = analysis.get("findings") or []
    lines = ["Deterministic pipeline (analyze → fuzz → mitigate)", ""]
    if not findings:
        lines.append("No vulnerabilities found.")
        return "\n".join(lines)

    lines.append(f"Findings: {len(findings)} — {analysis.get('summary') or {}}")
    for f in findings:
        lines.append(
            f"  • [{f.get('cwe_id','?')}] {f.get('cwe_name','')} "
            f"({f.get('severity','?')}) in {f.get('function', f.get('file',''))}"
        )

    fuzz_step = next((t for t in transcript if t["tool"] == "run_fuzz"), None)
    if fuzz_step:
        fr = fuzz_step["result"]
        if fr.get("executed"):
            lines.append(f"\nFuzzing: executed — {fr.get('total_hits', 0)} hit(s) "
                         f"(report: {fuzz_report_path}).")
        else:
            lines.append(f"\nFuzzing: {fr.get('message', 'not executed')} "
                         f"(script: {fr.get('script_path','')}).")
    else:
        lines.append("\nFuzzing: skipped (no findings).")

    mits = mitigations.get("mitigations") or []
    lines.append(f"\nMitigations: {len(mits)} proposed.")
    return "\n".join(lines)
