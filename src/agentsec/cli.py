"""cli.py — entry point for the security pipeline.

    python -m agentsec.cli scan targets/test_target2.py [options]

Modes:
  • default            — run all three tools deterministically, step by step
                         (analyze_code → run_fuzz → suggest_mitigations).
  • --tool NAME        — run ONLY that one tool (analyze | fuzz | mitigate).
  • --agentic          — let the LLM orchestrator decide the tool order.

Writes the combined report (analysis + fuzzing + mitigations) to --output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the reused legacy modules (vuln_scanner, seclist_selector, …) importable
# whether invoked as `python -m agentsec.cli` or `python src/agentsec/cli.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Accept short or fully-qualified tool names for --tool.
TOOL_ALIASES = {
    "analyze": "analyze_code", "analyze_code": "analyze_code",
    "fuzz": "run_fuzz", "run_fuzz": "run_fuzz",
    "mitigate": "suggest_mitigations", "suggest_mitigations": "suggest_mitigations",
}


def _write_report(result: dict, output: str) -> Path:
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, default=str))
    return out_path


def _run_single_tool(args, config, execute_fuzz: bool) -> int:
    """Run exactly one specialist tool via direct dispatch (MCP-style)."""
    from agentsec.models.registry import ModelRegistry
    from agentsec.skills import SkillContext, dispatch

    tool = TOOL_ALIASES[args.tool]
    ctx = SkillContext(config=config, registry=ModelRegistry(config))

    if tool == "analyze_code":
        tool_args = {"file_path": args.target, "min_severity": args.min_severity}
    elif tool == "run_fuzz":
        tool_args = {
            "target_url": args.target_url or (config.fuzz or {}).get("target_url"),
            "execute": execute_fuzz,
        }
    else:  # suggest_mitigations
        tool_args = {"min_severity": args.min_severity}

    print(f"[tool] running only: {tool}  args={tool_args}")
    result = dispatch(tool, tool_args, ctx)

    out_path = _write_report(result, args.output)
    print(f"\n[{tool}] status = {result.get('status')}  →  {out_path}")
    print(json.dumps(result, indent=2, default=str)[:2000])
    return 0 if result.get("status") == "ok" else 1


def _check_ollama(config) -> bool:
    """Verify Ollama is reachable and has the models this run needs.

    Ollama runs on the HOST (it needs the GPU), so it is the one dependency
    `docker compose up` cannot start for you. When it is down the failure used
    to surface deep inside the RAG embedder as
    ``urlopen error [Errno 101] Network is unreachable`` — which is doubly
    confusing because "network unreachable" (not "connection refused") is an
    artefact of host.docker.internal resolving to IPv6 inside the container.
    """
    import json as _json
    import os
    import urllib.error
    import urllib.request

    base = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    in_container = Path("/.dockerenv").exists()

    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=10) as resp:
            installed = {m["name"] for m in _json.loads(resp.read()).get("models", [])}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print("\n" + "=" * 62)
        print("  Ollama is not reachable — nothing can run without it.")
        print("=" * 62)
        print(f"  tried : {base}")
        print(f"  error : {exc}")
        print()
        print("  Start it in your OWN terminal (it must outlive this command):")
        print("      ollama serve")
        print()
        print("  Or have macOS keep it running across reboots:")
        print("      brew services start ollama")
        if in_container:
            print()
            print("  You are inside the runner container, so Ollama must be")
            print("  running on the HOST. Verify from the host with:")
            print("      curl -s http://localhost:11434/api/tags")
        print("=" * 62 + "\n")
        return False

    # Models are pulled on demand, but a missing one stalls mid-run for minutes
    # with no explanation, so name them now.
    rag = config.rag or {}
    wanted = {
        rag.get("embed_model") or "qwen3-embedding:0.6b",
        config.task("analyze_code").model,
    }
    # Ollama reports "name:tag"; a bare name means the :latest tag.
    have = installed | {n.split(":")[0] for n in installed}
    missing = sorted(m for m in wanted if m and m not in have and m not in installed)
    if missing:
        print("\n[warn] Ollama is up but these models are not pulled yet:")
        for m in missing:
            print(f"           ollama pull {m}")
        print("       The run will stall while Ollama downloads them.\n")

    return True


def cmd_scan(args) -> int:
    from agentsec.config import load_config

    config = load_config(Path(args.config) if args.config else None)
    execute_fuzz = not args.no_execute_fuzz  # default: execute the fuzz step

    # Fail fast on a bad target path (catches typos like `.pys`) before we spend
    # time loading the KB / models. Only modes that read the target file need it;
    # --tool fuzz/mitigate work off the existing vuln_report.json.
    tool = TOOL_ALIASES.get(args.tool) if args.tool else None
    if tool in (None, "analyze_code") and not Path(args.target).exists():
        print(f"[error] target file not found: {args.target!r}")
        print("        Check the path and extension (e.g. '.py', not '.pys').")
        return 2

    # Every stage needs Ollama — the orchestrator, all three specialists and the
    # RAG embedder. Check it ONCE up front: without this the run gets a long way
    # in before dying inside the embedder with a urllib errno, which reads like a
    # bug in the pipeline rather than "the model server isn't running".
    if not _check_ollama(config):
        return 3

    # Mode 1: single tool only.
    if args.tool:
        return _run_single_tool(args, config, execute_fuzz)

    # Mode 2: agentic orchestrator (LLM decides order).
    if args.agentic:
        from agentsec.orchestrator import run_agent

        print("[mode] agentic orchestrator (LLM-driven tool order)")
        result = run_agent(
            target_file=args.target,
            target_url=args.target_url,
            goal=args.goal,
            config=config,
            execute_fuzz=execute_fuzz,
        )
        header = "ORCHESTRATOR REPORT"
    # Mode 3 (default): deterministic step-by-step pipeline.
    else:
        from agentsec.orchestrator import run_sequential

        print("[mode] deterministic pipeline: analyze_code → run_fuzz → suggest_mitigations")
        result = run_sequential(
            target_file=args.target,
            target_url=args.target_url,
            config=config,
            execute_fuzz=execute_fuzz,
            min_severity=args.min_severity,
            verbose=True,
        )
        header = "PIPELINE REPORT"

    out_path = _write_report(result, args.output)
    print("\n" + "=" * 60)
    print(header)
    print("=" * 60)
    print(result.get("final_report", "(no final report)"))
    print(f"\nSteps: {result.get('steps')}  |  full report → {out_path}")
    return 0 if result.get("status") == "ok" else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="agentsec", description="Agentic security pipeline")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a target file (all tools, or one via --tool)")
    scan.add_argument("target", help="Python file to scan")
    scan.add_argument(
        "--tool", choices=sorted(TOOL_ALIASES), default=None,
        help="Run ONLY this tool (analyze | fuzz | mitigate). Omit to run the full pipeline.",
    )
    scan.add_argument(
        "--agentic", action="store_true",
        help="Use the LLM orchestrator to decide tool order (default: deterministic).",
    )
    scan.add_argument("--target-url", default=None, help="ffuf target URL containing FUZZ")
    scan.add_argument("--min-severity", default="MEDIUM",
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                      help="Minimum severity to report (default MEDIUM)")
    scan.add_argument(
        "--no-execute-fuzz", action="store_true",
        help="Generate fuzz.sh but do NOT run it in Docker (default: execute).",
    )
    scan.add_argument("--goal", default="Find, confirm, and propose fixes for vulnerabilities.",
                      help="Mission goal (agentic mode only)")
    scan.add_argument("--config", default=None, help="Path to agentsec.yaml (else AGENTSEC_CONFIG/default)")
    scan.add_argument("--output", default="results/reports/full_report.json")
    scan.set_defaults(func=cmd_scan)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
