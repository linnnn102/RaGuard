"""
mcp_client.py — Custom MCP client for the vulnerability server
==============================================================
Calls the three MCP tools in sequence:
  1. analyze_code        — static RAG analysis
  2. fuzz_target         — generates fuzz.sh script for Docker execution
  3. suggest_mitigations — RAG-grounded code fix suggestions

Usage:
    python src/client.py <target.py> [options]

Options:
    --target-url   URL    ffuf target URL with FUZZ keyword
                          [default: http://host.docker.internal:5055/user/FUZZ]
    --min-severity STR    Minimum severity to report/mitigate [default: LOW]
    --analyze-code        Enable vulnerability analysis
    --suggest-mitigations   Enable mitigation suggestions
    --fuzz-target         Enable fuzz target generation
    --output       PATH   Final combined report path [default: ./results/reports/full_report.json]
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run_mcp_server(
    target_file: str,
    target_url: str,
    min_severity: str,
    analyze_code: bool,
    fuzz_target: bool,
    suggest_mitigations: bool,
    output_path: Path,
):
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).parent / "server.py")],
        env={**os.environ, "HF_TOKEN": os.environ.get("HF_TOKEN", "")},
        )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ── list available tools ───────────────────────────────────────
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            print(f"[MCP] Connected. Available tools: {tool_names}\n")

            full_report = {
                "target":    target_file,
                "analysis":  None,
                "fuzzing":   None,
                "mitigations": None,
            }

            # ══════════════════════════════════════════════════════════════
            # TOOL 1 — analyze_code
            # ══════════════════════════════════════════════════════════════
            if analyze_code:
                print("=" * 60)
                print("Static vulnerability analysis")
                print("=" * 60)

                result1 = await session.call_tool(
                    "analyze_code",
                    arguments={
                        "file_path":    target_file,
                        "min_severity": min_severity,
                        "top_k":        6,
                    },
                )

                analysis = json.loads(result1.content[0].text)
                full_report["analysis"] = analysis

                if analysis.get("status") == "error":
                    print(f"[ERROR] Analysis failed: {analysis.get('message')}")
                    sys.exit(1)

                print(f"Functions scanned : {analysis.get('functions_scanned', '?')}")
                print(f"Duration          : {analysis.get('duration_s', '?')}s")
                print(f"Findings summary  : {analysis.get('summary', {})}")
                print(f"Report written to : {analysis.get('report_path')}")
                print()

                findings = analysis.get("findings", [])
                if not findings:
                    print("No vulnerabilities found. Stopping pipeline.\n")
                    _save(full_report, output_path)
                    return

                for f in findings:
                    sev  = f.get("severity", "?")
                    cwe  = f.get("cwe_id", "?")
                    name = f.get("cwe_name", "")
                    conf = f.get("confidence", 0)
                    print(f"  [{sev}] {cwe} {name} (confidence {conf:.0%})")
                print()

            # ══════════════════════════════════════════════════════════════
            # TOOL 2 — fuzz_target
            # ══════════════════════════════════════════════════════════════
            if fuzz_target:
                print("=" * 60)
                print("Fuzz target generation: ")
                print("This tool will help you generate a fuzz shell script and you can run it in the Docker container for a fuzzing report.")
                print("=" * 60)

                result2 = await session.call_tool(
                    "fuzz_target",
                )

            # ══════════════════════════════════════════════════════════════
            # TOOL 3 — suggest_mitigations
            # ══════════════════════════════════════════════════════════════
            if suggest_mitigations:
                print("=" * 60)
                print("RAG-grounded mitigation suggestions")
                print("This tool will give you a list of mitigation suggestions for the vulnerabilites found in the code.")
                print("If there's a fuzzing report, it will be used by this tool to generate more reliable suggestions. If not, it will use the vulnerability analysis report to generate suggestions.")
                print("=" * 60)

                result3 = await session.call_tool(
                    "suggest_mitigations",
                    arguments={
                        "min_severity": min_severity
                        if min_severity in ("HIGH", "CRITICAL")
                        else "MEDIUM",
                    },
                )

                mitigations = json.loads(result3.content[0].text)
                full_report["mitigations"] = mitigations

                if mitigations.get("status") == "error":
                    print(f"[WARN] Mitigation error: {mitigations.get('message')}")
                else:
                    total = mitigations.get("total", 0)
                    print(f"Generated {total} mitigation(s):\n")

                    for m in mitigations.get("mitigations", []):
                        if m.get("error"):
                            print(f"  [{m['cwe_id']}] ERROR: {m['error']}")
                            continue

                        print(f"  Function : {m['function']}")
                        print(f"  CWE      : {m['cwe_id']} ({m.get('severity','')})")
                        print(f"  Why      : {m.get('explanation','')[:200]}")
                        if m.get("hardening"):
                            print("  Hardening:")
                            for tip in m["hardening"][:3]:
                                print(f"    • {tip}")
                        if m.get("fixed_code"):
                            print("  Fixed code:")
                            for line in m["fixed_code"].splitlines()[:20]:
                                print(f"    {line}")
                        if m.get("references"):
                            print(f"  References: {', '.join(m['references'][:4])}")
                        print()

                # ── save combined report at the end of the pipeline ──
                _save(full_report, output_path)


def _save(report: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(f"[Client] Full report saved → {path}")


def parse_args():
    p = argparse.ArgumentParser(
        description="MCP client — runs analyze → fuzz → mitigate pipeline"
    )
    p.add_argument("target", help="Python file to scan")
    p.add_argument("--target-url", default="http://host.docker.internal:5055/user/FUZZ",
                   help="ffuf target URL with FUZZ keyword (default: http://host.docker.internal:5055/user/FUZZ)")
    p.add_argument("--min-severity", default="LOW",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    p.add_argument("--analyze-code", action="store_true")
    p.add_argument("--fuzz-target", action="store_true")
    p.add_argument("--suggest-mitigations", action="store_true")

    p.add_argument("--output", type=Path, default=Path("./results/reports/full_report.json"))
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(run_mcp_server(
        target_file=args.target,
        target_url=args.target_url,
        min_severity=args.min_severity,
        analyze_code=args.analyze_code,
        fuzz_target=args.fuzz_target,
        suggest_mitigations=args.suggest_mitigations,
        output_path=args.output,
    ))
