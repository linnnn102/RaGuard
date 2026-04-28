"""
MCP vulnerability analysis server
=======================================================
Exposes three tools via the MCP protocol (fastmcp):

  1. analyze_code        — RAG + Llama 3 static vulnerability analysis
  2. fuzz_target         — ffuf fuzzing guided by Tool 1 report
  3. suggest_mitigations — RAG + Llama 3 code-level fix suggestions

Usage:
    python src/server.py

Configuration (edit CONFIG block below or set env vars):
    CHUNKS_ZIP      path to rag_chunks.zip from Colab
    OLLAMA_URL      Ollama base URL
    OLLAMA_MODEL    Ollama model tag
    SECLISTS_PATH   root of SecLists installation
    FFUF_BIN        path to ffuf binary
    REPORT_PATH     where Tool 1 writes / Tool 2 reads results/reports/vuln_report.json
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from typing import Optional
import re

from fastmcp import FastMCP

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── Import vuln_scanner.py internals ───────────────────────────────────────────
# Import vuln_scanner.py internals
from vuln_scanner import (
    KnowledgeBase,
    OllamaClient,
    extract_functions,
    build_prompt,
    extract_json_array,
    validate_finding,
    save_json_report,
    SEVERITY_RANK,
    SYSTEM_PROMPT,
)
# ── CONFIG ─────────────────────────────────────────────────────────────────────
CONFIG = {
    "chunks_zip"   : Path(os.getenv("CHUNKS_ZIP",    str(PROJECT_ROOT / "data/kb/rag_chunks.zip"))),
    "ollama_url"   : os.getenv("OLLAMA_URL",          "http://localhost:11434"),
    "ollama_model" : os.getenv("OLLAMA_MODEL",         "llama3"),
    "seclists_path": Path(os.getenv("SECLISTS_PATH",  str(PROJECT_ROOT / "lib/SecLists"))),
    "ffuf_bin"     : os.getenv("FFUF_BIN",             "ffuf"),
    "report_path"  : Path(os.getenv("REPORT_PATH",    str(PROJECT_ROOT / "results/reports/vuln_report.json"))),
    "top_k"        : int(os.getenv("TOP_K",            "6")),
}

# ── CWE → SecLists wordlist mapping ───────────────────────────────────────────
# Maps CWE IDs to the most relevant SecLists wordlist paths (relative to SECLISTS_PATH).
# Extend this dict as you add more CWEs to your knowledge base.
CWE_WORDLIST_MAP = {
    "CWE-89":  [
        "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
        "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    ],
    "CWE-79":  [
        "Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
        "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
        "Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
        "Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
    ],
    "CWE-78":  [
        "Fuzzing/command-injection-commix.txt",
    ],
    "CWE-22":  [
        "Fuzzing/LFI/Linux/LFI-gracefulsecurity-linux.txt",
        "Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
    ],
    # "CWE-287": [
    # "CWE-352": [
    # "CWE-434": [
    # "CWE-918": [
    "CWE-502": [
        "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
    ],
    "CWE-20":  [
        "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
        "Fuzzing/special-chars.txt",
    ],
    # Fallback for unmapped CWEs
    "_default": [
        "Discovery/Web-Content/common.txt",
    ],
}

MITIGATION_SYSTEM_PROMPT = """\
You are am expert application security engineer specialising in Python secure code review.
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

# ── Lazy-loaded singletons ─────────────────────────────────────────────────────
_kb:  Optional[KnowledgeBase] = None
_llm: Optional[OllamaClient]  = None

def get_kb() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase(CONFIG["chunks_zip"])
    return _kb

def get_llm() -> OllamaClient:
    global _llm
    if _llm is None:
        _llm = OllamaClient(
            base_url=CONFIG["ollama_url"],
            model=CONFIG["ollama_model"],
        )
    return _llm

# ── MCP server instance ────────────────────────────────────────────────────────
mcp = FastMCP(
    name="vuln-analysis-server",
    instructions=(
        "Vulnerability analysis server with three tools:\n"
        "1. analyze_code — static RAG analysis of a Python file\n"
        "2. fuzz_target  — ffuf fuzzing guided by the analysis report\n"
        "3. suggest_mitigations — RAG-grounded code fix suggestions\n"
        "Run tools in order: analyze_code → fuzz_target → suggest_mitigations."
    ),
)

# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — analyze_code
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def analyze_code(
    file_path: str,
    min_severity: str = "LOW",
    top_k: int = 6,
) -> dict:
    """
    Statically analyze a Python file for security vulnerabilities using
    RAG-augmented Llama 3. Extracts each function, retrieves relevant
    CWE/CVE context, and asks the LLM to identify vulnerabilities.

    Args:
        file_path:    Absolute or relative path to the Python file to scan.
        min_severity: Minimum severity to include — CRITICAL/HIGH/MEDIUM/LOW/INFO.
        top_k:        Number of RAG chunks to retrieve per function (default 6).

    Returns:
        dict with keys:
          - status:    "ok" or "error"
          - summary:   finding counts by severity
          - findings:  list of all findings across all functions
          - report_path: path where full JSON report was written
    """
    target = Path(file_path)
    if not target.exists():
        return {"status": "error", "message": f"File not found: {file_path}"}

    kb  = get_kb()
    llm = get_llm()

    try:
        functions = extract_functions(target)
    except SyntaxError as e:
        return {"status": "error", "message": f"Python syntax error in target: {e}"}

    if not functions:
        return {"status": "ok", "summary": {}, "findings": [],
                "message": "No functions found in file."}

    all_results = []
    t0 = time.time()

    for fn in functions:
        rag_query = (
            f"Python function '{fn['name']}' vulnerability. "
            f"Args: {', '.join(fn['args'])}. "
            f"{fn['source'][:400]}"
        )
        chunks  = kb.retrieve(rag_query, top_k=top_k, min_severity=min_severity)
        context = kb.format_context(chunks)
        prompt  = build_prompt(fn, context)

        try:
            raw = llm.generate(prompt)
        except Exception as e:
            all_results.append({"function": fn, "findings": [], "error": str(e)})
            continue

        raw_findings = extract_json_array(raw)
        findings = [validate_finding(f) for f in raw_findings if isinstance(f, dict)]
        min_rank = SEVERITY_RANK.get(min_severity, 0)
        findings = [f for f in findings if SEVERITY_RANK.get(f["severity"], 0) >= min_rank]
        findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 0), reverse=True)
        all_results.append({"function": fn, "findings": findings})

    elapsed = time.time() - t0

    # Persist report so Tool 2 can read it
    report = save_json_report(
        target_file=target,
        results=all_results,
        output_path=CONFIG["report_path"],
        elapsed=elapsed,
        model=CONFIG["ollama_model"],
    )

    all_findings = [f for r in all_results for f in r["findings"]]
    from collections import Counter
    counts = Counter(f["severity"] for f in all_findings)

    return {
        "status":      "ok",
        "summary":     dict(counts),
        "findings":    all_findings,
        "report_path": str(CONFIG["report_path"]),
        "functions_scanned": len(functions),
        "duration_s":  round(elapsed, 2),
    }


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — fuzz_target
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def fuzz_target() -> dict:

    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "src/generate_fuzz_script.py")],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        error_msg = f"Scipt failed (exit {result.returncode}): \n{result.stderr}"
        print(error_msg, file=sys.stderr, flush=True)
        return error_msg
    print(result.stdout, file=sys.stderr, flush=True)
    return {
        "status": "ok",
        "message": "Fuzz target generation successful",
    }

# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — suggest_mitigations
# ══════════════════════════════════════════════════════════════════════════════

def _mitigation_prompt(finding: dict, fn_source: str, context: str) -> str:
    """Build a Llama 3 prompt for mitigation suggestions."""
    return (
        f"<|begin_of_text|>"
        f"<|start_header_id|>system<|end_header_id|>\n\n"
        f"{MITIGATION_SYSTEM_PROMPT}<|eot_id|>"
        f"<|start_header_id|>user<|end_header_id|>\n\n"
        f"Vulnerability finding:\n"
        f"  CWE: {finding['cwe_id']} — {finding.get('cwe_name','')}\n"
        f"  Severity: {finding['severity']}\n"
        f"  Description: {finding['description']}\n"
        f"  Evidence: {finding.get('evidence','')}\n\n"
        f"Vulnerable function source:\n"
        f"```python\n{fn_source}\n```\n\n"
        f"CWE/CVE reference context:\n{context}\n\n"
        f"Respond ONLY with a JSON object containing: "
        f"explanation, fixed_code, hardening (array), references (array)."
        f"<|eot_id|>"
        f"<|start_header_id|>assistant<|end_header_id|>\n\n"
    )

# ── Triple-quote fixer ─────────────────────────────────────────────────────────
# The LLM sometimes writes `"fixed_code": """..."""` which is invalid JSON.
# This converts every """...""" block into a properly escaped JSON string.
def _raw_parser(s: str) -> str:
    # Parse JSON — LLM returns a single object not an array here
    text = s.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    text = text.strip()

    def replacer(m):
        inner = m.group(1)
        inner = inner.replace("\\", "\\\\")
        inner = inner.replace('"',  '\\"')
        inner = inner.replace("\n", "\\n")
        inner = inner.replace("\r", "\\r")
        inner = inner.replace("\t", "\\t")
        return f'"{inner}"'
    return re.sub(r'"""(.*?)"""', replacer, s, flags=re.DOTALL)


@mcp.tool()
def suggest_mitigations(
    report_path: Optional[str] = None,
    min_severity: str = "MEDIUM",
    top_k: int = 6,
) -> dict:
    """
    For each vulnerability in the analyze_code report, retrieve RAG context
    and ask Llama 3 to produce a concrete code fix and hardening advice.

    Args:
        report_path:  Path to vuln_report.json. Defaults to Tool 1 output path.
        min_severity: Only suggest mitigations for findings at or above this
                      severity (default MEDIUM — skips INFO/LOW noise).
        top_k:        RAG chunks to retrieve per finding (default 6).

    Returns:
        dict with keys:
          - status:       "ok" or "error"
          - mitigations:  list of {function, cwe_id, explanation,
                          fixed_code, hardening, references}
          - total:        number of mitigations generated
    """
    rpath = Path(report_path) if report_path else CONFIG["report_path"]
    if not rpath.exists():
        return {
            "status": "error",
            "message": (
                f"Report not found at {rpath}. "
                "Run analyze_code first."
            ),
        }

    report = json.loads(rpath.read_text())
    kb  = get_kb()
    llm = get_llm()
    min_rank = SEVERITY_RANK.get(min_severity, 0)

    mitigations = []

    for result in report.get("results", []):
        fn_name   = result.get("function", "unknown")
        fn_source = result.get("source", "")

        if not fn_source:
            target = Path(report.get("meta", {}).get("target", ""))
            if target.exists():
                try:
                    fns = extract_functions(target)
                    match = next((f for f in fns if f["name"] == fn_name), None)
                    if match:
                        fn_source = match["source"]
                except Exception:
                    fn_source = f"# source unavailable for {fn_name}"

        for finding in result.get("findings", []):
            if SEVERITY_RANK.get(finding["severity"], 0) < min_rank:
                continue

            # RAG query: combine CWE name + evidence for targeted retrieval
            rag_query = (
                f"{finding['cwe_id']} {finding.get('cwe_name','')} "
                f"mitigation fix secure code. "
                f"{finding.get('evidence','')}"
            )
            chunks  = kb.retrieve(rag_query, top_k=top_k)
            context = kb.format_context(chunks)
            prompt  = _mitigation_prompt(finding, fn_source, context)

            try:
                raw = llm.generate(prompt, max_retries=2)
            except Exception as e:
                mitigations.append({
                    "function": fn_name,
                    "cwe_id":   finding["cwe_id"],
                    "error":    str(e),
                })
                continue

            # parse JSON with a triple-quote fixer
            text_for_parse = _raw_parser(raw)
            fixed_code_raw = None

            fc_match = re.search(
                r'"fixed_code"\s*:\s*"(.*?)"(?=\s*,\s*"|\s*})',
                text_for_parse, re.DOTALL
            )
            if fc_match:
                fixed_code_raw = fc_match.group(1)
                # Decode any \n \t the LLM did escape correctly
                fixed_code_raw = fixed_code_raw.replace("\\n", "\n") \
                                               .replace("\\t", "\t") \
                                               .replace('\\"', '"')
                # Replace the field value with a safe placeholder
                parsed_text = text_for_parse[:fc_match.start(1)] \
                                 + "__FIXED_CODE__" \
                                 + text_for_parse[fc_match.end(1):]
            
            parsed = json.loads(parsed_text)
            parsed["fixed_code"] = fixed_code_raw or ""

            if parsed and isinstance(parsed, dict):
                mitigations.append({
                    "function":    fn_name,
                    "cwe_id":      finding["cwe_id"],
                    "severity":    finding["severity"],
                    "explanation": parsed.get("explanation", ""),
                    "fixed_code":  parsed.get("fixed_code", ""),
                    "hardening":   parsed.get("hardening", []),
                    "references":  parsed.get("references", []),
                })
            else:
                mitigations.append({
                    "function":  fn_name,
                    "cwe_id":    finding["cwe_id"],
                    "severity":  finding["severity"],
                    "raw_response": raw[:1000],
                    "error":     "Could not parse LLM response as JSON",
                })

    return {
        "status":      "ok",
        "mitigations": mitigations,
        "total":       len(mitigations),
        "min_severity_filter": min_severity,
    }


if __name__ == "__main__":
    print("Starting MCP vulnerability server...", file=sys.stderr)
    print(f"  Chunks zip  : {CONFIG['chunks_zip']}", file=sys.stderr)
    print(f"  Ollama URL  : {CONFIG['ollama_url']}", file=sys.stderr)
    print(f"  Ollama model: {CONFIG['ollama_model']}", file=sys.stderr)
    print(f"  SecLists    : {CONFIG['seclists_path']}", file=sys.stderr)
    print(f"  Report path : {CONFIG['report_path']}", file=sys.stderr)
    print(file=sys.stderr)
    mcp.run()