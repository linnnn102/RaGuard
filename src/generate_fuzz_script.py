"""
generate_fuzz_script.py — Standalone fuzz.sh generator
========================================================
Reads results/reports/vuln_report.json produced by vuln_scanner.py and writes a
fuzz.sh shell script containing all ffuf commands ready to run inside Docker.

Wordlist selection (which SecLists list to fuzz each finding with):
  * --use-llm  (default) — hand the (API, API source code) pair plus the
                vulnerability finding and a catalog of available SecLists
                wordlists to a language model (via src/seclist_selector.py),
                and let it pick the most relevant wordlist(s). Every chosen
                path is validated against the catalog. Falls back to the
                static map below if the model is unreachable or returns
                nothing valid.
  * --no-use-llm — skip the model and look up SecLists wordlist paths directly
                in data/cwe_wordlist_map.json.

Either way ffuf is fed /SecLists/<path> inside the container.

Usage:
    python src/generate_fuzz_script.py [options]

Options:
    --report       PATH   Path to vuln_report.json  [default: ./results/reports/vuln_report.json]
    --target-url   URL    Target URL with FUZZ keyword
                          [default: http://host.docker.internal:5055/user/FUZZ]
    --output       PATH   Output path for fuzz.sh   [default: ./results/scripts/fuzz.sh]
    --match-codes  STR    HTTP codes to treat as hits [default: 200]
    --max-wordlists INT   Max wordlists per CWE [default: 2]
    --no-url-encode       Disable URL encoding of payloads
    --use-llm / --no-use-llm   Toggle the LLM wordlist selector (default: on)
    --model        STR    Ollama model name for selection [default: qwen3]
    --catalog      PATH   SecLists catalog file [default: ./data/seclists_catalog.txt]

Then run the Docker container:
    docker build -t vuln-fuzzer .
    mkdir -p results/fuzz
    docker run --rm \\
        -v $(pwd)/results/scripts/fuzz.sh:/fuzz/fuzz.sh \\
        -v $(pwd)/results/fuzz:/results \\
        --add-host=host.docker.internal:host-gateway \\
        vuln-fuzzer bash /fuzz/fuzz.sh

Then parse the results:
    python src/parse_fuzz_results.py
"""

import argparse
import json
import re
import stat
import sys
from pathlib import Path

# Make sibling module importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from seclist_selector import DEFAULT_MODEL, load_catalog, select_wordlists  # noqa: E402

# ── CWE → SecLists wordlist mapping (fallback only) ──────────────────────────
# Loaded from data/cwe_wordlist_map.json — used when the LLM selector is
# disabled or unavailable.
_MAP_PATH = Path(__file__).resolve().parent.parent / "data" / "cwe_wordlist_map.json"
with _MAP_PATH.open() as _f:
    CWE_WORDLIST_MAP: dict = json.load(_f)

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def build_ffuf_cmd(
    target_url: str,
    cwe_id: str,
    wordlist_rel: str,
    out_tag: str | None = None,
    match_codes: str = "all",
    threads: int = 20,
    timeout: int = 10,
    url_encode: bool = True,
    autocalibrate: bool = True,
) -> str:
    """Build a single ffuf command string using container-internal paths.

    ``wordlist_rel`` is a SecLists-relative path (e.g.
    ``Fuzzing/Databases/SQLi/Generic-SQLi.txt``) fed as ``/SecLists/<rel>``.

    With ``autocalibrate`` (``-ac``), ffuf first sends throwaway random inputs to
    learn what a *normal miss* looks like (e.g. an empty result set) and auto-adds
    size/word/line filters for it. Combined with ``-mc all`` this makes a "hit"
    mean *the response measurably differed from the baseline* — i.e. an actual
    injection (a boolean payload returning extra rows, or a broken-SQL 500) —
    instead of "the endpoint returned 200" (which it does for almost any input).
    """
    safe_cwe = cwe_id.replace("-", "_")
    wordlist = f"/SecLists/{wordlist_rel}"
    tag = out_tag or Path(wordlist_rel).stem
    out_path = f"/results/ffuf_{safe_cwe}_{tag}.json"

    parts = [
        "ffuf",
        f"-u '{target_url}'",
        f"-w '{wordlist}'",
        f"-mc {match_codes}",
        f"-o '{out_path}'",
        "-of json",
        f"-t {threads}",
        f"-timeout {timeout}",
        # -s (silent), NOT -v. Verbose printed a block per match, and a full run
        # lands thousands of hits — it buried the pipeline's own progress lines
        # in `docker compose up` output. The findings are not lost: every match
        # is still written to the JSON at -o and parsed into fuzz_report.json.
        # Each job already announces itself via the echo line above it.
        "-s",
    ]
    if autocalibrate:
        # -ac: auto-calibrate baseline filters from random inputs.
        # -acc: also calibrate per-host so each run learns its own baseline.
        parts.append("-ac")
    if url_encode:
        parts.append("-enc url")

    return " ".join(parts)


def _load_function_source(report: dict, result: dict) -> str:
    """
    Slice the function source out of the original target file using line_start
    and line_end from the result entry. Falls back to "" on any error so the
    model gets minimal context but the pipeline doesn't crash.
    """
    target_path = report.get("meta", {}).get("target")
    if not target_path:
        return ""
    try:
        src = Path(target_path).read_text()
    except OSError:
        return ""

    lines = src.splitlines()
    start = max(1, int(result.get("line_start") or 1))
    end = int(result.get("line_end") or len(lines))
    end = max(end, start)
    return "\n".join(lines[start - 1:end])


_ROUTE_RE = re.compile(
    r'@\w+\.(get|post|put|delete|patch|route)\s*\(\s*[\'"]([^\'"]+)[\'"]'
)


def _extract_api_info(report: dict, result: dict, target_url: str) -> dict:
    """
    Recover the (API) half of the (API, source) pair: the route path and HTTP
    method declared by the decorator(s) above the vulnerable function. Best
    effort — returns what it can, empty strings otherwise.
    """
    info = {
        "endpoint":   "",
        "method":     "",
        "target_url": target_url,
        "function":   result.get("function", ""),
    }
    target_path = report.get("meta", {}).get("target")
    line_start = result.get("line_start")
    if not target_path or not line_start:
        return info
    try:
        lines = Path(target_path).read_text().splitlines()
    except OSError:
        return info

    # Walk upward from the `def` line collecting contiguous decorator lines.
    idx = int(line_start) - 2  # line directly above the def (0-based)
    decorators: list[str] = []
    while idx >= 0:
        s = lines[idx].strip()
        if s.startswith("@"):
            decorators.insert(0, s)
            idx -= 1
        elif s == "":
            idx -= 1
        else:
            break

    for dec in decorators:
        m = _ROUTE_RE.search(dec)
        if not m:
            continue
        verb, path = m.group(1), m.group(2)
        info["endpoint"] = path
        if verb == "route":
            mm = re.search(r"methods\s*=\s*\[([^\]]*)\]", dec)
            info["method"] = (
                mm.group(1).replace('"', "").replace("'", "").strip() if mm else "GET"
            )
        else:
            info["method"] = verb.upper()
        break
    return info


def generate_fuzz_script(
    report_path: Path,
    target_url: str,
    output_path: Path,
    match_codes: str,
    max_wordlists: int,
    url_encode: bool,
    use_llm: bool = True,
    model: str = DEFAULT_MODEL,
    catalog_path: Path | None = None,
    quiet: bool = False,
    autocalibrate: bool = True,
) -> None:
    # ── Load and validate vuln_report.json ────────────────────────────────────
    if not report_path.exists():
        print(f"[ERROR] Report not found: {report_path}")
        print("        Run vuln_scanner.py first to generate the report.")
        raise SystemExit(1)

    if "FUZZ" not in target_url:
        print("[ERROR] --target-url must contain FUZZ at the injection point.")
        print("        Example: http://host.docker.internal:5055/user/FUZZ")
        raise SystemExit(1)

    report = json.loads(report_path.read_text())

    catalog = load_catalog(catalog_path) if catalog_path else load_catalog()
    if use_llm and not catalog:
        print("[WARN] SecLists catalog is empty/missing — falling back to the static map.")
        print("       Regenerate it with: python tools/build_seclists_catalog.py")

    # ── Collect (finding, result) pairs so we keep the file/line context ───────
    pairs: list[tuple[dict, dict]] = []
    for result in report.get("results", []):
        for f in result.get("findings", []):
            pairs.append((f, result))

    if not pairs:
        print("[WARN] No findings in report — fuzz.sh will be empty.")

    # ── Deduplicate CWE IDs, keep highest-severity per CWE ────────────────────
    cwe_seen: dict[str, tuple[dict, dict]] = {}
    for f, result in sorted(
        pairs,
        key=lambda fr: SEVERITY_RANK.get(fr[0].get("severity", "LOW"), 0),
        reverse=True,
    ):
        cid = f.get("cwe_id", "")
        if cid and cid not in cwe_seen:
            cwe_seen[cid] = (f, result)

    # ── Build script lines ────────────────────────────────────────────────────
    mode_str = f"llm={model}" if use_llm else "static-map"
    script_lines = [
        "#!/usr/bin/env bash",
        "# Auto-generated by generate_fuzz_script.py — do not edit manually",
        f"# Report : {report_path.resolve()}",
        f"# Target : {target_url}",
        f"# Mode   : {mode_str}",
        f"# CWEs   : {', '.join(cwe_seen.keys()) or 'none'}",
        "",
        # NOT `set -e`. Each ffuf job is INDEPENDENT: a missing wordlist or a
        # transient error in one must not discard every job after it. Under
        # `set -e` exactly that happened silently — one bad wordlist aborted the
        # script and the remaining CWEs were never fuzzed, so the report showed
        # "no hits" for vulnerabilities that were simply never tested. Failures
        # are counted and reported in the exit status instead.
        "set -uo pipefail",
        "mkdir -p /results",
        "",
        "fuzz_failed=0",
        "",
    ]

    jobs_written = 0

    for cwe_id, (finding, result) in cwe_seen.items():
        cwe_name = finding.get("cwe_name", "")
        script_lines.append(f"echo '[fuzz] Running {cwe_id} — {cwe_name}'")

        if use_llm and catalog:
            function_source = _load_function_source(report, result)
            api_info = _extract_api_info(report, result, target_url)
            wordlist_rels, source = select_wordlists(
                finding=finding,
                function_source=function_source,
                api_info=api_info,
                catalog=catalog,
                model=model,
                max_wordlists=max_wordlists,
            )
        else:
            wordlist_rels = CWE_WORDLIST_MAP.get(cwe_id, CWE_WORDLIST_MAP["_default"])[:max_wordlists]
            source = "static-map"

        # The README promises LLM-returned paths are validated against the
        # catalog so the model cannot invent one — but the STATIC FALLBACK map
        # was never held to that, and shipped four paths that do not exist in
        # SecLists (e.g. Fuzzing/SSRF/SSRF-targets.txt). Validate both sources.
        if catalog:
            checked = []
            for wl_rel in wordlist_rels:
                if wl_rel in catalog:
                    checked.append(wl_rel)
                else:
                    print(f"  [{cwe_id}] SKIP {wl_rel} — not in the SecLists catalog")
            if not checked:
                checked = [w for w in CWE_WORDLIST_MAP["_default"] if w in catalog][:1]
                if checked:
                    print(f"  [{cwe_id}] falling back to {checked[0]}")
            wordlist_rels = checked

        for wl_rel in wordlist_rels:
            cmd = build_ffuf_cmd(
                target_url=target_url,
                cwe_id=cwe_id,
                wordlist_rel=wl_rel,
                match_codes=match_codes,
                url_encode=url_encode,
                autocalibrate=autocalibrate,
            )
            # Keep going on failure, but record it so the run cannot look clean
            # when jobs were skipped.
            script_lines.append(cmd + " || {")
            script_lines.append(
                f"  echo \"[fuzz] WARN: {cwe_id} job failed (wordlist: {wl_rel})\" >&2"
            )
            script_lines.append("  fuzz_failed=$((fuzz_failed+1))")
            script_lines.append("}")
            jobs_written += 1
            print(f"  [{cwe_id}] {wl_rel} ({source})")

        script_lines.append("")

    script_lines.append("echo '[fuzz] Done. Results written to /results/'")
    script_lines.append('if [ "$fuzz_failed" -gt 0 ]; then')
    script_lines.append(
        '  echo "[fuzz] $fuzz_failed of '
        + str(jobs_written)
        + ' job(s) FAILED — those CWEs were not tested." >&2'
    )
    script_lines.append("fi")
    # Exit 0 even with failed jobs: the successful ones produced real results
    # worth parsing. run_fuzz surfaces the failure count instead of discarding
    # the whole run.
    script_lines.append("exit 0")

    # ── Write and chmod the script ────────────────────────────────────────────
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(script_lines) + "\n")
    output_path.chmod(output_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"\n[generate] Script written to : {output_path.resolve()}")
    print(f"[generate] Jobs              : {jobs_written}")
    print(f"[generate] Unique CWEs       : {len(cwe_seen)}")
    # The manual "Next steps" block only makes sense for standalone step-by-step
    # use. When called from the agentic/sequential pipeline (quiet=True) the
    # runner executes and parses on its own, so printing manual docker commands
    # would be misleading.
    if not quiet:
        print()
        print("Next steps:")
        print("  1. docker build -t vuln-fuzzer .")
        print("  2. mkdir -p results/fuzz")
        print("  3. docker run --rm \\")
        print("       -v $(pwd)/results/scripts/fuzz.sh:/fuzz/fuzz.sh \\")
        print("       -v $(pwd)/results/fuzz:/results \\")
        print("       --add-host=host.docker.internal:host-gateway \\")
        print("       vuln-fuzzer bash /fuzz/fuzz.sh")
        print("  4. python src/parse_fuzz_results.py")


def parse_args():
    p = argparse.ArgumentParser(
        description="Generate fuzz.sh from vuln_report.json for Docker execution"
    )
    p.add_argument(
        "--report", type=Path, default=Path("./results/reports/vuln_report.json"),
        help="Path to vuln_report.json (default: ./results/reports/vuln_report.json)",
    )
    p.add_argument(
        "--target-url",
        default="http://host.docker.internal:5055/user/FUZZ",
        help="Target URL with FUZZ keyword (default: http://host.docker.internal:5055/user/FUZZ)",
    )
    p.add_argument(
        "--output", type=Path, default=Path("./results/scripts/fuzz.sh"),
        help="Output path for fuzz.sh (default: ./results/scripts/fuzz.sh)",
    )
    p.add_argument(
        "--match-codes", default="200",
        help="HTTP status codes to treat as hits (default: 200)",
    )
    p.add_argument(
        "--max-wordlists", type=int, default=2,
        help="Max wordlists per CWE ID (default: 2)",
    )
    p.add_argument(
        "--no-url-encode", action="store_true",
        help="Disable URL encoding of payloads",
    )
    p.add_argument(
        "--use-llm", dest="use_llm", action="store_true", default=True,
        help="Use the LLM SecLists selector (default: on)",
    )
    p.add_argument(
        "--no-use-llm", dest="use_llm", action="store_false",
        help="Disable the LLM and use the static cwe_wordlist_map.json directly",
    )
    p.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Ollama model name for wordlist selection (default: {DEFAULT_MODEL})",
    )
    p.add_argument(
        "--catalog", type=Path, default=None,
        help="SecLists catalog file (default: ./data/seclists_catalog.txt)",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(f"[generate] Reading report : {args.report}")
    print(f"[generate] Target URL     : {args.target_url}")
    print(f"[generate] Output         : {args.output}")
    print(f"[generate] Mode           : {'llm=' + args.model if args.use_llm else 'static-map'}")
    print()
    generate_fuzz_script(
        report_path=args.report,
        target_url=args.target_url,
        output_path=args.output,
        match_codes=args.match_codes,
        max_wordlists=args.max_wordlists,
        url_encode=not args.no_url_encode,
        use_llm=args.use_llm,
        model=args.model,
        catalog_path=args.catalog,
    )
