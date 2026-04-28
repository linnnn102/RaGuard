"""
generate_fuzz_script.py — Standalone fuzz.sh generator
========================================================
Reads results/reports/vuln_report.json produced by vuln_scanner.py, maps each unique
CWE ID to the relevant SecLists wordlists, and writes a fuzz.sh shell
script containing all ffuf commands ready to run inside Docker.

Usage:
    python src/generate_fuzz_script.py [options]

Options:
    --report       PATH   Path to vuln_report.json  [default: ./results/reports/vuln_report.json]
    --target-url   URL    Target URL with FUZZ keyword
                          [default: http://host.docker.internal:5055/user/FUZZ]
    --output       PATH   Output path for fuzz.sh   [default: ./results/scripts/fuzz.sh]
    --match-codes  STR    HTTP codes to treat as hits [default: 200]
    --max-wordlists INT   Max wordlists per CWE       [default: 1]
    --no-url-encode       Disable URL encoding of payloads

Example:
    python src/generate_fuzz_script.py --report results/reports/vuln_report.json \\
        --target-url http://host.docker.internal:5055/user/FUZZ

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
import os
import stat
from pathlib import Path

# ── CWE → SecLists wordlist mapping ───────────────────────────────────────────
# Paths are relative to /SecLists inside the Docker container.
CWE_WORDLIST_MAP = {
    "CWE-89":  [
        "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
        "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    ],
    "CWE-79":  [
        "Fuzzing/XSS/XSS-Jhaddix.txt",
        "Fuzzing/XSS/XSS-BruteLogic.txt",
    ],
    "CWE-78":  [
        "Fuzzing/command-injection-commix.txt",
    ],
    "CWE-22":  [
        "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
    ],
    "CWE-287": [
        "Fuzzing/Authentication/Authentication.txt",
    ],
    "CWE-352": [
        "Fuzzing/CSRF/CSRF-token-wordlist.txt",
    ],
    "CWE-434": [
        "Fuzzing/Extensions.fuzz.txt",
    ],
    "CWE-502": [
        "Fuzzing/Polyglots/Polyglots.txt",
    ],
    "CWE-918": [
        "Fuzzing/SSRF/SSRF-targets.txt",
    ],
    "CWE-20":  [
        "Fuzzing/Polyglots/Polyglots.txt",
        "Fuzzing/special-chars.txt",
    ],
    "_default": [
        "Discovery/Web-Content/common.txt",
    ],
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def build_ffuf_cmd(
    target_url: str,
    wordlist_rel: str,
    cwe_id: str,
    match_codes: str = "200",
    threads: int = 20,
    timeout: int = 10,
    url_encode: bool = True,
) -> str:
    """Build a single ffuf command string using container-internal paths."""
    safe_cwe = cwe_id.replace("-", "_")
    wl_stem  = Path(wordlist_rel).stem
    out_path = f"/results/ffuf_{safe_cwe}_{wl_stem}.json"
    wordlist = f"/SecLists/{wordlist_rel}"

    parts = [
        "ffuf",
        f"-u '{target_url}'",
        f"-w '{wordlist}'",
        f"-mc {match_codes}",
        f"-o '{out_path}'",
        "-of json",
        f"-t {threads}",
        f"-timeout {timeout}",
        "-v",
    ]
    if url_encode:
        parts.append("-enc url")

    return " ".join(parts)


def generate_fuzz_script(
    report_path: Path,
    target_url: str,
    output_path: Path,
    match_codes: str,
    max_wordlists: int,
    url_encode: bool,
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

    # ── Collect all findings ───────────────────────────────────────────────────
    all_findings = [
        f
        for result in report.get("results", [])
        for f in result.get("findings", [])
    ]

    if not all_findings:
        print("[WARN] No findings in report — fuzz.sh will be empty.")

    # ── Deduplicate CWE IDs, keep highest-severity per CWE ────────────────────
    cwe_seen: dict[str, dict] = {}
    for f in sorted(
        all_findings,
        key=lambda x: SEVERITY_RANK.get(x.get("severity", "LOW"), 0),
        reverse=True,
    ):
        cid = f.get("cwe_id", "")
        if cid and cid not in cwe_seen:
            cwe_seen[cid] = f

    # ── Build script lines ────────────────────────────────────────────────────
    script_lines = [
        "#!/usr/bin/env bash",
        "# Auto-generated by generate_fuzz_script.py — do not edit manually",
        f"# Report : {report_path.resolve()}",
        f"# Target : {target_url}",
        f"# CWEs   : {', '.join(cwe_seen.keys()) or 'none'}",
        "",
        "set -euo pipefail",
        "mkdir -p /results",
        "",
    ]

    jobs_written = 0

    for cwe_id, finding in cwe_seen.items():
        wordlist_rels = CWE_WORDLIST_MAP.get(
            cwe_id, CWE_WORDLIST_MAP["_default"]
        )[:max_wordlists]

        cwe_name = finding.get("cwe_name", "")
        script_lines.append(
            f"echo '[fuzz] Running {cwe_id} — {cwe_name}'"
        )

        for wl_rel in wordlist_rels:
            cmd = build_ffuf_cmd(
                target_url=target_url,
                wordlist_rel=wl_rel,
                cwe_id=cwe_id,
                match_codes=match_codes,
                url_encode=url_encode,
            )
            script_lines.append(cmd)
            jobs_written += 1
            print(f"  [{cwe_id}] {wl_rel.split('/')[-1]}")

        script_lines.append("")

    script_lines.append("echo '[fuzz] Done. Results written to /results/'")

    # ── Write and chmod the script ────────────────────────────────────────────
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(script_lines) + "\n")
    output_path.chmod(output_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"\n[generate] Script written to : {output_path.resolve()}")
    print(f"[generate] Jobs              : {jobs_written}")
    print(f"[generate] Unique CWEs       : {len(cwe_seen)}")
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
        "--max-wordlists", type=int, default=1,
        help="Max wordlists per CWE ID (default: 1)",
    )
    p.add_argument(
        "--no-url-encode", action="store_true",
        help="Disable URL encoding of payloads",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(f"[generate] Reading report : {args.report}")
    print(f"[generate] Target URL     : {args.target_url}")
    print(f"[generate] Output         : {args.output}")
    print()
    generate_fuzz_script(
        report_path=args.report,
        target_url=args.target_url,
        output_path=args.output,
        match_codes=args.match_codes,
        max_wordlists=args.max_wordlists,
        url_encode=not args.no_url_encode,
    )
