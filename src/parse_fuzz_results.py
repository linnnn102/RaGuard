"""
parse_fuzz_results.py — Parse ffuf JSON output into a hits report
=================================================================
Run this after the Docker container has finished executing fuzz.sh.
Reads all ffuf JSON output files from ./results/fuzz/ and produces
a structured hits report saved to ./results/reports/fuzz_report.json.

Usage:
    python src/parse_fuzz_results.py [options]

Options:
    --results-dir  PATH   Directory containing ffuf JSON output files
                          [default: ./results/fuzz]
    --output       PATH   Path to write the hits report
                          [default: ./results/reports/fuzz_report.json]
    --match-codes  STR    Comma-separated HTTP codes to treat as hits
                          [default: 200]
"""

import argparse
import json
from pathlib import Path


def parse_ffuf_file(path: Path, match_codes: set[int]) -> dict:
    """Parse a single ffuf JSON output file and return a job summary."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return {"file": str(path), "error": str(e)}

    hits = []
    for result in data.get("results", []):
        status = result.get("status")
        if status in match_codes:
            hits.append({
                "url":    result.get("url"),
                "status": status,
                "length": result.get("length"),
                "words":  result.get("words"),
                "input":  result.get("input", {}).get("FUZZ", ""),
            })

    # Recover CWE ID from filename: ffuf_CWE_89_wordlistname.json
    stem  = path.stem
    parts = stem.split("_")
    cwe_id = None
    if len(parts) >= 3 and parts[0] == "ffuf":
        cwe_id = f"{parts[1]}-{parts[2]}"

    return {
        "file":      str(path),
        "cwe_id":    cwe_id,
        "wordlist":  data.get("config", {}).get("wordlist", "unknown"),
        "target":    data.get("config", {}).get("url", "unknown"),
        "hits":      hits,
        "hit_count": len(hits),
    }


def parse_fuzz_results(
    results_dir: Path,
    output_path: Path,
    match_codes: set[int],
) -> dict:
    result_files = sorted(results_dir.glob("ffuf_*.json"))

    if not result_files:
        print(f"[parse] No ffuf output files found in {results_dir}")
        return {"status": "ok", "jobs": [], "total_hits": 0}

    jobs       = []
    total_hits = 0

    for f in result_files:
        job = parse_ffuf_file(f, match_codes)
        jobs.append(job)
        total_hits += job.get("hit_count", 0)
        status = f"ERROR: {job['error']}" if job.get("error") else f"{job['hit_count']} hit(s)"
        print(f"  {f.name}: {status}")

    report = {
        "status":     "ok",
        "results_dir": str(results_dir.resolve()),
        "total_hits": total_hits,
        "jobs":       jobs,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
    print(f"\n[parse] Report saved → {output_path}")
    print(f"[parse] Total hits  : {total_hits} across {len(jobs)} job(s)")

    return report


def parse_args():
    p = argparse.ArgumentParser(
        description="Parse ffuf JSON output files into a hits report"
    )
    p.add_argument(
        "--results-dir", type=Path, default=Path("./results/fuzz"),
        help="Directory containing ffuf JSON output files (default: ./results/fuzz)",
    )
    p.add_argument(
        "--output", type=Path, default=Path("./results/reports/fuzz_report.json"),
        help="Output path for the hits report (default: ./results/reports/fuzz_report.json)",
    )
    p.add_argument(
        "--match-codes", default="200",
        help="Comma-separated HTTP status codes to count as hits (default: 200)",
    )
    return p.parse_args()


if __name__ == "__main__":
    args        = parse_args()
    match_codes = {int(c.strip()) for c in args.match_codes.split(",")}

    print(f"[parse] Results dir : {args.results_dir}")
    print(f"[parse] Match codes : {match_codes}")
    print(f"[parse] Output      : {args.output}\n")

    if not args.results_dir.exists():
        print(f"[ERROR] Results directory not found: {args.results_dir}")
        print("        Run the Docker container first: bash fuzz.sh inside the container")
        raise SystemExit(1)

    parse_fuzz_results(
        results_dir=args.results_dir,
        output_path=args.output,
        match_codes=match_codes,
    )
