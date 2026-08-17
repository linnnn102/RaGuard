#!/usr/bin/env python3
"""run_eval.py — thesis eval harness (3 arms).

Empirically supports the paper's cost/latency claims by running the pipeline
under three configurations and scoring each against ground-truth labels:

  arm 1  llm-only baseline      — qwen3 for every task, legacy fixed order
  arm 2  heterogeneous (OTS)    — local Qwen3 orchestrator + off-the-shelf Qwen SLMs
  arm 3  heterogeneous (tuned)  — local Qwen3 orchestrator + fine-tuned adapter tags

(The orchestrator can also be the GLM5 cloud model — swap in
config/agentsec.glm.yaml for any arm to measure that instead.)

Each arm is described by an agentsec.yaml config. Metrics:
  * latency  — per-task and end-to-end, from the S1 call logs
  * tokens   — prompt/completion per task, from the S1 call logs
  * price    — tokens x a per-model price table (local Ollama = 0)
  * quality  — CWE precision / recall / F1 vs eval/labels/, mitigation validity

Emits a Markdown table and a CSV to eval/results/.

Usage:
  # Run all arms live (needs Ollama running; GLM5 only if you use its config), then score:
  python eval/run_eval.py --run --target targets/test_target2.py \
      --arm baseline=config/agentsec.baseline.yaml \
      --arm ots=config/agentsec.yaml \
      --arm tuned=config/agentsec.v2.yaml

  # Score-only from artifacts already produced (no model calls):
  python eval/run_eval.py --labels eval/labels/test_target2.labels.json
"""

from __future__ import annotations

# ── run under the project venv, whatever `python` launched us ──────────────────
# This machine has several interpreters (FreeCAD's bundled python, the framework
# python3); only .venv has the project deps. Re-exec under it BEFORE importing
# anything heavy, so a bare `python …/script.py` can't silently run the wrong one.
# No-op when already under .venv, or when none exists.
if __name__ == "__main__":
    import os as _os
    import sys as _sys
    from pathlib import Path as _P
    for _parent in _P(__file__).resolve().parents:
        _venv_py = _parent / ".venv" / "bin" / "python"
        if _venv_py.exists():
            if _P(_sys.executable).resolve() != _venv_py.resolve():
                _argv = getattr(_sys, "orig_argv", None) or [_sys.executable, *_sys.argv]
                _os.execv(str(_venv_py), [str(_venv_py), *_argv[1:]])
            break

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Per-1K-token USD price table. Local Ollama models (orchestrator + specialists)
# are free; GLM5 is only paid when you select config/agentsec.glm.yaml. Adjust to
# the provider's public pricing for the thesis.
PRICE_PER_1K = {
    "glm-4.5": {"prompt": 0.0006, "completion": 0.0022},
    "_local": {"prompt": 0.0, "completion": 0.0},
}


def _price_for(model: str) -> dict:
    return PRICE_PER_1K.get(model, PRICE_PER_1K["_local"])


# ── metrics from S1 call logs ──────────────────────────────────────────────────

def load_log_metrics(logs_dir: Path) -> dict:
    """Aggregate latency + tokens + price per task from logs/calls/*.jsonl."""
    per_task = {}
    for path in sorted(logs_dir.glob("*.jsonl")):
        task = path.stem
        lat, pt, ct, price, n = 0.0, 0, 0, 0.0, 0
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            n += 1
            lat += float(rec.get("latency_s") or 0)
            usage = rec.get("usage") or {}
            p = int(usage.get("prompt_tokens") or 0)
            c = int(usage.get("completion_tokens") or 0)
            pt += p
            ct += c
            pr = _price_for(rec.get("model", ""))
            price += (p / 1000) * pr["prompt"] + (c / 1000) * pr["completion"]
        per_task[task] = {
            "calls": n, "latency_s": round(lat, 3),
            "prompt_tokens": pt, "completion_tokens": ct,
            "usd": round(price, 6),
        }
    totals = {
        "calls": sum(t["calls"] for t in per_task.values()),
        "latency_s": round(sum(t["latency_s"] for t in per_task.values()), 3),
        "prompt_tokens": sum(t["prompt_tokens"] for t in per_task.values()),
        "completion_tokens": sum(t["completion_tokens"] for t in per_task.values()),
        "usd": round(sum(t["usd"] for t in per_task.values()), 6),
    }
    return {"per_task": per_task, "totals": totals}


# ── quality metrics vs labels ──────────────────────────────────────────────────

def _findings_from_report(report_path: Path) -> set:
    """(function, cwe_id) pairs predicted by analyze_code."""
    if not report_path.exists():
        return set()
    report = json.loads(report_path.read_text())
    out = set()
    for result in report.get("results", []):
        fn = result.get("function", "")
        for f in result.get("findings", []):
            out.add((fn, f.get("cwe_id", "")))
    return out


def score_quality(report_path: Path, labels: dict) -> dict:
    predicted = _findings_from_report(report_path)
    expected = {(e["function"], e["cwe_id"]) for e in labels.get("expected_findings", [])}

    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def score_benign(report_path: Path, labels: dict) -> dict:
    """False positives on known-clean functions (`expected_clean`). A shrunk
    model that over-flags safe code shows up here even when its recall looks
    fine — this is the precision half of the capability claim (C1)."""
    predicted = _findings_from_report(report_path)
    flagged = {fn for (fn, _cwe) in predicted}
    clean = labels.get("expected_clean", []) or []
    fp = sum(1 for fn in clean if fn in flagged)
    total = len(clean)
    return {
        "benign_total": total,
        "benign_fp": fp,
        "benign_acc": round((total - fp) / total, 3) if total else "",
    }


def score_per_cwe(report_path: Path, labels: dict) -> dict:
    """Per-CWE precision/recall/F1 — which weaknesses the small model keeps vs
    drops. Same tp/fp/fn logic as score_quality, sliced by cwe_id."""
    predicted = _findings_from_report(report_path)
    expected = {(e["function"], e["cwe_id"]) for e in labels.get("expected_findings", [])}
    out = {}
    for cwe in sorted({c for (_f, c) in expected} | {c for (_f, c) in predicted}):
        p = {x for x in predicted if x[1] == cwe}
        e = {x for x in expected if x[1] == cwe}
        tp, fp, fn = len(p & e), len(p - e), len(e - p)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        out[cwe] = {"tp": tp, "fp": fp, "fn": fn,
                    "precision": round(prec, 3), "recall": round(rec, 3),
                    "f1": round(f1, 3)}
    return out


def score_mitigation_validity(full_report_path: Path) -> dict:
    """Fraction of mitigations that parsed and carry non-empty fixed_code."""
    if not full_report_path.exists():
        return {"mitigations": 0, "valid": 0, "validity": 0.0}
    data = json.loads(full_report_path.read_text())
    mits = []
    # full_report may embed the suggest_mitigations tool result in the transcript
    for step in data.get("transcript", []):
        if step.get("tool") == "suggest_mitigations":
            mits = step.get("result", {}).get("mitigations", [])
    valid = sum(1 for m in mits if m.get("fixed_code") and not m.get("error"))
    return {
        "mitigations": len(mits),
        "valid": valid,
        "validity": round(valid / len(mits), 3) if mits else 0.0,
    }


# ── running an arm live ────────────────────────────────────────────────────────

def run_arm(name: str, config_path: Path, target: str, execute_fuzz: bool,
            sequential: bool = False, repeat: int = 0) -> dict:
    import shutil
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from agentsec.config import load_config
    from agentsec.orchestrator import run_agent, run_sequential

    config = load_config(config_path)
    # Per-repeat isolation: append-only logs must NOT accumulate across repeats
    # (that would inflate token/latency totals), so each run gets a fresh dir.
    logs_dir = PROJECT_ROOT / "logs" / "eval" / name / f"r{repeat}"
    if logs_dir.exists():
        shutil.rmtree(logs_dir)
    config.logging.dir = logs_dir

    out_dir = PROJECT_ROOT / "results" / "eval" / name
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"r{repeat}.vuln_report.json"
    full_report = out_dir / f"r{repeat}.full_report.json"
    # Point analyze_code's report at this repeat's path (skill reads fuzz.report_path).
    config.fuzz = dict(config.fuzz or {})
    config.fuzz["report_path"] = str(report_path)

    runner = run_sequential if sequential else run_agent
    result = runner(target_file=target, config=config, execute_fuzz=execute_fuzz)
    full_report.write_text(json.dumps(result, indent=2, default=str))
    return {"logs_dir": logs_dir, "full_report": full_report, "report_path": report_path}


# ── table rendering ────────────────────────────────────────────────────────────

def render(rows: list[dict], per_cwe_by_arm: dict, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    cols = ["arm", "runs", "e2e_latency_s", "prompt_tokens", "completion_tokens",
            "usd", "precision", "recall", "f1", "benign_acc", "mitigation_validity"]

    md = ["## Main results (mean ± std over `runs`)", "",
          "| " + " | ".join(cols) + " |",
          "|" + "|".join(["---"] * len(cols)) + "|"]
    for r in rows:
        md.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")

    all_cwes = sorted({c for pc in per_cwe_by_arm.values() for c in pc})
    if all_cwes:
        arms = list(per_cwe_by_arm.keys())
        md += ["", "## Per-CWE F1", "",
               "| CWE | " + " | ".join(arms) + " |",
               "|" + "|".join(["---"] * (len(arms) + 1)) + "|"]
        for cwe in all_cwes:
            md.append("| " + " | ".join([cwe] + [per_cwe_by_arm[a].get(cwe, "") for a in arms]) + " |")

    (out_dir / "eval_table.md").write_text("\n".join(md) + "\n")
    with (out_dir / "eval_table.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

    print("\n".join(md))
    print(f"\n[eval] wrote {out_dir/'eval_table.md'}, eval_table.csv, raw_runs.json")


def _score_one(logs_dir, report_path, full_report, labels, mitigation=True) -> dict:
    """All metrics for a single run — the unit that gets aggregated over repeats."""
    metrics = load_log_metrics(logs_dir) if Path(logs_dir).exists() else {"totals": {}}
    return {
        "metrics": metrics,
        "quality": score_quality(report_path, labels),
        "benign": score_benign(report_path, labels),
        "valid": score_mitigation_validity(full_report) if mitigation else {"validity": ""},
        "per_cwe": score_per_cwe(report_path, labels),
    }


def _mean_std(vals):
    nums = [v for v in vals if isinstance(v, (int, float))]
    if not nums:
        return (None, None)
    return (statistics.fmean(nums), statistics.pstdev(nums) if len(nums) > 1 else 0.0)


def _fmt(mean, std, reps, dp=3) -> str:
    if mean is None:
        return ""
    if reps <= 1 or not std:
        return f"{mean:.{dp}f}"
    return f"{mean:.{dp}f} ± {std:.{dp}f}"


def _aggregate_row(name, reps, n_reps) -> dict:
    def totals(k): return [r["metrics"].get("totals", {}).get(k) for r in reps]
    def q(g, k): return [r[g].get(k) for r in reps]
    spec = [
        ("e2e_latency_s", totals("latency_s"), 2),
        ("prompt_tokens", totals("prompt_tokens"), 0),
        ("completion_tokens", totals("completion_tokens"), 0),
        ("usd", totals("usd"), 6),
        ("precision", q("quality", "precision"), 3),
        ("recall", q("quality", "recall"), 3),
        ("f1", q("quality", "f1"), 3),
        ("benign_acc", q("benign", "benign_acc"), 3),
        ("mitigation_validity", q("valid", "validity"), 3),
    ]
    row = {"arm": name, "runs": n_reps}
    for col, vals, dp in spec:
        row[col] = _fmt(*_mean_std(vals), n_reps, dp)
    return row


def _aggregate_per_cwe(reps, n_reps) -> dict:
    out = {}
    for cwe in sorted({c for r in reps for c in r["per_cwe"]}):
        f1s = [r["per_cwe"][cwe]["f1"] for r in reps if cwe in r["per_cwe"]]
        out[cwe] = _fmt(*_mean_std(f1s), n_reps, 3)
    return out


def main():
    p = argparse.ArgumentParser(description="3-arm eval harness")
    p.add_argument("--labels", type=Path,
                   default=PROJECT_ROOT / "eval/labels/test_target2.labels.json")
    p.add_argument("--target", default="targets/test_target2.py")
    p.add_argument("--run", action="store_true", help="Run each arm live before scoring")
    p.add_argument("--repeats", type=int, default=1,
                   help="Runs per arm (with --run); metrics reported as mean ± std.")
    p.add_argument("--execute-fuzz", action="store_true")
    p.add_argument("--arm", action="append", default=[],
                   help="name=config_path[:seq] (repeatable). Default: score current artifacts.")
    p.add_argument("--report", type=Path,
                   default=PROJECT_ROOT / "results/reports/vuln_report.json",
                   help="vuln_report.json for score-only mode")
    p.add_argument("--logs-dir", type=Path, default=PROJECT_ROOT / "logs/calls")
    p.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "eval/results")
    args = p.parse_args()

    labels = json.loads(args.labels.read_text())
    rows, per_cwe_by_arm, raw = [], {}, {}

    if args.arm:
        for spec in args.arm:
            name, _, cfg = spec.partition("=")
            cfg, _, mode = cfg.partition(":")   # optional ":seq" → fixed-order baseline
            sequential = mode == "seq"
            cfg_path = Path(cfg)
            n_reps = max(1, args.repeats) if args.run else 1
            reps = []
            for r in range(n_reps):
                if args.run:
                    arts = run_arm(name, cfg_path, args.target, args.execute_fuzz, sequential, r)
                    logs_dir, full_report, report_path = (
                        arts["logs_dir"], arts["full_report"], arts["report_path"])
                else:
                    base = PROJECT_ROOT / "results" / "eval" / name
                    logs_dir = PROJECT_ROOT / "logs" / "eval" / name / f"r{r}"
                    full_report = base / f"r{r}.full_report.json"
                    report_path = base / f"r{r}.vuln_report.json"
                reps.append(_score_one(logs_dir, report_path, full_report, labels))
            rows.append(_aggregate_row(name, reps, n_reps))
            per_cwe_by_arm[name] = _aggregate_per_cwe(reps, n_reps)
            raw[name] = reps
    else:
        reps = [_score_one(args.logs_dir, args.report,
                           PROJECT_ROOT / "results/eval/current.full_report.json",
                           labels, mitigation=False)]
        rows.append(_aggregate_row("current", reps, 1))
        per_cwe_by_arm["current"] = _aggregate_per_cwe(reps, 1)
        raw["current"] = reps

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "raw_runs.json").write_text(json.dumps(raw, indent=2, default=str))
    render(rows, per_cwe_by_arm, args.out_dir)


if __name__ == "__main__":
    main()
