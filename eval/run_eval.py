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

import argparse
import csv
import json
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
            sequential: bool = False) -> dict:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from agentsec.config import load_config
    from agentsec.orchestrator import run_agent, run_sequential

    config = load_config(config_path)
    # Isolate this arm's logs so metrics don't bleed across arms.
    config.logging.dir = PROJECT_ROOT / "logs" / "eval" / name
    out_path = PROJECT_ROOT / "results" / "eval" / f"{name}.full_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    runner = run_sequential if sequential else run_agent
    result = runner(target_file=target, config=config, execute_fuzz=execute_fuzz)
    out_path.write_text(json.dumps(result, indent=2, default=str))
    return {"logs_dir": config.logging.dir, "full_report": out_path}


# ── table rendering ────────────────────────────────────────────────────────────

def render(rows: list[dict], out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    cols = ["arm", "e2e_latency_s", "prompt_tokens", "completion_tokens",
            "usd", "precision", "recall", "f1", "mitigation_validity"]

    md = ["| " + " | ".join(cols) + " |",
          "|" + "|".join(["---"] * len(cols)) + "|"]
    for r in rows:
        md.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    (out_dir / "eval_table.md").write_text("\n".join(md) + "\n")

    with (out_dir / "eval_table.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

    print("\n".join(md))
    print(f"\n[eval] wrote {out_dir/'eval_table.md'} and eval_table.csv")


def main():
    p = argparse.ArgumentParser(description="3-arm eval harness")
    p.add_argument("--labels", type=Path,
                   default=PROJECT_ROOT / "eval/labels/test_target2.labels.json")
    p.add_argument("--target", default="targets/test_target2.py")
    p.add_argument("--run", action="store_true", help="Run each arm live before scoring")
    p.add_argument("--execute-fuzz", action="store_true")
    p.add_argument("--arm", action="append", default=[],
                   help="name=config_path (repeatable). Default: score current logs/report.")
    p.add_argument("--report", type=Path,
                   default=PROJECT_ROOT / "results/reports/vuln_report.json",
                   help="vuln_report.json for score-only mode")
    p.add_argument("--logs-dir", type=Path, default=PROJECT_ROOT / "logs/calls")
    p.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "eval/results")
    args = p.parse_args()

    labels = json.loads(args.labels.read_text())
    rows = []

    if args.arm:
        for spec in args.arm:
            name, _, cfg = spec.partition("=")
            # optional ":seq" suffix runs this arm through the fixed-order
            # baseline instead of the orchestrator loop
            cfg, _, mode = cfg.partition(":")
            sequential = mode == "seq"
            cfg_path = Path(cfg)
            if args.run:
                arts = run_arm(name, cfg_path, args.target, args.execute_fuzz, sequential)
                logs_dir, full_report = arts["logs_dir"], arts["full_report"]
                report_path = PROJECT_ROOT / "results/reports/vuln_report.json"
            else:
                logs_dir = PROJECT_ROOT / "logs" / "eval" / name
                full_report = PROJECT_ROOT / "results" / "eval" / f"{name}.full_report.json"
                report_path = PROJECT_ROOT / "results/reports/vuln_report.json"
            metrics = load_log_metrics(logs_dir) if logs_dir.exists() else {"totals": {}}
            quality = score_quality(report_path, labels)
            valid = score_mitigation_validity(full_report)
            rows.append(_row(name, metrics, quality, valid))
    else:
        # score-only from the default artifacts (M3 smoke output)
        metrics = load_log_metrics(args.logs_dir) if args.logs_dir.exists() else {"totals": {}}
        quality = score_quality(args.report, labels)
        rows.append(_row("current", metrics, quality, {"validity": ""}))

    render(rows, args.out_dir)


def _row(name, metrics, quality, valid) -> dict:
    totals = metrics.get("totals", {})
    return {
        "arm": name,
        "e2e_latency_s": totals.get("latency_s", ""),
        "prompt_tokens": totals.get("prompt_tokens", ""),
        "completion_tokens": totals.get("completion_tokens", ""),
        "usd": totals.get("usd", ""),
        "precision": quality.get("precision", ""),
        "recall": quality.get("recall", ""),
        "f1": quality.get("f1", ""),
        "mitigation_validity": valid.get("validity", ""),
    }


if __name__ == "__main__":
    main()
