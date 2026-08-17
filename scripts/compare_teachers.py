#!/usr/bin/env python3
"""compare_teachers.py — teacher-quality benchmark.

Scores a teacher's analyze_code findings against a ground-truth label file:

  detection recall — of the known-vulnerable functions, how many got >=1 finding
                     (the "does it MISS vulns" number — caps a distilled student)
  CWE recall       — how many got a finding with an acceptable CWE id
  false positives  — clean functions wrongly flagged

A teacher can be run LIVE (needs its API key) or reconstructed FROM THE LOG
(--from-log, free — scores what a model already labeled). Teachers are compared
on the COMMON set of vulnerable functions every teacher has data for, so a model
that only partially ran (e.g. Kimi before its balance ran out) is judged only on
what it actually attempted.

Targets/labels:
  * default: the fixtures  (data/vuln_fixtures + eval/labels/vuln_fixtures.truth.json)
  * or any file + eval-style labels, e.g. targets/vuln_dashboard.py

Examples:
  # free Kimi baseline from the log, on vuln_dashboard:
  python scripts/compare_teachers.py --from-log kimi=kimi-k2.7-code \
      --target targets/vuln_dashboard.py --truth eval/labels/vuln_dashboard.labels.json
  # run Muse live on the same target:
  OPENROUTER_API_KEY=... python scripts/compare_teachers.py --teacher muse=config/agentsec.muse.yaml \
      --target targets/vuln_dashboard.py --truth eval/labels/vuln_dashboard.labels.json
  python scripts/compare_teachers.py --report --truth eval/labels/vuln_dashboard.labels.json
"""

from __future__ import annotations

# ── run under the project venv, whatever `python` launched us ──────────────────
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
import json
import re
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = PROJECT_ROOT / "data" / "vuln_fixtures"
DEFAULT_TRUTH = PROJECT_ROOT / "eval" / "labels" / "vuln_fixtures.truth.json"
OUT_DIR = PROJECT_ROOT / "eval" / "teacher_compare"
LOG = PROJECT_ROOT / "logs" / "calls" / "analyze_code.jsonl"

PRICE = {  # USD per 1K tokens (prompt, completion)
    "kimi-k2.7-code": (0.00095, 0.004),
    "meta/muse-glimmer-30b": (0.0003, 0.0012),
}


def _norm(cwe):
    m = re.search(r"CWE[-_ ]?(\d+)", str(cwe or ""), re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else None


def _cwes_from_output(output):
    """Findings' CWE ids from a raw analyze_code output; None if it doesn't parse."""
    t = re.sub(r"<think>.*?</think>", "", output or "", flags=re.DOTALL).strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.MULTILINE).strip()
    for cand in (t, (re.search(r"\[.*\]", t, re.DOTALL) or [None])[0]):
        if not cand:
            continue
        try:
            arr = json.loads(cand)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(arr, list):
            return [c for c in (_norm(f.get("cwe_id")) for f in arr if isinstance(f, dict)) if c]
    return None


def _load_truth(path: Path) -> dict:
    d = json.loads(Path(path).read_text())
    if "vulnerable" in d:                         # fixtures format
        return {"vulnerable": d["vulnerable"], "clean": d.get("clean", [])}
    vuln: dict[str, list] = {}                    # eval/labels format
    for e in d.get("expected_findings", []):
        vuln.setdefault(e["function"], []).append(e["cwe_id"])
    return {"vulnerable": vuln, "clean": d.get("expected_clean", [])}


def _target_files(target: Path):
    p = Path(target)
    return sorted(p.glob("*.py")) if p.is_dir() else [p]


# ── produce a teacher's predictions ────────────────────────────────────────────

def run_teacher(name: str, config_path: str, target: Path) -> dict | None:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from agentsec.config import load_config
    from agentsec.models.registry import ModelRegistry
    from agentsec.skills import SkillContext, dispatch  # noqa: F401

    config = load_config(Path(config_path))
    logs_dir = PROJECT_ROOT / "logs" / "teacher_compare" / name
    if logs_dir.exists():
        shutil.rmtree(logs_dir)
    config.logging.dir = logs_dir
    report_path = OUT_DIR / name / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    config.fuzz = dict(config.fuzz or {})
    config.fuzz["report_path"] = str(report_path)

    ctx = SkillContext(config=config, registry=ModelRegistry(config))
    model = config.task("analyze_code").model
    print(f"[compare] {name}: live teacher = {model}")
    probe = ctx.registry.for_task("analyze_code").inner.chat(
        "Reply with a JSON array only.", "Return exactly: []")
    if not probe.success:
        print(f"[compare] {name}: teacher not answering — {probe.error}")
        return None

    predicted = {}
    files = _target_files(target)
    for i, f in enumerate(files, 1):
        print(f"[compare] {name}: ({i}/{len(files)}) {f.name}", flush=True)
        dispatch("analyze_code",
                 {"file_path": str(f), "min_severity": "INFO",
                  "progress": lambda k, t, nm: print(f"         {k}/{t} {nm}", flush=True)}, ctx)
        rep = json.loads(report_path.read_text()) if report_path.exists() else {"results": []}
        for r in rep.get("results", []):
            predicted[r["function"]] = [c for c in
                                        (_norm(fd.get("cwe_id")) for fd in r.get("findings", [])) if c]
    return {"model": model, "predicted": predicted, "no_data": [], "from_log": False,
            "metrics": _log_totals(logs_dir), "target": str(target)}


def from_log_teacher(name: str, model: str, target: Path) -> dict:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from vuln_scanner import extract_functions

    tfns = {}
    for f in _target_files(target):
        for fn in extract_functions(f):
            tfns[fn["name"]] = fn["source"]

    used = {}  # function -> (cwes, usage) from the most-recent matching log entry
    for line in LOG.read_text().splitlines() if LOG.exists() else []:
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("model") != model or not r.get("success"):
            continue
        up = r.get("user_prompt", "") or ""
        m = re.search(r"FUNCTION:\s*(\w+)", up)
        if not m or m.group(1) not in tfns:
            continue
        nm = m.group(1)
        # disambiguate same-named functions in other files by a distinctive source line
        keyline = next((ln.strip() for ln in tfns[nm].splitlines() if len(ln.strip()) > 15), "")
        if keyline and keyline not in up:
            continue
        cwes = _cwes_from_output(r.get("output", ""))
        if cwes is None:
            continue
        used[nm] = (cwes, r.get("usage") or {})    # last occurrence wins

    predicted = {nm: cwes for nm, (cwes, _u) in used.items()}
    pt = sum(int(u.get("prompt_tokens") or 0) for _c, u in used.values())
    ct = sum(int(u.get("completion_tokens") or 0) for _c, u in used.values())
    no_data = sorted(set(tfns) - set(predicted))
    print(f"[compare] {name}: from log, model={model} → {len(predicted)}/{len(tfns)} target "
          f"functions have data ({len(no_data)} never labeled)")
    return {"model": model, "predicted": predicted, "no_data": no_data, "from_log": True,
            "metrics": {"prompt_tokens": pt, "completion_tokens": ct}, "target": str(target)}


def _log_totals(logs_dir: Path) -> dict:
    pt = ct = 0
    f = logs_dir / "analyze_code.jsonl"
    if f.exists():
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            u = json.loads(line).get("usage") or {}
            pt += int(u.get("prompt_tokens") or 0)
            ct += int(u.get("completion_tokens") or 0)
    return {"prompt_tokens": pt, "completion_tokens": ct}


# ── comparison (fair: common set of vulns every teacher has data for) ───────────

def _has_data(d: dict, fn: str) -> bool:
    return (fn in d["predicted"]) if d.get("from_log") else True


def print_comparison(truth: dict):
    rows = [json.loads(p.read_text()) for p in sorted(OUT_DIR.glob("*.json")) if p.name != "report.json"]
    if not rows:
        print("[compare] no results yet — run a teacher first.")
        return
    targets = {d.get("target") for d in rows if d.get("target")}
    if len(targets) > 1:
        print(f"[compare] WARNING: saved results are for DIFFERENT targets {targets} — "
              f"not comparable. Re-run every teacher on the same --target.\n")
    vuln, clean = truth["vulnerable"], truth.get("clean", [])
    common = [fn for fn in vuln if all(_has_data(d, fn) for d in rows)]
    excluded = sorted(set(vuln) - set(common))

    cols = ["teacher", "model", "src", "detection", "cwe", "false_pos", "in_tok", "out_tok", "usd"]
    print(f"\n## Teacher comparison — {len(common)} common vulnerable fns"
          f"{f' ({len(excluded)} excluded: no data from some teacher)' if excluded else ''}, "
          f"{len(clean)} clean\n")
    print("| " + " | ".join(cols) + " |")
    print("|" + "|".join(["---"] * len(cols)) + "|")
    for d in rows:
        pred = d["predicted"]
        det = [fn for fn in common if pred.get(fn)]
        cwe = [fn for fn in common if set(pred.get(fn, [])) & set(vuln[fn])]
        fp = [fn for fn in clean if pred.get(fn)]
        n = len(common) or 1
        m = d.get("metrics", {})
        pr = PRICE.get(d.get("model", ""), (0.0, 0.0))
        usd = round(m.get("prompt_tokens", 0) / 1000 * pr[0] + m.get("completion_tokens", 0) / 1000 * pr[1], 4)
        print("| " + " | ".join(str(x) for x in [
            d["name"], d.get("model", ""), "log" if d.get("from_log") else "live",
            f"{len(det)}/{len(common)} ({round(len(det)/n, 3)})",
            f"{len(cwe)}/{len(common)} ({round(len(cwe)/n, 3)})",
            f"{len(fp)}/{len(clean)}", m.get("prompt_tokens", ""), m.get("completion_tokens", ""), usd]) + " |")
    print("\nMissed (of the common set — fewer = better):")
    for d in rows:
        miss = [fn for fn in common if not d["predicted"].get(fn)]
        print(f"  {d['name']}: {len(miss)}" + (f" — {', '.join(miss)}" if miss else " — none"))
    if excluded:
        print(f"\nExcluded (a teacher had no data): {', '.join(excluded)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Teacher-quality benchmark")
    ap.add_argument("--teacher", action="append", default=[], help="name=config_path (live run)")
    ap.add_argument("--from-log", action="append", default=[], dest="from_log",
                    help="name=MODEL (reconstruct predictions from logs/calls/analyze_code.jsonl)")
    ap.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    ap.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    ap.add_argument("--report", action="store_true", help="just print the comparison from saved results")
    args = ap.parse_args()

    truth = _load_truth(args.truth)
    if not args.report:
        jobs = [("live", s) for s in args.teacher] + [("log", s) for s in args.from_log]
        for kind, spec in jobs:
            name, _, rest = spec.partition("=")
            result = (from_log_teacher(name, rest, args.target) if kind == "log"
                      else run_teacher(name, rest, args.target))
            if result is None:
                continue
            OUT_DIR.mkdir(parents=True, exist_ok=True)
            (OUT_DIR / f"{name}.json").write_text(json.dumps({"name": name, **result}, indent=2, default=str))
    print_comparison(truth)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
