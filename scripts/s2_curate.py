#!/usr/bin/env python3
"""s2_curate.py — S2: curate raw S1 call logs into training candidates.

Reads logs/calls/<task>.jsonl (produced by the S1 LoggingModelClient) and, per
task, applies:
  * drop success=false / empty output
  * a task-specific quality gate:
      - analyze_code / suggest_mitigations: output must parse as JSON (array/obj)
      - select_wordlists: output must be a JSON array of strings
  * PII / secret scrub over prompts + output (emails, IPv4, sk-/hf_/bearer
    tokens, home paths) — code is preserved
  * dedupe by sha256(system + user)

Writes data/train/<task>.curated.jsonl and prints per-task drop-reason stats.

Dependency-light on purpose (stdlib only) so it runs anywhere the logs do.

Usage:
    python scripts/s2_curate.py [--logs-dir logs/calls] [--out-dir data/train]
                                [--task analyze_code ...]
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
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TASKS = ["analyze_code", "select_wordlists", "suggest_mitigations"]

# ── scrub patterns (applied to prompts + output; code structure preserved) ─────
_SCRUB = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<EMAIL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "<SECRET>"),
    (re.compile(r"\bhf_[A-Za-z0-9]{16,}\b"), "<SECRET>"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]+\b"), "Bearer <SECRET>"),
    (re.compile(r"/Users/[^/\s]+"), "/Users/<USER>"),
    (re.compile(r"/home/[^/\s]+"), "/home/<USER>"),
]


def scrub(text: str) -> str:
    if not text:
        return text
    for pat, repl in _SCRUB:
        text = pat.sub(repl, text)
    return text


def _strip_llm(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    return text.strip()


def _parses_json(text: str, kind: str) -> bool:
    """kind: 'array' | 'object' | 'string_array'."""
    t = _strip_llm(text)
    for candidate in (t, (re.search(r"[\[{].*[\]}]", t, re.DOTALL) or [None])[0] if re.search(r"[\[{].*[\]}]", t, re.DOTALL) else None):
        if candidate is None:
            continue
        try:
            val = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if kind == "array" and isinstance(val, list):
            return True
        if kind == "object" and isinstance(val, dict):
            return True
        if kind == "string_array" and isinstance(val, list) and all(isinstance(x, str) for x in val):
            return True
    return False


def _quality_ok(task: str, output: str) -> bool:
    if task == "select_wordlists":
        return _parses_json(output, "string_array")
    if task == "suggest_mitigations":
        return _parses_json(output, "object")
    # analyze_code
    return _parses_json(output, "array")


def curate_task(task: str, logs_dir: Path, out_dir: Path) -> dict:
    src = logs_dir / f"{task}.jsonl"
    stats = Counter()
    if not src.exists():
        return {"task": task, "kept": 0, "note": f"no log at {src}"}

    seen: set[str] = set()
    kept = []
    for line in src.read_text().splitlines():
        if not line.strip():
            continue
        stats["total"] += 1
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            stats["bad_json_line"] += 1
            continue
        if not rec.get("success", False):
            stats["drop_failed"] += 1
            continue
        output = rec.get("output", "") or ""
        if not output.strip():
            stats["drop_empty"] += 1
            continue
        if not _quality_ok(task, output):
            stats["drop_quality"] += 1
            continue

        system = scrub(rec.get("system_prompt", "") or "")
        user = scrub(rec.get("user_prompt", "") or "")
        out = scrub(output)

        key = hashlib.sha256((system + "\x00" + user).encode("utf-8")).hexdigest()
        if key in seen:
            stats["drop_dup"] += 1
            continue
        seen.add(key)

        kept.append({"system": system, "user": user, "assistant": out})
        stats["kept"] += 1

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{task}.curated.jsonl"
    with out_path.open("w", encoding="utf-8") as f:
        for row in kept:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return {"task": task, "out": str(out_path), **dict(stats)}


def main():
    p = argparse.ArgumentParser(description="S2 curation of S1 call logs")
    p.add_argument("--logs-dir", type=Path, default=PROJECT_ROOT / "logs/calls")
    p.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "data/train")
    p.add_argument("--task", action="append", dest="tasks", choices=TASKS,
                   help="Curate only these tasks (repeatable). Default: all.")
    args = p.parse_args()

    tasks = args.tasks or TASKS
    print(f"[s2] logs: {args.logs_dir}  ->  out: {args.out_dir}\n")
    for task in tasks:
        report = curate_task(task, args.logs_dir, args.out_dir)
        print(f"[{task}]")
        for k, v in report.items():
            if k != "task":
                print(f"    {k}: {v}")
        print()


if __name__ == "__main__":
    main()
