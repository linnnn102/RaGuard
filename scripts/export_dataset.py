#!/usr/bin/env python3
"""export_dataset.py — S5 (repo half): export a chat-format fine-tune dataset.

Converts data/train/<task>.curated.jsonl (from S2) into the
``{"messages":[system,user,assistant]}`` chat format QLoRA/LoRA trainers expect,
with a deterministic 90/10 train/val split. The resulting files are uploaded to
Colab where the GPU training (S5) actually runs; the returned adapter comes back
via register_adapter.py.

Outputs per task under data/export/<task>/:
    train.jsonl  val.jsonl  meta.json

Usage:
    python scripts/export_dataset.py [--task analyze_code] [--val-frac 0.1]
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
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TASKS = ["analyze_code", "select_wordlists", "suggest_mitigations"]


def _strip_llm(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.DOTALL).strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE)
    return text.strip()


def _is_benign(row: dict) -> bool:
    """An analyze_code row whose assistant output is an empty findings array is a
    clean/benign example. Unparseable output is treated as non-benign (kept)."""
    t = _strip_llm(row.get("assistant", ""))
    for cand in (t, (re.search(r"\[.*\]", t, re.DOTALL) or [None])[0]):
        if not cand:
            continue
        try:
            arr = json.loads(cand)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(arr, list):
            return len(arr) == 0
    return False


def _select_key(row: dict) -> int:
    """Deterministic ranking for the benign down-sample. SALTED so it does NOT
    correlate with _split_key — otherwise the kept benign would all share the
    same split bucket and skew the train/val ratio."""
    h = hashlib.sha256(("benign-select\x00" + row.get("user", "")).encode("utf-8")).hexdigest()
    return int(h[:8], 16)


def _downsample_benign(rows: list, max_frac: float):
    """Drop benign rows deterministically until benign share <= max_frac. Keeps
    every vulnerable row; picks which benign to keep by a salted hash (stable,
    and independent of the train/val split)."""
    if not (0.0 <= max_frac < 1.0):
        return rows, {}
    benign = [r for r in rows if _is_benign(r)]
    vuln = [r for r in rows if not _is_benign(r)]
    b, v = len(benign), len(vuln)
    total = b + v
    if total == 0 or b / total <= max_frac:
        keep = b
    else:
        keep = min(b, int(round(max_frac * v / (1.0 - max_frac))))
    kept = sorted(benign, key=_select_key)[:keep]
    denom = v + keep
    return vuln + kept, {
        "benign_before": b, "benign_kept": keep, "benign_dropped": b - keep,
        "benign_frac_after": round(keep / denom, 3) if denom else 0.0,
    }


def _to_chat(row: dict) -> dict:
    return {"messages": [
        {"role": "system", "content": row.get("system", "")},
        {"role": "user", "content": row.get("user", "")},
        {"role": "assistant", "content": row.get("assistant", "")},
    ]}


def _split_key(row: dict) -> float:
    """Deterministic [0,1) bucket from the user prompt — stable across runs, no
    RNG (so the same example always lands in the same split)."""
    h = hashlib.sha256(row.get("user", "").encode("utf-8")).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


def export_task(task: str, train_dir: Path, out_dir: Path, val_frac: float,
                max_benign_frac: float | None = None) -> dict:
    src = train_dir / f"{task}.curated.jsonl"
    if not src.exists():
        return {"task": task, "note": f"no curated file at {src}"}

    rows = [json.loads(l) for l in src.read_text().splitlines() if l.strip()]

    # Benign down-sample only makes sense for analyze_code (its empty-findings
    # rows are the benign class). Other tasks have no such distinction.
    benign_note = {}
    if max_benign_frac is not None and task == "analyze_code":
        rows, benign_note = _downsample_benign(rows, max_benign_frac)

    train, val = [], []
    for row in rows:
        (val if _split_key(row) < val_frac else train).append(_to_chat(row))

    dest = out_dir / task
    dest.mkdir(parents=True, exist_ok=True)
    for name, data in (("train.jsonl", train), ("val.jsonl", val)):
        with (dest / name).open("w", encoding="utf-8") as f:
            for r in data:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    meta = {"task": task, "n_total": len(rows), "n_train": len(train),
            "n_val": len(val), "val_frac": val_frac, "format": "chat-messages",
            **benign_note}
    (dest / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def main():
    p = argparse.ArgumentParser(description="S5 dataset export (chat format, 90/10 split)")
    p.add_argument("--train-dir", type=Path, default=PROJECT_ROOT / "data/train")
    p.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "data/export")
    p.add_argument("--val-frac", type=float, default=0.1)
    p.add_argument("--max-benign-frac", type=float, default=None,
                   help="Cap the benign (empty-findings) share of analyze_code by "
                        "dropping extras deterministically, e.g. 0.45. Default: keep all.")
    p.add_argument("--task", action="append", dest="tasks", choices=TASKS)
    args = p.parse_args()

    for task in (args.tasks or TASKS):
        meta = export_task(task, args.train_dir, args.out_dir, args.val_frac,
                           args.max_benign_frac)
        print(f"[export] {task}: {meta}")


if __name__ == "__main__":
    main()
