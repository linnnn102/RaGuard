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

import argparse
import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TASKS = ["analyze_code", "select_wordlists", "suggest_mitigations"]


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


def export_task(task: str, train_dir: Path, out_dir: Path, val_frac: float) -> dict:
    src = train_dir / f"{task}.curated.jsonl"
    if not src.exists():
        return {"task": task, "note": f"no curated file at {src}"}

    rows = [json.loads(l) for l in src.read_text().splitlines() if l.strip()]
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
            "n_val": len(val), "val_frac": val_frac, "format": "chat-messages"}
    (dest / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def main():
    p = argparse.ArgumentParser(description="S5 dataset export (chat format, 90/10 split)")
    p.add_argument("--train-dir", type=Path, default=PROJECT_ROOT / "data/train")
    p.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "data/export")
    p.add_argument("--val-frac", type=float, default=0.1)
    p.add_argument("--task", action="append", dest="tasks", choices=TASKS)
    args = p.parse_args()

    for task in (args.tasks or TASKS):
        meta = export_task(task, args.train_dir, args.out_dir, args.val_frac)
        print(f"[export] {task}: {meta}")


if __name__ == "__main__":
    main()
