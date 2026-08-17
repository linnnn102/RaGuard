#!/usr/bin/env python3
"""make_label_stub.py — scaffold a gold-label skeleton for a held-out eval target.

Extracts every function from a Python file and writes
eval/labels/<stem>.labels.json with each function listed under `_candidates`.
You then move each candidate into `expected_findings` (adding a cwe_id) or
`expected_clean`, and delete `_candidates`. This makes hand-labeling a held-out
test set fast and consistent — no eyeballing line numbers by hand.

It NEVER overwrites an existing label file, so re-running is safe.

Usage:
    python scripts/make_label_stub.py eval/testset/orders_api.py
    python scripts/make_label_stub.py --dir eval/testset      # every .py in a dir
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
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LABELS_DIR = PROJECT_ROOT / "eval" / "labels"


def _first_body_line(source: str) -> str:
    """A representative code line for line_hint — first line that isn't the def,
    a decorator, a docstring, or a comment."""
    for ln in source.splitlines():
        s = ln.strip()
        if s and not s.startswith(("def ", "async def ", "@", '"""', "'''", "#")):
            return s[:120]
    return ""


def stub_for(target: Path) -> dict:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from vuln_scanner import extract_functions

    fns = extract_functions(target)
    rel = target.relative_to(PROJECT_ROOT) if target.is_absolute() else target
    return {
        "target": str(rel),
        "description": "TODO: one line on what this held-out target exercises",
        "_labeling": (
            "For each function in _candidates, EITHER add an entry to "
            "expected_findings (with cwe_id, cwe_name, min_severity, line_hint) "
            "OR add its bare name to expected_clean. Then delete _candidates. "
            "This target MUST stay out of the training corpus (no leakage)."
        ),
        "expected_findings": [],
        "expected_clean": [],
        "expected_dynamic_confirmation": {},
        "_candidates": [
            {"function": fn["name"], "args": fn["args"],
             "line_hint": _first_body_line(fn["source"])}
            for fn in fns
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Scaffold a gold-label skeleton")
    ap.add_argument("target", nargs="?", type=Path, help="a .py file to stub")
    ap.add_argument("--dir", type=Path, help="stub every .py under this directory")
    ap.add_argument("--out-dir", type=Path, default=LABELS_DIR)
    args = ap.parse_args()

    if args.dir:
        targets = sorted(args.dir.rglob("*.py"))
    elif args.target:
        targets = [args.target]
    else:
        ap.error("pass a target .py file or --dir")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for t in targets:
        out = args.out_dir / f"{t.stem}.labels.json"
        if out.exists():
            print(f"[stub] SKIP {out.name} (exists — won't overwrite your labels)")
            continue
        try:
            stub = stub_for(t)
        except SyntaxError as e:
            print(f"[stub] SKIP {t} (not parseable Python: {e})")
            continue
        out.write_text(json.dumps(stub, indent=2))
        print(f"[stub] wrote {out}  ({len(stub['_candidates'])} functions to label)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
