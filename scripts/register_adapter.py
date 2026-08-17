#!/usr/bin/env python3
"""register_adapter.py — S5 (repo half): serve a Colab-trained adapter in Ollama.

After Colab returns a LoRA/GGUF adapter, drop it at
``adapters/<task>/vN/adapter.gguf`` with a ``Modelfile``:

    FROM qwen3:4b
    ADAPTER ./adapter.gguf

This script runs ``ollama create qwen3-<task>-vN -f <Modelfile>`` so the tag
becomes routable. Wiring it in is then a one-line config edit: set that task's
``model:`` in agentsec.yaml to the new tag — the registry routes to it with zero
code change (S6). ``--print-modelfile`` scaffolds a Modelfile if none exists.

Usage:
    python scripts/register_adapter.py --task analyze_code --version v2
    python scripts/register_adapter.py --task analyze_code --version v2 --print-modelfile --base qwen3:4b
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
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def adapter_dir(task: str, version: str) -> Path:
    return PROJECT_ROOT / "adapters" / task / version


def scaffold_modelfile(task: str, version: str, base: str) -> Path:
    d = adapter_dir(task, version)
    d.mkdir(parents=True, exist_ok=True)
    mf = d / "Modelfile"
    mf.write_text(f"FROM {base}\nADAPTER ./adapter.gguf\n")
    print(f"[register] wrote {mf}\n  (place the Colab adapter.gguf next to it)")
    return mf


def register(task: str, version: str) -> int:
    d = adapter_dir(task, version)
    mf = d / "Modelfile"
    if not mf.exists():
        print(f"[ERROR] No Modelfile at {mf}. Run with --print-modelfile first.", file=sys.stderr)
        return 1
    if not (d / "adapter.gguf").exists():
        print(f"[WARN] {d/'adapter.gguf'} missing — ollama create will fail until "
              "you copy the Colab adapter there.", file=sys.stderr)
    tag = f"qwen3-{task.replace('_', '-')}-{version}"
    cmd = ["ollama", "create", tag, "-f", str(mf)]
    print(f"[register] $ {' '.join(cmd)}  (cwd={d})")
    proc = subprocess.run(cmd, cwd=str(d))
    if proc.returncode == 0:
        print(f"[register] created tag: {tag}\n"
              f"           now set tasks.{task}.model: {tag} in config/agentsec.yaml")
    return proc.returncode


def main():
    p = argparse.ArgumentParser(description="Register a Colab-trained adapter with Ollama")
    p.add_argument("--task", required=True)
    p.add_argument("--version", required=True, help="e.g. v2")
    p.add_argument("--base", default="qwen3:4b", help="Base model for the Modelfile FROM")
    p.add_argument("--print-modelfile", action="store_true",
                   help="Scaffold a Modelfile then exit (don't call ollama create)")
    args = p.parse_args()

    if args.print_modelfile:
        scaffold_modelfile(args.task, args.version, args.base)
        return 0
    return register(args.task, args.version)


if __name__ == "__main__":
    raise SystemExit(main())
