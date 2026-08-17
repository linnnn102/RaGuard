#!/usr/bin/env python3
"""build_corpus.py — S5 data: assemble a diverse corpus, run the teacher, and
report coverage vs targets. The INPUT side of the S1→S6 flywheel.

The current training set is the teacher scanning ~11 functions from the demo
targets — too few, almost no benign examples, one example per long-tail CWE.
This harness fixes that by feeding the teacher a *diverse* corpus and showing,
live, how far the resulting (curated) dataset is from the targets that make a
fine-tune worthwhile:

    ~500+ distinct functions · ~40–50% benign · ≥20 examples per core CWE.

Subcommands
-----------
  fetch    resolve data/corpus_sources.yaml into local .py files
           (`--clone` to git-clone the `git:` sources)
  scan     run the analyze_code TEACHER over the corpus, logging one S1 row per
           function to logs/calls/analyze_code.jsonl (resumable, skips done files)
  report   print coverage vs targets from the current logs (no scanning)

`scan` prints the report when it finishes. Then feed the logs forward exactly as
before — nothing downstream changes:

    python scripts/s2_curate.py
    python scripts/export_dataset.py         # → Colab (docs/finetuning_colab.md)

Coverage is computed the way S2 curates (dedup by sha256(system+user), drop
non-JSON output) so the numbers match the dataset you will actually train on.
"""

from __future__ import annotations

# ── run under the project venv, whatever `python` launched us ──────────────────
# This machine has several interpreters (FreeCAD's bundled python, the framework
# python3); only .venv has the project deps. Re-exec under it BEFORE importing
# anything heavy, so `python scripts/build_corpus.py …` can't silently run the
# wrong one and do nothing. No-op when already under .venv, or when none exists.
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
import subprocess
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = PROJECT_ROOT / "logs" / "calls" / "analyze_code.jsonl"
CORPUS_DIR = PROJECT_ROOT / "data" / "corpus"
MANIFEST = CORPUS_DIR / "manifest.json"
SCAN_STATE = CORPUS_DIR / "scan_state.json"
DEFAULT_SOURCES = PROJECT_ROOT / "data" / "corpus_sources.yaml"
CLONE_DEST = PROJECT_ROOT / "data" / "corpus_src"

# Core CWEs a Python-web vuln detector should cover, with readable names. The
# report tracks each toward --per-cwe; everything else is folded into "other".
CORE_CWES = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-502": "Insecure Deserialization",
    "CWE-918": "SSRF",
    "CWE-611": "XXE",
    "CWE-306": "Missing Authentication",
    "CWE-287": "Improper Authentication",
    "CWE-862": "Missing Authorization",
    "CWE-327": "Broken/Weak Crypto",
    "CWE-798": "Hardcoded Credentials",
    "CWE-1336": "Server-Side Template Injection",
}

# Skipped in every source regardless of include/exclude.
_SKIP_PARTS = {
    "tests", "test", "__pycache__", "migrations", ".venv", "venv",
    "node_modules", "build", "dist", "docs", ".git", "site-packages",
    "examples", "example",
}


# ── coverage (mirrors s2_curate's dedup + JSON gate) ───────────────────────────

def _strip_llm(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    return text.strip()


def _parse_findings(output: str):
    """Return the findings list if the output parses as a JSON array (the S2
    quality gate for analyze_code), else None so it's dropped from coverage."""
    t = _strip_llm(output or "")
    for candidate in (t, (re.search(r"\[.*\]", t, re.DOTALL) or [None])[0]):
        if not candidate:
            continue
        try:
            val = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(val, list):
            return val
    return None


def _norm_cwe(raw) -> str | None:
    m = re.search(r"CWE[-_ ]?(\d+)", str(raw or ""), re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else None


def compute_coverage(log_path: Path) -> dict:
    """Unique curated-equivalent rows from an analyze_code S1 log."""
    rows: dict[str, list] = {}
    if log_path.exists():
        for line in log_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not rec.get("success", False):
                continue
            findings = _parse_findings(rec.get("output", ""))
            if findings is None:
                continue
            key = hashlib.sha256(
                (rec.get("system_prompt", "") + "\x00" + rec.get("user_prompt", ""))
                .encode("utf-8")
            ).hexdigest()
            rows[key] = findings  # dedup: identical prompt collapses to one row

    cwes: Counter = Counter()
    benign = 0
    for findings in rows.values():
        if not findings:
            benign += 1
        for f in findings:
            if isinstance(f, dict):
                cid = _norm_cwe(f.get("cwe_id"))
                if cid:
                    cwes[cid] += 1
    return {"unique": len(rows), "benign": benign, "cwes": cwes}


def _bar(frac: float, width: int = 22) -> str:
    frac = max(0.0, min(1.0, frac))
    filled = int(round(frac * width))
    return "█" * filled + "░" * (width - filled)


def print_report(log_path: Path, total_target: int, per_cwe: int,
                 benign_lo: float, benign_hi: float) -> dict:
    cov = compute_coverage(log_path)
    uniq, benign, cwes = cov["unique"], cov["benign"], cov["cwes"]
    benign_frac = (benign / uniq) if uniq else 0.0

    print("\nCorpus coverage")
    print(f"  source: {log_path}")
    print("  " + "─" * 58)
    print(f"  unique functions  [{_bar(uniq / total_target)}]  "
          f"{uniq} / {total_target}  ({uniq / total_target * 100:.0f}%)")
    bmark = "ok" if benign_lo <= benign_frac <= benign_hi else "LOW" if benign_frac < benign_lo else "high"
    print(f"  benign share      [{_bar(benign_frac / benign_hi)}]  "
          f"{benign_frac * 100:.0f}%  (target {benign_lo*100:.0f}–{benign_hi*100:.0f}%)  {bmark}")

    print(f"\n  CWE coverage (target ≥{per_cwe} each):")
    under = []
    for cid, name in CORE_CWES.items():
        n = cwes.get(cid, 0)
        flag = "ok " if n >= per_cwe else "   "
        if n < per_cwe:
            under.append(cid)
        print(f"    {flag}{cid:<9} {name:<30} {n:>3} / {per_cwe}  [{_bar(n / per_cwe, 14)}]")

    other = {c: n for c, n in cwes.items() if c not in CORE_CWES}
    if other:
        top = ", ".join(f"{c}×{n}" for c, n in Counter(other).most_common(6))
        print(f"    other CWEs seen: {sum(other.values())} findings across "
              f"{len(other)} classes  ({top}{'…' if len(other) > 6 else ''})")

    # verdict
    print("\n  " + "─" * 58)
    gaps = []
    if uniq < total_target:
        gaps.append(f"~{total_target - uniq} more unique functions")
    if benign_frac < benign_lo:
        gaps.append(f"benign share {benign_frac*100:.0f}% → ≥{benign_lo*100:.0f}% "
                    f"(feed more audited/library code)")
    if under:
        gaps.append(f"{len(under)}/{len(CORE_CWES)} core CWEs under {per_cwe}: "
                    f"{', '.join(under)}")
    if gaps:
        print("  VERDICT: not ready — " + "; ".join(gaps))
    else:
        print("  VERDICT: targets met — run s2_curate.py + export_dataset.py, then fine-tune.")
    print()
    return cov


# ── fetch ──────────────────────────────────────────────────────────────────────

def _collect_py(root: Path, include, exclude, cap: int) -> list[Path]:
    include = include or []
    exclude = exclude or []
    out: list[Path] = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root).as_posix()
        if any(part in _SKIP_PARTS for part in p.relative_to(root).parts):
            continue
        if p.name in {"setup.py", "conftest.py", "__main__.py"} or \
           p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue
        if include and not any(inc.strip("*/ ") in rel for inc in include):
            continue
        if exclude and any(exc.strip("*/ ") in rel for exc in exclude):
            continue
        out.append(p)
        if len(out) >= cap:
            break
    return out


def fetch(sources_path: Path, do_clone: bool, cap: int) -> int:
    import yaml  # project dep; only fetch needs it

    spec = yaml.safe_load(sources_path.read_text()) or {}
    sources = spec.get("sources", [])
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    CLONE_DEST.mkdir(parents=True, exist_ok=True)

    manifest, by_role, skipped = [], Counter(), []
    for s in sources:
        name, role = s["name"], s["role"]
        if "local" in s:
            root = Path(s["local"])
            if not root.is_absolute():
                root = PROJECT_ROOT / root
        else:
            root = CLONE_DEST / name
            if not root.exists():
                if do_clone:
                    print(f"[fetch] cloning {name} … {s['git']}")
                    r = subprocess.run(
                        ["git", "clone", "--depth", "1", s["git"], str(root)]
                    )
                    if r.returncode != 0:
                        skipped.append(f"{name} (clone failed)")
                        continue
                else:
                    skipped.append(f"{name} (not cloned — pass --clone)")
                    continue
        if not root.exists():
            skipped.append(f"{name} (missing path {root})")
            continue

        files = _collect_py(root, s.get("include"), s.get("exclude"), cap)
        for f in files:
            manifest.append({"path": str(f), "role": role, "source": name})
        by_role[role] += len(files)
        print(f"[fetch] {name:<16} {role:<10} {len(files)} files")

    MANIFEST.write_text(json.dumps(manifest, indent=2))
    print(f"\n[fetch] wrote {MANIFEST}  ({len(manifest)} files: "
          + ", ".join(f"{n} {r}" for r, n in by_role.items()) + ")")
    if skipped:
        print("[fetch] skipped: " + "; ".join(skipped))
    if not do_clone and any("not cloned" in s for s in skipped):
        print("[fetch] re-run with --clone to fetch the git sources.")
    return 0


# ── scan ───────────────────────────────────────────────────────────────────────

def _load_manifest(corpus_dir: Path | None) -> list[dict]:
    if corpus_dir:
        # Walk a directory whose immediate subdirs name the role.
        files = []
        for role_dir in sorted(Path(corpus_dir).iterdir()):
            if role_dir.is_dir():
                role = role_dir.name
                for p in _collect_py(role_dir, None, None, cap=10**9):
                    files.append({"path": str(p), "role": role, "source": role_dir.name})
        return files
    if not MANIFEST.exists():
        print(f"[scan] no manifest at {MANIFEST}. Run `build_corpus.py fetch` "
              f"or pass --corpus-dir.", file=sys.stderr)
        return []
    return json.loads(MANIFEST.read_text())


def _save_state(state: set) -> None:
    SCAN_STATE.parent.mkdir(parents=True, exist_ok=True)
    SCAN_STATE.write_text(json.dumps(sorted(state)))


def scan(config_path, corpus_dir, limit, min_severity, role=None) -> int:
    print(f"[scan] interpreter: {sys.executable}")
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from agentsec.config import load_config
    from agentsec.models.registry import ModelRegistry
    from agentsec.skills import SkillContext, dispatch  # noqa: F401 (registers skills)

    files = _load_manifest(corpus_dir)
    if role:
        files = [f for f in files if f.get("role") == role]
        print(f"[scan] role filter: {role} → {len(files)} files")
    if not files:
        return 1

    state = set(json.loads(SCAN_STATE.read_text())) if SCAN_STATE.exists() else set()
    todo = [f for f in files if f["path"] not in state]
    if limit:
        todo = todo[:limit]
    print(f"[scan] {len(files)} files in corpus · {len(state)} already scanned · "
          f"{len(todo)} to scan this run")
    if not todo:
        print("[scan] nothing new — showing coverage.")
        print_report(DEFAULT_LOG, args_total, args_per_cwe, BENIGN_LO, BENIGN_HI)
        return 0

    config = load_config(Path(config_path) if config_path else None)
    ctx = SkillContext(config=config, registry=ModelRegistry(config))

    # ── preflight: fail LOUD before churning through the whole corpus ──────────
    # The first run silently marked 259 files "done" with zero model calls
    # because the RAG KB threw under the wrong interpreter. Prove Ollama is up
    # and the KB loads *now*, so a broken environment stops at file 0 — visibly.
    from agentsec.cli import _check_ollama
    if not _check_ollama(config):
        return 3
    try:
        ctx.kb()  # force the RAG KB to load now, not silently per file
    except Exception as e:  # noqa: BLE001
        print(f"\n[scan] FATAL: the RAG knowledge base failed to load — "
              f"{type(e).__name__}: {e}")
        print("[scan] nothing was scanned. Usual causes: the wrong Python (see the "
              "interpreter line above — it must be your .venv), or a missing "
              "data/kb file.")
        return 4

    # Probe the teacher once (unlogged, so it never pollutes training data). A
    # failure here means the model isn't actually available — a local model not
    # pulled (the /api/chat 404 storm), or a bad cloud endpoint/key. The skill
    # swallows per-call failures and still returns status=ok, so without this
    # probe a whole corpus would scan "successfully" while every call 404s.
    teacher_route = config.task("analyze_code")
    teacher = teacher_route.model
    probe = ctx.registry.for_task("analyze_code").inner.chat(
        "Reply with a JSON array only.", "Return exactly: []")
    if not probe.success:
        print(f"\n[scan] FATAL: teacher model '{teacher}' is not answering — {probe.error}")
        if teacher_route.backend == "ollama":
            print(f"[scan] it's a local Ollama model — pull it first:  ollama pull {teacher}")
        else:
            print("[scan] it's a cloud model — check your account balance/quota and the "
                  "task's base_url / api_key in the config.")
        return 5
    print(f"[scan] teacher OK: {teacher}")
    interval = (teacher_route.options or {}).get("min_request_interval_s")
    if interval:
        print(f"[scan] teacher throttled to ~1 call / {interval}s (RPM limit) — progress is "
              f"slow and steady by design; safe to leave running overnight.", flush=True)

    done_this_run = failed = consec_dead = 0
    for i, f in enumerate(todo, 1):
        path = f["path"]
        if not Path(path).exists():
            print(f"[scan] ({i}/{len(todo)}) skip (missing) {path}")
            state.add(path)          # a vanished file is 'complete' — don't retry forever
            _save_state(state)
            continue
        # Header prints immediately so a function-dense file (dozens of sequential
        # teacher calls) shows activity right away instead of sitting silent.
        print(f"[scan] ({i}/{len(todo)}) {f['role']:<10} {path}", flush=True)

        def _tick(k, total, name):
            print(f"         {k}/{total} {name}", flush=True)  # live per-function progress

        try:
            result = dispatch("analyze_code",
                              {"file_path": path, "min_severity": min_severity,
                               "progress": _tick}, ctx)
        except Exception as e:  # noqa: BLE001 — one bad file must not kill the run
            print(f"         → ERROR {type(e).__name__}: {e}  (NOT marked done — retries next run)",
                  flush=True)
            failed += 1
            continue
        status = result.get("status")
        fns = result.get("functions_scanned", 0) or 0
        calls_ok = result.get("calls_ok", 0)
        calls_failed = result.get("calls_failed", 0)
        n = len(result.get("findings", []) or [])
        # A file is DONE only when the teacher labeled EVERY function (or there
        # were none). If ANY call failed — e.g. a rate-limited call — leave the
        # file un-done so a resume re-labels the missed functions instead of
        # silently dropping them. (An earlier bug marked a file done on ≥1 success,
        # which quietly lost every rate-limited function.)
        if status == "ok" and (fns == 0 or calls_failed == 0):
            detail = "no functions" if fns == 0 else f"{calls_ok}/{fns} ok · {n} findings"
            print(f"         → {detail}", flush=True)
            state.add(path)
            _save_state(state)
            done_this_run += 1
            consec_dead = 0
        elif status == "ok" and calls_ok > 0:
            print(f"         → PARTIAL {calls_ok}/{fns} ok · {calls_failed} call-fail "
                  f"— NOT marked done, retries next run", flush=True)
            failed += 1
            consec_dead = 0          # teacher is alive (some calls landed)
        else:
            reason = (result.get("message")
                      or (f"all {calls_failed} calls failed" if calls_failed else status))
            print(f"         → FAILED: {reason} — NOT marked done, retries next run", flush=True)
            failed += 1
            # Every teacher call on this file failed — count it. A run of these
            # means the teacher is exhausted (daily cap) or down; stop rather than
            # waste the throttle interval on every remaining file all night.
            if status == "ok" and calls_ok == 0 and calls_failed > 0:
                consec_dead += 1
                if consec_dead >= 3:
                    print("\n[scan] teacher failed every call on 3 files in a row — likely the "
                          "daily token cap (TPD) is exhausted or the teacher is down. Stopping. "
                          "Nothing is lost; resume later and un-done files pick up where they left off.",
                          flush=True)
                    break
            else:
                consec_dead = 0      # a syntax error etc. isn't the teacher's fault

    print(f"\n[scan] done {done_this_run} · failed {failed}  "
          f"(failed files are NOT marked complete — just re-run to retry them)")
    print_report(DEFAULT_LOG, args_total, args_per_cwe, BENIGN_LO, BENIGN_HI)
    return 0


# ── cli ────────────────────────────────────────────────────────────────────────

BENIGN_LO, BENIGN_HI = 0.40, 0.50
args_total, args_per_cwe = 500, 20  # module-level so scan() can reach the targets


def main(argv=None) -> int:
    global args_total, args_per_cwe, BENIGN_LO, BENIGN_HI
    p = argparse.ArgumentParser(prog="build_corpus", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("fetch", help="resolve corpus_sources.yaml → local .py files")
    pf.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    pf.add_argument("--clone", action="store_true", help="git-clone the git: sources")
    pf.add_argument("--max-per-source", type=int, default=200,
                    help="cap files taken per source (keeps one big repo from dominating)")

    ps = sub.add_parser("scan", help="run the teacher over the corpus (resumable)")
    ps.add_argument("--config", default=None, help="agentsec.yaml (else AGENTSEC_CONFIG/default)")
    ps.add_argument("--corpus-dir", default=None,
                    help="scan a dir whose subdirs are roles, instead of the fetch manifest")
    ps.add_argument("--limit", type=int, default=None, help="max files this run")
    ps.add_argument("--role", choices=["vulnerable", "benign"], default=None,
                    help="label only files of this role (e.g. --role vulnerable to skip "
                         "the benign backlog and label just new vuln fixtures)")
    ps.add_argument("--min-severity", default="INFO",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    for q in (ps, sub.add_parser("report", help="coverage vs targets (no scanning)")):
        q.add_argument("--log", type=Path, default=DEFAULT_LOG)
        q.add_argument("--target-total", type=int, default=500)
        q.add_argument("--per-cwe", type=int, default=20)
        q.add_argument("--benign-frac", type=float, default=0.45,
                       help="midpoint of the benign target band (±5%)")

    args = p.parse_args(argv)

    if hasattr(args, "target_total"):
        args_total, args_per_cwe = args.target_total, args.per_cwe
        BENIGN_LO, BENIGN_HI = max(0.0, args.benign_frac - 0.05), args.benign_frac + 0.05

    if args.cmd == "fetch":
        return fetch(args.sources, args.clone, args.max_per_source)
    if args.cmd == "report":
        print_report(args.log, args_total, args_per_cwe, BENIGN_LO, BENIGN_HI)
        return 0
    if args.cmd == "scan":
        return scan(args.config, args.corpus_dir, args.limit, args.min_severity, args.role)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
