#!/usr/bin/env python3
"""
build_seclists_catalog.py — Generate data/seclists_catalog.txt
==============================================================
The SecLists selector (src/seclist_selector.py) shows a language model a
catalog of the wordlist files available in the SecLists repo and asks it to
pick the ones relevant to a given vulnerability. This script (re)builds that
catalog.

Two sources:
  * --from-github  (default) — pull the repo file tree from the GitHub API.
                   No clone needed; only the file paths are downloaded.
  * --from-dir DIR — enumerate a local SecLists checkout instead (e.g. the
                   one baked into the Docker image, or a local clone).

The catalog is intentionally pruned to keep it small enough to fit comfortably
in an LLM prompt: the whole Fuzzing/ tree (minus the ~4.5k User-Agents files,
which are irrelevant to injection fuzzing) plus a curated slice of
Discovery/Web-Content (common, raft, api lists). Paths are stored relative to
the SecLists root, exactly as ffuf consumes them (/SecLists/<path> in Docker).

Usage:
    python tools/build_seclists_catalog.py
    python tools/build_seclists_catalog.py --from-dir /SecLists
    python tools/build_seclists_catalog.py --out data/seclists_catalog.txt
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "data" / "seclists_catalog.txt"

GITHUB_TREE_URL = (
    "https://api.github.com/repos/danielmiessler/SecLists/"
    "git/trees/master?recursive=1"
)

# Discovery/Web-Content is huge; keep only the lists useful for endpoint and
# content discovery fuzzing.
_DISCOVERY_KEEP = (
    "common.txt",
    "raft-",
    "/api/",
    "directory-list-2.3-small",
    "quickhits",
)


def _keep(path: str) -> bool:
    if not path.endswith(".txt"):
        return False
    if path.startswith("Fuzzing/"):
        # User-Agents is ~4.5k files of browser UA strings — not fuzz payloads.
        return not path.startswith("Fuzzing/User-Agents/")
    if path.startswith("Discovery/Web-Content/"):
        low = path.lower()
        return any(k in low for k in _DISCOVERY_KEEP)
    return False


def _fetch_tree() -> dict:
    """Fetch the SecLists git tree JSON, falling back to curl if urllib's TLS
    trust store is unavailable (common on macOS Python builds)."""
    req = urllib.request.Request(GITHUB_TREE_URL, headers={"User-Agent": "seclists-catalog"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001 — fall back to curl on any TLS/URL error
        if not shutil.which("curl"):
            raise
        print(f"[catalog] urllib failed ({exc}); falling back to curl.", file=sys.stderr)
        out = subprocess.run(
            ["curl", "-sSL", "--max-time", "60", GITHUB_TREE_URL],
            capture_output=True, text=True, check=True,
        )
        return json.loads(out.stdout)


def from_github() -> list[str]:
    data = _fetch_tree()
    if data.get("truncated"):
        print("[WARN] GitHub tree response was truncated; catalog may be incomplete.",
              file=sys.stderr)
    return [t["path"] for t in data.get("tree", [])
            if t.get("type") == "blob" and _keep(t["path"])]


def from_dir(root: Path) -> list[str]:
    if not root.exists():
        sys.exit(f"[ERROR] SecLists directory not found: {root}")
    out = []
    for f in root.rglob("*.txt"):
        rel = f.relative_to(root).as_posix()
        if _keep(rel):
            out.append(rel)
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Build the SecLists catalog for the LLM selector")
    p.add_argument("--from-dir", type=Path, default=None,
                   help="Enumerate a local SecLists checkout instead of GitHub")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT,
                   help=f"Output catalog path (default: {DEFAULT_OUT})")
    args = p.parse_args()

    paths = from_dir(args.from_dir) if args.from_dir else from_github()
    paths = sorted(set(paths))

    if not paths:
        sys.exit("[ERROR] No wordlist paths collected — catalog would be empty.")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(paths) + "\n")
    print(f"[catalog] Wrote {len(paths)} wordlist paths → {args.out}")


if __name__ == "__main__":
    main()
