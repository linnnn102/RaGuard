"""fuzz.py — deterministic fuzz skill (loop-closing).

Wraps the reused ``generate_fuzz_script`` + ``parse_fuzz_results`` modules:
  1. generate ``fuzz.sh`` from the analyze report (T2 selects wordlists inside),
  2. optionally execute it in the Docker ``vuln-fuzzer`` image,
  3. parse the ffuf output and **return the hits**.

Returning parsed hits is what finally closes the loop the MCP version left open:
``suggest_mitigations`` consumes them to mark findings dynamically confirmed and
``full_report["fuzzing"]`` gets populated.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .base import Skill, SkillContext, register


def _abs(config, value: str) -> Path:
    from ..config import PROJECT_ROOT
    p = Path(value)
    return p if p.is_absolute() else PROJECT_ROOT / p


TARGET_CONTAINER = "raguard-target"

# The path fuzz.sh writes ffuf JSON to. It is a container-internal path baked
# into the generated script, so the runner must have the results dir mounted
# there for the in-process path to work.
RESULTS_MOUNT = Path("/results")

# Where SecLists lives inside both the runner and the standalone fuzzer image.
SECLISTS_DIR = Path("/SecLists")


def _ffuf_available() -> bool:
    """True when we can run fuzz.sh directly instead of spawning a container.

    Both conditions matter: ffuf on PATH is not enough if the SecLists corpus
    the generated script references isn't mounted at the expected path.
    """
    return shutil.which("ffuf") is not None and SECLISTS_DIR.is_dir()


def _target_state(container: str = TARGET_CONTAINER) -> dict | None:
    """Snapshot the target container's liveness, or None if it isn't inspectable.

    Returns running/OOMKilled/exit-code/restart-count.
    """
    fmt = "{{.State.Running}},{{.State.OOMKilled}},{{.State.ExitCode}},{{.RestartCount}}"
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", fmt, container],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    parts = proc.stdout.strip().split(",")
    if len(parts) != 4:
        return None
    return {
        "running": parts[0] == "true",
        "oom_killed": parts[1] == "true",
        "exit_code": int(parts[2]) if parts[2].lstrip("-").isdigit() else None,
        "restart_count": int(parts[3]) if parts[3].isdigit() else 0,
    }


def _describe_target_failure(before: dict | None, after: dict | None) -> str | None:
    """Flag a target that died or restarted mid-fuzz — this INVALIDATES results.

    A fuzz run is only meaningful against a live target. If the target is
    OOM-killed or restarts partway through, every ffuf job after that point
    records connection errors rather than responses, so the run silently
    UNDER-reports hits and a genuine vulnerability looks unconfirmed. That is a
    false negative in the report, so it must be surfaced, not swallowed.

    The realistic cause is not an attack: the targets run Flask with
    ``debug=True`` (CWE-489, an intentional finding), and Werkzeug's debugger
    retains a traceback for every 500 response so its interactive console can
    reopen them. Fuzzing produces a 500 on most payloads, so target memory grows
    roughly linearly with the number of hits and can reach the container's
    mem_limit on a long run.
    """
    if after is None:
        return None if before is None else (
            f"the {TARGET_CONTAINER} container disappeared during fuzzing; "
            "results may be incomplete."
        )
    if not after["running"]:
        reason = "was OOM-killed (hit its mem_limit)" if after["oom_killed"] else (
            f"exited with code {after['exit_code']}"
        )
        return (
            f"the target container {reason} during fuzzing and is no longer "
            "running. Jobs after that point could not reach it, so hits are "
            "under-reported. Restart it (`scripts/target.sh up`) and re-run; if "
            "it was OOM-killed, raise `mem_limit` in docker-compose.yml."
        )
    if before is not None and after["restart_count"] > before["restart_count"]:
        return (
            "the target container restarted during fuzzing "
            f"({before['restart_count']} -> {after['restart_count']}); hits from "
            "jobs that ran while it was down are missing."
        )
    return None


def _docker_hardening_flags() -> list[str]:
    """Runtime confinement flags for the ffuf job container.

    Mirrors the target's posture in docker-compose.yml, per the OWASP Docker
    Security Cheat Sheet: rootless, no capabilities, no privilege escalation,
    immutable root filesystem, and CPU/memory/PID ceilings so a runaway fuzz
    job cannot exhaust the host.

    The user is the *host's* uid:gid rather than a fixed image UID, because
    /results is a bind mount — a fixed UID could not write into the host-owned
    output directory on native-Linux Docker. Falls back to a high unprivileged
    UID if the pipeline is (inadvisably) being run as root.
    """
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        uid = gid = 10001

    return [
        "--user", f"{uid}:{gid}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        # ffuf writes only to the /results bind mount, so the image itself can
        # stay immutable; /tmp is a noexec tmpfs for any scratch space.
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        # ffuf opens $HOME/.config/ffuf/scraper at startup. Running as a uid with
        # no passwd entry leaves HOME unset (-> "/"), which fails hard against a
        # read-only rootfs; point it at the tmpfs instead.
        "--env", "HOME=/tmp",
        "--cpus", "2",
        "--memory", "1g",
        "--pids-limit", "512",
    ]


def run_fuzz(
    ctx: SkillContext,
    report_path: str | None = None,
    target_url: str | None = None,
    execute: bool = False,
) -> dict:
    from generate_fuzz_script import generate_fuzz_script
    from parse_fuzz_results import parse_fuzz_results
    from ..config import PROJECT_ROOT

    fuzz_cfg = ctx.config.fuzz or {}
    report = _abs(ctx.config, report_path or "results/reports/vuln_report.json")
    target_url = target_url or fuzz_cfg.get(
        "target_url", "http://host.docker.internal:5055/user/FUZZ"
    )
    script_path = PROJECT_ROOT / "results/scripts/fuzz.sh"
    catalog_path = fuzz_cfg.get("catalog")

    if not report.exists():
        return {"status": "error", "message": f"Analyze report not found: {report}. Run analyze_code first."}

    # Auto-calibration makes a "hit" mean the response measurably differed from
    # the baseline (an actual injection), not just "returned 200". With it on we
    # match all status codes and let ffuf's calibration filter out the noise.
    autocalibrate = bool(fuzz_cfg.get("autocalibrate", True))
    match_codes = "all" if autocalibrate else str(fuzz_cfg.get("match_codes", "200"))

    # T2 wordlist selection happens inside generate_fuzz_script via the reused
    # selector; route its model to the configured specialist tag.
    route = ctx.config.task("select_wordlists")
    generate_fuzz_script(
        report_path=report,
        target_url=target_url,
        output_path=script_path,
        match_codes=match_codes,
        max_wordlists=int(fuzz_cfg.get("max_wordlists", 2)),
        url_encode=True,
        use_llm=True,
        model=route.model,
        catalog_path=_abs(ctx.config, catalog_path) if catalog_path else None,
        quiet=True,
        autocalibrate=autocalibrate,
    )

    out = {
        "status": "ok",
        "script_path": str(script_path),
        "executed": False,
        "hits": [],
        "total_hits": 0,
    }

    if not execute:
        out["message"] = "fuzz.sh generated; not executed (execute=false)."
        return out

    fuzz_out_dir = PROJECT_ROOT / "results/fuzz"
    fuzz_out_dir.mkdir(parents=True, exist_ok=True)

    # Two ways to run the same fuzz.sh, picked automatically:
    #
    #   • IN-PROCESS — we are already inside the `runner` container that
    #     docker compose starts, so ffuf and /SecLists are right here. No nested
    #     Docker, and therefore no Docker socket mount (which would hand the
    #     container effective root on the host and undo the target hardening).
    #   • SPAWN — running from the host, where ffuf usually isn't installed, so
    #     shell out to the standalone `vuln-fuzzer` image as before.
    #
    # fuzz.sh is identical either way: its /SecLists and /results paths are the
    # container contract, and the runner satisfies both.
    in_container = _ffuf_available()
    if in_container:
        cmd = ["bash", str(script_path)]
        if not RESULTS_MOUNT.is_dir():
            return {
                **out,
                "status": "error",
                "message": (
                    f"ffuf is available but {RESULTS_MOUNT} is missing. The runner "
                    "container must mount the results directory there "
                    "(see docker-compose.yml)."
                ),
            }
    else:
        cmd = [
            "docker", "run", "--rm",
            # Mount the script read-only: the container never needs to rewrite it.
            "-v", f"{script_path}:/fuzz/fuzz.sh:ro",
            "-v", f"{fuzz_out_dir}:/results",
            "--add-host=host.docker.internal:host-gateway",
            # ── hardening (OWASP Docker Security Cheat Sheet) ──────────────
            # Same posture as the target container in docker-compose.yml. This
            # one is a short-lived job, but it still mounts host paths, so it
            # gets the same treatment.
            *_docker_hardening_flags(),
            "vuln-fuzzer", "bash", "/fuzz/fuzz.sh",
        ]

    # Snapshot the target BEFORE fuzzing so we can tell afterwards whether it
    # survived. See _target_state() for why this matters to result validity.
    before = _target_state()

    print(f"[fuzz] executing {'in-process (runner)' if in_container else 'via vuln-fuzzer container'}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out["executed"] = True
    out["execution_mode"] = "in_process" if in_container else "spawned_container"
    out["docker_returncode"] = proc.returncode

    after = _target_state()
    warning = _describe_target_failure(before, after)
    if warning:
        out["target_health"] = warning
        out["status"] = "degraded"
        print(f"[fuzz] WARNING: {warning}", file=sys.stderr)

    # fuzz.sh keeps going past a failed job and reports the count on stderr.
    # Surface it: those CWEs were never tested, so their absence from the hits
    # is "not measured", not "not vulnerable".
    failed = [ln for ln in (proc.stderr or "").splitlines() if "job(s) FAILED" in ln]
    if failed:
        out["failed_jobs"] = failed[-1].replace("[fuzz] ", "").strip()
        out["status"] = "degraded"
        print(f"[fuzz] WARNING: {out['failed_jobs']}", file=sys.stderr)

    if proc.returncode != 0:
        out["status"] = "error"
        out["message"] = f"Docker fuzz run failed: {proc.stderr[-2000:]}"
        return out

    fuzz_report_path = PROJECT_ROOT / "results/reports/fuzz_report.json"
    # None → count every recorded result (ffuf's -ac already removed the baseline
    # noise). Only fall back to status-code filtering when calibration is off.
    parse_codes = None if autocalibrate else {
        int(c.strip()) for c in str(fuzz_cfg.get("match_codes", "200")).split(",")
    }
    report_data = parse_fuzz_results(
        results_dir=fuzz_out_dir,
        output_path=fuzz_report_path,
        match_codes=parse_codes,
    )
    out["fuzz_report_path"] = str(fuzz_report_path)
    out["hits"] = report_data.get("jobs", [])
    out["total_hits"] = report_data.get("total_hits", 0)
    return out


register(Skill(
    name="run_fuzz",
    description=(
        "Generate an ffuf fuzz script from the analyze report (auto-selecting "
        "wordlists per finding) and optionally execute it in Docker, returning "
        "the confirmed hits. Run after analyze_code."
    ),
    parameters={
        "type": "object",
        "properties": {
            "report_path": {"type": "string", "description": "Path to vuln_report.json."},
            "target_url": {"type": "string", "description": "ffuf target URL containing FUZZ."},
            "execute": {"type": "boolean", "description": "Run the script in Docker (default false)."},
        },
    },
    handler=run_fuzz,
))
