# RaGuard — Thesis Defense Demo Runbook

A rehearsed, ~8-minute live demo that maps every beat to a thesis claim, with
fallbacks so nothing on stage depends on model latency or a flaky network.

> **Golden rule:** do a full timed dry-run the day before and **record a terminal
> cast of it** (`asciinema rec defense_fallback.cast`). If anything stalls live,
> you play the cast and keep talking. A committee remembers a confident narrative,
> not who typed the commands.

---

## What each beat proves

| Beat | You show | Thesis claim it defends |
|---|---|---|
| 1 | The sandboxed vulnerable target | Realistic target; safe to exploit (isolation) |
| 2 | Static analysis, RAG-grounded | Findings are grounded in CWE/CVE, not hallucinated |
| 3 | Fuzzing confirms the finding | **Closed loop**: static → *dynamically confirmed* (low false positives) |
| 4 | Mitigations in the report | End-to-end analyze → confirm → fix |
| 5 | 3-arm eval table | **The contribution**: small local SLMs match F1 at a fraction of cost/latency |
| 6 (opt.) | `--agentic` orchestrator | Heterogeneous agentic system (arXiv:2506.02153) |

---

## Part 0 — Pre-flight

### T-1 day (once)
```bash
# 1. Warm the models so first-call latency isn't on stage.
ollama pull qwen3:8b              # orchestrator + all three specialists (default)
ollama pull qwen3-embedding:0.6b  # RAG retrieval embedder (0.091 s/query warm)

# 2. Build both containers (target + the pipeline runner).
docker compose build              # builds `target` and `runner`
docker build -t vuln-fuzzer .                 # optional: host-side ffuf image

# 3. Full timed dry-run of Part 2, and RECORD it as the fallback.
asciinema rec docs/defense_fallback.cast      # Ctrl-D to stop
```
Write your *measured* per-beat times into the "⏱" column below — do not trust the
estimates; qwen3:8b latency depends on your hardware.

### T-15 min (at the venue)
```bash
ollama run qwen3:8b "ok"        # wake Ollama, confirm the model answers
docker compose up -d target     # start the sandbox; wait for healthy
scripts/target.sh status        # -> healthy
git stash list; git status      # clean tree, no surprise diffs on screen

# Sanity: the whole pipeline is ONE command if you'd rather not do beats 2-4
# by hand.  docker compose up --build   (runs analyze -> fuzz -> mitigate)
```
Have **two terminals** open: one for the demo, one already showing
`docs/architecture.md` / your slides.

---

## Part 1 — Environment sanity check (run live, ~10s, reassures the room)
```bash
curl -s http://localhost:5055/user/alice | head -c 200   # target is up
docker images | grep -E 'vuln-(fuzzer|target)'           # both images exist
ollama list | grep qwen3                                 # model present
```

---

## Part 2 — The demo

Run it **stage-by-stage with `--tool`** (not one big `scan`). You control the
pace, narrate while each stage thinks, and can skip the slow fuzz step if you're
short on time. Reports accumulate in `results/reports/`.

### Beat 1 — The target, sandboxed  ⏱ ~45s
```bash
# It looks like an ordinary internal "ops dashboard"...
sed -n '1,30p' targets/vuln_dashboard.py
```
**Say:** *"A realistic Flask app — SQLi, command injection, SSTI, insecure
deserialization, SSRF. It runs in a container, so when the pipeline lands an
exploit, it executes inside a throwaway sandbox, not on this laptop."*

**Prove the isolation (the memorable moment):**
```bash
curl -s --get http://localhost:5055/admin/ping \
  --data-urlencode "token=s3cr3t-admin-token" \
  --data-urlencode "host=127.0.0.1; id; cat /etc/hostname"
```
**Point at the output:** *"`uid=10001(app)` and this hostname are the **container's**,
not my machine's."* Then, side by side:
```bash
docker exec raguard-target sh -c "id; hostname"   # same uid + hostname
```

**The stronger beat — show the exploit is not just contained but *declawed*:**
```bash
curl -s --get http://localhost:5055/admin/ping \
  --data-urlencode "token=s3cr3t-admin-token" \
  --data-urlencode "host=127.0.0.1; id; touch /app/backdoor.py; grep CapEff /proc/self/status"
```
**Say:** *"The RCE lands — that's the point, the fuzzer has to be able to confirm
it. But it lands as an unprivileged user, on a read-only filesystem, with zero
Linux capabilities. It cannot patch the app it just compromised, cannot persist,
and cannot execute anything it downloads. Hardened to the OWASP Docker Security
Cheat Sheet: rootless, non-privileged, read-only rootfs, CPU/memory/PID caps."*

### Beat 2 — Static analysis (RAG + specialist SLM)  ⏱ ~30–90s
```bash
python -m agentsec.cli scan targets/vuln_dashboard.py \
  --tool analyze --output results/reports/vuln_report.json
```
**Say (while it runs):** *"Before the model sees the code, we retrieve the most
relevant CWE definitions and real CVE examples from a local knowledge base by
cosine similarity, and put them in the prompt. The finding is grounded in
authoritative taxonomy — it cites the CWE, it doesn't invent it."*
```bash
python -c "import json;d=json.load(open('results/reports/vuln_report.json'));\
print('findings:',len(d.get('findings',[])));\
[print(' -',f['cwe'],f['severity'],f.get('endpoint','')) for f in d.get('findings',[])[:6]]"
```

### Beat 3 — Fuzzing confirms it (the closed loop)  ⏱ ~30–60s
```bash
python -m agentsec.cli scan targets/vuln_dashboard.py \
  --tool fuzz --output results/reports/fuzz_report.json
```
**Say:** *"A specialist SLM picks the SecLists wordlists for this specific CWE;
we generate an `ffuf` script and run it **from the fuzzer container** against the
target. A hit is a `500` — the payload reached the SQL parser and broke the query.
That turns a static *guess* into a *dynamically confirmed* vulnerability — this is
what kills the false positives that plague pure static analysis."*
```bash
python -c "import json;d=json.load(open('results/reports/fuzz_report.json'));\
print('confirmed hits:',d.get('total_hits'))"
```
> **Fallback if Docker fuzz is slow/flaky:** add `--no-execute-fuzz` (generates
> `fuzz.sh` without running it) and show a pre-generated `results/reports/fuzz_report.json`
> from your dry-run instead.

### Beat 4 — Mitigations + the full report  ⏱ ~30–90s
```bash
python -m agentsec.cli scan targets/vuln_dashboard.py \
  --tool mitigate --output results/reports/full_report.json
```
**Say:** *"The mitigation step consumes the confirmed hits, so each fix is
attached to a vulnerability we actually proved — analyze → confirm → fix, closed."*
Open `results/reports/full_report.json` and show one finding with its
`cwe`, `confirmed: true`, and `mitigation`.

> **Simpler alternative for Beats 2–4:** one command runs all three in order:
> `python -m agentsec.cli scan targets/vuln_dashboard.py`
> (executes the fuzz step by default). Use this if you'd rather narrate over a
> single run than type three commands.

### Beat 5 — The eval (the thesis money shot)  ⏱ ~30s (score-only)
Run **score-only** from the artifacts you just produced — no waiting on models:
```bash
python eval/run_eval.py --labels eval/labels/vuln_dashboard.labels.json
```
**Say:** *"Scored against hand-labelled ground truth: precision / recall / F1 on
the CWEs, plus latency, tokens, and price per task. The headline is the arm
comparison —"* switch to the table from your **full** eval run (below), *"— the
heterogeneous small-model configuration reaches comparable F1 while local
inference drives the price to zero and cuts latency. That is the paper's claim,
measured on this pipeline."*

**Full 2-arm run** (do this in the dry-run; present the saved table live):
```bash
python eval/run_eval.py --run --target targets/vuln_dashboard.py \
  --arm baseline=config/agentsec.baseline.yaml \
  --arm heterogeneous=config/agentsec.yaml
# → Markdown + CSV in eval/results/
```
> Honest framing: the **tuned** arm (`config/agentsec.v2.yaml`) needs the S5 LoRA
> adapter from Colab, which is in progress. Present baseline vs heterogeneous-OTS
> now; describe the tuned arm as the next data point, and show the S1–S6 flywheel
> (`docs/architecture.md`) as the mechanism that produces it. Committees respect a
> clearly-scoped "here's what's measured, here's what's next."

### Beat 6 (optional) — The agentic orchestrator  ⏱ ~1–3 min, higher risk
```bash
python -m agentsec.cli scan targets/vuln_dashboard.py --agentic
```
**Say:** *"Everything so far ran in a fixed order. In agentic mode the generalist
orchestrator runs a tool-calling loop and **decides** which specialist to invoke
next — the heterogeneous agent from the paper. Same tools, model-driven control."*
> Only show this if the dry-run was reliably fast. It's the most impressive beat
> and the least predictable. If unsure, describe it and play the recorded cast.

---

## Part 3 — Anticipated committee questions

- **"Isn't this just an LLM guessing bugs?"** → Two guards: RAG grounds each
  finding in retrieved CWE/CVE text, and the fuzzer *dynamically confirms* it.
  An unconfirmed finding is flagged as such.
- **"Why small / local models instead of GPT-class?"** → That's the thesis
  (arXiv:2506.02153). The eval shows OTS SLMs approach baseline F1 at ~zero
  marginal cost and lower latency; specialists are narrow, so a small tuned
  adapter is enough. The GLM5 cloud arm exists only as a comparison point.
- **"How do you handle false positives?"** → The confirm step: only findings a
  fuzzer reproduces are marked confirmed; the report separates the two.
- **"Is it safe to run these exploits?"** → Container isolation hardened to the
  OWASP Docker Security Cheat Sheet (shown in Beat 1): the target runs **rootless**
  (uid 10001), never privileged, with `cap_drop: ALL` (zero effective capabilities),
  `no-new-privileges`, a **read-only root filesystem**, and CPU/memory/PID limits.
  A landed RCE runs as an unprivileged user that cannot write to the app's own code
  or execute a dropped binary — verified by exploiting the container's own CWE-78
  endpoint. Egress can additionally be cut with an internal network (noted in
  `docker-compose.yml`).
- **"Does it generalize beyond this app?"** → The scanner is AST-driven and the
  KB is CWE/CVE-general; point it at any Python web file. Labels exist for a
  second target (`test_target2.py`) to show it isn't tuned to one app.
- **"What's novel vs. existing SAST/DAST?"** → The *closing of the loop by a
  heterogeneous agent* — one generalist routing narrow specialists, RAG-grounded,
  with static findings verified dynamically, runnable fully locally.

---

## Part 4 — Reset between runs
```bash
rm -f results/reports/*.json results/fuzz/*.json results/scripts/fuzz.sh
docker compose restart target      # fresh DB seed
```

## Teardown (after the defense)
```bash
docker compose down                # stop + remove the sandbox
```

---

## Appendix — One-shot sequence (if you must run it all at once)
```bash
docker compose up -d target && scripts/target.sh status
python -m agentsec.cli scan targets/vuln_dashboard.py            # analyze→fuzz→mitigate
python eval/run_eval.py --labels eval/labels/vuln_dashboard.labels.json
```

## Appendix — Offline / no-network fallback
Everything runs locally *except* the SSRF `/fetch` demo (needs internet) — don't
rely on it on stage. Ollama, the fuzzer, and the target are all local. If the
venue Wi-Fi dies, the demo is unaffected; only skip Beat 6 if the model is cold.
