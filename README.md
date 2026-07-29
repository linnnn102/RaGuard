# RAG-Powered Vulnerability Analysis & Fuzzing Pipeline

An automated security testing pipeline that combines **Retrieval-Augmented Generation (RAG)** with **LLM-driven code analysis** and **dynamic HTTP fuzzing** to detect, reproduce, and remediate vulnerabilities in Python web applications.

---

## How It Works

The pipeline runs in three stages:

1. **Static Analysis** — A local LLM (Qwen 3 via Ollama) analyzes Python source code for vulnerabilities. Before each LLM call, relevant CWE definitions and real-world CVE examples are retrieved from a pre-built knowledge base using semantic similarity (cosine distance on `qwen3-embedding:0.6b` embeddings, served by the **same local Ollama** as every other model). This RAG context grounds the model's output in authoritative security taxonomy.

2. **Fuzzing Script Generation** — For each vulnerable endpoint, the `(API, API source code)` pair and its vulnerability finding are handed to a language model (Qwen 3 via Ollama) along with a catalog of the wordlist files available in the [SecLists](https://github.com/danielmiessler/SecLists) repository (`data/seclists_catalog.txt`). The model picks the SecLists wordlist(s) best suited to fuzzing that specific vulnerability; **every path — whether chosen by the model or taken from the static fallback map — is validated against the catalog**, so a wordlist that does not exist can never reach the script. If the model is unreachable, the pipeline falls back to `data/cwe_wordlist_map.json`. A `fuzz.sh` script is then generated with `ffuf` commands, one job per CWE/wordlist combination.

3. **Dynamic Testing & Reporting** — The fuzzing script runs inside a container, black-box over HTTP against the running target. Raw `ffuf` JSON outputs are parsed into a structured report of confirmed hits, grouped by CWE. Jobs are independent: one failing job is reported but does not discard the rest, and a target that dies mid-run is flagged rather than silently under-reporting hits.

Everything runs with **one command** (`docker compose up`) — see [Quick Start](#quick-start). The stages can also be run individually.

### Fully local, verifiably

Every model call — the orchestrator, the three specialists, and the RAG embedder — goes to a local Ollama instance. The pipeline makes **no network calls to model providers at runtime**:

- Embeddings use `qwen3-embedding:0.6b` over Ollama's `/api/embed`. There is no `sentence-transformers` dependency on the default path, so no HuggingFace Hub request at startup and — importantly for a *security* tool — no `trust_remote_code=True` downloading and executing model code from the internet.
- Changing the embedding model requires re-embedding the knowledge base (`python scripts/reembed_kb.py`), because query and document vectors must share a vector space. The KB manifest records which model produced its vectors and `KnowledgeBase` refuses to load a mismatched one.

### Agentic architecture (LLM orchestrator + specialist SLMs)

Following NVIDIA's *Small Language Models are the Future of Agentic AI* ([arXiv:2506.02153](https://arxiv.org/abs/2506.02153)), the end-to-end pipeline is a **heterogeneous agentic system**: one generalist **LLM orchestrator** runs a tool-calling loop and decides which **specialist SLM (Qwen via Ollama)** to invoke for each narrow task — `analyze_code`, `select_wordlists`, `suggest_mitigations`. By default the orchestrator is itself a **local Qwen3** (served by Ollama over its OpenAI-compatible endpoint), so the whole system runs on local hardware with no cloud key; the **GLM5 cloud model** stays available as an optional orchestrator via `config/agentsec.glm.yaml`. The repo also implements the paper's **S1–S6 LLM-to-SLM conversion algorithm** (call logging → curation → clustering → dataset export → adapter serving → iteration) so off-the-shelf specialists can be replaced with fine-tuned adapters. GPU LoRA training (S5) runs separately on Colab; everything around it is automated here. See `config/agentsec.yaml` (the single routing source of truth) and the `agentsec` package under `src/`.

---

## Architecture

```
docker-compose.yml           # `docker compose up` = the whole pipeline (target + runner)
Dockerfile.runner            # The runner image: pipeline + ffuf + SecLists (no Docker socket)
Dockerfile                   # Standalone vuln-fuzzer image (host-side runs only)
targets/Dockerfile           # The hardened, intentionally-vulnerable target

src/
├── vuln_scanner.py          # RAG + LLM static analysis (reused by the analyze_code skill)
├── embedders.py             # Local Ollama embeddings (no HF Hub, no trust_remote_code)
├── seclist_selector.py      # LLM picks SecLists wordlists from the catalog (reused by select_wordlists)
├── generate_fuzz_script.py  # (API, source) + finding → SecLists wordlists → fuzz.sh
├── parse_fuzz_results.py    # Parses ffuf JSON outputs into fuzz_report.json
└── agentsec/                # Agentic package (LLM orchestrator + specialist SLMs)
    ├── config.py            # S4 router — parse config/agentsec.yaml
    ├── models/              # ModelClient ABC, Ollama/OpenAI backends, S1 call log, registry
    ├── rag/                 # KB retrieval, AST extraction, finding parsing (reused verbatim)
    ├── prompts.py           # analyze + mitigation prompts and output parsing
    ├── skills/              # analyze_code · select_wordlists · run_fuzz · suggest_mitigations
    ├── orchestrator/agent.py# orchestrator tool-calling loop (local Qwen3 default)
    └── cli.py               # python -m agentsec.cli scan <target.py>

config/agentsec.yaml         # Router: orchestrator + per-task specialist routing (versioned)
scripts/                     # S2 curate · S3 cluster · S5 export/register · S6 run_iteration.sh
scripts/reembed_kb.py        # Rebuild KB vectors with the local Ollama embedder
eval/run_eval.py             # 3-arm eval harness (latency / tokens / price / F1)

tools/
└── build_seclists_catalog.py # (Re)generate data/seclists_catalog.txt

data/
├── kb/rag_chunks.zip        # Pre-built knowledge base (CWE/CVE chunks + embeddings)
├── cwe/cwec_v4.19.1.xml     # Full CWE taxonomy reference
├── seclists_catalog.txt     # Catalog of SecLists wordlists shown to the selector LLM
└── cwe_wordlist_map.json    # Static CWE → SecLists fallback map (used if the LLM is down)

results/
├── reports/vuln_report.json # Output of vuln_scanner
├── reports/fuzz_report.json # Output of parse_fuzz_results
├── scripts/fuzz.sh          # Auto-generated fuzzing script
└── fuzz/ffuf_CWE_*.json     # Raw ffuf outputs (one file per job)
```

**Knowledge base format** (`rag_chunks.zip` contents):
- `cwe_chunks.parquet` — chunked CWE descriptions
- `cve_chunks.parquet` — real-world CVE examples
- `cwe_embeddings.npy` / `cve_embeddings.npy` — pre-computed sentence embeddings

---

## Prerequisites

| Dependency | Purpose |
|---|---|
| Python 3.10+ | Runtime |
| [Ollama](https://ollama.com) | Local LLM inference |
| Docker | Isolated fuzzing execution |
| `pip` packages (see below) | Python dependencies |

**Install Python dependencies:**
```bash
pip install -r requirements.txt
```

**Pull the models (specialists + local orchestrator + embedder):**
```bash
ollama pull qwen3:8b               # orchestrator + the 3 specialists (size to your RAM)
ollama pull qwen3-embedding:0.6b   # RAG retrieval embedder
```
The embedder is deliberately the **0.6B** variant, not the 8B default tag.
Retrieval runs on every specialist call, and measured on this repo's KB
(994 chunks) the difference is large:

| Embedder | Dim | Warm query | Build the KB |
|---|---|---|---|
| `qwen3-embedding:0.6b` | 1024 | **0.091 s** | **5.3 min** |
| `qwen3-embedding:8b` | 4096 | 0.520 s | 63.5 min |

The 0.6B model also **improves retrieval** over the `nomic-embed-text-v2-moe`
vectors the KB originally shipped with (MRR 0.385 vs 0.247, median rank 5 vs 10
on an 8-query CWE benchmark).
By default the orchestrator is a **local Qwen3** reached over Ollama's
OpenAI-compatible `/v1` endpoint — no cloud key required. Pick the orchestrator
size for your RAM: 8 GB → `qwen3:4b`, 16 GB → `qwen3:8b`, 24 GB → `qwen3:14b`,
32 GB+ → `qwen3:30b-a3b` (override with the `ORCH_MODEL` env var).

To use the **GLM5 cloud model** as the orchestrator instead, select its config and
set `GLM_API_KEY` (and optionally `GLM_BASE_URL` / `GLM_MODEL`):
```bash
export GLM_API_KEY=...
AGENTSEC_CONFIG=config/agentsec.glm.yaml python -m agentsec.cli scan targets/your_app.py
```
(Any local Ollama model works — override with `--model <tag>` or the `OLLAMA_MODEL`
env var. The pipeline uses Ollama's `/api/chat`, so the model's own chat template
is applied automatically; no model-specific prompt formatting is hard-coded.)

---

## Configuration

For the agentic pipeline, `config/agentsec.yaml` is the single source of truth
(orchestrator + per-task routing, RAG, fuzz). It expands `${VAR}` / `${VAR:-default}`
placeholders from the environment, so secrets stay out of the repo. Select an
alternate config for a clean rollback or to switch orchestrator with
`AGENTSEC_CONFIG=config/agentsec.glm.yaml`.

The default (`config/agentsec.yaml`) runs fully locally; `config/agentsec.glm.yaml`
swaps in the GLM5 cloud orchestrator.

| Variable | Default | Description |
|---|---|---|
| `ORCH_MODEL` | `qwen3:8b` | Local orchestrator model tag (default config) |
| `OLLAMA_OPENAI_URL` | `http://localhost:11434/v1` | Ollama OpenAI-compatible endpoint (orchestrator tool calling) |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint for the specialist SLMs |
| `ANALYZE_MODEL` / `WORDLIST_MODEL` / `MITIGATE_MODEL` | `qwen3:4b` | Per-task specialist tags (e.g. a fine-tuned adapter) |
| `AGENTSEC_CONFIG` | `config/agentsec.yaml` | Which router config to load |
| `GLM_API_KEY` | _(unset)_ | API key for the GLM5 orchestrator — only for `agentsec.glm.yaml` |
| `GLM_BASE_URL` | provider default | GLM orchestrator endpoint base URL (optional) |
| `GLM_MODEL` | `glm-4.5` | GLM orchestrator model tag (optional) |

The legacy standalone scripts (`src/vuln_scanner.py`, `src/generate_fuzz_script.py`)
keep their own `--model` / `--ollama-url` flags and the `OLLAMA_MODEL` / `CHUNKS_ZIP`
env vars for step-by-step runs.

---

## Quick Start

```bash
ollama serve &                     # the only host dependency
docker compose up --build          # runs the ENTIRE pipeline
```

That's it. Compose builds two containers, waits for the target to report
**healthy**, then runs analyze → fuzz → mitigate and writes
`results/reports/full_report.json`.

| Service | What it is | Lifecycle |
|---|---|---|
| `target` | The intentionally-vulnerable Flask app, hardened per the OWASP Docker Security Cheat Sheet | Long-lived |
| `runner` | The pipeline itself — orchestrator, specialists, **and** ffuf + SecLists | Runs to completion, then exits |

They share the compose network, so the runner fuzzes `http://target:5055`
directly — real container-to-container traffic. The target's port is published
only to `127.0.0.1` so the deliberately-vulnerable app is never exposed to your
LAN.

> **Why the pipeline doesn't spawn containers.** A containerised orchestrator can
> only run `docker run` if you mount `/var/run/docker.sock`, which grants it
> effective root on the host and would undo the target's hardening. The runner
> image bundles ffuf + SecLists instead, so the fuzz step just executes
> `bash fuzz.sh` in-process. No socket, no nested Docker. `run_fuzz` detects
> which mode it is in and falls back to spawning the standalone `vuln-fuzzer`
> image when run from the host.

On native Linux, match your uid so the bind-mounted `results/` stays writable:

```bash
DOCKER_UID=$(id -u) DOCKER_GID=$(id -g) docker compose up --build
```

---

## Usage

### Option A — Step-by-Step Pipeline

This is the recommended approach for understanding each stage or debugging.

**Step 1: Start the target application (in an isolated container)**

The target apps are *intentionally vulnerable* (real command-injection, pickle,
SSTI and SSRF), so run them in a throwaway container — a payload that lands
during fuzzing then executes inside the container instead of on your host:
```bash
docker compose up --build -d target   # or: scripts/target.sh up
# Serves the target at http://127.0.0.1:5055 for host-side steps.
# Stop it later with: docker compose down
```
To fuzz a different app, edit the `APP:` build arg in `docker-compose.yml`
(default `vuln_dashboard.py`).

<details><summary>Fallback: run it directly on the host (no isolation)</summary>

```bash
python targets/your_app.py
# Starts Flask app on http://localhost:5055
```
</details>

**Step 2: Run the vulnerability scanner**
```bash
python src/vuln_scanner.py targets/your_app.py
# Output: results/reports/vuln_report.json
```

**Step 3: Generate the fuzzing script**
```bash
python src/generate_fuzz_script.py \
    --report results/reports/vuln_report.json \
    --target-url http://host.docker.internal:5055/user/FUZZ
# Output: results/scripts/fuzz.sh
```
By default the LLM selects the SecLists wordlists from `data/seclists_catalog.txt`.
Pass `--no-use-llm` to use the static `data/cwe_wordlist_map.json` map instead.
Regenerate the catalog any time with `python tools/build_seclists_catalog.py`.

**Step 4: Build the standalone fuzzer image (once)**
```bash
docker compose --profile tools build fuzzer   # or: docker build -t vuln-fuzzer .
```
Only needed for host-side runs. Under `docker compose up` the runner already
contains ffuf + SecLists and executes `fuzz.sh` in-process.

**Step 5: Run fuzzing inside Docker**
```bash
mkdir -p results/fuzz
docker run --rm \
    -v $(pwd)/results/scripts/fuzz.sh:/fuzz/fuzz.sh:ro \
    -v $(pwd)/results/fuzz:/results \
    --add-host=host.docker.internal:host-gateway \
    --user "$(id -u):$(id -g)" --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m -e HOME=/tmp \
    --cpus 2 --memory 1g --pids-limit 512 \
    vuln-fuzzer bash /fuzz/fuzz.sh
# Output: results/fuzz/ffuf_CWE_*.json
```
(`run_fuzz` applies these hardening flags automatically — they are spelled out
here only because this step runs `docker` by hand.)

**Step 6: Parse fuzzing results**
```bash
python src/parse_fuzz_results.py
# Output: results/reports/fuzz_report.json
```

---

### Option B — One-Command Pipeline

Runs analysis, fuzzing, and mitigation suggestions together. **Start the target
app first:**
```bash
python targets/your_app.py
```

**Default — deterministic, step by step** (analyze → fuzz → mitigate, fully local, no key):
```bash
python -m agentsec.cli scan targets/your_app.py
# Output: results/reports/full_report.json
```
The three tools run in fixed order and the run always closes with a report. The
fuzz step **executes in Docker by default**; pass `--no-execute-fuzz` to only
generate `fuzz.sh`.

**Run a single tool** (MCP-style — each specialist is independently invokable):
```bash
python -m agentsec.cli scan targets/your_app.py --tool analyze    # only static analysis
python -m agentsec.cli scan targets/your_app.py --tool fuzz       # only fuzzing (reads vuln_report.json)
python -m agentsec.cli scan targets/your_app.py --tool mitigate   # only mitigations
```

**Agentic mode** — let the LLM orchestrator decide the tool order (the paper's contribution):
```bash
python -m agentsec.cli scan targets/your_app.py --agentic
```
In agentic mode the orchestrator may *request* fuzzing, but Docker runs only if
you did **not** pass `--no-execute-fuzz` (execution is user-gated).

**With the GLM5 cloud orchestrator** (agentic only):
```bash
export GLM_API_KEY=...
AGENTSEC_CONFIG=config/agentsec.glm.yaml python -m agentsec.cli scan targets/your_app.py --agentic
```
Routing — which model serves each task — lives in `config/agentsec.yaml`; point a
task's `model:` at a fine-tuned adapter tag to swap in a trained specialist with
no code change.

---

### LLM-to-SLM data path (S1–S6) & evaluation

Every model call is logged (S1) to `logs/calls/*.jsonl`. From those logs:

```bash
python scripts/s2_curate.py          # S2 — curate logs into training candidates
python scripts/s3_cluster.py         # S3 — validate the 3-task split (KMeans k=3)
python scripts/export_dataset.py     # S5 — export chat-format JSONL for Colab QLoRA
python scripts/register_adapter.py --task analyze_code --version v2   # S5 — serve the returned adapter
scripts/run_iteration.sh v2          # S6 — chain the whole loop for one iteration
```

Evaluate the three arms (LLM-only baseline · heterogeneous off-the-shelf ·
heterogeneous fine-tuned) against ground-truth labels:

```bash
python eval/run_eval.py --run --target targets/test_target2.py \
    --arm baseline=config/agentsec.baseline.yaml \
    --arm ots=config/agentsec.yaml \
    --arm tuned=config/agentsec.v2.yaml
# Emits eval/results/eval_table.md and .csv (latency / tokens / price / precision / recall / F1)
```

---

## Output Formats

**`vuln_report.json`** — vulnerability analysis results
```json
{
  "meta": { "tool": "...", "model": "qwen3", "scan_date": "...", "duration_s": 12.4 },
  "summary": { "total_findings": 2, "by_severity": { "HIGH": 1, "MEDIUM": 1 } },
  "results": [
    {
      "function": "get_user",
      "findings": [
        {
          "cwe_id": "CWE-89",
          "cwe_name": "SQL Injection",
          "severity": "HIGH",
          "confidence": 0.92,
          "description": "...",
          "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
          "solution": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
          "references": ["CVE-2023-12345"]
        }
      ]
    }
  ]
}
```

**`fuzz_report.json`** — confirmed fuzzing hits
```json
{
  "status": "ok",
  "total_hits": 3,
  "jobs": [
    {
      "cwe_id": "CWE-89",
      "wordlist": "/SecLists/Fuzzing/SQLi/Generic-SQLi.txt",
      "hit_count": 3,
      "hits": [
        { "url": "http://localhost:5055/user/1'", "status": 500, "input": "1'" }
      ]
    }
  ]
}
```
