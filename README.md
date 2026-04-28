# RAG-Powered Vulnerability Analysis & Fuzzing Pipeline

An automated security testing pipeline that combines **Retrieval-Augmented Generation (RAG)** with **LLM-driven code analysis** and **dynamic HTTP fuzzing** to detect, reproduce, and remediate vulnerabilities in Python web applications.

---

## How It Works

The pipeline runs in three stages:

1. **Static Analysis** — A local LLM (Llama 3 via Ollama) analyzes Python source code for vulnerabilities. Before each LLM call, relevant CWE definitions and real-world CVE examples are retrieved from a pre-built knowledge base using semantic similarity (cosine distance on `nomic-embed-text-v2-moe` embeddings). This RAG context grounds the model's output in authoritative security taxonomy.

2. **Fuzzing Script Generation** — Detected CWE IDs are mapped to curated SecLists wordlists. A `fuzz.sh` script is generated with `ffuf` commands targeting each vulnerable endpoint, one job per CWE/wordlist combination.

3. **Dynamic Testing & Reporting** — The fuzzing script runs inside a Docker container. Raw `ffuf` JSON outputs are parsed into a structured report of confirmed hits, grouped by CWE.

The pipeline can be run **step-by-step** (standalone scripts) or **end-to-end** (via an MCP client/server pair).

---

## Architecture

```
src/
├── vuln_scanner.py          # RAG + LLM static analysis
├── generate_fuzz_script.py  # Maps CWEs → SecLists wordlists → fuzz.sh
├── parse_fuzz_results.py    # Parses ffuf JSON outputs into fuzz_report.json
├── server.py                # MCP server exposing the three tools above
└── client.py                # MCP client that orchestrates the full pipeline

data/
├── kb/rag_chunks.zip        # Pre-built knowledge base (CWE/CVE chunks + embeddings)
└── cwe/cwec_v4.19.1.xml     # Full CWE taxonomy reference

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
pip install fastmcp sentence-transformers pandas numpy flask
```

**Pull the LLM model:**
```bash
ollama pull llama3
```

---

## Configuration

All paths and endpoints can be overridden via environment variables. Defaults work out of the box if you run from the repo root.

| Variable | Default | Description |
|---|---|---|
| `CHUNKS_ZIP` | `data/kb/rag_chunks.zip` | Path to knowledge base archive |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `llama3` | Model tag to use |
| `REPORT_PATH` | `results/reports/vuln_report.json` | Where to write the vulnerability report |
| `TOP_K` | `5` | Number of RAG chunks to retrieve per query |

---

## Usage

### Option A — Step-by-Step Pipeline

This is the recommended approach for understanding each stage or debugging.

**Step 1: Start the target application**
```bash
python targets/your_app.py
# Starts Flask app on http://localhost:5055
```

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

**Step 4: Build the Docker image (once)**
```bash
docker build -t vuln-fuzzer .
```

**Step 5: Run fuzzing inside Docker**
```bash
mkdir -p results/fuzz
docker run --rm \
    -v $(pwd)/results/scripts/fuzz.sh:/fuzz/fuzz.sh \
    -v $(pwd)/results/fuzz:/results \
    --add-host=host.docker.internal:host-gateway \
    vuln-fuzzer bash /fuzz/fuzz.sh
# Output: results/fuzz/ffuf_CWE_*.json
```

**Step 6: Parse fuzzing results**
```bash
python src/parse_fuzz_results.py
# Output: results/reports/fuzz_report.json
```

---

### Option B — MCP Orchestrated Pipeline

Runs analysis, fuzzing, and mitigation suggestions in one command using the Model Context Protocol server.

**Start the target app first:**
```bash
python targets/your_app.py
```

**Run the full pipeline:**
```bash
python src/client.py targets/your_app.py
# Output: results/reports/full_report.json
```

The MCP server (`server.py`) exposes three tools — `analyze_code`, `generate_fuzz_script`, and `suggest_mitigations` — which the client calls in sequence.

---

## Output Formats

**`vuln_report.json`** — vulnerability analysis results
```json
{
  "meta": { "tool": "...", "model": "llama3", "scan_date": "...", "duration_s": 12.4 },
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
