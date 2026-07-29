#!/usr/bin/env bash
# run_iteration.sh — S6: one LLM-to-SLM improvement iteration.
#
# Chains the repo-side stages of the paper's algorithm. GPU training (S5) is a
# manual Colab step in the middle; everything around it is automated here.
#
#   S1  logging      — happens live while the pipeline runs (nothing to do here)
#   S2  curate       — scripts/s2_curate.py
#   S3  cluster      — scripts/s3_cluster.py   (validate 3 task boundaries)
#   S5a export       — scripts/export_dataset.py  -> upload data/export to Colab
#   S5b train        — (Colab) QLoRA on the chosen Qwen base -> download adapter
#   S5c register     — scripts/register_adapter.py --task <t> --version <vN>
#   S4/S6 wire+eval  — bump config to vN+1, set the adapter tag, run eval
#
# Usage:
#   scripts/run_iteration.sh <version>        # e.g. v2
#
# Adapters live under adapters/<task>/<version>/ and are treated as immutable.
# Select the active config for a clean rollback with:
#   AGENTSEC_CONFIG=config/agentsec.<version>.yaml
set -euo pipefail

VERSION="${1:?usage: run_iteration.sh <version>  (e.g. v2)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== S2: curate call logs =="
python scripts/s2_curate.py

echo "== S3: cluster (validate 3 tasks) =="
python scripts/s3_cluster.py || echo "[warn] clustering skipped (need more data / deps)"

echo "== S5a: export chat dataset for Colab =="
python scripts/export_dataset.py
echo ">> Upload data/export/ to Colab, run QLoRA, download each adapter.gguf into"
echo "   adapters/<task>/${VERSION}/ (with a Modelfile), then re-run with register."

echo "== S5c: register adapters (skips tasks without an adapter.gguf) =="
for task in analyze_code select_wordlists suggest_mitigations; do
  if [ -f "adapters/${task}/${VERSION}/adapter.gguf" ]; then
    python scripts/register_adapter.py --task "${task}" --version "${VERSION}"
  else
    echo "[skip] no adapters/${task}/${VERSION}/adapter.gguf yet"
  fi
done

echo "== S4/S6: next steps =="
echo "  1. cp config/agentsec.yaml config/agentsec.${VERSION}.yaml"
echo "  2. set each fine-tuned task's model: to qwen3-<task>-${VERSION}"
echo "  3. AGENTSEC_CONFIG=config/agentsec.${VERSION}.yaml python eval/run_eval.py"
echo "Done."
