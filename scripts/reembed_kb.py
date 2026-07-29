#!/usr/bin/env python3
"""reembed_kb.py — rebuild the RAG knowledge base vectors with a local embedder.

Why this exists
---------------
The KB ships with document vectors produced on Colab by
``nomic-ai/nomic-embed-text-v2-moe`` (768-d) via ``sentence_transformers``. That
path calls the HuggingFace Hub at startup and runs ``trust_remote_code=True``,
so the "fully local" claim did not hold. Moving to Ollama's ``qwen3-embedding``
fixes both, but query and document vectors must come from the SAME model —
otherwise cosine similarity compares unrelated vector spaces and retrieval
quietly returns noise. So switching the embedder REQUIRES re-embedding the KB.

This rewrites ``cwe_embeddings.npy`` / ``cve_embeddings.npy`` in place (with a
backup) and records the new model in ``manifest.json``, which ``KnowledgeBase``
then treats as authoritative.

Usage
-----
    python scripts/reembed_kb.py                     # default KB + qwen3-embedding
    python scripts/reembed_kb.py --model qwen3-embedding --chunks-dir path/to/chunks
    python scripts/reembed_kb.py --no-backup         # skip the .bak copies
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from embedders import (  # noqa: E402
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    DEFAULT_QUERY_INSTRUCTION,
    OllamaEmbedder,
)

DEFAULT_CHUNKS_DIR = REPO_ROOT / "data/kb/rag_chunks/content/chunks"


def embed_split(embedder: OllamaEmbedder, df: pd.DataFrame, label: str) -> np.ndarray:
    """Embed one split's chunk_text column as DOCUMENTS (no query template)."""
    texts = df["chunk_text"].astype(str).tolist()
    print(f"[reembed] {label}: embedding {len(texts)} chunks ...", flush=True)
    vectors = embedder.encode(
        texts, is_query=False, normalize_embeddings=True, batch_size=16, progress_every=4
    )
    print(f"[reembed] {label}: done -> {vectors.shape}", flush=True)
    return vectors


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Re-embed the RAG KB with a local Ollama model")
    p.add_argument("--chunks-dir", default=str(DEFAULT_CHUNKS_DIR),
                   help=f"Directory holding the parquet/npy chunks [default: {DEFAULT_CHUNKS_DIR}]")
    p.add_argument("--model", default=DEFAULT_OLLAMA_MODEL,
                   help=f"Ollama embedding model [default: {DEFAULT_OLLAMA_MODEL}]")
    p.add_argument("--base-url", default=DEFAULT_OLLAMA_URL, help="Ollama base URL")
    p.add_argument("--no-backup", action="store_true", help="Do not keep .bak copies")
    args = p.parse_args(argv)

    chunks_dir = Path(args.chunks_dir)
    if not (chunks_dir / "cwe_chunks.parquet").exists():
        print(f"[error] no cwe_chunks.parquet under {chunks_dir}")
        return 2

    embedder = OllamaEmbedder(
        model=args.model, base_url=args.base_url,
        query_instruction=DEFAULT_QUERY_INSTRUCTION,
    )

    df_cwe = pd.read_parquet(chunks_dir / "cwe_chunks.parquet")
    df_cve = pd.read_parquet(chunks_dir / "cve_chunks.parquet")

    emb_cwe = embed_split(embedder, df_cwe, "CWE")
    emb_cve = embed_split(embedder, df_cve, "CVE")

    if emb_cwe.shape[1] != emb_cve.shape[1]:
        print(f"[error] dim mismatch between splits: {emb_cwe.shape} vs {emb_cve.shape}")
        return 1

    for name, arr in (("cwe_embeddings.npy", emb_cwe), ("cve_embeddings.npy", emb_cve)):
        dest = chunks_dir / name
        if dest.exists() and not args.no_backup:
            shutil.copy2(dest, dest.with_suffix(".npy.bak"))
        np.save(dest, arr)
        print(f"[reembed] wrote {dest}  {arr.shape}")

    manifest_path = chunks_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    if manifest_path.exists() and not args.no_backup:
        shutil.copy2(manifest_path, manifest_path.with_suffix(".json.bak"))
    manifest.update({
        "embed_model": args.model,
        "embed_backend": "ollama",
        "embed_dim": int(emb_cwe.shape[1]),
        "query_instruction": DEFAULT_QUERY_INSTRUCTION,
        "cwe_chunks": int(len(df_cwe)),
        "cve_chunks": int(len(df_cve)),
    })
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[reembed] manifest updated -> {manifest_path}")
    print(f"[reembed] OK: {args.model} @ {emb_cwe.shape[1]}-d, fully local.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
