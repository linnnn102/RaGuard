"""knowledge_base.py — CWE/CVE retrieval, reused from vuln_scanner.

``KnowledgeBase`` (nomic-embed-text embedder + numpy cosine over the Colab
Parquet/npy chunks) is imported verbatim. Also exposes ``load_kb`` which builds
one from an ``agentsec`` config's ``rag`` block.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from vuln_scanner import KnowledgeBase  # noqa: F401  (re-export)

from ..config import PROJECT_ROOT, Config


def load_kb(config: Config) -> KnowledgeBase:
    """Construct a KnowledgeBase from the config's ``rag`` block."""
    import os

    rag = config.rag or {}
    chunks_dir = rag.get("chunks_dir")
    if chunks_dir:
        source = Path(chunks_dir)
    else:
        source = Path(rag.get("chunks_zip", "data/kb/rag_chunks.zip"))
    if not source.is_absolute():
        source = PROJECT_ROOT / source

    # Embeddings come from the same Ollama the specialists use. In the runner
    # container that is the host gateway, not localhost, so respect OLLAMA_URL.
    ollama_url = rag.get("ollama_url") or os.environ.get(
        "OLLAMA_URL", "http://localhost:11434"
    )
    return KnowledgeBase(
        source,
        embed_model=rag.get("embed_model"),
        embed_backend=rag.get("embed_backend"),
        ollama_url=ollama_url,
    )
