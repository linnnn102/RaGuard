"""embedders.py — pluggable text embedding backends for the RAG knowledge base.

The pipeline's headline claim is that it runs **fully locally**. The original
embedder undermined that in two ways that were easy to miss:

  1. ``SentenceTransformer(...)`` contacts the HuggingFace Hub on every startup
     to resolve the model revision, printing
     ``"You are sending unauthenticated requests to the HF Hub"`` — a network
     call on what is supposed to be an offline pipeline.
  2. It was constructed with ``trust_remote_code=True``, which **downloads and
     executes** ``modeling_hf_nomic_bert.py`` from the Hub. Running arbitrary
     remote code inside a security-analysis tool is exactly the supply-chain
     pattern the tool exists to find.

``OllamaEmbedder`` removes both. Ollama already serves the orchestrator and the
three specialists locally, so routing embeddings through it means the whole
stack is one local runtime with no HF dependency and no remote code execution.

The legacy SentenceTransformer path is kept behind a lazy import so existing
knowledge bases built on Colab still load, but nothing on the default path
imports ``sentence_transformers`` any more.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Iterable, Sequence

import numpy as np

# Qwen3-Embedding is instruction-tuned: queries are wrapped in an "Instruct:"
# preamble describing the retrieval task, documents are embedded bare. Using the
# same asymmetry the model was trained with measurably improves retrieval, so it
# is applied here rather than left to the caller.
DEFAULT_QUERY_INSTRUCTION = (
    "Given a code vulnerability description, retrieve the CWE weakness "
    "definitions and CVE examples most relevant to it"
)

# Honour OLLAMA_URL: inside the runner container "localhost" is the container
# itself, while Ollama runs on the host gateway. Without this the KB fails to
# load under `docker compose up` even though the host-side run works fine.
DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

# The 0.6B variant, not the 8B default tag. Measured on this project's KB
# (994 chunks, ~1.2k chars each), warm:
#
#     qwen3-embedding:0.6b   1024-d   0.091 s/query    5.3 min to build the KB
#     qwen3-embedding:8b     4096-d   0.520 s/query   63.5 min to build the KB
#
# Retrieval happens on every specialist call, so the 8B model would add ~0.5 s
# to each one — which directly contradicts the thesis claim that small local
# models win on latency. 0.6B is the same model family at 1/6th the query cost.
DEFAULT_OLLAMA_MODEL = "qwen3-embedding:0.6b"


class EmbedderError(RuntimeError):
    """Raised when an embedding backend is unreachable or misconfigured."""


class OllamaEmbedder:
    """Embeddings from a local Ollama server. No network egress, no remote code.

    Exposes ``encode`` with a SentenceTransformer-compatible signature so
    ``KnowledgeBase`` can use either backend interchangeably.
    """

    backend = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_OLLAMA_MODEL,
        base_url: str = DEFAULT_OLLAMA_URL,
        query_instruction: str = DEFAULT_QUERY_INSTRUCTION,
        timeout: int = 300,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.query_instruction = query_instruction
        self.timeout = timeout

    # ── wire format ──────────────────────────────────────────────────────────
    def _post(self, inputs: Sequence[str]) -> list[list[float]]:
        payload = json.dumps({"model": self.model, "input": list(inputs)}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/embed",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise EmbedderError(
                f"Cannot reach Ollama at {self.base_url} for embeddings ({exc}).\n"
                f"Start it with `ollama serve` and pull the model:\n"
                f"    ollama pull {self.model}"
            ) from exc
        embeddings = data.get("embeddings")
        if not embeddings:
            raise EmbedderError(
                f"Ollama returned no embeddings for model {self.model!r}. "
                f"Is it an embedding model? Response keys: {list(data)}"
            )
        return embeddings

    def format_query(self, text: str) -> str:
        """Wrap a query in Qwen3-Embedding's instruction template."""
        if not self.query_instruction:
            return text
        return f"Instruct: {self.query_instruction}\nQuery: {text}"

    def encode(
        self,
        sentences: str | Iterable[str],
        *,
        is_query: bool = False,
        normalize_embeddings: bool = True,
        batch_size: int = 16,
        progress_every: int = 0,
    ) -> np.ndarray:
        """Embed one string (-> 1-D array) or many (-> 2-D array).

        ``is_query`` applies the instruction template; documents are embedded
        bare, matching how the stored KB vectors were produced.
        """
        single = isinstance(sentences, str)
        texts = [sentences] if single else list(sentences)
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)
        if is_query:
            texts = [self.format_query(t) for t in texts]

        vectors: list[list[float]] = []
        for start in range(0, len(texts), batch_size):
            vectors.extend(self._post(texts[start : start + batch_size]))
            if progress_every and (start // batch_size) % progress_every == 0:
                done = min(start + batch_size, len(texts))
                print(f"[embed] {done}/{len(texts)}", flush=True)

        arr = np.asarray(vectors, dtype=np.float32)
        if normalize_embeddings:
            # Cosine similarity downstream is a plain dot product, so normalise
            # here and keep retrieve() free of per-query norm computation.
            norms = np.linalg.norm(arr, axis=1, keepdims=True)
            arr = arr / np.clip(norms, 1e-12, None)
        return arr[0] if single else arr


class SentenceTransformerEmbedder:
    """Legacy HuggingFace path, kept only for knowledge bases built on Colab.

    Imported lazily: nothing on the default path pulls in
    ``sentence_transformers``, so the HF Hub call and ``trust_remote_code``
    never happen unless a KB explicitly asks for this backend.
    """

    backend = "sentence-transformers"

    def __init__(self, model: str, query_prefix: str = "search_query: "):
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        self.model = model
        self.query_prefix = query_prefix
        self._st = SentenceTransformer(model, trust_remote_code=True)

    def encode(
        self,
        sentences: str | Iterable[str],
        *,
        is_query: bool = False,
        normalize_embeddings: bool = True,
        batch_size: int = 16,
        progress_every: int = 0,
    ) -> np.ndarray:
        single = isinstance(sentences, str)
        texts = [sentences] if single else list(sentences)
        if is_query:
            texts = [f"{self.query_prefix}{t}" for t in texts]
        arr = self._st.encode(
            texts, normalize_embeddings=normalize_embeddings, batch_size=batch_size
        )
        arr = np.asarray(arr, dtype=np.float32)
        return arr[0] if single else arr


def make_embedder(
    backend: str | None = None,
    model: str | None = None,
    base_url: str = DEFAULT_OLLAMA_URL,
    query_instruction: str = DEFAULT_QUERY_INSTRUCTION,
):
    """Build the embedder a knowledge base asks for.

    ``backend`` comes from the KB manifest so a KB always retrieves with the
    same model that produced its stored vectors — mixing them silently yields
    meaningless cosine scores, since the two models occupy different vector
    spaces.
    """
    backend = (backend or "ollama").lower()
    if backend in ("ollama", "local"):
        return OllamaEmbedder(
            model=model or DEFAULT_OLLAMA_MODEL,
            base_url=base_url,
            query_instruction=query_instruction,
        )
    if backend in ("sentence-transformers", "sentence_transformers", "hf"):
        return SentenceTransformerEmbedder(model=model or "nomic-ai/nomic-embed-text-v2-moe")
    raise EmbedderError(f"Unknown embedding backend: {backend!r}")
