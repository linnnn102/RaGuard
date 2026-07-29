"""agentsec.rag — retrieval, AST extraction, and finding parsing.

These wrap the reused ``vuln_scanner`` internals (nomic embedder, numpy cosine
retrieval, AST function extraction, JSON-array parsing). Kept as thin
re-exports so there is a single source of truth and the golden report schema is
preserved. numpy / pandas / sentence-transformers are pulled in only when a
symbol is actually imported.
"""
