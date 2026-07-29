"""agentsec — agentic LLM orchestrator + specialist SLMs for security analysis.

Kept deliberately import-light: the top-level package pulls in no heavy
dependencies (numpy / openai / sklearn). Import the concrete submodule you need
(``agentsec.models.registry``, ``agentsec.rag.knowledge_base``, …) so that a
process that only touches the model layer never pays for RAG.
"""

__version__ = "2.0.0"
