"""giskard adapter — quality + safety LLM scan (injection/disclosure/hallucination).

See TOOL_API.md. Runs in /opt/venv-giskard; the runner forces the scan judge +
embedding LLM to the local Ollama (zero external egress).
"""
from .adapter import run  # noqa: F401
