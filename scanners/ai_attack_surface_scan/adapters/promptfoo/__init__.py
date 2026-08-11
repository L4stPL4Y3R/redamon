"""promptfoo adapter — broad red-team eval (dataset plugins) + per-plugin ASR.

See TOOL_API.md. promptfoo is a Node CLI (no venv); the adapter shells out to the
`promptfoo` binary with remote generation/telemetry disabled and the grader forced
to the local Ollama (zero external egress). Defaults to dataset-based plugins,
which are the only ones that run fully offline (TOOL_API.md §8).
"""
from .adapter import run  # noqa: F401
