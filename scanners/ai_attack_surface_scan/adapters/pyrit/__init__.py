"""PyRIT adapter — bounded multi-turn jailbreaks (crescendo / skeleton-key).

See TOOL_API.md. The tool runs in /opt/venv-pyrit (isolated from garak); this
package's adapter (base interpreter) invokes the runner and normalizes findings.
"""
from .adapter import run  # noqa: F401
