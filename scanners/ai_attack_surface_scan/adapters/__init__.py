"""Per-tool adapters for the AI Attack Surface scan.

Each adapter turns one tool's native run + report into the shared Finding shape
(normalizer.py). The shared spine (target loader, safety, normalizer) is
tool-agnostic; only the adapters know a tool's CLI and report format.
"""
