"""garak adapter — broad single-shot LLM scanner (Step 4).

See TOOL_API.md for the documented invocation surface, REST generator config,
and report.jsonl contract this adapter is written against (garak 0.15.1).

Public entry point: run(target, bounds, output_dir, run_id, judge_base_url) ->
list[Finding].
"""
from .adapter import run  # noqa: F401
