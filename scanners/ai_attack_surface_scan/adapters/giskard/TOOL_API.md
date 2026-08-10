# giskard — TOOL_API.md

> §15.1 mandate: document giskard's API + output contract + the OpenAI-egress
> fix to 100% **before** the adapter. Sourced from installing giskard==2.19.1 and
> introspecting the real API. The parser is written from this and tested against
> a captured artifact.

- **Tool:** giskard — ML/LLM test suite; its LLM scan detects injection,
  info-disclosure, hallucination (faithfulness/implausibility), sycophancy.
- **License:** Apache-2.0.
- **Repo:** https://github.com/Giskard-AI/giskard · **Pin:** **2.19.1** (Python 3.10+).
- **Role here:** quality + safety scan of a chat endpoint; chips: Prompt Injection
  (LLM01), Data Disclosure (LLM02), Hallucination (LLM09).

## 0. Own venv (conflict), library not CLI, WE define output

- giskard 2.19.1 conflicts with garak (`ResolutionImpossible`) → **/opt/venv-giskard**
  (per-tool-venv architecture, §1.2 amendment). Adapter invokes `$GISKARD_PYTHON`.
- giskard is a Python library → the runner (giskard_run.py, in venv-giskard)
  configures the scan, runs it, extracts issues, and writes OUR results JSON,
  which the parser reads.

## 1. THE EGRESS FIX (the §4.3/§12.5 footgun — the giskard review gate)

giskard's LLM-assisted detectors call an LLM **and an embedding model**, defaulting
to OpenAI. Force both to the local Ollama (giskard uses LiteLLM; the `ollama/`
prefix routes locally), and DON'T set OPENAI_API_KEY so nothing can egress:
```python
import giskard
api_base = "http://localhost:11434"
giskard.llm.set_llm_model("ollama/<judge_model>", disable_structured_output=True, api_base=api_base)
giskard.llm.set_embedding_model("ollama/nomic-embed-text", api_base=api_base)
```
- `set_llm_model(llm_model: str, disable_structured_output=False, **kwargs)` — api_base via kwargs.
- `set_embedding_model(model: str, **kwargs)` — api_base via kwargs.
- **Open item (fixture):** does the chosen detector set actually USE embeddings?
  If yes, `nomic-embed-text` must be pulled into the Ollama volume (a second model
  the lifecycle must ensure). MVP plan: prefer detectors that don't need
  embeddings (injection, info-disclosure) and confirm at capture.
- Review gate asserts **zero external egress**: no OPENAI_API_KEY set; scan
  completes using only Ollama.

## 2. Wrapping the target (where target auth applies)

```python
import pandas as pd, giskard
def predict(df: pd.DataFrame):
    return [call_target(q) for q in df["question"].values]   # HTTP to the victim
model = giskard.Model(
    model=predict, model_type="text_generation",
    name="<target>", description="<what it does — drives domain-specific probes>",
    feature_names=["question"])
```
- `Model(model, model_type, name=None, feature_names=None, description=<**kwargs>, ...)`.
- `call_target` makes the HTTP request to the endpoint, applying the SHARED auth
  (`auth_header`/`auth_scheme`/`api_key`) — same as garak/pyrit. Custom (off-graph)
  targets work too (the spine passes the Target).
- `description` matters — giskard uses it to generate domain-specific probes.

## 3. Running the scan + detectors

```python
scan_results = giskard.scan(model, only=[<detector names>], raise_exceptions=False,
                            max_issues_per_detector=15)
```
**LLM detector names (verbatim, 2.19.1):**
```
llm_prompt_injection         -> LLM01 prompt-injection
llm_information_disclosure   -> LLM02 data-disclosure
llm_faithfulness             -> LLM09 hallucination
llm_implausible_output       -> LLM09 hallucination
llm_basic_sycophancy         -> LLM09 hallucination (agreeable falsehoods)
llm_output_formatting        -> (robustness; excluded from MVP default)
```
MVP default `only`: `["llm_prompt_injection", "llm_information_disclosure"]`
(security-relevant, likely no embeddings). Hallucination detectors added once the
embedding requirement is confirmed.

## 4. Output contract — ScanReport (the parse source)

`scan()` returns a `ScanReport`:
- `report.to_json()` — serialized report.
- `report.issues` — list of `Issue`; each `Issue` has (verbatim attrs):
  `detector_name`, `description`, `examples` (a DataFrame of failing cases),
  `features`, and severity via `is_major` / `is_medium` / `is_minor`.
- `report.has_issues`.

The runner extracts per issue → results JSON:
```json
{"giskard_version":"2.19.1","detectors":["llm_prompt_injection",...],
 "issues":[{"detector":"llm_prompt_injection","description":"...",
            "severity":"major","num_examples":3}]}
```

### Findings / "ASR"
giskard is a scan (issue present / absent), not trials. So per issue:
- one `Finding` per issue, `ai_asr = 1.0` (the detector flagged a vulnerability),
  `ai_trials = num_examples`, `ai_oracle_kind = "judge_llm"`,
  `ai_payload_class = "giskard-<detector>"`, `ai_owasp_llm_id` + chip from the map,
  `severity` from is_major/medium/minor (-> high/medium/low),
  `ai_transcript_ref` = the report JSON, evidence = the description.

## 5. Determinism / safety
- LLM client at temp 0 via Ollama; pinned model. Scan determinism is "in
  expectation" (LLM-assisted detectors).
- Egress: judge + embedding LOCAL only (Ollama); target = in-scope only.

## 6. Open items to confirm at fixture capture
1. Whether the MVP detectors need an embedding model (pull nomic-embed-text or not).
2. Exact `Issue.examples` shape (DataFrame) -> num_examples extraction.
3. `report.to_json()` schema vs iterating `report.issues` (prefer iterating issues).
4. `set_llm_model` "ollama/<model>" round-trips through LiteLLM to the local Ollama
   with NO OpenAI call (the egress assertion).
5. giskard's own model-validation step (it may send a probe at wrap time) uses the
   target endpoint — confirm it respects auth.
