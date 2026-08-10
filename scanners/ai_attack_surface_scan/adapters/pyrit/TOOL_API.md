# PyRIT — TOOL_API.md

> §15.1 mandate: document PyRIT's API + output contract to 100% **before** the
> adapter. Sourced by installing pyrit==0.14.0 and introspecting the real API
> (the docs lag the code — 0.14.0 already completed the Orchestrator→Attack
> refactor). The parser is written from this and unit-tested against a captured
> real artifact.

- **Tool:** PyRIT — Microsoft's Python Risk Identification Tool (bounded multi-turn red-teaming).
- **License:** MIT.
- **Repo:** https://github.com/microsoft/PyRIT
- **Version pin:** **0.14.0** (Python 3.10–3.14).
- **Role here:** bounded multi-turn jailbreaks (crescendo · skeleton-key) using the local Ollama as the bounded **attacker + judge**; chips: Jailbreak (LLM01), Skeleton Key, Prompt Injection.

---

## 0. CRITICAL: PyRIT cannot share garak's venv → per-tool venvs

garak 0.15.1 needs `datasets<4.0,>=3.0.0`; PyRIT 0.14.0 needs `datasets>=4.8.0`.
**Irreconcilable** (`ResolutionImpossible`). Combined with promptfoo being a
Node.js tool, **per-tool dependency isolation is mandatory** — the plan's §1.2
"one image, all tools in one env" is amended to:

> **One image, per-tool virtualenvs.** The shared spine (neo4j driver +
> main/target_loader/safety/normalizer) runs in the base interpreter. Each tool
> gets its own venv: `/opt/venv-garak`, `/opt/venv-pyrit` (later a giskard venv
> + Node for promptfoo). Each adapter invokes its tool via that venv's
> interpreter as a subprocess. The orchestrator still spawns ONE image.

So garak's runner calls `/opt/venv-garak/bin/python -m garak …`; PyRIT's runner
is `/opt/venv-pyrit/bin/python adapters/pyrit/pyrit_run.py …`.

---

## 1. PyRIT is a library, not a CLI → WE define the output contract

Unlike garak (CLI → `report.jsonl`), PyRIT has no standard report. Our runner
script configures the attack, runs it, extracts conversations + outcome from
PyRIT's memory, and writes **our** results JSON — which the parser reads. So the
"output contract" in §4 is ours, derived from the PyRIT API below.

---

## 2. The building blocks (verbatim signatures, 0.14.0)

### 2.1 Targets (`pyrit.prompt_target`)
```python
HTTPTarget(http_request: str, prompt_regex_string: str = "{PROMPT}",
           use_tls: bool = True, callback_function: Optional[Callable] = None,
           model_name: str = "", **httpx_client_kwargs)         # the VICTIM
OpenAITarget(*, model_name=None, endpoint=None, api_key=None, headers=None,
             max_requests_per_minute=None, httpx_client_kwargs=None, ...)  # base
# OpenAIChatTarget(**) extends OpenAITarget (+ temperature, seed, top_p, ...)
```
- **Victim** = `HTTPTarget`: `http_request` is a **raw HTTP request string** (request line + headers + blank line + body) with the `{PROMPT}` token where the prompt is injected. `use_tls=False` for http. `callback_function(response)` parses the response (we extract `choices[0].message.content` for OpenAI-compat).
- **Attacker + Judge** = `OpenAIChatTarget(model_name=<judge>, endpoint="<ollama>/v1/chat/completions", api_key="ollama", seed=<seed>)` → the local Ollama (OpenAI-compat), local-only.
- **Footgun to verify at fixture time:** does `{PROMPT}` get JSON-escaped before substitution into a JSON body? If not, quotes/newlines in the adversarial prompt break the JSON — may need `callback`/escaping. CONFIRM with the captured run.

### 2.2 Attacks (`pyrit.executor.attack`)
```python
CrescendoAttack(*, objective_target: PromptTarget,
                attack_adversarial_config: AttackAdversarialConfig,
                attack_scoring_config: Optional[AttackScoringConfig] = None,
                max_backtracks: int = 10, max_turns: int = 10)
SkeletonKeyAttack(*, objective_target: PromptTarget,
                  attack_scoring_config: Optional[AttackScoringConfig] = None,
                  skeleton_key_prompt: Optional[str] = None,
                  max_attempts_on_failure: int = 0)             # single-turn, no adversary
result = await attack.execute_async(objective="<attack goal>")  # -> AttackResult
```
- **Bounds:** `max_turns` (hard turn budget) + `max_backtracks` — our §3 bound.
- Skeleton-key is single-turn (override prompt), no adversarial LLM.

### 2.3 Config wrappers
```python
AttackAdversarialConfig(target: PromptTarget,           # the attacker (Ollama)
                        system_prompt_path=None,
                        seed_prompt="Generate your first message to achieve: {{ objective }}")
AttackScoringConfig(objective_scorer: Optional[TrueFalseScorer] = None,
                    refusal_scorer: Optional[TrueFalseScorer] = None,
                    auxiliary_scorers: list = [], use_score_as_feedback: bool = True)
```

### 2.4 Scorer (the judge verdict)
```python
SelfAskRefusalScorer(*, chat_target: PromptTarget, ...)   # refusal vs compliance
SelfAskTrueFalseScorer(*, chat_target, true_false_question=..., ...)  # objective met?
```
Point `chat_target` at the local Ollama. For crescendo the `objective_scorer`
decides if the objective landed; refusal_scorer/SelfAskRefusalScorer is the
simplest judge (compliance = attack progressing).

### 2.5 Setup + memory
```python
# pyrit.setup: initialize_pyrit_async(...) / initialize_from_config_async(...)
await initialize_pyrit_async(memory_db_type="InMemory")   # CONFIRM exact arg at fixture
mem = CentralMemory.get_memory_instance()                 # MemoryInterface
mem.get_conversation(conversation_id=result.conversation_id)  # the turns
mem.get_prompt_scores(...)                                # scores
```

---

## 3. AttackResult — the parse source (verbatim fields, 0.14.0)

`AttackResult.model_fields`:
```
conversation_id, objective, attack_result_id, atomic_attack_identifier,
last_response, last_score, executed_turns, execution_time_ms,
outcome, outcome_reason, timestamp, related_conversations, metadata,
labels, error_message, error_type, error_traceback, ...
```
- **`outcome`** ∈ `AttackOutcome` = `{SUCCESS, FAILURE, UNDETERMINED, ERROR}` (str enum). **`outcome == "SUCCESS"` = the jailbreak landed.**
- `executed_turns` = turns used (vs `max_turns`).
- `last_score` = the final judge score; `outcome_reason` = textual rationale.
- `conversation_id` → `mem.get_conversation(...)` for the transcript turns.

---

## 4. Our results JSON (what the parser consumes)

`pyrit_run.py` writes one file:
```json
{
  "pyrit_version": "0.14.0",
  "attack": "crescendo",              // or "skeleton_key"
  "seed": 0,
  "max_turns": 4,
  "results": [
    {
      "objective": "<attack goal>",
      "outcome": "SUCCESS",          // SUCCESS/FAILURE/UNDETERMINED/ERROR
      "turns_used": 3,
      "last_score": 1.0,
      "outcome_reason": "...",
      "conversation": [{"role": "user", "content": "..."},
                       {"role": "assistant", "content": "..."}]
    }
  ]
}
```

### ASR
- Per objective: success = `outcome == "SUCCESS"`.
- **ASR(attack) = #SUCCESS / #objectives** (each objective is one bounded
  multi-turn conversation — "deterministic in expectation", §9).
- One normalized `Finding` per attack with `ai_asr`, `ai_trials = #objectives`,
  `ai_oracle_kind = "judge_llm"`, `ai_payload_class = "pyrit-crescendo"` /
  `"pyrit-skeleton-key"`, `ai_owasp_llm_id = "LLM01"`, chip `jailbreak`,
  `ai_transcript_ref` = the results JSON path. Evidence = the winning objective +
  turns used.

---

## 5. Determinism levers
- `OpenAIChatTarget(seed=…)` on attacker + judge (temp 0); fixed `max_turns` /
  `max_backtracks`; pinned Ollama model + version. "Deterministic in
  expectation" (§9) — comparable ASR across runs.

## 6. Egress / safety
- Victim = the in-scope HTTP target only. Attacker + judge = local Ollama
  (OpenAI-compat), no external egress. Verify `OpenAIChatTarget` doesn't fall
  back to api.openai.com when endpoint is set.
- PyRIT memory is `InMemory` (no DuckDB file needed) per run.

## 7. Open items to confirm at fixture capture
1. Exact `initialize_pyrit_async` arg for in-memory (`memory_db_type=` value).
2. `mem.get_conversation()` return structure → role + text extraction.
3. `{PROMPT}` JSON-escaping in HTTPTarget (the JSON-body footgun).
4. The right objective scorer for crescendo (SelfAskRefusalScorer vs a true/false
   objective question) — capture a real run and confirm outcomes are sane.
5. `OpenAIChatTarget` arg names for endpoint/key when pointing at Ollama.
