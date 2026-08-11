# garak — TOOL_API.md

> §15.1 mandate: document garak's invocation surface, target config, and output
> contract to 100% **before** writing the adapter. Sourced from the official
> garak source/docs (not memory), with verbatim references. The parser is
> written from this document and unit-tested against a captured real artifact.

- **Tool:** garak — NVIDIA's LLM vulnerability scanner ("Nessus for LLMs").
- **License:** Apache-2.0.
- **Repo:** https://github.com/NVIDIA/garak · **Docs:** https://reference.garak.ai · https://docs.garak.ai
- **Role here:** broad single-shot probe runner against a black-box HTTP endpoint via the `rest` generator; we parse its `report.jsonl` into per-probe ASR.
- **Version pin:** TBD at fixture capture (see §7). The parser keys on the
  *stable* `eval` rows; the version-sensitive part is the `attempt` row's
  `prompt`/`outputs` shape (changed to dataclass/Conversation form on `main`).

---

## 1. Invocation surface

Run as a module: `python -m garak <flags>`. Flags we use (verbatim meanings from `cliref.rst`):

| Flag | Short | Meaning |
|---|---|---|
| `--model_type` | `-m` | module (and optionally class) of the generator. For us: `rest` (= `rest.RestGenerator`). |
| `--generator_option_file` | `-G` | path to a JSON file of options passed to the generator (our REST config). |
| `--generator_options` | | same options as an inline JSON string (alternative to `-G`). |
| `--probes` | `-p` | comma-separated probe names, or `all` (default). |
| `--generations` | `-g` | number of generations per prompt (our **trials**). |
| `--seed` | `-s` | random seed (determinism lever). |
| `--report_prefix` | | prefix for the report + hit logs → `<prefix>.report.jsonl`. |
| `--parallel_attempts` | | how many probe attempts in parallel. |
| `--deprefix` | | strip the prompt from the front of the output. |
| `--list_probes` | | enumerate probes (with `-v`, a markdown table w/ tier + description). |

**MVP probe set (§4.1 of the plan):** `promptinject,dan,encoding,leakreplay`.
Probe *families* are valid probe names (e.g. `-p promptinject` runs the whole
family); specific probes use dotted form (e.g. `dan.DanInTheWild`).

**Canonical command we will run:**
```
python -m garak \
  --model_type rest \
  --generator_option_file /tmp/.../garak_rest.json \
  --probes promptinject,dan,encoding,leakreplay \
  --generations <trials> \
  --seed <seed> \
  --report_prefix /app/.../output/.../garak/garak_run \
  --parallel_attempts 8
```
→ writes `…/garak_run.report.jsonl` (+ `.report.html`, + a hit log).

---

## 2. Target config — the `rest` generator (the integration point)

We are black-box over HTTP, so we use `rest.RestGenerator`, configured by a JSON
**option file** with this exact nesting (`{family: {Class: {params}}}`),
verbatim from `configurable.rst`:

```json
{
    "rest": {
        "RestGenerator": {
            "name": "example service",
            "uri": "https://127.0.0.1/llm",
            "method": "post",
            "headers": { "X-Authorization": "$KEY" },
            "req_template_json_object": { "text": "$INPUT" },
            "response_json": true,
            "response_json_field": "text"
        }
    }
}
```

### 2.1 `RestGenerator.DEFAULT_PARAMS` (verbatim from `generators/rest.py`)
```python
DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
    "headers": {},
    "method": "post",
    "ratelimit_codes": [429],
    "skip_codes": [],
    "response_json": False,
    "response_json_field": None,
    "req_template": "$INPUT",
    "request_timeout": 20,
    "proxies": None,
    "verify_ssl": True,
    "client_cert": None,
    "client_key": None,
    "client_key_passphrase_env_var": None,
}
```

| Field | Default | Notes |
|---|---|---|
| `uri` | **required** | target URL (`baseurl`+`path` from recon). |
| `name` | = `uri` | friendly name. |
| `method` | `post` | get/post/put/patch/options/delete/head. |
| `headers` | `{}` | values support `$KEY`/`$INPUT` templating. |
| `req_template` | `"$INPUT"` | raw body template (string). |
| `req_template_json_object` | `None` | dict body; serialized to JSON then templated. **We use this.** |
| `response_json` | `False` | parse response as JSON and extract a field. |
| `response_json_field` | `None` | field name or JSONPath (see §2.3). |
| `request_timeout` | `20` | seconds. |
| `ratelimit_codes` | `[429]` | trigger backoff. |
| `skip_codes` | `[]` | return None (no error) for these statuses. |
| `verify_ssl` | `True` | bool or CA-bundle path. |
| `api_key` / `key_env_var` | env `REST_API_KEY` | only needed if `$KEY` is used. |

### 2.2 Templating ($INPUT / $KEY)
- `$INPUT` → the probe prompt. **JSON-escaped via `json.dumps()`** (quotes trimmed), so embedding it inside a JSON string context (`"content": "$INPUT"`) is safe even with quotes/newlines in the payload.
- `$KEY` → API key from `REST_API_KEY` (or `key_env_var`); JSON-escaped in JSON bodies. Only required when referenced.
- Templating is **string substitution on the serialized JSON**, so a *nested* `$INPUT` (e.g. inside `messages[0].content`) works fine.

### 2.3 Response extraction
- `response_json: false` → whole body returned as the output string.
- `response_json: true` + `response_json_field`:
  - not starting with `$` → treated as a top-level dict key / list index.
  - **starting with `$` → JSONPath.** Single match → the value; multiple → list; none → logs error, returns None.

### 2.4 Request templates built from recon's `ai_interface_type` (§2.3 payoff)
The adapter builds the `rest` body + `response_json_field` from the endpoint type:

| `ai_interface_type` | `req_template_json_object` | `response_json_field` |
|---|---|---|
| `llm-chat` (OpenAI-compat `/v1/chat/completions`) | `{"model":"<id>","messages":[{"role":"user","content":"$INPUT"}]}` | `$.choices[0].message.content` |
| `llm-completion` (`/v1/completions`) | `{"model":"<id>","prompt":"$INPUT"}` | `$.choices[0].text` |
| Ollama chat (`/api/chat`) | `{"model":"<id>","messages":[{"role":"user","content":"$INPUT"}],"stream":false}` | `$.message.content` |
| Ollama generate (`/api/generate`) | `{"model":"<id>","prompt":"$INPUT","stream":false}` | `$.response` |
| Anthropic (`/v1/messages`) | `{"model":"<id>","max_tokens":512,"messages":[{"role":"user","content":"$INPUT"}]}` | `$.content[0].text` |

`<id>` comes from `ai_model_ids` / `ai_model_family_guess`. `method: post`,
`headers: {"Content-Type":"application/json"}` (+ `Authorization: Bearer $KEY` if a key is in scope).

---

## 3. Output contract — `report.jsonl` (the parse target)

JSONL; one JSON object per line; each has an `entry_type`. We care about two.

### 3.1 `attempt` entry — `Attempt.as_dict()` verbatim (`garak/attempt.py`)
```python
return {
    "entry_type": "attempt",
    "uuid": str(self.uuid),
    "seq": self.seq,
    "status": self.status,
    "probe_classname": self.probe_classname,
    "probe_params": self.probe_params,
    "targets": self.targets,
    "prompt": asdict(self.prompt) if self.prompt is not None else None,
    "outputs": [asdict(output) if output else None for output in self.outputs],
    "detector_results": {k: list(v) for k, v in self.detector_results.items()},
    "notes": notes,
    "goal": self.goal,
    "conversations": [asdict(c) for c in self.conversations],
    "reverse_translation_outputs": [...],
}
```
- `status`: `0` = ATTEMPT_NEW (not sent), `1` = ATTEMPT_STARTED (response, not evaluated), `2` = ATTEMPT_COMPLETE (response + evaluated).
- `detector_results`: `{detector_name: [score_per_output, ...]}`, scores are floats; **score ≥ threshold (default 0.5) = a hit** (attack succeeded).
- `prompt` / `outputs`: **dataclass dicts** on `main` (Conversation/Turn/Message), NOT plain strings — version-sensitive; only needed for transcript drill-down, not ASR.

### 3.2 `eval` entry — verbatim (`garak/evaluators/base.py`)
```python
eval_record = {
    "entry_type": "eval",
    "probe": self.probename,
    "detector": detector,
    "passed": passes,
    "fails": fails,
    "nones": nones,
    "total_evaluated": outputs_evaluated,
    "total_processed": outputs_processed,
}
# optional: confidence_method="bootstrap", confidence, confidence_upper/lower
```
- **`passed`** = model **resisted** (safe). **`fails`** = attack **hit** (success). `nones` = un-scoreable.
- One `eval` row per (probe, detector) pair, written when the pair completes.

### 3.3 Other entries
`start_run`/`setup`/`init` (once at top: run params, start time, probe repetitions), `completion` (once at end: run finished OK), `digest`. We read these only for the reproducibility envelope (garak version, seed).

---

## 4. ASR computation (what the normalizer consumes)

Per garak's own formula: `failrate = 100 * (evals - passes) / evals`, i.e.

```
ASR(probe, detector) = fails / total_evaluated        # guard total_evaluated == 0
```

- **Per-probe ASR** = max ASR across that probe's detectors (a probe is vulnerable if any detector flags); record the winning detector in `evidence`.
- Emit one normalized `Finding` per probe that has any attempts, with:
  - `ai_payload_class = f"garak-{probe_family}"`, `ai_asr = <per-probe ASR>`,
    `ai_trials = total_evaluated`, `ai_oracle_kind = "judge_llm"` if the detector
    used the LLM judge else `"classifier"`/`"contains"`, `ai_owasp_llm_id` mapped
    from probe→OWASP (promptinject→LLM01, dan→LLM01, encoding→LLM01,
    leakreplay→LLM02/LLM07), `ai_transcript_ref = <report.jsonl path>`.
- Threshold to *become a finding* = the run's `asr_threshold` bound (§3 Run bounds).

---

## 5. Determinism levers
- `--seed` fixes RNG; `--generations` fixes trials. Same (seed, generations,
  probe set, generator, model) → comparable ASR.
- String/classifier detectors are deterministic; **judge-based detectors** call a
  model — point those at the local Ollama at temp 0 (no external egress).
- Pin: garak version + probe-pack + model id+digest recorded in the envelope.

## 6. Egress / safety footguns
- The `rest` generator only talks to the configured `uri` (our in-scope target). Good.
- garak may attempt telemetry / hub calls; run offline. Set `--narrow_output` and
  ensure no `--generator` defaults pull hosted models. Judge detectors must be
  pinned to local Ollama (verify no OpenAI default leaks).
- `report_prefix` must point inside our `output/{scan_id}/.../garak/` dir.

## 7. Open items to confirm at fixture capture (before parser is "done")
1. **Exact `report.jsonl` lines** from a pinned garak version run against a real
   endpoint — capture as the parser's golden fixture.
2. Confirm `eval` field names on the pinned version match §3.2 (esp.
   `total_evaluated` vs any rename).
3. Confirm `detector` naming (module.Class) for promptinject/dan/encoding/leakreplay
   so the OWASP + oracle_kind mapping is accurate.
4. Confirm default report path / `--report_prefix` output filename.
5. Confirm judge-detector configuration knob to force local Ollama.
