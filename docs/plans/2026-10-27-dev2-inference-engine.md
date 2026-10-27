# Dev 2: Nebius Token Factory Router & Tavily Threat Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete inference and threat intelligence module that receives code slices from Dev 1's orchestrator, triages them through Nemotron-Nano, enriches them with live CVE data via Tavily, and generates Red-Team exploit tests + Blue-Team patches via Nemotron-Ultra — all with built-in telemetry for Dev 4's HUD.

**Architecture:** Async Python module with two main subsystems: (1) a dual-tier Nebius Token Factory client that routes fast triage to Nemotron-Nano and complex reasoning to Nemotron-Ultra via the OpenAI-compatible API at `api.tokenfactory.nebius.com/v1`, and (2) a two-stage Tavily threat intelligence pipeline using `tavily.search(search_depth="advanced")` + `tavily.extract()`. Both subsystems emit structured telemetry events consumed by Dev 4. All LLM outputs use strict Pydantic/JSON-schema enforcement.

**Tech Stack:** Python 3.10+, `openai` (async), `tavily-python`, `pydantic`, `httpx`, `pytest`, `pytest-asyncio`

**Spec:** `docs/architecture.md` — Section "Person 2: AI & Intelligence Lead", Subsystem B

## Global Constraints

- Python ≥ 3.10, all code typed with `from __future__ import annotations`
- All shared types from `src/common/models.py` — never duplicate or redefine them
- All config from `src/common/config.py` via `load_config()` — never hardcode API keys
- Async-first: all I/O functions are `async def`
- Every function that calls Nebius or Tavily must emit a `TelemetryEvent` to the event callback
- Nemotron model IDs on Nebius Token Factory:
  - **Nano:** `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` ($0.06/1M in, $0.24/1M out, 262K ctx)
  - **Ultra:** `nvidia/Nemotron-3-Ultra-550b-a55b` ($1.00/1M in, $3.00/1M out, 1024K ctx)
- Nebius base URL: `https://api.tokenfactory.nebius.com/v1/`
- Tavily Python SDK: `TavilyClient(api_key=...)`, methods `.search()` and `.extract()`
- Max line length: 100 chars (ruff)
- Tests in `tests/unit/` using `pytest` + `pytest-asyncio`

## Review Focus

1. **Nebius API key missing/invalid at runtime** — the client must raise a clear `ConfigError` on init, not fail deep in an HTTP call
2. **Tavily returning zero results for an obscure CVE** — `search_threat_intel` must return a valid empty `TavilyIntelligence` with no crash, and the pipeline must continue without Tavily enrichment
3. **Nemotron-Ultra returning malformed JSON that doesn't parse into Pydantic** — the prompt must use `response_format={"type": "json_object"}` and the parser must have a retry with a "fix your JSON" follow-up (max 1 retry)
4. **Token/cost telemetry accuracy** — `usage.prompt_tokens` and `usage.completion_tokens` from the API response must be captured, not estimated; cost must be computed from the actual model's pricing tier
5. **Rate limiting or timeout from Nebius/Tavily** — `httpx.TimeoutException` and 429 responses must be caught with exponential backoff (max 3 retries), not crash the pipeline

---

## File Structure

```
src/inference/
├── __init__.py              # Public API re-exports
├── client.py                # NebisClient: async OpenAI-compatible dual-tier wrapper
├── tavily_engine.py         # TavilyThreatEngine: search + extract pipeline
├── triage.py                # Nano triage: filter false positives from CodeSlices
├── red_team.py              # Ultra Red-Team: generate PoC exploit tests
├── blue_team.py             # Ultra Blue-Team: generate surgical patches
├── prompts.py               # All system/user prompt templates
├── schemas.py               # Pydantic response schemas for structured LLM output
├── telemetry.py             # Telemetry event emitter + cost calculator
├── exceptions.py            # Module-specific exceptions

tests/unit/
├── test_client.py           # NebisClient unit tests (mocked API)
├── test_tavily_engine.py    # TavilyThreatEngine tests (mocked Tavily)
├── test_triage.py           # Triage logic tests
├── test_red_team.py         # Red-Team generation tests
├── test_blue_team.py        # Blue-Team generation tests
├── test_prompts.py          # Prompt template tests
├── test_telemetry.py        # Telemetry cost calculation tests
```

---

### Task 1: Exceptions & Telemetry Infrastructure

**Files:**
- Create: `src/inference/exceptions.py`
- Create: `src/inference/telemetry.py`
- Test: `tests/unit/test_telemetry.py`

**Interfaces:**
- Consumes: `TelemetryEvent`, `AgentState` from `src/common/models.py`
- Produces:
  - `InferenceError(Exception)`, `ConfigError(InferenceError)`, `ModelResponseError(InferenceError)`, `ThreatIntelError(InferenceError)`
  - `TelemetryEmitter(callback: Callable[[TelemetryEvent], None])` with method `emit(state, model_used, tokens_used, latency_ms, cost_estimate, tavily_urls, **metadata)`
  - `compute_cost(model_id: str, prompt_tokens: int, completion_tokens: int) -> float`
  - `NEBIUS_PRICING: dict[str, tuple[float, float]]` — maps model ID to (input_cost_per_1M, output_cost_per_1M)

- [ ] **Step 1: Write failing tests for cost calculation and telemetry emission**

```python
# tests/unit/test_telemetry.py
def test_compute_cost_nano():
    cost = compute_cost("nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B", 1000, 500)
    assert abs(cost - (1000 * 0.06 / 1_000_000 + 500 * 0.24 / 1_000_000)) < 1e-9

def test_compute_cost_ultra():
    cost = compute_cost("nvidia/Nemotron-3-Ultra-550b-a55b", 1000, 500)
    assert abs(cost - (1000 * 1.00 / 1_000_000 + 500 * 3.00 / 1_000_000)) < 1e-9

def test_compute_cost_unknown_model():
    cost = compute_cost("unknown/model", 1000, 500)
    assert cost == 0.0

@pytest.mark.asyncio
async def test_telemetry_emitter_calls_callback():
    events = []
    emitter = TelemetryEmitter(callback=lambda e: events.append(e))
    emitter.emit(state=AgentState.NANO_TRIAGE, model_used="nano", tokens_used=100, latency_ms=50.0, cost_estimate=0.001)
    assert len(events) == 1
    assert events[0].state == AgentState.NANO_TRIAGE
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_telemetry.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `src/inference/exceptions.py`**

Four exception classes: `InferenceError(Exception)`, `ConfigError(InferenceError)`, `ModelResponseError(InferenceError)`, `ThreatIntelError(InferenceError)`. Each stores a `message: str` and optional `details: dict`.

- [ ] **Step 4: Implement `src/inference/telemetry.py`**

`NEBIUS_PRICING` dict with the two model IDs. `compute_cost()` does simple arithmetic, returns 0.0 for unknown models. `TelemetryEmitter` wraps a callback, builds a `TelemetryEvent` with `time.time()` timestamp, and calls the callback synchronously.

- [ ] **Step 5: Run tests — verify they pass**

Run: `pytest tests/unit/test_telemetry.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/inference/exceptions.py src/inference/telemetry.py tests/unit/test_telemetry.py
git commit -m "feat(inference): add exceptions and telemetry infrastructure"
```

---

### Task 2: Nebius Token Factory Dual-Tier Client

**Files:**
- Create: `src/inference/client.py`
- Test: `tests/unit/test_client.py`

**Interfaces:**
- Consumes: `NebisConfig` from config, `TelemetryEmitter` from Task 1, `compute_cost` from Task 1
- Produces:
  - `NebisClient(config: NebisConfig, emitter: TelemetryEmitter | None = None)`
  - `async NebisClient.complete_nano(messages: list[dict], response_format: dict | None = None, state: AgentState = AgentState.NANO_TRIAGE) -> NebisResponse`
  - `async NebisClient.complete_ultra(messages: list[dict], response_format: dict | None = None, state: AgentState = AgentState.RED_TEAM_EXPLOIT) -> NebisResponse`
  - `NebisResponse(content: str, model: str, prompt_tokens: int, completion_tokens: int, latency_ms: float, cost: float)` — local dataclass, not in common models

- [ ] **Step 1: Write failing tests for the Nebius client**

```python
# tests/unit/test_client.py — mock openai.AsyncOpenAI
@pytest.mark.asyncio
async def test_complete_nano_returns_structured_response(mock_openai):
    client = NebisClient(config=test_config, emitter=emitter)
    resp = await client.complete_nano(messages=[{"role": "user", "content": "test"}])
    assert resp.model == "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
    assert resp.prompt_tokens > 0

@pytest.mark.asyncio
async def test_complete_ultra_uses_ultra_model(mock_openai):
    client = NebisClient(config=test_config, emitter=emitter)
    resp = await client.complete_ultra(messages=[{"role": "user", "content": "test"}])
    assert resp.model == "nvidia/Nemotron-3-Ultra-550b-a55b"

@pytest.mark.asyncio
async def test_emits_telemetry_on_completion(mock_openai):
    events = []
    emitter = TelemetryEmitter(callback=lambda e: events.append(e))
    client = NebisClient(config=test_config, emitter=emitter)
    await client.complete_nano(messages=[{"role": "user", "content": "test"}])
    assert len(events) == 1
    assert events[0].cost_estimate > 0

def test_raises_config_error_without_api_key():
    with pytest.raises(ConfigError):
        NebisClient(config=NebisConfig(api_key=""))

@pytest.mark.asyncio
async def test_retries_on_rate_limit(mock_openai_rate_limit):
    client = NebisClient(config=test_config)
    resp = await client.complete_nano(messages=[{"role": "user", "content": "test"}])
    assert resp.content  # succeeds after retry
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_client.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `src/inference/client.py`**

- `NebisResponse` dataclass with fields: `content`, `model`, `prompt_tokens`, `completion_tokens`, `latency_ms`, `cost`
- `NebisClient.__init__`: validates API key present (raises `ConfigError`), creates `openai.AsyncOpenAI(api_key=..., base_url="https://api.tokenfactory.nebius.com/v1/")`
- Private `async _complete(model, messages, response_format, state)`:
  - Records `time.perf_counter()` before/after
  - Calls `self._openai.chat.completions.create(model=model, messages=messages, response_format=response_format)`
  - Extracts `usage.prompt_tokens`, `usage.completion_tokens` from response
  - Computes cost via `compute_cost()`
  - Emits telemetry if emitter present
  - Wraps in `NebisResponse`
  - Retry logic: catch `openai.RateLimitError` and `openai.APITimeoutError`, exponential backoff (1s, 2s, 4s), max 3 attempts, then raise `InferenceError`
- `complete_nano()` delegates to `_complete(model=config.nano_model, ...)`
- `complete_ultra()` delegates to `_complete(model=config.ultra_model, ...)`

- [ ] **Step 4: Run tests — verify they pass**

Run: `pytest tests/unit/test_client.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/inference/client.py tests/unit/test_client.py
git commit -m "feat(inference): async Nebius dual-tier client with telemetry and retry"
```

---

### Task 3: Tavily Threat Intelligence Pipeline

**Files:**
- Create: `src/inference/tavily_engine.py`
- Test: `tests/unit/test_tavily_engine.py`

**Interfaces:**
- Consumes: `TavilyConfig` from config, `TavilyIntelligence`, `DependencyInfo`, `VulnAssessment` from models, `TelemetryEmitter` from Task 1
- Produces:
  - `TavilyThreatEngine(config: TavilyConfig, emitter: TelemetryEmitter | None = None)`
  - `async TavilyThreatEngine.search_threat_intel(assessment: VulnAssessment, dependencies: list[DependencyInfo] | None = None) -> TavilyIntelligence`

- [ ] **Step 1: Write failing tests for the Tavily engine**

```python
# tests/unit/test_tavily_engine.py
@pytest.mark.asyncio
async def test_search_returns_intelligence_with_cves(mock_tavily):
    engine = TavilyThreatEngine(config=test_config)
    intel = await engine.search_threat_intel(sample_assessment)
    assert len(intel.cve_ids) > 0
    assert len(intel.advisory_urls) > 0

@pytest.mark.asyncio
async def test_search_with_dependency_queries_package_advisories(mock_tavily):
    deps = [DependencyInfo(name="flask", current_version="2.0.0", manifest_file="requirements.txt")]
    intel = await engine.search_threat_intel(sample_assessment, dependencies=deps)
    assert intel.safe_version != ""

@pytest.mark.asyncio
async def test_returns_empty_intelligence_on_no_results(mock_tavily_empty):
    intel = await engine.search_threat_intel(sample_assessment)
    assert intel.cve_ids == []
    assert intel.mitigation_pattern == ""
    # must not raise

@pytest.mark.asyncio
async def test_emits_telemetry_with_tavily_urls(mock_tavily):
    events = []
    emitter = TelemetryEmitter(callback=lambda e: events.append(e))
    engine = TavilyThreatEngine(config=test_config, emitter=emitter)
    await engine.search_threat_intel(sample_assessment)
    assert len(events) >= 1
    assert len(events[0].tavily_urls) > 0

def test_raises_config_error_without_api_key():
    with pytest.raises(ConfigError):
        TavilyThreatEngine(config=TavilyConfig(api_key=""))
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_tavily_engine.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `src/inference/tavily_engine.py`**

- `__init__`: validates API key, creates `TavilyClient(api_key=...)`
- `_build_search_queries(assessment, dependencies)` → list of query strings:
  - Primary: `"{cwe_id} {vulnerability_type} mitigation CVE"` from assessment
  - Per-dep: `"{dep.name} {dep.current_version} CVE security advisory"` (if dependencies provided)
- `async search_threat_intel(assessment, dependencies)`:
  1. Build queries, call `tavily_client.search(query, search_depth="advanced", max_results=5, include_domains=["nvd.nist.gov", "github.com/advisories", "cve.org"])` for each (run in `asyncio.to_thread` since Tavily SDK is sync)
  2. Collect result URLs, extract CVE IDs via regex `r"CVE-\d{4}-\d{4,}"`
  3. If results found, call `tavily_client.extract(urls=top_3_urls)` to get detailed advisory content (also via `asyncio.to_thread`)
  4. Parse extracted content for safe versions and mitigation patterns
  5. Build and return `TavilyIntelligence`
  6. On any exception: log warning, return empty `TavilyIntelligence()` (never crash the pipeline)
  7. Emit `TelemetryEvent` with `state=TAVILY_ENRICH`, `tavily_urls=fetched_urls`

- [ ] **Step 4: Run tests — verify they pass**

Run: `pytest tests/unit/test_tavily_engine.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/inference/tavily_engine.py tests/unit/test_tavily_engine.py
git commit -m "feat(inference): Tavily threat intelligence pipeline with search + extract"
```

---

### Task 4: Prompt Templates & Response Schemas

**Files:**
- Create: `src/inference/prompts.py`
- Create: `src/inference/schemas.py`
- Test: `tests/unit/test_prompts.py`

**Interfaces:**
- Consumes: `CodeSlice`, `VulnAssessment`, `TavilyIntelligence` from models
- Produces:
  - `build_triage_messages(slice: CodeSlice) -> list[dict]`
  - `build_red_team_messages(assessment: VulnAssessment, intelligence: TavilyIntelligence) -> list[dict]`
  - `build_blue_team_messages(assessment: VulnAssessment, intelligence: TavilyIntelligence, exploit: ExploitTest, failed_patch_error: str | None = None) -> list[dict]`
  - `TriageResponseSchema` — Pydantic model: `is_vulnerable: bool, confidence: float, vulnerability_type: str, cwe_id: str, reasoning: str`
  - `ExploitResponseSchema` — Pydantic model: `test_code: str, test_filename: str, exploit_description: str`
  - `PatchResponseSchema` — Pydantic model: `diff: str, patch_description: str, files_modified: list[str]`
  - `TRIAGE_JSON_SCHEMA`, `EXPLOIT_JSON_SCHEMA`, `PATCH_JSON_SCHEMA` — `dict` versions for OpenAI `response_format`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_prompts.py
def test_triage_messages_contain_function_body():
    msgs = build_triage_messages(sample_slice)
    user_msg = next(m for m in msgs if m["role"] == "user")
    assert sample_slice.function_body in user_msg["content"]

def test_red_team_messages_include_cve_context():
    msgs = build_red_team_messages(sample_assessment, sample_intel)
    combined = " ".join(m["content"] for m in msgs)
    assert "CVE-" in combined or sample_intel.mitigation_pattern in combined

def test_blue_team_messages_include_exploit_code():
    msgs = build_blue_team_messages(sample_assessment, sample_intel, sample_exploit)
    combined = " ".join(m["content"] for m in msgs)
    assert "def test_" in combined

def test_blue_team_retry_includes_error():
    msgs = build_blue_team_messages(sample_assessment, sample_intel, sample_exploit, failed_patch_error="SyntaxError line 42")
    combined = " ".join(m["content"] for m in msgs)
    assert "SyntaxError" in combined

def test_triage_schema_validates():
    obj = TriageResponseSchema(is_vulnerable=True, confidence=0.9, vulnerability_type="SQLi", cwe_id="CWE-89", reasoning="...")
    assert obj.is_vulnerable

def test_exploit_schema_validates():
    obj = ExploitResponseSchema(test_code="def test_exploit(): ...", test_filename="test_exploit.py", exploit_description="...")
    assert "def test_" in obj.test_code
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_prompts.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `src/inference/schemas.py`**

Three Pydantic models (`TriageResponseSchema`, `ExploitResponseSchema`, `PatchResponseSchema`) plus a helper `to_openai_json_schema(model_class) -> dict` that produces the `{"type": "json_object"}` format with schema description in the system prompt.

- [ ] **Step 4: Implement `src/inference/prompts.py`**

Three prompt builders:
- `build_triage_messages`: system prompt instructs Nemotron-Nano to act as a security triage analyst, evaluate if the code slice is genuinely vulnerable or a false positive, respond in JSON matching `TriageResponseSchema`. User message contains the `CodeSlice` fields.
- `build_red_team_messages`: system prompt instructs Nemotron-Ultra to act as a Red-Team penetration tester, write a self-contained `pytest` function that exploits the vulnerability, respond in JSON matching `ExploitResponseSchema`. User message contains the code slice, assessment, and Tavily intelligence context.
- `build_blue_team_messages`: system prompt instructs Nemotron-Ultra to act as a Blue-Team security engineer, produce a minimal surgical unified diff that fixes the vulnerability without breaking existing behavior, respond in JSON matching `PatchResponseSchema`. User message contains code slice, exploit test, and Tavily advisory. If `failed_patch_error` is provided, append it as a "your previous patch failed with this error, fix it" instruction.

- [ ] **Step 5: Run tests — verify they pass**

Run: `pytest tests/unit/test_prompts.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/inference/prompts.py src/inference/schemas.py tests/unit/test_prompts.py
git commit -m "feat(inference): prompt templates and Pydantic response schemas"
```

---

### Task 5: Nano Triage Module

**Files:**
- Create: `src/inference/triage.py`
- Test: `tests/unit/test_triage.py`

**Interfaces:**
- Consumes: `NebisClient.complete_nano` from Task 2, `build_triage_messages` from Task 4, `TriageResponseSchema` from Task 4, `CodeSlice`, `VulnAssessment` from models
- Produces:
  - `async triage_slice(client: NebisClient, slice: CodeSlice) -> VulnAssessment`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_triage.py
@pytest.mark.asyncio
async def test_triage_returns_vuln_assessment(mock_nebis_client):
    result = await triage_slice(mock_nebis_client, sample_slice)
    assert isinstance(result, VulnAssessment)
    assert result.slice == sample_slice
    assert result.confidence >= 0.0

@pytest.mark.asyncio
async def test_triage_handles_malformed_json_with_retry(mock_nebis_client_bad_json_then_good):
    result = await triage_slice(mock_nebis_client_bad_json_then_good, sample_slice)
    assert isinstance(result, VulnAssessment)
    # should have retried once

@pytest.mark.asyncio
async def test_triage_raises_on_persistent_bad_json(mock_nebis_client_always_bad):
    with pytest.raises(ModelResponseError):
        await triage_slice(mock_nebis_client_always_bad, sample_slice)
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_triage.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `src/inference/triage.py`**

- `async triage_slice(client, slice)`:
  1. Build messages via `build_triage_messages(slice)`
  2. Call `client.complete_nano(messages, response_format={"type": "json_object"})`
  3. Parse `resp.content` into `TriageResponseSchema` via `json.loads` + Pydantic
  4. On `json.JSONDecodeError` or `pydantic.ValidationError`: retry once with a follow-up message asking the model to fix its JSON
  5. On second failure: raise `ModelResponseError`
  6. Convert to `VulnAssessment(slice=slice, **parsed_fields)` and return

- [ ] **Step 4: Run tests — verify they pass**

Run: `pytest tests/unit/test_triage.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/inference/triage.py tests/unit/test_triage.py
git commit -m "feat(inference): Nemotron-Nano triage with JSON repair retry"
```

---

### Task 6: Red-Team Exploit Generator

**Files:**
- Create: `src/inference/red_team.py`
- Test: `tests/unit/test_red_team.py`

**Interfaces:**
- Consumes: `NebisClient.complete_ultra` from Task 2, `build_red_team_messages` from Task 4, `ExploitResponseSchema` from Task 4, `VulnAssessment`, `TavilyIntelligence`, `ExploitTest` from models
- Produces:
  - `async generate_exploit(client: NebisClient, assessment: VulnAssessment, intelligence: TavilyIntelligence) -> ExploitTest`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_red_team.py
@pytest.mark.asyncio
async def test_generates_exploit_test(mock_nebis_client):
    exploit = await generate_exploit(mock_nebis_client, sample_assessment, sample_intel)
    assert isinstance(exploit, ExploitTest)
    assert "def test_" in exploit.test_code
    assert exploit.test_filename.endswith(".py")

@pytest.mark.asyncio
async def test_exploit_includes_description(mock_nebis_client):
    exploit = await generate_exploit(mock_nebis_client, sample_assessment, sample_intel)
    assert exploit.exploit_description != ""

@pytest.mark.asyncio
async def test_exploit_handles_json_repair(mock_nebis_client_bad_then_good):
    exploit = await generate_exploit(mock_nebis_client_bad_then_good, sample_assessment, sample_intel)
    assert isinstance(exploit, ExploitTest)
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_red_team.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `src/inference/red_team.py`**

- `async generate_exploit(client, assessment, intelligence)`:
  1. Build messages via `build_red_team_messages(assessment, intelligence)`
  2. Call `client.complete_ultra(messages, response_format={"type": "json_object"}, state=AgentState.RED_TEAM_EXPLOIT)`
  3. Parse into `ExploitResponseSchema`, same retry-once logic as triage
  4. Convert to `ExploitTest` and return

- [ ] **Step 4: Run tests — verify they pass**

Run: `pytest tests/unit/test_red_team.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/inference/red_team.py tests/unit/test_red_team.py
git commit -m "feat(inference): Red-Team exploit generator via Nemotron-Ultra"
```

---

### Task 7: Blue-Team Patch Synthesizer

**Files:**
- Create: `src/inference/blue_team.py`
- Test: `tests/unit/test_blue_team.py`

**Interfaces:**
- Consumes: `NebisClient.complete_ultra` from Task 2, `build_blue_team_messages` from Task 4, `PatchResponseSchema` from Task 4, `VulnAssessment`, `TavilyIntelligence`, `ExploitTest`, `PatchDiff` from models
- Produces:
  - `async generate_patch(client: NebisClient, assessment: VulnAssessment, intelligence: TavilyIntelligence, exploit: ExploitTest, failed_patch_error: str | None = None) -> PatchDiff`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_blue_team.py
@pytest.mark.asyncio
async def test_generates_patch_diff(mock_nebis_client):
    patch = await generate_patch(mock_nebis_client, sample_assessment, sample_intel, sample_exploit)
    assert isinstance(patch, PatchDiff)
    assert patch.diff != ""
    assert len(patch.files_modified) > 0

@pytest.mark.asyncio
async def test_retry_patch_includes_error_context(mock_nebis_client):
    patch = await generate_patch(
        mock_nebis_client, sample_assessment, sample_intel, sample_exploit,
        failed_patch_error="AssertionError: test_user_lookup failed"
    )
    assert isinstance(patch, PatchDiff)

@pytest.mark.asyncio
async def test_patch_handles_json_repair(mock_nebis_client_bad_then_good):
    patch = await generate_patch(mock_nebis_client_bad_then_good, sample_assessment, sample_intel, sample_exploit)
    assert isinstance(patch, PatchDiff)
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_blue_team.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `src/inference/blue_team.py`**

- `async generate_patch(client, assessment, intelligence, exploit, failed_patch_error=None)`:
  1. Build messages via `build_blue_team_messages(assessment, intelligence, exploit, failed_patch_error)`
  2. Call `client.complete_ultra(messages, response_format={"type": "json_object"}, state=AgentState.BLUE_TEAM_PATCH)`
  3. Parse into `PatchResponseSchema`, same retry-once logic
  4. Convert to `PatchDiff` and return

Note: the `failed_patch_error` parameter is how Dev 1's orchestrator feeds back sandbox regression errors for the self-healing retry loop.

- [ ] **Step 4: Run tests — verify they pass**

Run: `pytest tests/unit/test_blue_team.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/inference/blue_team.py tests/unit/test_blue_team.py
git commit -m "feat(inference): Blue-Team patch synthesizer with self-healing retry support"
```

---

### Task 8: Module Public API & Integration Wiring

**Files:**
- Modify: `src/inference/__init__.py`
- Create: `tests/unit/test_inference_integration.py`

**Interfaces:**
- Consumes: everything from Tasks 1–7
- Produces:
  - `InferenceEngine(config: VulnOSConfig, on_telemetry: Callable[[TelemetryEvent], None] | None = None)` — façade class
  - `async InferenceEngine.triage(slice: CodeSlice) -> VulnAssessment`
  - `async InferenceEngine.enrich(assessment: VulnAssessment, dependencies: list[DependencyInfo] | None = None) -> TavilyIntelligence`
  - `async InferenceEngine.generate_exploit(assessment: VulnAssessment, intelligence: TavilyIntelligence) -> ExploitTest`
  - `async InferenceEngine.generate_patch(assessment: VulnAssessment, intelligence: TavilyIntelligence, exploit: ExploitTest, failed_patch_error: str | None = None) -> PatchDiff`

- [ ] **Step 1: Write failing integration test**

```python
# tests/unit/test_inference_integration.py
@pytest.mark.asyncio
async def test_full_pipeline_triage_to_patch(mock_all_apis):
    engine = InferenceEngine(config=test_config, on_telemetry=lambda e: telemetry_log.append(e))
    
    assessment = await engine.triage(sample_slice)
    assert assessment.is_vulnerable
    
    intel = await engine.enrich(assessment)
    assert isinstance(intel, TavilyIntelligence)
    
    exploit = await engine.generate_exploit(assessment, intel)
    assert "def test_" in exploit.test_code
    
    patch = await engine.generate_patch(assessment, intel, exploit)
    assert patch.diff != ""
    
    assert len(telemetry_log) >= 4  # triage + enrich + exploit + patch

@pytest.mark.asyncio
async def test_retry_patch_flow(mock_all_apis):
    engine = InferenceEngine(config=test_config)
    # ... same setup ...
    patch2 = await engine.generate_patch(assessment, intel, exploit, failed_patch_error="test regression")
    assert patch2.diff != ""
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `pytest tests/unit/test_inference_integration.py -v`
Expected: ImportError / FAIL

- [ ] **Step 3: Implement `InferenceEngine` façade in `src/inference/__init__.py`**

- `__init__`: creates `TelemetryEmitter`, `NebisClient`, `TavilyThreatEngine` from config
- Four methods delegate to the underlying modules from Tasks 3–7
- Re-export all public types so consumers do `from src.inference import InferenceEngine, ...`

- [ ] **Step 4: Run all tests**

Run: `pytest tests/unit/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/inference/__init__.py tests/unit/test_inference_integration.py
git commit -m "feat(inference): InferenceEngine façade and full integration wiring"
```

---

### Task 9: Update Config for Correct Nebius Model IDs & Push

**Files:**
- Modify: `src/common/config.py` — update default model IDs to match actual Nebius Token Factory catalog
- Modify: `.env.example` — update model names

**Interfaces:**
- Consumes: nothing new
- Produces: corrected config defaults that match Nebius Token Factory

- [ ] **Step 1: Update `src/common/config.py`**

Change `nano_model` default to `"nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"` and `ultra_model` default to `"nvidia/Nemotron-3-Ultra-550b-a55b"`. Update `api_base` default to `"https://api.tokenfactory.nebius.com/v1/"`.

- [ ] **Step 2: Update `.env.example`**

Update model names and base URL to match.

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: ALL PASS

- [ ] **Step 4: Commit and push**

```bash
git add src/common/config.py .env.example
git commit -m "fix(config): correct Nebius model IDs and Token Factory base URL"
git push origin main
```
