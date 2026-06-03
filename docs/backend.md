# Backend design

The `apps/backend/` service is a single FastAPI process that ingests Sysmon
batches from the Rust agent, runs the three-tier YARA → ML → LLM+RAG cascade,
and ships ECS-shaped alerts to Elasticsearch. The RAG knowledge base
refreshes itself every 24 hours inside the same process.

This doc covers the design decisions behind that service — what each piece
does, why it's shaped the way it is, and what was rejected.

## API surface

One ingest endpoint plus two admin endpoints for the RAG service:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/ingest` | Accept a batch of Sysmon events from the agent |
| `GET`  | `/healthz` | Liveness probe |
| `GET`  | `/rag/status` | Chunk count, last-refresh timestamp, refresh cadence |
| `POST` | `/rag/refresh` | Trigger an ingestion cycle now (returns 202) |

There is no `/rag/query` endpoint. The RAG service is internal to the
cascade; the LLM detector calls it directly. The admin endpoints exist
because the design theory requires observability and a manual override
for the scheduler.

The `/ingest` payload mirrors the Rust agent's shipper output verbatim:

```json
{
  "agent": "sysmon_agent",
  "version": "0.1.0",
  "host_ip": "10.0.0.5",
  "events": [
    {
      "record_id": 1, "event_id": 1, "level": 4,
      "provider": "Microsoft-Windows-Sysmon",
      "channel":  "Microsoft-Windows-Sysmon/Operational",
      "computer": "WIN-LAB",
      "time_created": "2026-05-17T12:00:00Z",
      "data": {
        "Image": "...", "ParentImage": "...", "CommandLine": "..."
      }
    }
  ]
}
```

The endpoint returns `200 {"accepted": N, "host": host_key}` immediately;
detection runs asynchronously after the 60-second window closes.

## Per-host 60-second windowing

`HostWindowBuffer` (`lotl_backend/buffer.py`) holds one rolling window
per host, keyed by `host_ip` (fall back to `event.computer`, then the
literal string `"unknown"`). When the first event for a host arrives the
buffer schedules a single-shot `asyncio.create_task` that fires 60
seconds later and runs the cascade on whatever has accumulated. Each
host has its own `asyncio.Lock` to serialize buffer mutations and the
final drain.

A `max_buffered_events_per_host` cap (default 10 000) prevents a single
chatty host from exhausting memory; excess events are dropped with a
warning rather than blocking the ingest path.

**Rejected alternative — synchronous per-event detection.** The agent
batches events for efficiency, but the cascade is expensive (an LLM
call, an embedding, a vector query). Running it per-event would either
serialize the agent's batch into latency the agent can't afford, or
force the backend to fan out an unbounded number of background tasks.
The 60s window is the minimum useful aggregation horizon for chains
that span multiple Sysmon events and the largest gap that still lets a
SOC see incidents within the same minute they occurred.

**Rejected alternative — global window across all hosts.** A single
window would conflate process trees from different hosts and make the
ML detector's per-window aggregation meaningless (it would score the
"worst" event across the fleet rather than the worst event on the host
under attack). Per-host isolation keeps the feature semantics correct.

## The cascade

`pipeline.py:detect_lotl_attack` follows the pseudocode laid out in the
requirements one-for-one:

```python
async def detect_lotl_attack(sysmon_events: SysmonEvents) -> None:
    is_detected_yara, yara_hits = detect_yara(sysmon_events)
    if not is_detected_yara:
        is_detected_ml, ml_score = detect_ml(sysmon_events)
        if not is_detected_ml:
            is_detected_rag, rag_verdict = await detect_rag(sysmon_events)
            if not is_detected_rag:
                return
    alert = await generate_alert(...)
    await send_alert(alert)
```

Short-circuit semantics are deliberate: YARA is engineered for
near-zero false positives, so a YARA match must not be second-guessed
by ML or by the LLM. The cascade only escalates to the next tier when
the previous one is silent.

### Tier 1 — YARA

`detectors/yara_detector.py` compiles `*.yar` files from
`detectors/yara_rules/` at startup, concatenates the per-event
`CommandLine`, `ParentCommandLine`, `Image`, `ParentImage`, and
`OriginalFileName` fields, and scans them. The starter rule set
(`lotl_core.yar`) targets the obvious LOTL chains: Office spawning a
shell, encoded PowerShell flags, IEX/download cradles, rundll32/regsvr32
proxy execution, wmic process call create, bitsadmin transfers,
certutil URL cache / decode, mshta with remote scripts, schtasks remote
or hidden tasks, and renamed `powershell.exe`. A match on any rule
flags the entire window.

Rules are added as new `.yar` files in the same directory; no code
changes needed. The compile happens once at app lifespan startup so
runtime scans don't pay the compile cost.

### Tier 2 — ML

`detectors/ml_detector.py` loads the XGBoost booster from
`LOTL_ML_MODEL_PATH` and the sidecar from `LOTL_ML_SIDECAR_PATH`.
Inference goes through `detectors/features.py`, which is a
*deliberately decoupled* port of the training-time feature builder: the
backend has zero Python imports from `log_analyzer_ml` / `train_utils`.
The 18 named dense features and the 1024-dim hashed char n-gram
representation (`analyzer=char_wb`, `ngram_range=(3,5)`,
`alternate_sign=false`, `norm=l2`) match the sidecar exactly.

The detector scores every Sysmon process-create event in the window and
returns `(max_score >= threshold, max_score)`. The default threshold is
`0.5`; tune via `LOTL_ML_THRESHOLD`. Per `project_cascade_architecture`
the ML tier is evaluated by ROC-AUC and recall-at-top-K rather than
precision-at-p95, so the threshold is a deployment knob, not a quality
ceiling.

**Rejected alternative — depend on `log_analyzer_ml` as a Python
package.** It would couple the runtime to the training environment
(pulls MLflow, pandas, the full training pipeline at runtime), and any
schema drift in `train_utils.schema` would silently break the backend.
Treating the model as a file artifact + a tiny ported feature module
draws a clean contract: the backend depends on `lotl_xgb.json` +
`lotl_xgb.sidecar.json`, nothing else.

**Rejected alternative — re-fit the feature pipeline at startup.** The
hashing vectorizer is stateless (no `fit` needed), and the dense
features are hand-engineered; there is nothing to learn at startup. The
port is byte-for-byte compatible with the training-time code.

### Tier 3 — LLM + RAG

`detectors/rag_detector.py` retrieves the top-K most similar chunks from
the persistent Chroma store, builds a context block, and asks the LLM (JSON
schema-constrained response, temperature 0) for:

```json
{
  "is_attack": true/false,
  "confidence": 0.0-1.0,
  "technique": "PowerShell encoded command",
  "mitre_ids": ["T1059.001"],
  "rationale": "..."
}
```

**Per-event vs whole-window.** `LOTL_LLM_PER_EVENT` (default `true`)
selects the granularity:

- *Per-event* (`_detect_per_event`): the window is deduplicated to unique
  events (`MAX_EVENTS_IN_PROMPT=40` cap), and each event is classified on
  its own merits — its own retrieval query, its own LLM call — with an
  `asyncio.Semaphore(LLM_EVENT_CONCURRENCY=4)` bounding concurrency. The
  cascade short-circuits on the first event that returns a confident attack
  verdict; remaining in-flight calls are cancelled. The per-event system
  prompt explicitly tells the model it sees a *single* event in isolation
  and must not assume a broader chain.
- *Whole-window* (`_detect_window`): one LLM call over a block of the whole
  window. The original behavior, kept as a fallback.

A verdict only counts as an attack when
`confidence >= LOTL_LLM_MIN_CONFIDENCE` (default `0.6`); the raw boolean
from the model is gated by that floor in `_build_payload`.

Both system prompts are constrained: treat the knowledge context as
supporting reference material, judge what the event actually *does* rather
than the mere presence of a built-in binary, and keep confidence low when
the signal is weak or ambiguous.

The LLM client (`llm.py`) is the standard `openai.AsyncOpenAI` library
pointed at any OpenAI-compatible endpoint via `LOTL_LLM_BASE_URL`. That
makes the backend compatible with HuggingFace TGI, vLLM, Ollama,
LM Studio, llama.cpp's `llama-server`, etc.

## RAG service

Lives entirely inside the FastAPI process. Five files in
`lotl_backend/rag/`:

| File | Role |
|---|---|
| `store.py` | Persistent Chroma collection (`PersistentClient`) with cosine space |
| `embeddings.py` | `sentence-transformers` model, encode runs in `asyncio.to_thread` |
| `scrapers.py` | LOLBAS JSON + advisory feeds (RSS/Atom via `feedparser`), filtered by LOTL keywords |
| `ingest.py` | One ingestion cycle: fetch → chunk → embed → upsert |
| `service.py` | `query()` + APScheduler 24h job + lifespan start/stop |

**Persistent vector store.** The Chroma store sits on disk at
`LOTL_RAG_STORE_DIR`. Restarts do not reseed if the collection already
has content (`store.count() > 0` skips the seed). This satisfies the
"survive process restart" requirement.

**Deterministic IDs with upsert.** Every chunk gets a SHA-1 of a
stable identifier (`lolbas:{name}:{index}:{command}` or
`advisory:{link or title}`), and chunked variants suffix `:c{n}`. The
ingestion always calls `collection.upsert(...)`; unchanged docs
overwrite themselves harmlessly, new docs add entries. This is the
mechanism that makes the 24-hour schedule safe to repeat — there is no
separate deduplication step.

**Source split: taxonomy vs stream.** LOLBAS is the slow taxonomy
describing *what* a LOLBin is and how it's abused. The advisory feeds
are the fast stream describing *what is being exploited now*; they are
keyword-filtered (`living off the land`, `lolbin`, individual LOLBin
names, etc.) so unrelated CVE noise doesn't drown the store.

**Offloaded embedding.** `sentence-transformers` is CPU-bound and would
block the asyncio event loop. `Embedder.encode` wraps the synchronous
call in `asyncio.to_thread`, which keeps the request path responsive
while a full ingestion cycle runs.

**24-hour scheduler bound to lifespan.** `start_scheduler()` runs in
the FastAPI `lifespan` context manager: it constructs the store
(creating the directory and collection if missing), kicks off a
background seed task when the store is empty, registers the 24h
`IntervalTrigger` job, and starts the scheduler. `stop_scheduler()`
shuts it down cleanly on app exit.

**Failure isolation per scraper.** Each fetcher is wrapped in
`try/except` and degrades to an empty list on error. A dead CISA feed
or a 502 from LOLBAS reduces coverage for this cycle but does not abort
the rest.

**Rejected alternative — separate microservice for the RAG.** The
brief explicitly asked for everything under one FastAPI process. The
escape hatch is documented: if coupling becomes unacceptable, lift
`run_ingestion_cycle` into a standalone entrypoint driven by `cron` /
systemd timer, leaving the API read-only against the same on-disk
Chroma store. No code in the cascade or in `query()` would need to
change.

## Alert generation and ELK shipping

`alerts.py:generate_alert` asks the LLM for a structured incident
report (`description`, `mitre_ids`, `technique`, `involved_processes`,
`recommended_response`) given the window events and the cascade's
intermediate verdicts. The result is mapped onto Elastic Common Schema:

```json
{
  "@timestamp": "...",
  "event": { "kind": "alert", "category": ["intrusion_detection"], ... },
  "host":  { "name": "<host_key>", "id": "<host_key>" },
  "rule":  { "name": "<technique>", "ruleset": "<detected_by>", ... },
  "threat":{ "framework": "MITRE ATT&CK",
             "technique": [{"id": "T1059.001", "name": "..."}] },
  "process": { "involved": [{ "parent": "...", "image": "...", "command_line": "..." }] },
  "lotl":  { "detected_by": "...", "rationale": "...",
             "recommended_response": "...", "raw_event_count": N },
  "tags":  ["lotl", "sysmon", "<tier>"]
}
```

`send_alert` POSTs this document to
`${LOTL_ELASTICSEARCH_URL}/${LOTL_ELASTICSEARCH_INDEX}/_doc` via
`httpx`. There is no authentication — the backend is intended to run
on a trusted network or behind a reverse proxy.

**Rejected alternative — official `elasticsearch` client.** Adds a
heavy dependency and an opinion on how index templates and bulk APIs
should be used. The backend writes one alert at a time at human-scale
volume, so the dependency cost would dwarf the benefit. A future move
to `_bulk` is straightforward if alert volume grows.

**Rejected alternative — raw JSON, ignore ECS.** Kibana, the
Elastic-stack rule engine, and most existing SIEM tooling assume ECS.
Emitting non-ECS docs would force every downstream consumer to
maintain a translation layer.

## Configuration

All knobs live in `lotl_backend/config.py` as a `pydantic_settings`
`BaseSettings` subclass with `env_prefix="LOTL_"`. Override via `.env`
(loaded automatically from `apps/backend/.env`) or `LOTL_*` environment
variables. The `.env.example` lists every knob the service reads.

The categories:

| Group | Knobs |
|---|---|
| Window / buffering | `LOTL_WINDOW_SECONDS`, `LOTL_MAX_BUFFERED_EVENTS_PER_HOST` |
| ML | `LOTL_ML_MODEL_PATH`, `LOTL_ML_SIDECAR_PATH`, `LOTL_ML_THRESHOLD` |
| YARA | `LOTL_YARA_RULES_DIR` |
| LLM | `LOTL_LLM_BASE_URL`, `LOTL_LLM_MODEL`, `LOTL_LLM_API_KEY`, `LOTL_LLM_TIMEOUT_SECONDS`, `LOTL_LLM_REASONING_EFFORT`, `LOTL_LLM_MIN_CONFIDENCE`, `LOTL_LLM_PER_EVENT` |
| RAG | `LOTL_RAG_STORE_DIR`, `LOTL_RAG_COLLECTION`, `LOTL_RAG_EMBED_MODEL`, `LOTL_RAG_REFRESH_HOURS`, `LOTL_RAG_TOP_K`, `LOTL_RAG_CHUNK_SIZE`, `LOTL_RAG_CHUNK_OVERLAP`, `LOTL_LOLBAS_URL`, `LOTL_ADVISORY_FEEDS` |
| ELK | `LOTL_ELASTICSEARCH_URL`, `LOTL_ELASTICSEARCH_INDEX` |

## Lifecycle and failure behavior

**Startup.** The lifespan context manager:

1. Constructs the per-host buffer with the cascade as its `on_window_close`
   handler.
2. Eagerly loads the YARA rules and the ML model so first-request
   latency is not paid by the agent. Failures here are logged but do not
   abort startup — detection degrades to whatever tiers loaded
   successfully.
3. Calls `start_scheduler()` which creates the Chroma store if missing,
   spawns the seed task in the background when the store is empty, and
   registers the 24-hour interval job.
4. Logs `"backend ready"` and yields to FastAPI.

**Steady state.** Ingest requests are O(1) on the backend side: append
to the buffer, return 200. All heavy work (detection, alerting,
ingestion cycles) runs as background tasks.

**Shutdown.** The lifespan exit cancels the APScheduler, then drains
any open windows (running detection on the partial buffers) before the
event loop closes. Hosts that have not had a 60-second window close
yet still get their events processed.

**Per-cycle failure.** If detection raises, the buffer logs the
exception and continues. The cascade itself swallows LLM errors
(returns `is_attack=false`) and ELK shipping errors (returns `False`
from `send_alert`) — the backend never wedges on a flaky downstream.

## What is intentionally out of scope

- **Authentication.** Not in this version. The brief specified no auth;
  add a reverse proxy or API-gateway in front if you need it.
- **Per-source retention.** Old advisories accumulate forever in the
  store. Adding an `ingested_at` timestamp + a "delete past retention
  window" pass would convert the store from accumulate-only to a
  rolling window. Documented as the most likely extension.
- **Multi-process deployment.** The in-process scheduler couples
  ingestion to the worker. The documented escape is to split the
  scheduler into a standalone entrypoint and run the API read-only.
- **External vector database.** Chroma on disk is enough for a single
  process. If you need shared state across replicas, swap the
  `VectorStore` implementation; everything else is store-agnostic.
- **Bulk alert shipping.** One alert per `_doc` POST. Move to `_bulk`
  if alert volume requires it.

Each of these is a known extension point, not a missing feature.
