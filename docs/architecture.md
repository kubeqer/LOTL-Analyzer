# Architecture

## The cascade

The system is a three-tier cascading detector. Each tier is precision-aware
on its own terms: YARA is precision-first, ML is rank/triage, LLM+RAG is
semantic verification with citation:

```
Tier 1: YARA rules (precision ≈ 0.99999, low recall)
   ↓ events that pass YARA
Tier 2: ML model (XGBoost trained in apps/log_analyzer_ml/) — ranks by P(LOTL)
   ↓ top-K% by score
Tier 3: LLM + RAG over LOLBAS + advisory feeds (final precision pass)
   ↓ confirmed
   ECS alert into Elasticsearch
```

Tier 1 and Tier 3 are implemented by the **backend** (`apps/backend/`).
Tier 2 is trained offline by the **ML pipeline** (`apps/log_analyzer_ml/`)
and consumed by the backend as a saved XGBoost artifact. The ML tier's
role is to **compress the post-YARA event stream** by ~10–100× so the
expensive LLM tier only sees ranked candidates, not the firehose. This
shapes how the model is evaluated: the canonical "is this model good?"
question is *ranking quality*, not single-threshold precision. See M-10
in [decisions.md](decisions.md).

## Component map

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Windows endpoint                              │
│                                                                     │
│   Sysmon driver  ──► Microsoft-Windows-Sysmon/Operational           │
│                                  │                                  │
│                                  ▼                                  │
│                       apps/sysmon_agent (Rust)                       │
│                       - reads channel via wevtapi                   │
│                       - parses BinXML → SysmonEvent                 │
│                       - sanitizes secrets in CommandLine            │
│                       - batches and POSTs JSON                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ HTTPS, JSON batches
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  apps/backend (FastAPI, single process)              │
│                                                                     │
│   POST /ingest  ──► per-host 60s buffer                             │
│                            │                                        │
│                            ▼                                        │
│                  detect_lotl_attack(SysmonEvents)                   │
│                    YARA  ─►  ML  ─►  LLM+RAG                        │
│                            │                                        │
│                            ▼                                        │
│                  generate_alert (LLM report)                        │
│                            │                                        │
│                            ▼                                        │
│                  send_alert → Elasticsearch (ECS)                   │
│                                                                     │
│   RAG service (in-process, APScheduler, 24h)                        │
│     scrapers: LOLBAS JSON + CISA advisory feeds                     │
│     embeddings: sentence-transformers (thread-offloaded)            │
│     store: persistent Chroma on disk                                │
│                                                                     │
│   Admin: GET /rag/status, POST /rag/refresh                         │
└─────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
                     Elasticsearch / Kibana
                     (index: lotl-alerts, ECS shape)


┌─────────────────────────────────────────────────────────────────────┐
│                      Offline training host                          │
│                                                                     │
│   Public corpora ──► scripts/download_datasets.sh                   │
│   (OTRF, Splunk,         │                                          │
│    EVTX-ATTACK)          ▼                                          │
│                    datasets/                                        │
│                          │                                          │
│                          ▼                                          │
│   apps/log_analyzer_ml/prepare.py                                    │
│     - extracts ZIPs, runs evtx_dump, writes manifest.json per       │
│       capture, normalizes filenames                                 │
│                          │                                          │
│                          ▼                                          │
│   apps/log_analyzer_ml/main.py                                       │
│     loaders → label_records → build_features →                      │
│       capture_split → train_xgb → evaluate                          │
│     │                                                               │
│     └─► MLflow (data/mlruns/) + data/lotl_xgb.json                  │
│                                       + data/lotl_xgb.sidecar.json  │
└─────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
                            Backend loads as black-box artifact
                            (LOTL_ML_MODEL_PATH, LOTL_ML_SIDECAR_PATH)
```

## The three halves

### Agent (`apps/sysmon_agent/`)

Rust binary that runs as a Windows service or scheduled task. Responsibilities:

- **Read**: subscribe to `Microsoft-Windows-Sysmon/Operational` via `wevtapi`,
  bookmarked by `EventRecordID` so restarts don't lose or duplicate events.
- **Parse**: BinXML to a flat record — `record_id`, `event_id`, `level`,
  `provider`, `channel`, `computer`, `time_created`, and a flat
  `data: BTreeMap<String, String>` of EventData fields. See
  [`apps/sysmon_agent/src/event.rs`](../apps/sysmon_agent/src/event.rs).
- **Sanitize**: redact common secret patterns in `CommandLine` /
  `ParentCommandLine` before they leave the host. See
  [`apps/sysmon_agent/src/sanitizer.rs`](../apps/sysmon_agent/src/sanitizer.rs).
- **Ship**: batch and POST to a configurable HTTP endpoint with retries.

The agent's JSON shape (`{agent, version, host_ip, events: [...]}`) is
what the backend's `/ingest` endpoint accepts. The pipeline's `agent`
loader dialect expects the same per-event shape, which makes the agent
and ML pipeline naturally compatible.

### ML pipeline (`apps/log_analyzer_ml/`)

Python package + two scripts (`prepare.py` and `main.py`). Each module has a
single responsibility:

| Module | File | Purpose |
|---|---|---|
| Canonical schema | `train_utils/schema.py` | `SysmonRecord` dataclass; mirrors agent JSON shape |
| LOLBAS catalog | `train_utils/lolbas.py` | LOLBin set, LOTL T-code set, `parent_technique()` rollup |
| Loaders | `train_utils/loaders.py` | `agent` / `mordor` / `attack_data` / `evtx` dialects |
| Labeling | `train_utils/labeling.py` | LOLBAS ∩ ATT&CK + process-tree propagation |
| Features | `train_utils/features.py` | 3-layer dense features + 1024-dim hashed char n-grams |
| Splits | `train_utils/splitting.py` | Stratified capture-grouped K-fold + feature-cluster stratum refinement |
| Training | `train_utils/train.py` | XGBoost with `scale_pos_weight`; tracks aucpr+logloss, early stop on logloss |
| Evaluation | `train_utils/evaluate.py` | Event- and capture-level reports: PR/ROC-AUC, F1, precision floors, recall-at-top-K |
| Pipeline glue | `train_utils/pipeline.py` | `load_sources` / `load_and_label` / `build_strata` — source enumeration, labeling, technique + feature-cluster strata |
| CV loop | `train_utils/cv.py` | `run_cv` per-fold train+evaluate, `log_cv_block` cross-fold MLflow logging |
| Tracking | `train_utils/tracking.py` | `save_best_model` (native JSON + sidecar) and `log_top_features` |

`main.py` is glue that wires these together; all knobs (`SEED`, `N_FOLDS`,
`MAX_DEPTH`, …) are constants at the top of `main.py` and logged to MLflow.
The training pipeline emits two files the backend depends on:
`data/lotl_xgb.json` (XGBoost booster) and `data/lotl_xgb.sidecar.json`
(feature schema metadata).

### Backend (`apps/backend/`)

FastAPI service. Single process. One Sysmon ingest endpoint plus two
admin endpoints for the in-process RAG service:

| Module | File | Purpose |
|---|---|---|
| App | `lotl_backend/app.py` | FastAPI app, lifespan, routes |
| Config | `lotl_backend/config.py` | pydantic_settings (`LOTL_*` env vars + `.env`) |
| Schemas | `lotl_backend/schema.py` | `SysmonEvent`, `IngestPayload`, `SysmonEvents`, `Alert` |
| Buffer | `lotl_backend/buffer.py` | Per-host 60s windowing with `asyncio.Lock`s |
| Pipeline | `lotl_backend/pipeline.py` | `detect_lotl_attack` cascade |
| YARA | `lotl_backend/detectors/yara_detector.py` | rule compilation + match |
| ML | `lotl_backend/detectors/ml_detector.py` | loads model as black-box artifact |
| ML features | `lotl_backend/detectors/features.py` | ported feature extraction (no `train_utils` import) |
| LLM+RAG | `lotl_backend/detectors/rag_detector.py` | retrieval + verdict JSON |
| LLM client | `lotl_backend/llm.py` | OpenAI-compatible async client |
| Alerts | `lotl_backend/alerts.py` | LLM-generated ECS doc + HTTP shipper |
| RAG service | `lotl_backend/rag/*.py` | scrapers, embeddings, store, scheduler |

See [backend.md](backend.md) for the full design rationale.

## Canonical event schema

Both the agent and the loaders converge on this shape:

```python
SysmonRecord(
    record_id:    int,           # monotonic, from Sysmon EventRecordID
    event_id:     int,           # 1=process create, 3=net connect, 11=file create, …
    time_created: datetime,
    data:         dict[str, str],  # flat Sysmon EventData fields
    computer:     str,
    capture_id:   str,           # which capture this event came from
    capture_techniques: tuple[str, ...],  # MITRE T-codes from manifest.json
    capture_is_malicious: bool,
    …
)
```

`SysmonRecord` exposes properties for the fields used most often —
`image`, `command_line`, `process_guid`, `parent_process_guid`, etc. — so
downstream code doesn't have to keep typing `record.data["CommandLine"]`.
See [`train_utils/schema.py`](../apps/log_analyzer_ml/train_utils/schema.py).
The backend's `SysmonEvent` (`apps/backend/lotl_backend/schema.py`) is the
Pydantic mirror of the same shape, minus the training-only
`capture_*` fields.

## Data flow on a single ingest call

1. The agent batches Sysmon events (default: up to 128 per batch, or
   every 10s) and POSTs `{agent, version, host_ip, events: [...]}` to
   `/ingest`.
2. The backend picks a host key (prefer `host_ip`, fall back to
   `event.computer`, then `"unknown"`), appends the events to that host's
   60-second buffer, and returns 200 immediately.
3. The first event for a host starts a 60-second timer (one
   `asyncio.create_task` per host). When the timer fires, the buffer
   drains and `detect_lotl_attack(SysmonEvents)` runs.
4. **YARA** scans the event payloads. A match returns `(True,
   [matching_rule_names])` and the cascade short-circuits to alerting.
5. If YARA misses, **ML** ports the feature extraction inline (no
   dependency on `train_utils`), scores each Sysmon process-create
   event, and returns `(max_score >= threshold, max_score)`.
6. If ML misses, **LLM+RAG** runs. By default (`LOTL_LLM_PER_EVENT=true`)
   each unique event is classified independently: per event it retrieves
   top-K chunks from the persistent Chroma store and asks the LLM for
   `{is_attack, confidence, technique, mitre_ids, rationale}` JSON, with up
   to 4 events in flight at once, short-circuiting on the first confident
   attack verdict. With `LOTL_LLM_PER_EVENT=false` it falls back to a single
   whole-window verdict. Either way `is_attack` only sticks when
   `confidence >= LOTL_LLM_MIN_CONFIDENCE`.
7. If any tier detected, the backend asks the LLM for a structured
   incident report (`description`, `mitre_ids`, `involved_processes`,
   `recommended_response`), maps it onto Elastic Common Schema, and
   POSTs to `${LOTL_ELASTICSEARCH_URL}/${LOTL_ELASTICSEARCH_INDEX}/_doc`.

## Data flow on a single training run

1. `main.py` enumerates `SOURCES` and skips paths that don't exist.
2. `load_all` walks each dataset root, picks a loader by dialect, and yields
   `SysmonRecord`s with `capture_id` set to the relative subfolder name.
3. `label_records` finds malicious roots, closes over the
   `ProcessGuid → ParentProcessGuid` graph, and emits a parallel list of
   integer labels.
4. `filter_process_creates` drops everything except Sysmon EID 1 — the rows
   the classifier scores.
5. `build_features` computes dense session/parent-child features in two
   sweeps (one for sibling windows, one for network/file-write windows),
   hashes character 3-5-grams of the CommandLine into 1024 dims, and stacks
   them into a `scipy.sparse.csr_matrix`.
6. Per-capture stratum is computed via `capture_stratum_for_kfold`: each
   malicious capture gets a stratum label = its primary LOTL technique
   rolled up to parent T-code (T1218.005 → T1218); benign captures share
   `"neg"`.
7. `refine_strata_by_feature_cluster` clusters captures *within* each
   stratum by their mean L2-normalized n-gram signature (k-means, k=2-3),
   so similar attack styles spread across folds instead of clumping. Strata
   with fewer than `MIN_CLUSTER_SIZE` captures are left intact.
8. `stratified_capture_kfold` produces `N_FOLDS` train/val/test row-index
   triples. Each capture appears in test exactly once across the K folds;
   val is sampled stratified from the per-fold non-test pool.
9. For each fold: `train_xgb` fits with `scale_pos_weight = neg/pos`,
   tracks both `aucpr` and `logloss` on val, and early-stops on val
   `logloss` (the smoother signal at small val pos counts).
10. For each fold: `evaluate` produces an event-level report and
    `evaluate_capture_level` produces a capture-level report (max-aggregating
    event scores per capture). Both report PR-AUC, ROC-AUC, F1, precision
    floors (p80/p95/p99), and recall-at-top-K (1%, 5%, 10%).
11. Cross-fold mean ± std is logged for every metric in both reports — this
    is the headline summary.
12. The fold with the lowest val `logloss` is saved as the canonical model
    both natively (`data/lotl_xgb.json`) and as an MLflow artifact, alongside
    `data/lotl_xgb.sidecar.json` containing the feature-schema metadata the
    backend reads to keep inference features aligned.
