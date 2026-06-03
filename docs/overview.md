# Overview

## Problem

Endpoint defenses have improved at blocking unsigned, never-before-seen
binaries. Attackers responded by leaning harder on Windows' own toolchain —
`powershell.exe`, `regsvr32.exe`, `mshta.exe`, `wmic.exe`, `certutil.exe`,
`msbuild.exe`, `bitsadmin.exe`, `rundll32.exe`, `msiexec.exe`, and many more.
These binaries are Microsoft-signed, present on every Windows host, and have
legitimate administrative uses, which is why the technique class is called
**Living Off The Land (LOTL)**.

The detection problem is therefore not "is this binary malicious?" (it isn't —
it's signed by Microsoft), but "is *this particular invocation* of a known
LOLBin part of an attack chain?" That framing makes it a binary classification
problem over Sysmon process-creation events with strong class imbalance —
roughly 100:1 benign-to-malicious in production traffic.

## The three-tier cascade

```
Tier 1: YARA  ─► precision-first deterministic rules
   ↓ events that pass YARA
Tier 2: ML   ─► XGBoost ranker (this repo trains it)
   ↓ top-K% by score
Tier 3: LLM + RAG ─► semantic verification against a self-updating
                     knowledge base of LOLBAS + advisory feeds
   ↓ confirmed
   ECS alert into Elasticsearch
```

- **Tier 1** (YARA) is owned by the **backend**. A precision-first rule set
  catches the most blatant LOTL chains (Office spawning a shell, encoded
  PowerShell, mshta with remote scripts, etc.) and routes them straight to
  reporting.
- **Tier 2** (ML) is the **`apps/log_analyzer_ml/`** pipeline trained
  offline; the resulting XGBoost model is consumed by the backend as a
  black-box artifact. Its role is *ranking and triage*, not autonomous
  alerting — it compresses the post-YARA event stream so the expensive
  LLM tier only sees the top K% of candidates. See
  [architecture.md](architecture.md#the-cascade-this-model-lives-in) and
  M-10 in [decisions.md](decisions.md).
- **Tier 3** (LLM + RAG) lives inside the **backend**. The RAG service
  refreshes its knowledge base every 24 hours from LOLBAS + CISA
  advisory feeds, filtered by LOTL keywords. The LLM answers strictly
  from retrieved context. See [backend.md](backend.md).

## What this repo does

- A Rust **Sysmon agent** runs on Windows endpoints, reads the
  `Microsoft-Windows-Sysmon/Operational` event channel, redacts secrets
  in command-line fields, and ships batches over HTTPS. See
  [`apps/sysmon_agent/README.md`](../apps/sysmon_agent/README.md).
- A Python **ML pipeline** consumes Sysmon JSONL — both from the agent
  and from public research corpora (OTRF, Splunk attack_data,
  EVTX-ATTACK-SAMPLES) — labels each process-creation event as
  LOTL/not-LOTL using the LOLBAS catalog intersected with MITRE ATT&CK
  technique IDs, builds a three-layer feature representation, and trains
  an XGBoost classifier. MLflow tracks every run. See
  [`apps/log_analyzer_ml/README.md`](../apps/log_analyzer_ml/README.md).
- A FastAPI **backend** ingests Sysmon batches from the agent, buffers
  events per host for 60 seconds, runs the three-tier cascade, and ships
  ECS-shaped alerts to Elasticsearch. The RAG knowledge base updates
  itself inside the same process on a 24-hour schedule. See
  [`backend.md`](backend.md) and
  [`apps/backend/README.md`](../apps/backend/README.md).

## Quickstart

### Train the ML model

```bash
./scripts/download_datasets.sh

cd apps/log_analyzer_ml
uv sync
uv run python prepare.py
uv run python main.py

uv run mlflow ui --backend-store-uri file://$(pwd)/data/mlruns
```

### Run the detection backend

```bash
cd apps/backend
uv sync
cp .env.example .env

uv run python main.py
```

Prerequisites: `git`, `uv`, optionally `git-lfs` (for Splunk attack_data)
and `cargo` (for `cargo install evtx`, used to convert
EVTX-ATTACK-SAMPLES to JSONL). The backend additionally expects an
OpenAI-compatible LLM endpoint (HuggingFace TGI, vLLM, Ollama, …) and a
reachable Elasticsearch instance.

## What you get

After training:

- `apps/log_analyzer_ml/data/lotl_xgb.json` — the trained XGBoost booster
  from the K-fold fold with the lowest val logloss, saved natively.
- `apps/log_analyzer_ml/data/lotl_xgb.sidecar.json` — feature schema
  metadata (dense feature names, n-gram dims, hashing-vectorizer params)
  used by the backend to keep inference-time features aligned with the
  training-time ones.
- `apps/log_analyzer_ml/data/mlruns/` — the MLflow experiment store. Each
  run contains params, per-fold metrics, cross-fold aggregates, the
  model artifact, and a feature-importance table.
- Console output with PR-AUC, ROC-AUC, F1, recall at precision floors,
  recall at top-K%, and top features by gain. ROC-AUC ≈ 0.81 ± 0.05 at
  capture level is the most stable signal on the current dataset. See
  [decisions.md](decisions.md) M-6, M-7 and
  [limitations.md](limitations.md) L-11.

After running the backend:

- ECS documents in the `lotl-alerts` Elasticsearch index, one per
  confirmed LOTL detection, with `threat.framework=MITRE ATT&CK`,
  involved processes, the LLM-generated description, and a recommended
  response. See [backend.md](backend.md) for the document shape.
- A persistent Chroma vector store on disk under `apps/backend/data/rag_store/`
  containing the embedded LOTL knowledge base. Survives restarts.

## Non-goals

- This is not an EDR product. The backend reports detections to a SIEM;
  it does not isolate hosts or terminate processes.
- This is not malware analysis. The classifier looks at how a process
  was invoked and what surrounds it, not at file hashes or static
  analysis.
- The agent does not implement alerting, deduplication, or aggregation.
  It ships raw events; the backend decides what to do with them.
- No authentication. The ingest endpoint, the RAG admin endpoints, and
  the Elasticsearch shipper all run without auth and are intended for
  trusted networks or to sit behind a reverse proxy.
