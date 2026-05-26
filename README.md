# LOTL-Analyzer

A three-part system for detecting Living Off The Land (LOTL) attacks on
Windows hosts via Sysmon telemetry.

- **`apps/sysmon_agent/`** — Rust agent reading the
  `Microsoft-Windows-Sysmon/Operational` event channel, redacting secrets
  in command-line fields, and shipping JSON batches over HTTPS.
- **`apps/log_analyzer_ml/`** — Python ML pipeline that consumes Sysmon
  events from public research corpora, labels each process-creation event
  as LOTL/not-LOTL via LOLBAS ∩ ATT&CK with process-tree propagation, and
  trains an XGBoost classifier with MLflow experiment tracking.
- **`apps/backend/`** — FastAPI detection backend. Ingests Sysmon batches
  from the agent, buffers events per host on a 60-second window, runs the
  three-tier cascade (YARA → ML → LLM+RAG), and ships ECS-shaped alerts
  to Elasticsearch. The RAG service refreshes its LOTL knowledge base
  from LOLBAS + advisory feeds every 24 hours inside the same process.

## Pipeline at a glance

```
Windows host                ingest backend                       SIEM
─────────────               ──────────────                       ────
Sysmon driver  ──HTTPS──►   POST /ingest   ──(60s per host)──►
                                                  │
                                                  ▼
                            YARA → ML → LLM+RAG cascade
                                                  │
                                                  ▼
                            generate_alert (LLM report)
                                                  │
                                                  └──HTTPS──►  Elasticsearch
                                                              (ECS docs in
                                                               lotl-alerts)
```

## Quickstart

### Train the ML model (offline)

```bash
./scripts/download_datasets.sh

cd apps/log_analyzer_ml
uv sync
uv run python prepare.py
uv run python main.py

uv run mlflow ui --backend-store-uri file://$(pwd)/data/mlruns
```

This produces `apps/log_analyzer_ml/data/lotl_xgb.json` plus
`lotl_xgb.sidecar.json`, which the backend loads as a black-box artifact.

### Run the detection backend

```bash
cd apps/backend
uv sync
cp .env.example .env

uv run python main.py
```

The backend serves `POST /ingest`, `GET /healthz`, and the RAG admin
endpoints `GET /rag/status` + `POST /rag/refresh` on port 8080.

## Documentation

See **[docs/](docs/README.md)** for the design-rationale documentation:

- **[docs/overview.md](docs/overview.md)** — the problem and what this project does
- **[docs/architecture.md](docs/architecture.md)** — components, data flow, schema
- **[docs/decisions.md](docs/decisions.md)** — every ML-pipeline design choice with rationale and rejected alternatives
- **[docs/backend.md](docs/backend.md)** — backend design: cascade, RAG service, ELK shipping, configuration
- **[docs/limitations.md](docs/limitations.md)** — known weaknesses, cross-referenced to decisions

Subproject-specific run instructions:

- [apps/sysmon_agent/README.md](apps/sysmon_agent/README.md) — agent setup,
  configuration, Windows prerequisites
- [apps/log_analyzer_ml/README.md](apps/log_analyzer_ml/README.md) — ML
  pipeline run instructions
- [apps/backend/README.md](apps/backend/README.md) — backend run instructions
  and configuration knobs
