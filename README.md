# LOTL-Analyzer

A two-part system for detecting Living Off The Land (LOTL) attacks on
Windows hosts via Sysmon telemetry.

- **`src/sysmon_agent/`** — Rust agent reading the
  `Microsoft-Windows-Sysmon/Operational` event channel, redacting secrets
  in command-line fields, and shipping JSON batches over HTTPS.
- **`src/log_analyzer_ml/`** — Python ML pipeline that consumes Sysmon
  events from public research corpora, labels each process-creation event
  as LOTL/not-LOTL via LOLBAS ∩ ATT&CK with process-tree propagation, and
  trains an XGBoost classifier with MLflow experiment tracking.

## Quickstart

```bash
# 1. clone the three public Sysmon corpora into ./datasets/
./scripts/download_datasets.sh

# 2. normalize them into the canonical schema (writes manifest.json per capture)
cd src/log_analyzer_ml
uv sync
uv run python prepare.py

# 3. train + evaluate
uv run python main.py

# 4. browse runs
uv run mlflow ui --backend-store-uri file://$(pwd)/data/mlruns
# → http://127.0.0.1:5000
```

## Documentation

See **[docs/](docs/README.md)** for the design-rationale documentation:

- **[docs/overview.md](docs/overview.md)** — the problem and what this project does
- **[docs/architecture.md](docs/architecture.md)** — components, data flow, schema
- **[docs/decisions.md](docs/decisions.md)** — every design choice with rationale and rejected alternatives
- **[docs/limitations.md](docs/limitations.md)** — known weaknesses, cross-referenced to decisions

Subproject-specific run instructions:

- [src/sysmon_agent/README.md](src/sysmon_agent/README.md) — agent setup,
  configuration, Windows prerequisites
- [src/log_analyzer_ml/README.md](src/log_analyzer_ml/README.md) — ML
  pipeline run instructions
