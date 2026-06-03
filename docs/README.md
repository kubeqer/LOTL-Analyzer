# LOTL-Analyzer documentation

Documentation for a three-part Sysmon-based LOTL attack detector:

1. **`apps/sysmon_agent/`** — Rust agent reading the
   `Microsoft-Windows-Sysmon/Operational` channel, redacting secrets, and
   shipping JSON batches.
2. **`apps/log_analyzer_ml/`** — Python ML pipeline that consumes public
   Sysmon corpora, labels LOTL events via LOLBAS ∩ ATT&CK with process-tree
   propagation, and trains XGBoost with MLflow tracking.
3. **`apps/backend/`** — FastAPI detection backend that ingests agent
   batches, runs the three-tier cascade (YARA → ML → LLM+RAG), and ships
   ECS-shaped alerts to Elasticsearch. Hosts the in-process RAG service
   that refreshes from LOLBAS + advisory feeds every 24 hours.

## What's here

| Doc | Purpose |
|---|---|
| [overview.md](overview.md) | The problem, what this project does, quickstart |
| [architecture.md](architecture.md) | Components, data flow, canonical schema, module map |
| **[decisions.md](decisions.md)** | **Every ML-pipeline design choice with rationale and rejected alternatives** |
| [backend.md](backend.md) | Backend design: API surface, cascade, RAG service, ELK shipping, configuration |
| [limitations.md](limitations.md) | Known weaknesses, each cross-referenced to the decision it follows from |

The decisions doc is the centerpiece for the ML pipeline — it walks
through every non-trivial choice made while building it (data, labeling,
splits, features, model, tooling, code structure) with context, the
choice itself, rejected alternatives, and a source ("brief" = the
methodology brief anchoring the thesis; "mine" = a judgment call with
stated rationale). The backend doc plays the same role for the runtime
detection service.

## Glossary

- **LOTL** — Living Off The Land. Attacks that abuse pre-installed
  legitimate Windows tooling to bypass signature- and reputation-based
  defenses.
- **LOLBin** — a "Living Off the Land Binary": a Microsoft-signed binary
  that can be coerced into attacker behavior. Cataloged at
  [lolbas-project.github.io](https://lolbas-project.github.io).
- **Sysmon** — Sysinternals tool that emits structured Windows event logs
  for process creation, network connections, file creation, image loads, etc.
- **EID** — Sysmon Event ID. EID 1 = process creation; EID 3 = network
  connection; EID 11 = file create.
- **MITRE ATT&CK technique (T-code)** — e.g. `T1059.001` = PowerShell;
  `T1218.010` = regsvr32 abuse. See [attack.mitre.org](https://attack.mitre.org).
- **PR-AUC** — area under precision–recall curve. Preferred over ROC-AUC on
  highly imbalanced binary problems.
- **ECS** — Elastic Common Schema. The shape `lotl-alerts` documents take
  when shipped to Elasticsearch by the backend.
- **Cascade** — the YARA → ML → LLM+RAG pipeline. YARA is precision-first,
  ML is rank/triage, LLM+RAG provides last-mile semantic verification.
