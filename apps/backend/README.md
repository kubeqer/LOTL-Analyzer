# LOTL-Analyzer Backend

FastAPI service that ingests Sysmon events from the Rust agent and runs them through a three-tier detection cascade (YARA -> ML -> LLM+RAG). Attacks are reported as ECS-shaped alerts to an Elasticsearch index.

## Layout

```
apps/backend/
├── main.py                      uvicorn entrypoint
├── lotl_backend/
│   ├── app.py                   FastAPI app (lifespan, /ingest, /rag/*)
│   ├── config.py                pydantic_settings (knob panel + .env loader)
│   ├── schema.py                SysmonEvent, IngestPayload, SysmonEvents, Alert
│   ├── buffer.py                per-host 60s windowing
│   ├── pipeline.py              detect_lotl_attack cascade
│   ├── llm.py                   OpenAI-compatible async client
│   ├── alerts.py                LLM-generated ECS alert + ELK shipper
│   ├── detectors/
│   │   ├── yara_detector.py
│   │   ├── ml_detector.py       loads XGB model + sidecar as a black-box artifact
│   │   ├── features.py          ported feature extraction (18 dense + 1024 hashed n-grams)
│   │   ├── rag_detector.py
│   │   └── yara_rules/lotl_core.yar
│   └── rag/
│       ├── service.py           scheduler + query
│       ├── ingest.py            24h ingestion cycle
│       ├── scrapers.py          LOLBAS + advisory feeds
│       ├── store.py             persistent Chroma store
│       └── embeddings.py        sentence-transformers (thread-offloaded)
├── Dockerfile                   backend image
├── docker-compose.backend.yml   runs the backend container (port 8080)
├── docker-compose.siem.yml      dev ELK stack (Elasticsearch + Kibana)
├── elk/index-template.json      mapping for the lotl-alerts index
└── .env.example
```

## Run

```bash
uv sync
cp .env.example .env
uv run python main.py
```

## Ingestion endpoint

`POST /ingest` accepts the Rust agent's payload:

```json
{
  "agent": "sysmon_agent",
  "version": "0.1.0",
  "host_ip": "10.0.0.5",
  "events": [
    {
      "record_id": 1,
      "event_id": 1,
      "level": 4,
      "provider": "Microsoft-Windows-Sysmon",
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "computer": "WIN-LAB",
      "time_created": "2026-05-17T12:00:00Z",
      "data": {
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "CommandLine": "cmd.exe /c powershell -enc ..."
      }
    }
  ]
}
```

The endpoint returns 200 immediately. Each host accumulates events in a 60-second window; when the window closes the cascade runs in the background.

## RAG admin

- `GET  /rag/status`   chunk count + last refresh
- `POST /rag/refresh`  trigger an ingestion cycle now (returns 202)

The scheduler reseeds when the persistent Chroma store is empty at startup and refreshes every `LOTL_RAG_REFRESH_HOURS` (default 24) thereafter.

## ELK stack

A self-contained dev stack ships in `docker-compose.siem.yml`:

```bash
docker compose -f docker-compose.siem.yml up -d

# once Elasticsearch is up, apply the lotl-alerts index template
curl -X PUT http://localhost:9200/_index_template/lotl-alerts \
  -H 'Content-Type: application/json' \
  --data-binary @elk/index-template.json
```

This brings up Elasticsearch on `:9200` (auth disabled, single-node) and Kibana on `:5601`. The template in `elk/index-template.json` maps the `lotl-alerts*` index to the ECS fields the shipper emits. The backend's defaults (`LOTL_ELASTICSEARCH_URL=http://localhost:9200`, `LOTL_ELASTICSEARCH_INDEX=lotl-alerts`) line up out of the box.

Open `http://localhost:5601` → Discover → create a data view on `lotl-alerts` to see alerts as they land. Useful first searches: `event.kind: "alert"`, `lotl.detected_by: "yara"`, `threat.technique.id: "T1059.001"`.

To run the backend itself in a container instead of `uv run python main.py`, use `docker compose -f docker-compose.backend.yml up -d` (reads `.env`, exposes port 8080, persists the RAG store in a named volume).

## Configuration

All tunables live in `lotl_backend/config.py`. Override via `.env` or `LOTL_*` env vars. See `.env.example`.

## ML model artifact

The backend treats the XGBoost model as a black-box file (`LOTL_ML_MODEL_PATH`). It does not import `log_analyzer_ml` Python code — feature extraction is reimplemented in `lotl_backend/detectors/features.py` to stay in sync with `lotl_xgb.sidecar.json` (18 named dense features + 1024 hashed char n-grams, `analyzer=char_wb`, `ngram_range=(3,5)`, `alternate_sign=false`, `norm=l2`). Copy `lotl_xgb.json` + `lotl_xgb.sidecar.json` anywhere on disk and point the env vars at them.
