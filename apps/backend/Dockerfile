FROM astral/uv:python3.12-bookworm-slim

WORKDIR /app

COPY apps/backend/ /app/
COPY apps/log_analyzer_ml/data/lotl_xgb.json /models/lotl_xgb.json
COPY apps/log_analyzer_ml/data/lotl_xgb.sidecar.json /models/lotl_xgb.sidecar.json

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH" \
    LOTL_ML_MODEL_PATH=/models/lotl_xgb.json \
    LOTL_ML_SIDECAR_PATH=/models/lotl_xgb.sidecar.json \
    LOTL_RAG_STORE_DIR=/data/rag_store

EXPOSE 8080

CMD ["uvicorn", "lotl_backend.app:app", "--host", "0.0.0.0", "--port", "8080"]
