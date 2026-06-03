# log_analyzer_ml

Binary LOTL (Living Off The Land) attack classifier for Sysmon. Per
process-creation event, predicts whether the event is part of a LOLBin-driven
attack chain.

## Workflow

```bash
# 1. fetch the three public Sysmon corpora into ../../datasets/
#    (run from the repo root; the script lives at scripts/download_datasets.sh)
./scripts/download_datasets.sh

# 2. normalize them into our canonical schema (writes manifest.json per capture)
cd apps/log_analyzer_ml
uv sync
uv run python prepare.py

# 3. train + evaluate
uv run python main.py
```

The trained model is written to `data/lotl_xgb.json` (XGBoost native format)
alongside `data/lotl_xgb.sidecar.json` (feature-schema metadata the backend
reads). Inspect runs with `uv run mlflow ui --backend-store-uri file://$(pwd)/data/mlruns`.

## Data sources

| Source | Where | Native format | Loader dialect |
|---|---|---|---|
| OTRF Security-Datasets | `datasets/Security-Datasets/` | Winlogbeat ECS JSONL inside per-capture ZIPs | `attack_data` |
| Splunk attack_data | `datasets/attack_data/` | XmlWinEventLog → JSON, per-T-code folders | `attack_data` |
| EVTX-ATTACK-SAMPLES | `datasets/EVTX-ATTACK-SAMPLES/` | Native EVTX (converted via `evtx_dump` in `prepare.py`) | `evtx` |

## Labels

`LOTL = 1` for a process-creation event when EITHER:

1. `basename(Image)` or `OriginalFileName` is in the curated LOLBAS catalog
   AND the capture is flagged malicious, OR
2. The capture maps to a canonical LOTL technique (T1059/T1218/T1127/T1216/
   T1220/T1197/T1047/T1140/T1105/T1027/T1053.005/T1490/T1548.002) AND the
   process is a descendant of the malicious root in the process tree
   (closure over `ProcessGuid` → `ParentProcessGuid`).

The classifier scores only Sysmon EID 1 (process creation) — everything else
is dropped before training.

## Splits

Stratified, capture-grouped **K-fold** (`N_FOLDS=5`,
`stratified_capture_kfold`). Every event from a `capture_id` stays in one
fold — random per-event splits leak via shared `ProcessGuid` chains, sibling
clusters, and host artifacts. Captures are stratified by primary LOTL
technique (rolled up to parent T-code) and then refined into sub-strata by
k-means over each capture's mean n-gram signature, so similar attack styles
spread across folds instead of clumping. Each capture lands in the test fold
exactly once; the cross-fold mean ± std is the headline metric. The **test
set is held at natural imbalance**; only training may be downsampled. See
`decisions.md` D-7/M-7/M-8 for the rationale.

## Layout

```
log_analyzer_ml/
├── pyproject.toml
├── main.py                      # glue: load → label → features → split → CV → save
├── prepare.py                   # normalizes the three public corpora into our schema
├── train_utils/
│   ├── schema.py                # canonical Sysmon record (matches apps/sysmon_agent)
│   ├── lolbas.py                # curated LOLBAS catalog + LOTL T-code set
│   ├── loaders.py               # agent / mordor / attack_data / evtx dialects
│   ├── labeling.py              # LOLBAS ∩ ATT&CK + process-tree propagation
│   ├── features.py              # 3-layer features (18 dense) + hashed char n-grams (1024 dims)
│   ├── splitting.py             # stratified capture-grouped K-fold
│   ├── pipeline.py              # source loading, labeling, strata building
│   ├── cv.py                    # K-fold CV loop + MLflow per-fold logging
│   ├── tracking.py              # MLflow artifact/feature-importance helpers
│   ├── train.py                 # XGBoost with scale_pos_weight + logloss early stop
│   └── evaluate.py              # ROC-AUC, top-K recall (ranking), precision floors
```

## Caveats

- Pure-benign captures are scarce in the public corpora. Most negatives come
  from Windows housekeeping events inside malicious captures (non-LOLBin
  processes outside the malicious tree). The neg/pos ratio in the test set
  will be lower than the production 100:1+, so precision numbers are softer
  than they would be at scale. Adding a self-generated VM benign capture is
  the next step recommended in the project brief.
- Sysmon config drift across sources is real — `OriginalFileName`,
  `IntegrityLevel`, `RuleName` are not uniformly present. Features degrade
  gracefully via empty-string defaults.
- EVTX-ATTACK-SAMPLES is GPL-3.0. Segregate corpora before releasing model
  artifacts if license matters for your deliverable.
