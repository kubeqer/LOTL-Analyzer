from __future__ import annotations

import logging
from pathlib import Path

import mlflow
import mlflow.xgboost
import numpy as np

from train_utils.cv import log_cv_block, run_cv
from train_utils.features import build_features
from train_utils.pipeline import build_strata, load_and_label, load_sources
from train_utils.splitting import stratified_capture_kfold
from train_utils.tracking import log_top_features, save_best_model

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent.parent
DATASETS = REPO_ROOT / "datasets"
MODEL_OUT = HERE / "data" / "lotl_xgb.json"
MODEL_SIDECAR_OUT = HERE / "data" / "lotl_xgb.sidecar.json"

MLFLOW_TRACKING_URI = f"file://{HERE / 'data' / 'mlruns'}"
MLFLOW_EXPERIMENT = "lotl-detector"

OTRF_ROOT = DATASETS / "Security-Datasets" / "datasets"
ATTACK_DATA_ROOT = DATASETS / "attack_data" / "datasets" / "attack_techniques"
EVTX_SAMPLES_ROOT = DATASETS / "EVTX-ATTACK-SAMPLES"

SOURCES: list[tuple[Path, str]] = [
    (OTRF_ROOT, "attack_data"),
    (ATTACK_DATA_ROOT, "attack_data"),
    (EVTX_SAMPLES_ROOT, "evtx"),
]

SEED = 30
VAL_SIZE = 0.15

NUM_BOOST_ROUND = 600
EARLY_STOPPING_ROUNDS = 50
LEARNING_RATE = 0.08
MAX_DEPTH = 8

MIN_CLUSTER_SIZE = 6
N_FOLDS = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("lotl")


def main() -> None:
    available_sources = load_sources(SOURCES, DATASETS)

    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    mlflow.set_experiment(MLFLOW_EXPERIMENT)
    mlflow.xgboost.autolog(log_models=False, log_input_examples=False, silent=True)

    with mlflow.start_run() as run:
        logger.info(
            "MLflow run %s — view with: uv run mlflow ui --backend-store-uri %s",
            run.info.run_id,
            MLFLOW_TRACKING_URI,
        )
        mlflow.log_params(
            {
                "sources": [str(p) for p, _ in available_sources],
                "seed": SEED,
                "val_size": VAL_SIZE,
                "n_folds": N_FOLDS,
                "num_boost_round": NUM_BOOST_ROUND,
                "early_stopping_rounds": EARLY_STOPPING_ROUNDS,
                "learning_rate": LEARNING_RATE,
                "max_depth": MAX_DEPTH,
                "min_cluster_size": MIN_CLUSTER_SIZE,
            }
        )

        all_records, process_records, process_labels = load_and_label(available_sources)
        groups = [r.capture_id for r in process_records]

        logger.info("Building features (dense + hashed char n-grams)...")
        matrix, _ = build_features(process_records, all_records=all_records)
        labels = np.asarray(process_labels, dtype=np.int32)

        refined_strata = build_strata(
            process_records,
            matrix,
            groups,
            min_cluster_size=MIN_CLUSTER_SIZE,
            seed=SEED,
        )
        splits = stratified_capture_kfold(
            groups,
            refined_strata,
            n_folds=N_FOLDS,
            val_size=VAL_SIZE,
            seed=SEED,
        )

        best_model, best_fold, fold_reports_event, fold_reports_capture = run_cv(
            matrix,
            labels,
            groups,
            splits,
            num_boost_round=NUM_BOOST_ROUND,
            early_stopping_rounds=EARLY_STOPPING_ROUNDS,
            learning_rate=LEARNING_RATE,
            max_depth=MAX_DEPTH,
            seed=SEED,
        )

        log_cv_block("EVENT-LEVEL", fold_reports_event, "event")
        log_cv_block("CAPTURE-LEVEL", fold_reports_capture, "capture")
        log_top_features(best_model)
        save_best_model(
            best_model,
            best_fold,
            best_model.best_val_logloss,
            model_out=MODEL_OUT,
            sidecar_out=MODEL_SIDECAR_OUT,
        )


if __name__ == "__main__":
    main()
