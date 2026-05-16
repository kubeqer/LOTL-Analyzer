from __future__ import annotations

import dataclasses
import json
import logging
import math
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

import mlflow
import mlflow.xgboost
import numpy as np
from scipy.sparse import csr_matrix

from log_analyzer_ml.evaluate import EvalReport, evaluate, evaluate_capture_level
from log_analyzer_ml.features import (
    DENSE_FEATURE_NAMES,
    NGRAM_DIMS,
    build_features,
    feature_names,
)
from log_analyzer_ml.labeling import filter_process_creates, label_records
from log_analyzer_ml.loaders import load_all
from log_analyzer_ml.lolbas import LOTL_TECHNIQUES, parent_technique
from log_analyzer_ml.schema import SysmonRecord
from log_analyzer_ml.splitting import (
    CaptureSplit,
    refine_strata_by_feature_cluster,
    stratified_capture_kfold,
)
from log_analyzer_ml.train import TrainedModel, predict_proba, train_xgb

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

NGRAM_VECTORIZER_PARAMS: dict[str, object] = {
    "analyzer": "char_wb",
    "ngram_range": (3, 5),
    "alternate_sign": False,
    "norm": "l2",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("lotl")


def _capture_stratum(record: SysmonRecord) -> str:
    if not record.capture_is_malicious:
        return "neg"
    for technique in record.capture_techniques:
        parent = parent_technique(technique)
        if technique in LOTL_TECHNIQUES or parent in LOTL_TECHNIQUES:
            return parent
    return "mal_other"


def _load_sources() -> list[tuple[Path, str]]:
    available_sources = [(path, dialect) for path, dialect in SOURCES if path.exists()]
    for path in (path for path, _ in SOURCES if not path.exists()):
        logger.warning("source missing — skipping: %s", path)
    if not available_sources:
        logger.error(
            "No prepared datasets found under %s. Run scripts/download_datasets.sh "
            "and then prepare.py before training.",
            DATASETS,
        )
        raise SystemExit(2)
    return available_sources


def _load_and_label(
    available_sources: list[tuple[Path, str]],
) -> tuple[list[SysmonRecord], list[SysmonRecord], list[int]]:
    logger.info("Loading from %d source(s)...", len(available_sources))
    all_records = load_all(available_sources)
    logger.info("Loaded %d raw Sysmon events", len(all_records))
    if not all_records:
        logger.error("Zero events read. Did prepare.py complete?")
        raise SystemExit(2)

    logger.info("Labeling per-capture (LOLBin basename ∪ LOTL technique tree closure)...")
    labels_all = label_records(all_records)
    process_records, process_labels = filter_process_creates(all_records, labels_all)
    pos = sum(process_labels)
    neg = len(process_labels) - pos
    logger.info("Process-create events: %d (pos=%d, neg=%d)", len(process_records), pos, neg)
    mlflow.log_metrics(
        {
            "data_raw_events": float(len(all_records)),
            "data_process_creates": float(len(process_records)),
            "data_positives": float(pos),
            "data_negatives": float(neg),
            "data_imbalance_ratio": float(neg) / max(pos, 1),
        }
    )
    if pos == 0:
        logger.error(
            "Zero positives after labeling. Check that manifest.json files are "
            "present in capture directories and declare ATT&CK techniques."
        )
        raise SystemExit(2)
    return all_records, process_records, process_labels


def _build_strata(
    process_records: Sequence[SysmonRecord],
    matrix: csr_matrix,
    groups: Sequence[str],
) -> dict[str, str]:
    capture_strata: dict[str, str] = {}
    for record in process_records:
        if record.capture_id not in capture_strata:
            capture_strata[record.capture_id] = _capture_stratum(record)

    n_dense = len(DENSE_FEATURE_NAMES)
    rows_by_capture: dict[str, list[int]] = {}
    for i, cap in enumerate(groups):
        rows_by_capture.setdefault(cap, []).append(i)
    capture_signatures: dict[str, np.ndarray] = {}
    for cap, rows in rows_by_capture.items():
        block = matrix[rows, n_dense:]
        capture_signatures[cap] = np.asarray(block.mean(axis=0)).ravel()
    refined = refine_strata_by_feature_cluster(
        capture_strata,
        capture_signatures,
        min_cluster_size=MIN_CLUSTER_SIZE,
        seed=SEED,
    )

    stratum_counts = Counter(refined.values())
    logger.info("Distinct captures: %d", len(capture_strata))
    logger.info(
        "Strata: %d raw → %d refined; refined counts: %s",
        len(set(capture_strata.values())),
        len(stratum_counts),
        dict(stratum_counts),
    )
    mlflow.log_metrics(
        {
            "data_distinct_captures": float(len(capture_strata)),
            "data_distinct_strata_raw": float(len(set(capture_strata.values()))),
            "data_distinct_strata_refined": float(len(stratum_counts)),
        }
    )
    return refined


def _log_fold_metrics(
    fold_idx: int,
    event_report: EvalReport,
    capture_report: EvalReport,
    model: TrainedModel,
) -> None:
    for field in dataclasses.fields(event_report):
        value = getattr(event_report, field.name)
        if isinstance(value, (int, float)):
            metric = float(value) if math.isfinite(float(value)) else float("nan")
            mlflow.log_metric(f"fold_event_{field.name}", metric, step=fold_idx)
    for field in dataclasses.fields(capture_report):
        value = getattr(capture_report, field.name)
        if isinstance(value, (int, float)):
            metric = float(value) if math.isfinite(float(value)) else float("nan")
            mlflow.log_metric(f"fold_capture_{field.name}", metric, step=fold_idx)
    mlflow.log_metric("fold_best_val_logloss", float(model.best_val_logloss), step=fold_idx)
    mlflow.log_metric("fold_best_iteration", float(model.best_iteration), step=fold_idx)


def _run_cv(
    matrix: csr_matrix,
    labels: np.ndarray,
    groups: Sequence[str],
    splits: list[CaptureSplit],
) -> tuple[TrainedModel, int, list[EvalReport], list[EvalReport]]:
    fold_reports_event: list[EvalReport] = []
    fold_reports_capture: list[EvalReport] = []
    best_model: TrainedModel | None = None
    best_val_logloss = float("inf")
    best_fold = -1

    for fold_idx, split in enumerate(splits):
        x_train, y_train = matrix[split.train_idx], labels[split.train_idx]
        x_val, y_val = matrix[split.val_idx], labels[split.val_idx]
        x_test, y_test = matrix[split.test_idx], labels[split.test_idx]
        test_capture_ids = [groups[i] for i in split.test_idx]
        n_test_captures = len(set(test_capture_ids))
        logger.info(
            "Fold %d/%d — Train: %d (pos=%d), Val: %d (pos=%d), "
            "Test: %d events / %d captures (pos_events=%d)",
            fold_idx + 1,
            len(splits),
            len(y_train),
            int(y_train.sum()),
            len(y_val),
            int(y_val.sum()),
            len(y_test),
            n_test_captures,
            int(y_test.sum()),
        )
        if y_train.sum() == 0 or y_val.sum() == 0 or y_test.sum() == 0:
            logger.warning("Fold %d has empty positives in some split — skipping", fold_idx + 1)
            continue

        model = train_xgb(
            x_train,
            y_train,
            x_val,
            y_val,
            num_boost_round=NUM_BOOST_ROUND,
            early_stopping_rounds=EARLY_STOPPING_ROUNDS,
            learning_rate=LEARNING_RATE,
            max_depth=MAX_DEPTH,
            seed=SEED,
        )
        y_test_score = predict_proba(model, x_test)
        event_report = evaluate(y_test, y_test_score)
        capture_report = evaluate_capture_level(y_test, y_test_score, test_capture_ids)
        fold_reports_event.append(event_report)
        fold_reports_capture.append(capture_report)
        logger.info(
            "Fold %d done — best_iter=%d val_logloss=%.4f | "
            "EVENT PR-AUC=%.4f F1=%.4f r@p95=%.4f | "
            "CAPTURE PR-AUC=%.4f F1=%.4f r@p95=%.4f (%d pos / %d total)",
            fold_idx + 1,
            model.best_iteration,
            model.best_val_logloss,
            event_report.pr_auc,
            event_report.f1_best,
            event_report.recall_at_p95,
            capture_report.pr_auc,
            capture_report.f1_best,
            capture_report.recall_at_p95,
            capture_report.positives,
            capture_report.positives + capture_report.negatives,
        )
        _log_fold_metrics(fold_idx, event_report, capture_report, model)

        is_better = best_model is None or (
            math.isfinite(model.best_val_logloss) and model.best_val_logloss < best_val_logloss
        )
        if is_better:
            best_val_logloss = model.best_val_logloss
            best_model = model
            best_fold = fold_idx

    if best_model is None or not fold_reports_event:
        logger.error("All folds failed — cannot summarize.")
        raise SystemExit(2)
    return best_model, best_fold, fold_reports_event, fold_reports_capture


def _log_cv_block(name: str, reports: list[EvalReport], mlflow_prefix: str) -> None:
    logger.info("=== %d-fold CV summary — %s (mean ± std) ===", len(reports), name)
    for field in dataclasses.fields(reports[0]):
        values = [getattr(r, field.name) for r in reports]
        if all(isinstance(v, (int, float)) and math.isfinite(float(v)) for v in values):
            arr = np.asarray(values, dtype=float)
            logger.info("  %-22s = %.4f ± %.4f", field.name, arr.mean(), arr.std())
            mlflow.log_metric(f"cv_{mlflow_prefix}_{field.name}_mean", float(arr.mean()))
            mlflow.log_metric(f"cv_{mlflow_prefix}_{field.name}_std", float(arr.std()))


def _resolve_feature_label(raw_key: str, names: list[str]) -> str:
    if raw_key.startswith("f"):
        stripped = raw_key.removeprefix("f")
        if stripped.isdigit():
            idx = int(stripped)
            if 0 <= idx < len(names):
                return names[idx]
    return raw_key


def _log_top_features(best_model: TrainedModel) -> None:
    names = feature_names()
    top = Counter(best_model.booster.get_score(importance_type="gain")).most_common(20)
    if not top:
        return
    labelled = [(_resolve_feature_label(raw_key, names), gain) for raw_key, gain in top]
    logger.info("Top features by gain (best model):")
    for label, gain in labelled[:10]:
        logger.info("  %-30s gain=%.2f", label, gain)
    mlflow.log_text(
        "\n".join(f"{label}\t{gain:.4f}" for label, gain in labelled),
        "feature_importance_top20.tsv",
    )


def _save_best_model(best_model: TrainedModel, best_fold: int, best_val_logloss: float) -> None:
    logger.info(
        "Saving best-val-logloss model (fold %d, val_logloss=%.4f)",
        best_fold + 1,
        best_val_logloss,
    )
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    best_model.booster.save_model(str(MODEL_OUT))

    sidecar = {
        "dense_names": list(DENSE_FEATURE_NAMES),
        "ngram_dims": NGRAM_DIMS,
        "vectorizer_params": NGRAM_VECTORIZER_PARAMS,
        "best_fold": best_fold,
        "best_val_logloss": (best_val_logloss if math.isfinite(best_val_logloss) else None),
    }
    MODEL_SIDECAR_OUT.write_text(json.dumps(sidecar, indent=2, default=list), encoding="utf-8")

    mlflow.log_artifact(str(MODEL_OUT))
    mlflow.log_artifact(str(MODEL_SIDECAR_OUT))
    logger.info("Saved model to %s (sidecar: %s)", MODEL_OUT, MODEL_SIDECAR_OUT)


def main() -> None:
    available_sources = _load_sources()

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

        all_records, process_records, process_labels = _load_and_label(available_sources)
        groups = [r.capture_id for r in process_records]

        logger.info("Building features (dense + hashed char n-grams)...")
        matrix, _ = build_features(process_records, all_records=all_records)
        labels = np.asarray(process_labels, dtype=np.int32)

        refined_strata = _build_strata(process_records, matrix, groups)
        splits = stratified_capture_kfold(
            groups,
            refined_strata,
            n_folds=N_FOLDS,
            val_size=VAL_SIZE,
            seed=SEED,
        )

        best_model, best_fold, fold_reports_event, fold_reports_capture = _run_cv(
            matrix, labels, groups, splits
        )

        _log_cv_block("EVENT-LEVEL", fold_reports_event, "event")
        _log_cv_block("CAPTURE-LEVEL", fold_reports_capture, "capture")
        _log_top_features(best_model)
        _save_best_model(best_model, best_fold, best_model.best_val_logloss)


if __name__ == "__main__":
    main()
