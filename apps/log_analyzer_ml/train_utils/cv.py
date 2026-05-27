from __future__ import annotations

import dataclasses
import logging
import math
from collections.abc import Sequence

import mlflow
import numpy as np
from scipy.sparse import csr_matrix

from .evaluate import EvalReport, evaluate, evaluate_capture_level
from .splitting import CaptureSplit
from .train import TrainedModel, predict_proba, train_xgb

logger = logging.getLogger(__name__)


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


def run_cv(
    matrix: csr_matrix,
    labels: np.ndarray,
    groups: Sequence[str],
    splits: list[CaptureSplit],
    *,
    num_boost_round: int,
    early_stopping_rounds: int,
    learning_rate: float,
    max_depth: int,
    seed: int,
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
            num_boost_round=num_boost_round,
            early_stopping_rounds=early_stopping_rounds,
            learning_rate=learning_rate,
            max_depth=max_depth,
            seed=seed,
        )
        y_test_score = predict_proba(model, x_test)
        event_report = evaluate(y_test, y_test_score)
        capture_report = evaluate_capture_level(y_test, y_test_score, test_capture_ids)
        fold_reports_event.append(event_report)
        fold_reports_capture.append(capture_report)
        logger.info(
            "Fold %d done — best_iter=%d val_logloss=%.4f | "
            "EVENT ROC-AUC=%.4f PR-AUC=%.4f r@top5%%=%.4f | "
            "CAPTURE ROC-AUC=%.4f PR-AUC=%.4f r@top5%%=%.4f (%d pos / %d total)",
            fold_idx + 1,
            model.best_iteration,
            model.best_val_logloss,
            event_report.roc_auc,
            event_report.pr_auc,
            event_report.recall_at_top_5pct,
            capture_report.roc_auc,
            capture_report.pr_auc,
            capture_report.recall_at_top_5pct,
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


def log_cv_block(name: str, reports: list[EvalReport], mlflow_prefix: str) -> None:
    logger.info("=== %d-fold CV summary — %s (mean ± std) ===", len(reports), name)
    for field in dataclasses.fields(reports[0]):
        values = [getattr(r, field.name) for r in reports]
        if all(isinstance(v, (int, float)) and math.isfinite(float(v)) for v in values):
            arr = np.asarray(values, dtype=float)
            logger.info("  %-22s = %.4f ± %.4f", field.name, arr.mean(), arr.std())
            mlflow.log_metric(f"cv_{mlflow_prefix}_{field.name}_mean", float(arr.mean()))
            mlflow.log_metric(f"cv_{mlflow_prefix}_{field.name}_std", float(arr.std()))
