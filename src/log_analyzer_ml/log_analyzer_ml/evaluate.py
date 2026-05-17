from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

PRECISION_FLOORS: tuple[float, ...] = (0.80, 0.95, 0.99)
TOP_K_PERCENTILES: tuple[float, ...] = (0.01, 0.05, 0.10)


def _floor_key(target: float) -> str:
    return f"p{int(round(target * 100))}"


def _top_key(fraction: float) -> str:
    return f"top_{int(round(fraction * 100))}pct"


@dataclass(slots=True)
class EvalReport:
    pr_auc: float
    roc_auc: float
    f1_best: float
    f1_threshold: float
    precision_best: float
    recall_best: float
    precision_at_p80: float
    recall_at_p80: float
    precision_at_p95: float
    recall_at_p95: float
    precision_at_p99: float
    recall_at_p99: float
    recall_at_top_1pct: float
    recall_at_top_5pct: float
    recall_at_top_10pct: float
    positives: int
    negatives: int
    imbalance_ratio: float

    def pretty(self) -> str:
        lines: list[str] = [
            f"PR-AUC      = {self.pr_auc:.4f}",
            f"ROC-AUC     = {self.roc_auc:.4f}",
            f"Best F1     = {self.f1_best:.4f} @ threshold {self.f1_threshold:.4f}",
            f"  precision = {self.precision_best:.4f}",
            f"  recall    = {self.recall_best:.4f}",
            "Cascade ranking (primary metric for LLM-tier handoff):",
        ]
        for fraction in TOP_K_PERCENTILES:
            key = _top_key(fraction)
            value = getattr(self, f"recall_at_{key}")
            lines.append(f"  recall @ top {fraction * 100:>4.0f}% = {value:.4f}")
        for target in PRECISION_FLOORS:
            key = _floor_key(target)
            lines.append(f"At precision ≥ {target:.2f}:")
            lines.append(f"  precision = {getattr(self, f'precision_at_{key}'):.4f}")
            lines.append(f"  recall    = {getattr(self, f'recall_at_{key}'):.4f}")
        lines.append(
            f"Test set    : {self.positives} positives, {self.negatives} negatives "
            f"(neg/pos = {self.imbalance_ratio:.1f})"
        )
        return "\n".join(lines)


def evaluate(y_true: np.ndarray, y_score: np.ndarray) -> EvalReport:
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score).astype(float)

    pr_auc = float(average_precision_score(y_true, y_score)) if y_true.sum() else float("nan")
    try:
        roc_auc = float(roc_auc_score(y_true, y_score))
    except ValueError:
        roc_auc = float("nan")

    precisions, recalls, thresholds = precision_recall_curve(y_true, y_score)

    f1_vals = (2 * precisions * recalls) / np.clip(precisions + recalls, 1e-9, None)
    if len(thresholds) == 0:
        f1_threshold = float("nan")
        f1_best = float("nan")
        precision_best = float("nan")
        recall_best = float("nan")
    else:
        best_idx = int(np.argmax(f1_vals[:-1]))
        f1_threshold = float(thresholds[best_idx])
        y_pred_best = (y_score >= f1_threshold).astype(int)
        f1_best = float(f1_score(y_true, y_pred_best, zero_division=0))
        precision_best = float(precision_score(y_true, y_pred_best, zero_division=0))
        recall_best = float(recall_score(y_true, y_pred_best, zero_division=0))

    floor_metrics: dict[str, float] = {}
    for target in PRECISION_FLOORS:
        prec, rec = _max_recall_at_precision(precisions, recalls, target)
        key = _floor_key(target)
        floor_metrics[f"precision_at_{key}"] = prec
        floor_metrics[f"recall_at_{key}"] = rec

    top_k_metrics: dict[str, float] = {}
    for fraction in TOP_K_PERCENTILES:
        top_k_metrics[f"recall_at_{_top_key(fraction)}"] = _recall_at_top_k(
            y_true,
            y_score,
            fraction,
        )

    positives = int(y_true.sum())
    negatives = int((y_true == 0).sum())
    imbalance = negatives / max(positives, 1)
    return EvalReport(
        pr_auc=pr_auc,
        roc_auc=roc_auc,
        f1_best=f1_best,
        f1_threshold=f1_threshold,
        precision_best=precision_best,
        recall_best=recall_best,
        positives=positives,
        negatives=negatives,
        imbalance_ratio=imbalance,
        **floor_metrics,
        **top_k_metrics,
    )


def _recall_at_top_k(y_true: np.ndarray, y_score: np.ndarray, fraction: float) -> float:
    total_positives = int(y_true.sum())
    if total_positives == 0:
        return 0.0
    n = len(y_score)
    k = max(1, int(round(n * fraction)))
    top = np.argsort(y_score)[::-1][:k]
    return float(y_true[top].sum()) / total_positives


def evaluate_capture_level(
    y_true_events: np.ndarray,
    y_score_events: np.ndarray,
    capture_ids: Sequence[str],
) -> EvalReport:
    y_true_events = np.asarray(y_true_events).astype(int)
    y_score_events = np.asarray(y_score_events).astype(float)
    by_capture: dict[str, list[int]] = defaultdict(list)
    for i, cap in enumerate(capture_ids):
        by_capture[cap].append(i)

    capture_y = np.empty(len(by_capture), dtype=np.int32)
    capture_score = np.empty(len(by_capture), dtype=np.float64)
    for out_i, idxs in enumerate(by_capture.values()):
        rows = np.asarray(idxs, dtype=np.int64)
        capture_y[out_i] = int(y_true_events[rows].max())
        capture_score[out_i] = float(y_score_events[rows].max())
    return evaluate(capture_y, capture_score)


def _max_recall_at_precision(
    precisions: np.ndarray, recalls: np.ndarray, target: float
) -> tuple[float, float]:

    p = precisions[:-1]
    r = recalls[:-1]
    mask = (p >= target) & (r > 0)
    if not mask.any():
        return 0.0, 0.0
    candidates = np.where(mask)[0]
    chosen = int(candidates[np.argmax(r[candidates])])
    return float(p[chosen]), float(r[chosen])
