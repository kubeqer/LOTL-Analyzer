from __future__ import annotations

import json
import logging
import math
from collections import Counter
from pathlib import Path

import mlflow

from .features import DENSE_FEATURE_NAMES, NGRAM_DIMS, NGRAM_VECTORIZER_PARAMS, feature_names
from .train import TrainedModel

logger = logging.getLogger(__name__)


def _resolve_feature_label(raw_key: str, names: list[str]) -> str:
    if raw_key.startswith("f"):
        stripped = raw_key.removeprefix("f")
        if stripped.isdigit():
            idx = int(stripped)
            if 0 <= idx < len(names):
                return names[idx]
    return raw_key


def log_top_features(best_model: TrainedModel) -> None:
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


def save_best_model(
    best_model: TrainedModel,
    best_fold: int,
    best_val_logloss: float,
    *,
    model_out: Path,
    sidecar_out: Path,
) -> None:
    logger.info(
        "Saving best-val-logloss model (fold %d, val_logloss=%.4f)",
        best_fold + 1,
        best_val_logloss,
    )
    model_out.parent.mkdir(parents=True, exist_ok=True)
    best_model.booster.save_model(str(model_out))

    sidecar = {
        "dense_names": list(DENSE_FEATURE_NAMES),
        "ngram_dims": NGRAM_DIMS,
        "vectorizer_params": NGRAM_VECTORIZER_PARAMS,
        "best_fold": best_fold,
        "best_val_logloss": (best_val_logloss if math.isfinite(best_val_logloss) else None),
    }
    sidecar_out.write_text(json.dumps(sidecar, indent=2, default=list), encoding="utf-8")

    mlflow.log_artifact(str(model_out))
    mlflow.log_artifact(str(sidecar_out))
    logger.info("Saved model to %s (sidecar: %s)", model_out, sidecar_out)
