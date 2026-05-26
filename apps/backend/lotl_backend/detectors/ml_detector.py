from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np
import xgboost as xgb

from ..config import settings
from ..schema import SysmonEvents
from .features import build_features

logger = logging.getLogger(__name__)


class MlDetector:
    def __init__(self, booster: xgb.Booster, threshold: float) -> None:
        self._booster = booster
        self._threshold = threshold

    @classmethod
    def load(cls, model_path: Path, sidecar_path: Path, threshold: float) -> MlDetector:
        booster = xgb.Booster()
        booster.load_model(str(model_path))
        if sidecar_path.exists():
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            logger.info(
                "ML model loaded (sidecar best_val_logloss=%s)", sidecar.get("best_val_logloss")
            )
        else:
            logger.info("ML model loaded (no sidecar at %s)", sidecar_path)
        return cls(booster, threshold)

    def score(self, window: SysmonEvents) -> tuple[float, list[float]]:
        matrix, _ = build_features(window.events)
        if matrix.shape[0] == 0:
            return (0.0, [])
        dmatrix = xgb.DMatrix(matrix)
        scores = self._booster.predict(dmatrix)
        scores_list = [float(s) for s in np.asarray(scores).ravel().tolist()]
        return (max(scores_list), scores_list)

    def detect(self, window: SysmonEvents) -> tuple[bool, float]:
        max_score, _ = self.score(window)
        return (max_score >= self._threshold, max_score)


_detector: MlDetector | None = None


def get_detector() -> MlDetector:
    global _detector
    if _detector is None:
        _detector = MlDetector.load(
            settings.ml_model_path,
            settings.ml_sidecar_path,
            settings.ml_threshold,
        )
    return _detector


def detect_ml(window: SysmonEvents) -> tuple[bool, float]:
    return get_detector().detect(window)
