from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import xgboost as xgb
from scipy.sparse import csr_matrix


@dataclass(slots=True)
class TrainedModel:
    booster: xgb.Booster
    best_iteration: int
    best_val_logloss: float
    best_val_aucpr: float
    scale_pos_weight: float


def train_xgb(
    x_train: csr_matrix,
    y_train: np.ndarray,
    x_val: csr_matrix,
    y_val: np.ndarray,
    *,
    num_boost_round: int = 800,
    early_stopping_rounds: int = 50,
    learning_rate: float = 0.08,
    max_depth: int = 6,
    seed: int = 30,
) -> TrainedModel:
    pos = float((y_train == 1).sum())
    neg = float((y_train == 0).sum())
    if pos == 0:
        raise ValueError("training set has zero positives — cannot fit a binary classifier")
    scale_pos_weight = neg / pos

    params = {
        "objective": "binary:logistic",
        "eval_metric": ["aucpr", "logloss"],
        "tree_method": "hist",
        "max_depth": max_depth,
        "learning_rate": learning_rate,
        "min_child_weight": 1.0,
        "subsample": 0.9,
        "colsample_bytree": 0.8,
        "reg_lambda": 1.0,
        "scale_pos_weight": scale_pos_weight,
        "seed": seed,
        "verbosity": 1,
    }

    dtrain = xgb.DMatrix(x_train, label=y_train)
    dval = xgb.DMatrix(x_val, label=y_val)
    evals_result: dict = {}
    booster = xgb.train(
        params=params,
        dtrain=dtrain,
        num_boost_round=num_boost_round,
        evals=[(dtrain, "train"), (dval, "val")],
        early_stopping_rounds=early_stopping_rounds,
        evals_result=evals_result,
        verbose_eval=50,
    )
    best_iter = getattr(booster, "best_iteration", num_boost_round - 1)
    val_logloss_history = evals_result.get("val", {}).get("logloss", [])
    val_aucpr_history = evals_result.get("val", {}).get("aucpr", [])
    best_logloss = (
        float(val_logloss_history[best_iter])
        if best_iter < len(val_logloss_history)
        else float("nan")
    )
    best_aucpr = (
        float(val_aucpr_history[best_iter]) if best_iter < len(val_aucpr_history) else float("nan")
    )
    return TrainedModel(
        booster=booster,
        best_iteration=best_iter,
        best_val_logloss=best_logloss,
        best_val_aucpr=best_aucpr,
        scale_pos_weight=scale_pos_weight,
    )


def predict_proba(model: TrainedModel, x: csr_matrix) -> np.ndarray:
    return model.booster.predict(
        xgb.DMatrix(x),
        iteration_range=(0, model.best_iteration + 1),
    )
