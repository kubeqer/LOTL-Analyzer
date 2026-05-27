from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import normalize

DEFAULT_REFINE_MAX_CLUSTERS = 3
DEFAULT_REFINE_MIN_CLUSTER_SIZE = 4
KMEANS_N_INIT = 10


@dataclass(slots=True)
class CaptureSplit:
    train_idx: np.ndarray
    val_idx: np.ndarray
    test_idx: np.ndarray


def stratified_capture_kfold(
    groups: Sequence[str],
    capture_strata: dict[str, str],
    *,
    n_folds: int,
    val_size: float = 0.15,
    seed: int = 42,
) -> list[CaptureSplit]:
    if n_folds < 2:
        raise ValueError("n_folds must be at least 2")

    rows_by_capture: dict[str, list[int]] = defaultdict(list)
    for i, cap in enumerate(groups):
        rows_by_capture[cap].append(i)

    by_stratum: dict[str, list[str]] = defaultdict(list)
    for cap, st in capture_strata.items():
        by_stratum[st].append(cap)

    rng = np.random.default_rng(seed)
    test_buckets: list[list[str]] = [[] for _ in range(n_folds)]
    for caps in by_stratum.values():
        caps_sorted = sorted(caps)
        rng.shuffle(caps_sorted)
        for i, cap in enumerate(caps_sorted):
            test_buckets[i % n_folds].append(cap)

    splits: list[CaptureSplit] = []
    for fold in range(n_folds):
        test_caps_set = set(test_buckets[fold])
        non_test_by_stratum: dict[str, list[str]] = defaultdict(list)
        for cap, st in capture_strata.items():
            if cap not in test_caps_set:
                non_test_by_stratum[st].append(cap)

        fold_rng = np.random.default_rng(seed + 1 + fold)
        val_caps: list[str] = []
        train_caps: list[str] = []
        for caps in non_test_by_stratum.values():
            caps_sorted = sorted(caps)
            fold_rng.shuffle(caps_sorted)
            n = len(caps_sorted)
            if n <= 1:
                train_caps.extend(caps_sorted)
                continue
            n_val = max(1, round(n * val_size))
            if n_val >= n:
                n_val = 1
            val_caps.extend(caps_sorted[:n_val])
            train_caps.extend(caps_sorted[n_val:])

        splits.append(
            CaptureSplit(
                train_idx=_collect_rows(train_caps, rows_by_capture),
                val_idx=_collect_rows(val_caps, rows_by_capture),
                test_idx=_collect_rows(test_buckets[fold], rows_by_capture),
            )
        )
    return splits


def _collect_rows(cap_list: list[str], rows_by_capture: dict[str, list[int]]) -> np.ndarray:
    if not cap_list:
        return np.array([], dtype=np.int64)
    idx = np.concatenate([np.asarray(rows_by_capture[c], dtype=np.int64) for c in cap_list])
    idx.sort()
    return idx


def refine_strata_by_feature_cluster(
    capture_strata: dict[str, str],
    capture_signatures: dict[str, np.ndarray],
    *,
    min_cluster_size: int = DEFAULT_REFINE_MIN_CLUSTER_SIZE,
    max_clusters: int = DEFAULT_REFINE_MAX_CLUSTERS,
    seed: int = 42,
) -> dict[str, str]:
    by_stratum: dict[str, list[str]] = defaultdict(list)
    for cap, st in capture_strata.items():
        by_stratum[st].append(cap)

    refined: dict[str, str] = {}
    for stratum, caps in by_stratum.items():
        if len(caps) < min_cluster_size:
            for cap in caps:
                refined[cap] = stratum
            continue
        signatures = np.vstack([capture_signatures[cap] for cap in caps])
        signatures = normalize(signatures, norm="l2")
        k = min(max_clusters, max(2, len(caps) // 3))
        kmeans = KMeans(n_clusters=k, random_state=seed, n_init=KMEANS_N_INIT).fit(signatures)
        for cap, cluster_id in zip(caps, kmeans.labels_, strict=True):
            refined[cap] = f"{stratum}_c{int(cluster_id)}"
    return refined
