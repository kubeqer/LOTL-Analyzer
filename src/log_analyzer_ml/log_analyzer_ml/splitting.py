from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from sklearn.cluster import KMeans
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import normalize


@dataclass(slots=True)
class CaptureSplit:
    train_idx: np.ndarray
    val_idx: np.ndarray
    test_idx: np.ndarray


def capture_split(
    groups: Sequence[str],
    *,
    test_size: float = 0.2,
    val_size: float = 0.1,
    seed: int = 42,
) -> CaptureSplit:
    """Split row indices into train/val/test along ``groups`` boundaries.

    ``val_size`` is taken from the train remainder (so ``test_size + val_size``
    is *not* required to be ≤ 1 with respect to total — val is a slice of the
    post-test split).
    """
    groups_arr = np.asarray(groups)
    indices = np.arange(len(groups_arr))

    outer = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_full, test_idx = next(outer.split(indices, groups=groups_arr))

    inner_val = val_size / (1.0 - test_size)
    inner = GroupShuffleSplit(n_splits=1, test_size=inner_val, random_state=seed + 1)
    train_relative, val_relative = next(inner.split(train_full, groups=groups_arr[train_full]))

    train_idx = train_full[train_relative]
    val_idx = train_full[val_relative]
    return CaptureSplit(train_idx=train_idx, val_idx=val_idx, test_idx=test_idx)


def stratified_capture_split(
    groups: Sequence[str],
    capture_strata: dict[str, str],
    *,
    test_size: float = 0.2,
    val_size: float = 0.1,
    seed: int = 42,
) -> CaptureSplit:
    rows_by_capture: dict[str, list[int]] = defaultdict(list)
    for i, cap in enumerate(groups):
        rows_by_capture[cap].append(i)

    missing = [cap for cap in rows_by_capture if cap not in capture_strata]
    if missing:
        raise ValueError(
            f"capture_strata missing entries for {len(missing)} captures (e.g. {missing[:3]})"
        )

    captures_by_stratum: dict[str, list[str]] = defaultdict(list)
    for cap in rows_by_capture:
        captures_by_stratum[capture_strata[cap]].append(cap)

    rng = np.random.default_rng(seed)
    train_caps: list[str] = []
    val_caps: list[str] = []
    test_caps: list[str] = []
    for caps in captures_by_stratum.values():
        caps_sorted = sorted(caps)
        rng.shuffle(caps_sorted)
        n_test, n_val = _stratum_split_sizes(len(caps_sorted), test_size, val_size)
        test_caps.extend(caps_sorted[:n_test])
        val_caps.extend(caps_sorted[n_test : n_test + n_val])
        train_caps.extend(caps_sorted[n_test + n_val :])

    def _collect(cap_list: list[str]) -> np.ndarray:
        if not cap_list:
            return np.array([], dtype=np.int64)
        idx = np.concatenate([np.asarray(rows_by_capture[c], dtype=np.int64) for c in cap_list])
        idx.sort()
        return idx

    return CaptureSplit(
        train_idx=_collect(train_caps),
        val_idx=_collect(val_caps),
        test_idx=_collect(test_caps),
    )


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
    min_cluster_size: int = 4,
    max_clusters: int = 3,
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
        kmeans = KMeans(n_clusters=k, random_state=seed, n_init=10).fit(signatures)
        for cap, cluster_id in zip(caps, kmeans.labels_, strict=True):
            refined[cap] = f"{stratum}_c{int(cluster_id)}"
    return refined


def _stratum_split_sizes(n: int, test_size: float, val_size: float) -> tuple[int, int]:
    if n <= 1:
        return 0, 0
    if n == 2:
        return 1, 0
    n_test = max(1, round(n * test_size))
    n_val = max(1, round(n * val_size))
    if n_test + n_val >= n:
        n_test, n_val = 1, 1
    return n_test, n_val


def downsample_majority(
    train_idx: np.ndarray,
    labels: np.ndarray,
    *,
    target_ratio: float = 100.0,
    seed: int = 42,
) -> np.ndarray:
    rng = np.random.default_rng(seed)
    train_labels = labels[train_idx]
    pos_mask = train_labels == 1
    neg_mask = train_labels == 0
    pos = train_idx[pos_mask]
    neg = train_idx[neg_mask]
    if len(pos) == 0 or len(neg) == 0:
        return train_idx
    desired_neg = int(len(pos) * target_ratio)
    if desired_neg >= len(neg):
        return train_idx
    sampled_neg = rng.choice(neg, size=desired_neg, replace=False)
    out = np.concatenate([pos, sampled_neg])
    rng.shuffle(out)
    return out
