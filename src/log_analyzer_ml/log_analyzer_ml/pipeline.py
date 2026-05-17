from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

import mlflow
import numpy as np
from scipy.sparse import csr_matrix

from .features import DENSE_FEATURE_NAMES
from .labeling import filter_process_creates, label_records
from .loaders import load_all
from .lolbas import LOTL_TECHNIQUES, parent_technique
from .schema import SysmonRecord
from .splitting import refine_strata_by_feature_cluster

logger = logging.getLogger(__name__)


def capture_stratum_for_kfold(record: SysmonRecord) -> str:
    """Stratum label per capture for stratified K-fold splitting.

    Returns a parent (or full sub-) technique for malicious-LOTL captures so
    each stratum holds related captures together; non-LOTL malicious captures
    bucket into ``mal_other``; benign captures into ``neg``.
    """
    if not record.capture_is_malicious:
        return "neg"
    for technique in record.capture_techniques:
        if technique in LOTL_TECHNIQUES:
            return technique
        parent = parent_technique(technique)
        if parent in LOTL_TECHNIQUES:
            return parent
    return "mal_other"


def load_sources(sources: list[tuple[Path, str]], datasets_root: Path) -> list[tuple[Path, str]]:
    available_sources = [(path, dialect) for path, dialect in sources if path.exists()]
    for path, _ in sources:
        if not path.exists():
            logger.warning("source missing — skipping: %s", path)
    if not available_sources:
        logger.error(
            "No prepared datasets found under %s. Run scripts/download_datasets.sh "
            "and then prepare.py before training.",
            datasets_root,
        )
        raise SystemExit(2)
    return available_sources


def load_and_label(
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


def build_strata(
    process_records: Sequence[SysmonRecord],
    matrix: csr_matrix,
    groups: Sequence[str],
    *,
    min_cluster_size: int,
    seed: int,
) -> dict[str, str]:
    capture_strata: dict[str, str] = {}
    for record in process_records:
        if record.capture_id not in capture_strata:
            capture_strata[record.capture_id] = capture_stratum_for_kfold(record)

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
        min_cluster_size=min_cluster_size,
        seed=seed,
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
