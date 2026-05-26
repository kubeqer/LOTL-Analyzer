from __future__ import annotations

import bisect
import math
import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import timedelta

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import HashingVectorizer

from .labeling import basename
from .schema import (
    SYSMON_FILE_CREATE,
    SYSMON_NETWORK_CONNECT,
    SysmonRecord,
)

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"\b(?:[A-Fa-f0-9]{2}){12,}\b")
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)

_SPECIAL_RE = re.compile(r"[`^\"';|$&%]")

_PS_ENC_ABBREVS = frozenset(
    {"e", "en", "enc", "enco", "encod", "encode", "encoded", "encodedcommand"}
)
_PS_FLAG_RE = re.compile(r"(?<![A-Za-z0-9])-([A-Za-z]+)(?=[\s=:]|$)")
_POWERSHELL_PARENTS = frozenset({"powershell.exe", "powershell_ise.exe", "pwsh.exe"})

_IEX_RE = re.compile(r"(?i)\biex\b|invoke-expression")
_DOWNLOAD_RE = re.compile(r"(?i)downloadstring|downloadfile|webclient|invoke-webrequest")

OFFICE_PARENTS = frozenset(
    {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
)
BROWSER_PARENTS = frozenset(
    {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"}
)
SUSPICIOUS_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        ("winword.exe", "cmd.exe"),
        ("winword.exe", "powershell.exe"),
        ("winword.exe", "wscript.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "mshta.exe"),
        ("outlook.exe", "cmd.exe"),
        ("powerpnt.exe", "powershell.exe"),
        ("explorer.exe", "wmic.exe"),
        ("services.exe", "cmd.exe"),
        ("svchost.exe", "powershell.exe"),
        ("wmiprvse.exe", "powershell.exe"),
    }
)

SESSION_WINDOW = timedelta(minutes=5)
EFFECTS_WINDOW = timedelta(seconds=60)

DENSE_FEATURE_NAMES = (
    "cmdline_len",
    "cmdline_entropy",
    "has_base64",
    "has_hex_blob",
    "has_enc_flag",
    "has_iex",
    "has_downloadstring",
    "url_count",
    "special_char_ratio",
    "image_path_depth",
    "in_temp_path",
    "renamed_image",
    "parent_is_office",
    "parent_is_browser",
    "suspicious_pair",
    "sibling_count_5m",
    "net_connects_60s",
    "files_written_60s",
)

NGRAM_DIMS = 1024

NGRAM_VECTORIZER_PARAMS: dict[str, object] = {
    "analyzer": "char_wb",
    "ngram_range": (3, 5),
    "alternate_sign": False,
    "norm": "l2",
}


def _has_ps_encoded_flag(cmdline: str) -> bool:
    return any(match.group(1).lower() in _PS_ENC_ABBREVS for match in _PS_FLAG_RE.finditer(cmdline))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in Counter(text).values())


def _dense_row(
    record: SysmonRecord,
    session_count: int,
    effect_counts: tuple[int, int],
) -> list[float]:
    cmdline = record.command_line
    image_base = basename(record.image)
    original = record.original_file_name.lower()
    parent_base = basename(record.parent_image)
    image_path = record.image.lower()
    cmd_len = len(cmdline)
    entropy = shannon_entropy(cmdline)
    has_base64 = 1.0 if _BASE64_RE.search(cmdline) else 0.0
    has_hex = 1.0 if _HEX_RE.search(cmdline) else 0.0
    has_enc = 1.0 if parent_base in _POWERSHELL_PARENTS and _has_ps_encoded_flag(cmdline) else 0.0
    has_iex = 1.0 if _IEX_RE.search(cmdline) else 0.0
    has_dl = 1.0 if _DOWNLOAD_RE.search(cmdline) else 0.0
    url_count = float(len(_URL_RE.findall(cmdline)))
    special_ratio = len(_SPECIAL_RE.findall(cmdline)) / cmd_len if cmd_len else 0.0
    path_depth = float(image_path.count("\\") + image_path.count("/"))
    in_temp = (
        1.0
        if any(s in image_path for s in ("\\temp\\", "\\appdata\\local\\temp\\", "/tmp/"))
        else 0.0
    )
    renamed_image = 1.0 if original and original != image_base else 0.0
    parent_office = 1.0 if parent_base in OFFICE_PARENTS else 0.0
    parent_browser = 1.0 if parent_base in BROWSER_PARENTS else 0.0
    pair_flag = 1.0 if (parent_base, image_base) in SUSPICIOUS_PAIRS else 0.0

    net_connects, file_writes = effect_counts

    return [
        float(cmd_len),
        entropy,
        has_base64,
        has_hex,
        has_enc,
        has_iex,
        has_dl,
        url_count,
        special_ratio,
        path_depth,
        in_temp,
        renamed_image,
        parent_office,
        parent_browser,
        pair_flag,
        float(session_count),
        float(net_connects),
        float(file_writes),
    ]


def _compute_session_counts(
    process_records: Sequence[SysmonRecord],
) -> dict[int, int]:
    by_parent: dict[str, list[tuple[int, SysmonRecord]]] = defaultdict(list)
    for idx, record in enumerate(process_records):
        if record.parent_process_guid:
            by_parent[record.parent_process_guid].append((idx, record))
    for sibling_list in by_parent.values():
        sibling_list.sort(key=lambda pair: pair[1].time_created)

    counts: dict[int, int] = {}
    for sibling_list in by_parent.values():
        times = [pair[1].time_created for pair in sibling_list]
        for right, (orig_idx, record) in enumerate(sibling_list):
            window_start = record.time_created - SESSION_WINDOW
            left = bisect.bisect_left(times, window_start)
            counts[orig_idx] = (right - left + 1) - 1
    return counts


def _compute_effect_counts(
    process_records: Sequence[SysmonRecord], all_records: Sequence[SysmonRecord]
) -> dict[int, tuple[int, int]]:
    net_by_guid: dict[str, list] = defaultdict(list)
    file_by_guid: dict[str, list] = defaultdict(list)
    for record in all_records:
        guid = record.process_guid
        if not guid:
            continue
        if record.event_id == SYSMON_NETWORK_CONNECT:
            net_by_guid[guid].append(record.time_created)
        elif record.event_id == SYSMON_FILE_CREATE:
            file_by_guid[guid].append(record.time_created)
    for times in net_by_guid.values():
        times.sort()
    for times in file_by_guid.values():
        times.sort()

    counts: dict[int, tuple[int, int]] = {}
    for idx, record in enumerate(process_records):
        guid = record.process_guid
        start = record.time_created
        end = start + EFFECTS_WINDOW
        net_times = net_by_guid.get(guid, [])
        file_times = file_by_guid.get(guid, [])

        net = bisect.bisect_left(net_times, end) - bisect.bisect_left(net_times, start)
        files = bisect.bisect_left(file_times, end) - bisect.bisect_left(file_times, start)
        counts[idx] = (net, files)
    return counts


def build_features(
    process_records: Sequence[SysmonRecord],
    all_records: Sequence[SysmonRecord] | None = None,
    *,
    vectorizer: HashingVectorizer | None = None,
) -> tuple[csr_matrix, HashingVectorizer]:
    if all_records is None:
        all_records = process_records

    session_counts = _compute_session_counts(process_records)
    effect_counts = _compute_effect_counts(process_records, all_records)

    dense_rows: list[list[float]] = []
    cmdlines: list[str] = []
    for idx, record in enumerate(process_records):
        sc = session_counts.get(idx, 0)
        ec = effect_counts.get(idx, (0, 0))
        dense_rows.append(_dense_row(record, sc, ec))
        cmdlines.append(record.command_line)

    dense = csr_matrix(np.asarray(dense_rows, dtype=np.float32))

    if vectorizer is None:
        vectorizer = HashingVectorizer(n_features=NGRAM_DIMS, **NGRAM_VECTORIZER_PARAMS)
    sparse_ngrams = vectorizer.transform(cmdlines).astype(np.float32)

    matrix = hstack([dense, sparse_ngrams], format="csr")
    return matrix, vectorizer


def feature_names() -> list[str]:
    return list(DENSE_FEATURE_NAMES) + [f"ngram_{i}" for i in range(NGRAM_DIMS)]
