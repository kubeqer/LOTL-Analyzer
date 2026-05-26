from __future__ import annotations

import bisect
import math
import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import HashingVectorizer

from ..schema import SysmonEvent

SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_FILE_CREATE = 11

SESSION_WINDOW = timedelta(minutes=5)
EFFECTS_WINDOW = timedelta(seconds=60)

TEMP_PATH_MARKERS = ("\\temp\\", "\\appdata\\local\\temp\\", "/tmp/")

EPOCH = datetime(1970, 1, 1)

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"\b(?:[A-Fa-f0-9]{2}){12,}\b")
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_SPECIAL_RE = re.compile(r"[`^\"';|$&%]")
_PS_FLAG_RE = re.compile(r"(?<![A-Za-z0-9])-([A-Za-z]+)(?=[\s=:]|$)")
_IEX_RE = re.compile(r"(?i)\biex\b|invoke-expression")
_DOWNLOAD_RE = re.compile(r"(?i)downloadstring|downloadfile|webclient|invoke-webrequest")

_PS_ENC_ABBREVS = frozenset(
    {"e", "en", "enc", "enco", "encod", "encode", "encoded", "encodedcommand"}
)
_POWERSHELL_PARENTS = frozenset({"powershell.exe", "powershell_ise.exe", "pwsh.exe"})

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


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _parse_time(raw: str) -> datetime:
    if not raw:
        return EPOCH
    cleaned = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return EPOCH
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in Counter(text).values())


def _has_ps_encoded_flag(cmdline: str) -> bool:
    return any(m.group(1).lower() in _PS_ENC_ABBREVS for m in _PS_FLAG_RE.finditer(cmdline))


def _dense_row(
    event: SysmonEvent,
    session_count: int,
    effect_counts: tuple[int, int],
) -> list[float]:
    cmdline = event.data.get("CommandLine", "")
    image = event.data.get("Image", "")
    original = event.data.get("OriginalFileName", "").lower()
    parent_image = event.data.get("ParentImage", "")
    image_base = _basename(image)
    parent_base = _basename(parent_image)
    image_path = image.lower()
    cmd_len = len(cmdline)
    entropy = _shannon_entropy(cmdline)
    has_base64 = 1.0 if _BASE64_RE.search(cmdline) else 0.0
    has_hex = 1.0 if _HEX_RE.search(cmdline) else 0.0
    has_enc = 1.0 if parent_base in _POWERSHELL_PARENTS and _has_ps_encoded_flag(cmdline) else 0.0
    has_iex = 1.0 if _IEX_RE.search(cmdline) else 0.0
    has_dl = 1.0 if _DOWNLOAD_RE.search(cmdline) else 0.0
    url_count = float(len(_URL_RE.findall(cmdline)))
    special_ratio = len(_SPECIAL_RE.findall(cmdline)) / cmd_len if cmd_len else 0.0
    path_depth = float(image_path.count("\\") + image_path.count("/"))
    in_temp = 1.0 if any(marker in image_path for marker in TEMP_PATH_MARKERS) else 0.0
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
    process_events: Sequence[SysmonEvent],
    times: Sequence[datetime],
) -> dict[int, int]:
    by_parent: dict[str, list[tuple[int, datetime]]] = defaultdict(list)
    for index, event in enumerate(process_events):
        parent_guid = event.data.get("ParentProcessGuid", "")
        if parent_guid:
            by_parent[parent_guid].append((index, times[index]))
    for sibling_list in by_parent.values():
        sibling_list.sort(key=lambda pair: pair[1])

    counts: dict[int, int] = {}
    for sibling_list in by_parent.values():
        ordered_times = [pair[1] for pair in sibling_list]
        for right, (original_index, when) in enumerate(sibling_list):
            window_start = when - SESSION_WINDOW
            left = bisect.bisect_left(ordered_times, window_start)
            counts[original_index] = (right - left + 1) - 1
    return counts


def _compute_effect_counts(
    process_events: Sequence[SysmonEvent],
    process_times: Sequence[datetime],
    all_events: Sequence[SysmonEvent],
    all_times: Sequence[datetime],
) -> dict[int, tuple[int, int]]:
    net_by_guid: dict[str, list[datetime]] = defaultdict(list)
    file_by_guid: dict[str, list[datetime]] = defaultdict(list)
    for event, when in zip(all_events, all_times, strict=True):
        guid = event.data.get("ProcessGuid", "")
        if not guid:
            continue
        if event.event_id == SYSMON_NETWORK_CONNECT:
            net_by_guid[guid].append(when)
        elif event.event_id == SYSMON_FILE_CREATE:
            file_by_guid[guid].append(when)
    for series in net_by_guid.values():
        series.sort()
    for series in file_by_guid.values():
        series.sort()

    counts: dict[int, tuple[int, int]] = {}
    for index, event in enumerate(process_events):
        guid = event.data.get("ProcessGuid", "")
        start = process_times[index]
        end = start + EFFECTS_WINDOW
        net_times = net_by_guid.get(guid, [])
        file_times = file_by_guid.get(guid, [])
        net = bisect.bisect_left(net_times, end) - bisect.bisect_left(net_times, start)
        files = bisect.bisect_left(file_times, end) - bisect.bisect_left(file_times, start)
        counts[index] = (net, files)
    return counts


def build_features(events: Sequence[SysmonEvent]) -> tuple[csr_matrix, list[int]]:
    all_times = [_parse_time(e.time_created) for e in events]
    process_indices = [i for i, e in enumerate(events) if e.event_id == SYSMON_PROCESS_CREATE]
    process_events = [events[i] for i in process_indices]
    process_times = [all_times[i] for i in process_indices]

    if not process_events:
        return csr_matrix((0, len(DENSE_FEATURE_NAMES) + NGRAM_DIMS), dtype=np.float32), []

    session_counts = _compute_session_counts(process_events, process_times)
    effect_counts = _compute_effect_counts(process_events, process_times, events, all_times)

    dense_rows: list[list[float]] = []
    cmdlines: list[str] = []
    for local_index, event in enumerate(process_events):
        sc = session_counts.get(local_index, 0)
        ec = effect_counts.get(local_index, (0, 0))
        dense_rows.append(_dense_row(event, sc, ec))
        cmdlines.append(event.data.get("CommandLine", ""))

    dense = csr_matrix(np.asarray(dense_rows, dtype=np.float32))
    vectorizer = HashingVectorizer(n_features=NGRAM_DIMS, **NGRAM_VECTORIZER_PARAMS)
    sparse_ngrams = vectorizer.transform(cmdlines).astype(np.float32)
    matrix = hstack([dense, sparse_ngrams], format="csr")
    return matrix, process_indices
