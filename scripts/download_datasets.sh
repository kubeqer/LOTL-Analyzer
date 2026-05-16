#!/usr/bin/env bash
# Clone the three public LOTL Sysmon corpora into ./datasets/ and ensure
# evtx_dump is available for the EVTX-ATTACK-SAMPLES conversion that runs in
# prepare.py.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATASETS_DIR="${REPO_ROOT}/datasets"
mkdir -p "${DATASETS_DIR}"

log()  { printf '[download] %s\n' "$*"; }
warn() { printf '[download][WARN] %s\n' "$*" >&2; }
die()  { printf '[download][FATAL] %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

require git

OTRF_DIR="${DATASETS_DIR}/Security-Datasets"
if [[ ! -d "${OTRF_DIR}/.git" ]]; then
    log "cloning OTRF Security-Datasets..."
    git clone --depth 1 https://github.com/OTRF/Security-Datasets "${OTRF_DIR}"
else
    log "OTRF Security-Datasets already present, skipping clone"
fi

ATTACK_DATA_DIR="${DATASETS_DIR}/attack_data"
if command -v git-lfs >/dev/null 2>&1; then
    if [[ ! -d "${ATTACK_DATA_DIR}/.git" ]]; then
        log "cloning Splunk attack_data (~9 GB via git-lfs)..."
        git lfs install --skip-repo
        git clone --depth 1 https://github.com/splunk/attack_data "${ATTACK_DATA_DIR}"
    else
        log "Splunk attack_data already present, skipping clone"
    fi
else
    warn "git-lfs not installed — skipping Splunk attack_data."
    warn "Install with: sudo apt install git-lfs   (or brew install git-lfs)"
fi

EVTX_DIR="${DATASETS_DIR}/EVTX-ATTACK-SAMPLES"
if [[ ! -d "${EVTX_DIR}/.git" ]]; then
    log "cloning EVTX-ATTACK-SAMPLES..."
    git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES "${EVTX_DIR}"
else
    log "EVTX-ATTACK-SAMPLES already present, skipping clone"
fi

if ! command -v evtx_dump >/dev/null 2>&1; then
    if command -v cargo >/dev/null 2>&1; then
        log "installing evtx_dump via cargo..."
        cargo install evtx
    else
        warn "evtx_dump not on PATH and cargo not installed."
        warn "Either install Rust (https://rustup.rs/) and re-run, or install evtx_dump manually."
        warn "EVTX-ATTACK-SAMPLES conversion in prepare.py will be skipped without it."
    fi
fi

log "done. datasets are under ${DATASETS_DIR}"
