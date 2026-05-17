from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import yaml

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent.parent
DATASETS = REPO_ROOT / "datasets"

OTRF_ROOT = DATASETS / "Security-Datasets" / "datasets"
ATTACK_DATA_ROOT = DATASETS / "attack_data" / "datasets" / "attack_techniques"
EVTX_SAMPLES_ROOT = DATASETS / "EVTX-ATTACK-SAMPLES"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prepare")

T_CODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _read_yaml(path: Path) -> dict | list | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        logger.warning("cannot read %s: %s", path, error)
        return None


def _write_manifest(capture_dir: Path, malicious: bool, techniques: list[str]) -> None:
    manifest = {"malicious": bool(malicious), "techniques": sorted(set(techniques))}
    (capture_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _otrf_techniques_from_yaml(payload: dict | list | None) -> tuple[list[str], bool]:
    if not isinstance(payload, dict):
        return [], True
    techniques: list[str] = []
    for mapping in payload.get("attack_mappings") or []:
        if isinstance(mapping, dict):
            value = mapping.get("technique")
            if value:
                value = str(value)
                if not value.startswith("T"):
                    value = "T" + value
                if mapping.get("sub-technique"):
                    sub = str(mapping["sub-technique"]).lstrip(".")
                    value = f"{value}.{sub}" if "." not in value else value
                techniques.append(value)
    tags = payload.get("tags") or []
    is_benign = any("benign" in str(t).lower() for t in tags) if isinstance(tags, list) else False
    return techniques, not is_benign


def _otrf_relative_from_link(link: str) -> Path | None:
    marker = "/datasets/"
    idx = link.find(marker)
    if idx == -1:
        return None
    return Path(link[idx + len(marker) :])


def prepare_otrf(root: Path) -> int:
    if not root.exists():
        logger.info("OTRF not found at %s — skipping", root)
        return 0
    logger.info("preparing OTRF Security-Datasets at %s", root)
    n_prepared = 0
    for dataset_yaml in sorted(root.rglob("_metadata/*.yaml")):
        payload = _read_yaml(dataset_yaml)
        if not isinstance(payload, dict):
            continue
        techniques, malicious = _otrf_techniques_from_yaml(payload)
        for entry in payload.get("files") or []:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("type", "")).lower() != "host":
                continue
            link = str(entry.get("link") or "")
            relative = _otrf_relative_from_link(link)
            if relative is None:
                continue
            zip_path = root / relative
            if not zip_path.exists() or zip_path.suffix.lower() != ".zip":
                continue
            capture_dir = zip_path.with_suffix("")
            capture_dir.mkdir(parents=True, exist_ok=True)
            marker = capture_dir / ".extracted"
            if not marker.exists():
                try:
                    with zipfile.ZipFile(zip_path) as archive:
                        archive.extractall(capture_dir)
                    marker.touch()
                except zipfile.BadZipFile:
                    logger.warning("bad zip: %s", zip_path)
                    continue
            renamed_any = False
            for inner in list(capture_dir.iterdir()):
                if inner.is_file() and inner.suffix.lower() == ".json":
                    target = inner.with_suffix(".jsonl")
                    if not target.exists():
                        inner.rename(target)
                    renamed_any = True
            if not renamed_any and not any(capture_dir.glob("*.jsonl")):
                continue
            _write_manifest(capture_dir, malicious=malicious, techniques=techniques)
            n_prepared += 1
    logger.info("OTRF: %d captures prepared", n_prepared)
    return n_prepared


_SYSMON_FILENAMES = {"windows-sysmon.log", "sysmon.log", "windows-sysmon.json"}


def _attack_data_technique_from_path(path: Path) -> str | None:
    for part in path.parts:
        match = T_CODE_RE.fullmatch(part)
        if match:
            return match.group(0)
        match = T_CODE_RE.search(part)
        if match:
            return match.group(0)
    return None


def _is_attack_data_capture(directory: Path) -> bool:
    if not directory.is_dir():
        return False
    for filename in _SYSMON_FILENAMES:
        if (directory / filename).exists():
            return True
    return any(directory.glob("windows-sysmon*"))


def prepare_attack_data(root: Path) -> int:
    if not root.exists():
        logger.info("Splunk attack_data not found at %s — skipping", root)
        return 0
    logger.info("preparing Splunk attack_data at %s", root)
    n_prepared = 0
    for capture_dir in sorted(p for p in root.rglob("*") if p.is_dir()):
        if not _is_attack_data_capture(capture_dir):
            continue

        techniques: list[str] = []
        for manifest_yaml in capture_dir.glob("*manifest*.yml"):
            payload = _read_yaml(manifest_yaml)
            if isinstance(payload, dict):
                attack = payload.get("attack_dataset") or {}
                value = attack.get("id") if isinstance(attack, dict) else None
                if value:
                    techniques.append(str(value))
        if not techniques:
            inferred = _attack_data_technique_from_path(capture_dir.relative_to(root))
            if inferred:
                techniques.append(inferred)

        for sysmon_file in capture_dir.iterdir():
            if not sysmon_file.is_file():
                continue
            name = sysmon_file.name.lower()
            if name.startswith("windows-sysmon") and sysmon_file.suffix in {".log", ".json"}:
                target = sysmon_file.with_suffix(".jsonl")
                if target.exists() and target.stat().st_mtime >= sysmon_file.stat().st_mtime:
                    continue
                if target.exists():
                    target.unlink()

                try:
                    os.link(sysmon_file, target)
                except OSError:
                    shutil.copyfile(sysmon_file, target)
        _write_manifest(capture_dir, malicious=True, techniques=techniques)
        n_prepared += 1
    logger.info("attack_data: %d captures prepared", n_prepared)
    return n_prepared


def _evtx_dump_available() -> bool:
    return shutil.which("evtx_dump") is not None


def _evtx_techniques_from_name(evtx_path: Path, repo_root: Path) -> list[str]:
    relative_parts = evtx_path.relative_to(repo_root).parts
    found: list[str] = []
    for part in relative_parts:
        found.extend(T_CODE_RE.findall(part))
    return found


def prepare_evtx_samples(root: Path) -> int:
    if not root.exists():
        logger.info("EVTX-ATTACK-SAMPLES not found at %s — skipping", root)
        return 0
    if not _evtx_dump_available():
        logger.warning(
            "evtx_dump not on PATH — skipping EVTX-ATTACK-SAMPLES. "
            "Install via `cargo install evtx` and re-run."
        )
        return 0
    logger.info("preparing EVTX-ATTACK-SAMPLES at %s", root)
    n_prepared = 0
    for evtx_path in root.rglob("*.evtx"):
        capture_dir = evtx_path.parent / evtx_path.stem
        capture_dir.mkdir(parents=True, exist_ok=True)
        jsonl_out = capture_dir / "events.jsonl"
        if jsonl_out.exists() and jsonl_out.stat().st_mtime >= evtx_path.stat().st_mtime:
            techniques = _evtx_techniques_from_name(evtx_path, root)
            _write_manifest(capture_dir, malicious=True, techniques=techniques)
            n_prepared += 1
            continue
        try:
            subprocess.run(
                ["evtx_dump", "-o", "jsonl", "-t", "1", "-f", str(jsonl_out), str(evtx_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as error:
            logger.warning("evtx_dump failed for %s: %s", evtx_path, error)
            continue
        except subprocess.CalledProcessError as error:
            stderr_excerpt = (error.stderr or b"")[:200].decode("utf-8", errors="replace").strip()
            logger.warning("evtx_dump failed for %s: %s — %s", evtx_path, error, stderr_excerpt)
            continue
        techniques = _evtx_techniques_from_name(evtx_path, root)
        _write_manifest(capture_dir, malicious=True, techniques=techniques)
        n_prepared += 1
    logger.info("EVTX-ATTACK-SAMPLES: %d captures prepared", n_prepared)
    return n_prepared


def main() -> None:
    if not DATASETS.exists():
        logger.error("datasets/ not found at %s — run scripts/download_datasets.sh first", DATASETS)
        raise SystemExit(2)

    total = 0
    total += prepare_otrf(OTRF_ROOT)
    total += prepare_attack_data(ATTACK_DATA_ROOT)
    total += prepare_evtx_samples(EVTX_SAMPLES_ROOT)
    logger.info("done — %d captures prepared in total", total)
    if total == 0:
        logger.error(
            "No captures prepared. Did download_datasets.sh complete? "
            "Check that the directories exist under %s.",
            DATASETS,
        )
        raise SystemExit(2)


if __name__ == "__main__":
    main()
