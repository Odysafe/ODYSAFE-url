from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from app.analyzers import analyze_behavior, analyze_downloads, analyze_with_yara


def _normalize_detection(detection: dict[str, Any]) -> dict[str, Any]:
    identity = json.dumps({"engine": detection.get("engine"),
                           "rule_id": detection.get("rule_id"),
                           "evidence": detection.get("evidence", [])},
                          sort_keys=True, separators=(",", ":"))
    normalized = dict(detection)
    normalized["id"] = f"{detection.get('engine', 'unknown')}.{hashlib.sha256(identity.encode()).hexdigest()[:16]}"
    return normalized


def run_detections(scan_dir: Path, project_root: Path, database_path: Path | None = None,
                   *, enable_yara: bool = True,
                   observed_domains: list[str] | None = None,
                   selected_yara_sources: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    behavior = analyze_behavior(scan_dir, project_root / "rules" / "behavior" / "rules.json")
    files = analyze_downloads(scan_dir / "downloads")
    custom_sources = []
    database_path = database_path or (Path(os.environ["ODYSAFE_DB_PATH"]) if os.environ.get("ODYSAFE_DB_PATH") else None)
    if selected_yara_sources is None and database_path and Path(database_path).is_file() and not Path(database_path).is_symlink():
        try:
            from app.database import Database
            from app.rules import RuleRegistry
            custom_sources, _ = RuleRegistry(Database(Path(database_path)),
                                             project_root / "rules" / "yara").active_sources()
            custom_sources = [item for item in custom_sources if not item[0].startswith("builtin:")]
        except Exception:
            custom_sources = []
    effective_sources = selected_yara_sources if selected_yara_sources is not None else custom_sources
    yara = (analyze_with_yara(scan_dir, project_root / "rules" / "yara", files, custom_sources,
                              observed_domains, selected_sources=effective_sources)
            if enable_yara and effective_sources else {"status":"not_performed",
                                 "reason":"no_active_rules" if enable_yara else "disabled",
                                 "detections":[],"warnings":[],
                                 "errors":[],"rule_set":{},"execution":{"artifacts_scanned":0,
                                 "files_skipped":0,"matches":0}})
    unique: dict[str, dict[str, Any]] = {}
    for detection in behavior["detections"] + yara["detections"]:
        normalized = _normalize_detection(detection)
        unique.setdefault(normalized["id"], normalized)
    detections = sorted(unique.values(), key=lambda item: (item["engine"], item["rule_id"], item["id"]))
    engines = {
        "behavior": {key: behavior[key] for key in ("status", "warnings", "errors")},
        "file_analysis": {key: files[key] for key in ("status", "warnings", "errors")},
        "yara_x": {key: yara[key] for key in ("status", "warnings", "errors", "rule_set", "execution") if key in yara},
    }
    return {
        "detections": detections,
        "detection_summary": {
            "total": len(detections),
            "by_engine": dict(sorted(Counter(item["engine"] for item in detections).items())),
            "by_severity": dict(sorted(Counter(item["severity"] for item in detections).items())),
        },
        "detection_engines": engines,
        "file_analysis": files,
    }
