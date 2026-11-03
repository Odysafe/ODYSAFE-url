from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.analyzers import HarAnalysisError, Har2TreeAdapterError, analyze_har, build_har2tree
from app.reporting.normalize import json_safe
from app.reporting.detections import run_detections
from app.config import PROJECT_ROOT
from app.reporting.investigation import javascript_observations, relation_graph


class ReportBuildError(RuntimeError):
    """The scan directory cannot be used to build a report."""


def _regular_file(path: Path, required: bool = True) -> bool:
    if path.is_symlink():
        raise ReportBuildError(f"Symbolic links are forbidden: {path.name}")
    if not path.is_file():
        if required:
            raise ReportBuildError(f"Missing artifact: {path.name}")
        return False
    return True


def _read_json(path: Path, required: bool = True) -> dict[str, Any] | None:
    if not _regular_file(path, required):
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportBuildError(f"Invalid {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReportBuildError(f"{path.name} must contain a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _download_indicators(directory: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if directory.is_symlink():
        raise ReportBuildError("Symbolic links are forbidden: downloads")
    if not directory.exists():
        return [], []
    if not directory.is_dir():
        raise ReportBuildError("downloads must be a directory")
    files = []
    hashes = []
    metadata: dict[str, dict[str, Any]] = {}
    manifest = directory.parent / "downloads.json"
    if manifest.is_file() and not manifest.is_symlink():
        try:
            parsed = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(parsed, list):
                metadata = {str(item.get("stored_name")): item for item in parsed if isinstance(item, dict)}
        except (OSError, UnicodeError, json.JSONDecodeError):
            metadata = {}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_symlink():
            raise ReportBuildError(f"Symbolic links are forbidden: downloads/{path.name}")
        if not path.is_file():
            continue
        sha256 = _sha256(path)
        item = metadata.get(path.name, {})
        files.append({"path": f"downloads/{path.name}", "stored_name": path.name,
                      "original_name": item.get("original_name") or path.name,
                      "source_url": item.get("source_url"), "status": "collected",
                      "size": path.stat().st_size, "sha256": sha256})
        hashes.append(sha256)
    for item in metadata.values():
        if item.get("status") != "collected":
            files.append({"original_name": item.get("original_name"), "source_url": item.get("source_url"),
                          "status": item.get("status", "unavailable"), "size": item.get("size"),
                          "sha256": None, "path": None})
    return files, hashes


def _network_indicators(hosts: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    domains: set[str] = set()
    ips: set[str] = {ip for host in hosts for ip in host["ip_addresses"]}
    for host in hosts:
        try:
            ips.add(str(ipaddress.ip_address(host["hostname"])))
        except ValueError:
            domains.add(host["hostname"])
    return sorted(domains), sorted(ips)


def _browser_events_summary(scan_dir: Path) -> tuple[dict[str, Any], list[str]]:
    path = scan_dir / "browser_events.json"
    if not path.exists():
        return ({"status": "not_collected", "total": None, "counts_by_type": {},
                 "events": [], "warnings": [], "artifact": None}, [])
    try:
        artifact = _read_json(path)
        assert artifact is not None
        instrumentation = artifact.get("instrumentation")
        events = artifact.get("events")
        if not isinstance(instrumentation, dict) or not isinstance(events, list):
            raise ReportBuildError("browser_events.json has an invalid structure")
        clean_events = []
        for index, event in enumerate(events, 1):
            if (not isinstance(event, dict) or not isinstance(event.get("type"), str)
                    or not isinstance(event.get("details"), dict)):
                raise ReportBuildError(f"browser_events.json event {index} is invalid")
            clean_events.append(event)
        counts = Counter(event["type"] for event in clean_events)
        warnings = artifact.get("warnings", [])
        if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
            raise ReportBuildError("browser_events.json warnings must be strings")
        return ({"status": instrumentation.get("status", "unknown"),
                 "total": len(clean_events), "counts_by_type": dict(sorted(counts.items())),
                 "events": clean_events, "warnings": warnings,
                 "artifact": "browser_events.json"}, [])
    except ReportBuildError as exc:
        return ({"status": "failed", "total": None, "counts_by_type": {},
                 "events": [], "warnings": [str(exc)],
                 "artifact": "browser_events.json"}, [str(exc)])


def _atomic_write(path: Path, report: dict[str, Any]) -> None:
    payload = json.dumps(json_safe(report), ensure_ascii=False, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def build_report(scan_dir: Path, database_path: Path | None = None, *,
                 enable_yara: bool = True,
                 selected_yara_sources: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    """Rebuild report.json solely from local artifacts, without navigation."""
    scan_dir = Path(scan_dir)
    if scan_dir.is_symlink() or not scan_dir.is_dir():
        raise ReportBuildError("Scan directory must be a regular directory")
    meta = _read_json(scan_dir / "meta.json", required=False)
    warnings: list[str] = []
    errors: list[str] = []
    if meta is None:
        meta = {}
        warnings.append("meta.json is missing")
    else:
        missing_meta = [name for name in ("scan_id", "status", "submitted_url", "final_url")
                        if name not in meta]
        if missing_meta:
            warnings.append(f"meta.json is missing fields: {', '.join(missing_meta)}")
    har_path = scan_dir / "network.har"
    analysis: dict[str, Any] | None = None
    tree = None
    try:
        analysis = analyze_har(har_path)
    except (HarAnalysisError, ReportBuildError) as exc:
        errors.append(str(exc))
    if analysis is not None:
        try:
            tree = build_har2tree(har_path, str(meta.get("scan_id") or scan_dir.name))
        except Har2TreeAdapterError as exc:
            errors.append(str(exc))
    downloads, download_hashes = _download_indicators(scan_dir / "downloads")
    domains, ips = _network_indicators(analysis["hosts"] if analysis else [])
    browser_events, browser_warnings = _browser_events_summary(scan_dir)
    warnings.extend(browser_warnings)
    detection_result = run_detections(scan_dir, PROJECT_ROOT, database_path, enable_yara=enable_yara,
                                      observed_domains=domains,
                                      selected_yara_sources=selected_yara_sources)
    detection_problem = any(engine["status"] in {"partial", "error"}
                            for engine in detection_result["detection_engines"].values())
    if analysis is None:
        status = "failed"
    elif errors or warnings or detection_problem:
        status = "partial"
    else:
        status = "completed"
    empty_network = {"total_requests": 0, "total_responses": 0, "methods": {},
                     "status_codes": {}, "content_types": {}, "distinct_hosts": 0,
                     "distinct_urls": 0, "requests": []}
    report = {
        "schema_version": "1.0",
        "scan_id": meta.get("scan_id", scan_dir.name),
        "analysis_status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overview": {
            "submitted_url": meta.get("submitted_url"), "final_url": meta.get("final_url"),
            "title": meta.get("title"), "capture_status": meta.get("status", "unknown"),
            "profile": meta.get("profile"), "browser": meta.get("browser"),
            "duration_ms": meta.get("duration_ms"),
        },
        "network": analysis["network"] if analysis else empty_network,
        "hosts": analysis["hosts"] if analysis else [],
        "urls": analysis["urls"] if analysis else [],
        "navigation": {
            "final_url": meta.get("final_url"),
            "observed_redirects": analysis["http_redirects"] if analysis else [],
            "tree": tree,
        },
        "indicators": {
            "urls": analysis["urls"] if analysis else [],
            "domains": domains,
            "ips": ips,
            "hashes": download_hashes,
        },
        "artifacts": meta.get("artifacts", {"har": "network.har", "dom": "dom.html",
            "screenshot": "screenshot.png", "cookies": "cookies.json",
            "console": "console.json", "downloads": "downloads/",
            "browser_events": "browser_events.json"}),
        "downloaded_files": downloads,
        "javascript": javascript_observations(scan_dir),
        "browser_events": browser_events,
        "capture_limits": meta.get("capture_limits", {}),
        "detections": detection_result["detections"],
        "detection_summary": detection_result["detection_summary"],
        "detection_engines": detection_result["detection_engines"],
        "file_analysis": detection_result["file_analysis"],
        "warnings": warnings, "errors": errors,
    }
    report["relations"] = relation_graph(scan_dir, report)
    _atomic_write(scan_dir / "report.json", report)
    return report
