from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .connection import Database

MAX_JSON_BYTES = 4 * 1024 * 1024


def _read_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if path.is_symlink() or not path.is_file():
        return None, None
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            return None, f"{path.name} exceeds {MAX_JSON_BYTES} bytes"
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None, f"{path.name} is not an object"
        return value, None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"invalid {path.name}: {exc}"


def _text(value: Any, limit: int = 8192) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def reconcile_scans(database: Database, scans_root: Path) -> dict[str, int]:
    scans_root = Path(scans_root)
    counts = {"indexed": 0, "unchanged": 0, "invalid": 0}
    now = datetime.now(timezone.utc).isoformat()
    present: set[str] = set()
    if scans_root.is_symlink():
        raise RuntimeError("Scans root must not be symbolic")
    scans_root.mkdir(parents=True, exist_ok=True)
    with database.transaction() as connection:
        hidden = {row[0] for row in connection.execute("SELECT scan_id FROM hidden_scans")}
        for entry in sorted(scans_root.iterdir(), key=lambda item: item.name):
            try:
                parsed = uuid.UUID(entry.name)
                valid = str(parsed) == entry.name and entry.is_dir() and not entry.is_symlink()
            except ValueError:
                valid = False
            if not valid:
                counts["invalid"] += 1
                continue
            present.add(entry.name)
            mtimes = [entry.stat().st_mtime_ns]
            for filename in ("meta.json", "report.json"):
                path = entry / filename
                if path.exists() and not path.is_symlink():
                    mtimes.append(path.stat().st_mtime_ns)
            source_mtime = max(mtimes)
            previous = connection.execute(
                "SELECT source_mtime_ns FROM scans WHERE scan_id=?", (entry.name,)).fetchone()
            if previous and previous[0] == source_mtime:
                connection.execute("UPDATE scans SET present=? WHERE scan_id=?",
                                   (0 if entry.name in hidden else 1, entry.name))
                counts["unchanged"] += 1
                continue
            meta, meta_error = _read_object(entry / "meta.json")
            report, report_error = _read_object(entry / "report.json")
            meta, report = meta or {}, report or {}
            overview = report.get("overview") if isinstance(report.get("overview"), dict) else {}
            network = report.get("network") if isinstance(report.get("network"), dict) else {}
            indicators = report.get("indicators") if isinstance(report.get("indicators"), dict) else {}
            submitted = _text(overview.get("submitted_url")) or _text(meta.get("submitted_url"))
            final = _text(overview.get("final_url")) or _text(meta.get("final_url"))
            host = None
            try:
                host = urlsplit(final or submitted or "").hostname
            except ValueError:
                pass
            detections = report.get("detection_summary")
            detection_count = _integer(detections.get("total")) if isinstance(detections, dict) else 0
            hosts = report.get("hosts")
            connection.execute("""
                INSERT INTO scans(scan_id,present,indexed_at,source_mtime_ns,capture_date,
                 submitted_url,final_url,host,profile,browser,capture_status,analysis_status,
                 duration_ms,request_count,host_count,detection_count,report_available,
                 report_error,indicators_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(scan_id) DO UPDATE SET present=excluded.present,indexed_at=excluded.indexed_at,
                 source_mtime_ns=excluded.source_mtime_ns,capture_date=excluded.capture_date,
                 submitted_url=excluded.submitted_url,final_url=excluded.final_url,host=excluded.host,
                 profile=excluded.profile,browser=excluded.browser,capture_status=excluded.capture_status,
                 analysis_status=excluded.analysis_status,duration_ms=excluded.duration_ms,
                 request_count=excluded.request_count,host_count=excluded.host_count,
                 detection_count=excluded.detection_count,report_available=excluded.report_available,
                 report_error=excluded.report_error,indicators_json=excluded.indicators_json
            """, (entry.name, 0 if entry.name in hidden else 1, now, source_mtime, _text(meta.get("started_at")) or
                    _text(report.get("generated_at")), submitted, final, host,
                    _text(overview.get("profile")) or _text(meta.get("profile")),
                    _text(overview.get("browser")) or _text(meta.get("browser")),
                    _text(overview.get("capture_status")) or _text(meta.get("status")) or "unknown",
                    _text(report.get("analysis_status")) or "not_analyzed",
                    _integer(overview.get("duration_ms")) or _integer(meta.get("duration_ms")),
                    _integer(network.get("total_requests")) or 0,
                    len(hosts) if isinstance(hosts, list) else 0, detection_count or 0,
                    int(bool(report)), report_error or meta_error,
                    json.dumps(indicators, ensure_ascii=False)[:65536]))
            counts["indexed"] += 1
        connection.execute("UPDATE scans SET present=0")
        visible = present - hidden
        if visible:
            placeholders = ",".join("?" for _ in visible)
            connection.execute(f"UPDATE scans SET present=1 WHERE scan_id IN ({placeholders})", tuple(visible))
        connection.execute("INSERT OR REPLACE INTO scan_index_state(key,value) VALUES('last_reconcile',?)", (now,))
    return counts
