from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_DOMAINS = 500
SPECIAL_SUFFIXES = (".local", ".localhost", ".test", ".invalid", ".example", ".internal")


def normalize_public_domain(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or len(value) > 253:
        raise ValueError("Invalid domain")
    try: ipaddress.ip_address(value); raise ValueError("IP literals are not DNS enrichment domains")
    except ValueError as exc:
        if "literals" in str(exc): raise
    try: normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc: raise ValueError("Invalid IDNA domain") from exc
    if "." not in normalized or normalized == "localhost" or normalized.endswith(SPECIAL_SUFFIXES):
        raise ValueError("Private or special-use domain")
    labels = normalized.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("Invalid domain")
    return normalized


def _host_from_url(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 8192: return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password: return None
        return parsed.hostname
    except ValueError: return None


def extract_domains(scan_dir: Path, limit: int = MAX_DOMAINS) -> list[dict[str, str]]:
    report_path = Path(scan_dir) / "report.json"
    if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Report unavailable or too large")
    report = json.loads(report_path.read_text(encoding="utf-8")); candidates: list[str] = []
    overview = report.get("overview") if isinstance(report.get("overview"), dict) else {}
    for key in ("submitted_url", "final_url"):
        host = _host_from_url(overview.get(key))
        if host: candidates.append(host)
    indicators = report.get("indicators") if isinstance(report.get("indicators"), dict) else {}
    for value in indicators.get("domains", []) if isinstance(indicators.get("domains"), list) else []:
        if isinstance(value, str): candidates.append(value)
    for value in indicators.get("urls", []) if isinstance(indicators.get("urls"), list) else []:
        host = _host_from_url(value)
        if host: candidates.append(host)
    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    for item in network.get("requests", []) if isinstance(network.get("requests"), list) else []:
        if isinstance(item, dict):
            host = _host_from_url(item.get("url"))
            if host: candidates.append(host)
    seen = set(); output = []
    for original in candidates:
        try: normalized = normalize_public_domain(original)
        except ValueError: continue
        if normalized not in seen:
            output.append({"original": original[:253], "normalized": normalized}); seen.add(normalized)
            if len(output) >= min(limit, MAX_DOMAINS): break
    return output
