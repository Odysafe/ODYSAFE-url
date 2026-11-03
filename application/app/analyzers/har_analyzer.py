from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_HAR_BYTES = 100 * 1024 * 1024


class HarAnalysisError(ValueError):
    """The HAR cannot be safely parsed as a collection of transactions."""


def _read_har(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise HarAnalysisError("network.har must be a regular file")
    if path.stat().st_size > MAX_HAR_BYTES:
        raise HarAnalysisError(f"HAR exceeds the {MAX_HAR_BYTES} byte limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HarAnalysisError(f"Invalid HAR JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("log"), dict):
        raise HarAnalysisError("HAR must contain a log object")
    entries = data["log"].get("entries")
    if not isinstance(entries, list):
        raise HarAnalysisError("HAR log.entries must be an array")
    return data


def _number(value: Any) -> int | float | None:
    return value if isinstance(value, (int, float)) and value >= 0 else None


def _header(headers: Any, name: str) -> str | None:
    if not isinstance(headers, list):
        return None
    for item in headers:
        if isinstance(item, dict) and str(item.get("name", "")).lower() == name.lower():
            value = item.get("value")
            return value if isinstance(value, str) and value else None
    return None


def analyze_har(path: Path) -> dict[str, Any]:
    """Return deterministic, body-free observations from a HAR file."""
    data = _read_har(Path(path))
    transactions: list[dict[str, Any]] = []
    methods: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    content_types: Counter[str] = Counter()
    host_urls: dict[str, set[str]] = defaultdict(set)
    host_transactions: Counter[str] = Counter()
    host_ips: dict[str, set[str]] = defaultdict(set)
    distinct_urls: set[str] = set()
    redirects: list[dict[str, Any]] = []

    for index, entry in enumerate(data["log"]["entries"], 1):
        if not isinstance(entry, dict):
            raise HarAnalysisError(f"HAR entry {index} must be an object")
        request = entry.get("request")
        response = entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise HarAnalysisError(f"HAR entry {index} requires request and response objects")
        url = request.get("url")
        method = request.get("method")
        if not isinstance(url, str) or not url or not isinstance(method, str) or not method:
            raise HarAnalysisError(f"HAR entry {index} has an invalid request")
        parsed = urlsplit(url)
        hostname = parsed.hostname.lower() if parsed.hostname else None
        status = response.get("status") if isinstance(response.get("status"), int) else None
        content = response.get("content") if isinstance(response.get("content"), dict) else {}
        mime = content.get("mimeType") if isinstance(content.get("mimeType"), str) else None
        mime = mime.split(";", 1)[0].strip().lower() if mime else None
        redirect_target = response.get("redirectURL")
        if not isinstance(redirect_target, str) or not redirect_target:
            redirect_target = _header(response.get("headers"), "location")
        if redirect_target and 300 <= (status or 0) < 400:
            redirect_target = urljoin(url, redirect_target)
        else:
            redirect_target = None
        transaction_id = f"request-{index:06d}"
        transaction = {
            "id": transaction_id,
            "url": url,
            "hostname": hostname,
            "method": method.upper(),
            "status": status,
            "mime_type": mime,
            "started_at": entry.get("startedDateTime") if isinstance(entry.get("startedDateTime"), str) else None,
            "duration_ms": _number(entry.get("time")),
            "request_body_size": _number(request.get("bodySize")),
            "response_body_size": _number(response.get("bodySize")),
            "response_content_size": _number(content.get("size")),
            "server_ip_address": entry.get("serverIPAddress") if isinstance(entry.get("serverIPAddress"), str) else None,
            "redirect_url": redirect_target,
            "page_ref": entry.get("pageref") if isinstance(entry.get("pageref"), str) else None,
        }
        transactions.append(transaction)
        methods[transaction["method"]] += 1
        if status is not None:
            statuses[str(status)] += 1
        if mime:
            content_types[mime] += 1
        distinct_urls.add(url)
        if hostname:
            host_transactions[hostname] += 1
            host_urls[hostname].add(url)
            if transaction["server_ip_address"]:
                host_ips[hostname].add(transaction["server_ip_address"])
        if redirect_target:
            redirects.append({"source": url, "target": redirect_target,
                              "status": status, "transaction_id": transaction_id,
                              "mechanism": "http"})

    hosts = [{"hostname": host, "transaction_count": host_transactions[host],
              "urls": sorted(host_urls[host]), "ip_addresses": sorted(host_ips[host])}
             for host in sorted(host_transactions)]
    return {
        "network": {
            "total_requests": len(transactions),
            "total_responses": sum(item["status"] is not None for item in transactions),
            "methods": dict(sorted(methods.items())),
            "status_codes": dict(sorted(statuses.items())),
            "content_types": dict(sorted(content_types.items())),
            "distinct_hosts": len(hosts),
            "distinct_urls": len(distinct_urls),
            "requests": transactions,
        },
        "hosts": hosts,
        "urls": sorted(distinct_urls),
        "http_redirects": redirects,
    }
