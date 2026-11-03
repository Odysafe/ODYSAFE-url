from __future__ import annotations

import base64
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_TEXT_BYTES = 2 * 1024 * 1024


def _load_har(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        entries = value.get("log", {}).get("entries", [])
        return entries if isinstance(entries, list) else []
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []


def javascript_observations(scan_dir: Path) -> list[dict[str, Any]]:
    stored: dict[str, dict[str, Any]] = {}
    manifest = scan_dir / "scripts" / "manifest.json"
    if manifest.is_file() and not manifest.is_symlink():
        try:
            items = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(items, list):
                stored = {str(item.get("url")): item for item in items if isinstance(item, dict)}
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
    result = []
    for index, entry in enumerate(_load_har(scan_dir / "network.har"), 1):
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        response = entry.get("response", {}) if isinstance(entry, dict) else {}
        content = response.get("content", {}) if isinstance(response, dict) else {}
        url = request.get("url")
        mime = str(content.get("mimeType", "")).split(";", 1)[0].lower()
        if not isinstance(url, str) or not ("javascript" in mime or urlsplit(url).path.lower().endswith((".js", ".mjs"))):
            continue
        item = stored.get(url, {})
        result.append({"id": f"script-{index:06d}", "request_id": f"request-{index:06d}",
            "url": url, "hostname": urlsplit(url).hostname, "inline": False,
            "mime_type": mime or None, "status": "truncated" if item.get("truncated") else
                ("collected" if item.get("path") else "referenced"),
            "size": item.get("size") if isinstance(item.get("size"), int) else content.get("size"),
            "sha256": item.get("sha256"), "path": item.get("path")})
    return result


def relation_graph(scan_dir: Path, report: dict[str, Any]) -> dict[str, Any]:
    entries = _load_har(scan_dir / "network.har")
    primary_host = urlsplit(str(report.get("overview", {}).get("submitted_url") or "")).hostname
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    host_resources: defaultdict[str, list[str]] = defaultdict(list)
    for index, entry in enumerate(entries, 1):
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        response = entry.get("response", {}) if isinstance(entry, dict) else {}
        url = request.get("url")
        if not isinstance(url, str):
            continue
        request_id = f"request-{index:06d}"; host = urlsplit(url).hostname or "unknown"
        content = response.get("content", {}) if isinstance(response, dict) else {}
        mime = str(content.get("mimeType", "")).split(";", 1)[0]
        resource_type = ("script" if "javascript" in mime else "image" if mime.startswith("image/")
                         else "css" if "css" in mime else "document" if "html" in mime else "resource")
        nodes[request_id] = {"id": request_id, "kind": "resource", "label": url,
            "url": url, "host": host, "resource_type": resource_type,
            "status": response.get("status"), "started_at": entry.get("startedDateTime")}
        host_id = f"host:{host}"
        nodes.setdefault(host_id, {"id": host_id, "kind": "host", "label": host, "host": host,
                                   "primary": host == primary_host})
        host_resources[host].append(request_id)
        # A Referer or explicit HAR initiator is evidence. Absence is kept as an
        # unverified host-membership edge, never promoted to causality.
        referer = next((h.get("value") for h in request.get("headers", []) if
                        isinstance(h, dict) and str(h.get("name", "")).lower() == "referer"), None)
        initiator = entry.get("_initiator", {}) if isinstance(entry, dict) else {}
        source_url = initiator.get("url") if isinstance(initiator, dict) else None
        source_url = source_url or referer
        if isinstance(source_url, str) and source_url:
            source = next((node_id for node_id, node in nodes.items() if node.get("url") == source_url), None)
            if not source:
                source = f"source:{hashlib.sha256(source_url.encode()).hexdigest()[:16]}"
                nodes[source] = {"id": source, "kind": "resource", "label": source_url,
                                 "url": source_url, "host": urlsplit(source_url).hostname,
                                 "resource_type": "document", "status": None}
            edges.append({"source": source, "target": request_id, "type": "initiated",
                          "verified": True})
        edges.append({"source": host_id, "target": request_id, "type": "contains",
                      "verified": False})
    redirects = []
    for edge in report.get("navigation", {}).get("observed_redirects", []):
        if not isinstance(edge, dict): continue
        source = edge.get("source") or edge.get("from_url"); target = edge.get("target") or edge.get("to_url")
        if not isinstance(source, str) or not isinstance(target, str): continue
        redirects.append({"source": source, "target": target, "status": edge.get("status"),
                          "mechanism": edge.get("mechanism") or "unknown",
                          "transaction_id": edge.get("transaction_id"), "scope": "resource"})
    browser_nodes: dict[str, dict[str, Any]] = {}
    browser_paths: list[dict[str, Any]] = []
    events_path = scan_dir / "browser_events.json"
    try:
        envelope = json.loads(events_path.read_text(encoding="utf-8"))
        events = envelope.get("events", []) if isinstance(envelope, dict) else []
    except (OSError, UnicodeError, json.JSONDecodeError):
        events = []
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict) or event.get("type") not in {"navigation", "popup"}: continue
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        if event.get("type") == "navigation" and details.get("frame") != "main": continue
        destination = details.get("destination_url") or event.get("url")
        source = details.get("initial_url") if event.get("type") == "navigation" else details.get("parent_url")
        if not isinstance(destination, str) or not destination or destination == "about:blank": continue
        browser_nodes.setdefault(destination,{"url":destination,"timestamp":event.get("timestamp"),
                                              "event_type":event.get("type")})
        if isinstance(source, str) and source and source != "about:blank" and source != destination:
            browser_nodes.setdefault(source,{"url":source,"timestamp":None,"event_type":"observed_source"})
            browser_paths.append({"source":source,"target":destination,"status":None,
                                  "mechanism":"popup" if event.get("type")=="popup" else "navigation",
                                  "timestamp":event.get("timestamp"),"event_id":event.get("id")})
    # Host relations are only aggregated from explicit evidence. Membership of
    # a resource in a host remains a visual grouping and is never an edge here.
    host_edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    def add_host_edge(source_url: Any, target_url: Any, relation: str) -> None:
        if not isinstance(source_url, str) or not isinstance(target_url, str):
            return
        source_host=urlsplit(source_url).hostname; target_host=urlsplit(target_url).hostname
        if not source_host or not target_host or source_host == target_host:
            return
        key=(source_host,target_host,relation)
        item=host_edges.setdefault(key,{"source":f"host:{source_host}","target":f"host:{target_host}",
                                        "source_host":source_host,"target_host":target_host,
                                        "type":relation,"verified":True,"count":0})
        item["count"] += 1
    for edge in edges:
        if not edge.get("verified"):
            continue
        source_node=nodes.get(str(edge.get("source")),{}); target_node=nodes.get(str(edge.get("target")),{})
        add_host_edge(source_node.get("url"),target_node.get("url"),"initiated")
    for edge in redirects:
        add_host_edge(edge.get("source"),edge.get("target"),"http_redirect")
    for edge in browser_paths:
        add_host_edge(edge.get("source"),edge.get("target"),str(edge.get("mechanism") or "navigation"))
    return {"nodes": list(nodes.values()), "edges": edges, "redirects": redirects,
            "browser_nodes": list(browser_nodes.values()), "browser_paths": browser_paths,
            "host_edges": list(host_edges.values()),
            "summary": [{"host": host, "request_ids": ids, "count": len(ids)}
                        for host, ids in sorted(host_resources.items())]}
