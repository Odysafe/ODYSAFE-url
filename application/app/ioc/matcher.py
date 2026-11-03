from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.database import Database
from .registry import normalize_ioc, normalize_hostname


def _observed(report: dict[str, Any]) -> dict[str, set[str]]:
    indicators = report.get("indicators") if isinstance(report.get("indicators"), dict) else {}
    values = {key: set() for key in ("url", "domain", "hostname", "ipv4", "ipv6", "sha256")}
    for value in indicators.get("urls", []) if isinstance(indicators.get("urls"), list) else []:
        if isinstance(value, str):
            try: values["url"].add(normalize_ioc("url", value))
            except ValueError: pass
    for value in indicators.get("domains", []) if isinstance(indicators.get("domains"), list) else []:
        if isinstance(value, str):
            try:
                normalized = normalize_hostname(value); values["domain"].add(normalized); values["hostname"].add(normalized)
            except ValueError: pass
    for value in indicators.get("ips", []) if isinstance(indicators.get("ips"), list) else []:
        if isinstance(value, str):
            try:
                address = ipaddress.ip_address(value); values[f"ipv{address.version}"].add(str(address))
            except ValueError: pass
    for value in indicators.get("hashes", []) if isinstance(indicators.get("hashes"), list) else []:
        if isinstance(value, str):
            try: values["sha256"].add(normalize_ioc("sha256", value))
            except ValueError: pass
    return values


def match_scan_iocs(database: Database, scan_id: str, scan_dir: Path,
                    selected_ioc_ids: list[str] | None = None) -> dict[str, Any]:
    path = Path(scan_dir) / "report.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Report unavailable or too large")
    report = json.loads(path.read_text(encoding="utf-8")); observed = _observed(report)
    now = datetime.now(timezone.utc); now_text = now.isoformat(); job_id = str(uuid.uuid4()); matches = []
    with database.transaction() as connection:
        connection.execute("INSERT INTO enrichment_jobs(id,scan_id,kind,status,created_at) VALUES(?,?,'offline_ioc','running',?)",
                           (job_id, scan_id, now_text))
        if selected_ioc_ids is None:
            rows = connection.execute("""SELECT * FROM manual_iocs WHERE active=1 AND archived=0
              AND (expires_at IS NULL OR expires_at>?)""", (now_text,)).fetchall()
        else:
            identifiers=list(dict.fromkeys(selected_ioc_ids))[:100]
            if not identifiers:
                raise ValueError("Select at least one IOC")
            placeholders=",".join("?" for _ in identifiers)
            rows = connection.execute(f"""SELECT * FROM manual_iocs WHERE archived=0
              AND id IN ({placeholders}) AND (expires_at IS NULL OR expires_at>?)""",
              (*identifiers,now_text)).fetchall()
            if len(rows)!=len(identifiers):
                raise ValueError("One or more selected IOCs are unavailable")
        for row in rows:
            kind = row["type"]; normalized = row["normalized_value"]; hit_values: list[str] = []
            if kind in {"domain", "hostname"} and normalized.startswith("*."):
                # Include subdomains of any depth, with a strict label boundary.
                suffix = normalized[1:]
                hit_values = sorted(value for value in observed[kind] if value.endswith(suffix))
            elif kind == "ipv4" and "*" in normalized:
                parts = normalized.split(".")
                hit_values = sorted(value for value in observed[kind]
                                    if all(expected == "*" or expected == actual
                                           for expected, actual in zip(parts, value.split("."))))
            elif kind in observed: hit_values = [normalized] if normalized in observed[kind] else []
            elif kind in {"cidr4", "cidr6"}:
                network = ipaddress.ip_network(normalized); key = f"ipv{network.version}"
                hit_values = [value for value in observed[key] if ipaddress.ip_address(value) in network]
            for value in hit_values:
                explanation = (f"Exact {kind} match" if not kind.startswith("cidr")
                               else f"Observed IP belongs to {normalized}")
                if "*" in normalized:
                    explanation = f"La valeur observée correspond au motif {normalized}"
                connection.execute("""INSERT INTO ioc_matches
                    (job_id,scan_id,ioc_id,observed_type,observed_value,matched_at,explanation)
                    VALUES(?,?,?,?,?,?,?)""", (job_id, scan_id, row["id"], kind, value, now_text, explanation))
                connection.execute("UPDATE manual_iocs SET last_used_at=? WHERE id=?", (now_text, row["id"]))
                matches.append({"ioc_id": row["id"], "type": kind, "value": value,
                                "category": row["category"], "explanation": explanation,
                                "provenance": "manual"})
        connection.execute("UPDATE enrichment_jobs SET status='completed',completed_at=? WHERE id=?", (now_text, job_id))
    return {"job_id": job_id, "scan_id": scan_id, "status": "completed", "matches": matches,
            "observed_counts": {key: len(value) for key, value in observed.items()}}
