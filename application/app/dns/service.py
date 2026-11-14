from __future__ import annotations

import json
import os
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.database import Database
from .domains import extract_domains, normalize_public_domain
from .engine import POLICY_VERSION
from .providers import PROVIDERS, seed_providers

VALID_INTERPRETATIONS = {"blocked", "not_blocked_observed", "indeterminate", "error", "not_checked", "not_applicable"}


def prepare_dns_job(database: Database, scan_id: str, scan_dir: Path) -> dict[str, Any]:
    seed_providers(database)
    with database.connect() as connection:
        enabled = connection.execute("SELECT value FROM app_settings WHERE key='dns_external_enabled'").fetchone()
        if not enabled or enabled[0] != "true": raise ValueError("External DNS enrichment is disabled")
        providers = [row[0] for row in connection.execute("SELECT id FROM threat_providers WHERE enabled=1 ORDER BY id")]
        custom_providers=[{"id":f"custom:{row['id']}","name":row["name"],"address":row["address"]}
                          for row in connection.execute("SELECT * FROM custom_dns_resolvers WHERE enabled=1 ORDER BY name")]
        providers.extend(item["id"] for item in custom_providers)
        max_domains_row = connection.execute("SELECT value FROM app_settings WHERE key='dns_max_domains'").fetchone()
        timeout_row = connection.execute("SELECT value FROM app_settings WHERE key='dns_timeout_seconds'").fetchone()
        concurrency_row = connection.execute("SELECT value FROM app_settings WHERE key='dns_concurrency'").fetchone()
        cache_row = connection.execute("SELECT value FROM app_settings WHERE key='dns_cache_hours'").fetchone()
    if not providers: raise ValueError("No DNS provider is enabled")
    configured_max = max(1, min(int(max_domains_row[0] if max_domains_row else 100), 500))
    timeout = max(1, min(int(timeout_row[0] if timeout_row else 4), 10))
    concurrency = max(1, min(int(concurrency_row[0] if concurrency_row else 8), 16))
    cache_hours = max(0, min(int(cache_row[0] if cache_row else 24), 168))
    all_domains = extract_domains(scan_dir, 500)
    domains = all_domains[:configured_max]
    if not domains: raise ValueError("No eligible public domain in scan")
    job_id = str(uuid.uuid4()); now = datetime.now(timezone.utc).isoformat()
    cached_results: list[dict[str, Any]]=[]
    if cache_hours:
        threshold=(datetime.now(timezone.utc)-timedelta(hours=cache_hours)).isoformat()
        wanted={item["normalized"] for item in domains}
        with database.connect() as connection:
            rows=connection.execute("""SELECT * FROM dns_results WHERE checked_at>=?
              ORDER BY checked_at DESC,id DESC""",(threshold,))
            seen=set()
            for row in rows:
                key=(row["provider_id"],row["domain"],row["qtype"])
                if (row["domain"] not in wanted or row["provider_id"] not in providers
                        or row["policy_version"] != POLICY_VERSION or key in seen):
                    continue
                seen.add(key); cached_results.append({
                  "domain":row["domain"],"original_domain":row["original_domain"],
                  "provider_id":row["provider_id"],"provider_profile":row["provider_profile"],
                  "method":row["method"],"qtype":row["qtype"],"checked_at":row["checked_at"],
                  "duration_ms":row["duration_ms"],"rcode":row["rcode"],
                  "answers":json.loads(row["answers_json"]),"authority":json.loads(row["authority_json"]),
                  "ede":json.loads(row["ede_json"]),"interpretation":row["interpretation"],
                  "reference_rcode":row["reference_rcode"],
                  "reference_answers":json.loads(row["reference_answers_json"]),
                  "justification":f"Cached observation: {row['justification']}","error":row["error"],
                  "policy_version":row["policy_version"],"cache_hit":True})
    with database.transaction() as connection:
        connection.execute("""INSERT INTO enrichment_jobs
          (id,scan_id,kind,status,created_at,domains_count,total_domains,omitted_domains)
          VALUES(?,?,'dns','running',?,?,?,?)""",
          (job_id, scan_id, now, len(domains),len(all_domains),max(0,len(all_domains)-len(domains))))
    return {"schema": 1, "job_id": job_id, "scan_id": scan_id,
            "domains": domains, "providers": providers,
            "timeout_seconds": timeout,"concurrency":concurrency,"cached_results":cached_results,
            "custom_providers":custom_providers}


def _text(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def import_dns_result(database: Database, scan_id: str, payload: dict[str, Any]) -> dict[str, int]:
    if payload.get("schema") != 1 or not isinstance(payload.get("job_id"), str) or not isinstance(payload.get("results"), list):
        raise ValueError("Invalid DNS result envelope")
    if len(payload["results"]) > 6000: raise ValueError("Too many DNS results")
    job_id = payload["job_id"]
    with database.transaction() as connection:
        job = connection.execute("SELECT * FROM enrichment_jobs WHERE id=? AND scan_id=? AND kind='dns'",
                                 (job_id, scan_id)).fetchone()
        if not job or job["status"] != "running": raise ValueError("DNS job is missing or already finalized")
        count = 0
        for item in payload["results"]:
            if not isinstance(item, dict): raise ValueError("Invalid DNS result")
            domain = normalize_public_domain(str(item.get("domain", "")))
            provider_id = item.get("provider_id"); qtype = item.get("qtype")
            interpretation = item.get("interpretation")
            custom=connection.execute("SELECT * FROM custom_dns_resolvers WHERE ?=('custom:'||id)",(provider_id,)).fetchone()
            if (provider_id not in PROVIDERS and custom is None) or qtype not in {"A", "AAAA"} or interpretation not in VALID_INTERPRETATIONS:
                raise ValueError("Invalid DNS result fields")
            provider = PROVIDERS.get(provider_id)
            answers = item.get("answers", []); authority = item.get("authority", []); ede = item.get("ede", [])
            reference_answers=item.get("reference_answers",[])
            if not isinstance(answers, list) or not isinstance(authority, list) or not isinstance(ede, list) or not isinstance(reference_answers,list):
                raise ValueError("Invalid DNS evidence")
            encoded_answers=json.dumps(answers,ensure_ascii=False)[:32768]
            encoded_authority=json.dumps(authority,ensure_ascii=False)[:16384]
            encoded_ede=json.dumps(ede,ensure_ascii=False)[:8192]
            duration = item.get("duration_ms") if isinstance(item.get("duration_ms"), int) else None
            original_domain=_text(item.get("original_domain"),253) or domain
            connection.execute("""INSERT INTO dns_results
              (job_id,scan_id,domain,original_domain,provider_id,provider_profile,method,qtype,
               checked_at,duration_ms,rcode,answers_json,authority_json,ede_json,interpretation,
               justification,error,policy_version,cache_hit,reference_rcode,reference_answers_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (job_id,scan_id,domain,original_domain,provider_id,
               provider.profile if provider else "custom-resolution",provider.method if provider else "udp",qtype,
               _text(item.get("checked_at"),64) or datetime.now(timezone.utc).isoformat(),duration,
               _text(item.get("rcode"),32),encoded_answers,encoded_authority,encoded_ede,
               interpretation,_text(item.get("justification"),1000) or "No justification",
               _text(item.get("error"),1000),_text(item.get("policy_version"),64) or POLICY_VERSION,
               1 if item.get("cache_hit") is True else 0,_text(item.get("reference_rcode"),32),
               json.dumps(reference_answers,ensure_ascii=False)[:32768]))
            count += 1
        now = datetime.now(timezone.utc).isoformat()
        connection.execute("UPDATE enrichment_jobs SET status='completed',completed_at=?,progress_count=? WHERE id=?", (now,count,job_id))
    return {"imported": count}


def dns_status(database: Database, scan_id: str) -> dict[str, Any]:
    with database.connect() as connection:
        jobs = [dict(row) for row in connection.execute(
            "SELECT * FROM enrichment_jobs WHERE scan_id=? ORDER BY created_at DESC LIMIT 20", (scan_id,))]
        results = []
        for row in connection.execute("SELECT * FROM dns_results WHERE scan_id=? ORDER BY checked_at DESC,id DESC LIMIT 1000",(scan_id,)):
            item=dict(row)
            for key in ("answers_json","authority_json","ede_json","reference_answers_json"):
                item[key.removesuffix("_json")]=json.loads(item.pop(key))
            results.append(item)
        matches = [dict(row) for row in connection.execute("""SELECT m.*,i.type,i.original_value,i.category,i.comment
          FROM ioc_matches m JOIN manual_iocs i ON i.id=m.ioc_id WHERE m.scan_id=?
          ORDER BY m.matched_at DESC LIMIT 1000""", (scan_id,))]
        blocked_provider_counts = {
            row["domain"]: row["provider_count"] for row in connection.execute("""
              SELECT domain,COUNT(DISTINCT provider_id) AS provider_count
              FROM dns_results WHERE scan_id=? AND interpretation='blocked'
              GROUP BY domain""", (scan_id,))
        }
        provider_rows={row["id"]:dict(row) for row in connection.execute("SELECT * FROM threat_providers ORDER BY name")}
    rank={"blocked":4,"error":3,"indeterminate":2,"not_blocked_observed":1}
    matrix: dict[str, dict[str, Any]]={}
    for item in results:
        row=matrix.setdefault(item["domain"],{"domain":item["domain"],"providers":{},"blocked_count":0})
        current=row["providers"].get(item["provider_id"])
        if current is None or rank.get(item["interpretation"],0)>rank.get(current["interpretation"],0):
            row["providers"][item["provider_id"]]=item
    for row in matrix.values():
        row["blocked_count"]=sum(item["interpretation"]=="blocked" for item in row["providers"].values())
    return {"jobs":jobs,"dns_results":results,"ioc_matches":matches,
            "blocked_provider_counts":blocked_provider_counts,"dns_matrix":list(matrix.values()),
            "providers":provider_rows}


def automatic_enabled(database: Database) -> bool:
    with database.connect() as connection:
        rows=dict(connection.execute("SELECT key,value FROM app_settings WHERE key IN ('dns_external_enabled','dns_auto_enabled')"))
    return rows.get("dns_external_enabled")=="true" and rows.get("dns_auto_enabled")=="true"


def run_dns_job(database: Database, scan_id: str, scan_dir: Path) -> dict[str, int]:
    job=prepare_dns_job(database,scan_id,scan_dir)
    try:
        request=urllib.request.Request(
          os.environ.get("ODYSAFE_DNS_WORKER_URL","http://dns-enrichment:8053/v1/query"),
          data=json.dumps(job,separators=(",",":")).encode(),method="POST",
          headers={"Content-Type":"application/json","Authorization":f"Bearer {os.environ.get('ODYSAFE_DNS_WORKER_TOKEN','')}"})
        timeout=max(30,min(1800,len(job["domains"])*len(job["providers"])*job["timeout_seconds"]//max(1,job["concurrency"])+30))
        with urllib.request.urlopen(request,timeout=timeout) as response:
            raw=response.read(32*1024*1024+1)
            if len(raw)>32*1024*1024: raise ValueError("DNS worker response too large")
            payload=json.loads(raw)
        return import_dns_result(database,scan_id,payload)
    except Exception as exc:
        with database.transaction() as connection:
            connection.execute("UPDATE enrichment_jobs SET status='failed',completed_at=?,error=? WHERE id=?",
              (datetime.now(timezone.utc).isoformat(),f"{type(exc).__name__}: {str(exc)[:700]}",job["job_id"]))
        raise
