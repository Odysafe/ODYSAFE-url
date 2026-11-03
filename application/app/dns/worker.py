from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed

from .domains import normalize_public_domain
from .engine import query_one, query_custom
from .providers import PROVIDERS

MAX_INPUT = 16 * 1024 * 1024
MAX_REQUESTS = 6000


def execute(payload: dict) -> dict:
    job_id = payload.get("job_id"); raw_domains = payload.get("domains"); raw_providers = payload.get("providers")
    timeout = payload.get("timeout_seconds", 4)
    concurrency = payload.get("concurrency", 8)
    cached = payload.get("cached_results", [])
    raw_custom = payload.get("custom_providers", [])
    if not isinstance(job_id, str) or not isinstance(raw_domains, list) or not isinstance(raw_providers, list):
        raise ValueError("Invalid DNS job")
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 10: raise ValueError("Invalid timeout")
    if not isinstance(concurrency, int) or not 1 <= concurrency <= 16: raise ValueError("Invalid concurrency")
    if not isinstance(cached, list) or len(cached) > MAX_REQUESTS: raise ValueError("Invalid cache payload")
    domains = []
    for item in raw_domains:
        if not isinstance(item, dict) or not isinstance(item.get("normalized"),str) or not isinstance(item.get("original"),str):
            raise ValueError("Invalid domain entry")
        normalized=normalize_public_domain(item["normalized"])
        if len(item["original"])>253: raise ValueError("Original domain too large")
        domains.append((normalized,item["original"]))
    custom = {}
    for item in raw_custom:
        if not isinstance(item,dict) or not all(isinstance(item.get(key),str) for key in ("id","name","address")):
            raise ValueError("Invalid custom resolver")
        import ipaddress
        address=ipaddress.ip_address(item["address"])
        if not address.is_global or not item["id"].startswith("custom:") or not 1<=len(item["name"])<=80:
            raise ValueError("Custom resolver must use a public IP address")
        custom[item["id"]]={"name":item["name"],"address":str(address)}
    providers = [item for item in raw_providers if isinstance(item, str) and (item in PROVIDERS or item in custom)]
    if len(providers) != len(raw_providers) or not providers: raise ValueError("Unknown or empty provider list")
    cached_keys={(item.get("provider_id"),item.get("domain"),item.get("qtype")) for item in cached if isinstance(item,dict)}
    tasks = [(provider, domain, qtype, original) for provider in providers for domain,original in domains for qtype in ("A", "AAAA")
             if (provider,domain,qtype) not in cached_keys]
    if len(tasks) > MAX_REQUESTS: raise ValueError("DNS request quota exceeded")
    results = list(cached)
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {(executor.submit(query_one,provider,domain,qtype,timeout) if provider in PROVIDERS else
                    executor.submit(query_custom,provider,custom[provider]["name"],custom[provider]["address"],domain,qtype,timeout)):original
                   for provider,domain,qtype,original in tasks}
        for future in as_completed(futures):
            result=future.result(); result["original_domain"]=futures[future]; results.append(result)
    return {"schema": 1, "job_id": job_id, "results": sorted(results,key=lambda x:(x["domain"],x["provider_id"],x["qtype"]))}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        token=os.environ.get("ODYSAFE_DNS_WORKER_TOKEN","")
        if self.path!="/v1/query" or not token or self.headers.get("Authorization")!=f"Bearer {token}":
            self.send_error(404); return
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length<1 or length>MAX_INPUT: raise ValueError("Invalid payload size")
            output=execute(json.loads(self.rfile.read(length)))
            raw=json.dumps(output,ensure_ascii=False,separators=(",",":")).encode()
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
        except (ValueError,TypeError,json.JSONDecodeError) as exc:
            raw=json.dumps({"error":str(exc)}).encode(); self.send_response(400)
            self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
    def log_message(self, *_: object) -> None: return


def serve() -> None:
    ThreadingHTTPServer(("0.0.0.0",int(os.environ.get("ODYSAFE_DNS_WORKER_PORT","8053"))),_Handler).serve_forever()


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        print(json.dumps({"error": "Input too large"})); return 2
    try: output = execute(json.loads(raw))
    except (ValueError, json.JSONDecodeError, TypeError) as exc:
        print(json.dumps({"error": str(exc)})); return 2
    print(json.dumps(output, ensure_ascii=False, separators=(",", ":"))); return 0


if __name__ == "__main__":
    if os.environ.get("ODYSAFE_DNS_WORKER_SERVE")=="1": serve()
    else: raise SystemExit(main())
