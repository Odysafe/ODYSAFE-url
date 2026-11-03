from __future__ import annotations

import hashlib
import asyncio
import ipaddress
import json
import os
import secrets
import shutil
import uuid
import tempfile
import threading
import zipfile
import sqlite3
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import DATA_ROOT, PROJECT_ROOT
from app.database import Database, reconcile_scans
from app.rules import RuleRegistry, RuleValidationError
from app.rules.registry import RULE_NAME, compile_sources
from app.rules.library import EngineLibrary
from app.web.forms import IOC_INPUTS, ioc_form_error
from app.web.i18n import configure as configure_i18n, language as interface_language
from app.dns import (PROVIDERS, automatic_enabled, dns_status, run_dns_job,
                     seed_providers)
from app.ioc import IOCRegistry, IOCValidationError
from app.reporting import build_report, ReportBuildError
from app.reporting.investigation import javascript_observations, relation_graph
from app.orchestration import (ControllerClient, ControllerError,
                               ControllerHTTPError, ControllerUnavailable)
from app.config import validate_public_url, validate_scan_url, ConfigurationError
from app.web.security import SessionStore, configured_origins, origin_is_allowed

WEB_ROOT = Path(__file__).parent
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
MAX_EXPORT_BYTES = 100 * 1024 * 1024
ALLOWED_ARTIFACTS = {"network.har", "dom.html", "screenshot.png", "cookies.json",
                     "console.json", "browser_events.json", "downloads.json", "meta.json", "report.json"}


def re_date(value: str) -> bool:
    if not value:
        return False
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def _is_public_ip(value: Any) -> bool:
    try: return ipaddress.ip_address(str(value)).is_global
    except ValueError: return False


def report_presentation(report: dict[str, Any], intelligence: dict[str, Any]) -> dict[str, Any]:
    def public_ips(values: Any) -> list[str]:
        result=[]
        for value in values if isinstance(values,list) else []:
            try: address=ipaddress.ip_address(str(value))
            except ValueError: continue
            if _is_public_ip(address) and str(address) not in result: result.append(str(address))
        return result
    resolved_by_host: dict[str,list[dict[str,Any]]]={}
    for observation in intelligence.get("dns_results",[]):
        if not isinstance(observation,dict): continue
        for answer in observation.get("answers",[]):
            candidate=str(answer).rstrip(".").split()[-1]
            try: address=ipaddress.ip_address(candidate)
            except ValueError: continue
            if not address.is_global: continue
            bucket=resolved_by_host.setdefault(str(observation.get("domain")),[])
            item={"ip":str(address),"version":address.version,
                  "source":str(observation.get("provider_id") or "dns"),
                  "observed_at":observation.get("checked_at")}
            if not any(old["ip"]==item["ip"] and old["source"]==item["source"] for old in bucket):
                bucket.append(item)
    requests=(report.get("network",{}).get("requests",[])
              if isinstance(report.get("network"),dict) else [])
    requests=requests if isinstance(requests,list) else []
    request_counts: dict[str,int]={}
    host_stats: dict[str,dict[str,Any]]={}
    for item in requests:
        if not isinstance(item,dict) or not item.get("hostname"): continue
        host=str(item["hostname"]); request_counts[host]=request_counts.get(host,0)+1
        stats=host_stats.setdefault(host,{"sent":0,"received":0,"first":None,"last":None})
        stats["sent"] += item.get("request_body_size") if isinstance(item.get("request_body_size"),int) else 0
        stats["received"] += item.get("response_body_size") if isinstance(item.get("response_body_size"),int) else 0
        stamp=item.get("started_at")
        if isinstance(stamp,str):
            stats["first"]=min(filter(None,(stats["first"],stamp)),default=stamp)
            stats["last"]=max(filter(None,(stats["last"],stamp)),default=stamp)
    provider_rows=intelligence.get("providers",{})
    signals: dict[tuple[str,str],dict[str,Any]]={}
    for item in intelligence.get("dns_results",[]):
        if item.get("interpretation") != "blocked": continue
        key=(str(item.get("domain")),str(item.get("provider_id")))
        signal=signals.setdefault(key,{"domain":key[0],"provider_id":key[1],
            "provider":provider_rows.get(key[1],{}).get("name") or key[1],"qtypes":[],
            "rcodes":[],"ede":[],"checked_at":item.get("checked_at"),
            "request_count":request_counts.get(key[0],0),"observations":0})
        signal["observations"]+=1
        if item.get("qtype") and item["qtype"] not in signal["qtypes"]: signal["qtypes"].append(item["qtype"])
        if item.get("rcode") and item["rcode"] not in signal["rcodes"]: signal["rcodes"].append(item["rcode"])
        for ede in item.get("ede",[]):
            if ede not in signal["ede"]: signal["ede"].append(ede)
        if item.get("checked_at") and (not signal["checked_at"] or item["checked_at"]>signal["checked_at"]):
            signal["checked_at"]=item["checked_at"]
    dns_by_host={row.get("domain"):row for row in intelligence.get("dns_matrix",[])}
    hosts=[]
    for item in report.get("hosts",[]):
        if not isinstance(item,dict) or not item.get("hostname"): continue
        host=str(item["hostname"]); stats=host_stats.get(host,{})
        dns=dns_by_host.get(host,{})
        hosts.append({"hostname":host,"requests":item.get("transaction_count",request_counts.get(host,0)),
            "connection_ips":public_ips(item.get("ip_addresses",[])),
            "resolved_ips":resolved_by_host.get(host,[]),"sent":stats.get("sent",0),
            "received":stats.get("received",0),"first":stats.get("first"),"last":stats.get("last"),
            "blocked_providers":dns.get("blocked_count",0),"dns":dns})
    hosts.sort(key=lambda item:(item.get("first") is None,item.get("first") or "",item["hostname"]))
    def host_for(url: Any) -> dict[str,Any] | None:
        hostname=urlsplit(str(url or "")).hostname
        if not hostname:
            return None
        known=next((item for item in hosts if item["hostname"]==hostname),None)
        if known:
            return known
        if hostname in resolved_by_host:
            return {"hostname":hostname,"connection_ips":[],
                    "resolved_ips":resolved_by_host[hostname]}
        return None
    jobs_by_kind: dict[str,dict[str,Any]]={}
    for job in intelligence.get("jobs",[]):
        if isinstance(job,dict) and job.get("kind") and job["kind"] not in jobs_by_kind:
            jobs_by_kind[str(job["kind"])]=job
    yara=report.get("detection_engines",{}).get("yara_x",{})
    yara_execution=yara.get("execution",{}) if isinstance(yara,dict) else {}
    yara_coverage={item.get("domain"):item for item in yara_execution.get("domain_coverage",[])
                   if isinstance(item,dict) and item.get("domain")}
    yara_artifacts=yara_execution.get("artifacts",[]) if isinstance(yara_execution,dict) else []
    loaded_rules=(yara.get("rule_set",{}).get("active_rules",0)
                  if isinstance(yara.get("rule_set"),dict) else 0)
    dns_rows: dict[str,list[dict[str,Any]]]={}
    for item in intelligence.get("dns_results",[]):
        if isinstance(item,dict) and item.get("domain"):
            dns_rows.setdefault(str(item["domain"]),[]).append(item)
    ioc_rows: dict[str,list[dict[str,Any]]]={}
    for item in intelligence.get("ioc_matches",[]):
        if not isinstance(item,dict) or item.get("observed_type") not in {"domain","hostname"}: continue
        ioc_rows.setdefault(str(item.get("observed_value")),[]).append(item)
    status_labels={"scanned":"Analysé","no_compatible_artifact":"Aucun artefact compatible",
                   "detail_unavailable":"Détail indisponible pour cet ancien rapport",
                   "completed":"Terminé","partial":"Partiel","running":"En cours",
                   "failed":"Échec","error":"Erreur","not_performed":"Non exécuté",
                   "not_authorized":"Non autorisé"}
    domain_coverage=[]
    for host in hosts:
        domain=host["hostname"]; yara_item=yara_coverage.get(domain)
        related_yara=[item for item in yara_artifacts if isinstance(item,dict) and item.get("domain")==domain]
        dns_items=dns_rows.get(domain,[]); ioc_items=ioc_rows.get(domain,[])
        yara_status=(str(yara_item.get("status")) if yara_item else
                     ("detail_unavailable" if yara.get("status") in {"completed","partial"} else
                      str(yara.get("status") or "not_performed")))
        domain_coverage.append({
            "domain":domain,
            "yara":{"status":yara_status,"label":status_labels.get(yara_status,yara_status.replace("_"," ")),
                    "rules":loaded_rules,
                    "attempted":int(yara_item.get("artifacts_available",0)) if yara_item else 0,
                    "succeeded":int(yara_item.get("artifacts_scanned",0)) if yara_item else 0,
                    "failed":sum(item.get("status")=="error" for item in related_yara),
                    "matches":int(yara_item.get("matches",0)) if yara_item else 0},
            "ioc":{"status":str(jobs_by_kind.get("offline_ioc",{}).get("status") or "not_performed"),
                   "runs":1 if jobs_by_kind.get("offline_ioc") else 0,"matches":len(ioc_items)},
            "dns":{"status":str(jobs_by_kind.get("dns",{}).get("status") or "not_performed"),
                   "queries":len(dns_items),
                   "succeeded":sum(item.get("interpretation")!="error" for item in dns_items),
                   "failed":sum(item.get("interpretation")=="error" for item in dns_items),
                   "providers":len({item.get("provider_id") for item in dns_items}),
                   "signals":len({item.get("provider_id") for item in dns_items
                                  if item.get("interpretation")=="blocked"})},
        })
        domain_coverage[-1]["ioc"]["label"]=status_labels.get(domain_coverage[-1]["ioc"]["status"],domain_coverage[-1]["ioc"]["status"].replace("_"," "))
        domain_coverage[-1]["dns"]["label"]=status_labels.get(domain_coverage[-1]["dns"]["status"],domain_coverage[-1]["dns"]["status"].replace("_"," "))
    overview=report.get("overview",{})
    indicators=report.get("indicators",{}) if isinstance(report.get("indicators"),dict) else {}
    ioc_indicators_tested=sum(len(indicators.get(key,[])) for key in ("urls","domains","ips","hashes")
                              if isinstance(indicators.get(key),list))
    return {"security_signals":list(signals.values()),"hosts":hosts,
            "submitted_host":host_for(overview.get("submitted_url")),
            "final_host":host_for(overview.get("final_url")),
            "dns_domains":len(intelligence.get("dns_matrix",[])),
            "dns_providers":len({item.get("provider_id") for item in intelligence.get("dns_results",[])}),
            "dns_provider_total":len(intelligence.get("providers",{})),
            "yara_rules_tested":int(loaded_rules or 0),
            "yara_artifacts_tested":int(yara_execution.get("artifacts_scanned",0) or 0),
            "yara_matches":int(yara_execution.get("matches",0) or 0),
            "ioc_passes":1 if jobs_by_kind.get("offline_ioc") else 0,
            "ioc_indicators_tested":ioc_indicators_tested,
            "ioc_matches":len(intelligence.get("ioc_matches",[])),
            "dns_responses":len(intelligence.get("dns_results",[])),
            "domain_analysis_coverage":domain_coverage}
def create_app(*, database_path: Path | None = None, scans_root: Path | None = None,
               testing: bool = False,
               allowed_origins: frozenset[str] | None = None,
               local_no_auth: bool | None = None,
               web_bind: str | None = None,
               controller_client: ControllerClient | None = None,
               internet_controller_client: ControllerClient | None = None) -> FastAPI:
    db = Database(database_path or Path(os.environ.get("ODYSAFE_DB_PATH", "/database/odysafe.db")))
    scan_path = Path(scans_root or (DATA_ROOT / "scans"))
    rules = RuleRegistry(db, PROJECT_ROOT / "rules" / "yara")
    iocs = IOCRegistry(db)
    manual_dns_lock = threading.Lock()
    capture_finalize_lock = threading.Lock()
    controller = controller_client or ControllerClient()
    internet_controller = (internet_controller_client or controller if controller_client
                           else ControllerClient(base_url=os.environ.get(
                               "ODYSAFE_INTERNET_CONTROLLER_URL",
                               "http://controller-gateway-internet:8765")))
    sessions = SessionStore(ttl=3600)
    web_origins = configured_origins(",".join(allowed_origins)) if allowed_origins is not None else configured_origins(os.environ.get(
        "ODYSAFE_WEB_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080"))
    configured_bind = web_bind or os.environ.get("ODYSAFE_WEB_BIND", "127.0.0.1")
    public_capture = os.environ.get("ODYSAFE_PUBLIC_CAPTURE", "false").lower() == "true"
    default_xpra_scheme = "http" if testing else "https"
    xpra_url = os.environ.get("ODYSAFE_XPRA_URL",f"{default_xpra_scheme}://127.0.0.1:14500")
    xpra_internet_url = os.environ.get(
        "ODYSAFE_XPRA_INTERNET_URL",f"{default_xpra_scheme}://127.0.0.1:14501")

    def gateway_for(request: Request, network_policy: str) -> str:
        configured=urlsplit(xpra_internet_url if network_policy=="internet" else xpra_url)
        if configured.scheme not in {"http","https"} or configured.hostname not in {"127.0.0.1","localhost"}:
            raise RuntimeError("The display gateway must use a loopback HTTP(S) address")
        hostname=request.url.hostname
        if hostname not in {"127.0.0.1","localhost"}: hostname="127.0.0.1"
        port=configured.port or (443 if configured.scheme=="https" else 80)
        return f"{configured.scheme}://{hostname}:{port}"

    def controller_for(network_policy: str) -> ControllerClient:
        return internet_controller if network_policy == "internet" else controller
    if configured_bind != "127.0.0.1":
        raise RuntimeError("The local web console requires ODYSAFE_WEB_BIND=127.0.0.1")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        db.initialize(); rules.seed_builtins(); seed_providers(db); reconcile_scans(db, scan_path)
        with db.transaction() as connection:
            if not testing and connection.execute(
                "SELECT 1 FROM app_settings WHERE key='dns_provider_defaults_initialized'"
            ).fetchone() is None:
                now=datetime.now(timezone.utc).isoformat()
                connection.execute("UPDATE threat_providers SET enabled=1,updated_at=?", (now,))
                connection.execute("INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,?)",
                                   ("dns_provider_defaults_initialized", "true", now))
            connection.execute("""UPDATE enrichment_jobs SET status='failed',completed_at=datetime('now'),
              error='Application restarted before DNS enrichment completed'
              WHERE kind='dns' AND status='running'""")
        reconcile_capture_sessions()
        task=None
        if not testing:
            async def poll_sessions() -> None:
                while True:
                    await asyncio.sleep(3)
                    try: await asyncio.to_thread(reconcile_capture_sessions)
                    except Exception: pass
            task=asyncio.create_task(poll_sessions())
        try: yield
        finally:
            if task:
                task.cancel()
                try: await task
                except asyncio.CancelledError: pass

    app = FastAPI(title="ODYSAFE-URL", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.database = db; app.state.scans_root = scan_path; app.state.rules = rules; app.state.iocs = iocs
    app.state.sessions = sessions
    trusted_hosts = ["127.0.0.1", "localhost"]
    if testing:
        trusted_hosts.append("testserver")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
    app.mount("/static", StaticFiles(directory=WEB_ROOT / "static"), name="static")
    templates = Jinja2Templates(directory=WEB_ROOT / "templates")
    configure_i18n(templates)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        try: content_length = int(request.headers.get("content-length", "0"))
        except ValueError: return JSONResponse({"detail": "Invalid Content-Length"}, 400)
        if content_length > 1024 * 1024:
            return JSONResponse({"detail": "Request body too large"}, 413)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if not origin_is_allowed(origin, web_origins):
                return JSONResponse({"detail": "Origin refused"}, 403)
        new_session_token = None
        session = sessions.get(request.cookies.get("odysafe_session"))
        if session is None:
            new_session_token, session = sessions.create()
        request.state.local_session = session
        response = await call_next(request)
        if new_session_token:
            response.set_cookie("odysafe_session", new_session_token, httponly=True,
                                samesite="strict",
                                secure=os.environ.get("ODYSAFE_COOKIE_SECURE") == "1",
                                max_age=3600)
        launch_page=request.url.path.endswith(("/xpra-access","/connect"))
        display_origins=" ".join(gateway_for(request,policy) for policy in ("fixture","internet")) if launch_page else ""
        response.headers.update({
            "Content-Security-Policy": (f"default-src 'none'; script-src 'nonce-launch'; form-action 'self' {display_origins}; base-uri 'none'; frame-ancestors 'none'"
                if launch_page else "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin" if launch_page else "same-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-store",
        })
        return response

    def session_for(request: Request):
        session = getattr(request.state, "local_session", None)
        if session is None:
            session = sessions.get(request.cookies.get("odysafe_session"))
        if session is None:
            raise HTTPException(403, "Local CSRF session required")
        return session

    def context(request: Request, **values: Any) -> dict[str, Any]:
        session = session_for(request)
        return {"request": request, "csrf": session.csrf if session else "",
                "active": "", "interface_language": interface_language(request), **values}

    def require_csrf(request: Request, supplied: str) -> None:
        session = session_for(request)
        if not supplied or not secrets.compare_digest(session.csrf, supplied):
            raise HTTPException(403, "Invalid CSRF token")

    def page(request: Request, name: str, **values: Any):
        if name in {"rules.html", "intelligence.html"}:
            engine = "yara" if name == "rules.html" else "ioc"
            library = EngineLibrary(db, engine)
            folder = values.get("forced_folder", request.query_params.get("folder", "all"))
            if folder == "none": folder = library.default_folder()
            view = values.get("forced_view", request.query_params.get("view", "library"))
            if view not in {"library", "analyze", "results"}: view = "library"
            items = values.get("rules" if engine == "yara" else "iocs", [])
            items = [item for item in items if (item.get("archived") if folder == "archive" else not item.get("archived"))]
            if folder not in {"all", "archive"}:
                items = [item for item in items if (item.get("folder_id") or "none") == folder]
            with db.connect() as connection:
                scans = [dict(row) for row in connection.execute("SELECT scan_id,host,submitted_url,capture_date FROM scans WHERE present=1 AND report_available=1 ORDER BY indexed_at DESC LIMIT 200")]
                jobs = [dict(row) for row in connection.execute("SELECT * FROM enrichment_jobs WHERE kind='offline_ioc' ORDER BY created_at DESC LIMIT 100")]
            all_items = rules.list() if engine == "yara" else iocs.list()
            analysis_groups = [{"id": f["id"], "is_default": f["is_default"], "name": f["name"], "items": [i for i in all_items if i.get("folder_id")==f["id"] and not i["archived"]]} for f in library.folders()]
            analysis_groups.append({"id":"unfiled","is_default":False,"name": "À ranger", "items": [i for i in all_items if not i.get("folder_id") and not i["archived"]]})
            values.update(default_folder=library.default_folder(), ioc_inputs=IOC_INPUTS, analysis_groups=analysis_groups, engine=engine, folders=library.folders(), folder=folder, view=view,
                          items=items, recent_scans=scans, jobs=jobs,
                          show_editor=bool(values.get("selected")) or request.query_params.get("new") == "1")
            if engine == "yara" and view == "results":
                results = []
                for scan in scans[:100]:
                    try: report = read_json(scan_directory(scan["scan_id"]) / "report.json")
                    except HTTPException: continue
                    result = report.get("detection_engines", {}).get("yara_x", {})
                    results.append({**scan, "result": result, "date": report.get("generated_at")})
                values["results"] = results
            name = "engine_library.html"
        return templates.TemplateResponse(request, name, context(request, **values))

    @app.exception_handler(StarletteHTTPException)
    async def localized_http_error(request: Request, exc: StarletteHTTPException):
        # Preserve machine-readable API errors. Browser navigation gets the
        # same status and a localized explanation, without changing actions.
        if "text/html" not in request.headers.get("accept", ""):
            return JSONResponse({"detail": exc.detail}, exc.status_code, headers=exc.headers)
        referer=urlsplit(request.headers.get("referer", ""))
        back_url=(referer.path or "/") if referer.netloc==request.url.netloc else "/"
        if not back_url.startswith("/") or back_url.startswith("//"): back_url="/"
        response=page(request,"error.html",error=exc.detail,back_url=back_url)
        response.status_code=exc.status_code
        if exc.headers: response.headers.update(exc.headers)
        return response

    def scan_directory(scan_id: str) -> Path:
        try: parsed = uuid.UUID(scan_id)
        except ValueError as exc: raise HTTPException(404, "Scan not found") from exc
        if str(parsed) != scan_id: raise HTTPException(404, "Scan not found")
        root = scan_path.resolve(strict=True); candidate = scan_path / scan_id
        if candidate.is_symlink() or not candidate.is_dir(): raise HTTPException(404, "Scan not found")
        resolved = candidate.resolve(strict=True)
        if resolved.parent != root: raise HTTPException(404, "Scan not found")
        return resolved

    def read_json(path: Path, limit: int = 8*1024*1024) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit: return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, UnicodeError, json.JSONDecodeError): return {}

    def compatible_report(report: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        """Supply display-only defaults for old, missing or partial reports."""
        value = dict(report) if isinstance(report, dict) else {}
        overview = value.get("overview")
        if not isinstance(overview, dict):
            overview = {}
        overview = {**{
            "submitted_url": meta.get("submitted_url"),
            "final_url": meta.get("final_url"),
            "title": meta.get("title"),
            "capture_status": meta.get("status", "unknown"),
            "profile": meta.get("profile"),
            "browser": meta.get("browser"),
            "duration_ms": meta.get("duration_ms"),
        }, **overview}
        value["overview"] = overview
        value.setdefault("analysis_status", "not_available")
        value.setdefault("generated_at", None)
        defaults: dict[str, Any] = {
            "network": {"total_requests": 0, "requests": []}, "hosts": [],
            "navigation": {"observed_redirects": []},
            "indicators": {"urls": [], "domains": [], "ips": [], "hashes": []},
            "downloaded_files": [], "javascript": [],
            "browser_events": {"events": [], "total": 0}, "detections": [],
            "detection_summary": {"total": 0}, "detection_engines": {},
            "file_analysis": {"status": "not_performed", "files": [], "warnings": [], "errors": []},
        }
        for key, default in defaults.items():
            if not isinstance(value.get(key), type(default)):
                value[key] = default
        for key in ("urls", "domains", "ips", "hashes"):
            if not isinstance(value["indicators"].get(key), list):
                value["indicators"][key] = []
        value["report_available"] = bool(report)
        return value

    def finalize_capture_session(item: dict[str, Any]) -> None:
        # A poll and an HTTP refresh can observe the same unfinished row.
        # Recheck under one lock before generating reports or scheduling DNS.
        with capture_finalize_lock:
            with db.connect() as connection:
                current=connection.execute("SELECT finalized FROM capture_sessions WHERE id=?",(item["id"],)).fetchone()
            if current is None or current["finalized"]:
                return
            directory=scan_path/item["scan_id"]
            build_report(directory,db.path,enable_yara=bool(item.get("analyze_yara",1))); reconcile_scans(db,scan_path)
            from app.ioc import match_scan_iocs
            try:
                if item.get("analyze_ioc",1): match_scan_iocs(db,item["scan_id"],directory)
            except Exception as exc:
                now=datetime.now(timezone.utc).isoformat()
                with db.transaction() as connection:
                    connection.execute("""INSERT INTO enrichment_jobs
                      (id,scan_id,kind,status,created_at,completed_at,error)
                      VALUES(?,?,'offline_ioc','failed',?,?,?)""",
                      (str(uuid.uuid4()),item["scan_id"],now,now,
                       f"{type(exc).__name__}: {str(exc)[:700]}"))
            with db.transaction() as connection:
                connection.execute("UPDATE capture_sessions SET finalized=1 WHERE id=?",(item["id"],))
            with db.connect() as connection:
                dns_already_scheduled=connection.execute(
                  "SELECT 1 FROM enrichment_jobs WHERE scan_id=? AND kind='dns' LIMIT 1",(item["scan_id"],)).fetchone()
            if item.get("analyze_dns",1) and automatic_enabled(db) and not dns_already_scheduled:
                def enrich() -> None:
                    try: run_dns_job(db,item["scan_id"],directory)
                    except Exception: pass
                threading.Thread(target=enrich,name=f"dns-{item['scan_id'][:8]}",daemon=True).start()

    def reconcile_capture_sessions() -> None:
        active_states={"queued","starting","running","finalizing","analyzing"}
        with db.connect() as connection:
            active=[dict(row) for row in connection.execute(
                "SELECT * FROM capture_sessions WHERE status IN ('queued','starting','running','finalizing','analyzing')")]
        for item in active:
            try:
                remote=controller_for(item.get("network_policy", "fixture")).status(item["id"])
            except ControllerHTTPError as exc:
                if exc.status != 404 or exc.code != "session_unknown":
                    continue
                completed_at=datetime.now(timezone.utc).isoformat()
                directory=scan_path/item["scan_id"]
                if (directory/"meta.json").is_file() and (directory/"network.har").is_file():
                    try:
                        finalize_capture_session(item); status="completed"; error=None
                    except Exception as final_exc:
                        status="interrupted"; error=f"Controller restarted; finalization failed: {str(final_exc)[:700]}"
                else:
                    status="interrupted"; error="Controller restarted while this capture was active"
                with db.transaction() as connection:
                    connection.execute("UPDATE capture_sessions SET status=?,completed_at=?,updated_at=?,error=? WHERE id=?",
                                       (status,completed_at,completed_at,error,item["id"]))
                continue
            except ControllerUnavailable:
                continue
            status=remote.get("status") if remote.get("status") in active_states|{"completed","failed","cancelled"} else "failed"
            with db.transaction() as connection:
                connection.execute("""UPDATE capture_sessions SET status=?,started_at=coalesce(?,started_at),
                  completed_at=?,updated_at=?,error=? WHERE id=?""",
                  (status,remote.get("started_at"),remote.get("completed_at"),remote.get("updated_at") or datetime.now(timezone.utc).isoformat(),
                   remote.get("error"),item["id"]))
            if status=="completed" and not item["finalized"]:
                try:
                    finalize_capture_session(item)
                except Exception as exc:
                    with db.transaction() as connection:
                        connection.execute("UPDATE capture_sessions SET status='failed',error=? WHERE id=?",
                                           (f"Finalization failed: {str(exc)[:800]}",item["id"]))
    def sync_capture_sessions() -> list[dict[str, Any]]:
        reconcile_capture_sessions()
        with db.connect() as connection:
            values=[dict(row) for row in connection.execute("SELECT * FROM capture_sessions ORDER BY created_at DESC LIMIT 100")]
        current=datetime.now(timezone.utc)
        for item in values:
            try:
                start=datetime.fromisoformat(item.get("started_at") or item["created_at"])
                end=datetime.fromisoformat(item["completed_at"]) if item.get("completed_at") else current
                item["duration_seconds"]=max(0,int((end-start).total_seconds()))
            except (TypeError,ValueError): item["duration_seconds"]=None
        return values

    @app.get("/healthz")
    def health():
        try:
            with db.connect() as connection: connection.execute("SELECT 1").fetchone()
            return {"status": "ok", "setup_required": False}
        except Exception: return JSONResponse({"status": "failed"}, 503)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, error: str = "", message: str = ""):
        capture_sessions=sync_capture_sessions()
        with db.connect() as connection:
            stats = dict(connection.execute("""SELECT count(*) total,
              sum(capture_status='completed') completed,sum(capture_status='failed') failed,
              sum(report_available) reports,sum(detection_count) detections FROM scans WHERE present=1""").fetchone())
            recent = [dict(row) for row in connection.execute("SELECT * FROM scans WHERE present=1 ORDER BY coalesce(capture_date,indexed_at) DESC LIMIT 8")]
            active_rules = connection.execute("SELECT count(*) FROM yara_rules WHERE active=1 AND archived=0").fetchone()[0]
            active_iocs = connection.execute("SELECT count(*) FROM manual_iocs WHERE active=1 AND archived=0").fetchone()[0]
            provider_rows=[dict(row) for row in connection.execute(
                "SELECT id,name,profile,enabled FROM threat_providers ORDER BY name")]
            dns_settings=dict(connection.execute("SELECT key,value FROM app_settings WHERE key IN ('dns_external_enabled','dns_auto_enabled')"))
        active_session=next((item for item in capture_sessions if item["status"] in {"queued","starting","running","finalizing","analyzing"}),None)
        return page(request, "dashboard.html", active="dashboard", stats=stats, recent=recent,
                    active_rules=active_rules,active_iocs=active_iocs,dns_providers=provider_rows,
                    capture_sessions=capture_sessions[:5],active_session=active_session,
                    public_capture=public_capture,error=error,message=message,
                    dns_authorized=dns_settings.get("dns_external_enabled")=="true",
                    dns_automatic=dns_settings.get("dns_auto_enabled")=="true")

    @app.get("/scans", response_class=HTMLResponse)
    def scans(request: Request, q: str = "", status: str = "", profile: str = "", detected: str = "", date_from: str = "", date_to: str = "", order: str = "new", page_number: int = 1):
        q=q[:200]; page_number=max(1,min(page_number,100000)); params=[]; where=["present=1"]
        if q: where.append("(scan_id LIKE ? OR submitted_url LIKE ? OR final_url LIKE ? OR host LIKE ? OR indicators_json LIKE ?)"); params.extend([f"%{q}%"]*5)
        if status: where.append("(capture_status=? OR analysis_status=?)"); params.extend([status[:30]]*2)
        if profile: where.append("profile=?"); params.append(profile[:50])
        if detected == "yes": where.append("detection_count>0")
        elif detected == "no": where.append("detection_count=0")
        if re_date(date_from): where.append("capture_date>=?"); params.append(date_from)
        if re_date(date_to): where.append("capture_date<?"); params.append(date_to+"T23:59:59.999999")
        with db.connect() as connection:
            size_row=connection.execute("SELECT value FROM app_settings WHERE key='page_size'").fetchone(); size=int(size_row[0]) if size_row else 25
            exportable_total=connection.execute("SELECT count(*) FROM scans WHERE present=1").fetchone()[0]
            clause=" AND ".join(where); total=connection.execute(f"SELECT count(*) FROM scans WHERE {clause}",params).fetchone()[0]
            rows=[dict(row) for row in connection.execute(f"SELECT * FROM scans WHERE {clause} ORDER BY coalesce(capture_date,indexed_at) {'ASC' if order=='old' else 'DESC'} LIMIT ? OFFSET ?", (*params,size,(page_number-1)*size))]
            profiles=[row[0] for row in connection.execute("SELECT DISTINCT profile FROM scans WHERE profile IS NOT NULL ORDER BY profile")]
        return page(request,"scans.html",active="scans",scans=rows,total=total,exportable_total=exportable_total,page_number=page_number,page_size=size,profiles=profiles,filters={"q":q,"status":status,"profile":profile,"detected":detected,"date_from":date_from,"date_to":date_to,"order":order})

    @app.post("/admin/reindex")
    def reindex(request: Request, csrf: str = Form(...)):
        require_csrf(request, csrf); reconcile_scans(db, scan_path)
        return RedirectResponse("/settings?message=Index+reconciled",303)

    @app.post("/scans/{scan_id}/remove")
    def remove_scan_from_history(request: Request, scan_id: str, csrf: str = Form(...)):
        require_csrf(request, csrf)
        # Validate the identifier and retain the on-disk evidence. This action
        # only removes the investigation from lists and aggregate counters.
        scan_directory(scan_id)
        with db.transaction() as connection:
            known = connection.execute("SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
            if not known:
                raise HTTPException(404, "Scan not found")
            connection.execute(
                "INSERT OR REPLACE INTO hidden_scans(scan_id,hidden_at) VALUES(?,?)",
                (scan_id, datetime.now(timezone.utc).isoformat()),
            )
            connection.execute("UPDATE scans SET present=0 WHERE scan_id=?", (scan_id,))
        if request.headers.get("HX-Request") == "true":
            return Response("", media_type="text/html", headers={"HX-Trigger": "scanRemoved"})
        return RedirectResponse("/scans?message=Investigation+retirée", 303)

    def delete_scan_data(scan_id: str) -> None:
        """Delete one terminal investigation and its evidence atomically."""
        directory = scan_directory(scan_id)
        with db.connect() as connection:
            active = connection.execute(
                "SELECT 1 FROM capture_sessions WHERE scan_id=? AND status IN "
                "('queued','starting','running','finalizing','analyzing')",
                (scan_id,),
            ).fetchone()
        if active:
            raise HTTPException(409, "An active investigation cannot be deleted")

        staging = directory.parent / f".delete-{scan_id}-{secrets.token_hex(6)}"
        directory.rename(staging)
        try:
            with db.transaction() as connection:
                connection.execute("DELETE FROM ioc_matches WHERE scan_id=?", (scan_id,))
                connection.execute("DELETE FROM dns_results WHERE scan_id=?", (scan_id,))
                connection.execute("DELETE FROM enrichment_jobs WHERE scan_id=?", (scan_id,))
                connection.execute("DELETE FROM capture_sessions WHERE scan_id=?", (scan_id,))
                connection.execute("DELETE FROM hidden_scans WHERE scan_id=?", (scan_id,))
                connection.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
                connection.execute(
                    "INSERT INTO audit_events(created_at,action,target,outcome,detail) "
                    "VALUES(?, 'scan.delete', ?, 'success', 'report and evidence deleted')",
                    (datetime.now(timezone.utc).isoformat(), scan_id),
                )
        except Exception:
            staging.rename(directory)
            raise
        shutil.rmtree(staging)

    @app.post("/scans/{scan_id}/delete")
    def delete_scan_permanently(request: Request, scan_id: str, csrf: str = Form(...)):
        """Delete one terminal investigation and all of its stored evidence."""
        require_csrf(request, csrf)
        delete_scan_data(scan_id)
        if request.headers.get("HX-Request") == "true":
            return Response("", media_type="text/html", headers={"HX-Trigger": "scanDeleted"})
        return RedirectResponse("/scans?message=Investigation+supprimée", 303)

    def spreadsheet_response(request: Request, identifiers: list[str], filename: str):
        from app.reporting.xlsx_export import export_investigations, ExportLimitError, ExportBusyError
        temporary=tempfile.NamedTemporaryFile(prefix="odysafe-report-",suffix=".xlsx",delete=False)
        destination=Path(temporary.name);temporary.close()
        try:
            export_investigations(db,scan_path,identifiers,destination,interface_language(request))
        except ExportBusyError as exc:
            destination.unlink(missing_ok=True)
            raise HTTPException(429,str(exc),headers={"Retry-After":"5"}) from exc
        except ExportLimitError as exc:
            destination.unlink(missing_ok=True)
            raise HTTPException(413,str(exc)) from exc
        except ValueError as exc:
            destination.unlink(missing_ok=True)
            raise HTTPException(409,"Les preuves d’une investigation sont indisponibles. Actualisez la liste puis réessayez.") from exc
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return FileResponse(destination,filename=filename,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Cache-Control":"no-store"},
            background=BackgroundTask(destination.unlink,missing_ok=True))

    @app.get("/scans/export.xlsx")
    def export_all_spreadsheets(request: Request):
        with db.connect() as connection:
            identifiers=[row[0] for row in connection.execute("SELECT scan_id FROM scans WHERE present=1 ORDER BY coalesce(capture_date,indexed_at) DESC")]
        if not identifiers:
            raise HTTPException(409,"Aucune investigation à exporter. Enregistrez une première investigation.")
        return spreadsheet_response(request,identifiers,"odysafe-investigations.xlsx")

    @app.get("/scans/{scan_id}/export.xlsx")
    def export_spreadsheet(request: Request, scan_id: str):
        scan_directory(scan_id)
        return spreadsheet_response(request,[scan_id],f"odysafe-investigation-{scan_id[:8]}.xlsx")

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_detail(request: Request, scan_id: str, section: str = "overview", q: str = "", page_number: int = 1):
        directory=scan_directory(scan_id); report=read_json(directory/"report.json"); meta=read_json(directory/"meta.json")
        report=compatible_report(report,meta)
        if not isinstance(report.get("javascript"),list): report["javascript"]=javascript_observations(directory)
        if (not isinstance(report.get("relations"),dict) or
                not isinstance(report.get("relations",{}).get("browser_paths"),list) or
                not isinstance(report.get("relations",{}).get("host_edges"),list)):
            report["relations"]=relation_graph(directory,report)
        primary_host=urlsplit(str(report.get("overview",{}).get("submitted_url") or "")).hostname
        for node in report.get("relations",{}).get("nodes",[]):
            if isinstance(node,dict) and node.get("kind")=="host": node["primary"]=node.get("host")==primary_host
        if isinstance(report.get("downloaded_files"),list):
            for item in report["downloaded_files"]:
                if isinstance(item,dict) and item.get("path") and not item.get("status"):
                    item.update(status="collected",original_name=Path(item["path"]).name,
                                stored_name=Path(item["path"]).name,source_url=None)
        sections={"overview","hosts","network","navigation","behavior","detections","artifacts","indicators","threat_intelligence"}; section=section if section in sections else "overview"
        requests_data=report.get("network",{}).get("requests",[]) if isinstance(report.get("network"),dict) else []
        if not isinstance(requests_data,list): requests_data=[]
        relation_nodes={item.get("id"):item for item in report.get("relations",{}).get("nodes",[]) if isinstance(item,dict)}
        initiators={edge.get("target"):relation_nodes.get(edge.get("source"),{}).get("label")
                    for edge in report.get("relations",{}).get("edges",[])
                    if isinstance(edge,dict) and edge.get("verified")}
        for item in requests_data:
            if isinstance(item,dict): item["initiator"]=initiators.get(item.get("id"))
        if q: requests_data=[item for item in requests_data if q.lower() in json.dumps(item,ensure_ascii=False).lower()]
        page_number=max(1,page_number); network_page=requests_data[(page_number-1)*50:page_number*50]
        artifacts=[]
        for name in sorted(ALLOWED_ARTIFACTS):
            path=directory/name
            if path.is_file() and not path.is_symlink(): artifacts.append({"name":name,"size":path.stat().st_size})
        downloads=directory/"downloads"
        if downloads.is_dir() and not downloads.is_symlink():
            for child in sorted(downloads.iterdir()):
                if child.is_file() and not child.is_symlink(): artifacts.append({"name":f"downloads/{child.name}","size":child.stat().st_size})
        dom_text=""
        if section=="artifacts" and (directory/"dom.html").is_file() and (directory/"dom.html").stat().st_size<=1024*1024:
            dom_text=(directory/"dom.html").read_text(encoding="utf-8",errors="replace")
        intelligence=dns_status(db,scan_id)
        presentation=report_presentation(report,intelligence)
        resolved_ips=[]
        for observation in intelligence["dns_results"]:
            for answer in observation.get("answers",[]):
                candidate=str(answer).rstrip(".").split()[-1]
                try: address=str(ipaddress.ip_address(candidate))
                except ValueError: continue
                if not ipaddress.ip_address(address).is_global: continue
                resolved_ips.append({"domain":observation["domain"],"ip":address,
                    "version":ipaddress.ip_address(address).version,
                    "source":observation["provider_id"],"observed_at":observation["checked_at"],
                    "kind":"resolved"})
        resolved_by_host: dict[str,list[dict[str,Any]]]={}
        for item in resolved_ips:
            bucket=resolved_by_host.setdefault(item["domain"],[])
            if not any(existing["ip"]==item["ip"] and existing["source"]==item["source"] for existing in bucket):
                bucket.append(item)
        for item in network_page:
            if not isinstance(item,dict): continue
            item["resolved_ips"]=resolved_by_host.get(str(item.get("hostname")),[])
            try:
                address=ipaddress.ip_address(str(item.get("server_ip_address")))
                item["remote_server_ip"]=str(address) if address.is_global else None
            except ValueError: item["remote_server_ip"]=None
        host_connections={item.get("hostname"):[str(value) for value in item.get("ip_addresses",[])
                          if _is_public_ip(value)] for item in report.get("hosts",[])
                          if isinstance(item,dict) and item.get("hostname")}
        for node in report.get("relations",{}).get("nodes",[]):
            if isinstance(node,dict) and node.get("kind")=="host":
                node["connection_ips"]=host_connections.get(node.get("host"),[])
                node["resolved_ips"]=[item["ip"] for item in resolved_ips if item["domain"]==node.get("host")]
        jobs_by_kind={}
        for job in intelligence["jobs"]:
            jobs_by_kind.setdefault(job["kind"],job)
        with db.connect() as connection:
            dns_settings=dict(connection.execute(
                "SELECT key,value FROM app_settings WHERE key IN ('dns_external_enabled','dns_auto_enabled')"))
        dns_job=jobs_by_kind.get("dns"); ioc_job=jobs_by_kind.get("offline_ioc")
        analysis_states={
            "capture": report["overview"].get("capture_status") or "unknown",
            "yara_x": report.get("detection_engines",{}).get("yara_x",{}).get("status","not_performed"),
            "file_analysis": report.get("file_analysis",{}).get("status","not_performed"),
            "ioc": ioc_job["status"] if ioc_job else "not_performed",
            "dns": (dns_job["status"] if dns_job else
                    ("not_authorized" if dns_settings.get("dns_external_enabled")!="true" else "not_performed")),
        }
        return page(request,"detail.html",active="scans",scan_id=scan_id,report=report,meta=meta,section=section,network_page=network_page,network_total=len(requests_data),artifacts=artifacts,dom_text=dom_text,q=q,page_number=page_number,intelligence=intelligence,analysis_states=analysis_states,resolved_ips=resolved_ips,presentation=presentation)

    @app.get("/scans/{scan_id}/view/{artifact_path:path}", response_class=HTMLResponse)
    def view_text(request: Request, scan_id: str, artifact_path: str):
        session_for(request); directory=scan_directory(scan_id)
        parts=Path(artifact_path).parts
        allowed=artifact_path in {"network.har","dom.html","cookies.json","console.json","browser_events.json","downloads.json","meta.json","report.json"} or (len(parts)==2 and parts[0]=="scripts")
        path=directory/artifact_path
        if (not allowed or artifact_path.startswith("/") or ".." in parts or path.is_symlink() or
                not path.is_file() or path.stat().st_size>2*1024*1024 or path.resolve().parent not in {directory,directory/"scripts"}):
            raise HTTPException(404)
        raw=path.read_bytes(); text=raw.decode("utf-8",errors="replace")
        return page(request,"viewer.html",active="scans",scan_id=scan_id,artifact_name=artifact_path,
                    content=text,content_lines=text.splitlines() or [""],line_count=text.count("\n")+1,
                    sha256=hashlib.sha256(raw).hexdigest())

    @app.post("/scans/{scan_id}/downloads.zip")
    def export_downloads(request: Request, scan_id: str, csrf: str=Form(...), artifact: str=Form("")):
        require_csrf(request,csrf); directory=scan_directory(scan_id); downloads=directory/"downloads"
        if downloads.is_symlink() or not downloads.is_dir(): raise HTTPException(404)
        report=read_json(directory/"report.json"); records=report.get("downloaded_files",[])
        if not isinstance(records,list): records=[]
        selected=[]; total=0
        for item in records:
            if not isinstance(item,dict) or not item.get("path"): continue
            if item.get("status") not in {None,"collected"}: continue
            if artifact and item.get("path") != artifact: continue
            path=directory/str(item["path"])
            if (path.is_symlink() or not path.is_file() or path.resolve().parent!=downloads.resolve()):
                continue
            total += path.stat().st_size
            if total>MAX_EXPORT_BYTES: raise HTTPException(413,"Archive limit exceeded")
            selected.append((item,path))
        if not selected: raise HTTPException(404,"No collected download available")
        temporary=tempfile.NamedTemporaryFile(prefix="odysafe-export-",suffix=".zip",delete=False); temporary.close()
        manifest=[]
        try:
            with zipfile.ZipFile(temporary.name,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
                for index,(item,path) in enumerate(selected,1):
                    internal=f"files/{index:03d}-{path.name}"
                    archive.write(path,internal)
                    manifest.append({"archive_path":internal,"original_name":item.get("original_name"),
                        "source_url":item.get("source_url"),"size":path.stat().st_size,
                        "sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"status":"collected"})
                archive.writestr("manifest.json",json.dumps({"scan_id":scan_id,"files":manifest},ensure_ascii=False,indent=2))
        except Exception:
            Path(temporary.name).unlink(missing_ok=True); raise
        return FileResponse(temporary.name,media_type="application/zip",filename=f"odysafe-{scan_id}-downloads.zip",
                            background=BackgroundTask(Path(temporary.name).unlink,missing_ok=True),
                            headers={"X-Content-Type-Options":"nosniff"})

    @app.get("/scans/{scan_id}/artifact/{artifact_path:path}")
    def artifact(request: Request, scan_id: str, artifact_path: str, inline: bool=False):
        session_for(request); directory=scan_directory(scan_id)
        if artifact_path.startswith("/") or ".." in Path(artifact_path).parts: raise HTTPException(404)
        allowed=artifact_path in ALLOWED_ARTIFACTS or (Path(artifact_path).parts[0] in {"downloads","scripts"} and len(Path(artifact_path).parts)==2)
        if not allowed: raise HTTPException(404)
        path=directory/artifact_path
        if path.is_symlink() or not path.is_file() or path.resolve().parent not in {directory,directory/"downloads",directory/"scripts"}: raise HTTPException(404)
        if path.stat().st_size>MAX_ARTIFACT_BYTES: raise HTTPException(413,"Artifact too large")
        if inline and artifact_path=="screenshot.png" and path.read_bytes()[:8]==b"\x89PNG\r\n\x1a\n":
            return FileResponse(path,media_type="image/png",headers={"Content-Disposition":f'inline; filename="{scan_id}.png"'})
        return FileResponse(path,media_type="application/octet-stream",filename=Path(artifact_path).name)

    @app.get("/engines",response_class=HTMLResponse)
    def engines_page(request:Request):
        return page(request,"engines.html",active="engines")

    @app.post("/engines/{engine}/folders/{action}")
    def engine_folder_action(request: Request, engine: str, action: str, csrf: str=Form(...),
                             name: str=Form(""), folder_id: str=Form("")):
        require_csrf(request,csrf)
        try:
            library=EngineLibrary(db,engine)
            if action == "save": folder_id=library.save_folder(name,folder_id)
            elif action == "delete": library.delete_folder(folder_id); folder_id="none"
            else: raise ValueError("Action inconnue")
        except (ValueError,sqlite3.IntegrityError) as exc:
            raise HTTPException(400,"Nom déjà utilisé ou dossier invalide : "+str(exc)) from exc
        return RedirectResponse(f"/engines/{engine}?folder={folder_id}",303)

    @app.post("/engines/{engine}/move")
    def engine_move(request: Request, engine: str, csrf: str=Form(...),
                    selected: list[str]=Form(default=[]), folder_id: str=Form("")):
        require_csrf(request,csrf)
        try: EngineLibrary(db,engine).move(selected,folder_id)
        except ValueError as exc: raise HTTPException(400,str(exc)) from exc
        return RedirectResponse(f"/engines/{engine}?folder={folder_id or 'none'}&message=Éléments+déplacés",303)

    @app.post("/engines/{engine}/prepare")
    def engine_prepare(request: Request, engine: str, csrf: str=Form(...), selected: list[str]=Form(default=[]), folders:list[str]=Form(default=[])):
        require_csrf(request,csrf)
        if engine not in {"yara","ioc"}: raise HTTPException(404,"Moteur inconnu")
        # Reuse the GET page, with the selected rows already checked.
        values={"rules":rules.list()} if engine=="yara" else {"iocs":iocs.list()}
        if folders:
            try: selected=EngineLibrary(db,engine).selection(selected,folders)
            except ValueError as exc: values["error"]="Ce dossier ne peut pas être préparé : "+str(exc)
        values.update(forced_view="analyze",preselected=selected,q="",state="all",selected=None)
        return page(request,"rules.html" if engine=="yara" else "intelligence.html",active="engines",**values)

    @app.post("/engines/ioc/bulk/{action}")
    def ioc_bulk(request: Request, action: str, csrf: str=Form(...), selected: list[str]=Form(default=[])):
        require_csrf(request,csrf)
        if action not in {"activate","disable","archive"} or not selected or len(selected)>100:
            raise HTTPException(400,"Sélection ou action invalide")
        try:
            for identifier in dict.fromkeys(selected): iocs.set_state(identifier,action)
        except IOCValidationError as exc: raise HTTPException(400,str(exc)) from exc
        return RedirectResponse("/engines/ioc?message=Sélection+mise+à+jour",303)

    @app.post("/engines/{engine}/analyze")
    def engine_analyze(request: Request, engine: str, csrf: str=Form(...),
                       selected: list[str]=Form(default=[]), folders: list[str]=Form(default=[]),
                       scan_ids: list[str]=Form(default=[]), include_inactive: str=Form("false"),
                       stage: str=Form("preview")):
        require_csrf(request,csrf)
        if engine not in {"yara","ioc","dns"}: raise HTTPException(404,"Moteur inconnu")
        investigations=list(dict.fromkeys(scan_ids))
        if not investigations or len(investigations)>20: raise HTTPException(400,"Choisissez entre 1 et 20 investigations")
        directories=[scan_directory(identifier) for identifier in investigations]
        identifiers=[]; chosen=[]; sources=[]
        try:
            if engine != "dns":
                identifiers=EngineLibrary(db,engine).selection(selected,folders,include_inactive=="true")
                chosen=[(rules.get(identifier)["name"] if engine=="yara" else iocs.get(identifier)["original_value"]) for identifier in identifiers]
                if engine=="yara": sources=rules.sources_by_ids(identifiers)
            else:
                with db.connect() as connection:
                    consent=connection.execute("SELECT value FROM app_settings WHERE key='dns_external_enabled'").fetchone()
                    providers=[row[0] for row in connection.execute("SELECT name FROM threat_providers WHERE enabled=1")]
                    providers += [row[0] for row in connection.execute("SELECT name FROM custom_dns_resolvers WHERE enabled=1")]
                if not consent or consent[0]!="true": raise ValueError("Autorisez les requêtes dans les réglages DNS")
                if not providers: raise ValueError("Choisissez au moins un fournisseur DNS")
                from app.dns.domains import extract_domains
                domain_counts=[len(extract_domains(directory,500)) for directory in directories]
                if not all(domain_counts): raise ValueError("Une investigation ne contient aucun domaine public vérifiable")
                chosen=providers
        except ValueError as exc: raise HTTPException(400,str(exc)) from exc
        if stage != "run":
            return page(request,"engine_confirm.html",active="engines",engine=engine,selected_ids=identifiers,
                        chosen=chosen,scan_ids=investigations,include_inactive=include_inactive,
                        domain_counts=domain_counts if engine=="dns" else [])
        if engine=="dns":
            if not manual_dns_lock.acquire(blocking=False):
                raise HTTPException(409,"Une vérification manuelle DNS est déjà en cours")
            def batch_dns():
                try:
                    for identifier,directory in zip(investigations,directories):
                        try: run_dns_job(db,identifier,directory)
                        except Exception: pass  # run_dns_job persists worker failures.
                finally: manual_dns_lock.release()
            try: threading.Thread(target=batch_dns,name="dns-manual-batch",daemon=True).start()
            except Exception:
                manual_dns_lock.release()
                raise
        else:
            from app.ioc import match_scan_iocs
            for identifier,directory in zip(investigations,directories):
                try:
                    if engine=="yara": build_report(directory,db.path,selected_yara_sources=sources)
                    else: match_scan_iocs(db,identifier,directory,identifiers)
                except (ReportBuildError,ValueError,OSError,TypeError) as exc: raise HTTPException(400,str(exc)) from exc
            reconcile_scans(db,scan_path)
        return RedirectResponse(f"/engines/{engine}?view={'checks' if engine=='dns' else 'results'}&message="+
                                ("Vérification+DNS+lancée" if engine=="dns" else "Analyse+terminée"),303)

    @app.get("/engines/yara",response_class=HTMLResponse)
    @app.get("/rules",response_class=HTMLResponse)
    def rules_page(request:Request,q:str="",state:str="all",category:str="",edit:str=""):
        selected=rules.get(edit) if edit else None
        all_rules=rules.list()
        categories=sorted({str(item.get("category") or "Général") for item in all_rules})
        with db.connect() as connection:
            recent_scans=[dict(row) for row in connection.execute("""SELECT scan_id,host,submitted_url,capture_date
                FROM scans WHERE present=1 AND report_available=1
                ORDER BY coalesce(capture_date,indexed_at) DESC LIMIT 30""")]
        return page(request,"rules.html",active="rules",rules=rules.list(q,state,category),selected=selected,
                    categories=categories,category=category,q=q,state=state,
                    recent_scans=recent_scans,
                    behavior=read_json(PROJECT_ROOT/"rules"/"behavior"/"rules.json"))

    @app.get("/engines/ioc",response_class=HTMLResponse)
    @app.get("/intelligence",response_class=HTMLResponse)
    def intelligence_page(request:Request,q:str="",state:str="all",ioc_type:str="",edit:str=""):
        selected=iocs.get(edit) if edit else None
        with db.connect() as connection:
            recent_ioc_matches=[dict(row) for row in connection.execute("""SELECT m.scan_id,m.observed_type,
              m.observed_value,m.matched_at,m.explanation,i.original_value,i.category
              FROM ioc_matches m JOIN manual_iocs i ON i.id=m.ioc_id
              ORDER BY m.matched_at DESC,m.id DESC LIMIT 100""")]
            recent_scans=[dict(row) for row in connection.execute("""SELECT scan_id,host,submitted_url,capture_date
                FROM scans WHERE present=1 AND report_available=1
                ORDER BY coalesce(capture_date,indexed_at) DESC LIMIT 30""")]
        return page(request,"intelligence.html",active="intelligence",iocs=iocs.list(q,state,ioc_type),
                    selected=selected,q=q,state=state,ioc_type=ioc_type,recent_ioc_matches=recent_ioc_matches,
                    recent_scans=recent_scans)

    @app.post("/iocs/save")
    def save_ioc(request:Request,csrf:str=Form(...),ioc_type:str=Form("domain"),value:str=Form(""),
                 category:str=Form("unknown"),comment:str=Form(""),source:str=Form(""),
                 expires_at:str=Form(""),ioc_id:str=Form(""),folder_id:str=Form("")):
        require_csrf(request,csrf)
        library=EngineLibrary(db,"ioc")
        folder_id=folder_id or library.default_folder()
        if folder_id not in {f['id'] for f in library.folders()}: raise HTTPException(400,"Dossier introuvable")
        try:
            if ioc_id and not iocs.get(ioc_id): raise IOCValidationError("IOC not found")
            identifier=iocs.save(ioc_type,value,category,comment,source,expires_at or None,ioc_id or None)
            library.move([identifier],folder_id)
        except (ValueError,sqlite3.IntegrityError) as exc:
            field,message=ioc_form_error(str(exc),ioc_type)
            draft={"id":ioc_id,"type":ioc_type,"original_value":value,"category":category,
                   "comment":comment,"declared_source":source,"expires_at":expires_at,"folder_id":folder_id}
            response=page(request,"intelligence.html",active="intelligence",iocs=iocs.list(),
                          selected=draft,q="",state="all",ioc_type="",forced_view="library",forced_folder=folder_id,
                          error="L’indicateur n’a pas été enregistré. Corrigez le champ signalé ci-dessous.",
                          field_errors={field:message})
            response.status_code=400
            return response
        return RedirectResponse(f"/engines/ioc?edit={identifier}&folder={folder_id}&message=Indicateur+enregistré",303)

    @app.post("/iocs/{ioc_id}/state/{action}")
    def ioc_state(request:Request,ioc_id:str,action:str,csrf:str=Form(...)):
        require_csrf(request,csrf)
        try: iocs.set_state(ioc_id,action)
        except IOCValidationError as exc: raise HTTPException(400,str(exc)) from exc
        return RedirectResponse("/intelligence?message=IOC+updated",303)

    @app.get("/iocs/export")
    def export_iocs(request:Request):
        session_for(request)
        payload={"schema":1,"provenance":"manual","iocs":iocs.list()}
        return Response(json.dumps(payload,ensure_ascii=False,indent=2),media_type="application/json",
                        headers={"Content-Disposition":"attachment; filename=odysafe-manual-iocs.json"})

    @app.post("/iocs/reanalyze")
    def reanalyze_with_selected_iocs(request:Request,csrf:str=Form(...),
                                     selected:list[str]=Form(default=[]),
                                     scan_ids:list[str]=Form(default=[])):
        require_csrf(request,csrf)
        identifiers=list(dict.fromkeys(selected))
        investigations=list(dict.fromkeys(scan_ids))
        if not identifiers or len(identifiers)>100:
            raise HTTPException(400,"Select between 1 and 100 IOCs")
        if not investigations or len(investigations)>20:
            raise HTTPException(400,"Select between 1 and 20 investigations")
        from app.ioc import match_scan_iocs
        for scan_id in investigations:
            try: match_scan_iocs(db,scan_id,scan_directory(scan_id),identifiers)
            except (ValueError,OSError,TypeError) as exc:
                raise HTTPException(400,f"{scan_id}: {exc}") from exc
        if len(investigations)==1:
            return RedirectResponse(f"/scans/{investigations[0]}?section=detections",303)
        return RedirectResponse(f"/intelligence?message={len(investigations)}+investigations+comparées",303)

    @app.post("/rules/save")
    async def save_rule(request:Request,csrf:str=Form(...),name:str=Form(...),description:str=Form(""),
                        category:str=Form("Général"),source:str=Form(""),rule_id:str=Form(""),
                        upload:UploadFile|None=None,folder_id:str=Form("")):
        require_csrf(request,csrf)
        if folder_id and folder_id not in {f["id"] for f in EngineLibrary(db,"yara").folders()}: raise HTTPException(400,"Dossier introuvable")
        if upload and upload.filename:
            if not upload.filename.lower().endswith((".yar",".yara")): raise HTTPException(400,"Only .yar/.yara files are accepted")
            payload=await upload.read(64*1024+1)
            try: source=payload.decode("utf-8")
            except UnicodeError: raise HTTPException(400,"Rule must be UTF-8")
        try:
            identifier=rules.save(name,source,description,rule_id or None,category)
            EngineLibrary(db,"yara").move([identifier],folder_id)
        except RuleValidationError as exc:
            all_rules=rules.list(); categories=sorted({str(item.get("category") or "Général") for item in all_rules}|{category})
            return page(request,"rules.html",active="rules",rules=all_rules,
                        selected={"id":rule_id,"name":name,"description":description,"category":category,"source":source,"folder_id":folder_id or EngineLibrary(db,"yara").default_folder()},
                        categories=categories,category="",error=str(exc),q="",state="all",
                        behavior=read_json(PROJECT_ROOT/"rules"/"behavior"/"rules.json"))
        return RedirectResponse(f"/engines/yara?edit={identifier}&folder={folder_id or 'none'}&message=Règle+enregistrée",303)

    @app.post("/rules/import")
    async def import_rules(request:Request,csrf:str=Form(...),uploads:list[UploadFile]=File(...),folder_id:str=Form("")):
        require_csrf(request,csrf)
        library=EngineLibrary(db,"yara")
        if folder_id and folder_id not in {f["id"] for f in library.folders()}: raise HTTPException(400,"Dossier introuvable")
        if not folder_id:
            folder_id=library.default_folder()
        if len(uploads)>20: raise HTTPException(413,"At most 20 uploads are accepted")
        candidates=[]; failures=[]; total=0
        for upload in uploads:
            name=Path(upload.filename or "").name
            payload=await upload.read(2*1024*1024+1); total+=len(payload)
            if total>2*1024*1024: raise HTTPException(413,"Rule import exceeds 2 MiB")
            if name.lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(__import__("io").BytesIO(payload)) as archive:
                        infos=archive.infolist()
                        if len(infos)>100 or sum(item.file_size for item in infos)>4*1024*1024:
                            raise ValueError("Archive limits exceeded")
                        for item in infos:
                            parts=Path(item.filename).parts
                            if (item.is_dir() or item.filename.startswith("/") or ".." in parts or
                                (item.external_attr>>16)&0o170000==0o120000):
                                if not item.is_dir(): failures.append({"name":item.filename,"error":"unsafe archive entry"})
                                continue
                            if not item.filename.lower().endswith((".yar",".yara")): continue
                            if item.file_size>64*1024 or (item.compress_size and item.file_size/item.compress_size>100):
                                failures.append({"name":item.filename,"error":"size or compression limit"}); continue
                            candidates.append((Path(item.filename).name,archive.read(item)))
                except (zipfile.BadZipFile,ValueError) as exc:
                    failures.append({"name":name,"error":str(exc)})
            elif name.lower().endswith((".yar",".yara")):
                candidates.append((name,payload))
            else: failures.append({"name":name,"error":"unsupported extension"})
        if len(candidates)>50: raise HTTPException(413,"At most 50 rule files are accepted")
        existing_declared=set()
        for item in rules.list():
            current=rules.get(item["id"])
            if current: existing_declared.update(RULE_NAME.findall(current["source"]))
        imported=[]; seen=set()
        for filename,payload in candidates:
            try:
                source=payload.decode("utf-8")
                declared=RULE_NAME.findall(source)
                if not declared: raise RuleValidationError("No YARA rule declaration found")
                conflict=(set(declared)&existing_declared)|(set(declared)&seen)
                if conflict: raise RuleValidationError("Rule name conflict: "+", ".join(sorted(conflict)))
                compile_sources([(f"import:{filename}",source)])
                registry_name=re.sub(r"[^A-Za-z0-9_.-]","_",Path(filename).stem)[:70]
                if not registry_name or not registry_name[0].isalpha(): registry_name="import_"+registry_name
                identifier=rules.save(registry_name,source,f"Imported from {filename}",category="Importées")
                library.move([identifier],folder_id)
                imported.append({"name":filename,"rules":declared,"id":identifier}); seen.update(declared)
            except (UnicodeError,RuleValidationError) as exc:
                failures.append({"name":filename,"error":str(exc)})
        all_rules=rules.list(); categories=sorted({str(item.get("category") or "Général") for item in all_rules})
        return page(request,"rules.html",active="rules",rules=all_rules,selected=None,
                    categories=categories,category="",error="",q="",state="all",
                    behavior=read_json(PROJECT_ROOT/"rules"/"behavior"/"rules.json"),
                    import_result={"imported":imported,"failed":failures})

    @app.post("/rules/{rule_id}/state/{action}")
    def rule_state(request:Request,rule_id:str,action:str,csrf:str=Form(...)):
        require_csrf(request,csrf)
        try: rules.set_state(rule_id,action)
        except RuleValidationError as exc: raise HTTPException(400,str(exc)) from exc
        return RedirectResponse(f"/rules?edit={rule_id}",303)

    @app.post("/rules/bulk/{action}")
    async def rule_bulk(request:Request,action:str,csrf:str=Form(...),selected:list[str]=Form(default=[])):
        require_csrf(request,csrf)
        try: result=rules.bulk_action(selected,action)
        except RuleValidationError as exc: raise HTTPException(400,str(exc)) from exc
        message=f"{len(result['updated'])}+règle(s)+mise(s)+à+jour"
        if result["refused"]: message+=f"+·+{len(result['refused'])}+refusée(s)"
        return RedirectResponse(f"/rules?message={message}",303)

    @app.post("/rules/reanalyze")
    def reanalyze_with_selected_rules(request:Request,csrf:str=Form(...),
                                      selected:list[str]=Form(default=[]),
                                      scan_ids:list[str]=Form(default=[])):
        require_csrf(request,csrf)
        if not scan_ids or len(set(scan_ids))>20:
            raise HTTPException(400,"Select between 1 and 20 investigations")
        try: selected_sources=rules.sources_by_ids(selected)
        except RuleValidationError as exc: raise HTTPException(400,str(exc)) from exc
        completed=[]
        for scan_id in dict.fromkeys(scan_ids):
            directory=scan_directory(scan_id)
            try: build_report(directory,db.path,selected_yara_sources=selected_sources)
            except (ReportBuildError,OSError,TypeError) as exc:
                raise HTTPException(400,f"{scan_id}: {exc}") from exc
            completed.append(scan_id)
        reconcile_scans(db,scan_path)
        if len(completed)==1:
            return RedirectResponse(f"/scans/{completed[0]}?section=detections",303)
        return RedirectResponse(f"/rules?message={len(completed)}+investigations+réanalysées",303)

    @app.post("/rules/{rule_id}/test")
    def test_rule(request:Request,rule_id:str,csrf:str=Form(...),target:str=Form("fixture"),scan_id:str=Form("")):
        require_csrf(request,csrf)
        artifact="harmless fixture"
        payload=b"ODYSAFE_YARA_TEST LOCAL_MARKER"
        if target=="scan":
            directory=scan_directory(scan_id); path=directory/"dom.html"
            if path.is_symlink() or not path.is_file(): raise HTTPException(400,"Scan DOM unavailable")
            if path.stat().st_size>10*1024*1024: raise HTTPException(413,"Scan DOM too large")
            payload=path.read_bytes(); artifact=f"{scan_id}/dom.html"
        elif target!="fixture": raise HTTPException(400,"Invalid test target")
        try: matches=rules.test(rule_id,payload)
        except RuleValidationError as exc: raise HTTPException(400,str(exc)) from exc
        selected=rules.get(rule_id)
        all_rules=rules.list(); categories=sorted({str(item.get("category") or "Général") for item in all_rules})
        return page(request,"rules.html",active="rules",rules=all_rules,selected=selected,q="",state="all",
                    categories=categories,category="",
                    behavior=read_json(PROJECT_ROOT/"rules"/"behavior"/"rules.json"),
                    test_result={"artifact":artifact,"matches":matches})

    @app.post("/scans/{scan_id}/reanalyze")
    def reanalyze(request:Request,scan_id:str,csrf:str=Form(...),
                  yara:str=Form("true"),ioc:str=Form("true"),dns:str=Form("false")):
        require_csrf(request,csrf); directory=scan_directory(scan_id)
        if not any(value=="true" for value in (yara,ioc,dns)):
            raise HTTPException(400,"Select at least one analysis engine")
        try:
            if yara=="true": build_report(directory,db.path)
            if ioc=="true":
                from app.ioc import match_scan_iocs
                match_scan_iocs(db,scan_id,directory)
            if dns=="true":
                with db.connect() as connection:
                    consent = connection.execute("SELECT value FROM app_settings WHERE key='dns_external_enabled'").fetchone()
                if not consent or consent[0] != "true": raise ValueError("Autorisez d’abord les requêtes dans Réputation DNS")
                threading.Thread(target=run_dns_job,args=(db,scan_id,directory),
                                 name=f"dns-manual-{scan_id[:8]}",daemon=True).start()
            reconcile_scans(db,scan_path)
        except (ReportBuildError,OSError,TypeError,ValueError) as exc: raise HTTPException(400,str(exc)) from exc
        return RedirectResponse(f"/scans/{scan_id}?section=detections",303)

    @app.get("/engines/dns",response_class=HTMLResponse)
    @app.get("/settings",response_class=HTMLResponse)
    def settings(request:Request,message:str=""):
        with db.connect() as connection:
            settings_values={row["key"]:row["value"] for row in connection.execute("SELECT key,value FROM app_settings WHERE key<>'admin_password_hash'")}
            scan_count=connection.execute("SELECT count(*) FROM scans WHERE present=1").fetchone()[0]
            dns_providers=[dict(row) for row in connection.execute("SELECT * FROM threat_providers ORDER BY name")]
            custom_dns_resolvers=[dict(row) for row in connection.execute("SELECT * FROM custom_dns_resolvers ORDER BY name")]
        from app.dns.providers import PROVIDER_SUMMARIES
        for item in dns_providers:
            configured=PROVIDERS.get(item["id"])
            if configured is None:
                continue
            item.update(
                primary_ip=configured.bootstrap,
                secondary_ip=configured.secondary,
                doh_endpoint=f"https://{configured.hostname}{configured.path}",
                coverage=PROVIDER_SUMMARIES[item["id"]]["coverage"],
                evidence=PROVIDER_SUMMARIES[item["id"]]["evidence"],
            )
        dns_page = request.url.path == "/engines/dns"
        with db.connect() as connection:
            recent = [dict(row) for row in connection.execute("SELECT * FROM enrichment_jobs WHERE kind='dns' ORDER BY created_at DESC LIMIT 100")]
            scans = [dict(row) for row in connection.execute("SELECT scan_id,host,submitted_url,capture_date FROM scans WHERE present=1 AND report_available=1 ORDER BY indexed_at DESC LIMIT 200")]
            observations = [dict(row) for row in connection.execute("SELECT * FROM dns_results ORDER BY checked_at DESC,id DESC LIMIT 200")]
        return page(request,"dns.html" if dns_page else "settings.html",active="engines" if dns_page else "settings",
                    settings=settings_values,scan_count=scan_count,database_path="/database/odysafe.db",message=message,
                    dns_providers=dns_providers,custom_dns_resolvers=custom_dns_resolvers,
                    jobs=recent,recent_scans=scans,observations=observations,view=request.query_params.get("view","checks"))

    @app.post("/settings")
    def save_settings(request:Request,csrf:str=Form(...),page_size:int=Form(...)):
        require_csrf(request,csrf)
        if page_size not in {10,25,50,100}: raise HTTPException(400,"Invalid page size")
        with db.transaction() as connection:
            connection.execute("INSERT OR REPLACE INTO app_settings VALUES('page_size',?,datetime('now'))",(str(page_size),))
            connection.execute("INSERT INTO audit_events(created_at,action,outcome,detail) VALUES(datetime('now'),'settings.update','success','page_size')")
        return RedirectResponse("/settings?message=Saved",303)

    @app.post("/settings/dns")
    def save_dns_settings(request:Request,csrf:str=Form(...),external_enabled:str=Form("false"),
                          auto_enabled:str=Form("false"),
                          providers:list[str]=Form(default=[]),max_domains:int=Form(25),
                          timeout_seconds:int=Form(4),concurrency:int=Form(8),cache_hours:int=Form(24),return_view:str=Form("settings")):
        require_csrf(request,csrf)
        if any(item not in PROVIDERS for item in providers): raise HTTPException(400,"Unknown provider")
        if max_domains not in {10,25,50,100,250,500} or timeout_seconds not in range(1,11) or concurrency not in {2,4,8,16} or cache_hours not in {0,1,6,24,72,168}:
            raise HTTPException(400,"Invalid DNS limits")
        now=datetime.now(timezone.utc).isoformat()
        with db.transaction() as connection:
            connection.execute("UPDATE threat_providers SET enabled=0,updated_at=?",(now,))
            for provider in providers: connection.execute("UPDATE threat_providers SET enabled=1,updated_at=? WHERE id=?",(now,provider))
            for key,value in (("dns_external_enabled","true" if external_enabled=="true" else "false"),
                              ("dns_auto_enabled","true" if auto_enabled=="true" else "false"),
                              ("dns_max_domains",str(max_domains)),("dns_timeout_seconds",str(timeout_seconds)),
                              ("dns_concurrency",str(concurrency)),("dns_cache_hours",str(cache_hours))):
                connection.execute("INSERT OR REPLACE INTO app_settings VALUES(?,?,?)",(key,value,now))
            connection.execute("INSERT INTO audit_events(created_at,action,outcome,detail) VALUES(?,?,'success',?)",
                               (now,"dns.settings",f"external={external_enabled};providers={len(providers)}"))
        return RedirectResponse(f"/engines/dns?view={'providers' if return_view=='providers' else 'settings'}&message=Réglages+enregistrés",303)

    @app.post("/settings/dns/custom")
    def add_custom_dns(request:Request,csrf:str=Form(...),name:str=Form(...),address:str=Form(...)):
        require_csrf(request,csrf)
        name=name.strip(); address=address.strip()
        if not 1<=len(name)<=80: raise HTTPException(400,"Resolver name must contain 1 to 80 characters")
        try: parsed=ipaddress.ip_address(address)
        except ValueError as exc: raise HTTPException(400,"Resolver address must be an IP address") from exc
        if not parsed.is_global: raise HTTPException(400,"Resolver address must be a public IP address")
        identifier=str(uuid.uuid4()); now=datetime.now(timezone.utc).isoformat()
        try:
            with db.transaction() as connection:
                connection.execute("INSERT INTO custom_dns_resolvers(id,name,address,created_at) VALUES(?,?,?,?)",
                                   (identifier,name,str(parsed),now))
                connection.execute("INSERT INTO audit_events(created_at,action,target,outcome,detail) VALUES(?,?,?,'success',?)",
                                   (now,"dns.custom.add",identifier,str(parsed)))
        except sqlite3.IntegrityError as exc: raise HTTPException(409,"This resolver is already configured") from exc
        return RedirectResponse("/engines/dns?view=settings&message=Résolveur+ajouté",303)

    @app.post("/settings/dns/custom/{resolver_id}/delete")
    def delete_custom_dns(request:Request,resolver_id:str,csrf:str=Form(...)):
        require_csrf(request,csrf)
        try: resolver_id=str(uuid.UUID(resolver_id))
        except ValueError: raise HTTPException(404,"Resolver not found")
        with db.transaction() as connection:
            deleted=connection.execute("DELETE FROM custom_dns_resolvers WHERE id=?",(resolver_id,)).rowcount
            if not deleted: raise HTTPException(404,"Resolver not found")
            connection.execute("INSERT INTO audit_events(created_at,action,target,outcome) VALUES(?,?,?,'success')",
                               (datetime.now(timezone.utc).isoformat(),"dns.custom.delete",resolver_id))
        return RedirectResponse("/engines/dns?view=settings&message=Résolveur+retiré",303)

    @app.post("/sessions/start")
    def start_capture(request:Request,csrf:str=Form(...),url:str=Form(...),mode:str=Form(...),
                      profile:str=Form("desktop"),timeout_seconds:int=Form(90),network_policy:str=Form("fixture"),
                      duration_mode:str=Form("preset"),custom_duration:int=Form(5),duration_unit:str=Form("minutes"),
                      analyze_yara:str=Form("true"),analyze_ioc:str=Form("true"),
                      analyze_dns:str=Form("true"),dns_consent:str=Form("false")):
        require_csrf(request,csrf)
        yara_enabled=analyze_yara=="true"; ioc_enabled=analyze_ioc=="true"; dns_enabled=analyze_dns=="true"
        if duration_mode=="custom":
            multiplier=1 if duration_unit=="seconds" else 60 if duration_unit=="minutes" else 3600 if duration_unit=="hours" else 0
            timeout_seconds=custom_duration*multiplier
        elif duration_mode=="manual" and mode=="interactive":
            timeout_seconds=8*3600  # hard orphan-session guard, despite manual-stop UX
        elif duration_mode!="preset":
            timeout_seconds=0
        if mode not in {"automatic","interactive"} or profile not in {"desktop","mobile"} or not 15<=timeout_seconds<=28800 or network_policy not in {"fixture","internet"}:
            return RedirectResponse("/?error=Invalid+capture+parameters",303)
        try:
            if network_policy=="fixture": validate_scan_url(url,{"http://fixture-server:8000"})
            elif public_capture: validate_public_url(url)
            else: raise ConfigurationError("Public capture is disabled by the administrator")
        except ConfigurationError as exc:
            from urllib.parse import quote_plus
            return RedirectResponse(f"/?error={quote_plus(str(exc))}",303)
        if dns_consent=="true":
            consent_time=datetime.now(timezone.utc).isoformat()
            with db.transaction() as connection:
                for key in ("dns_external_enabled","dns_auto_enabled"):
                    connection.execute("INSERT OR REPLACE INTO app_settings VALUES(?,?,?)",(key,"true",consent_time))
                connection.execute("UPDATE threat_providers SET enabled=1,updated_at=? WHERE capability='supported'",(consent_time,))
                connection.execute("INSERT INTO audit_events(created_at,action,outcome,detail) VALUES(?,?,'success',?)",
                    (consent_time,"dns.consent","launch; supported providers enabled"))
        reconcile_capture_sessions()
        session_id=str(uuid.uuid4()); scan_id=str(uuid.uuid4()); now=datetime.now(timezone.utc).isoformat()
        with db.transaction() as connection:
            active=connection.execute("SELECT id FROM capture_sessions WHERE status IN ('queued','starting','running','finalizing','analyzing')").fetchone()
            if active:
                return RedirectResponse(f"/sessions?error=Controller+busy%3A+session+{active[0]}",303)
            connection.execute("""INSERT INTO capture_sessions(id,scan_id,target_url,mode,profile,status,
              created_at,updated_at,timeout_seconds,network_policy,analyze_yara,analyze_ioc,analyze_dns)
              VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?)""",
              (session_id,scan_id,url,mode,profile,now,now,timeout_seconds,network_policy,
               int(yara_enabled),int(ioc_enabled),int(dns_enabled)))
        try: remote=controller_for(network_policy).start({"session_id":session_id,"scan_id":scan_id,"url":url,"mode":mode,"profile":profile,"timeout_seconds":timeout_seconds,"network_policy":network_policy})
        except ControllerError as exc:
            with db.transaction() as connection: connection.execute("UPDATE capture_sessions SET status='failed',error=? WHERE id=?",(str(exc),session_id))
            from urllib.parse import quote_plus
            return RedirectResponse(f"/sessions?error={quote_plus(str(exc))}",303)
        with db.transaction() as connection:
            connection.execute("UPDATE capture_sessions SET status=?,updated_at=? WHERE id=?",
                               (remote.get("status","queued"),now,session_id))
        return RedirectResponse(f"/sessions?focus={session_id}&message=Session+created",303)

    @app.post("/sessions/{session_id}/stop")
    def stop_capture(request:Request,session_id:str,csrf:str=Form(...)):
        require_csrf(request,csrf)
        try: uuid.UUID(session_id)
        except ValueError: return RedirectResponse("/sessions?error=Invalid+session+identifier",303)
        with db.connect() as connection:
            item=connection.execute("SELECT * FROM capture_sessions WHERE id=?",(session_id,)).fetchone()
        if item is None: return RedirectResponse("/sessions?error=Unknown+session",303)
        if item["status"] not in {"queued","starting","running","finalizing","analyzing"}:
            destination=f"/scans/{item['scan_id']}" if item["status"]=="completed" and item["finalized"] else "/sessions"
            return RedirectResponse(destination,303)
        try: controller_for(item["network_policy"]).stop(session_id)
        except ControllerHTTPError as exc:
            if exc.status==404 and exc.code=="session_unknown":
                reconcile_capture_sessions()
                return RedirectResponse("/sessions?error=Session+interrupted+after+controller+restart",303)
            return RedirectResponse("/sessions?error=Controller+rejected+the+stop+request",303)
        except ControllerUnavailable:
            return RedirectResponse("/sessions?error=Capture+controller+is+unreachable",303)
        return RedirectResponse(f"/sessions?focus={session_id}&message=Stop+requested",303)

    @app.post("/sessions/delete")
    def delete_sessions(request:Request,csrf:str=Form(...),selected:list[str]=Form(default=[])):
        require_csrf(request,csrf)
        identifiers=[]
        for value in selected[:100]:
            try: identifiers.append(str(uuid.UUID(value)))
            except ValueError: continue
        deleted=[]; refused=[]; seen_scans=set()
        terminal={"completed","failed","cancelled","interrupted"}
        with db.connect() as connection:
            rows={row["id"]:dict(row) for row in connection.execute(
                "SELECT id,scan_id,status FROM capture_sessions WHERE id IN ("+
                ",".join("?" for _ in identifiers)+")",identifiers
            )} if identifiers else {}
        for identifier in identifiers:
            row=rows.get(identifier)
            if not row or row["status"] not in terminal or row["scan_id"] in seen_scans:
                refused.append(identifier); continue
            try:
                delete_scan_data(row["scan_id"])
            except (HTTPException,OSError,sqlite3.Error):
                refused.append(identifier); continue
            seen_scans.add(row["scan_id"]); deleted.append(identifier)
        with db.transaction() as connection:
            connection.execute("INSERT INTO audit_events(created_at,action,outcome,detail) VALUES(datetime('now'),'sessions.delete',?,?)",
                               ("success" if not refused else "partial",f"deleted={len(deleted)};refused={len(refused)}"))
        from urllib.parse import quote_plus
        return RedirectResponse("/sessions?message="+quote_plus(
            f"{len(deleted)} investigation(s) supprimée(s) avec leurs preuves; {len(refused)} refusée(s)."),303)

    def display_page(request,session_id,csrf,attempt=0,**values):
        return templates.TemplateResponse(request,"xpra_launch.html",
            {"request":request,"session_id":session_id,"csrf":csrf,"attempt":max(0,min(attempt,5)),**values},
            headers={"Cache-Control":"no-store","Referrer-Policy":"strict-origin"})

    @app.get("/sessions/{session_id}/connect",response_class=HTMLResponse)
    def reconnect_display(request:Request,session_id:str,attempt:int=0):
        session=session_for(request)
        try: session_id=str(uuid.UUID(session_id))
        except ValueError: raise HTTPException(404,"Session introuvable")
        return display_page(request,session_id,session.csrf,attempt,auto_submit=True)

    @app.post("/sessions/{session_id}/xpra-access",response_class=HTMLResponse)
    def xpra_access(request:Request,session_id:str,csrf:str=Form(...),attempt:int=Form(0)):
        require_csrf(request,csrf)
        try: session_id=str(uuid.UUID(session_id))
        except ValueError: raise HTTPException(404,"Session introuvable")
        with db.connect() as connection:
            row=connection.execute("SELECT * FROM capture_sessions WHERE id=?",(session_id,)).fetchone()
        if row is None or row["mode"]!="interactive":
            return display_page(request,session_id,csrf,attempt,error="Cette session interactive n’est plus disponible.",retryable=False)
        if row["status"] not in {"queued","starting","running"}:
            return display_page(request,session_id,csrf,attempt,error="Cette session est terminée. Vous pouvez consulter son investigation ou en démarrer une nouvelle.",retryable=False,scan_id=row["scan_id"])
        if row["status"]!="running":
            return display_page(request,session_id,csrf,attempt,error="Le navigateur démarre. La connexion va reprendre automatiquement.",retryable=True)
        try: access=controller_for(row["network_policy"]).xpra_ticket(session_id)
        except ControllerHTTPError as exc:
            terminal=exc.code=="session_unknown"
            if terminal: reconcile_capture_sessions()
            return display_page(request,session_id,csrf,attempt,
                error="Cette session a été interrompue. Revenez aux sessions pour consulter les preuves disponibles ou démarrer une nouvelle investigation." if terminal else "Le navigateur n’est pas encore prêt. Nouvelle tentative de connexion…",retryable=not terminal)
        except ControllerError:
            return display_page(request,session_id,csrf,attempt,error="Le service du navigateur est momentanément indisponible. Nouvelle tentative de connexion…",retryable=True)
        return display_page(request,session_id,csrf,attempt,gateway=gateway_for(request,row["network_policy"]),ticket=access["ticket"],auto_submit=True)

    @app.get("/sessions",response_class=HTMLResponse)
    def session_page(request:Request,message:str="",error:str="",state:str="",focus:str=""):
        values=sync_capture_sessions()
        focused=False
        if focus:
            try: focus=str(uuid.UUID(focus))
            except ValueError: focus=""
            if focus:
                selected=[item for item in values if item["id"]==focus]
                if selected:
                    values=selected; focused=True
        if state: values=[item for item in values if item["status"]==state]
        return page(request,"sessions.html",active="sessions",capture_sessions=values,message=message,error=error,state=state,
                    focus=focus,focused=focused,public_capture=public_capture)

    @app.get("/system",response_class=HTMLResponse)
    def system_page(request:Request):
        with db.connect() as connection:
            migration=connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
        def installed(distribution:str)->str:
            try: return package_version(distribution)
            except PackageNotFoundError: return "Non disponible"
        components=(
            ("Version ODYSAFE",installed("odysafe-url"),"Version de l’application ODYSAFE-URL actuellement installée."),
            ("Python",os.sys.version.split()[0],"Langage qui fait fonctionner l’application et ses analyses."),
            ("API FastAPI",installed("fastapi"),"Reçoit les demandes de l’interface et renvoie les pages et résultats."),
            ("Serveur Uvicorn",installed("uvicorn"),"Serveur local qui fait fonctionner l’application web ODYSAFE."),
            ("Templates Jinja2",installed("jinja2"),"Construit les pages HTML à partir des données des investigations."),
            ("Interface HTMX","2.0.8","Met à jour certaines parties des pages sans recharger tout l’écran."),
            ("Base SQLite",sqlite3.sqlite_version,"Conserve l’index des scans, les réglages et les données de l’interface."),
            ("Moteur YARA-X",installed("yara-x"),"Teste les fichiers collectés avec les règles de détection actives."),
            ("Arbres HAR har2tree",installed("har2tree"),"Transforme les requêtes web capturées en relations entre URLs et hôtes."),
            ("Client DNS dnspython",installed("dnspython"),"Interroge les filtres DNS autorisés et interprète leurs réponses."),
            ("Version des données",str(migration),"Version de la structure utilisée pour enregistrer les données ODYSAFE."),
        )
        return page(request,"system.html",active="system",components=components,
                    behavior=read_json(PROJECT_ROOT/"rules"/"behavior"/"rules.json"))

    @app.post("/system/reset")
    def reset_local_data(request:Request,csrf:str=Form(...),confirm:str=Form(...)):
        """Return the local application data to its initial state.

        This is intentionally unavailable while a capture is active. Scan
        directories are staged before the database transaction so a database
        error can restore every directory instead of leaving a partial reset.
        """
        require_csrf(request,csrf)
        if confirm.strip() != "EFFACER ODYSAFE":
            raise HTTPException(400,"Saisissez EFFACER ODYSAFE pour confirmer.")
        # Read the shipped sources before touching user data. Seeding below
        # shares the deletion transaction, so either both succeed or neither does.
        builtin_sources=rules._builtins()
        staged=[]
        try:
            with db.transaction() as connection:
                # BEGIN IMMEDIATE serializes this check with capture/job writes.
                active=connection.execute("""SELECT count(*) FROM capture_sessions
                    WHERE status IN ('queued','starting','running','finalizing','analyzing')
                       OR (status='completed' AND finalized=0)""").fetchone()[0]
                jobs=connection.execute("""SELECT count(*) FROM enrichment_jobs
                    WHERE status IN ('queued','running','starting')""").fetchone()[0]
                if active or jobs:
                    raise HTTPException(409,"Terminez les captures et les analyses en cours avant de réinitialiser ODYSAFE.")
                for child in scan_path.iterdir():
                    if child.is_symlink() or not child.is_dir():
                        continue
                    try: parsed=uuid.UUID(child.name)
                    except ValueError: continue
                    if str(parsed)!=child.name: continue
                    target=scan_path/f".reset-{child.name}-{secrets.token_hex(5)}"
                    child.rename(target)
                    staged.append((child,target))
                # Keep app_settings, threat_providers and custom_dns_resolvers:
                # consent, limits, provider selection and preferences are config.
                for table in ("ioc_matches","dns_results","enrichment_jobs","capture_sessions",
                              "hidden_scans","scans","scan_index_state","manual_iocs","yara_rule_versions",
                              "yara_rules","engine_folders","audit_events"):
                    connection.execute(f"DELETE FROM {table}")
                for engine in ("yara","ioc"):
                    connection.execute("""INSERT INTO engine_folders(id,engine,name,is_default)
                        VALUES(?,?,'Défaut',1)""",(f"default-{engine}",engine))
                rules.seed_builtins(connection=connection,sources=builtin_sources)
        except Exception:
            for original,temporary in reversed(staged):
                if temporary.exists() and not original.exists(): temporary.rename(original)
            raise
        for _,temporary in staged:
            shutil.rmtree(temporary)
        return RedirectResponse("/system?message=ODYSAFE+réinitialisé",303)

    return app


app = create_app()
