from __future__ import annotations

import asyncio
import json
import os
import secrets
import hashlib
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.capture import CaptureError, capture
from app.config import (configured_origins, load_profiles, select_profile,
                        validate_public_url, validate_scan_url)
from app.reporting import build_report
from app.sandbox.session import interactive_settings

TOKEN = os.environ.get("ODYSAFE_CONTROLLER_TOKEN", "")
SCANS = Path(os.environ.get("ODYSAFE_DATA_DIR", "/data")) / "scans"
ALLOWED = configured_origins()
LOCK = threading.Lock()
SESSIONS: dict[str, dict[str, Any]] = {}
ACTIVE_STATES = {"queued", "starting", "running", "finalizing", "analyzing"}
PUBLIC_ENABLED = os.environ.get("ODYSAFE_PUBLIC_CAPTURE", "false").lower() == "true"
INTERNET_PROXY = os.environ.get("ODYSAFE_INTERNET_PROXY", "http://internet-proxy:3128")
DEPENDENCY_READY_TIMEOUT = float(os.environ.get("ODYSAFE_NETWORK_READY_TIMEOUT", "8"))


class NetworkDependencyError(RuntimeError):
    """A required endpoint on the controller's isolated network is unavailable."""


def wait_for_tcp_endpoint(host: str, port: int, label: str,
                          timeout: float = DEPENDENCY_READY_TIMEOUT) -> None:
    """Wait briefly for Docker DNS and a TCP listener, preserving the last cause."""
    deadline = time.monotonic() + max(0, timeout)
    last_error = "not ready"
    while True:
        try:
            socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            last_error = f"DNS resolution failed ({exc})"
        else:
            try:
                remaining = max(0.1, deadline - time.monotonic())
                with socket.create_connection((host, port), timeout=min(0.75, remaining)):
                    return
            except OSError as exc:
                last_error = f"TCP connection failed ({exc})"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NetworkDependencyError(
                f"{label} {host}:{port} unavailable after {timeout:g}s: {last_error}"
            )
        time.sleep(min(0.2, remaining))


def wait_for_network_dependency(value: dict[str, Any]) -> None:
    if value["network_policy"] == "fixture":
        target = urlsplit(value["target_url"])
        if not target.hostname:
            raise NetworkDependencyError("Fixture target has no hostname")
        port = target.port or (443 if target.scheme == "https" else 80)
        wait_for_tcp_endpoint(target.hostname, port, "Fixture target")
        return
    proxy = urlsplit(INTERNET_PROXY)
    if proxy.scheme not in {"http", "https"} or not proxy.hostname:
        raise NetworkDependencyError("Internet proxy configuration is invalid")
    wait_for_tcp_endpoint(proxy.hostname, proxy.port or 3128, "Internet proxy")


def now() -> str: return datetime.now(timezone.utc).isoformat()


def public(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {
        "stop_event", "thread", "xpra_process", "xpra_tickets"}}


def reap_dead_sessions() -> None:
    """Never let a dead worker thread retain controller capacity."""
    for value in SESSIONS.values():
        thread = value.get("thread")
        if value.get("status") in ACTIVE_STATES and thread is not None and not thread.is_alive():
            value.update(status="failed", completed_at=now(), updated_at=now(),
                         error="Capture worker stopped without a terminal state")

    # UI history lives in SQLite. Keep only a bounded cache of terminal
    # controller objects; active captures must never be evicted.
    terminal=[key for key,value in SESSIONS.items() if value.get("status") not in ACTIVE_STATES]
    for key in terminal[:-128]:
        SESSIONS.pop(key,None)


def start_xpra(password: str) -> subprocess.Popen:
    env = {**os.environ, "XPRA_PASSWORD": password, "XDG_RUNTIME_DIR": "/run/odysafe"}
    Path("/run/odysafe").mkdir(mode=0o700, parents=True, exist_ok=True)
    command = ["xpra", "seamless", ":100", "--daemon=no", "--attach=no", "--html=on",
        "--bind-tcp=0.0.0.0:14500,auth=env(name=XPRA_PASSWORD)", "--socket-dirs=/run/odysafe",
        "--ssh-upgrade=no", "--start-new-commands=no", "--system-tray=no", "--notifications=no",
        "--file-transfer=no", "--open-files=no", "--open-url=no", "--printing=no", "--clipboard=no",
        "--dbus=no", "--dbus-control=no", "--mdns=no", "--webcam=no", "--audio=no",
        "--speaker=disabled", "--microphone=disabled", "--exit-with-children=no", "--max-size=1920x1080",
        "--dpi=96", "--encoding=rgb", "--auto-refresh-delay=0", "--quality=100", "--min-quality=95"]
    process = subprocess.Popen(command, env=env)
    socket_path = Path("/run/odysafe/xpra/100/socket")
    for _ in range(100):
        if socket_path.exists(): return process
        if process.poll() is not None: break
        time.sleep(.1)
    process.terminate(); raise RuntimeError("Xpra did not become ready")


def issue_xpra_ticket(value: dict[str, Any], current: float | None = None) -> tuple[str, int]:
    timestamp=time.time() if current is None else current
    ticket=secrets.token_urlsafe(32); tickets=value.setdefault("xpra_tickets",{})
    value["xpra_tickets"]={key:expiry for key,expiry in tickets.items() if expiry>=timestamp}
    if len(value["xpra_tickets"])>=4:
        value["xpra_tickets"].pop(min(value["xpra_tickets"],key=value["xpra_tickets"].get),None)
    value["xpra_tickets"][hashlib.sha256(ticket.encode()).hexdigest()]=timestamp+20
    return ticket,20


def redeem_xpra_ticket(ticket: str, current: float | None = None) -> dict[str, str] | None:
    if len(ticket)<32 or len(ticket)>256: return None
    timestamp=time.time() if current is None else current; digest=hashlib.sha256(ticket.encode()).hexdigest()
    for value in SESSIONS.values():
        tickets=value.get("xpra_tickets",{})
        stored=next((item for item in tickets if secrets.compare_digest(item,digest)),None)
        if not stored: continue
        expires=float(tickets.get(stored,0))
        if (value.get("status")!="running" or value.get("mode")!="interactive" or
                not value.get("xpra_ready") or expires<timestamp): return None
        tickets.pop(stored,None)
        return {"username":"odysafe","password":value["xpra_password"],"session_id":value["id"], "expires_at":value.get("expires_at")}
    return None


def expire_interactive_session(value: dict[str, Any]) -> None:
    """End operator access at the deadline while evidence is finalized."""
    with LOCK:
        if value.get("status") != "running":
            return
        value.update(status="finalizing", xpra_ready=False, updated_at=now(), end_reason="timeout")
        value.pop("xpra_tickets", None)
        Path("/run/odysafe/finish").touch()
    # Keep the X server alive for screenshots/HAR, but reject further input
    # and detach clients. The browser is closed by capture finalization.
    for command in (["xpra", "control", ":100", "readonly", "on", "--socket-dirs=/run/odysafe"],
                    ["xpra", "detach", ":100", "--socket-dirs=/run/odysafe"]):
        try:
            subprocess.run(command, timeout=3, check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, env={**os.environ, "XDG_RUNTIME_DIR":"/run/odysafe"})
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"Interactive deadline: {type(exc).__name__}", flush=True)


def close_xpra(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_session(session_id: str) -> None:
    value = SESSIONS[session_id]; scan_dir = SCANS / value["scan_id"]
    xpra = None
    deadline_timer = None
    try:
        value.update(status="starting", started_at=now(), updated_at=now())
        profiles = load_profiles(); _, profile = select_profile(profiles, value["profile"])
        profile = dict(profile, _scan_id=value["scan_id"], _profile_name=value["profile"],
                       _network_policy=value["network_policy"])
        if value["network_policy"] == "fixture":
            profile["_allowed_origins"] = sorted(ALLOWED)
        else:
            profile["_proxy"] = INTERNET_PROXY
        wait_for_network_dependency(value)
        if value["mode"] == "interactive":
            xpra = start_xpra(value["xpra_password"]); value["xpra_process"] = xpra
            os.environ["DISPLAY"] = ":100"; os.environ["ODYSAFE_INTERACTIVE_TIMEOUT"] = str(value["timeout_seconds"])
            finish = Path("/run/odysafe/finish"); finish.unlink(missing_ok=True)
            profile = interactive_settings(profile); value["xpra_ready"] = True
        else:
            profile["timeout_ms"] = value["timeout_seconds"] * 1000
        value.update(status="running", started_at=now(), updated_at=now())
        if value["mode"] == "interactive":
            profile["_interactive_deadline"] = time.monotonic() + value["timeout_seconds"]
            value["expires_at"] = time.time() + value["timeout_seconds"]
            deadline_timer = threading.Timer(value["timeout_seconds"], expire_interactive_session, args=(value,))
            deadline_timer.daemon = True
            deadline_timer.start()
        asyncio.run(capture(value["target_url"], scan_dir, profile))
        if value.get("stop_requested") and value["mode"] != "interactive":
            raise RuntimeError("Capture cancelled by user")
        with LOCK:
            value.update(status="finalizing", xpra_ready=False, updated_at=now())
            value.pop("xpra_tickets", None)
        if deadline_timer:
            deadline_timer.cancel()
            if deadline_timer.is_alive():
                deadline_timer.join(timeout=7)
        if xpra:
            close_xpra(xpra)
            xpra = None
        value.update(status="analyzing", updated_at=now())
        build_report(scan_dir)
        value.update(status="completed", completed_at=now(), updated_at=now())
    except Exception as exc:
        value.update(status="cancelled" if value.get("stop_requested") else "failed",
                     error=f"{type(exc).__name__}: {str(exc)[:1000]}", completed_at=now(), updated_at=now())
    finally:
        if deadline_timer:
            deadline_timer.cancel()
            if deadline_timer.is_alive():
                deadline_timer.join(timeout=7)
        value.update(xpra_ready=False)
        value.pop("xpra_tickets", None)
        if xpra:
            close_xpra(xpra)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_: Any) -> None: return
    def answer(self, status: int, payload: dict[str, Any]) -> None:
        body=json.dumps(payload).encode(); self.send_response(status); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def authorized(self) -> bool:
        return bool(TOKEN) and secrets.compare_digest(self.headers.get("X-ODYSAFE-Token", ""), TOKEN)
    def parts(self) -> list[str]: return [part for part in self.path.split("?")[0].split("/") if part]
    def do_GET(self) -> None:
        if self.path == "/healthz":
            with LOCK: reap_dead_sessions(); active=sum(v["status"] in ACTIVE_STATES for v in SESSIONS.values())
            return self.answer(200,{"status":"ok","active":active,"public_capture":PUBLIC_ENABLED})
        if not self.authorized(): return self.answer(403,{"error":"refused"})
        parts=self.parts()
        if len(parts)==3 and parts[:2]==["v1","sessions"]:
            with LOCK:
                value=SESSIONS.get(parts[2])
                snapshot=public(value) if value is not None else None
            if snapshot is not None: return self.answer(200,snapshot)
        self.answer(404,{"error":"session_unknown","message":"Capture session is unknown"})
    def do_POST(self) -> None:
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length>16384: raise ValueError("request too large")
            payload=json.loads(self.rfile.read(length) or b"{}")
        except (ValueError,json.JSONDecodeError): return self.answer(400,{"error":"invalid request"})
        parts=self.parts()
        if parts==["v1","xpra","redeem"]:
            ticket=str(payload.get("ticket", ""))
            with LOCK:
                credentials=redeem_xpra_ticket(ticket)
            return self.answer(200,credentials) if credentials else self.answer(403,{"error":"invalid_ticket"})
        if not self.authorized(): return self.answer(403,{"error":"refused"})
        if parts==["v1","sessions"]:
            try:
                url=str(payload["url"]); mode=str(payload["mode"]); profile=str(payload["profile"])
                network_policy=str(payload.get("network_policy","fixture"))
                timeout=int(payload["timeout_seconds"]); session_id=str(uuid.UUID(str(payload["session_id"])))
                scan_id=str(uuid.UUID(str(payload["scan_id"])))
                if network_policy == "fixture": validate_scan_url(url, ALLOWED)
                elif network_policy == "internet" and PUBLIC_ENABLED: validate_public_url(url)
                else: raise ValueError
                if mode not in {"automatic","interactive"} or profile not in {"desktop","mobile"} or not 15<=timeout<=28800: raise ValueError
            except (KeyError,ValueError): return self.answer(400,{"error":"invalid capture parameters"})
            with LOCK:
                reap_dead_sessions()
                active=next((v for v in SESSIONS.values() if v["status"] in ACTIVE_STATES),None)
                if active:
                    return self.answer(409,{"error":"capture_active","message":"A capture is already active",
                                            "session_id":active["id"],"scan_id":active["scan_id"]})
                value={"id":session_id,"scan_id":scan_id,"target_url":url,"mode":mode,"profile":profile,
                       "network_policy":network_policy,"timeout_seconds":timeout,"status":"queued","created_at":now(),"updated_at":now(),
                       "error":None,"xpra_ready":False,"xpra_password":secrets.token_urlsafe(18) if mode=="interactive" else None}
                SESSIONS[session_id]=value; thread=threading.Thread(target=run_session,args=(session_id,),daemon=True); value["thread"]=thread; thread.start()
            return self.answer(202,public(value))
        if len(parts)==4 and parts[:2]==["v1","sessions"] and parts[3]=="stop":
            with LOCK:
                value=SESSIONS.get(parts[2])
                if value is None:
                    return self.answer(404,{"error":"session_unknown","message":"Capture session is unknown"})
                if value["status"] not in ACTIVE_STATES:
                    return self.answer(200,public(value))
                value["stop_requested"]=True; value["status"]="finalizing"; value["updated_at"]=now()
                value.pop("xpra_tickets",None)
                Path("/run/odysafe/finish").touch()
                return self.answer(202,public(value))
        if len(parts)==4 and parts[:2]==["v1","sessions"] and parts[3]=="xpra-ticket":
            with LOCK:
                value=SESSIONS.get(parts[2])
                if (value is None or value.get("status")!="running" or
                    value.get("mode")!="interactive" or not value.get("xpra_ready")):
                    return self.answer(409,{"error":"xpra_not_ready","message":"Interactive display is not ready"})
                ticket,expires_in=issue_xpra_ticket(value)
                return self.answer(201,{"ticket":ticket,"expires_in":expires_in})
        self.answer(404,{"error":"route_not_found","message":"Controller route does not exist"})


def main() -> None:
    if not TOKEN: raise SystemExit("ODYSAFE_CONTROLLER_TOKEN is required")
    SCANS.mkdir(parents=True,exist_ok=True)
    # Capture already runs in a worker. Keeping control I/O single-threaded
    # ensures that a stop request still works when Chromium reaches the PID cap.
    HTTPServer(("0.0.0.0",8765),Handler).serve_forever()


if __name__ == "__main__": main()
