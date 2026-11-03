from __future__ import annotations

import html
import http.client
import json
import os
import secrets
import selectors
import socket
import ssl
import threading
import time
import uuid
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit, urlencode

LISTEN = ("0.0.0.0", int(os.environ.get("GATEWAY_LISTEN_PORT", "14500")))
TARGET = (os.environ.get("GATEWAY_TARGET_HOST", "browser-interactive"),
          int(os.environ.get("GATEWAY_TARGET_PORT", "14500")))
AUTH_TARGET = (os.environ.get("GATEWAY_AUTH_HOST", TARGET[0]),
               int(os.environ.get("GATEWAY_AUTH_PORT", "8765")))
PUBLIC_PORT = int(os.environ.get("GATEWAY_PUBLIC_PORT", "14500"))
ALLOWED_ORIGINS = frozenset(filter(None, os.environ.get(
    "GATEWAY_WEB_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080").split(",")))
ALLOWED_HOSTS = {f"127.0.0.1:{PUBLIC_PORT}", f"localhost:{PUBLIC_PORT}"}
CONSOLE_URL = os.environ.get("GATEWAY_CONSOLE_URL", "http://127.0.0.1:8080/sessions")
ACCESS: dict[str, tuple[float, dict[str, str]]] = {}
ACCESS_LOCK = threading.Lock()
TLS_ENABLED = os.environ.get("GATEWAY_TLS_ENABLED", "false").lower() == "true"
TLS_CERTIFICATE = os.environ.get("GATEWAY_TLS_CERTIFICATE", "/certificates/odysafe.crt")
TLS_PRIVATE_KEY = os.environ.get("GATEWAY_TLS_PRIVATE_KEY", "/certificates/odysafe.key")
TLS_CONTEXT: ssl.SSLContext | None = None


def response(client: socket.socket, status: str, body: bytes, headers: dict[str, str] | None = None) -> None:
    values = {"Content-Type": "text/plain; charset=utf-8", "Content-Length": str(len(body)),
              "Cache-Control": "no-store", "Connection": "close", **(headers or {})}
    head = f"HTTP/1.1 {status}\r\n" + "".join(f"{key}: {value}\r\n" for key, value in values.items()) + "\r\n"
    client.sendall(head.encode("ascii") + body)


def redeem(ticket: str) -> dict[str, str] | None:
    connection = http.client.HTTPConnection(*AUTH_TARGET, timeout=5)
    try:
        payload = json.dumps({"ticket": ticket}).encode()
        connection.request("POST", "/v1/xpra/redeem", payload,
                           {"Content-Type": "application/json", "Content-Length": str(len(payload))})
        result = connection.getresponse()
        data = json.loads(result.read()) if result.status == 200 else {}
        if (result.status == 200 and data.get("username") == "odysafe" and
                isinstance(data.get("password"), str)):
            return data
        return None
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    finally:
        connection.close()


def target_ready() -> bool:
    try:
        connection = socket.create_connection(TARGET, timeout=1)
        connection.close()
        return True
    except OSError:
        return False


def wait_target_ready(timeout: float = 3.0, interval: float = 0.1) -> bool:
    """Wait briefly for Xpra without consuming the redeemed authorization."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if target_ready():
            return True
        time.sleep(interval)
    return target_ready()


def recovery_url(headers: dict[str,str], session_id: str = "", attempt: int = 0) -> str:
    configured=urlsplit(CONSOLE_URL)
    host=headers.get("host","").split(":",1)[0]
    if host not in {"127.0.0.1","localhost"}: host="127.0.0.1"
    port=configured.port or (443 if configured.scheme=="https" else 80)
    origin=f"{configured.scheme}://{host}:{port}"
    try: identifier=str(uuid.UUID(session_id))
    except ValueError: return origin+"/sessions"
    return origin+f"/sessions/{identifier}/connect?attempt={min(max(attempt,0),5)}"


def waiting_response(client: socket.socket, status: str, message: str, destination: str,
                     automatic: bool = False) -> None:
    escaped=html.escape(destination,quote=True)
    refresh=f'<meta http-equiv="refresh" content="2;url={escaped}">' if automatic else ""
    body=("<!doctype html><html lang=fr><head><meta charset=utf-8>"
          "<meta name=viewport content='width=device-width,initial-scale=1'>"
          f"<title>Connexion au navigateur</title>{refresh}</head><body>"
          f"<h1>Connexion au navigateur</h1><p role=status>{html.escape(message)}</p>"
          f"<a href='{escaped}'>Reconnecter à Chromium</a></body></html>").encode()
    response(client,status,body,{"Content-Type":"text/html; charset=utf-8",
        "Content-Security-Policy":"default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "Referrer-Policy":"no-referrer","X-Content-Type-Options":"nosniff"})


def expired_response(client: socket.socket, headers: dict[str,str] | None = None,
                     session_id: str = "", attempt: int = 0) -> None:
    destination=recovery_url(headers or {},session_id,attempt+1)
    waiting_response(client,"403 Forbidden","La connexion va être renouvelée pour cette session." if session_id else
        "Revenez à votre session pour ouvrir le navigateur avec une nouvelle autorisation.",
        destination,bool(session_id) and attempt<5)


def ticket_connect(client: socket.socket, method: str, headers: dict[str, str], body: bytes) -> None:
    if method != "POST":
        return response(client, "405 Method Not Allowed", b"Method not allowed")
    if headers.get("origin") not in ALLOWED_ORIGINS or headers.get("host") not in ALLOWED_HOSTS:
        return response(client, "403 Forbidden", b"Access refused")
    try:
        values = parse_qs(body.decode("ascii"), strict_parsing=True)
        ticket = values["ticket"][0]
        navigation=values.get("navigation",[""])[0]=="1"
        session_id=values.get("session_id",[""])[0]
        attempt=max(0,min(int(values.get("attempt",["0"])[0]),5))
    except (UnicodeError, ValueError, KeyError, IndexError):
        return response(client, "400 Bad Request", b"Invalid request")
    credentials = redeem(ticket)
    if credentials is None:
        if navigation: return expired_response(client,headers,session_id,attempt)
        return response(client, "403 Forbidden", b"Ticket expired or already used")
    access=secrets.token_urlsafe(32)
    with ACCESS_LOCK:
        now=time.time()
        for key in [key for key,(expiry,_) in ACCESS.items() if expiry<now]: ACCESS.pop(key,None)
        if len(ACCESS)>=8: ACCESS.pop(min(ACCESS,key=lambda key:ACCESS[key][0]),None)
        ACCESS[access]=(now+20,credentials)
    response(client,"303 See Other" if navigation else "204 No Content",b"",{
        **({"Location":"/odysafe-bootstrap?"+urlencode({"session":credentials.get("session_id",session_id),"attempt":attempt})} if navigation else {}),
        "Access-Control-Allow-Origin":headers["origin"],"Access-Control-Allow-Credentials":"true",
        "Vary":"Origin","Set-Cookie":f"odysafe_xpra={access}; HttpOnly; Secure; SameSite=Strict; Path=/odysafe-bootstrap; Max-Age=20",
    })


def bootstrap(client: socket.socket, method: str, headers: dict[str, str], query: str = "") -> None:
    if method != "GET" or headers.get("host") not in ALLOWED_HOSTS:
        return response(client,"403 Forbidden",b"Access refused")
    values=parse_qs(query)
    session_id=values.get("session",[""])[0]
    try: attempt=max(0,min(int(values.get("attempt",["0"])[0]),5))
    except ValueError: attempt=5
    cookie=SimpleCookie(); cookie.load(headers.get("cookie",""))
    access=cookie.get("odysafe_xpra"); credentials=None
    if access:
        with ACCESS_LOCK:
            stored=ACCESS.get(access.value)
        if stored and stored[0]>=time.time(): credentials=stored[1]
    if credentials is None:
        if access:
            with ACCESS_LOCK: ACCESS.pop(access.value,None)
        return expired_response(client,headers,session_id,attempt)
    if not wait_target_ready():
        # The ticket has already been consumed, but the short-lived gateway
        # authorization remains valid. A refresh can therefore finish the
        # connection without minting a new scan or reusing the ticket.
        return waiting_response(client,"503 Service Unavailable",
            "Chromium démarre. Cette page reprendra la connexion automatiquement.",
            "/odysafe-bootstrap?"+urlencode({"session":session_id,"attempt":attempt}),True)
    nonce = secrets.token_urlsafe(18)
    settings = json.dumps({"username": "odysafe", "password": credentials["password"]}).replace("<", "\\u003c")
    deadline=json.dumps(float(credentials.get("expires_at") or 0) * 1000)
    reconnect=json.dumps(recovery_url(headers,credentials.get("session_id",session_id))).replace("<","\\u003c")
    page = ("<!doctype html><meta charset=utf-8><title>Chromium</title>"
            f"<script nonce='{html.escape(nonce)}'>sessionStorage.setItem('',{json.dumps(settings)});"
            f"sessionStorage.setItem('odysafe-reconnect-url',{reconnect});"
            f"sessionStorage.setItem('odysafe-session-deadline',{deadline});"
            "location.replace('/');</script>").encode()
    response(client, "200 OK", page, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": f"default-src 'none'; script-src 'nonce-{nonce}'; base-uri 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
    })


def relay_streams(client: socket.socket, upstream: socket.socket) -> None:
    """Relay TLS/WebSocket traffic without dropping partial nonblocking writes."""
    peers = {client: upstream, upstream: client}
    buffers = {client: bytearray(), upstream: bytearray()}
    writes: dict[socket.socket, bytes | None] = {client: None, upstream: None}
    reading = {client, upstream}
    read_wants_write = {client: False, upstream: False}
    write_wants_read = {client: False, upstream: False}
    limit = 2 * 1024 * 1024
    for stream in peers:
        stream.setblocking(False)
    with selectors.DefaultSelector() as selector:
        registered = set()
        while True:
            pending = {}
            for stream, peer in peers.items():
                can_read = stream in reading and len(buffers[peer]) < limit
                events = 0
                if can_read or (buffers[stream] and write_wants_read[stream]):
                    events |= selectors.EVENT_READ
                if (buffers[stream] and not write_wants_read[stream]) or (can_read and read_wants_write[stream]):
                    events |= selectors.EVENT_WRITE
                if events:
                    if stream in registered:
                        selector.modify(stream, events)
                    else:
                        selector.register(stream, events); registered.add(stream)
                elif stream in registered:
                    selector.unregister(stream); registered.remove(stream)
                if can_read and isinstance(stream, ssl.SSLSocket) and stream.pending():
                    pending[stream] = selectors.EVENT_READ
            for key, mask in selector.select(timeout=0 if pending else 1):
                pending[key.fileobj] = pending.get(key.fileobj, 0) | mask
            for stream, mask in pending.items():
                peer = peers[stream]
                if buffers[stream] and (mask & selectors.EVENT_WRITE or
                                        write_wants_read[stream] and mask & selectors.EVENT_READ):
                    try:
                        # OpenSSL requires the same bytes on a WANT_READ/WRITE retry.
                        if writes[stream] is None:
                            writes[stream] = bytes(buffers[stream][:65536])
                        sent = stream.send(writes[stream])
                        if not sent:
                            return
                        del buffers[stream][:sent]
                        writes[stream] = writes[stream][sent:] or None
                        write_wants_read[stream] = False
                    except ssl.SSLWantReadError:
                        write_wants_read[stream] = True
                    except (ssl.SSLWantWriteError, BlockingIOError):
                        write_wants_read[stream] = False
                if stream in reading and len(buffers[peer]) < limit and (
                    mask & selectors.EVENT_READ or read_wants_write[stream] and mask & selectors.EVENT_WRITE
                ):
                    try:
                        chunk = stream.recv(min(65536, limit - len(buffers[peer])))
                        read_wants_write[stream] = False
                        if chunk:
                            buffers[peer].extend(chunk)
                        else:
                            reading.discard(stream)
                    except ssl.SSLWantWriteError:
                        read_wants_write[stream] = True
                    except (ssl.SSLWantReadError, BlockingIOError):
                        read_wants_write[stream] = False
            # Flush the final bytes before closing a stream that reached EOF.
            if any(stream not in reading and not buffers[peer] for stream, peer in peers.items()):
                return


def relay(client: socket.socket) -> None:
    upstream = None
    try:
        client.settimeout(5); initial = b""
        while b"\r\n\r\n" not in initial and len(initial) <= 65536:
            chunk = client.recv(8192)
            if not chunk: return
            initial += chunk
        if b"\r\n\r\n" not in initial:
            return response(client, "431 Request Header Fields Too Large", b"Headers too large")
        raw_head, body = initial.split(b"\r\n\r\n", 1)
        lines = raw_head.decode("iso-8859-1").split("\r\n"); request_line = lines[0].split(" ")
        if len(request_line) != 3: return response(client, "400 Bad Request", b"Invalid request")
        method, path, _ = request_line
        headers = {key.strip().lower(): value.strip() for key, value in
                   (line.split(":", 1) for line in lines[1:] if ":" in line)}
        length = int(headers.get("content-length", "0"))
        if length > 4096: return response(client, "413 Content Too Large", b"Request too large")
        while len(body) < length: body += client.recv(length-len(body))
        if path == "/odysafe-connect":
            ticket_connect(client, method, headers, body[:length]); return
        if urlsplit(path).path == "/odysafe-bootstrap":
            bootstrap(client,method,headers,urlsplit(path).query); return
        upstream = socket.create_connection(TARGET, timeout=5)
        upstream.sendall(raw_head + b"\r\n\r\n" + body)
        relay_streams(client, upstream)
    except (OSError, ValueError):
        return
    finally:
        if upstream: upstream.close()
        client.close()


def serve_connection(connection: socket.socket) -> None:
    if TLS_CONTEXT is None:
        relay(connection)
        return
    try:
        connection.settimeout(5)
        secured = TLS_CONTEXT.wrap_socket(connection, server_side=True)
    except (OSError, ssl.SSLError):
        connection.close()
        return
    relay(secured)


def monitor_certificate() -> None:
    """Swap TLS contexts only for new connections; existing Xpra stays open."""
    previous=None
    while True:
        try:
            signature=tuple((os.stat(path).st_mtime_ns,os.stat(path).st_size) for path in (TLS_CERTIFICATE,TLS_PRIVATE_KEY))
            if signature!=previous:
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version=ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(TLS_CERTIFICATE,TLS_PRIVATE_KEY)
                global TLS_CONTEXT
                TLS_CONTEXT=context
                previous=signature
        except (OSError,ssl.SSLError):
            # Keep the previously loaded certificate while a replacement is
            # unavailable. A later iteration retries without dropping sockets.
            pass
        time.sleep(60)


def main() -> None:
    global TLS_CONTEXT
    if TLS_ENABLED:
        TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        TLS_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2
        TLS_CONTEXT.load_cert_chain(TLS_CERTIFICATE, TLS_PRIVATE_KEY)
        threading.Thread(target=monitor_certificate,daemon=True).start()
    with socket.create_server(LISTEN, reuse_port=False) as server:
        while True:
            connection, _ = server.accept()
            threading.Thread(target=serve_connection, args=(connection,), daemon=True).start()


if __name__ == "__main__": main()
