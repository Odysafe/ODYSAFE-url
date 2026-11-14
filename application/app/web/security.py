from __future__ import annotations

import secrets
import time
import threading
from dataclasses import dataclass
from urllib.parse import urlsplit


class OriginPolicyError(ValueError):
    pass


def normalize_local_origin(value: str) -> str:
    """Return a canonical, explicit loopback origin or reject it."""
    if not value or value == "null" or "*" in value:
        raise OriginPolicyError("Origin must be an explicit local origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise OriginPolicyError("Malformed origin") from exc
    if (parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost"}
            or port is None or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment
            or parsed.netloc != f"{parsed.hostname}:{port}"):
        raise OriginPolicyError("Origin must be an explicit HTTP(S) loopback origin")
    return f"{parsed.scheme}://{parsed.hostname}:{port}"


def configured_origins(raw: str) -> frozenset[str]:
    values = [item.strip() for item in raw.split(",") if item.strip()]
    if not values:
        raise OriginPolicyError("At least one web origin is required")
    return frozenset(normalize_local_origin(item) for item in values)


def origin_is_allowed(value: str | None, allowed: frozenset[str]) -> bool:
    if value is None:
        return False
    try:
        return normalize_local_origin(value) in allowed
    except OriginPolicyError:
        return False


@dataclass
class Session:
    csrf: str
    expires: float


class SessionStore:
    def __init__(self, ttl: int = 3600, max_sessions: int = 4096):
        self.ttl = ttl
        self.max_sessions = max(1, max_sessions)
        self.values: dict[str, Session] = {}
        self._lock = threading.RLock()
        self._last_prune = 0.0

    def create(self) -> tuple[str, Session]:
        current = time.time()
        with self._lock:
            if current-self._last_prune >= 60 or len(self.values)>=self.max_sessions:
                for token in [token for token,value in self.values.items() if value.expires<current]:
                    self.values.pop(token,None)
                self._last_prune=current
            while len(self.values)>=self.max_sessions:
                self.values.pop(next(iter(self.values)))
            token = secrets.token_urlsafe(32)
            value = Session(secrets.token_urlsafe(32), current+self.ttl)
            self.values[token] = value
            return token,value

    def get(self, token: str | None) -> Session | None:
        with self._lock:
            value = self.values.get(token or "")
            if not value or value.expires < time.time():
                if token: self.values.pop(token, None)
                return None
            return value
