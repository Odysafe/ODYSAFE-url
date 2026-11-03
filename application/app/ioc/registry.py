from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from app.database import Database

IOC_TYPES = {"domain", "hostname", "url", "ipv4", "ipv6", "cidr4", "cidr6", "sha256"}
CATEGORIES = {"malware", "phishing", "C2", "suspicious", "unwanted", "unknown"}
MAX_VALUE = 4096


class IOCValidationError(ValueError):
    pass


def normalize_hostname(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or len(value) > 253 or "/" in value or ":" in value or "@" in value:
        raise IOCValidationError("Invalid hostname")
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise IOCValidationError("Invalid IDNA hostname") from exc
    labels = normalized.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
           for label in labels):
        raise IOCValidationError("Invalid hostname")
    return normalized


def normalize_ioc(ioc_type: str, value: str) -> str:
    if ioc_type not in IOC_TYPES:
        raise IOCValidationError("Unsupported IOC type")
    value = value.strip()
    if not value or len(value) > MAX_VALUE:
        raise IOCValidationError("IOC value is empty or too large")
    if ioc_type in {"domain", "hostname"}:
        if "*" in value:
            if not value.startswith("*.") or "*" in value[2:]:
                raise IOCValidationError("Use a leading *. followed by a domain, for example *.ru")
            suffix = normalize_hostname(value[2:])
            if len(suffix) > 251:
                raise IOCValidationError("Invalid hostname pattern")
            return "*." + suffix
        return normalize_hostname(value)
    if ioc_type == "url":
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise IOCValidationError("Invalid URL") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise IOCValidationError("URL must be HTTP(S) without credentials")
        host = normalize_hostname(parsed.hostname)
        default = (parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)
        netloc = host if port is None or default else f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, parsed.fragment))
    if ioc_type == "ipv4" and "*" in value:
        parts = value.split(".")
        if len(parts) != 4 or all(part == "*" for part in parts):
            raise IOCValidationError("Use four octets with at least one fixed number, for example 8.*.8.8")
        for part in parts:
            if part != "*" and (not re.fullmatch(r"0|[1-9][0-9]{0,2}", part) or int(part) > 255):
                raise IOCValidationError("Each IPv4 octet must be * or a number from 0 to 255")
        return value
    if ioc_type in {"ipv4", "ipv6"}:
        address = ipaddress.ip_address(value)
        if (ioc_type == "ipv4") != (address.version == 4):
            raise IOCValidationError("IP version does not match IOC type")
        return str(address)
    if ioc_type in {"cidr4", "cidr6"}:
        network = ipaddress.ip_network(value, strict=False)
        if (ioc_type == "cidr4") != (network.version == 4):
            raise IOCValidationError("CIDR version does not match IOC type")
        return str(network)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise IOCValidationError("SHA-256 must contain exactly 64 hexadecimal characters")
    return value.lower()


class IOCRegistry:
    def __init__(self, database: Database):
        self.database = database

    def save(self, ioc_type: str, value: str, category: str = "unknown", comment: str = "",
             source: str = "user", expires_at: str | None = None, ioc_id: str | None = None) -> str:
        normalized = normalize_ioc(ioc_type, value)
        if category not in CATEGORIES:
            raise IOCValidationError("Invalid category")
        if len(comment) > 2000 or len(source) > 200:
            raise IOCValidationError("IOC metadata is too large")
        if expires_at:
            try: datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except ValueError as exc: raise IOCValidationError("Invalid expiration date") from exc
        now = datetime.now(timezone.utc).isoformat(); identifier = ioc_id or str(uuid.uuid4())
        with self.database.transaction() as connection:
            current = connection.execute("SELECT * FROM manual_iocs WHERE id=?", (identifier,)).fetchone()
            collision = connection.execute(
                "SELECT id FROM manual_iocs WHERE type=? AND normalized_value=? AND id<>?",
                (ioc_type, normalized, identifier)).fetchone()
            if collision: raise IOCValidationError("IOC already exists")
            if current:
                connection.execute("""UPDATE manual_iocs SET type=?,original_value=?,normalized_value=?,
                    category=?,comment=?,declared_source=?,expires_at=?,version=version+1,updated_at=? WHERE id=?""",
                    (ioc_type, value.strip(), normalized, category, comment, source, expires_at, now, identifier))
            else:
                connection.execute("""INSERT INTO manual_iocs
                    (id,type,original_value,normalized_value,category,comment,declared_source,
                     created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (identifier, ioc_type, value.strip(), normalized, category, comment, source, now, now, expires_at))
            connection.execute("INSERT INTO audit_events(created_at,action,target,outcome,detail) VALUES(?,?,?,?,?)",
                               (now, "ioc.save", identifier, "success", ioc_type))
        return identifier

    def set_state(self, ioc_id: str, action: str) -> None:
        if action not in {"activate", "disable", "archive"}: raise IOCValidationError("Invalid IOC action")
        now = datetime.now(timezone.utc).isoformat()
        values = {"activate": (1, 0), "disable": (0, 0), "archive": (0, 1)}[action]
        with self.database.transaction() as connection:
            if not connection.execute("SELECT 1 FROM manual_iocs WHERE id=?", (ioc_id,)).fetchone():
                raise IOCValidationError("IOC not found")
            connection.execute("UPDATE manual_iocs SET active=?,archived=?,version=version+1,updated_at=? WHERE id=?",
                               (*values, now, ioc_id))
            connection.execute("INSERT INTO audit_events(created_at,action,target,outcome) VALUES(?,?,?,'success')",
                               (now, f"ioc.{action}", ioc_id))

    def get(self, ioc_id: str) -> dict[str, Any] | None:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM manual_iocs WHERE id=?", (ioc_id,)).fetchone()
            return dict(row) if row else None

    def list(self, query: str = "", state: str = "all", ioc_type: str = "") -> list[dict[str, Any]]:
        where = ["(original_value LIKE ? OR normalized_value LIKE ? OR comment LIKE ?)"]
        needle = f"%{query[:200]}%"; params: list[Any] = [needle, needle, needle]
        if state == "active": where.append("active=1 AND archived=0")
        elif state == "inactive": where.append("active=0 AND archived=0")
        elif state == "archived": where.append("archived=1")
        if ioc_type in IOC_TYPES: where.append("type=?"); params.append(ioc_type)
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(
                f"SELECT * FROM manual_iocs WHERE {' AND '.join(where)} ORDER BY updated_at DESC LIMIT 500", params)]
