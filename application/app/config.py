from __future__ import annotations

import json
import os
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = Path(os.environ.get("ODYSAFE_DATA_DIR", PROJECT_ROOT / "data"))
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "profiles.json"
PRODUCTION_ORIGINS = {"http://127.0.0.1:8000", "http://localhost:8000"}


class ConfigurationError(ValueError):
    """Invalid profile configuration or scan URL."""


def load_profiles(path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to load profiles: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), dict):
        raise ConfigurationError("Configuration must contain a profiles object")
    default = data.get("default_profile")
    if not isinstance(default, str) or default not in data["profiles"]:
        raise ConfigurationError("default_profile must name an existing profile")
    for name, profile in data["profiles"].items():
        validate_profile(profile, name)
    return data


def validate_profile(profile: Any, name: str = "profile") -> dict[str, Any]:
    if not isinstance(profile, dict):
        raise ConfigurationError(f"{name} must be an object")
    required = {
        "browser", "user_agent", "viewport", "locale", "timezone",
        "referer", "timeout_ms", "wait_after_load_ms", "headless",
    }
    missing = required - profile.keys()
    if missing:
        raise ConfigurationError(f"{name} is missing: {', '.join(sorted(missing))}")
    if profile["browser"] not in {"chromium", "firefox", "webkit"}:
        raise ConfigurationError(f"{name}.browser is invalid")
    viewport = profile["viewport"]
    if (not isinstance(viewport, dict)
            or not all(isinstance(viewport.get(k), int) and viewport[k] > 0
                       for k in ("width", "height"))):
        raise ConfigurationError(f"{name}.viewport is invalid")
    if not isinstance(profile["timeout_ms"], int) or profile["timeout_ms"] < 15_000:
        raise ConfigurationError(f"{name}.timeout_ms must be at least 15000")
    if not isinstance(profile["wait_after_load_ms"], int) or profile["wait_after_load_ms"] < 0:
        raise ConfigurationError(f"{name}.wait_after_load_ms must be non-negative")
    if not isinstance(profile["headless"], bool):
        raise ConfigurationError(f"{name}.headless must be boolean")
    instrumentation = profile.get("instrumentation", {"enabled": False})
    if (not isinstance(instrumentation, dict)
            or not isinstance(instrumentation.get("enabled"), bool)):
        raise ConfigurationError(f"{name}.instrumentation.enabled must be boolean")
    return profile


def select_profile(data: dict[str, Any], name: str | None) -> tuple[str, dict[str, Any]]:
    selected = name or data["default_profile"]
    try:
        profile = data["profiles"][selected]
    except KeyError as exc:
        raise ConfigurationError(f"Unknown profile: {selected}") from exc
    return selected, validate_profile(profile, selected)


def origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("Only well-formed HTTP(S) URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("URLs containing credentials are forbidden")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("Invalid URL port") from exc
    default_port = 80 if parsed.scheme == "http" else 443
    return f"{parsed.scheme}://{parsed.hostname.lower()}" + (f":{port}" if port and port != default_port else "")


def validate_scan_url(url: str, allowed_origins: set[str] | None = None) -> str:
    allowed = allowed_origins if allowed_origins is not None else configured_origins()
    if origin(url) not in allowed:
        raise ConfigurationError("URL origin is not allowed for this development stage")
    return url


def validate_public_url(url: str) -> str:
    """Validate public-mode syntax; the egress proxy enforces resolved IPs."""
    parsed = urlsplit(url)
    normalized = origin(url)
    hostname = parsed.hostname or ""
    if parsed.scheme not in {"http", "https"}:
        raise ConfigurationError("Public captures accept only HTTP and HTTPS")
    if parsed.port not in {None, 80, 443}:
        raise ConfigurationError("Public captures accept only ports 80 and 443")
    lowered = hostname.rstrip(".").lower()
    if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal", ".home.arpa")):
        raise ConfigurationError("Local and internal hostnames are forbidden")
    try:
        address = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        if "." not in lowered:
            raise ConfigurationError("Public captures require a qualified hostname")
    else:
        if not address.is_global:
            raise ConfigurationError("Private, local and reserved addresses are forbidden")
    if normalized.startswith("http://") and parsed.port == 443:
        raise ConfigurationError("Invalid HTTP port")
    return url


def configured_origins() -> set[str]:
    """Return the exact origin allowlist configured for this process."""
    raw = os.environ.get("ODYSAFE_ALLOWED_ORIGINS")
    if raw is None:
        return set(PRODUCTION_ORIGINS)
    values = {item.strip() for item in raw.split(",") if item.strip()}
    if not values:
        raise ConfigurationError("ODYSAFE_ALLOWED_ORIGINS must not be empty")
    normalized = {origin(item) for item in values}
    if normalized != values:
        raise ConfigurationError("ODYSAFE_ALLOWED_ORIGINS entries must be normalized origins")
    return normalized
