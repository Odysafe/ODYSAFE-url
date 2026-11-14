from __future__ import annotations

from app.config import configured_origins, validate_scan_url


def validate_worker_url(url: str) -> str:
    """Validate a worker target against the process-wide exact-origin allowlist."""
    return validate_scan_url(url, configured_origins())
