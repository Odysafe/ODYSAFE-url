from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class ControllerError(RuntimeError):
    pass


class ControllerHTTPError(ControllerError):
    def __init__(self, status: int, code: str, message: str, payload: dict[str, Any] | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.payload = payload or {}


class ControllerUnavailable(ControllerError):
    pass


class ControllerClient:
    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = (base_url or os.environ.get("ODYSAFE_CONTROLLER_URL", "http://capture-controller:8765")).rstrip("/")
        self.token = token or os.environ.get("ODYSAFE_CONTROLLER_TOKEN", "")

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base_url + path, data=body, method=method,
            headers={"Content-Type": "application/json", "X-ODYSAFE-Token": self.token})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                value = json.load(response)
                if not isinstance(value, dict): raise ControllerError("Invalid controller response")
                return value
        except urllib.error.HTTPError as exc:
            try:
                value = json.loads(exc.read().decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                value = {}
            code = value.get("error", "controller_http_error") if isinstance(value, dict) else "controller_http_error"
            message = value.get("message", str(exc)) if isinstance(value, dict) else str(exc)
            raise ControllerHTTPError(exc.code, str(code), str(message), value if isinstance(value, dict) else {}) from exc
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise ControllerUnavailable(f"Capture controller unavailable: {exc}") from exc

    def start(self, payload: dict[str, Any]) -> dict[str, Any]: return self.request("POST", "/v1/sessions", payload)
    def status(self, session_id: str) -> dict[str, Any]: return self.request("GET", f"/v1/sessions/{session_id}")
    def stop(self, session_id: str) -> dict[str, Any]: return self.request("POST", f"/v1/sessions/{session_id}/stop", {})
    def xpra_ticket(self, session_id: str) -> dict[str, Any]:
        return self.request("POST", f"/v1/sessions/{session_id}/xpra-ticket", {})
