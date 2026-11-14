from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_EVENTS = 1000
MAX_PREVIEW_CHARS = 256
MAX_EVENT_BYTES = 16 * 1024
HOOKS = [
    "clipboard.writeText", "eval", "document.write", "document.writeln", "navigation",
    "localStorage.setItem", "localStorage.removeItem", "localStorage.clear",
    "sessionStorage.setItem", "sessionStorage.removeItem", "sessionStorage.clear",
    "popup", "download",
]
JS_EVENT_TYPES = set(HOOKS) - {"popup", "download"}
ESSENTIAL_JS_HOOKS = {
    "clipboard.writeText", "eval", "document.write", "document.writeln",
    "localStorage.setItem", "sessionStorage.setItem",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_PREVIEW_CHARS]
    raise ValueError("event detail values must be scalar")


class BrowserInstrumentation:
    """Collect bounded events delivered by a Playwright browser context."""

    def __init__(self, enabled: bool, *, max_events: int = MAX_EVENTS) -> None:
        self.enabled = enabled
        self.max_events = max(1, min(int(max_events), MAX_EVENTS))
        self.events: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.status = "not_enabled" if not enabled else "failed"
        self.installed_hooks: list[str] = []
        self._frame_urls: dict[int, str] = {}

    async def install(self, context: Any) -> None:
        if not self.enabled:
            return
        try:
            script_path = Path(__file__).parent / "js" / "hooks.js"
            script = script_path.read_text(encoding="utf-8")
            await context.expose_binding("__odysafeRecordEvent", self._receive_event)
            await context.add_init_script(script=script)
            self.status = "partial"
        except Exception as exc:
            self.errors.append(f"Instrumentation installation failed: {type(exc).__name__}: {exc}")
            self.status = "failed"

    def attach_page(self, page: Any) -> None:
        if not self.enabled or self.status == "failed":
            return
        try:
            page.on("popup", self._receive_popup)
            page.on("framenavigated", self._receive_navigation)
            self.installed_hooks.extend(("popup", "navigation"))
            self.installed_hooks = sorted(set(self.installed_hooks))
        except Exception as exc:
            self.warnings.append(f"Popup listener unavailable: {type(exc).__name__}: {exc}")
            self.status = "partial"

    def _receive_navigation(self, frame: Any) -> None:
        try:
            destination = getattr(frame, "url", None); key=id(frame); initial=self._frame_urls.get(key)
            self._frame_urls[key] = destination
            self._append("navigation", _utc_now(), destination, {
                "initial_url": initial, "destination_url": destination,
                "frame": "main" if getattr(frame, "parent_frame", None) is None else "child",
                "mechanism": "unknown"
            })
        except Exception:
            self._warn("Navigation listener unavailable")

    async def _receive_event(self, source: dict[str, Any], payload: Any) -> None:
        if not isinstance(payload, dict):
            self._warn("Malformed browser event ignored")
            return
        try:
            if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > MAX_EVENT_BYTES:
                self._warn("Oversized browser event ignored")
                return
        except (TypeError, ValueError):
            self._warn("Non-serializable browser event ignored")
            return
        event_type = payload.get("type")
        details = payload.get("details", {})
        if event_type == "__odysafe.ready" and isinstance(details, dict):
            hooks = details.get("hooks")
            if isinstance(hooks, list) and all(isinstance(item, str) for item in hooks):
                self.installed_hooks = sorted(set(self.installed_hooks) | (set(hooks) & JS_EVENT_TYPES))
                if ESSENTIAL_JS_HOOKS <= set(self.installed_hooks):
                    self.status = "completed"
            return
        if event_type == "__odysafe.hook_error" and isinstance(details, dict):
            hook = details.get("hook")
            self._warn(f"Browser hook unavailable: {hook}" if isinstance(hook, str)
                       else "Browser hook unavailable")
            return
        if event_type not in JS_EVENT_TYPES or not isinstance(details, dict):
            self._warn("Malformed browser event ignored")
            return
        frame = source.get("frame") if isinstance(source, dict) else None
        source_url = getattr(frame, "url", None)
        try:
            clean_details = {str(key)[:80]: _bounded(value) for key, value in details.items()}
        except ValueError:
            self._warn("Malformed browser event details ignored")
            return
        self._append(event_type, payload.get("timestamp"), source_url or payload.get("url"), clean_details)

    async def _receive_popup(self, popup: Any) -> None:
        parent_url = None
        try:
            parent = await popup.opener()
            parent_url = getattr(parent, "url", None)
        except Exception:
            self._warn("Popup parent page unavailable")
        self._append("popup", _utc_now(), getattr(popup, "url", None),
                     {"state": "opened", "parent_url": parent_url})
        self.attach_page(popup)

    def record_download(self, filename: str, content: bytes, *, source_url: str | None = None,
                        stored_name: str | None = None) -> None:
        if not self.enabled or self.status == "failed":
            return
        self.installed_hooks.append("download")
        self.installed_hooks = sorted(set(self.installed_hooks))
        self._append("download", _utc_now(), None, {
            "suggested_filename": filename[:MAX_PREVIEW_CHARS],
            "size": len(content), "sha256": hashlib.sha256(content).hexdigest(),
            "source_url": source_url, "stored_name": stored_name,
        })

    def _append(self, event_type: str, timestamp: Any, url: Any, details: dict[str, Any]) -> None:
        if len(self.events) >= self.max_events:
            self._warn(f"Event limit reached ({self.max_events})")
            return
        self.events.append({
            "id": len(self.events) + 1,
            "type": event_type,
            "timestamp": timestamp if isinstance(timestamp, str) else None,
            "url": url if isinstance(url, str) else None,
            "details": details,
        })

    def _warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)
        if self.status == "completed":
            self.status = "partial"

    def artifact(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "instrumentation": {
                "enabled": self.enabled,
                "status": self.status,
                "hooks": sorted(set(self.installed_hooks)),
                "limitations": [
                    "Hooks are detectable by page scripts.",
                    "Direct eval lexical semantics may differ because eval is wrapped.",
                    "Playwright binding delivery expressions are excluded from eval events.",
                    "Workers, WebAssembly, new Function, and uninstrumented mutations are not covered.",
                    "Popup URLs are recorded at the instant Playwright emits the popup event.",
                ] if self.enabled else [],
            },
            "events": self.events,
            "warnings": self.warnings,
            "errors": self.errors,
        }

    def write(self, path: Path) -> None:
        payload = json.dumps(self.artifact(), ensure_ascii=False, indent=2) + "\n"
        descriptor, temporary = tempfile.mkstemp(prefix=".events-", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
