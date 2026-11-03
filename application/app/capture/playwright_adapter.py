from __future__ import annotations

import json
import asyncio
import re
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import origin, validate_profile, validate_public_url, validate_scan_url
from app.capture.instrumentation import BrowserInstrumentation


class CaptureError(RuntimeError):
    """The capture failed or produced incomplete mandatory artifacts."""


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _safe_filename(name: str | None) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name or "download.bin").name)
    return cleaned[:180] or "download.bin"


MAX_CAPTURED_DOWNLOAD = 25 * 1024 * 1024
MAX_CAPTURED_DOWNLOADS = 20
MAX_CAPTURED_SCRIPTS = 100
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
NON_FATAL_CAPTURE_MESSAGES = {"Unable to get the storage (timeout)."}


def _classify_capture_messages(value: Any) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    for message in str(value or "").splitlines():
        message = message.strip()
        if not message:
            continue
        (warnings if message in NON_FATAL_CAPTURE_MESSAGES else failures).append(message)
    return failures, warnings


async def capture(url: str, out_dir: Path, profile: dict[str, Any]) -> dict[str, Any]:
    """Capture one allowlisted URL and persist the stage-1 artifacts."""
    profile = validate_profile(profile)
    allowed_origins = set(profile.get("_allowed_origins", [])) or None
    network_policy = str(profile.get("_network_policy", "fixture"))
    if network_policy == "internet":
        validate_public_url(url)
    else:
        validate_scan_url(url, allowed_origins)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    downloads_dir = out_dir / "downloads"
    downloads_dir.mkdir(exist_ok=True)
    scan_id = str(profile.get("_scan_id", out_dir.name))
    profile_name = str(profile.get("_profile_name", "unknown"))
    started = datetime.now(timezone.utc)
    started_clock = time.perf_counter()
    errors: list[str] = []
    warnings: list[str] = []
    result: dict[str, Any] = {}
    title = ""
    actual_user_agent = ""
    instrumentation_config = profile.get("instrumentation", {"enabled": False})
    instrumentation = BrowserInstrumentation(instrumentation_config["enabled"])
    download_tasks: list[asyncio.Task[Any]] = []
    script_tasks: list[asyncio.Task[Any]] = []
    download_records: list[dict[str, Any]] = []
    script_records: list[dict[str, Any]] = []
    finalization_placeholder = False

    try:
        from lookyloo_models import CaptureSettings, ViewportSettings
        from playwrightcapture import Capture

        settings = CaptureSettings(
            url=url,
            browser=profile["browser"],
            user_agent=profile["user_agent"],
            viewport=ViewportSettings.model_validate(profile["viewport"]),
            locale=profile["locale"],
            timezone_id=profile["timezone"],
            referer=profile["referer"],
            general_timeout_in_sec=max(15, profile["timeout_ms"] // 1000),
            final_wait=max(0, profile["wait_after_load_ms"] // 1000),
            headless=profile["headless"],
            with_screenshot=True,
            with_favicon=False,
            with_video=False,
            allow_tracking=False,
            java_script_enabled=True,
            depth=0,
            proxy=profile.get("_proxy"),
            remote_headfull=bool(profile.get("_remote_headfull", False)),
        )
        async with Capture(capture_settings=settings, uuid=scan_id,
                           only_global_lookup=False) as engine:
            await engine.initialize_context()

            async def enforce_allowlist(route: Any, request: Any) -> None:
                try:
                    permitted = origin(request.url) in (allowed_origins or set())
                except Exception:
                    permitted = False
                if permitted:
                    await route.continue_()
                else:
                    await route.abort("blockedbyclient")

            if network_policy == "fixture":
                effective_origins = allowed_origins or {origin(url)}
                allowed_origins = effective_origins
                await engine.context.route("**/*", enforce_allowlist)
            page = await engine.setup_page_capture()
            actual_user_agent = await page.evaluate("navigator.userAgent")
            await instrumentation.install(engine.context)
            instrumentation.attach_page(page)

            async def collect_download(download: Any) -> None:
                if len(download_records) >= MAX_CAPTURED_DOWNLOADS:
                    return
                name = _safe_filename(getattr(download, "suggested_filename", None))
                try:
                    source_url = getattr(download, "url", None)
                    temporary = await download.path()
                    if not temporary:
                        raise OSError("download has no local path")
                    source = Path(temporary)
                    size = source.stat().st_size
                    if size > MAX_CAPTURED_DOWNLOAD:
                        download_records.append({"original_name": name, "source_url": source_url,
                            "status": "too_large", "size": size})
                        return
                    digest = hashlib.sha256(source.read_bytes()).hexdigest()
                    stored = f"{len(download_records)+1:03d}-{digest[:12]}-{name}"
                    destination = downloads_dir / stored
                    await download.save_as(destination)
                    download_records.append({"original_name": name, "stored_name": stored,
                        "source_url": source_url, "status": "collected", "size": size,
                        "sha256": digest})
                    instrumentation.record_download(name, destination.read_bytes(), source_url=source_url,
                                                    stored_name=stored)
                except Exception as exc:
                    download_records.append({"original_name": name, "source_url": getattr(download, "url", None),
                                             "status": "unavailable", "error": type(exc).__name__})

            async def collect_script(response: Any) -> None:
                if len(script_records) >= MAX_CAPTURED_SCRIPTS:
                    return
                try:
                    content_type = str((await response.header_value("content-type")) or "").lower()
                    request = response.request
                    if request.resource_type != "script" and "javascript" not in content_type:
                        return
                    body = await response.body(); size = len(body); truncated = size > MAX_SCRIPT_BYTES
                    original = body[:MAX_SCRIPT_BYTES]
                    digest = hashlib.sha256(body).hexdigest()
                    scripts = out_dir / "scripts"; scripts.mkdir(exist_ok=True)
                    name = f"{len(script_records)+1:03d}-{digest[:16]}.js"
                    (scripts / name).write_bytes(original)
                    script_records.append({"url": response.url, "path": f"scripts/{name}",
                        "size": size, "stored_size": len(original), "sha256": digest,
                        "mime_type": content_type.split(";", 1)[0] or None, "truncated": truncated})
                except Exception:
                    return

            page.on("download", lambda item: download_tasks.append(asyncio.create_task(collect_download(item))))
            page.on("response", lambda item: script_tasks.append(asyncio.create_task(collect_script(item))))
            await engine.open_page(page, url=url, referer=profile["referer"])
            if finish_file := profile.get("_interactive_finish_file"):
                deadline = float(profile.get("_interactive_deadline", time.monotonic() + int(profile.get("_interactive_timeout_sec", 300))))
                while not Path(finish_file).is_file() and time.monotonic() < deadline:
                    # Closing the last Chromium window is an explicit end of
                    # the interactive work, not a reason to leave Xpra on an
                    # empty desktop until the session timeout.
                    if page.is_closed() and not [candidate for candidate in engine.context.pages
                                                 if not candidate.is_closed()]:
                        break
                    await asyncio.sleep(0.25)
            # An investigator may close the tab that initiated the session.
            # Finalize from the most recently surviving page instead of losing
            # the whole capture; popup/navigation events preserve the history.
            if page.is_closed():
                surviving = [candidate for candidate in engine.context.pages if not candidate.is_closed()]
                if not surviving:
                    page = await engine.context.new_page()
                    await page.set_content("<!doctype html><title>ODYSAFE finalization</title><p>All observed pages were closed by the operator before finalization.</p>")
                    finalization_placeholder = True
                else:
                    page = surviving[-1]
            if profile["wait_after_load_ms"]:
                await page.wait_for_timeout(profile["wait_after_load_ms"])
            title = await page.title()
            result = await engine.capture_page(
                page=page, current_page_only=True,
                max_depth_capture_time=max(15, profile["timeout_ms"] // 1000),
            )
            if download_tasks or script_tasks:
                await asyncio.gather(*download_tasks, *script_tasks, return_exceptions=True)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    if result.get("error"):
        capture_errors, capture_warnings = _classify_capture_messages(result["error"])
        errors.extend(capture_errors)
        warnings.extend(capture_warnings)
    if isinstance(result.get("har"), dict):
        _write_json(out_dir / "network.har", result["har"])
    if isinstance(result.get("html"), str) and result["html"]:
        (out_dir / "dom.html").write_text(result["html"], encoding="utf-8")
    if isinstance(result.get("png"), bytes) and result["png"].startswith(b"\x89PNG\r\n\x1a\n"):
        (out_dir / "screenshot.png").write_bytes(result["png"])
    if isinstance(result.get("cookies"), list):
        _write_json(out_dir / "cookies.json", result["cookies"])
    if isinstance(result.get("console_messages"), list):
        _write_json(out_dir / "console.json", result["console_messages"])
    else:
        _write_json(out_dir / "console.json", [])
    if isinstance(result.get("downloaded_file"), bytes) and not download_records:
        filename = _safe_filename(result.get("downloaded_filename"))
        (downloads_dir / filename).write_bytes(result["downloaded_file"])
        instrumentation.record_download(filename, result["downloaded_file"], stored_name=filename)
        download_records.append({"original_name": filename, "stored_name": filename,
            "source_url": None, "status": "collected", "size": len(result["downloaded_file"]),
            "sha256": hashlib.sha256(result["downloaded_file"]).hexdigest()})
    if download_records:
        _write_json(out_dir / "downloads.json", download_records)
    if script_records:
        _write_json(out_dir / "scripts" / "manifest.json", script_records)
    try:
        instrumentation.write(out_dir / "browser_events.json")
    except OSError as exc:
        errors.append(f"Unable to write browser_events.json: {exc}")

    required = ["network.har", "dom.html", "screenshot.png", "cookies.json", "console.json"]
    missing = [name for name in required if not (out_dir / name).is_file()]
    if missing:
        errors.append(f"Missing mandatory artifacts: {', '.join(missing)}")
    har_valid = False
    if (out_dir / "network.har").is_file():
        try:
            har = json.loads((out_dir / "network.har").read_text(encoding="utf-8"))
            har_valid = bool(har.get("log", {}).get("entries"))
        except (OSError, json.JSONDecodeError):
            pass
    if not har_valid:
        errors.append("HAR has no network entries")

    finished = datetime.now(timezone.utc)
    meta = {
        "schema_version": "1.0", "scan_id": scan_id,
        "status": "failed" if errors else "completed",
        "submitted_url": url, "final_url": result.get("last_redirected_url", ""),
        "title": title, "profile": profile_name, "browser": profile["browser"],
        "user_agent": actual_user_agent, "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": round((time.perf_counter() - started_clock) * 1000),
        "errors": list(dict.fromkeys(errors)),
        "warnings": list(dict.fromkeys(warnings)),
        "artifacts": {"har": "network.har", "dom": "dom.html",
                      "screenshot": "screenshot.png", "cookies": "cookies.json",
                      "console": "console.json", "downloads": "downloads/",
                      "browser_events": "browser_events.json"},
        "capture_limits": {
            "ignore_https_errors_forced_by_dependency": True,
            "bypass_csp_forced_by_dependency": True,
            "network_policy": network_policy,
            "egress_proxy": bool(profile.get("_proxy")),
            "finalization_placeholder": finalization_placeholder,
            "private_ephemeral_context": True,
        },
    }
    _write_json(out_dir / "meta.json", meta)
    if errors:
        raise CaptureError("; ".join(meta["errors"]))
    return meta
