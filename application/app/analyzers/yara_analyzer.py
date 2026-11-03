from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
from importlib.metadata import version
from urllib.parse import urlsplit

MAX_SCAN_BYTES = 10 * 1024 * 1024
MAX_MATCHES_PER_PATTERN = 20
SCAN_TIMEOUT_SECONDS = 5


class YaraAnalysisError(RuntimeError):
    pass


def compile_rules(rules_dir: Path, extra_sources: list[tuple[str, str]] | None = None,
                  *, selected_sources: list[tuple[str, str]] | None = None) -> tuple[Any, list[str]]:
    import yara_x

    if rules_dir.is_symlink() or not rules_dir.is_dir():
        raise YaraAnalysisError("YARA rules directory is unavailable or symbolic")
    paths = [] if selected_sources is not None else sorted(rules_dir.glob("*.yar"))
    if not paths and selected_sources is None:
        raise YaraAnalysisError("No YARA rules found")
    compiler = yara_x.Compiler(includes_enabled=False)
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise YaraAnalysisError(f"Invalid YARA rule file: {path.name}")
        try:
            compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path))
        except (OSError, UnicodeError, yara_x.CompileError) as exc:
            raise YaraAnalysisError(f"Unable to compile {path.name}: {exc}") from exc
    for origin, source in (selected_sources if selected_sources is not None else (extra_sources or [])):
        try:
            compiler.add_source(source, origin=origin)
        except (UnicodeError, yara_x.CompileError) as exc:
            raise YaraAnalysisError(f"Unable to compile {origin}: {exc}") from exc
    try:
        return compiler.build(), [str(item) for item in compiler.warnings()]
    except yara_x.CompileError as exc:
        raise YaraAnalysisError(f"Unable to build YARA rules: {exc}") from exc


def _matches(scanner: Any, path: Path, artifact: str) -> list[dict[str, Any]]:
    import yara_x

    if path.is_symlink() or not path.is_file():
        raise YaraAnalysisError(f"Scan source unavailable or symbolic: {artifact}")
    if path.stat().st_size > MAX_SCAN_BYTES:
        raise YaraAnalysisError(f"Scan source exceeds size limit: {artifact}")
    try:
        results = scanner.scan_file(str(path))
    except (yara_x.ScanError, yara_x.TimeoutError, OSError) as exc:
        raise YaraAnalysisError(f"YARA scan failed for {artifact}: {exc}") from exc
    matches = []
    for rule in results.matching_rules:
        occurrences = []
        for pattern in rule.patterns:
            for match in pattern.matches:
                occurrences.append({"pattern": pattern.identifier, "offset": match.offset,
                                    "length": match.length})
        metadata = {str(key): value for key, value in rule.metadata}
        matches.append({"engine": "yara_x", "rule_id": rule.identifier,
                        "category": str(metadata.get("category", "signature_match")),
                        "severity": str(metadata.get("severity", "info")),
                        "confidence": str(metadata.get("confidence", "medium")),
                        "title": rule.identifier.replace("_", " ").title(),
                        "description": str(metadata.get("description", "Local YARA-X rule matched.")),
                        "evidence": [{"artifact": artifact}], "matches": occurrences,
                        "metadata": metadata, "namespace": rule.namespace,
                        "tags": list(rule.tags)})
    return matches


def analyze_with_yara(scan_dir: Path, rules_dir: Path,
                      file_analysis: dict[str, Any],
                      extra_sources: list[tuple[str, str]] | None = None,
                      observed_domains: list[str] | None = None,
                      selected_sources: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    try:
        rules, warnings = compile_rules(rules_dir, extra_sources, selected_sources=selected_sources)
    except YaraAnalysisError as exc:
        return {"status": "error", "detections": [], "warnings": [], "errors": [str(exc)]}
    try:
        import yara_x
        scanner = yara_x.Scanner(rules)
        scanner.set_timeout(SCAN_TIMEOUT_SECONDS)
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
    except Exception as exc:
        return {"status": "error", "detections": [], "warnings": [],
                "errors": [f"Unable to initialize YARA-X scanner: {type(exc).__name__}: {exc}"]}
    detections: list[dict[str, Any]] = []
    errors: list[str] = []
    skipped = False
    sources: list[tuple[Path, str, str | None]] = []
    def hostname(value: Any) -> str | None:
        try: return urlsplit(str(value)).hostname
        except ValueError: return None
    meta: dict[str, Any] = {}
    try: meta = json.loads((scan_dir / "meta.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError): pass
    dom = scan_dir / "dom.html"
    if dom.exists() or dom.is_symlink():
        sources.append((dom, "dom.html", hostname(meta.get("final_url") or meta.get("submitted_url"))))
    download_urls: dict[str, str] = {}
    try:
        records=json.loads((scan_dir/"downloads.json").read_text(encoding="utf-8"))
        download_urls={f"downloads/{item.get('stored_name')}":str(item.get("source_url") or "")
                       for item in records if isinstance(item,dict) and item.get("stored_name")}
    except (OSError,UnicodeError,json.JSONDecodeError,TypeError): pass
    for item in file_analysis.get("files", []):
        if item.get("status") == "analyzed":
            sources.append((scan_dir / item["path"], item["path"], hostname(download_urls.get(item["path"]))))
        elif item.get("status") == "skipped_size":
            skipped = True
    manifest=scan_dir/"scripts"/"manifest.json"
    try:
        scripts=json.loads(manifest.read_text(encoding="utf-8"))
        for item in scripts:
            if not isinstance(item,dict) or not item.get("path"): continue
            path=scan_dir/str(item["path"])
            if path.resolve().parent != (scan_dir/"scripts").resolve(): continue
            sources.append((path,str(item["path"]),hostname(item.get("url"))))
    except (OSError,UnicodeError,json.JSONDecodeError,TypeError): pass
    artifact_results=[]
    for path, artifact, domain in sources:
        try:
            findings=_matches(scanner, path, artifact); detections.extend(findings)
            artifact_results.append({"artifact":artifact,"domain":domain,"status":"scanned",
                                     "matches":len(findings)})
        except YaraAnalysisError as exc:
            errors.append(str(exc))
            artifact_results.append({"artifact":artifact,"domain":domain,"status":"error",
                                     "matches":0,"error":str(exc)})
    status = "error" if errors and not sources else ("partial" if errors or skipped else "completed")
    digest = hashlib.sha256()
    for path in ([] if selected_sources is not None else sorted(rules_dir.glob("*.yar"))):
        digest.update(path.name.encode()); digest.update(path.read_bytes())
    effective_extra = selected_sources if selected_sources is not None else (extra_sources or [])
    for origin, source in effective_extra:
        digest.update(origin.encode()); digest.update(source.encode())
    builtin_rule_count = 0
    for path in ([] if selected_sources is not None else sorted(rules_dir.glob("*.yar"))):
        try:
            builtin_rule_count += len(__import__("re").findall(
                r"(?m)^\s*(?:private\s+|global\s+)?rule\s+[A-Za-z_]\w*",
                path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError):
            pass
    custom_rule_count = sum(len(__import__("re").findall(
        r"(?m)^\s*(?:private\s+|global\s+)?rule\s+[A-Za-z_]\w*", source))
        for _, source in effective_extra)
    coverage=[]
    for domain in sorted(set(observed_domains or []) | {item["domain"] for item in artifact_results if item["domain"]}):
        related=[item for item in artifact_results if item["domain"]==domain]
        scanned=sum(item["status"]=="scanned" for item in related)
        coverage.append({"domain":domain,"status":"scanned" if scanned else "no_compatible_artifact",
                         "artifacts_scanned":scanned,"artifacts_available":len(related),
                         "matches":sum(item["matches"] for item in related)})
    return {"status": status, "detections": detections, "warnings": warnings, "errors": errors,
            "rule_set": {"sha256": digest.hexdigest(), "custom_rules": len(effective_extra),
                         "active_rules": builtin_rule_count + custom_rule_count,
                         "engine_version": version("yara-x")},
            "execution": {"artifacts_scanned": len(sources) - len(errors),
                          "artifacts_attempted": len(sources),
                          "files_skipped": sum(item.get("status") != "analyzed"
                                               for item in file_analysis.get("files", [])),
                          "matches": len(detections),"artifacts":artifact_results,
                          "domain_coverage":coverage}}
