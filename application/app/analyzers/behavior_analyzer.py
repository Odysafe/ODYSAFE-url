from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_CONFIDENCES = {"low", "medium", "high"}
ALLOWED_OPERATORS = {"event_present", "event_field_contains_any", "dom_hidden_iframe"}
MAX_RULES_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


class BehaviorAnalysisError(ValueError):
    pass


class _IframeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden: list[dict[str, Any]] = []
        self.index = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "iframe":
            return
        self.index += 1
        values = {key.lower(): (value or "") for key, value in attrs}
        style = values.get("style", "").replace(" ", "").lower()
        hidden = ("hidden" in values or "display:none" in style or "visibility:hidden" in style
                  or values.get("width") == "0" or values.get("height") == "0")
        if hidden:
            self.hidden.append({"element_index": self.index, "src": values.get("src") or None})


def _read_regular(path: Path, limit: int, required: bool = False) -> str | None:
    if path.is_symlink():
        raise BehaviorAnalysisError(f"Symbolic link refused: {path.name}")
    if not path.is_file():
        if required:
            raise BehaviorAnalysisError(f"Missing file: {path.name}")
        return None
    if path.stat().st_size > limit:
        raise BehaviorAnalysisError(f"File exceeds analysis limit: {path.name}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BehaviorAnalysisError(f"Unable to read {path.name}: {exc}") from exc


def load_behavior_rules(path: Path) -> list[dict[str, Any]]:
    raw = _read_regular(path, MAX_RULES_BYTES, required=True)
    try:
        document = json.loads(raw or "")
    except json.JSONDecodeError as exc:
        raise BehaviorAnalysisError(f"Invalid behavior rules JSON: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise BehaviorAnalysisError("Behavior rules must contain a rules array")
    seen: set[str] = set()
    validated = []
    for index, rule in enumerate(document["rules"], 1):
        required = {"id", "version", "description", "category", "severity", "confidence",
                    "active", "source", "condition", "evidence_field"}
        if not isinstance(rule, dict) or not required <= rule.keys():
            raise BehaviorAnalysisError(f"Behavior rule {index} is incomplete")
        if not isinstance(rule["id"], str) or rule["id"] in seen:
            raise BehaviorAnalysisError(f"Behavior rule {index} has a duplicate or invalid id")
        condition = rule["condition"]
        if (rule["severity"] not in ALLOWED_SEVERITIES
                or rule["confidence"] not in ALLOWED_CONFIDENCES
                or not isinstance(condition, dict)
                or condition.get("operator") not in ALLOWED_OPERATORS):
            raise BehaviorAnalysisError(f"Behavior rule {rule['id']} is invalid")
        if condition["operator"] == "event_field_contains_any":
            patterns = condition.get("patterns")
            if (not isinstance(patterns, list) or not patterns or
                    not all(isinstance(item, str) and 0 < len(item) <= 128 for item in patterns)):
                raise BehaviorAnalysisError(f"Behavior rule {rule['id']} has invalid patterns")
        seen.add(rule["id"])
        validated.append(rule)
    return validated


def _finding(rule: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "engine": "behavior", "rule_id": rule["id"], "category": rule["category"],
        "severity": rule["severity"], "confidence": rule["confidence"],
        "title": rule["id"].replace("behavior.", "").replace("_", " ").title(),
        "description": rule["description"], "evidence": [evidence],
    }


def analyze_behavior(scan_dir: Path, rules_path: Path) -> dict[str, Any]:
    """Apply explicit local rules to captured events and DOM evidence."""
    try:
        rules = load_behavior_rules(rules_path)
        events_text = _read_regular(scan_dir / "browser_events.json", MAX_ARTIFACT_BYTES)
        events: list[dict[str, Any]] = []
        if events_text is not None:
            artifact = json.loads(events_text)
            if not isinstance(artifact, dict) or not isinstance(artifact.get("events"), list):
                raise BehaviorAnalysisError("browser_events.json has an invalid structure")
            events = [event for event in artifact["events"] if isinstance(event, dict)]
        dom = _read_regular(scan_dir / "dom.html", MAX_ARTIFACT_BYTES)
        hidden_iframes: list[dict[str, Any]] = []
        if dom is not None:
            parser = _IframeParser()
            parser.feed(dom)
            hidden_iframes = parser.hidden
        detections = []
        for rule in rules:
            if not rule["active"]:
                continue
            condition = rule["condition"]
            operator = condition["operator"]
            if operator == "dom_hidden_iframe":
                detections.extend(_finding(rule, {"artifact": "dom.html", **item})
                                  for item in hidden_iframes)
                continue
            for event in events:
                if event.get("type") != condition.get("event_type"):
                    continue
                matched = operator == "event_present"
                if operator == "event_field_contains_any":
                    details = event.get("details")
                    value = details.get(condition.get("field")) if isinstance(details, dict) else None
                    matched = isinstance(value, str) and any(
                        pattern.casefold() in value.casefold() for pattern in condition["patterns"])
                if matched:
                    detections.append(_finding(rule, {"artifact": "browser_events.json",
                                                       "event_id": event.get("id")}))
        return {"status": "completed", "detections": detections, "warnings": [], "errors": []}
    except (BehaviorAnalysisError, json.JSONDecodeError) as exc:
        return {"status": "error", "detections": [], "warnings": [], "errors": [str(exc)]}
