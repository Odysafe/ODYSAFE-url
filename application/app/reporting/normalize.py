from __future__ import annotations

from typing import Any


def json_safe(value: Any) -> Any:
    """Normalize supported values without evaluating or stringifying objects."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, set):
        return [json_safe(item) for item in sorted(value, key=str)]
    raise TypeError(f"Unsupported report value: {type(value).__name__}")
