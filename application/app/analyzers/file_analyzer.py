from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 10 * 1024 * 1024


def _content_type(prefix: bytes, size: int) -> str:
    if size == 0:
        return "application/x-empty"
    signatures = [(b"%PDF-", "application/pdf"), (b"\x89PNG\r\n\x1a\n", "image/png"),
                  (b"PK\x03\x04", "application/zip"), (b"\x7fELF", "application/x-elf"),
                  (b"MZ", "application/x-dosexec")]
    for signature, mime in signatures:
        if prefix.startswith(signature):
            return mime
    try:
        prefix.decode("utf-8")
        if b"\x00" not in prefix:
            return "text/plain"
    except UnicodeDecodeError:
        pass
    return "application/octet-stream"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def analyze_downloads(directory: Path, max_file_bytes: int = MAX_FILE_BYTES) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    if directory.is_symlink():
        return {"status": "error", "files": [], "warnings": [],
                "errors": ["Symbolic link refused: downloads"]}
    if not directory.exists():
        return {"status": "not_performed", "files": [], "warnings": ["downloads directory missing"],
                "errors": []}
    if not directory.is_dir():
        return {"status": "error", "files": [], "warnings": [],
                "errors": ["downloads is not a directory"]}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        relative = f"downloads/{path.name}"
        if path.is_symlink():
            errors.append(f"Symbolic link refused: {relative}")
            files.append({"path": relative, "status": "error", "error": "symbolic_link"})
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > max_file_bytes:
            warnings.append(f"File exceeds analysis limit: {relative}")
            files.append({"path": relative, "status": "skipped_size", "size": size,
                          "sha256": None, "content_type": None})
            continue
        with path.open("rb") as stream:
            prefix = stream.read(8192)
        files.append({"path": relative, "status": "analyzed", "size": size,
                      "sha256": _hash_file(path), "content_type": _content_type(prefix, size)})
    status = "partial" if warnings or errors else "completed"
    return {"status": status, "files": files, "warnings": warnings, "errors": errors}
