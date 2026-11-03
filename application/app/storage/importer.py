from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import stat
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


class ScanImportError(RuntimeError):
    pass


@dataclass(frozen=True)
class ImportItem:
    scan_id: str
    status: str
    reason: str


def _canonical_uuid(name: str) -> str | None:
    try:
        value = uuid.UUID(name)
    except ValueError:
        return None
    return str(value) if str(value) == name else None


def _inventory(root: Path) -> list[tuple[Path, bool]]:
    """Return safe relative paths and their directory flag without following links."""
    inventory: list[tuple[Path, bool]] = []

    def walk(directory: Path, relative: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                child_relative = relative / entry.name
                if entry.is_symlink():
                    raise ScanImportError(f"symbolic link refused: {child_relative}")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    inventory.append((child_relative, True))
                    walk(Path(entry.path), child_relative)
                elif stat.S_ISREG(metadata.st_mode):
                    inventory.append((child_relative, False))
                else:
                    raise ScanImportError(f"special file refused: {child_relative}")

    walk(root, Path())
    if not any(path == Path("network.har") and not is_dir for path, is_dir in inventory):
        raise ScanImportError("required regular file network.har is missing")
    return inventory


def _copy_file(source: Path, destination: Path) -> str:
    digest = hashlib.sha256()
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ScanImportError(f"source changed type during copy: {source.name}")
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            while chunk := os.read(source_fd, 1024 * 1024):
                pending = memoryview(chunk)
                while pending:
                    written = os.write(destination_fd, pending)
                    if written == 0:
                        raise OSError("short write while copying scan")
                    pending = pending[written:]
                digest.update(chunk)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        after = os.fstat(source_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ScanImportError(f"source changed during copy: {source.name}")
    finally:
        os.close(source_fd)
    return digest.hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _set_tree_access(root: Path, uid: int, gid: int) -> None:
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        os.chmod(directory_path, 0o700, follow_symlinks=False)
        os.chown(directory_path, uid, gid, follow_symlinks=False)
        for name in [*names, *files]:
            path = directory_path / name
            if path.is_symlink():
                raise ScanImportError(f"symbolic link appeared during copy: {path.name}")
            os.chmod(path, 0o700 if path.is_dir() else 0o600, follow_symlinks=False)
            os.chown(path, uid, gid, follow_symlinks=False)


def permission_issues(root: Path, uid: int, gid: int) -> list[str]:
    issues: list[str] = []
    for directory, names, files in os.walk(root, followlinks=False):
        for path in [Path(directory), *(Path(directory) / name for name in [*names, *files])]:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                issues.append(f"symlink:{path.relative_to(root)}")
            elif (metadata.st_uid, metadata.st_gid) != (uid, gid):
                issues.append(f"owner:{path.relative_to(root)}")
            elif path.is_dir() and metadata.st_mode & stat.S_IRWXU != stat.S_IRWXU:
                issues.append(f"mode:{path.relative_to(root)}")
            elif path.is_file() and metadata.st_mode & (stat.S_IRUSR | stat.S_IWUSR) != (
                    stat.S_IRUSR | stat.S_IWUSR):
                issues.append(f"mode:{path.relative_to(root)}")
    return issues


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ScanImportError("atomic no-replace rename is unavailable")
    result = renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(destination)
        raise OSError(error, os.strerror(error), destination)


def import_scans(source_root: Path, target_root: Path, uid: int, gid: int,
                 *, repair_existing: bool = False) -> dict[str, object]:
    source_root = source_root.absolute()
    target_root = target_root.absolute()
    if source_root.is_symlink() or not source_root.is_dir():
        raise ScanImportError("source root must be a real directory")
    if target_root.is_symlink():
        raise ScanImportError("target root must not be a symbolic link")
    target_root.mkdir(parents=True, exist_ok=True)
    source_resolved = source_root.resolve(strict=True)
    target_resolved = target_root.resolve(strict=True)
    if source_resolved == target_resolved or source_resolved in target_resolved.parents \
            or target_resolved in source_resolved.parents:
        raise ScanImportError("source and target roots must not overlap")
    results: list[ImportItem] = []

    for entry in sorted(os.scandir(source_root), key=lambda item: item.name):
        scan_id = _canonical_uuid(entry.name)
        if scan_id is None:
            results.append(ImportItem(entry.name, "skipped", "name is not a canonical UUID"))
            continue
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            results.append(ImportItem(scan_id, "failed", "scan path is not a real directory"))
            continue
        destination = target_root / scan_id
        if destination.exists() or destination.is_symlink():
            reason = "destination already exists; content was not replaced"
            if repair_existing and destination.is_dir() and not destination.is_symlink():
                try:
                    _inventory(destination)
                    _set_tree_access(destination, uid, gid)
                    issues = permission_issues(destination, uid, gid)
                    if issues:
                        raise ScanImportError(f"permission verification failed: {issues[0]}")
                    reason += "; ownership and owner access repaired"
                except (OSError, ScanImportError) as exc:
                    results.append(ImportItem(scan_id, "failed", f"existing scan repair failed: {exc}"))
                    continue
            results.append(ImportItem(scan_id, "skipped", reason))
            continue

        staging = target_root / f".import-{scan_id}-{uuid.uuid4().hex}"
        try:
            inventory = _inventory(Path(entry.path))
            staging.mkdir(mode=0o700)
            hashes: dict[Path, str] = {}
            for relative, is_directory in inventory:
                output = staging / relative
                if is_directory:
                    output.mkdir(mode=0o700)
                else:
                    hashes[relative] = _copy_file(Path(entry.path) / relative, output)
            for relative, expected in hashes.items():
                if _sha256(staging / relative) != expected:
                    raise ScanImportError(f"copy verification failed: {relative}")
            _set_tree_access(staging, uid, gid)
            issues = permission_issues(staging, uid, gid)
            if issues:
                raise ScanImportError(f"permission verification failed: {issues[0]}")
            _rename_noreplace(staging, destination)
            results.append(ImportItem(scan_id, "imported", "verified and published atomically"))
        except FileExistsError:
            results.append(ImportItem(scan_id, "skipped", "destination appeared during import; content was not replaced"))
        except (OSError, ScanImportError) as exc:
            results.append(ImportItem(scan_id, "failed", str(exc)))
        finally:
            if staging.exists():
                import shutil
                shutil.rmtree(staging)

    counts = {status: sum(item.status == status for item in results)
              for status in ("imported", "skipped", "failed")}
    return {"source": str(source_root), "target": str(target_root), "uid": uid, "gid": gid,
            "counts": counts, "items": [asdict(item) for item in results]}
