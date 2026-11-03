"""Bounded local SQLite backups. No network and no deletion of investigations."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import time

DATABASE=Path(os.environ.get('ODYSAFE_DB_PATH','/database/odysafe.db'))
BACKUPS=Path(os.environ.get('ODYSAFE_BACKUP_DIR','/backups'))
BACKUP_NAME=re.compile(r'database-\d{8}T\d{6}Z\.sqlite3')


def snapshots():
    return sorted(path for path in BACKUPS.glob('database-*.sqlite3') if BACKUP_NAME.fullmatch(path.name) and path.is_file() and not path.is_symlink())


def _backup_database():
    if DATABASE.is_symlink() or not DATABASE.is_file():raise RuntimeError('Database is not available')
    if BACKUPS.is_symlink():raise RuntimeError('Backup directory must not be a symbolic link')
    BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
    if shutil.disk_usage(BACKUPS).free<DATABASE.stat().st_size+64*1024*1024:
        raise RuntimeError('Not enough free space for a database snapshot')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    destination=BACKUPS/f'database-{stamp}.sqlite3';temporary=BACKUPS/f'.database-{stamp}.tmp'
    if destination.exists():return destination
    temporary.unlink(missing_ok=True);deadline=time.monotonic()+120
    try:
        with sqlite3.connect(f'file:{DATABASE}?mode=ro',uri=True,timeout=10) as source:
            with sqlite3.connect(temporary) as target:
                def progress(*_):
                    if time.monotonic()>deadline:raise TimeoutError('Database backup exceeded 120 seconds')
                source.backup(target,pages=128,progress=progress,sleep=.1)
                if target.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('Database snapshot integrity check failed')
                target.execute('PRAGMA journal_mode=DELETE')
        os.chmod(temporary,0o600)
        with temporary.open('rb') as stream:os.fsync(stream.fileno())
        temporary.replace(destination)
        digest=hashlib.sha256()
        with destination.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
        manifest=destination.with_suffix('.json')
        manifest.write_text(json.dumps({'file':destination.name,'sha256':digest.hexdigest(),'created_utc':stamp,'scope':'SQLite only; evidence files need a separate backup'},indent=2)+'\n')
        os.chmod(manifest,0o600)
        for old in snapshots()[:-14]:
            old.unlink();old.with_suffix('.json').unlink(missing_ok=True)
        print('SQLite snapshot saved:',destination.name,flush=True)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def backup_database():
    if BACKUPS.is_symlink():raise RuntimeError('Backup directory must not be symbolic')
    BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
    descriptor=os.open(BACKUPS/'.backup.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        for stale in BACKUPS.glob('.database-*.tmp'):
            if re.fullmatch(r'\.database-\d{8}T\d{6}Z\.tmp',stale.name):stale.unlink(missing_ok=True)
        return _backup_database()


def healthy():
    files=snapshots()
    return bool(files and time.time()-files[-1].stat().st_mtime<172800)


def main():
    if '--check' in sys.argv:raise SystemExit(0 if healthy() else 1)
    if '--once' in sys.argv:backup_database();return
    while True:
        try:
            if not healthy() or time.time()-snapshots()[-1].stat().st_mtime>=86400:
                backup_database()
            delay=3600
        except Exception as exc:
            print(f'SQLite backup failed: {type(exc).__name__}: {exc}',file=sys.stderr,flush=True)
            delay=60
        time.sleep(delay)


if __name__=='__main__':main()
