#!/bin/sh
# Never overwrite an existing populated volume. Sources stay untouched.
set -eu
cd -- "$(dirname -- "$0")/../application"
. ./common.sh
require_docker
require_local_configuration

if [ "$#" -ne 1 ]; then printf '%s\n' 'Usage: ./restore.sh /path/to/backup.tar.gz (run sh start.dh --build-only first)' >&2; exit 2; fi
archive=$1
case "$archive" in /*) ;; *) archive="$(pwd)/$archive";; esac
[ -f "$archive" ] || exit 2
if [ -n "$(compose ps --status running -q)" ]; then
    printf '%s\n' 'Stop ODYSAFE before restoring a backup. No files were changed.' >&2; exit 2
fi
docker image inspect odysafe-source-app:0.1.0 >/dev/null
for name in database scans certificates backups; do
    case "$name" in database) volume=odysafe-distribution-db;; scans) volume=odysafe-distribution-scans;; certificates) volume=odysafe-distribution-certificates;; backups) volume=odysafe-distribution-backups;; esac
    if ! docker volume inspect "$volume" >/dev/null 2>&1; then
        docker volume create --label com.docker.compose.project=odysafe-distribution --label "com.docker.compose.volume=$name" "$volume" >/dev/null
    fi
done
docker run --rm --network none --read-only --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE \
  --mount "type=bind,source=$archive,target=/backup.tar.gz,readonly" \
  --mount type=volume,source=odysafe-distribution-db,target=/restore/database \
  --mount type=volume,source=odysafe-distribution-scans,target=/restore/scans \
  --mount type=volume,source=odysafe-distribution-certificates,target=/restore/certificates \
  --mount type=volume,source=odysafe-distribution-backups,target=/restore/backups \
  --entrypoint python odysafe-source-app:0.1.0 -c '
from pathlib import Path
import tarfile, os, sqlite3
root=Path("/restore")
for name in ("database","scans","certificates","backups"):
    entries=list((root/name).iterdir())
    # Docker may initialize the empty /data/scans directory from the image.
    if name=="scans" and entries==[root/name/"scans"] and entries[0].is_dir() and not entries[0].is_symlink() and not list(entries[0].iterdir()): continue
    if entries: raise SystemExit("The volume is not empty. Restore refused; no data was overwritten.")
with tarfile.open("/backup.tar.gz","r:gz") as archive:
    members=archive.getmembers()
    for member in members:
        path=Path(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] not in {"database","scans","certificates","backups"} or not (member.isfile() or member.isdir()):
            raise SystemExit("The archive contains unsafe paths or special links. Restore refused.")
    archive.extractall(root,members=members,filter="data")
    for member in reversed(members):
        os.chown(root/member.name,member.uid,member.gid,follow_symlinks=False)
with sqlite3.connect("file:/restore/database/odysafe.db?mode=ro",uri=True) as database:
    if database.execute("PRAGMA quick_check").fetchone()[0]!="ok": raise SystemExit("The restored database failed its integrity check. Do not start the application.")
print("Restore complete. Run start.dh.")'
