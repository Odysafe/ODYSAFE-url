#!/bin/sh
# A deliberate full backup pauses the services, then restores their running state.
set -eu
cd -- "$(dirname -- "$0")/../application"
. ./common.sh
require_docker
require_local_configuration

if [ "$#" -ne 1 ]; then printf '%s\n' 'Usage: ./backup.sh /path/to/backup.tar.gz' >&2; exit 2; fi
output=$1
case "$output" in /*) ;; *) output="$(pwd)/$output";; esac
if [ -e "$output" ]; then printf '%s\n' 'The destination already exists. No files were overwritten.' >&2; exit 2; fi
for volume in odysafe-distribution-db odysafe-distribution-scans odysafe-distribution-certificates odysafe-distribution-backups; do docker volume inspect "$volume" >/dev/null; done
was_running=$(compose ps --status running -q)
if [ -n "$was_running" ]; then
    compose exec -T app python -c 'import sqlite3; c=sqlite3.connect("file:/database/odysafe.db?mode=ro",uri=True); active=c.execute("SELECT count(*) FROM capture_sessions WHERE status IN (?,?,?,?,?)",("queued","starting","running","finalizing","analyzing")).fetchone()[0]; jobs=c.execute("SELECT count(*) FROM enrichment_jobs WHERE status IN (?,?)",("queued","running")).fetchone()[0]; raise SystemExit("Finish all captures and analyses before creating a backup." if active or jobs else 0)'
fi
umask 077
partial="$output.partial"
cleanup() {
    rm -f -- "$partial"
    if [ -n "$was_running" ]; then compose up -d --no-build --pull never; fi
}
trap cleanup EXIT
if [ -n "$was_running" ]; then compose stop; fi
docker run --rm --network none --read-only \
  --mount type=volume,source=odysafe-distribution-db,target=/database,readonly \
  --mount type=volume,source=odysafe-distribution-scans,target=/data,readonly \
  --mount type=volume,source=odysafe-distribution-certificates,target=/certificates,readonly \
  --mount type=volume,source=odysafe-distribution-backups,target=/backups,readonly \
  --entrypoint python odysafe-source-app:0.1.0 -c 'import sys,tarfile; t=tarfile.open(fileobj=sys.stdout.buffer,mode="w|gz"); [t.add(path,arcname=name) for path,name in [("/database","database"),("/data","scans"),("/certificates","certificates"),("/backups","backups")]]; t.close()' > "$partial"
mv -- "$partial" "$output"
(cd -- "$(dirname -- "$output")" && sha256sum "$(basename -- "$output")") > "$output.sha256"
printf '%s\n' "Private backup saved: $output"
