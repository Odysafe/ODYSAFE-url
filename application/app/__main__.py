from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

from app.capture import CaptureError, capture
from app.config import (ConfigurationError, DATA_ROOT, PROJECT_ROOT, configured_origins,
                        load_profiles, select_profile, validate_scan_url)
from app.reporting import ReportBuildError, build_report
from app.sandbox.session import interactive_settings
from app.storage.importer import ScanImportError, import_scans
from app.database import Database, reconcile_scans
from app.dns import dns_status, import_dns_result, prepare_dns_job, seed_providers
from app.ioc import match_scan_iocs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="capture an allowlisted URL")
    scan.add_argument("url")
    scan.add_argument("--profile")
    report = commands.add_parser("report", help="build a report from an existing scan")
    report.add_argument("scan_id")
    detect = commands.add_parser("detect", help="rerun local detections for an existing scan")
    detect.add_argument("scan_id")
    importer = commands.add_parser("import-scans", help="safely import historical scans")
    importer.add_argument("source")
    importer.add_argument("--uid", type=int, default=int(os.environ.get("ODYSAFE_UID", "1000")))
    importer.add_argument("--gid", type=int, default=int(os.environ.get("ODYSAFE_GID", "1000")))
    importer.add_argument("--repair-existing", action="store_true")
    commands.add_parser("reindex", help="rebuild the SQLite scan index from local evidence")
    enrich = commands.add_parser("enrich", help="run or inspect local enrichment")
    enrich_sub = enrich.add_subparsers(dest="enrich_command", required=True)
    enrich_offline = enrich_sub.add_parser("offline", help="match manual IOC without network")
    enrich_offline.add_argument("scan_id")
    enrich_status = enrich_sub.add_parser("status", help="show persisted enrichment")
    enrich_status.add_argument("scan_id")
    dns = commands.add_parser("dns", help="prepare and import isolated DNS enrichment")
    dns_sub = dns.add_subparsers(dest="dns_command", required=True)
    dns_sub.add_parser("providers", help="list fixed provider profiles")
    dns_prepare = dns_sub.add_parser("prepare", help="emit a bounded DNS job on stdout")
    dns_prepare.add_argument("scan_id")
    dns_import = dns_sub.add_parser("import", help="validate and persist a worker result from stdin")
    dns_import.add_argument("scan_id")
    return parser


def _scans_root() -> Path:
    if "ODYSAFE_DATA_DIR" in os.environ:
        return DATA_ROOT / "scans"
    return PROJECT_ROOT / "data" / "scans"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    database = Database(Path(os.environ.get("ODYSAFE_DB_PATH", PROJECT_ROOT / "data" / "odysafe.db")))
    if args.command in {"enrich", "dns"}:
        try:
            database.initialize(); seed_providers(database)
            if args.command == "dns" and args.dns_command == "providers":
                from app.dns.providers import PROVIDERS, public_provider
                with database.connect() as connection:
                    enabled={row[0]:bool(row[1]) for row in connection.execute("SELECT id,enabled FROM threat_providers")}
                print(json.dumps([{**public_provider(item),"enabled":enabled.get(item.id,False)}
                                  for item in PROVIDERS.values()],ensure_ascii=False,indent=2)); return 0
            scan_id = args.scan_id.lower(); parsed=uuid.UUID(scan_id)
            if str(parsed)!=scan_id: raise ValueError("Invalid scan ID")
            scan_dir=_scans_root()/scan_id
            if not scan_dir.is_dir() or scan_dir.is_symlink(): raise ValueError("Scan does not exist")
            if args.command == "enrich":
                result=(match_scan_iocs(database,scan_id,scan_dir) if args.enrich_command=="offline"
                        else dns_status(database,scan_id))
            elif args.dns_command == "prepare": result=prepare_dns_job(database,scan_id,scan_dir)
            else:
                raw=sys.stdin.buffer.read(4*1024*1024+1)
                if len(raw)>4*1024*1024: raise ValueError("DNS result exceeds 4 MiB")
                result=import_dns_result(database,scan_id,json.loads(raw))
            print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
        except (ValueError,OSError,json.JSONDecodeError) as exc:
            print(json.dumps({"status":"failed","error":str(exc)},ensure_ascii=False)); return 1
    if args.command == "import-scans":
        try:
            summary = import_scans(Path(args.source), _scans_root(), args.uid, args.gid,
                                   repair_existing=args.repair_existing)
        except (OSError, ScanImportError, ValueError) as exc:
            print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
            return 1
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 1 if summary["counts"]["failed"] else 0
    if args.command == "reindex":
        try:
            database.initialize()
            result = reconcile_scans(database, _scans_root())
        except (OSError, RuntimeError) as exc:
            print(json.dumps({"status": "failed", "error": str(exc)}))
            return 1
        print(json.dumps({"status": "completed", **result}, indent=2))
        return 0
    if args.command in {"report", "detect"}:
        try:
            scan_uuid = uuid.UUID(args.scan_id)
            if str(scan_uuid) != args.scan_id.lower():
                raise ValueError
            scan_dir = _scans_root() / str(scan_uuid)
            if not scan_dir.is_dir() or scan_dir.is_symlink():
                raise ReportBuildError("Scan does not exist")
            report = build_report(scan_dir)
        except (ValueError, ReportBuildError, OSError, TypeError) as exc:
            print(f"Scan ID: {args.scan_id}\nAnalysis: failed\nError: {exc}")
            return 1
        if args.command == "detect":
            engines = report["detection_engines"]
            print(f"Scan ID: {report['scan_id']}\nAnalysis: {report['analysis_status']}"
                  f"\nDetections: {report['detection_summary']['total']}"
                  f"\nBehavior: {engines['behavior']['status']}"
                  f"\nYARA-X: {engines['yara_x']['status']}"
                  f"\nFiles: {engines['file_analysis']['status']}"
                  f"\nReport: {scan_dir / 'report.json'}")
        else:
            print(f"Scan ID: {report['scan_id']}\nAnalysis: {report['analysis_status']}"
                  f"\nRequests: {report['network']['total_requests']}"
                  f"\nHosts: {len(report['hosts'])}\nURLs: {len(report['urls'])}"
                  f"\nReport: {scan_dir / 'report.json'}")
        return 0

    scan_id = str(uuid.uuid4())
    out_dir = _scans_root() / scan_id
    try:
        profiles = load_profiles()
        profile_name, profile = select_profile(profiles, args.profile)
        validate_scan_url(args.url)
        if os.environ.get("ODYSAFE_INTERACTIVE") == "1":
            profile = interactive_settings(profile)
        runtime_profile = dict(profile, _scan_id=scan_id, _profile_name=profile_name,
                               _allowed_origins=sorted(configured_origins()))
        meta = asyncio.run(capture(args.url, out_dir, runtime_profile))
    except (ConfigurationError, CaptureError) as exc:
        print(f"Scan ID: {scan_id}\nStatus: failed\nError: {exc}\nArtifacts: {out_dir}")
        return 1
    except Exception as exc:
        print(f"Scan ID: {scan_id}\nStatus: failed\nError: {type(exc).__name__}: {exc}\nArtifacts: {out_dir}")
        return 1
    analysis_line = ""
    if (out_dir / "network.har").is_file():
        try:
            report = build_report(out_dir)
            analysis_line = f"\nAnalysis: {report['analysis_status']}"
        except (ReportBuildError, OSError, TypeError) as exc:
            analysis_line = f"\nAnalysis: failed ({exc})"
    print(f"Scan ID: {scan_id}\nStatus: {meta['status']}\nFinal URL: {meta['final_url']}"
          f"{analysis_line}\nArtifacts: {out_dir}\nDuration: {meta['duration_ms']} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
