from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

MIGRATIONS = [
"""
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans(
 scan_id TEXT PRIMARY KEY, present INTEGER NOT NULL DEFAULT 1, indexed_at TEXT NOT NULL,
 source_mtime_ns INTEGER NOT NULL, capture_date TEXT, submitted_url TEXT, final_url TEXT,
 host TEXT, profile TEXT, browser TEXT, capture_status TEXT, analysis_status TEXT,
 duration_ms INTEGER, request_count INTEGER NOT NULL DEFAULT 0,
 host_count INTEGER NOT NULL DEFAULT 0, detection_count INTEGER NOT NULL DEFAULT 0,
 report_available INTEGER NOT NULL DEFAULT 0, report_error TEXT,
 indicators_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS scans_date_idx ON scans(capture_date);
CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(capture_status, analysis_status);
CREATE INDEX IF NOT EXISTS scans_host_idx ON scans(host);
CREATE INDEX IF NOT EXISTS scans_profile_idx ON scans(profile);
CREATE TABLE IF NOT EXISTS scan_index_state(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS yara_rules(
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
 origin TEXT NOT NULL CHECK(origin IN ('builtin','custom')), active INTEGER NOT NULL DEFAULT 0,
 archived INTEGER NOT NULL DEFAULT 0, current_version INTEGER NOT NULL,
 content_hash TEXT NOT NULL, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS yara_rule_versions(
 rule_id TEXT NOT NULL REFERENCES yara_rules(id), version INTEGER NOT NULL,
 source TEXT NOT NULL, content_hash TEXT NOT NULL, compilation_error TEXT, created_at TEXT NOT NULL,
 PRIMARY KEY(rule_id, version)
);
CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, action TEXT NOT NULL,
 target TEXT, outcome TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
""",
"""
CREATE TABLE IF NOT EXISTS threat_providers(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, profile TEXT NOT NULL,
 capability TEXT NOT NULL CHECK(capability IN ('supported','limited','unsupported')),
 enabled INTEGER NOT NULL DEFAULT 0, method TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrichment_jobs(
 id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, kind TEXT NOT NULL,
 status TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT,
 domains_count INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE INDEX IF NOT EXISTS enrichment_jobs_scan_idx ON enrichment_jobs(scan_id,created_at);
CREATE TABLE IF NOT EXISTS dns_results(
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES enrichment_jobs(id),
 scan_id TEXT NOT NULL, domain TEXT NOT NULL, original_domain TEXT NOT NULL,
 provider_id TEXT NOT NULL, provider_profile TEXT NOT NULL, method TEXT NOT NULL,
 qtype TEXT NOT NULL, checked_at TEXT NOT NULL, duration_ms INTEGER,
 rcode TEXT, answers_json TEXT NOT NULL DEFAULT '[]', authority_json TEXT NOT NULL DEFAULT '[]',
 ede_json TEXT NOT NULL DEFAULT '[]', interpretation TEXT NOT NULL,
 justification TEXT NOT NULL, error TEXT, policy_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_results_scan_idx ON dns_results(scan_id,checked_at);
CREATE INDEX IF NOT EXISTS dns_results_domain_idx ON dns_results(domain,checked_at);
CREATE TABLE IF NOT EXISTS manual_iocs(
 id TEXT PRIMARY KEY, type TEXT NOT NULL, original_value TEXT NOT NULL,
 normalized_value TEXT NOT NULL, category TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
 archived INTEGER NOT NULL DEFAULT 0, comment TEXT NOT NULL DEFAULT '',
 declared_source TEXT NOT NULL DEFAULT '', provenance TEXT NOT NULL DEFAULT 'manual',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_used_at TEXT,
 expires_at TEXT, version INTEGER NOT NULL DEFAULT 1,
 UNIQUE(type,normalized_value)
);
CREATE INDEX IF NOT EXISTS manual_iocs_lookup_idx ON manual_iocs(type,normalized_value,active,archived);
CREATE TABLE IF NOT EXISTS ioc_matches(
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES enrichment_jobs(id),
 scan_id TEXT NOT NULL, ioc_id TEXT NOT NULL REFERENCES manual_iocs(id),
 observed_type TEXT NOT NULL, observed_value TEXT NOT NULL,
 matched_at TEXT NOT NULL, explanation TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ioc_matches_scan_idx ON ioc_matches(scan_id,matched_at);
""",
"""
CREATE TABLE IF NOT EXISTS capture_sessions(
 id TEXT PRIMARY KEY, scan_id TEXT NOT NULL UNIQUE, target_url TEXT NOT NULL,
 mode TEXT NOT NULL CHECK(mode IN ('automatic','interactive')),
 profile TEXT NOT NULL CHECK(profile IN ('desktop','mobile')),
 status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 started_at TEXT, completed_at TEXT, timeout_seconds INTEGER NOT NULL,
 error TEXT, xpra_password TEXT, finalized INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS capture_sessions_status_idx ON capture_sessions(status,created_at);
""",
"""
ALTER TABLE capture_sessions ADD COLUMN network_policy TEXT NOT NULL DEFAULT 'fixture'
 CHECK(network_policy IN ('fixture','internet'));
""",
"""
UPDATE capture_sessions SET xpra_password=NULL WHERE xpra_password IS NOT NULL;
""",
"""
ALTER TABLE enrichment_jobs ADD COLUMN total_domains INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enrichment_jobs ADD COLUMN omitted_domains INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enrichment_jobs ADD COLUMN progress_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dns_results ADD COLUMN cache_hit INTEGER NOT NULL DEFAULT 0;
""",
"""SELECT 1;""",
"""SELECT 1;""",
"""
CREATE TABLE IF NOT EXISTS hidden_scans(
 scan_id TEXT PRIMARY KEY, hidden_at TEXT NOT NULL
);
""",
"""
ALTER TABLE yara_rules ADD COLUMN category TEXT NOT NULL DEFAULT 'Général';
""",
"""
CREATE TABLE IF NOT EXISTS custom_dns_resolvers(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
""",
"""
CREATE TABLE engine_folders(
 id TEXT PRIMARY KEY, engine TEXT NOT NULL CHECK(engine IN ('yara','ioc')),
 name TEXT NOT NULL, UNIQUE(engine,name)
);
ALTER TABLE yara_rules ADD COLUMN folder_id TEXT REFERENCES engine_folders(id) ON DELETE SET NULL;
ALTER TABLE manual_iocs ADD COLUMN folder_id TEXT REFERENCES engine_folders(id) ON DELETE SET NULL;
INSERT INTO engine_folders(id,engine,name)
 SELECT 'yara-category-' || min(id),'yara',category FROM yara_rules
 WHERE category<>'' GROUP BY category;
UPDATE yara_rules SET folder_id=(SELECT id FROM engine_folders WHERE engine='yara' AND name=yara_rules.category);
""",
"""
ALTER TABLE engine_folders ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0;
INSERT OR IGNORE INTO engine_folders(id,engine,name) VALUES('default-yara','yara','Défaut');
INSERT OR IGNORE INTO engine_folders(id,engine,name) VALUES('default-ioc','ioc','Défaut');
UPDATE engine_folders SET is_default=1 WHERE name='Défaut';
CREATE UNIQUE INDEX engine_default_folder_idx ON engine_folders(engine) WHERE is_default=1;
UPDATE yara_rules SET folder_id=(SELECT id FROM engine_folders WHERE engine='yara' AND is_default=1) WHERE folder_id IS NULL;
UPDATE manual_iocs SET folder_id=(SELECT id FROM engine_folders WHERE engine='ioc' AND is_default=1) WHERE folder_id IS NULL;
CREATE TRIGGER yara_default_folder AFTER INSERT ON yara_rules WHEN NEW.folder_id IS NULL
BEGIN UPDATE yara_rules SET folder_id=(SELECT id FROM engine_folders WHERE engine='yara' AND is_default=1) WHERE id=NEW.id; END;
CREATE TRIGGER ioc_default_folder AFTER INSERT ON manual_iocs WHEN NEW.folder_id IS NULL
BEGIN UPDATE manual_iocs SET folder_id=(SELECT id FROM engine_folders WHERE engine='ioc' AND is_default=1) WHERE id=NEW.id; END;
"""
]


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)

    def initialize(self) -> None:
        if self.path.exists() and self.path.is_symlink():
            raise RuntimeError("SQLite path must not be a symbolic link")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent == Path("/database"):
            self.path.parent.chmod(0o700)
        with self.connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            for version, sql in enumerate(MIGRATIONS, 1):
                applied = connection.execute(
                    "SELECT 1 FROM schema_migrations WHERE version=?", (version,)).fetchone()
                if not applied:
                    if version == 7:
                        columns = {
                            row[1] for row in connection.execute("PRAGMA table_info(dns_results)")
                        }
                        if "reference_rcode" not in columns:
                            connection.execute(
                                "ALTER TABLE dns_results ADD COLUMN reference_rcode TEXT"
                            )
                        if "reference_answers_json" not in columns:
                            connection.execute(
                                "ALTER TABLE dns_results ADD COLUMN reference_answers_json TEXT NOT NULL DEFAULT '[]'"
                            )
                    elif version == 8:
                        columns = {row[1] for row in connection.execute("PRAGMA table_info(capture_sessions)")}
                        for name in ("analyze_yara", "analyze_ioc", "analyze_dns"):
                            if name not in columns:
                                connection.execute(f"ALTER TABLE capture_sessions ADD COLUMN {name} INTEGER NOT NULL DEFAULT 1")
                    else:
                        connection.executescript(sql)
                    connection.execute(
                        "INSERT INTO schema_migrations(version,applied_at) VALUES(?,datetime('now'))",
                        (version,))
        # SQLite follows the process umask when creating the file. Enforce the
        # private mode expected for the dedicated application volume.
        self.path.chmod(0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
