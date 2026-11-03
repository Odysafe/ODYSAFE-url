from __future__ import annotations

import hashlib
from contextlib import nullcontext
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.database import Database

MAX_RULE_BYTES = 64 * 1024
MAX_ACTIVE_CUSTOM_RULES = 100
RULE_NAME = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)")


class RuleValidationError(ValueError):
    pass


def compile_sources(sources: list[tuple[str, str]]) -> tuple[Any, list[str], str]:
    import yara_x
    compiler = yara_x.Compiler(includes_enabled=False)
    combined = hashlib.sha256()
    for origin, source in sources:
        if len(source.encode("utf-8")) > MAX_RULE_BYTES:
            raise RuleValidationError(f"Rule source exceeds {MAX_RULE_BYTES} bytes")
        if re.search(r"(?m)^\s*include\s", source):
            raise RuleValidationError("YARA include directives are forbidden")
        combined.update(origin.encode()); combined.update(b"\0"); combined.update(source.encode())
        try:
            compiler.add_source(source, origin=origin)
        except yara_x.CompileError as exc:
            raise RuleValidationError(str(exc)) from exc
    try:
        rules = compiler.build()
    except yara_x.CompileError as exc:
        raise RuleValidationError(str(exc)) from exc
    return rules, [str(item) for item in compiler.warnings()], combined.hexdigest()


class RuleRegistry:
    def __init__(self, database: Database, builtin_dir: Path):
        self.database = database
        self.builtin_dir = Path(builtin_dir)

    def _builtins(self) -> list[tuple[str, str]]:
        # YARA-X starts empty. Only user-created or imported rules are used.
        return []

    def seed_builtins(self, connection=None, sources=None) -> None:
        """Remove the retired shipped example without touching custom rules."""
        identifier = "builtin-" + hashlib.sha256(b"builtin:odysafe_rules.yar").hexdigest()[:16]
        with (self.database.transaction() if connection is None else nullcontext(connection)) as connection:
            connection.execute("""DELETE FROM yara_rule_versions WHERE rule_id IN
                (SELECT id FROM yara_rules WHERE origin='builtin' AND id=?)""", (identifier,))
            connection.execute("DELETE FROM yara_rules WHERE origin='builtin' AND id=?", (identifier,))

    def list(self, query: str = "", state: str = "all", category: str = "") -> list[dict[str, Any]]:
        sql = "SELECT * FROM yara_rules WHERE name LIKE ?"
        params: list[Any] = [f"%{query[:100]}%"]
        if state == "active": sql += " AND active=1 AND archived=0"
        elif state == "inactive": sql += " AND active=0 AND archived=0"
        elif state == "archived": sql += " AND archived=1"
        if category:
            sql += " AND category=?"
            params.append(category[:60])
        sql += " ORDER BY category,origin,name"
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(sql, params)]

    def get(self, rule_id: str) -> dict[str, Any] | None:
        with self.database.connect() as connection:
            row = connection.execute("""SELECT r.*,v.source FROM yara_rules r
                JOIN yara_rule_versions v ON v.rule_id=r.id AND v.version=r.current_version
                WHERE r.id=?""", (rule_id,)).fetchone()
            if not row: return None
            item = dict(row)
            item["versions"] = [dict(v) for v in connection.execute(
                "SELECT version,content_hash,compilation_error,created_at FROM yara_rule_versions WHERE rule_id=? ORDER BY version DESC",
                (rule_id,))]
            return item

    def sources_by_ids(self, rule_ids: list[str]) -> list[tuple[str, str]]:
        """Return an explicit, bounded rule set for a one-off reanalysis."""
        identifiers = list(dict.fromkeys(rule_ids))
        if not identifiers or len(identifiers) > 100:
            raise RuleValidationError("Select between 1 and 100 rules")
        placeholders = ",".join("?" for _ in identifiers)
        with self.database.connect() as connection:
            rows = connection.execute(f"""SELECT r.id,r.name,r.last_error,v.source
                FROM yara_rules r JOIN yara_rule_versions v
                  ON v.rule_id=r.id AND v.version=r.current_version
                WHERE r.id IN ({placeholders}) AND r.archived=0""", identifiers).fetchall()
        if len(rows) != len(identifiers):
            raise RuleValidationError("One or more selected rules are unavailable")
        if any(row["last_error"] for row in rows):
            raise RuleValidationError("One or more selected rules do not compile")
        ordered = {row["id"]: row for row in rows}
        sources = [(f"selected:{identifier}:{ordered[identifier]['name']}", ordered[identifier]["source"])
                   for identifier in identifiers]
        compile_sources(sources)
        return sources

    def _active_sources(self, connection, exclude: str | None = None) -> list[tuple[str, str]]:
        params: tuple[Any, ...] = () if exclude is None else (exclude,)
        exclusion = "" if exclude is None else " AND r.id<>?"
        rows = connection.execute(f"""SELECT r.id,r.name,v.source FROM yara_rules r
            JOIN yara_rule_versions v ON v.rule_id=r.id AND v.version=r.current_version
            WHERE r.origin='custom' AND r.active=1 AND r.archived=0{exclusion} ORDER BY r.name""", params)
        return [(f"custom:{row['id']}:{row['name']}", row["source"]) for row in rows]

    def _active_builtin_sources(self, connection, exclude: str | None = None) -> list[tuple[str, str]]:
        params: tuple[Any, ...] = () if exclude is None else (exclude,)
        exclusion = "" if exclude is None else " AND r.id<>?"
        rows = connection.execute(f"""SELECT r.id,r.name,v.source FROM yara_rules r
            JOIN yara_rule_versions v ON v.rule_id=r.id AND v.version=r.current_version
            WHERE r.origin='builtin' AND r.active=1 AND r.archived=0{exclusion} ORDER BY r.name""", params)
        return [(f"builtin:{row['id']}:{row['name']}", row["source"]) for row in rows]

    def save(self, name: str, source: str, description: str = "", rule_id: str | None = None,
             category: str = "Général") -> str:
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", name):
            raise RuleValidationError("Invalid rule name")
        category = " ".join(category.strip().split()) or "Général"
        if len(category) > 60 or any(ord(character) < 32 for character in category):
            raise RuleValidationError("Invalid category")
        encoded = source.encode("utf-8")
        if not encoded or len(encoded) > MAX_RULE_BYTES:
            raise RuleValidationError("Rule source is empty or too large")
        declared = RULE_NAME.findall(source)
        if not declared:
            raise RuleValidationError("No YARA rule declaration found")
        compile_error = None
        try:
            compile_sources([(f"candidate:{name}", source)])
        except RuleValidationError as exc:
            compile_error = str(exc)
        now = datetime.now(timezone.utc).isoformat(); digest = hashlib.sha256(encoded).hexdigest()
        identifier = rule_id or str(uuid.uuid4())
        with self.database.transaction() as connection:
            current = connection.execute("SELECT * FROM yara_rules WHERE id=?", (identifier,)).fetchone()
            if current and current["origin"] == "builtin":
                raise RuleValidationError("Built-in rules are read-only")
            collision = connection.execute("SELECT id FROM yara_rules WHERE name=? AND id<>?", (name, identifier)).fetchone()
            if collision: raise RuleValidationError("Rule name already exists")
            version = (connection.execute(
                "SELECT coalesce(max(version),0)+1 FROM yara_rule_versions WHERE rule_id=?",
                (identifier,)).fetchone()[0] if current else 1)
            if not compile_error and current and current["active"]:
                try:
                    candidates = self._active_builtin_sources(connection) + self._active_sources(connection, exclude=identifier)
                    candidates.append((f"custom:{identifier}:{name}", source))
                    compile_sources(candidates)
                except RuleValidationError as exc:
                    compile_error = str(exc)
            if current:
                if compile_error:
                    connection.execute("UPDATE yara_rules SET updated_at=? WHERE id=?", (now, identifier))
                else:
                    connection.execute("""UPDATE yara_rules SET name=?,description=?,category=?,current_version=?,
                        content_hash=?,last_error=NULL,updated_at=? WHERE id=?""",
                        (name, description[:500], category, version, digest, now, identifier))
            else:
                connection.execute("""INSERT INTO yara_rules
                    (id,name,description,category,origin,active,archived,current_version,content_hash,last_error,created_at,updated_at)
                    VALUES(?,?,?,?,'custom',0,0,?,?,?, ?,?)""",
                    (identifier, name, description[:500], category, version, digest, compile_error, now, now))
            connection.execute("INSERT INTO yara_rule_versions VALUES(?,?,?,?,?,?)",
                               (identifier, version, source, digest, compile_error, now))
            connection.execute("INSERT INTO audit_events(created_at,action,target,outcome,detail) VALUES(?,?,?,?,?)",
                               (now, "rule.save", identifier, "failed" if compile_error else "success", compile_error or ""))
        if compile_error: raise RuleValidationError(compile_error)
        return identifier

    def test(self, rule_id: str, payload: bytes) -> list[str]:
        import yara_x
        if len(payload) > 10 * 1024 * 1024:
            raise RuleValidationError("Test payload exceeds 10 MiB")
        rule = self.get(rule_id)
        if not rule: raise RuleValidationError("Rule not found")
        compiled, _, _ = compile_sources([(f"test:{rule_id}", rule["source"])])
        scanner = yara_x.Scanner(compiled); scanner.set_timeout(5); scanner.max_matches_per_pattern(20)
        try: return [item.identifier for item in scanner.scan(payload).matching_rules][:100]
        except (yara_x.ScanError, yara_x.TimeoutError) as exc: raise RuleValidationError(str(exc)) from exc

    def set_state(self, rule_id: str, action: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM yara_rules WHERE id=?", (rule_id,)).fetchone()
            if not row: raise RuleValidationError("Rule not found")
            if action == "archive":
                if row["origin"] == "builtin": raise RuleValidationError("Built-in rules cannot be archived")
                connection.execute("UPDATE yara_rules SET active=0,archived=1,updated_at=? WHERE id=?", (now, rule_id))
            elif action == "disable":
                connection.execute("UPDATE yara_rules SET active=0,updated_at=? WHERE id=?", (now, rule_id))
            elif action == "activate":
                if row["last_error"]: raise RuleValidationError("Current version does not compile")
                count = connection.execute("SELECT count(*) FROM yara_rules WHERE origin='custom' AND active=1").fetchone()[0]
                if count >= MAX_ACTIVE_CUSTOM_RULES: raise RuleValidationError("Active rule limit reached")
                candidates = (self._active_builtin_sources(connection, exclude=rule_id) +
                              self._active_sources(connection, exclude=rule_id))
                version = connection.execute("SELECT source FROM yara_rule_versions WHERE rule_id=? AND version=?",
                                             (rule_id, row["current_version"])).fetchone()
                candidates.append((f"custom:{rule_id}:{row['name']}", version[0]))
                compile_sources(candidates)
                connection.execute("UPDATE yara_rules SET active=1,archived=0,updated_at=? WHERE id=?", (now, rule_id))
            else: raise RuleValidationError("Invalid rule action")
            connection.execute("INSERT INTO audit_events(created_at,action,target,outcome) VALUES(?,?,?,'success')",
                               (now, f"rule.{action}", rule_id))

    def bulk_action(self, rule_ids: list[str], action: str) -> dict[str, list[str]]:
        """Disable or permanently remove custom rules from future rule sets."""
        if action not in {"activate", "disable", "delete"}:
            raise RuleValidationError("Invalid bulk rule action")
        identifiers = list(dict.fromkeys(rule_ids))
        if not identifiers or len(identifiers) > 100:
            raise RuleValidationError("Select between 1 and 100 rules")
        result: dict[str, list[str]] = {"updated": [], "refused": []}
        now = datetime.now(timezone.utc).isoformat()
        with self.database.transaction() as connection:
            for identifier in identifiers:
                row = connection.execute("SELECT id,origin FROM yara_rules WHERE id=?", (identifier,)).fetchone()
                if not row or (action == "delete" and row["origin"] != "custom"):
                    result["refused"].append(identifier)
                    continue
                if action == "activate":
                    if row["origin"] == "custom":
                        count = connection.execute(
                            "SELECT count(*) FROM yara_rules WHERE origin='custom' AND active=1"
                        ).fetchone()[0]
                        if count >= MAX_ACTIVE_CUSTOM_RULES:
                            result["refused"].append(identifier)
                            continue
                    current = connection.execute(
                        "SELECT last_error FROM yara_rules WHERE id=?", (identifier,)
                    ).fetchone()
                    if current["last_error"]:
                        result["refused"].append(identifier)
                        continue
                    connection.execute("UPDATE yara_rules SET active=1,archived=0,updated_at=? WHERE id=?",
                                       (now, identifier))
                elif action == "disable":
                    connection.execute("UPDATE yara_rules SET active=0,updated_at=? WHERE id=?",
                                       (now, identifier))
                else:
                    connection.execute("DELETE FROM yara_rule_versions WHERE rule_id=?", (identifier,))
                    connection.execute("DELETE FROM yara_rules WHERE id=?", (identifier,))
                connection.execute(
                    "INSERT INTO audit_events(created_at,action,target,outcome) VALUES(?,?,?,'success')",
                    (now, f"rule.{action}", identifier))
                result["updated"].append(identifier)
        return result

    def active_sources(self) -> tuple[list[tuple[str, str]], str]:
        with self.database.connect() as connection:
            sources = self._active_builtin_sources(connection) + self._active_sources(connection)
        _, _, digest = compile_sources(sources)
        return sources, digest
