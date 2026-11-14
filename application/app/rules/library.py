"""Private, persistent folders shared by the two offline libraries."""
from __future__ import annotations

import uuid
from app.database import Database


class EngineLibrary:
    def __init__(self, database: Database, engine: str):
        if engine not in {"yara", "ioc"}:
            raise ValueError("Moteur inconnu")
        self.database = database
        self.engine = engine
        self.table = "yara_rules" if engine == "yara" else "manual_iocs"

    def folders(self):
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(f"""SELECT f.*,count(r.id) count
                FROM engine_folders f LEFT JOIN {self.table} r ON r.folder_id=f.id AND r.archived=0
                WHERE f.engine=? GROUP BY f.id ORDER BY f.name COLLATE NOCASE""", (self.engine,))]

    def save_folder(self, name: str, identifier: str = "") -> str:
        name = " ".join(name.split())
        if not name or len(name) > 60 or any(ord(char) < 32 for char in name):
            raise ValueError("Le nom doit contenir entre 1 et 60 caractères")
        with self.database.transaction() as connection:
            if identifier:
                if not connection.execute("UPDATE engine_folders SET name=? WHERE id=? AND engine=?",
                                          (name, identifier, self.engine)).rowcount:
                    raise ValueError("Dossier introuvable")
            else:
                identifier = str(uuid.uuid4())
                connection.execute("INSERT INTO engine_folders(id,engine,name) VALUES(?,?,?)", (identifier, self.engine, name))
        return identifier

    def default_folder(self) -> str:
        with self.database.connect() as connection:
            return connection.execute("SELECT id FROM engine_folders WHERE engine=? AND is_default=1", (self.engine,)).fetchone()[0]

    def delete_folder(self, identifier: str) -> None:
        with self.database.transaction() as connection:
            row=connection.execute("SELECT * FROM engine_folders WHERE id=? AND engine=?",(identifier,self.engine)).fetchone()
            if not row: raise ValueError("Dossier introuvable")
            if row["is_default"]: raise ValueError("Le dossier par défaut doit être conservé")
            default=connection.execute("SELECT id FROM engine_folders WHERE engine=? AND is_default=1",(self.engine,)).fetchone()[0]
            connection.execute(f"UPDATE {self.table} SET folder_id=? WHERE folder_id=?",(default,identifier))
            connection.execute("DELETE FROM engine_folders WHERE id=?",(identifier,))

    def move(self, identifiers: list[str], folder: str) -> None:
        folder = folder or self.default_folder()
        identifiers = list(dict.fromkeys(identifiers))
        if not identifiers or len(identifiers) > 500:
            raise ValueError("Sélectionnez entre 1 et 500 éléments")
        with self.database.transaction() as connection:
            if folder and not connection.execute("SELECT 1 FROM engine_folders WHERE id=? AND engine=?",
                                                 (folder, self.engine)).fetchone():
                raise ValueError("Dossier introuvable")
            marks = ",".join("?" for _ in identifiers)
            count = connection.execute(f"SELECT count(*) FROM {self.table} WHERE id IN ({marks})", identifiers).fetchone()[0]
            if count != len(identifiers):
                raise ValueError("Un élément est introuvable")
            connection.execute(f"UPDATE {self.table} SET folder_id=? WHERE id IN ({marks})", (folder or None, *identifiers))

    def selection(self, identifiers: list[str], folders: list[str], include_inactive: bool = False) -> list[str]:
        identifiers = list(dict.fromkeys(identifiers))
        folders = list(dict.fromkeys(folders))
        if len(identifiers) > 100 or len(folders) > 100:
            raise ValueError("Sélection trop volumineuse")
        with self.database.connect() as connection:
            for folder in folders:
                if not connection.execute("SELECT 1 FROM engine_folders WHERE id=? AND engine=?", (folder, self.engine)).fetchone():
                    raise ValueError("Dossier introuvable")
            rows = connection.execute(f"SELECT * FROM {self.table} WHERE archived=0 ORDER BY id").fetchall()
        available = {row['id'] for row in rows}
        if not set(identifiers) <= available:
            raise ValueError("Un élément sélectionné est indisponible")
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        result = []
        for row in rows:
            if row['id'] not in identifiers and row['folder_id'] not in folders:
                continue
            if not include_inactive and not row['active']:
                continue
            if self.engine == 'yara' and row['last_error']:
                raise ValueError("Une règle sélectionnée ne compile pas")
            if self.engine == 'ioc' and row['expires_at']:
                expiry = datetime.fromisoformat(row['expires_at'].replace('Z', '+00:00'))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry <= now:
                    continue
            result.append(row['id'])
        if not result or len(result) > 100:
            raise ValueError("Choisissez entre 1 et 100 éléments utilisables (hors archives et IOC expirés)")
        return result
