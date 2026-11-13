"""SQLite persistence for case reports and hashed document signatures.

Privacy notes:
- Uploaded PDFs are never stored here.
- Only the investigation result is kept (default 24h) so the PDF report can be
  downloaded.
- Document similarity stores only SHA-256 hashes of normalised word 5-grams,
  never the document text itself.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime(ISO_FMT)


def _connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cases_expires ON cases(expires_at);

            CREATE TABLE IF NOT EXISTS document_index (
                fingerprint TEXT PRIMARY KEY,
                shingles TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_doc_created ON document_index(created_at);
            """
        )


def save_case(db_path, case: dict, ttl_hours: int = 24) -> None:
    now = _now()
    expires = now + timedelta(hours=max(1, ttl_hours))
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cases (id, created_at, expires_at, payload) VALUES (?, ?, ?, ?)",
            (
                case["id"],
                _iso(now),
                _iso(expires),
                json.dumps(case, ensure_ascii=False, default=str),
            ),
        )
        conn.execute("DELETE FROM cases WHERE expires_at < ?", (_iso(now),))


def get_case(db_path, case_id: str) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT payload FROM cases WHERE id = ? AND expires_at >= ?",
            (case_id, _iso(_now())),
        ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["payload"])
    except (TypeError, ValueError):
        return None


def cleanup_expired(db_path, doc_index_days: int = 90) -> None:
    now = _now()
    cutoff = now - timedelta(days=max(1, doc_index_days))
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM cases WHERE expires_at < ?", (_iso(now),))
        conn.execute("DELETE FROM document_index WHERE created_at < ?", (_iso(cutoff),))


def add_document_signature(db_path, fingerprint: str, shingles: list[str]) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO document_index (fingerprint, shingles, created_at) VALUES (?, ?, ?)",
            (fingerprint, json.dumps(shingles), _iso(_now())),
        )


def get_document_signatures(db_path, limit: int = 500) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT fingerprint, shingles, created_at FROM document_index "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    results = []
    for row in rows:
        try:
            shingles = json.loads(row["shingles"])
        except (TypeError, ValueError):
            shingles = []
        results.append(
            {
                "fingerprint": row["fingerprint"],
                "shingles": shingles if isinstance(shingles, list) else [],
                "created_at": row["created_at"],
            }
        )
    return results


def document_fingerprint_exists(db_path, fingerprint: str) -> bool:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM document_index WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
    return row is not None
