"""SQLite storage for scan history, threat records and the intel response cache."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    scan_type   TEXT NOT NULL,
    target      TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    summary     TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);

CREATE TABLE IF NOT EXISTS threat_records (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator      TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    threat_type    TEXT NOT NULL DEFAULT 'phishing',
    source         TEXT NOT NULL DEFAULT 'manual',
    description    TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    UNIQUE(indicator, indicator_type)
);

CREATE TABLE IF NOT EXISTS intel_cache (
    cache_key  TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
"""


def utcnow() -> datetime:
    return datetime.now(UTC)


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    path = get_settings().database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)


# --------------------------------------------------------------------------- scans


def save_scan(result: dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans (id, scan_type, target, verdict, risk_score, summary,"
            " result_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result["id"],
                result["scan_type"],
                result["target"],
                result["verdict"],
                result["risk_score"],
                result["summary"],
                json.dumps(result, default=str),
                result["created_at"],
            ),
        )


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["result_json"]) if row else None


def delete_scan(scan_id: str) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cur.rowcount > 0


def list_scans(
    *,
    scan_type: str | None = None,
    verdict: str | None = None,
    query: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    clauses, params = [], []
    if scan_type:
        clauses.append("scan_type = ?")
        params.append(scan_type)
    if verdict:
        clauses.append("verdict = ?")
        params.append(verdict)
    if query:
        clauses.append("target LIKE ?")
        params.append(f"%{query}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM scans {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT id, scan_type, target, verdict, risk_score, summary, created_at FROM scans"
            f" {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return [dict(r) for r in rows], total


def scan_stats(days: int = 30) -> dict[str, Any]:
    since = (utcnow() - timedelta(days=days - 1)).date().isoformat()
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_verdict = {
            r["verdict"]: r["n"]
            for r in conn.execute("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict")
        }
        by_type = {
            r["scan_type"]: r["n"]
            for r in conn.execute("SELECT scan_type, COUNT(*) n FROM scans GROUP BY scan_type")
        }
        daily = conn.execute(
            "SELECT substr(created_at, 1, 10) day, verdict, COUNT(*) n FROM scans"
            " WHERE substr(created_at, 1, 10) >= ? GROUP BY day, verdict",
            (since,),
        ).fetchall()
        recent_flagged = conn.execute(
            "SELECT result_json FROM scans WHERE verdict != 'safe'"
            " ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        threat_count = conn.execute("SELECT COUNT(*) FROM threat_records").fetchone()[0]
        avg_score = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0]

    timeline: dict[str, dict[str, int]] = {}
    start = utcnow().date() - timedelta(days=days - 1)
    for i in range(days):
        d = (start + timedelta(days=i)).isoformat()
        timeline[d] = {"safe": 0, "suspicious": 0, "malicious": 0}
    for r in daily:
        if r["day"] in timeline:
            timeline[r["day"]][r["verdict"]] = r["n"]

    technique_counts: dict[str, dict[str, Any]] = {}
    for r in recent_flagged:
        for f in json.loads(r["result_json"]).get("findings", []):
            if f.get("kind") != "risk":
                continue
            entry = technique_counts.setdefault(f["id"], {"id": f["id"], "title": f["title"], "count": 0})
            entry["count"] += 1
    top_techniques = sorted(technique_counts.values(), key=lambda e: e["count"], reverse=True)[:8]

    return {
        "total_scans": total,
        "by_verdict": {v: by_verdict.get(v, 0) for v in ("safe", "suspicious", "malicious")},
        "by_type": {t: by_type.get(t, 0) for t in ("url", "domain", "email")},
        "average_risk": round(avg_score or 0, 1),
        "threat_records": threat_count,
        "timeline": [{"date": d, **counts} for d, counts in timeline.items()],
        "top_techniques": top_techniques,
    }


# ------------------------------------------------------------------ threat records


def add_threat(
    indicator: str, indicator_type: str, threat_type: str, source: str, description: str
) -> dict[str, Any]:
    now = utcnow().isoformat()
    with connect() as conn:
        conn.execute(
            "INSERT INTO threat_records (indicator, indicator_type, threat_type, source,"
            " description, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(indicator, indicator_type) DO UPDATE SET threat_type=excluded.threat_type,"
            " source=excluded.source, description=excluded.description",
            (indicator, indicator_type, threat_type, source, description, now),
        )
        row = conn.execute(
            "SELECT * FROM threat_records WHERE indicator = ? AND indicator_type = ?",
            (indicator, indicator_type),
        ).fetchone()
    return dict(row)


def list_threats(query: str | None = None, limit: int = 200, offset: int = 0) -> tuple[list[dict], int]:
    where, params = "", []
    if query:
        where, params = "WHERE indicator LIKE ? OR description LIKE ?", [f"%{query}%", f"%{query}%"]
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM threat_records {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM threat_records {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return [dict(r) for r in rows], total


def delete_threat(threat_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM threat_records WHERE id = ?", (threat_id,))
    return cur.rowcount > 0


def match_threats(indicators: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Return local threat records matching any (indicator, type) pair."""
    if not indicators:
        return []
    clause = " OR ".join("(indicator = ? AND indicator_type = ?)" for _ in indicators)
    params = [v for pair in indicators for v in pair]
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM threat_records WHERE {clause}", params).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------- intel cache


def cache_get(cache_key: str, ttl_hours: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT payload, fetched_at FROM intel_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
    if not row:
        return None
    if datetime.fromisoformat(row["fetched_at"]) < utcnow() - timedelta(hours=ttl_hours):
        return None
    return json.loads(row["payload"])


def cache_put(cache_key: str, source: str, payload: dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO intel_cache (cache_key, source, payload, fetched_at)"
            " VALUES (?, ?, ?, ?)",
            (cache_key, source, json.dumps(payload), utcnow().isoformat()),
        )
