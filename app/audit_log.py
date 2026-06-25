"""
Audit Logging Module
-----------------------
Provides accountability ("who ran what scan, when, with what outcome")
without storing the sensitive content of any scan. This module is the only
place in the codebase permitted to write to the audit database, and the
schema below is deliberately limited to non-identifying, non-sensitive
fields. Vendor names, vendor website URLs, scan findings, narrative text,
and the Claude API key are NEVER written here — by construction, the
functions in this module don't even accept those values as parameters, so
a future change elsewhere in the codebase can't accidentally start logging
them through this path.

Identifiers that could otherwise re-identify a person (the session cookie
value, the raw IP address) are stored only as one-way SHA-256 hashes,
truncated to 16 hex characters. This is sufficient to answer "did the same
visitor run multiple scans" without storing a value that could be reversed
back into the original cookie or IP.

Storage caveat: this uses a local SQLite file on disk. On Render's free
tier, local disk is ephemeral — this file is wiped on every redeploy and
may not survive every restart/spin-down cycle. This module provides
within-deployment accountability and basic usage analytics, not a
durable, long-term audit trail suitable for compliance/legal retention.
For that, point DB_PATH at a persistent volume or swap this module's
storage backend for an external database.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "..", "audit_log.sqlite3")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    vendor_count INTEGER NOT NULL,
    used_ai_key INTEGER NOT NULL,
    status TEXT NOT NULL,
    error_type TEXT,
    duration_seconds REAL
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON scan_audit_log(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_audit_session ON scan_audit_log(session_hash);
"""


def _hash(value: str) -> str:
    """One-way truncated hash. Not reversible to the original session/IP."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_audit_log() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def record_scan_started(job_id: str, session_token: str, ip: str, vendor_count: int, used_ai_key: bool) -> None:
    """Called once when a scan is accepted and queued."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scan_audit_log "
            "(job_id, timestamp_utc, session_hash, ip_hash, vendor_count, used_ai_key, status, error_type, duration_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                job_id,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                _hash(session_token),
                _hash(ip),
                vendor_count,
                1 if used_ai_key else 0,
                "started",
                None,
                None,
            ),
        )


def record_scan_finished(job_id: str, status: str, started_at_epoch: float, error_type: str | None = None) -> None:
    """
    Called once when a scan reaches a terminal state (complete/failed).
    error_type should be a short class/category (e.g. "TimeoutError"),
    never the full exception message, since vendor-identifying details
    can appear in error text (e.g. a domain name in a connection error).
    """
    duration = round(time.time() - started_at_epoch, 2)
    with _connect() as conn:
        conn.execute(
            "UPDATE scan_audit_log SET status = ?, error_type = ?, duration_seconds = ? WHERE job_id = ?",
            (status, error_type, duration, job_id),
        )


def get_usage_stats(hours: int = 24) -> dict:
    """
    Aggregate, non-identifying usage stats for the last N hours. Used by
    the admin stats endpoint — returns counts only, never per-job detail
    that could be tied back to a specific session.
    """
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - hours * 3600))
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(
            "SELECT COUNT(*) as c FROM scan_audit_log WHERE timestamp_utc >= ?", (cutoff,)
        ).fetchone()["c"]
        by_status = conn.execute(
            "SELECT status, COUNT(*) as c FROM scan_audit_log WHERE timestamp_utc >= ? GROUP BY status",
            (cutoff,),
        ).fetchall()
        ai_key_used = conn.execute(
            "SELECT COUNT(*) as c FROM scan_audit_log WHERE timestamp_utc >= ? AND used_ai_key = 1", (cutoff,)
        ).fetchone()["c"]
        total_vendors = conn.execute(
            "SELECT COALESCE(SUM(vendor_count), 0) as s FROM scan_audit_log WHERE timestamp_utc >= ?", (cutoff,)
        ).fetchone()["s"]
        unique_sessions = conn.execute(
            "SELECT COUNT(DISTINCT session_hash) as c FROM scan_audit_log WHERE timestamp_utc >= ?", (cutoff,)
        ).fetchone()["c"]

    return {
        "window_hours": hours,
        "total_scans": total,
        "by_status": {row["status"]: row["c"] for row in by_status},
        "scans_using_ai_key": ai_key_used,
        "total_vendors_assessed": total_vendors,
        "unique_sessions": unique_sessions,
    }
