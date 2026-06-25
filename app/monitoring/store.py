"""
Monitoring Persistence Store
--------------------------------
SQLite-backed storage for:
  - The vendor inventory (so "select from existing inventory" works
    across sessions, not just within a single scan job)
  - Continuous monitoring configuration per vendor (which detectors,
    scan frequency, alert threshold, webhook/email target)
  - Score history over time (the actual time-series Black-Kite-style
    "rating trend" data)
  - Pending alerts (score drops exceeding the configured threshold)

This is intentionally a SEPARATE SQLite file from audit_log.sqlite3,
since this store's purpose (operational vendor/monitoring data) is
different from the audit log's purpose (privacy-preserving usage
accountability) — keeping them apart avoids any temptation to cross-
contaminate schemas later.

Storage caveat: same as audit_log.py — this uses local SQLite on disk,
which is ephemeral on Render's free tier (wiped on redeploy). For
continuous monitoring to mean anything across days/weeks, this needs a
persistent volume or external database in any real deployment. This is
flagged prominently in the README; this module's docstring repeats it
here because it is the single most important operational fact about the
continuous monitoring feature.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "..", "..", "monitoring.sqlite3")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors (
    vendor_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitoring_configs (
    vendor_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'ad_hoc',  -- 'ad_hoc' or 'continuous'
    detector_types TEXT NOT NULL,          -- JSON list, e.g. ["exploitation","vulnerability"]
    frequency TEXT NOT NULL DEFAULT 'daily',  -- 'daily' or 'weekly'
    alert_threshold_points INTEGER NOT NULL DEFAULT 20,  -- score drop that triggers an alert
    webhook_url TEXT,
    notify_email TEXT,
    last_run_at TEXT,
    next_run_at TEXT,
    owner_session_hash TEXT,  -- hashed session that set up monitoring, for ownership checks
    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
);

CREATE TABLE IF NOT EXISTS score_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id TEXT NOT NULL,
    detector_type TEXT NOT NULL,
    score INTEGER,
    rating_letter TEXT,
    summary TEXT,
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
);
CREATE INDEX IF NOT EXISTS idx_score_history_vendor ON score_history(vendor_id, recorded_at);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id TEXT NOT NULL,
    detector_type TEXT NOT NULL,
    previous_score INTEGER,
    new_score INTEGER,
    drop_points INTEGER,
    triggered_at TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    delivery_error TEXT,
    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
);
"""


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_store() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


# --- Vendor inventory ---

def upsert_vendor(name: str, domain: str) -> str:
    """Returns vendor_id. If the domain already exists, returns the existing vendor_id
    (updating the stored name) rather than creating a duplicate."""
    with _connect() as conn:
        existing = conn.execute("SELECT vendor_id FROM vendors WHERE domain = ?", (domain,)).fetchone()
        if existing:
            conn.execute("UPDATE vendors SET name = ? WHERE vendor_id = ?", (name, existing["vendor_id"]))
            return existing["vendor_id"]
        vendor_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO vendors (vendor_id, name, domain, created_at) VALUES (?, ?, ?, ?)",
            (vendor_id, name, domain, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        return vendor_id


def list_vendors() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM vendors ORDER BY name").fetchall()
        return [dict(r) for r in rows]


def get_vendor(vendor_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vendor_id,)).fetchone()
        return dict(row) if row else None


# --- Monitoring configuration ---

def set_monitoring_config(
    vendor_id: str,
    mode: str,
    detector_types: list[str],
    frequency: str,
    alert_threshold_points: int,
    owner_session_hash: str,
    webhook_url: str | None = None,
    notify_email: str | None = None,
) -> None:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    next_run = _compute_next_run(frequency)
    with _connect() as conn:
        conn.execute(
            """INSERT INTO monitoring_configs
               (vendor_id, mode, detector_types, frequency, alert_threshold_points,
                webhook_url, notify_email, last_run_at, next_run_at, owner_session_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
               ON CONFLICT(vendor_id) DO UPDATE SET
                 mode=excluded.mode, detector_types=excluded.detector_types,
                 frequency=excluded.frequency, alert_threshold_points=excluded.alert_threshold_points,
                 webhook_url=excluded.webhook_url, notify_email=excluded.notify_email,
                 next_run_at=excluded.next_run_at, owner_session_hash=excluded.owner_session_hash""",
            (vendor_id, mode, json.dumps(detector_types), frequency, alert_threshold_points,
             webhook_url, notify_email, next_run, owner_session_hash),
        )


def get_monitoring_config(vendor_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM monitoring_configs WHERE vendor_id = ?", (vendor_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["detector_types"] = json.loads(d["detector_types"])
        return d


def list_due_continuous_monitors(now_iso: str) -> list[dict]:
    """Returns monitoring configs in 'continuous' mode whose next_run_at has passed."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM monitoring_configs WHERE mode = 'continuous' AND (next_run_at IS NULL OR next_run_at <= ?)",
            (now_iso,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detector_types"] = json.loads(d["detector_types"])
            out.append(d)
        return out


def mark_monitor_run(vendor_id: str, frequency: str) -> None:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    next_run = _compute_next_run(frequency)
    with _connect() as conn:
        conn.execute(
            "UPDATE monitoring_configs SET last_run_at = ?, next_run_at = ? WHERE vendor_id = ?",
            (now, next_run, vendor_id),
        )


def _compute_next_run(frequency: str) -> str:
    delta_seconds = 7 * 86400 if frequency == "weekly" else 86400
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + delta_seconds))


# --- Score history ---

def record_score(vendor_id: str, detector_type: str, score: int | None, rating_letter: str | None, summary: str) -> None:
    with _connect() as conn:
        conn.execute(
            """INSERT INTO score_history (vendor_id, detector_type, score, rating_letter, summary, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (vendor_id, detector_type, score, rating_letter, summary, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )


def get_score_history(vendor_id: str, detector_type: str | None = None, limit: int = 100) -> list[dict]:
    with _connect() as conn:
        if detector_type:
            rows = conn.execute(
                "SELECT * FROM score_history WHERE vendor_id = ? AND detector_type = ? ORDER BY recorded_at DESC LIMIT ?",
                (vendor_id, detector_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM score_history WHERE vendor_id = ? ORDER BY recorded_at DESC LIMIT ?",
                (vendor_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]


def get_latest_score(vendor_id: str, detector_type: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM score_history WHERE vendor_id = ? AND detector_type = ? ORDER BY recorded_at DESC LIMIT 1",
            (vendor_id, detector_type),
        ).fetchone()
        return dict(row) if row else None


# --- Alerts ---

def record_alert(vendor_id: str, detector_type: str, previous_score: int, new_score: int) -> int:
    drop = previous_score - new_score
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO alerts (vendor_id, detector_type, previous_score, new_score, drop_points, triggered_at, delivered)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (vendor_id, detector_type, previous_score, new_score, drop, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        return cursor.lastrowid


def mark_alert_delivered(alert_id: int, error: str | None = None) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE alerts SET delivered = ?, delivery_error = ? WHERE id = ?",
            (0 if error else 1, error, alert_id),
        )


def list_recent_alerts(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
