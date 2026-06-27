"""
Risk Assessment Tool — Vendor Inventory & Report History Store
--------------------------------------------------------------------
SQLite-backed persistence for the Risk Assessment tool (the Excel-upload
/ single-vendor-add flow in index.html), separate from the unrelated
monitoring.sqlite3 used by the Threat Detector tool — same separation
rationale as that module: different purpose, different lifecycle, no
shared schema to avoid cross-contaminating the two tools later.

What this store adds, by design:
  - A persistent vendor inventory: every vendor that's ever been scanned
    (via Excel import OR the single-vendor "Add a Vendor" flow) gets
    upserted here, keyed by (domain, owner_session_hash), so each browser
    session's inventory view survives across scans within that session
    without being affected by, or affecting, any other session's view of
    the same vendor domain.
  - A report history per vendor: each completed scan that produces a PDF
    records vendor_id, job_id, score, tier, created_at, and expires_at.
    This lets the UI show "last assessed 3 days ago, score 82" and offer
    a re-download link, without keeping the encrypted PDF bytes anywhere
    but the existing on-disk OUTPUT_DIR location (this table stores only
    metadata + the same job_id main.py already uses to locate the file).

Retention model (per product decision): encrypted PDFs are kept for
REPORT_RETENTION_MINUTES (now 7 days, see main.py) rather than 30
minutes, specifically so "click a vendor in the inventory and download
its report anytime" is literally true within that window. The 30-minute
window was the original tighter default; 7 days is a deliberate
trade-off toward usability, still bounded (not indefinite) and still
encrypted at rest via the same Fernet mechanism in report_encryption.py.

Ownership: report rows store the same owner_session_hash pattern used
elsewhere in this codebase (audit_log.py, monitoring/store.py) — a
one-way hash of the session token, never the raw token — so that listing
"my vendor inventory" only surfaces vendors/reports created by sessions
that share the requester's hash, without ever persisting a reversible
session identifier in this table.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "..", "report_store.sqlite3")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors (
    vendor_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    website TEXT NOT NULL,
    domain TEXT NOT NULL,
    owner_session_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_scanned_at TEXT,
    UNIQUE(domain, owner_session_hash)
);
CREATE INDEX IF NOT EXISTS idx_vendors_owner ON vendors(owner_session_hash);

CREATE TABLE IF NOT EXISTS vendor_reports (
    report_id TEXT PRIMARY KEY,
    vendor_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    score INTEGER,
    tier TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    owner_session_hash TEXT NOT NULL,
    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
);
CREATE INDEX IF NOT EXISTS idx_reports_vendor ON vendor_reports(vendor_id, created_at);
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


def hash_session(session_token: str) -> str:
    """One-way hash of a session token, same pattern as audit_log.py —
    never store the raw token, only a value we can compare against future
    requests' hashed tokens for ownership checks."""
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()


# --- Vendor inventory ---

def upsert_vendor(name: str, website: str, domain: str, owner_session_hash: str) -> str:
    """
    Returns vendor_id. Re-scanning a domain THIS SAME SESSION has already
    scanned updates name/website/last_scanned_at on the existing row rather
    than duplicating it. Uniqueness is scoped to (domain, owner_session_hash)
    — not domain alone — so two different sessions scanning the same vendor
    domain each get their own independent inventory row, exactly the way
    report ownership already works elsewhere in this store. An earlier
    version of this function scoped uniqueness to domain only, which meant
    a second session's scan of an already-scanned domain would silently
    update someone else's vendor row's name/website/timestamp and would
    NOT make that vendor visible in the second session's own inventory
    (list_vendors_for_owner filters by owner_session_hash on the vendor
    row) even though a real report had just been generated for them.
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _connect() as conn:
        existing = conn.execute(
            "SELECT vendor_id FROM vendors WHERE domain = ? AND owner_session_hash = ?",
            (domain, owner_session_hash),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE vendors SET name = ?, website = ?, last_scanned_at = ? WHERE vendor_id = ?",
                (name, website, now, existing["vendor_id"]),
            )
            return existing["vendor_id"]
        vendor_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO vendors (vendor_id, name, website, domain, owner_session_hash, created_at, last_scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (vendor_id, name, website, domain, owner_session_hash, now, now),
        )
        return vendor_id


def list_vendors_for_owner(owner_session_hash: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM vendors WHERE owner_session_hash = ? ORDER BY last_scanned_at DESC",
            (owner_session_hash,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_vendor(vendor_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vendor_id,)).fetchone()
        return dict(row) if row else None


# --- Report history ---

def record_report(vendor_id: str, job_id: str, score: int | None, tier: str | None,
                   owner_session_hash: str, retention_minutes: int) -> str:
    now = time.time()
    report_id = str(uuid.uuid4())
    with _connect() as conn:
        conn.execute(
            """INSERT INTO vendor_reports
               (report_id, vendor_id, job_id, score, tier, created_at, expires_at, owner_session_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (report_id, vendor_id, job_id, score, tier,
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + retention_minutes * 60)),
             owner_session_hash),
        )
        return report_id


def list_reports_for_vendor(vendor_id: str, owner_session_hash: str) -> list[dict]:
    """Only returns reports owned by the requesting session — same ownership
    boundary as everywhere else report data is served in this codebase."""
    with _connect() as conn:
        rows = conn.execute(
            """SELECT * FROM vendor_reports WHERE vendor_id = ? AND owner_session_hash = ?
               ORDER BY created_at DESC""",
            (vendor_id, owner_session_hash),
        ).fetchall()
        return [dict(r) for r in rows]


def get_latest_report_for_vendor(vendor_id: str, owner_session_hash: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """SELECT * FROM vendor_reports WHERE vendor_id = ? AND owner_session_hash = ?
               ORDER BY created_at DESC LIMIT 1""",
            (vendor_id, owner_session_hash),
        ).fetchone()
        return dict(row) if row else None


def delete_expired_report_rows(now_iso: str) -> None:
    """Cleans up metadata rows whose underlying encrypted PDF has already
    been swept from disk by main.py's existing cleanup task, so the
    inventory UI doesn't keep offering a download link for a file that
    no longer exists. This does NOT delete the vendor row itself — only
    the report-history entry — since the vendor should remain visible in
    the inventory (re-scannable) even after its old report expires."""
    with _connect() as conn:
        conn.execute("DELETE FROM vendor_reports WHERE expires_at <= ?", (now_iso,))
