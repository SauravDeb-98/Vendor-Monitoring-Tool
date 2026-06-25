"""
Main FastAPI application
---------------------------
Public, no-login web app. Flow:
  1. POST /api/scan with an Excel file (+ optional Claude API key) -> returns job_id
  2. GET /api/jobs/{job_id} -> poll status/progress
  3. GET /api/jobs/{job_id}/report -> download generated PDF once complete

Rate limiting: simple in-memory per-IP throttle, since this app has no auth
and no required API key. This protects server compute/bandwidth regardless
of whether a visitor brings their own Claude key.

Data retention: uploaded Excel bytes are processed entirely in memory and
are never written to disk (see start_scan — file_bytes is read into a
Python bytes object, passed directly to the parser, and never touched by
any file-write call). Generated PDF reports ARE written to disk (so they
can be served back for download) but are automatically deleted
REPORT_RETENTION_MINUTES after creation by a background sweep task, so
vendor data does not persist indefinitely on the server.
Session binding: each browser session is issued a random, HttpOnly,
SameSite=Lax cookie on first contact with /api/scan. Every job is tagged
with the session token that created it. The job-status and report-download
endpoints both verify the requester's session token matches the job's
owner before returning anything — a visitor who somehow learns or guesses
another job's UUID still cannot view its status or download its report.
This is in addition to, not a replacement for, the 30-minute auto-delete
above; the two protections cover different threat windows.

Audit logging: every scan is recorded in a local SQLite file
(audit_log.py) for accountability — timestamp, vendor COUNT, status, and
hashed (not raw) session/IP identifiers. Vendor names, vendor URLs, scan
findings, narrative text, and the AI key are never written to this log by
construction; the logging functions don't accept those values as
parameters. See audit_log.py's module docstring for the full schema and
the ephemeral-disk caveat on Render's free tier.

Encryption at rest: the generated PDF is encrypted (Fernet/AES, via
report_encryption.py) before being written to disk, using a server-side
key from the REPORT_ENCRYPTION_KEY environment variable. It is decrypted
only in memory, at the moment of serving a download to the verified job
owner, and the decrypted bytes are never themselves written back to disk.
This protects against casual/lazy disk exposure (backup snapshots, log
aggregators, anyone browsing the filesystem without the key) but not
against a full compromise of the running server process itself — see
report_encryption.py's module docstring for the complete threat model.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import time
import uuid
from collections import defaultdict, deque

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.ingestion import parse_vendor_excel, IngestionError
from app.scanner.engine import scan_vendors
from app.compliance.engine import evaluate_compliance, deduplicate_and_cap
from app.scoring import compute_score
from app.ai_analysis import generate_vendor_narrative, generate_executive_summary
from app.reporting.pdf_builder import build_pdf_report
from app import audit_log
from app import report_encryption
from app import detector_routes
from app.monitoring.scheduler import run_monitoring_scheduler_loop

APP_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(APP_DIR, "..", "generated_reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_VENDORS_PER_RUN = 25         # protects compute even for legitimate use
RATE_LIMIT_WINDOW_SECONDS = 86400
RATE_LIMIT_MAX_REQUESTS = 5      # per-IP scans per day, independent of AI key use
REPORT_RETENTION_MINUTES = 30    # generated PDFs are deleted this long after creation
CLEANUP_SWEEP_INTERVAL_SECONDS = 120  # how often the background sweep checks for expired files
SESSION_COOKIE_NAME = "vrt_session"
SESSION_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24  # cookie itself lasts 24h; jobs still expire in 30min regardless
ADMIN_STATS_TOKEN = os.environ.get("ADMIN_STATS_TOKEN")  # set this in Render's env vars to enable /api/admin/stats

app = FastAPI(title="Third-Party Vendor Risk Assessment Tool")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(detector_routes.router)

_rate_buckets: dict[str, deque] = defaultdict(deque)
_jobs: dict[str, dict] = {}


async def _cleanup_expired_reports() -> None:
    """
    Background task: periodically scans OUTPUT_DIR and deletes any PDF
    older than REPORT_RETENTION_MINUTES, regardless of in-memory job state.
    Scanning the directory directly (rather than only relying on the
    in-memory _jobs dict) also cleans up any file left behind by a process
    restart, since _jobs is not persisted across restarts.
    """
    retention_seconds = REPORT_RETENTION_MINUTES * 60
    while True:
        try:
            now = time.time()
            for filename in os.listdir(OUTPUT_DIR):
                if not filename.endswith(".pdf.enc"):
                    continue
                filepath = os.path.join(OUTPUT_DIR, filename)
                try:
                    age_seconds = now - os.path.getmtime(filepath)
                    if age_seconds > retention_seconds:
                        os.remove(filepath)
                        job_id = filename[:-len(".pdf.enc")]
                        job = _jobs.get(job_id)
                        if job is not None:
                            job["status"] = "expired"
                            job["report_path"] = None
                except OSError:
                    continue  # file may have been removed concurrently; skip
        except Exception:
            pass  # never let the sweep loop die from a transient error
        await asyncio.sleep(CLEANUP_SWEEP_INTERVAL_SECONDS)


@app.on_event("startup")
async def _start_background_tasks() -> None:
    audit_log.init_audit_log()
    asyncio.create_task(_cleanup_expired_reports())
    asyncio.create_task(run_monitoring_scheduler_loop())


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def _resolve_session_token(request: Request) -> tuple[str, bool]:
    """
    Returns (token, is_new). If the request already carries a well-formed
    session cookie, reuse it (is_new=False). Otherwise generate a fresh
    cryptographically random token (is_new=True) — the caller is
    responsible for attaching it to the actual outgoing response via
    _set_session_cookie_if_new, since FastAPI's injected Response
    parameter is discarded if the route handler returns its own response
    object instead of mutating the injected one.
    """
    existing = request.cookies.get(SESSION_COOKIE_NAME)
    if existing and len(existing) >= 32:
        return existing, False
    return secrets.token_urlsafe(32), True


def _is_request_https(request: Request) -> bool:
    """
    True if the original client request was HTTPS. Checks request.url.scheme
    first (correct when uvicorn is run with --proxy-headers and the proxy is
    in --forwarded-allow-ips, as configured in this project's Dockerfile).
    Falls back to checking the X-Forwarded-Proto header directly, in case
    uvicorn's proxy-header trust doesn't propagate for any reason — this
    matters because Render terminates TLS at its edge and forwards to the
    container over plain HTTP, so getting this wrong would silently send the
    session cookie without the Secure flag in production.
    """
    if request.url.scheme == "https":
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return forwarded_proto.split(",")[0].strip().lower() == "https"


def _set_session_cookie_if_new(request: Request, response, token: str) -> None:
    if request.cookies.get(SESSION_COOKIE_NAME) == token:
        return  # already had this exact cookie; nothing to set
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=_is_request_https(request),
    )


def _require_job_owner(job: dict, request: Request) -> None:
    """
    Raises a 403 if the requester's session cookie does not match the
    session that created this job. Deliberately returns the same generic
    error for "wrong owner" as for "job not found" elsewhere in this file,
    so the API does not leak whether a given job ID exists to someone who
    doesn't own it.
    """
    requester_session = request.cookies.get(SESSION_COOKIE_NAME)
    if not requester_session or requester_session != job.get("owner_session"):
        raise HTTPException(status_code=403, detail="Not authorized to access this job.")


def _check_rate_limit(ip: str) -> None:
    now = time.time()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_MAX_REQUESTS} scans per IP per day. Please try again later.",
        )
    bucket.append(now)


async def _run_assessment(job_id: str, vendors, api_key: str | None, started_at: float) -> None:
    job = _jobs[job_id]
    try:
        job["status"] = "scanning"
        job["progress"] = "Scanning vendor domains (passive OSINT)..."
        scan_results = await scan_vendors(vendors, concurrency=4)

        job["status"] = "analyzing"
        vendor_reports = []
        for vendor in vendors:
            job["progress"] = f"Analyzing {vendor.name}..."
            scan = scan_results[vendor.domain]
            findings = deduplicate_and_cap(evaluate_compliance(scan))
            score, tier = compute_score(findings)
            narrative = await generate_vendor_narrative(
                vendor.name, vendor.domain, score, tier.label, findings, api_key,
            )
            vendor_reports.append({
                "name": vendor.name,
                "website": vendor.website,
                "domain": vendor.domain,
                "score": score,
                "tier": tier.label,
                "narrative": narrative,
                "findings": findings,
            })

        job["status"] = "rendering"
        job["progress"] = "Building PDF report..."
        output_path = os.path.join(OUTPUT_DIR, f"{job_id}.pdf.enc")

        def _build_and_encrypt() -> bytes:
            # build_pdf_report writes to a temp path on disk (ReportLab's
            # SimpleDocTemplate requires a filesystem path), then we read
            # those plaintext bytes back, encrypt them, and only the
            # ciphertext is written to the real output location. The
            # plaintext temp file is removed immediately after.
            tmp_path = os.path.join(OUTPUT_DIR, f"{job_id}.tmp.pdf")
            build_pdf_report(vendor_reports, tmp_path)
            with open(tmp_path, "rb") as f:
                plaintext = f.read()
            os.remove(tmp_path)
            return report_encryption.encrypt_bytes(plaintext)

        ciphertext = await asyncio.to_thread(_build_and_encrypt)
        with open(output_path, "wb") as f:
            f.write(ciphertext)

        job["status"] = "complete"
        job["progress"] = "Done"
        job["report_path"] = output_path
        job["summary"] = [
            {"name": v["name"], "score": v["score"], "tier": v["tier"]} for v in vendor_reports
        ]
        audit_log.record_scan_finished(job_id, "complete", started_at)
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)
        # error_type is the exception's class name only (e.g. "TimeoutError"),
        # never str(exc), since the full message can contain vendor-identifying
        # details (e.g. a domain name embedded in a connection error string).
        audit_log.record_scan_finished(job_id, "failed", started_at, error_type=type(exc).__name__)


@app.post("/api/scan")
async def start_scan(
    request: Request,
    file: UploadFile = File(...),
    claude_api_key: str | None = Form(default=None),
):
    ip = _client_ip(request)
    _check_rate_limit(ip)
    session_token, _is_new = _resolve_session_token(request)

    if not file.filename.lower().endswith((".xlsx", ".xls")):
        raise HTTPException(status_code=400, detail="Please upload an Excel file (.xlsx or .xls).")

    file_bytes = await file.read()
    if len(file_bytes) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 5MB).")

    try:
        vendors = parse_vendor_excel(file_bytes)
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if len(vendors) > MAX_VENDORS_PER_RUN:
        raise HTTPException(
            status_code=400,
            detail=f"Too many vendors ({len(vendors)}). Max {MAX_VENDORS_PER_RUN} per run on this public instance.",
        )

    job_id = str(uuid.uuid4())
    started_at = time.time()
    _jobs[job_id] = {
        "status": "queued", "progress": "Queued", "vendor_count": len(vendors),
        "owner_session": session_token,
    }

    api_key = claude_api_key.strip() if claude_api_key and claude_api_key.strip() else None
    audit_log.record_scan_started(job_id, session_token, ip, len(vendors), used_ai_key=api_key is not None)
    asyncio.create_task(_run_assessment(job_id, vendors, api_key, started_at))

    result = JSONResponse({"job_id": job_id, "vendor_count": len(vendors)})
    _set_session_cookie_if_new(request, result, session_token)
    return result


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str, request: Request):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    _require_job_owner(job, request)
    return JSONResponse({k: v for k, v in job.items() if k not in ("report_path", "owner_session")})


@app.get("/api/jobs/{job_id}/report")
async def get_job_report(job_id: str, request: Request):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    _require_job_owner(job, request)
    if job.get("status") == "expired":
        raise HTTPException(
            status_code=410,
            detail=f"This report has expired and was deleted {REPORT_RETENTION_MINUTES} minutes after "
                   f"generation for data confidentiality. Please re-run the assessment to generate a new report.",
        )
    if job.get("status") != "complete":
        raise HTTPException(status_code=409, detail=f"Report not ready (status: {job.get('status')}).")
    report_path = job.get("report_path")
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(
            status_code=410,
            detail=f"This report has expired and was deleted {REPORT_RETENTION_MINUTES} minutes after "
                   f"generation for data confidentiality. Please re-run the assessment to generate a new report.",
        )

    def _read_and_decrypt() -> bytes:
        with open(report_path, "rb") as f:
            ciphertext = f.read()
        return report_encryption.decrypt_bytes(ciphertext)

    try:
        plaintext_pdf = await asyncio.to_thread(_read_and_decrypt)
    except report_encryption.InvalidToken:
        # This happens if the server restarted with a different
        # auto-generated fallback key than the one used to encrypt this
        # specific report (only possible when REPORT_ENCRYPTION_KEY is not
        # set — see report_encryption.py). Treat it the same as expiry
        # from the visitor's perspective, since the report is unrecoverable.
        raise HTTPException(
            status_code=410,
            detail="This report can no longer be decrypted (the server may have restarted). "
                   "Please re-run the assessment to generate a new report.",
        )

    return Response(
        content=plaintext_pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="vendor_risk_assessment_report.pdf"'},
    )


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/admin/stats")
async def admin_stats(request: Request, hours: int = 24):
    """
    Aggregate usage statistics only (counts, not per-job detail) — see
    audit_log.get_usage_stats for exactly what is and isn't included.
    Disabled (404) unless the ADMIN_STATS_TOKEN environment variable is
    set on the server, and requires a matching X-Admin-Token header.
    """
    if not ADMIN_STATS_TOKEN:
        raise HTTPException(status_code=404, detail="Not found.")
    provided = request.headers.get("x-admin-token")
    if not provided or provided != ADMIN_STATS_TOKEN:
        raise HTTPException(status_code=403, detail="Not authorized.")
    return JSONResponse(audit_log.get_usage_stats(hours=hours))


# Serve the frontend last so /api routes take precedence
app.mount("/", StaticFiles(directory=os.path.join(APP_DIR, "static"), html=True), name="static")
