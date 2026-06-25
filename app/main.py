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
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections import defaultdict, deque

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.ingestion import parse_vendor_excel, IngestionError
from app.scanner.engine import scan_vendors
from app.compliance.engine import evaluate_compliance, deduplicate_and_cap
from app.scoring import compute_score
from app.ai_analysis import generate_vendor_narrative, generate_executive_summary
from app.reporting.pdf_builder import build_pdf_report

APP_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(APP_DIR, "..", "generated_reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_VENDORS_PER_RUN = 25         # protects compute even for legitimate use
RATE_LIMIT_WINDOW_SECONDS = 86400
RATE_LIMIT_MAX_REQUESTS = 5      # per-IP scans per day, independent of AI key use

app = FastAPI(title="Third-Party Vendor Risk Assessment Tool")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_rate_buckets: dict[str, deque] = defaultdict(deque)
_jobs: dict[str, dict] = {}


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


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


async def _run_assessment(job_id: str, vendors, api_key: str | None) -> None:
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
        output_path = os.path.join(OUTPUT_DIR, f"{job_id}.pdf")
        await asyncio.to_thread(build_pdf_report, vendor_reports, output_path)

        job["status"] = "complete"
        job["progress"] = "Done"
        job["report_path"] = output_path
        job["summary"] = [
            {"name": v["name"], "score": v["score"], "tier": v["tier"]} for v in vendor_reports
        ]
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)


@app.post("/api/scan")
async def start_scan(
    request: Request,
    file: UploadFile = File(...),
    claude_api_key: str | None = Form(default=None),
):
    ip = _client_ip(request)
    _check_rate_limit(ip)

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
    _jobs[job_id] = {"status": "queued", "progress": "Queued", "vendor_count": len(vendors)}

    api_key = claude_api_key.strip() if claude_api_key and claude_api_key.strip() else None
    asyncio.create_task(_run_assessment(job_id, vendors, api_key))

    return JSONResponse({"job_id": job_id, "vendor_count": len(vendors)})


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return JSONResponse({k: v for k, v in job.items() if k != "report_path"})


@app.get("/api/jobs/{job_id}/report")
async def get_job_report(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    if job.get("status") != "complete":
        raise HTTPException(status_code=409, detail=f"Report not ready (status: {job.get('status')}).")
    return FileResponse(
        job["report_path"],
        media_type="application/pdf",
        filename="vendor_risk_assessment_report.pdf",
    )


@app.get("/api/health")
async def health():
    return {"status": "ok"}


# Serve the frontend last so /api routes take precedence
app.mount("/", StaticFiles(directory=os.path.join(APP_DIR, "static"), html=True), name="static")
