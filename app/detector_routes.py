"""
Detector & Continuous Monitoring API Router
------------------------------------------------
New endpoints for the Cyber Security Vendor Threat Detector feature,
mounted into the main FastAPI app. Kept as a separate router (rather than
added directly to main.py) so the original vendor-risk-report flow stays
untouched and this feature is purely additive.

Endpoints:
  GET    /api/detectors              - list available detector types
  POST   /api/detect                 - ad-hoc detector scan for one or more vendors
  GET    /api/detect/{request_id}    - poll ad-hoc detector job status/results
  GET    /api/vendors                - list vendor inventory
  POST   /api/vendors/discover-domain - domain auto-discovery for a name-only vendor
  POST   /api/monitoring/{vendor_id} - create/update continuous monitoring config
  GET    /api/monitoring/{vendor_id} - get monitoring config + score history
  DELETE /api/monitoring/{vendor_id} - stop continuous monitoring for a vendor
  GET    /api/monitoring             - list all vendors under continuous monitoring
  GET    /api/alerts                 - list recent score-drop alerts

All write/delete operations on monitoring configs reuse the same
session-cookie ownership model already established in main.py
(vrt_session), so one visitor cannot reconfigure or cancel another
visitor's monitored vendors.
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.detectors.registry import DetectorType, ALL_DETECTOR_TYPES, DETECTOR_LABELS, DETECTOR_DESCRIPTIONS
from app.detectors.orchestrator import run_detectors_for_vendors
from app.domain_discovery import discover_domain
from app.monitoring import store as monitoring_store
from app.ingestion import _clean_url, _extract_domain
from app.detector_export import build_export_workbook

router = APIRouter()

DETECT_MAX_VENDORS_PER_RUN = 25
_detect_jobs: dict[str, dict] = {}


def _hash_session(session_token: str | None) -> str:
    if not session_token:
        return ""
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()[:16]


def _get_session_from_request(request: Request) -> str | None:
    return request.cookies.get("vrt_session")


class SimpleVendor:
    def __init__(self, name: str, domain: str):
        self.name = name
        self.domain = domain


@router.get("/api/detectors")
async def list_detectors():
    return JSONResponse({
        "detectors": [
            {"type": dt.value, "label": DETECTOR_LABELS[dt], "description": DETECTOR_DESCRIPTIONS[dt]}
            for dt in ALL_DETECTOR_TYPES
        ]
    })


@router.post("/api/vendors/discover-domain")
async def discover_vendor_domain(payload: dict):
    vendor_name = (payload or {}).get("vendor_name", "").strip()
    if not vendor_name:
        raise HTTPException(status_code=400, detail="vendor_name is required.")
    result = await discover_domain(vendor_name)
    return JSONResponse(result.to_dict())


@router.get("/api/vendors")
async def list_vendor_inventory():
    monitoring_store.init_store()
    return JSONResponse({"vendors": monitoring_store.list_vendors()})


async def _resolve_vendor_input(vendor_name: str, domain: str | None) -> tuple[str, str, dict | None]:
    if domain:
        cleaned = _clean_url(domain)
        if cleaned:
            return vendor_name, _extract_domain(cleaned), None

    discovery = await discover_domain(vendor_name)
    if not discovery.discovered_domain:
        raise HTTPException(
            status_code=400,
            detail=f"Could not determine a domain for '{vendor_name}'. Please provide the vendor's "
                   f"website explicitly. Tried: {', '.join(discovery.candidates_tried)}",
        )
    return vendor_name, discovery.discovered_domain, discovery.to_dict()


async def _run_detect_job(job_id: str, vendor_inputs: list, detector_types: list) -> None:
    job = _detect_jobs[job_id]
    try:
        job["status"] = "running"
        resolved_vendors = []
        discovery_notes = []
        for name, domain in vendor_inputs:
            vname, rdomain, discovery_info = await _resolve_vendor_input(name, domain)
            resolved_vendors.append(SimpleVendor(vname, rdomain))
            if discovery_info:
                discovery_notes.append(discovery_info)
            monitoring_store.upsert_vendor(vname, rdomain)

        results_by_domain = await run_detectors_for_vendors(resolved_vendors, detector_types)

        output = []
        for v in resolved_vendors:
            vendor_results = results_by_domain.get(v.domain, [])
            output.append({
                "vendor_name": v.name,
                "domain": v.domain,
                "results": [
                    {
                        "detector": r.detector.value,
                        "detector_label": DETECTOR_LABELS[r.detector],
                        "risk_score": r.risk_score,
                        "rating_letter": r.rating_letter,
                        "summary": r.summary,
                        "detail_items": r.detail_items,
                        "error": r.error,
                    }
                    for r in vendor_results
                ],
            })

        job["status"] = "complete"
        job["results"] = output
        job["discovery_notes"] = discovery_notes
    except HTTPException as exc:
        job["status"] = "failed"
        job["error"] = exc.detail
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = f"{type(exc).__name__}: {exc}"


@router.post("/api/detect")
async def start_detect_job(request: Request, payload: dict):
    """
    Payload: {"vendors": [{"name": "Oracle", "domain": "oracle.com"}, {"name": "Some Co"}],
              "detector_types": ["exploitation", "vulnerability"]}
    Domain is optional per-vendor; auto-discovery is attempted if absent.
    """
    monitoring_store.init_store()
    vendors_input = (payload or {}).get("vendors", [])
    if not vendors_input:
        raise HTTPException(status_code=400, detail="At least one vendor is required.")
    if len(vendors_input) > DETECT_MAX_VENDORS_PER_RUN:
        raise HTTPException(status_code=400, detail=f"Max {DETECT_MAX_VENDORS_PER_RUN} vendors per request.")

    requested_types = (payload or {}).get("detector_types") or []
    try:
        detector_types = [DetectorType(t) for t in requested_types] if requested_types else ALL_DETECTOR_TYPES
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid detector type: {exc}")

    vendor_inputs = [(v.get("name", "").strip(), (v.get("domain") or "").strip() or None) for v in vendors_input]
    if any(not name for name, _domain in vendor_inputs):
        raise HTTPException(status_code=400, detail="Every vendor entry needs a name.")

    job_id = str(uuid.uuid4())
    _detect_jobs[job_id] = {"status": "queued", "results": None, "error": None}
    asyncio.create_task(_run_detect_job(job_id, vendor_inputs, detector_types))
    return JSONResponse({"request_id": job_id})


@router.get("/api/detect/{request_id}")
async def get_detect_job(request_id: str):
    job = _detect_jobs.get(request_id)
    if not job:
        raise HTTPException(status_code=404, detail="Detection job not found.")
    return JSONResponse(job)


@router.post("/api/monitoring/{vendor_id}")
async def set_continuous_monitoring(vendor_id: str, request: Request, payload: dict):
    monitoring_store.init_store()
    vendor = monitoring_store.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found in inventory.")

    session_token = _get_session_from_request(request)
    session_hash = _hash_session(session_token)

    # Enforce ownership on UPDATE of an existing config: if a config already
    # exists with a real (non-empty) owner hash, only that same session may
    # modify it. A config with no owner on record (e.g. created by a request
    # that had no session cookie at all) has no enforceable prior owner, so
    # the current request is allowed to (re-)establish ownership — but once
    # any non-empty owner hash is on record, it is binding from then on.
    existing_config = monitoring_store.get_monitoring_config(vendor_id)
    if existing_config and existing_config.get("owner_session_hash"):
        if existing_config["owner_session_hash"] != session_hash:
            raise HTTPException(status_code=403, detail="Not authorized to modify monitoring for this vendor.")

    requested_types = (payload or {}).get("detector_types") or []
    try:
        detector_types = [DetectorType(t).value for t in requested_types] if requested_types else [DetectorType.VULNERABILITY.value]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid detector type: {exc}")

    frequency = (payload or {}).get("frequency", "daily")
    if frequency not in ("daily", "weekly"):
        raise HTTPException(status_code=400, detail="frequency must be 'daily' or 'weekly'.")

    monitoring_store.set_monitoring_config(
        vendor_id=vendor_id,
        mode="continuous",
        detector_types=detector_types,
        frequency=frequency,
        alert_threshold_points=int((payload or {}).get("alert_threshold_points", 20)),
        owner_session_hash=session_hash,
        webhook_url=(payload or {}).get("webhook_url"),
        notify_email=(payload or {}).get("notify_email"),
    )
    return JSONResponse({"vendor_id": vendor_id, "status": "monitoring_enabled"})


@router.get("/api/monitoring/{vendor_id}")
async def get_monitoring_status(vendor_id: str):
    monitoring_store.init_store()
    vendor = monitoring_store.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found in inventory.")
    config = monitoring_store.get_monitoring_config(vendor_id)
    history = monitoring_store.get_score_history(vendor_id, limit=200)
    return JSONResponse({"vendor": vendor, "config": config, "score_history": history})


@router.delete("/api/monitoring/{vendor_id}")
async def stop_continuous_monitoring(vendor_id: str, request: Request):
    monitoring_store.init_store()
    config = monitoring_store.get_monitoring_config(vendor_id)
    if not config:
        raise HTTPException(status_code=404, detail="No monitoring configuration found for this vendor.")

    session_token = _get_session_from_request(request)
    session_hash = _hash_session(session_token)
    # Ownership enforcement: if this config has a real owner on record,
    # only that exact session may stop it — a missing/empty requester
    # session must NOT be treated as a match for a missing/empty owner
    # hash once a real owner is established (see set_continuous_monitoring
    # for the matching establish-ownership logic).
    if config.get("owner_session_hash"):
        if config["owner_session_hash"] != session_hash:
            raise HTTPException(status_code=403, detail="Not authorized to modify monitoring for this vendor.")

    monitoring_store.set_monitoring_config(
        vendor_id=vendor_id, mode="ad_hoc", detector_types=config["detector_types"],
        frequency=config["frequency"], alert_threshold_points=config["alert_threshold_points"],
        owner_session_hash=session_hash,
    )
    return JSONResponse({"vendor_id": vendor_id, "status": "monitoring_disabled"})


@router.get("/api/monitoring")
async def list_all_monitoring():
    monitoring_store.init_store()
    vendors = monitoring_store.list_vendors()
    out = []
    for v in vendors:
        config = monitoring_store.get_monitoring_config(v["vendor_id"])
        if config and config["mode"] == "continuous":
            out.append({"vendor": v, "config": config})
    return JSONResponse({"monitored_vendors": out})


@router.get("/api/alerts")
async def list_alerts():
    monitoring_store.init_store()
    return JSONResponse({"alerts": monitoring_store.list_recent_alerts()})


@router.get("/api/detect/{request_id}/export")
async def export_detect_job_to_excel(request_id: str):
    job = _detect_jobs.get(request_id)
    if not job:
        raise HTTPException(status_code=404, detail="Detection job not found.")
    if job.get("status") != "complete" or not job.get("results"):
        raise HTTPException(status_code=409, detail=f"Job not ready for export (status: {job.get('status')}).")

    monitoring_store.init_store()
    monitoring_lookup = {}
    for vendor_entry in job["results"]:
        domain = vendor_entry.get("domain")
        vendors_in_store = monitoring_store.list_vendors()
        match = next((v for v in vendors_in_store if v["domain"] == domain), None)
        if match:
            config = monitoring_store.get_monitoring_config(match["vendor_id"])
            if config:
                monitoring_lookup[domain] = config

    xlsx_bytes = build_export_workbook(job["results"], monitoring_lookup)
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="vendor_threat_detection_export.xlsx"'},
    )
