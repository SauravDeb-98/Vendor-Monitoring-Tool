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
from app.detectors.full_registry import get_active_registry_summary, get_active_by_domain
from app.domain_discovery import discover_domain
from app.monitoring import store as monitoring_store
from app.ingestion import _clean_url, _extract_domain
from app.detector_export import build_export_workbook
from app.executive_report import build_executive_pdf
from app import audit_log

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
    """
    Returns every vendor in the shared inventory (this tool has no login,
    so the inventory is global, not per-session — consistent with how
    /api/monitoring and /api/alerts already behave). Each vendor entry is
    enriched with its monitoring mode and most recent vulnerability score
    (if any), so the Vendors tab list view can render a useful summary row
    per vendor without firing a separate request per vendor.
    """
    monitoring_store.init_store()
    vendors = monitoring_store.list_vendors()
    for v in vendors:
        config = monitoring_store.get_monitoring_config(v["vendor_id"])
        v["monitoring_mode"] = config["mode"] if config else "ad_hoc"
        v["monitoring_frequency"] = config["frequency"] if config else None
        latest = monitoring_store.get_latest_score(v["vendor_id"], "vulnerability")
        v["latest_score"] = latest["score"] if latest else None
        v["latest_rating"] = latest["rating_letter"] if latest else None
        v["last_scanned_at"] = latest["recorded_at"] if latest else None
    return JSONResponse({"vendors": vendors})


@router.get("/api/vendors/{vendor_id}")
async def get_vendor_detail(vendor_id: str):
    """
    Combined detail view for the Vendors tab: vendor identity, monitoring
    configuration (if any), and full score history across all detector
    types. This intentionally returns the same shape as the pre-existing
    GET /api/monitoring/{vendor_id} (kept as-is for backward compatibility
    with anything already calling it) — exposed under /api/vendors/ too
    since that's the more discoverable path for a vendor-detail UI to call.
    """
    monitoring_store.init_store()
    vendor = monitoring_store.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found in inventory.")
    config = monitoring_store.get_monitoring_config(vendor_id)
    history = monitoring_store.get_score_history(vendor_id, limit=200)
    return JSONResponse({"vendor": vendor, "config": config, "score_history": history})


@router.put("/api/vendors/{vendor_id}")
async def update_vendor_detail(vendor_id: str, request: Request, payload: dict):
    """
    Updates a vendor's own name/domain AND, optionally, its monitoring
    settings in one call — the "modify everything" entry point for the
    Vendors tab's edit view. Vendor identity (name/domain) has no
    per-session ownership concept in this tool (the inventory itself is
    shared/global, matching list_vendor_inventory above), but monitoring
    settings retain the existing ownership check from
    set_continuous_monitoring, so editing someone else's monitoring
    schedule still requires being the session that originally set it up.
    """
    monitoring_store.init_store()
    vendor = monitoring_store.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found in inventory.")

    payload = payload or {}
    new_name = (payload.get("name") or vendor["name"]).strip()
    new_domain_raw = (payload.get("domain") or vendor["domain"]).strip()
    cleaned = _clean_url(new_domain_raw) or f"https://{new_domain_raw}"
    new_domain = _extract_domain(cleaned)

    if not new_name:
        raise HTTPException(status_code=400, detail="Vendor name cannot be empty.")

    ok = monitoring_store.update_vendor(vendor_id, new_name, new_domain)
    if not ok:
        raise HTTPException(
            status_code=409,
            detail=f"Another vendor already uses the domain '{new_domain}'. Choose a different domain or merge the two entries manually.",
        )

    if "monitoring" in payload:
        m = payload["monitoring"] or {}
        session_token = _get_session_from_request(request)
        session_hash = _hash_session(session_token)
        existing_config = monitoring_store.get_monitoring_config(vendor_id)
        if existing_config and existing_config.get("owner_session_hash"):
            if existing_config["owner_session_hash"] != session_hash:
                raise HTTPException(status_code=403, detail="Not authorized to modify monitoring for this vendor.")

        requested_types = m.get("detector_types") or (existing_config["detector_types"] if existing_config else None) or [DetectorType.VULNERABILITY.value]
        try:
            detector_types = [DetectorType(t).value for t in requested_types]
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid detector type: {exc}")

        frequency = m.get("frequency", existing_config["frequency"] if existing_config else "daily")
        if frequency not in ("daily", "weekly"):
            raise HTTPException(status_code=400, detail="frequency must be 'daily' or 'weekly'.")

        mode = m.get("mode", existing_config["mode"] if existing_config else "ad_hoc")
        if mode not in ("ad_hoc", "continuous"):
            raise HTTPException(status_code=400, detail="mode must be 'ad_hoc' or 'continuous'.")

        monitoring_store.set_monitoring_config(
            vendor_id=vendor_id,
            mode=mode,
            detector_types=detector_types,
            frequency=frequency,
            alert_threshold_points=int(m.get("alert_threshold_points", existing_config["alert_threshold_points"] if existing_config else 20)),
            owner_session_hash=session_hash,
            webhook_url=m.get("webhook_url", existing_config.get("webhook_url") if existing_config else None),
            notify_email=m.get("notify_email", existing_config.get("notify_email") if existing_config else None),
        )

    return JSONResponse({"vendor_id": vendor_id, "status": "updated", "name": new_name, "domain": new_domain})


@router.delete("/api/vendors/{vendor_id}")
async def delete_vendor_detail(vendor_id: str):
    """Removes a vendor from the inventory entirely, including monitoring
    config, score history, and alerts — see monitoring_store.delete_vendor
    for why this is a multi-table delete rather than relying on cascade."""
    monitoring_store.init_store()
    vendor = monitoring_store.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found in inventory.")
    monitoring_store.delete_vendor(vendor_id)
    return JSONResponse({"vendor_id": vendor_id, "status": "deleted"})


@router.post("/api/vendors/{vendor_id}/rescan")
async def rescan_vendor(vendor_id: str, payload: dict = None):
    """
    Convenience wrapper around the existing ad-hoc /api/detect flow for a
    single, already-known vendor: looks up the vendor's current name/domain
    from the inventory so the Vendors tab can offer a one-click "Scan now"
    action without the caller needing to re-supply vendor identity. Uses
    the vendor's existing monitoring detector_types if configured,
    otherwise defaults to the vulnerability detector — same default
    set_continuous_monitoring uses when no detector_types are specified.
    """
    monitoring_store.init_store()
    vendor = monitoring_store.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found in inventory.")

    config = monitoring_store.get_monitoring_config(vendor_id)
    requested_types = (payload or {}).get("detector_types") or (config["detector_types"] if config else None) or [DetectorType.VULNERABILITY.value]
    try:
        # _run_detect_job (and run_detectors_for_vendors underneath it)
        # expects a list of DetectorType enum members, matching the
        # convention used by the original /api/detect endpoint
        # (start_detect_job, a few lines below) — NOT a list of plain
        # .value strings. An earlier version of this endpoint passed
        # strings here, which crashed with "'str' object has no attribute
        # 'value'" once the job actually ran the detectors.
        detector_types = [DetectorType(t) for t in requested_types]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid detector type: {exc}")

    job_id = str(uuid.uuid4())
    _detect_jobs[job_id] = {"status": "queued", "results": None, "error": None}
    asyncio.create_task(_run_detect_job(job_id, [(vendor["name"], vendor["domain"])], detector_types))
    return JSONResponse({"request_id": job_id})


@router.get("/api/vendors/{vendor_id}/last-report")
async def download_vendor_last_report(vendor_id: str):
    """
    Builds and returns a PDF report from the vendor's most recently
    recorded scores in score_history — NOT from the in-memory _detect_jobs
    dict, since that's ephemeral (cleared on server restart, and never
    keyed by vendor_id in the first place). This means "download last
    report" works for any vendor with at least one persisted scan result,
    regardless of how long ago that scan ran or whether the original
    detect job/process is still around.
    """
    monitoring_store.init_store()
    vendor = monitoring_store.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found in inventory.")

    history = monitoring_store.get_score_history(vendor_id, limit=200)
    if not history:
        raise HTTPException(
            status_code=404,
            detail="No scan results recorded yet for this vendor. Run a scan first.",
        )

    # Reduce to the single latest row per detector_type (history is already
    # ordered most-recent-first from get_score_history).
    latest_by_type: dict[str, dict] = {}
    for row in history:
        if row["detector_type"] not in latest_by_type:
            latest_by_type[row["detector_type"]] = row

    vendor_results = [{
        "vendor_name": vendor["name"],
        "domain": vendor["domain"],
        "results": [
            {
                "detector": row["detector_type"],
                "detector_label": DETECTOR_LABELS.get(DetectorType(row["detector_type"]), row["detector_type"]),
                "risk_score": row["score"],
                "rating_letter": row["rating_letter"],
                "summary": row["summary"],
                "detail_items": [],
                "error": None,
            }
            for row in latest_by_type.values()
        ],
    }]

    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = os.path.join(tmp_dir, "vendor_report.pdf")
        build_executive_pdf(
            output_path=output_path,
            vendor_results=vendor_results,
            registry_by_domain=get_active_by_domain(),
            mttd_seconds=None,
            drift_index=None,
            generated_for=f"{vendor['name']} — Threat Detection Report",
        )
        with open(output_path, "rb") as f:
            pdf_bytes = f.read()

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in vendor["name"])
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_threat_report.pdf"'},
    )


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
        vendor_ids_by_domain = {}
        for name, domain in vendor_inputs:
            vname, rdomain, discovery_info = await _resolve_vendor_input(name, domain)
            resolved_vendors.append(SimpleVendor(vname, rdomain))
            if discovery_info:
                discovery_notes.append(discovery_info)
            vendor_ids_by_domain[rdomain] = monitoring_store.upsert_vendor(vname, rdomain)

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
            # Record each detector's result to score_history, the same way
            # the continuous-monitoring scheduler does (see
            # monitoring/scheduler.py:_run_one_monitored_vendor). Before
            # this, score_history was only ever populated for vendors with
            # continuous monitoring turned on — an ad-hoc, one-off scan
            # left no trace at all, so a vendor management view with a
            # "latest results" panel would show nothing for the vast
            # majority of vendors (anyone who had only ever run a manual
            # scan, which is everyone before continuous monitoring exists
            # as a UI feature).
            vendor_id = vendor_ids_by_domain.get(v.domain)
            if vendor_id:
                for r in vendor_results:
                    if r.error:
                        continue  # don't pollute history with a failed-detector run
                    monitoring_store.record_score(
                        vendor_id, r.detector.value, r.risk_score, r.rating_letter, r.summary,
                    )

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


@router.get("/api/registry")
async def get_full_registry():
    """
    Returns the detector registry, filtered to ACTIVE and BYO_KEY entries
    only — the ~23 NOT_IMPLEMENTED slots are intentionally excluded from
    this public-facing response (per product decision: showing a long list
    of "not implemented" rows read as clutter/broken functionality to
    visitors, rather than as the transparency gesture it was intended to
    be). The full 35-slot catalog, including every NOT_IMPLEMENTED entry
    and its specific gap_category/gap_reason, still lives in
    app/detectors/full_registry.py as internal documentation of deliberate
    scope decisions — it's just not served here anymore.
    """
    return JSONResponse({
        "summary": get_active_registry_summary(),
        "by_domain": {
            domain: [
                {
                    "det_id": d.det_id, "domain": d.domain, "name": d.name, "mechanism": d.mechanism,
                    "monitoring_mode": d.monitoring_mode, "risk_priority": d.risk_priority,
                    "implementation_status": d.implementation_status, "example_sources": d.example_sources,
                    "gap_category": d.gap_category, "gap_reason": d.gap_reason,
                    "internal_detector_key": d.internal_detector_key,
                }
                for d in specs
            ]
            for domain, specs in get_active_by_domain().items()
        },
    })


@router.get("/api/kpis")
async def get_kpi_metrics():
    """
    Quick-glance KPI metrics for the dashboard's middle section: total
    monitored vendors, critical/high priority detector coverage, and
    continuous-scan health (how many continuously-monitored vendors had
    a successful run recently vs. are stale/erroring).
    """
    monitoring_store.init_store()
    vendors = monitoring_store.list_vendors()
    continuous_configs = []
    for v in vendors:
        config = monitoring_store.get_monitoring_config(v["vendor_id"])
        if config and config["mode"] == "continuous":
            continuous_configs.append(config)

    registry_summary = get_active_registry_summary()
    recent_alerts = monitoring_store.list_recent_alerts(limit=10)

    return JSONResponse({
        "total_monitored_vendors": len(vendors),
        "continuous_monitoring_count": len(continuous_configs),
        "ad_hoc_only_count": len(vendors) - len(continuous_configs),
        "detector_registry": registry_summary,
        "recent_alert_count": len(recent_alerts),
    })


@router.get("/api/concentration-clusters")
async def get_concentration_clusters():
    """
    Runs the concentration-risk detector across the full vendor inventory
    and returns vendors clustered by shared hosting/CDN provider — the
    'which vendors share fourth-party infrastructure' view for the
    dashboard's entity-relationship / clustering toggle.
    """
    monitoring_store.init_store()
    vendors = monitoring_store.list_vendors()
    if not vendors:
        return JSONResponse({"clusters": {}})

    simple_vendors = [SimpleVendor(v["name"], v["domain"]) for v in vendors]
    results_by_domain = await run_detectors_for_vendors(simple_vendors, [DetectorType.CONCENTRATION_RISK])

    from app.detectors.concentration_risk import ConcentrationResult
    concentration_results = []
    for v in simple_vendors:
        dr_list = results_by_domain.get(v.domain, [])
        if dr_list:
            dr = dr_list[0]
            detail = dr.detail_items[0] if dr.detail_items else {}
            concentration_results.append(ConcentrationResult(
                domain=v.domain,
                resolved_ips=detail.get("resolved_ips", []),
                asn=detail.get("asn"),
                asn_organization=detail.get("asn_organization"),
                detected_provider=detail.get("detected_provider"),
                evidence=detail.get("evidence"),
            ))

    from app.detectors.concentration_risk import cluster_vendors_by_provider
    clusters = cluster_vendors_by_provider(concentration_results)

    # Map back domain -> vendor name for display
    domain_to_name = {v.domain: v.name for v in simple_vendors}
    clusters_with_names = {
        provider: [{"domain": d, "name": domain_to_name.get(d, d)} for d in domains]
        for provider, domains in clusters.items()
    }
    return JSONResponse({"clusters": clusters_with_names})


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


@router.get("/api/detect/{request_id}/export-executive-pdf")
async def export_detect_job_to_executive_pdf(request_id: str):
    """
    Generates the boardroom-ready executive PDF (Slate/Deep-Blue theme,
    KPIs including MTTD and Security Drift Index, the active detector
    registry matrix, and operational runbook) for a completed detect job.
    The registry matrix here matches the live dashboard: ACTIVE/BYO_KEY
    detectors only, with NOT_IMPLEMENTED slots excluded for the same
    consistency reason as the dashboard's /api/registry endpoint.
    """
    job = _detect_jobs.get(request_id)
    if not job:
        raise HTTPException(status_code=404, detail="Detection job not found.")
    if job.get("status") != "complete" or not job.get("results"):
        raise HTTPException(status_code=409, detail=f"Job not ready for export (status: {job.get('status')}).")

    monitoring_store.init_store()
    audit_log.init_audit_log()

    mttd = audit_log.get_mean_time_to_detect(hours=24)
    drift = monitoring_store.get_vendor_security_drift_index()

    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = os.path.join(tmp_dir, "executive_report.pdf")
        build_executive_pdf(
            output_path=output_path,
            vendor_results=job["results"],
            registry_by_domain=get_active_by_domain(),
            mttd_seconds=mttd,
            drift_index=drift,
        )
        with open(output_path, "rb") as f:
            pdf_bytes = f.read()

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="vendor_threat_executive_report.pdf"'},
    )
