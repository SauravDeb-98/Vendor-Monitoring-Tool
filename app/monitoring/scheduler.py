"""
Continuous Monitoring Scheduler
------------------------------------
Background worker (an asyncio task, started at app startup alongside the
existing report-cleanup sweep in main.py) that periodically checks for
vendors due for a scheduled scan and runs them.

Design notes:
  - Runs on a fixed poll interval (default 5 minutes) rather than precise
    per-vendor timers, since with potentially many monitored vendors,
    individual asyncio.sleep() timers per vendor would be harder to
    reason about and harder to make resilient to a server restart. The
    poll-and-check-due pattern means a missed check (e.g. server was
    down) is simply caught on the next poll, with no special recovery
    logic needed.
  - Each due vendor's configured detector(s) are run via the same
    orchestrator used for ad-hoc scans (app/detectors/orchestrator.py),
    so there is exactly one code path for "what does running a detector
    mean" — continuous monitoring is just "run the same detectors
    automatically, on a timer, and remember the results."
  - Alert threshold comparison is done per-detector against that
    detector's own most recent recorded score. A detector that doesn't
    produce a numeric score (exploitation, phishing — see registry.py)
    cannot trigger a score-drop alert by definition; only the
    vulnerability detector currently produces a comparable 0-100 score.
  - "Continuous monitoring" tasks should not disrupt platform performance
    (per the original spec) — this is implemented by (a) a low base poll
    frequency, (b) bounded concurrency when multiple vendors are due at
    once, and (c) defensive exception handling so one vendor's failure
    cannot crash the loop.
"""
from __future__ import annotations

import asyncio
import time

from app.detectors.orchestrator import run_detectors_for_vendor
from app.detectors.registry import DetectorType
from app.monitoring import store
from app.monitoring.notifications import send_webhook_alert

MONITOR_POLL_INTERVAL_SECONDS = 5 * 60  # how often the scheduler checks for due vendors
MONITOR_RUN_CONCURRENCY = 3  # max vendors scanned simultaneously when several are due at once


async def _run_one_monitored_vendor(config: dict) -> None:
    vendor = store.get_vendor(config["vendor_id"])
    if not vendor:
        return  # vendor was deleted from inventory after being scheduled; nothing to do

    detector_types = [DetectorType(t) for t in config["detector_types"]]
    try:
        results = await run_detectors_for_vendor(vendor["name"], vendor["domain"], detector_types)
    except Exception:
        # Defensive: don't let one vendor's scan failure stop the scheduler loop.
        store.mark_monitor_run(config["vendor_id"], config["frequency"])
        return

    for result in results:
        previous = store.get_latest_score(config["vendor_id"], result.detector.value)
        store.record_score(
            config["vendor_id"], result.detector.value, result.risk_score, result.rating_letter, result.summary,
        )

        # Only numeric-score detectors (currently: vulnerability) can trigger
        # a threshold-based score-drop alert.
        if result.risk_score is not None and previous and previous.get("score") is not None:
            drop = previous["score"] - result.risk_score
            if drop >= config["alert_threshold_points"]:
                alert_id = store.record_alert(
                    config["vendor_id"], result.detector.value, previous["score"], result.risk_score,
                )
                if config.get("webhook_url"):
                    success, error = await send_webhook_alert(
                        config["webhook_url"], vendor["name"], vendor["domain"],
                        result.detector.value, previous["score"], result.risk_score,
                    )
                    store.mark_alert_delivered(alert_id, error=None if success else error)
                # Email delivery: see notifications.email_delivery_not_configured_message().
                # notify_email is stored but not yet actionable without a chosen provider.

    store.mark_monitor_run(config["vendor_id"], config["frequency"])


async def _scheduler_tick() -> None:
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    due = store.list_due_continuous_monitors(now_iso)
    if not due:
        return

    semaphore = asyncio.Semaphore(MONITOR_RUN_CONCURRENCY)

    async def _bounded(config: dict) -> None:
        async with semaphore:
            try:
                await _run_one_monitored_vendor(config)
            except Exception:
                pass  # one vendor's unexpected failure must never kill the scheduler loop

    await asyncio.gather(*(_bounded(c) for c in due))


async def run_monitoring_scheduler_loop() -> None:
    """Long-running background task. Call once via asyncio.create_task() at app startup."""
    store.init_store()
    while True:
        try:
            await _scheduler_tick()
        except Exception:
            pass  # the loop itself must never die; next tick will simply try again
        await asyncio.sleep(MONITOR_POLL_INTERVAL_SECONDS)
