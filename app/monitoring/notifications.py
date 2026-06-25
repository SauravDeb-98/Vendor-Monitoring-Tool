"""
Alert Notification Delivery
--------------------------------
Delivers score-drop alerts via webhook POST. Email delivery is
deliberately NOT implemented in this module despite being requested in
the spec — sending real email requires either an SMTP relay or a
transactional email provider (SendGrid, Postmark, SES, etc.), each of
which needs its own API key/credentials that this codebase doesn't have
and that a person needs to actively choose and configure. Rather than
wiring up a specific provider unprompted, the `notify_email` field is
stored in monitoring_configs (see store.py) and the delivery function
below clearly logs the gap, so adding it later is a small, well-defined
task once a provider is chosen.

Webhook delivery: a standard JSON POST to a user-configured URL,
following the same content rules as the rest of this app's notification-
adjacent surfaces (audit_log.py, etc.) — the payload contains vendor
name, domain, detector, score delta, and a timestamp, but never raw
findings text or any other potentially sensitive scan content, since
webhook URLs may point to third-party services outside this app's
control.
"""
from __future__ import annotations

import time

import httpx

WEBHOOK_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


async def send_webhook_alert(
    webhook_url: str,
    vendor_name: str,
    domain: str,
    detector_type: str,
    previous_score: int,
    new_score: int,
) -> tuple[bool, str | None]:
    """Returns (success, error_message)."""
    payload = {
        "event": "vendor_risk_score_drop",
        "vendor_name": vendor_name,
        "domain": domain,
        "detector": detector_type,
        "previous_score": previous_score,
        "new_score": new_score,
        "drop_points": previous_score - new_score,
        "triggered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            resp = await client.post(webhook_url, json=payload)
            if 200 <= resp.status_code < 300:
                return True, None
            return False, f"Webhook returned HTTP {resp.status_code}"
    except Exception as exc:
        return False, f"Webhook delivery failed: {type(exc).__name__}"


def email_delivery_not_configured_message() -> str:
    return (
        "Email alert delivery is not configured. This requires choosing an email "
        "provider (e.g. SendGrid, Postmark, AWS SES) and setting its API key as an "
        "environment variable. Webhook delivery is available now; email can be added "
        "once a provider is chosen."
    )
