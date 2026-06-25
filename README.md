# Third-Party Vendor Risk Assessment Tool

A public, no-login web tool that ingests a vendor list, runs **passive external
OSINT scans** against each vendor's website/domain, maps findings against
NIST, ISO/IEC 27001, DORA, and GDPR, scores each vendor 0–100, and generates
a dynamic PDF report.

Live as a single FastAPI service with a static HTML/JS frontend — no
database, no accounts, no required API key.

---

## What it actually checks (and what it deliberately does NOT do)

This tool performs **passive, publicly-available reconnaissance only** —
the same category of request a normal browser or DNS resolver makes. It
does **not** perform port scanning, banner grabbing, credential testing, or
any other active probing of vendor infrastructure. That line is intentional
and not configurable: scanning systems you don't own or operate without
authorization can violate the CFAA and equivalent laws elsewhere. The tool
stays in the legal/passive OSINT lane:

| Signal | Source |
|---|---|
| HTTPS enforcement, status code | Direct HTTP(S) GET (same as a browser) |
| Security response headers (HSTS, CSP, X-Frame-Options, etc.) | HTTP response headers |
| TLS version, certificate validity, expiry | Standard TLS handshake |
| SPF / DKIM / DMARC / MX records | Public DNS TXT/MX lookups |
| Subdomain footprint | Certificate Transparency logs (crt.sh) |
| Known CVEs associated with vendor/product name | NVD public CVE API (best-effort keyword match) |

No API keys are required for any of the above — all free, public sources.

---

## Architecture

```
app/
  ingestion.py          # Excel parsing: extracts ONLY Vendor Name + Vendor Website Link
  scanner/engine.py      # Async passive OSINT: TLS, headers, DNS, CT logs, CVEs
  compliance/engine.py   # Rules engine: scan finding -> NIST/ISO/DORA/GDPR citations + severity weight
  scoring.py             # Deduction-based 0-100 scoring + risk tier classification
  ai_analysis.py         # Optional Claude API narrative layer (BYO key) + deterministic fallback
  reporting/pdf_builder.py  # ReportLab dynamic PDF: dashboard, per-vendor matrix, methodology
  main.py                # FastAPI app: upload, job orchestration, rate limiting, downloads
  static/index.html      # Single-page frontend (vanilla JS, no build step)
```

### Data flow

1. **Ingestion** — Upload an `.xlsx`. The parser recognizes common header
   aliases (`Vendor Name`, `Vendor`, `Company`, etc. / `Vendor Website Link`,
   `Website`, `URL`, etc.) but **only ever extracts those two columns**,
   regardless of what else is in the sheet. URLs are normalized (scheme
   added if missing, path/query stripped, deduplicated by domain).

2. **Scanning** — Each vendor's domain is scanned concurrently (bounded
   semaphore, default 4 at a time) across TLS, HTTP headers, DNS, CT logs,
   and CVE lookups, fully async via `httpx` + `dnspython`.

3. **Compliance mapping** — Every scan finding is run through a rules
   engine that emits a `ComplianceFinding`: a human-readable description,
   severity (`critical`/`high`/`medium`/`low`/`info`), a point weight, and
   citations into NIST SP 800-53/CSF, ISO/IEC 27001:2022 Annex A, DORA
   Articles 28–30, and GDPR Articles 28/32/44-49.

4. **Scoring** — See "Scoring Algorithm" below.

5. **Narrative** — If the visitor pasted a Claude API key in the UI, it's
   used (server-side, single request, never logged or stored) to write a
   short prose risk narrative per vendor. If no key is given, a
   deterministic rule-based narrative generator produces equivalent
   (if less fluent) prose — **the tool is 100% functional with zero key.**

6. **Reporting** — ReportLab assembles a multi-page PDF: cover + executive
   dashboard (bar chart of scores, pie chart of tier distribution, summary
   table), then a per-vendor section (score badge, narrative, full
   compliance mapping matrix), then a methodology/limitations page.

---

## Scoring algorithm — design rationale

A **deterministic deduction model** was chosen over an opaque ML score
because this is a compliance-adjacent tool: every point lost must be
traceable back to a specific, citable control failure for the report to
survive an audit or a vendor dispute ("why did we score 61?" needs a real
answer, not a black box).

```
score = clamp(100 - sum(finding.weight for finding in findings), 0, 100)
```

Weights are pre-calibrated by severity in the compliance engine — e.g. no
HTTPS enforcement costs 25 points (critical), a missing `Permissions-Policy`
header costs 2 (informational). The full weight table lives in
`app/compliance/engine.py`.

### Risk tiers (5-tier scheme, mirrors industry-standard CVSS severity banding)

This tool scores security **posture** (higher = safer), which is the inverse
of CVSS, which scores vulnerability **severity** (higher = worse). The tier
boundaries mirror CVSS v3.x's proportional band widths (Critical 90–100%,
High 70–89%, Medium 40–69%, Low 0.1–39%, None 0%) but flipped in direction,
so a perfect-posture vendor lands at 100 ("Informational") rather than 0.

| Score | Tier |
|---|---|
| 0–9 | Critical Impact |
| 10–29 | High Impact |
| 30–59 | Medium Impact |
| 60–99 | Low Impact |
| 100 | Informational |

This is a 5-tier, gapless scheme — every score from 0–100 maps to exactly
one tier, with no manual-review dead zone.

---

## Compliance frameworks mapped

- **NIST SP 800-53 Rev 5 / CSF 2.0** — primarily the `SR` (Supply Chain Risk
  Management) and `SC` (System & Communications Protection) control
  families, plus `SI-8`, `RA-5`, `CM-8` where relevant.
- **ISO/IEC 27001:2022 Annex A** — A.5.19–5.23 (supplier relationships,
  cloud services), A.8.8 (vulnerability management), A.8.24 (cryptography),
  A.8.26 (application security requirements).
- **DORA (EU 2022/2554)** — Articles 28 (general ICT third-party risk
  principles, due diligence), 29 (concentration risk), 30 (mandatory
  contractual security/audit clauses).
- **GDPR** — Articles 28 (processor obligations), 32 (security of
  processing — encryption, ongoing confidentiality/integrity, testing),
  44–49 (cross-border transfer safeguards, referenced where relevant).

These mappings are a starting point for due diligence, not a certified
compliance audit — see the "Methodology & Limitations" page generated in
every report.

---

## Running locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Visit `http://localhost:8000`. Upload `samples/sample_vendor_list.xlsx` to
try it immediately (includes a third "Internal Notes" column to verify the
strict two-column extraction works).

### Or with Docker

```bash
docker build -t vendor-risk-tool .
docker run -p 8000:8000 vendor-risk-tool
```

---

## Deploying for a public link (Render, free tier)

This repo includes a `render.yaml` (Render's Infrastructure-as-Code format)
and a `Dockerfile`, so deployment is close to one-click.

1. **Push this repo to GitHub** (see below) if you haven't already.
2. Go to **https://dashboard.render.com** and sign up / log in (free, no
   credit card required for the free web service tier).
3. Click **New +** → **Blueprint**.
4. Connect your GitHub account if prompted, then select this repository.
   Render will detect `render.yaml` automatically and show the
   `vendor-risk-assessment-tool` service it's about to create.
5. Click **Apply** / **Create Web Service**. Render will build the
   `Dockerfile` and deploy.
6. Wait for the build to finish (first Docker build typically takes
   2–4 minutes). Once live, Render gives you a public URL like:
   `https://vendor-risk-assessment-tool.onrender.com`
7. That URL is your shareable link — open it, upload an Excel file, run
   an assessment, download the PDF. Anyone with the link can use it,
   subject to the built-in rate limit (5 scans per IP per 24h, 25 vendors
   max per run) that protects the server regardless of whether a visitor
   brings their own Claude key.

**Note on the free tier:** Render's free web services spin down after
15 minutes of inactivity and take ~30-50 seconds to wake up on the next
request. That's normal — not a bug — and fine for sharing a link casually.
If you want it always-on, upgrade the service plan in Render's dashboard
(`render.yaml`'s `plan: free` line is the only thing to change).

### Alternative hosts

The app is a standard Dockerized FastAPI service with no platform-specific
code, so it also runs unmodified on Railway, Fly.io, Google Cloud Run, or
any VM with Docker. Just point the platform at the `Dockerfile` and expose
port `8000`.

---

## Rate limiting & abuse protection

Since this app has no login and no required API key, two safeguards are
built in regardless of whether a visitor supplies their own Claude key:

- **5 scans per IP per 24 hours** (in-memory sliding window)
- **25 vendors max per scan run**
- **5MB max upload size**

These are configurable at the top of `app/main.py`
(`RATE_LIMIT_MAX_REQUESTS`, `MAX_VENDORS_PER_RUN`).

## Audit logging

Every scan is recorded in a local SQLite file (`audit_log.sqlite3`,
managed by `app/audit_log.py`) for accountability — "who ran what size
scan, when, and what happened" — without storing the sensitive content of
the scan itself.

**What's logged:** timestamp, vendor *count* (not names), final status
(complete/failed), error *type* only on failure (e.g. `TimeoutError`, never
the full exception message), whether an AI key was used (boolean only),
and one-way truncated SHA-256 hashes of the session cookie and IP address
(not the raw values — these hashes can confirm "same visitor ran multiple
scans" without being reversible back to the original cookie or IP).

**What's never logged, by construction:** vendor names, vendor website
URLs, scan findings, generated narrative text, or the Claude API key. The
logging functions in `audit_log.py` don't accept those values as
parameters at all, so a future code change elsewhere can't accidentally
start logging them through this path. This was verified directly by
running a real scan and grepping the raw `audit_log.sqlite3` file's bytes
for the test vendor names/domains — confirmed absent.

**Viewing the stats:** set an `ADMIN_STATS_TOKEN` environment variable on
the server (in Render: Service → Environment → Add Environment Variable)
to enable `GET /api/admin/stats` (returns 404 if unset). Call it with
header `X-Admin-Token: <your token>` to get aggregate counts (total scans,
breakdown by status, unique sessions, total vendors assessed) for a
configurable time window (`?hours=24` by default). The endpoint returns
counts only — never per-job detail that could be tied back to a specific
visitor.

**Durability caveat:** this uses local SQLite on disk. On Render's free
tier, local disk is ephemeral — wiped on every redeploy and possibly on
restarts/spin-downs. This gives you within-deployment accountability and
basic usage analytics, not a durable, long-term audit trail suitable for
compliance/legal retention. For that, point `DB_PATH` in `audit_log.py` at
a persistent volume (Render's paid disk add-on) or swap the storage
backend for an external database.

## Encryption at rest

Generated PDF reports are encrypted (Fernet — AES-128-CBC with HMAC-SHA256
authentication, via the `cryptography` library) before being written to
disk, and decrypted only in memory at the moment of serving a verified
download to the job's owner. The on-disk file (`{job-id}.pdf.enc`) is
opaque ciphertext — running `file` on it reports plain ASCII text, not
"PDF document," and the raw bytes contain no PDF structural markers or
vendor names. This was verified directly: a real scan was run, the
on-disk file was inspected with `file` and `strings`, and decrypted
output was confirmed to be a valid, fully readable PDF only through the
proper authenticated download endpoint.

**What this protects against:** casual/lazy disk exposure — a
misconfigured backup snapshot, a log aggregator that slurps disk
contents, anyone who can browse the filesystem but doesn't separately
have the encryption key.

**What this does NOT protect against:** a full compromise of the running
server process itself. The key has to be available to the application
automatically (there's no login step where a human enters a password to
unlock it), so a sufficiently capable attacker with code-execution access
to the live process could retrieve the key from its environment. This is
the correct tradeoff for a public, no-login tool; full key isolation
would require per-visitor secrets, which doesn't fit this app's design.

**Setup:** generate a key and set it as `REPORT_ENCRYPTION_KEY` in
Render's environment variables (Service → Environment → Add Environment
Variable):
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
If unset, the app auto-generates a fallback key at process startup (with a
console warning) so it still runs — but that fallback key only lives in
process memory and is lost on every restart, meaning reports encrypted
with it become permanently undecryptable after a restart (the visitor
sees a clear "please re-run the assessment" message in that case, not a
crash). Setting the env var explicitly avoids this.

## Privacy notes

- **Uploaded Excel files are never written to disk.** The uploaded bytes
  are read directly into memory (`file_bytes = await file.read()` in
  `app/main.py`) and passed straight to the parser; there is no file-write
  call anywhere in that code path. Once the request handler returns, the
  bytes are garbage collected.
- **The optional Claude API key is never written to disk.** It's read from
  the request body for that one scan, used for narrative generation calls,
  and discarded — never logged or stored beyond the lifetime of the
  request.
- **Generated PDF reports ARE written to disk, but encrypted** (under
  `generated_reports/` as `{job-id}.pdf.enc`, ciphertext only — see
  "Encryption at rest" above for the full design and key management).
  A background sweep task (`_cleanup_expired_reports` in `app/main.py`)
  runs every 2 minutes and deletes any report older than
  `REPORT_RETENTION_MINUTES` (default: 30). After deletion, the download
  endpoint returns HTTP 410 Gone with a message explaining the report
  expired, rather than a confusing file-not-found error. This window is
  configurable at the top of `app/main.py`.
- **Vendor names and website URLs from the upload are held in server
  memory** (the in-memory `_jobs` dict) for the lifetime of that job, and
  are not separately persisted beyond what's baked into the generated PDF
  itself — once the PDF is deleted, no other on-disk copy of that vendor
  list remains. Memory contents do not survive a server restart.
- **Each browser session is bound to its own jobs via an HttpOnly session
  cookie**, issued automatically on first contact with `/api/scan`. Every
  job is tagged with the session that created it, and both the job-status
  (`GET /api/jobs/{id}`) and report-download (`GET /api/jobs/{id}/report`)
  endpoints verify the requester's cookie matches the job's owner before
  returning anything — HTTP 403 otherwise, with an identical generic error
  whether the job doesn't exist or simply isn't yours, so the API doesn't
  leak which job IDs are valid. This means a visitor who somehow learns or
  guesses another job's UUID during the 30-minute retention window still
  cannot view its status or download its report. The cookie itself is
  HttpOnly (inaccessible to JavaScript), SameSite=Lax, and Secure when
  served over HTTPS (which Render's default deployment provides — the
  Dockerfile runs uvicorn with `--proxy-headers --forwarded-allow-ips=*`
  so it correctly detects HTTPS via Render's edge proxy). This protection
  does not survive clearing cookies or switching devices/browsers — that's
  an intentional tradeoff, since there's no shared secret to leak instead.
  Sessions are stored in-memory and do not survive a server restart or
  scale past a single server instance; a multi-instance deployment would
  need a shared session store (e.g. Redis) instead.
- Render's own infrastructure (disk, logs, network) is a third party in
  this picture: the app's own code does not persist data beyond the
  windows described above, but the underlying hosting platform's general
  operational logging is outside this project's control.

## Vendor Threat Detector & Continuous Monitoring

A second tool, available at `/detector.html`, alongside the original
vendor risk report tool. It lets you select vendors, choose which
detector(s) to run, and optionally enable continuous monitoring with
score-drop alerts — a Black-Kite-style ongoing tracking workflow rather
than a one-off report.

### Detectors (3, not 4 — see naming note below)

| Detector | What it actually checks | Data source |
|---|---|---|
| **Active Exploitation & Advisory Detector** | Confirmed, actively-exploited CVEs and ransomware-campaign links associated with the vendor | CISA's public Known Exploited Vulnerabilities (KEV) catalog |
| **Vulnerability & Exploit Scanner** | TLS/certificate health, HTTP security headers, DNS email-auth records, publicly disclosed CVEs | Same passive scan engine as the original vendor risk report tool |
| **Phishing & Brand Impersonation Detector** | Plausible lookalike/typosquat domains with evidence of live, certificate-backed infrastructure | Public Certificate Transparency logs (crt.sh) |

**Naming note — read this before expecting breach/dark-web detection:**
The original feature request specified four detectors, including a "Data
Breach Detector" (checking for exposed credentials/leaked databases) and
an "Incident & Ransomware Tracker" (checking dark-web extortion notices).
Both were intentionally not built as specified. Querying credential-dump
databases or dark-web extortion content means building infrastructure for
accessing stolen data and criminal markets — that's not something this
codebase implements, regardless of the defensive framing. Those two slots
were merged into the single **Active Exploitation & Advisory Detector**,
named for what it actually measures (CISA's own public confirmed-active-
exploitation data, including a `knownRansomwareCampaignUse` flag — a
real, legitimate, public answer to the "ransomware" part of the original
ask) rather than implying breach-news monitoring it cannot do. CISA's KEV
catalog is fetched from the [cisagov/kev-data GitHub
mirror](https://github.com/cisagov/kev-data), which CISA documents as
staying in sync with cisa.gov within minutes — used instead of the
canonical cisa.gov URL because it's a more universally allowlist-friendly
HTTPS host for outbound requests from a server environment.

### Domain auto-discovery fallback

If a vendor is submitted with only a name and no domain, the app tries
the vendor-name-as-slug pattern against `.com`/`.net`/`.io`/`.co`/`.org`
and confirms each candidate via a real DNS + HTTPS reachability check
before accepting it (`app/domain_discovery.py`). This deliberately does
NOT call a general web search API (kept the feature zero-signup per
project scope), so it's weaker than a true search-based lookup for
generic or ambiguous vendor names — results carry a confidence level
("medium" for a confirmed `.com` match, "low" otherwise, "none" if
nothing resolved) and the UI surfaces which domains were auto-discovered
rather than silently trusting a guess.

### Continuous monitoring

Selecting "Continuous Monitoring" instead of "Ad-Hoc Scan" persists a
monitoring configuration (`app/monitoring/store.py`, SQLite-backed) for
each selected vendor: which detector(s), how often (daily/weekly), and
the score-drop point threshold that should trigger an alert. A background
scheduler (`app/monitoring/scheduler.py`) polls every 5 minutes for
vendors due for a re-scan, runs the same detector code used for ad-hoc
scans, records the result in a score-history table, and — if the
**Vulnerability & Exploit Scanner**'s score drops by at least the
configured threshold versus its last recorded value — fires a webhook
POST and logs an alert. (Only that detector currently produces a
comparable 0–100 score; the exploitation and phishing detectors report
findings rather than a single posture score, so they cannot trigger a
score-drop alert by definition.)

**Email alerts are not implemented.** The `notify_email` field is stored
but not actionable — sending real email requires choosing and
configuring a provider (SendGrid, Postmark, SES, etc.) with its own API
key, which this codebase doesn't have and shouldn't silently choose on
your behalf. Webhook delivery is fully functional today; see
`app/monitoring/notifications.py` for exactly what's needed to add email
once you pick a provider.

**Monitoring config ownership:** the same session-cookie model used
elsewhere in this app protects monitoring configs — once a real session
has set up monitoring for a vendor, only that session can modify or
cancel it (verified directly: a second, genuinely distinct session
attempting to delete another session's monitoring config receives a 403).
A config that was never claimed by any session (e.g., set up by a raw API
call with no cookie) has no enforceable owner until the first real
session establishes one.

### 24-hour result caching

Ad-hoc detector results are cached in-memory per (domain, detector) pair
for 24 hours (`app/detector_cache.py`), so repeated lookups of the same
vendor reuse the prior result instead of re-querying CISA/crt.sh —
per the spec's requirement to optimize external API usage. Continuous
monitoring's scheduled runs always bypass this cache, since the entire
point of a scheduled run is to capture a fresh data point.

### Excel export

A completed ad-hoc detection job can be exported to `.xlsx`
(`GET /api/detect/{request_id}/export`, wired to the "Export to Excel"
button in the UI) with one row per vendor-detector combination: Vendor
Name, Domain, Detector Applied, Risk Score, Rating, Incident Summary,
Monitoring Status (live-linked to whether that vendor currently has
continuous monitoring enabled), and Timestamp — matching the columns
specified in the original feature request.

### API endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/detectors` | List available detector types |
| POST | `/api/detect` | Start an ad-hoc detection job |
| GET | `/api/detect/{request_id}` | Poll job status/results |
| GET | `/api/detect/{request_id}/export` | Export completed job to Excel |
| POST | `/api/vendors/discover-domain` | Domain auto-discovery for a name-only vendor |
| GET | `/api/vendors` | List vendor inventory |
| POST | `/api/monitoring/{vendor_id}` | Create/update continuous monitoring |
| GET | `/api/monitoring/{vendor_id}` | Get monitoring config + score history |
| DELETE | `/api/monitoring/{vendor_id}` | Stop continuous monitoring |
| GET | `/api/monitoring` | List all continuously-monitored vendors |
| GET | `/api/alerts` | List recent score-drop alerts |

### Storage caveat (same as audit_log.py)

`monitoring.sqlite3` is a separate local SQLite file from
`audit_log.sqlite3`, kept apart deliberately since the two stores serve
different purposes (operational monitoring data vs. privacy-preserving
usage accountability). Like the audit log, it lives on Render's free-tier
ephemeral disk — wiped on every redeploy. This means continuous
monitoring's "tracks score trend over time" promise only holds *between*
redeploys, not indefinitely, on the free tier. For real long-term
trending, point `DB_PATH` in `app/monitoring/store.py` at a persistent
volume or external database.

## Known limitations

- CVE lookups are best-effort keyword matches against the NVD API and can
  produce false positives/negatives — they are not a substitute for a real
  vulnerability assessment.
- This is a point-in-time external snapshot. It does not replace vendor
  questionnaires, SOC 2/ISO 27001 certificate review, or contractual due
  diligence.
- The free NVD API has a low unauthenticated rate limit; under heavy
  concurrent load CVE lookups may be skipped (this fails gracefully — the
  rest of the score is unaffected).
