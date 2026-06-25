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

## Privacy notes

- The optional Claude API key is read from the request body for that one
  scan, used for narrative generation calls, and never written to disk,
  logged, or stored beyond the lifetime of the request.
- Generated PDF reports are stored on local disk under `generated_reports/`
  keyed by a random job UUID. There's no cleanup job in this version —
  for a long-running public deployment, add a periodic sweep (e.g. delete
  files older than 24h) before relying on this for sensitive vendor data.

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
