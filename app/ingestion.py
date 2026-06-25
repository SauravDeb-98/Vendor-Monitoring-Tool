"""
Data Ingestion Module
----------------------
Parses an uploaded Excel vendor list. Per spec, this module STRICTLY extracts
only two columns from the source file: Vendor Name and Vendor Website Link.
Any other columns present in the source workbook are ignored. Input is
cleaned/standardized before being handed to the scanner.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import pandas as pd

# Column header aliases we will recognize in the source file, matched
# case-insensitively with whitespace stripped.
NAME_ALIASES = {"vendor name", "vendor", "name", "company", "company name", "supplier", "supplier name"}
URL_ALIASES = {
    "vendor website link", "vendor website", "website", "website link", "url",
    "web url", "domain", "site", "vendor url", "link",
}


@dataclass
class Vendor:
    name: str
    website: str
    domain: str


class IngestionError(ValueError):
    pass


def _normalize_header(h) -> str:
    return re.sub(r"\s+", " ", str(h).strip().lower())


def _find_column(columns, aliases) -> str | None:
    normalized = {col: _normalize_header(col) for col in columns}
    for col, norm in normalized.items():
        if norm in aliases:
            return col
    # fallback: partial/contains match
    for col, norm in normalized.items():
        if any(alias in norm or norm in alias for alias in aliases):
            return col
    return None


def _clean_url(raw: str) -> str | None:
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw or raw.lower() in {"n/a", "na", "none", "-"}:
        return None
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc or "." not in parsed.netloc:
        return None
    # Strip path/query — we want the site root for scanning purposes
    clean = f"{parsed.scheme}://{parsed.netloc}".lower()
    return clean


def _extract_domain(url: str) -> str:
    netloc = urlparse(url).netloc.lower()
    return netloc[4:] if netloc.startswith("www.") else netloc


def parse_vendor_excel(file_bytes: bytes) -> list[Vendor]:
    """
    Parse vendor list from raw Excel bytes. Extracts ONLY Vendor Name and
    Vendor Website Link columns, regardless of what else is present in the
    sheet. Raises IngestionError with a user-facing message on failure.
    """
    try:
        df = pd.read_excel(io.BytesIO(file_bytes), engine="openpyxl")
    except Exception as exc:
        raise IngestionError(f"Could not read the Excel file: {exc}") from exc

    if df.empty:
        raise IngestionError("The uploaded Excel file has no rows.")

    name_col = _find_column(df.columns, NAME_ALIASES)
    url_col = _find_column(df.columns, URL_ALIASES)

    if name_col is None or url_col is None:
        raise IngestionError(
            "Could not find required columns. The file must contain a "
            "'Vendor Name' column and a 'Vendor Website Link' column "
            f"(found columns: {list(df.columns)})."
        )

    # Strict extraction: only these two columns survive past this point.
    trimmed = df[[name_col, url_col]].copy()
    trimmed.columns = ["name", "website"]

    vendors: list[Vendor] = []
    seen_domains: set[str] = set()

    for _, row in trimmed.iterrows():
        raw_name = row["name"]
        raw_url = row["website"]

        if pd.isna(raw_name) or pd.isna(raw_url):
            continue

        name = re.sub(r"\s+", " ", str(raw_name).strip())
        if not name:
            continue

        clean_url = _clean_url(str(raw_url))
        if clean_url is None:
            continue

        domain = _extract_domain(clean_url)
        if domain in seen_domains:
            continue
        seen_domains.add(domain)

        vendors.append(Vendor(name=name, website=clean_url, domain=domain))

    if not vendors:
        raise IngestionError(
            "No valid vendor rows found after cleaning. Check that the "
            "Vendor Website Link column contains valid URLs/domains."
        )

    return vendors
