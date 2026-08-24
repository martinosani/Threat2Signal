"""Data containers for advisory ingestion."""

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)


def normalize_date(raw: str | None) -> str | None:
    """Normalize a date string to YYYY-MM-DD format.

    Handles ISO dates/datetimes, partial ISO (YYYY-MM), human-readable
    ("13 Jul 2023"), and RFC 2822 ("Mon, 15 Jul 2026 10:00:00 +1000").
    Returns None for empty/None input.
    """
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", raw):
        return raw
    if re.match(r"^\d{4}-\d{2}-\d{2}T", raw):
        return raw[:10]
    if re.match(r"^\d{4}-\d{2}$", raw):
        return raw + "-01"
    for fmt in ("%d %b %Y", "%d %B %Y", "%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(raw, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    try:
        return parsedate_to_datetime(raw).strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        pass
    logger.warning("Could not normalize date: %r", raw)
    return raw


# -- ACSC ---------------------------------------------------------------------


@dataclass(frozen=True)
class AcscEntry:
    url: str
    title: str
    pub_date: str
    advisory_type: str
    severity: str | None
    advisory_id: str


# -- JPCERT -------------------------------------------------------------------


@dataclass(frozen=True)
class JpcertEntry:
    url: str
    title: str
    pub_date: str
    category: str
    advisory_id: str


@dataclass(frozen=True)
class SitemapEntry:
    url: str
    lastmod: str          # ISO 8601 from sitemap <lastmod>
    advisory_id: str      # e.g. "aa26-231a"
    advisory_type: str    # "cybersecurity_advisory" | "analysis_report"


@dataclass(frozen=True)
class ScrapeResult:
    advisory_id: str
    url: str
    status: str           # "ok" | "cf_challenged" | "http_error" | "error"
    raw_html: str | None
    article_body: str | None
    http_status: int | None
    cf_ray: str | None    # CF-RAY header if present
    response_size: int = 0  # bytes (0 for network errors with no response)
    error: str | None = None


# -- MSRC / KEV ---------------------------------------------------------------


@dataclass(frozen=True)
class MsrcCveRecord:
    cve_id: str
    title: str | None = None
    description: str | None = None
    released: str | None = None
    component: str | None = None
    component_category: str | None = None
    impact: str | None = None
    severity: str | None = None
    cvss_base: float | None = None
    cvss_temporal: float | None = None
    cvss_vector: str | None = None
    av: str | None = None
    ac: str | None = None
    pr: str | None = None
    ui: str | None = None
    scope: str | None = None
    cwe_id: str | None = None
    cwe_description: str | None = None
    exploit_status: str | None = None
    publicly_disclosed: bool = False
    exploited_wild: bool = False
    customer_action: str | None = None
    raw_json: str | None = None


@dataclass(frozen=True)
class KbRecord:
    cve_id: str
    kb_number: str
    product_name: str | None = None
    download_url: str | None = None


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    vendor: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    known_ransomware: str | None = None
    notes: str | None = None
