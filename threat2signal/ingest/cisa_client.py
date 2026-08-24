"""CISA sitemap fetch, parse, and advisory scraping."""

from __future__ import annotations

import logging
import random
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from bs4 import BeautifulSoup, Tag

from threat2signal.ingest.http import create_http_client as _make_http_client
from threat2signal.ingest.http import html_cache_path
from threat2signal.ingest.models import ScrapeResult, SitemapEntry
from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

_SITEMAP_NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

_ARTICLE_SELECTORS = (
    "article .field--name-body",
    "article",
    "[role='main'], main",
    ".node__content",
    "#main-content",
)

_NOISE_CLASSES = (
    "breadcrumb", "sidebar", "footer", "header", "menu",
    "navigation", "cookie", "social-share",
)

# -- HTTP client ---------------------------------------------------------------

def create_http_client(settings: dict) -> httpx.Client:
    """Create an httpx client with browser TLS fingerprint for CISA scraping."""
    return _make_http_client(
        user_agent=settings["cisa"]["user_agent"],
        connect_timeout=settings["http"]["connect_timeout"],
        read_timeout=settings["http"]["read_timeout"],
        use_curl_cffi=True,
    )


# -- Sitemap fetch & parse -----------------------------------------------------

def fetch_sitemap(
    client: httpx.Client, sitemap_url: str, settings: dict,
) -> bytes:
    """GET the CISA sitemap with an extended read timeout."""
    timeout = httpx.Timeout(
        settings["http"]["sitemap_read_timeout"],
        connect=settings["http"]["connect_timeout"],
    )
    try:
        response = client.get(sitemap_url, timeout=timeout)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Sitemap fetch failed: %s returned %s",
            sitemap_url, exc.response.status_code,
        )
        raise
    logger.info("Fetched sitemap from %s (%d bytes)", sitemap_url, len(response.content))
    return response.content


def _entry_from_url_element(url_el: ET.Element) -> SitemapEntry | None:
    """Build a SitemapEntry from a sitemap <url> element, or None if not AA/AR."""
    loc_el = url_el.find("sm:loc", _SITEMAP_NS)
    lastmod_el = url_el.find("sm:lastmod", _SITEMAP_NS)
    if loc_el is None or loc_el.text is None:
        return None
    loc = loc_el.text.strip()
    lastmod = lastmod_el.text.strip() if lastmod_el is not None and lastmod_el.text else ""

    # Only AA (cybersecurity advisories) and AR (analysis reports) are relevant
    if "/cybersecurity-advisories/aa" in loc:
        advisory_type = "cybersecurity_advisory"
    elif "/analysis-reports/ar" in loc:
        advisory_type = "analysis_report"
    else:
        return None

    advisory_id = loc.rstrip("/").rsplit("/", 1)[-1]
    return SitemapEntry(
        url=loc,
        lastmod=lastmod,
        advisory_id=advisory_id,
        advisory_type=advisory_type,
    )


def _parse_urlset(root: ET.Element) -> list[SitemapEntry]:
    """Extract SitemapEntry items from a <urlset> element."""
    entries: list[SitemapEntry] = []
    for url_el in root.findall("sm:url", _SITEMAP_NS):
        entry = _entry_from_url_element(url_el)
        if entry is not None:
            entries.append(entry)
    return entries


def parse_sitemap(
    xml_bytes: bytes, fetch_fn: Callable[[str], bytes],
) -> list[SitemapEntry]:
    """Parse a CISA sitemap XML, following sub-sitemap links if needed."""
    root = ET.fromstring(xml_bytes)
    # Namespace-qualified tags look like {http://...}urlset
    tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag

    if tag == "urlset":
        entries = _parse_urlset(root)
    elif tag == "sitemapindex":
        entries = []
        for sitemap_el in root.findall("sm:sitemap", _SITEMAP_NS):
            loc_el = sitemap_el.find("sm:loc", _SITEMAP_NS)
            if loc_el is not None and loc_el.text:
                sub_bytes = fetch_fn(loc_el.text.strip())
                sub_root = ET.fromstring(sub_bytes)
                entries.extend(_parse_urlset(sub_root))
    else:
        logger.warning("Unexpected sitemap root element: %s", tag)
        entries = []

    # Newest first so backfill prioritises recent advisories
    entries.sort(key=lambda e: e.lastmod, reverse=True)

    aa_count = sum(1 for e in entries if e.advisory_type == "cybersecurity_advisory")
    ar_count = sum(1 for e in entries if e.advisory_type == "analysis_report")
    logger.info("Sitemap parsed: %d AA entries, %d AR entries", aa_count, ar_count)
    return entries


# -- Sitemap diff & validation --------------------------------------------------

def diff_sitemap(
    entries: list[SitemapEntry], conn: sqlite3.Connection,
) -> tuple[list[SitemapEntry], list[SitemapEntry], int]:
    """Compare sitemap entries against stored advisories."""
    new_entries: list[SitemapEntry] = []
    updated_entries: list[SitemapEntry] = []
    unchanged = 0

    for entry in entries:
        stored = db.get_advisory(conn, entry.advisory_id)
        if stored is None:
            new_entries.append(entry)
        elif entry.lastmod > (stored.get("sitemap_lastmod") or ""):
            updated_entries.append(entry)
        else:
            unchanged += 1

    logger.info(
        "Sitemap diff: %d new, %d updated, %d unchanged",
        len(new_entries), len(updated_entries), unchanged,
    )
    return new_entries, updated_entries, unchanged


def validate_sitemap_result(
    entries: list[SitemapEntry], conn: sqlite3.Connection,
) -> bool:
    """Guard against empty sitemap responses when the database has existing data."""
    if len(entries) == 0:
        existing = db.count_advisories(conn, source="cisa")
        if existing >= 100:
            logger.error(
                "Sitemap returned zero AA/AR URLs but database has %d "
                "advisories — skipping poll",
                existing,
            )
            return False
    return True


# -- Cloudflare detection ------------------------------------------------------

def detect_cloudflare_challenge(response: httpx.Response) -> bool:
    """Detect if a response is a Cloudflare challenge page."""
    # Check 1: CF-Mitigated header set by Cloudflare edge
    cf_mitigated = response.headers.get("cf-mitigated", "")
    if cf_mitigated.lower() == "challenge":
        logger.debug("CF challenge detected: check 1 (cf-mitigated header)")
        return True

    content_len = len(response.content)

    # Check 2: Challenge pages fall in a narrow size band
    if 5000 <= content_len <= 15000:
        logger.debug("CF challenge detected: check 2 (content size %d)", content_len)
        return True

    # Check 3: Known CF challenge page markers in the first 2 KB
    text_prefix = response.text[:2048]
    cf_markers = (
        "Just a moment...",
        "Attention Required!",
        'id="cf-browser-verification"',
        "window._cf_chl_opt",
    )
    if any(marker in text_prefix for marker in cf_markers):
        logger.debug("CF challenge detected: check 3 (marker in first 2KB)")
        return True

    # Check 4: Missing expected CISA page structure (skip empty responses)
    if content_len > 0:
        body = response.text
        real_content_markers = (
            'class="field--name-body"',
            'role="main"',
            "<article",
        )
        if not any(marker in body for marker in real_content_markers):
            logger.debug("CF challenge detected: check 4 (no CISA content markers)")
            return True

    return False


# -- Article extraction ---------------------------------------------------------

def _strip_noise(element: Tag) -> None:
    """Remove navigation, scripts, and other non-content elements."""
    for tag_name in ("nav", "script", "style"):
        for el in element.find_all(tag_name):
            el.decompose()

    for el in element.find_all(
        class_=lambda c: c and any(n in c for n in _NOISE_CLASSES),
    ):
        el.decompose()


def extract_page_title(raw_html: str) -> str | None:
    """Extract the advisory title from the page <h1>."""
    soup = BeautifulSoup(raw_html, "lxml")
    h1 = soup.find("h1")
    if h1:
        title = h1.get_text(strip=True)
        if title:
            return title
    return None


def extract_pub_date(raw_html: str) -> str | None:
    """Extract the publication date from the first <time datetime> element."""
    soup = BeautifulSoup(raw_html, "lxml")
    time_el = soup.find("time", attrs={"datetime": True})
    if time_el:
        dt = time_el["datetime"]
        if isinstance(dt, str) and len(dt) >= 10:
            return dt[:10]
    return None


def extract_article_body(raw_html: str) -> str:
    """Extract the main article content from a CISA advisory page."""
    soup = BeautifulSoup(raw_html, "lxml")

    matched = None
    for selector in _ARTICLE_SELECTORS:
        candidate = soup.select_one(selector)
        if candidate and len(candidate.get_text(strip=True)) >= 500:
            matched = candidate
            break

    if matched is None:
        logger.warning("No article body found, using full body as fallback")
        return str(soup.body) if soup.body else raw_html

    _strip_noise(matched)
    _resolve_relative_links(matched, "https://www.cisa.gov")
    return str(matched)


def _resolve_relative_links(soup, base_url: str) -> None:
    """Resolve relative href/src attributes to absolute URLs."""
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if not href.startswith(("http://", "https://", "mailto:", "#", "javascript:", "data:")):
            tag["href"] = base_url + ("" if href.startswith("/") else "/") + href
    for tag in soup.find_all("img", src=True):
        src = tag["src"]
        if not src.startswith(("http://", "https://", "data:")):
            tag["src"] = base_url + ("" if src.startswith("/") else "/") + src


# -- Advisory scraping ----------------------------------------------------------

def scrape_advisory(
    client: httpx.Client, url: str, settings: dict, data_dir: Path,
) -> ScrapeResult:
    """Fetch and extract content from a single CISA advisory page."""
    advisory_id = url.rstrip("/").rsplit("/", 1)[-1]

    try:
        response = client.get(url)
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.warning("Network error scraping %s: %s", url, exc)
        return ScrapeResult(
            advisory_id=advisory_id, url=url, status="error",
            raw_html=None, article_body=None, http_status=None, cf_ray=None,
            error=str(exc),
        )

    if response.status_code != 200:
        return ScrapeResult(
            advisory_id=advisory_id, url=url, status="http_error",
            raw_html=None, article_body=None,
            http_status=response.status_code, cf_ray=None,
        )

    if detect_cloudflare_challenge(response):
        logger.warning("Cloudflare challenge for %s (CF-RAY: %s)",
                       url, response.headers.get("cf-ray"))
        return ScrapeResult(
            advisory_id=advisory_id, url=url, status="cf_challenged",
            raw_html=None, article_body=None, http_status=200,
            cf_ray=response.headers.get("cf-ray"),
            response_size=len(response.content),
        )

    article_body = extract_article_body(response.text)
    _write_html_cache(data_dir, advisory_id, response.text)
    return ScrapeResult(
        advisory_id=advisory_id, url=url, status="ok",
        raw_html=response.text, article_body=article_body,
        http_status=200, cf_ray=None,
    )


def _write_html_cache(data_dir: Path, advisory_id: str, html: str) -> None:
    """Persist raw HTML to the monthly cache directory."""
    try:
        cache_file = html_cache_path(data_dir, "cisa", advisory_id)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(html, encoding="utf-8")
    except OSError:
        logger.warning("Failed to write html_cache for %s", advisory_id)


# -- Backfill & batch scraping --------------------------------------------------

def _backfill_page_metadata(
    conn: sqlite3.Connection, advisory_id: str, raw_html: str,
) -> None:
    """Extract title and pub_date from HTML and update the advisory row."""
    title = extract_page_title(raw_html)
    pub_date = extract_pub_date(raw_html)
    updates: list[str] = []
    params: list[str] = []
    if title:
        updates.append("title = ?")
        params.append(title)
    if pub_date:
        updates.append("pub_date = ?")
        params.append(pub_date)
    if updates:
        params.append(advisory_id)
        with conn:
            conn.execute(
                f"UPDATE advisory SET {', '.join(updates)} WHERE advisory_id = ?",
                params,
            )


def _limit_by_type(
    entries: list[SitemapEntry], limit: int,
) -> list[SitemapEntry]:
    """Take the first N entries of each advisory type."""
    by_type: dict[str, list[SitemapEntry]] = {}
    for entry in entries:
        by_type.setdefault(entry.advisory_type, []).append(entry)
    result: list[SitemapEntry] = []
    for type_entries in by_type.values():
        result.extend(type_entries[:limit])
    return result


def seed_backfill(
    conn: sqlite3.Connection,
    entries: list[SitemapEntry],
    limit_per_type: int | None = None,
) -> int:
    """Insert new sitemap entries into the database as pending advisories."""
    if limit_per_type is not None:
        entries = _limit_by_type(entries, limit_per_type)

    seeded = 0
    now = datetime.now(timezone.utc).isoformat()
    for entry in entries:
        if db.get_advisory(conn, entry.advisory_id) is not None:
            continue
        db.upsert_advisory(conn, {
            "advisory_id": entry.advisory_id,
            "type": entry.advisory_type,
            "source": "cisa",
            "link": entry.url,
            "sitemap_lastmod": entry.lastmod,
            "scrape_status": "pending",
            "first_seen": now,
        })
        seeded += 1

    logger.info("Seeded %d new advisories from sitemap", seeded)
    return seeded


def scrape_batch(
    conn: sqlite3.Connection,
    client: httpx.Client,
    settings: dict,
    advisories: list[dict],
    delay_base: float,
    delay_jitter: float,
    data_dir: Path | None = None,
) -> dict[str, int]:
    """Scrape a batch of advisories with rate-limiting delays."""
    batch_data_dir = data_dir or Path(settings.get("data_dir", "data"))
    counts = {"scraped": 0, "cf_challenged": 0, "failed": 0, "errors": 0}
    for i, adv in enumerate(advisories):
        result = scrape_advisory(client, adv["link"], settings, batch_data_dir)
        if result.status == "ok":
            db.update_scrape_result(
                conn, adv["advisory_id"], "scraped", result.raw_html, result.article_body,
            )
            _backfill_page_metadata(conn, adv["advisory_id"], result.raw_html)
            counts["scraped"] += 1
        elif result.status == "cf_challenged":
            db.update_scrape_result(conn, adv["advisory_id"], "cf_challenged", None, None)
            counts["cf_challenged"] += 1
        elif result.status == "http_error":
            db.update_scrape_result(conn, adv["advisory_id"], "failed", None, None)
            counts["failed"] += 1
            logger.warning("HTTP error %s for %s", result.http_status, adv["advisory_id"])
        else:
            db.update_scrape_result(conn, adv["advisory_id"], "failed", None, None)
            counts["errors"] += 1

        if i < len(advisories) - 1:
            delay = delay_base + random.uniform(0, delay_jitter)
            # Conservative delay to avoid CISA rate limiting
            time.sleep(delay)

    return counts


# -- Poll orchestrator ----------------------------------------------------------

def _merge_counts(target: dict[str, int], source: dict[str, int]) -> None:
    """Accumulate scrape counters from one batch into the running total."""
    for key in source:
        target[key] = target.get(key, 0) + source.get(key, 0)


def _run_scrape_phases(
    conn: sqlite3.Connection,
    client: httpx.Client,
    settings: dict,
    updated_entries: list[SitemapEntry],
    counts: dict[str, int],
    data_dir: Path,
) -> None:
    """Execute backfill, update, and CF-retry scrape phases."""
    pending = db.get_pending_scrape(conn, settings["cisa"]["backfill_batch_size"])
    if pending:
        _merge_counts(counts, scrape_batch(
            conn, client, settings, pending,
            settings["cisa"]["delay_backfill_base"],
            settings["cisa"]["delay_backfill_jitter"],
            data_dir=data_dir,
        ))

    if updated_entries:
        for e in updated_entries:
            db.upsert_advisory(conn, {
                "advisory_id": e.advisory_id, "sitemap_lastmod": e.lastmod,
            })
        updated_dicts = [{"advisory_id": e.advisory_id, "link": e.url} for e in updated_entries]
        _merge_counts(counts, scrape_batch(
            conn, client, settings, updated_dicts,
            settings["cisa"]["delay_daily"], 0,
            data_dir=data_dir,
        ))

    cf_retries = db.get_cf_challenged(conn)
    if cf_retries:
        _merge_counts(counts, scrape_batch(
            conn, client, settings, cf_retries,
            settings["cisa"]["delay_daily"], 0,
            data_dir=data_dir,
        ))


def _build_poll_summary(
    conn: sqlite3.Connection,
    entries: list[SitemapEntry],
    new_entries: list[SitemapEntry],
    updated_entries: list[SitemapEntry],
    counts: dict[str, int],
) -> dict:
    """Record the poll in history and return summary statistics."""
    aa_total = sum(1 for e in entries if e.advisory_type == "cybersecurity_advisory")
    ar_total = sum(1 for e in entries if e.advisory_type == "analysis_report")

    errors_str = str(counts["errors"]) if counts["errors"] > 0 else None
    db.record_cisa_poll(
        conn, polled_at=datetime.now(timezone.utc).isoformat(),
        source="sitemap", aa_total=aa_total, ar_total=ar_total,
        new_advisories=len(new_entries), updated=len(updated_entries),
        errors=errors_str,
    )
    return {
        "aa_total": aa_total,
        "ar_total": ar_total,
        "new": len(new_entries),
        "updated": len(updated_entries),
        "scraped": counts["scraped"],
        "cf_challenged": counts["cf_challenged"],
        "errors": counts["errors"],
    }


def cisa_poll(
    conn: sqlite3.Connection,
    client: httpx.Client,
    settings: dict,
    data_dir: Path | None = None,
) -> dict:
    """Run a full CISA sitemap poll and scrape cycle."""
    poll_data_dir = data_dir or Path(settings.get("data_dir", "data"))
    sitemap_bytes = fetch_sitemap(client, settings["cisa"]["sitemap_url"], settings)

    fetch_fn = lambda url: client.get(
        url,
        timeout=httpx.Timeout(
            connect=settings["http"]["connect_timeout"],
            read=settings["http"]["sitemap_read_timeout"],
        ),
    ).content

    entries = parse_sitemap(sitemap_bytes, fetch_fn)
    if not validate_sitemap_result(entries, conn):
        return {"aborted": True}

    new_entries, updated_entries, unchanged = diff_sitemap(entries, conn)
    seed_backfill(conn, new_entries)

    counts = {"scraped": 0, "cf_challenged": 0, "failed": 0, "errors": 0}
    _run_scrape_phases(
        conn, client, settings, updated_entries, counts, data_dir=poll_data_dir,
    )

    return _build_poll_summary(conn, entries, new_entries, updated_entries, counts)
