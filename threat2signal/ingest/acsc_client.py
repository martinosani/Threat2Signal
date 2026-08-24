"""ACSC advisory discovery and scraping."""

from __future__ import annotations

import logging
import random
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from bs4 import BeautifulSoup, Tag

from threat2signal.ingest.http import create_http_client as _make_http_client
from threat2signal.ingest.http import html_cache_path
from threat2signal.ingest.models import AcscEntry, ScrapeResult, normalize_date
from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

_SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_ARTICLE_SELECTORS = (
    "article .field--name-body",
    "article",
    "[role='main'], main",
    ".node__content",
)

_NOISE_CLASSES = (
    "breadcrumb", "sidebar", "footer", "header", "menu",
    "navigation", "cookie", "social-share",
)

_AKAMAI_MARKERS = (
    "AkamaiGHost",
    "akamaiedge",
    "Request unsuccessful",
)


# -- HTTP client ---------------------------------------------------------------


def create_acsc_client(settings: dict) -> httpx.Client:
    """Create an httpx client with browser TLS fingerprint for ACSC scraping."""
    return _make_http_client(
        user_agent=settings["acsc"]["user_agent"],
        connect_timeout=settings["http"]["connect_timeout"],
        read_timeout=settings["http"]["read_timeout"],
        use_curl_cffi=True,
    )


# -- Severity parsing ----------------------------------------------------------


def _parse_severity(title: str) -> tuple[str, str | None]:
    """Split an alert title into (clean_title, severity)."""
    upper = title.upper()
    for level in _SEVERITY_LEVELS:
        prefix = f"{level} ALERT:"
        if upper.startswith(prefix):
            clean = title[len(prefix):].strip()
            return clean, level.lower()
    return title, None


# -- RSS feed parsing ----------------------------------------------------------


def _parse_rss_feed(xml_bytes: bytes, advisory_type: str) -> list[AcscEntry]:
    """Parse one ACSC RSS 2.0 feed into AcscEntry items."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        logger.error("Failed to parse RSS XML: %s", exc)
        return []

    entries: list[AcscEntry] = []
    for item in root.iter("item"):
        title_el = item.find("title")
        link_el = item.find("link")
        pub_date_el = item.find("pubDate")
        if title_el is None or link_el is None:
            continue

        raw_title = (title_el.text or "").strip()
        url = (link_el.text or "").strip()
        raw_date = (pub_date_el.text or "").strip() if pub_date_el is not None else ""
        pub_date = normalize_date(raw_date) or ""
        if not url:
            continue

        advisory_id = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        title, severity = _parse_severity(raw_title)

        entries.append(AcscEntry(
            url=url, title=title, pub_date=pub_date,
            advisory_type=advisory_type, severity=severity,
            advisory_id=advisory_id,
        ))

    logger.debug("Parsed %d entries from %s RSS feed", len(entries), advisory_type)
    return entries


def fetch_rss_entries(client: httpx.Client, settings: dict) -> list[AcscEntry]:
    """Fetch both ACSC alert and advisory RSS feeds."""
    feeds = (
        (settings["acsc"]["rss_alerts_url"], "acsc_alert"),
        (settings["acsc"]["rss_advisories_url"], "acsc_advisory"),
    )
    all_entries: list[AcscEntry] = []
    for url, adv_type in feeds:
        try:
            response = client.get(url)
            response.raise_for_status()
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            logger.warning("RSS fetch failed for %s: %s", url, exc)
            continue
        except httpx.HTTPStatusError as exc:
            logger.warning("RSS feed %s returned %s", url, exc.response.status_code)
            continue
        all_entries.extend(_parse_rss_feed(response.content, adv_type))

    logger.info("Fetched %d total RSS entries from ACSC", len(all_entries))
    return all_entries


# -- Listing page parsing ------------------------------------------------------


def _severity_from_card(link: Tag) -> tuple[str, str | None]:
    """Extract advisory type and severity from card CSS classes."""
    classes = " ".join(link.get("class", []))
    for level in ("critical", "high", "medium", "low"):
        if f"rating--{level}" in classes:
            return "acsc_alert", level
    return "acsc_advisory", None


def _entry_from_listing_row(row: Tag, origin: str) -> AcscEntry | None:
    """Build an AcscEntry from a single listing row element."""
    link = row.find("a", href=True)
    if link is None:
        return None

    href = link["href"]
    if href.startswith("/"):
        href = origin + href
    if "/advisories/" not in href and "/alerts/" not in href:
        return None

    advisory_id = href.split("?")[0].rstrip("/").rsplit("/", 1)[-1]

    h3 = link.find("h3") or row.find("h3")
    title = h3.get_text(strip=True) if h3 else link.get_text(strip=True)
    if not title:
        return None

    date_el = row.select_one(".date, time, .date-display-single")
    pub_date = ""
    if date_el is not None:
        time_attr = date_el.get("datetime")
        raw_date = str(time_attr) if time_attr else date_el.get_text(strip=True)
        pub_date = normalize_date(raw_date) or ""

    title, severity = _parse_severity(title)
    if severity is None:
        advisory_type, severity = _severity_from_card(link)
    else:
        advisory_type = "acsc_alert"

    return AcscEntry(
        url=href, title=title, pub_date=pub_date,
        advisory_type=advisory_type, severity=severity,
        advisory_id=advisory_id,
    )


def _parse_listing_html(html: str, origin: str) -> list[AcscEntry]:
    """Extract advisory entries from an ACSC listing page."""
    soup = BeautifulSoup(html, "lxml")
    entries: list[AcscEntry] = []

    rows = soup.select(".views-row")

    for row in rows:
        entry = _entry_from_listing_row(row, origin)
        if entry is not None:
            entries.append(entry)

    return entries


def fetch_listing_page(
    client: httpx.Client, settings: dict, page: int = 0,
) -> list[AcscEntry]:
    """Fetch one page of the ACSC alerts-and-advisories listing."""
    base_url = settings["acsc"]["listing_url"]
    url = f"{base_url}?items_per_page=200&page={page}"

    try:
        response = client.get(url)
        response.raise_for_status()
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.warning("Listing page %d fetch failed: %s", page, exc)
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("Listing page %d returned %s", page, exc.response.status_code)
        return []

    origin = "/".join(base_url.split("/")[:3])
    entries = _parse_listing_html(response.text, origin)
    logger.debug("Listing page %d: %d entries", page, len(entries))
    return entries


def fetch_all_listing_pages(
    client: httpx.Client, settings: dict,
) -> list[AcscEntry]:
    """Paginate through all ACSC listing pages for backfill discovery."""
    all_entries: list[AcscEntry] = []
    page = 0
    delay = settings["acsc"]["delay_daily"]

    while True:
        entries = fetch_listing_page(client, settings, page)
        if not entries:
            break
        all_entries.extend(entries)
        page += 1
        # Rate-limit requests to avoid triggering Akamai bot detection
        time.sleep(delay)

    logger.info("Fetched %d entries across %d listing pages", len(all_entries), page)
    return all_entries


# -- Akamai block detection ----------------------------------------------------


def detect_akamai_block(response: httpx.Response) -> bool:
    """Detect if a response is an Akamai Bot Manager block page."""
    # Akamai returns 403 with a reference ID, unlike Cloudflare's 200 challenges
    if response.status_code == 403:
        text = response.text[:2048]
        if "Reference #" in text or "Access Denied" in text:
            logger.debug("Akamai block detected: 403 with reference ID")
            return True

    content_len = len(response.content)

    # Block pages are typically under 2KB with no real page structure
    if 0 < content_len < 2048:
        text = response.text
        if "<article" not in text and 'role="main"' not in text:
            logger.debug("Akamai block suspected: small response (%d bytes)", content_len)
            return True

    text_prefix = response.text[:2048]
    if any(marker in text_prefix for marker in _AKAMAI_MARKERS):
        logger.debug("Akamai block detected: known marker in response")
        return True

    return False


def extract_page_title(raw_html: str) -> str | None:
    """Extract article title from an ACSC advisory page."""
    soup = BeautifulSoup(raw_html, "lxml")
    h1 = soup.select_one("article h1, h1.page-title, h1")
    if h1:
        text = h1.get_text(strip=True)
        if text:
            return text
    title_tag = soup.find("title")
    if title_tag:
        text = title_tag.get_text(strip=True)
        if text:
            return text.split("|")[0].strip()
    return None


# -- Article extraction --------------------------------------------------------


def _strip_noise(element: Tag) -> None:
    """Remove navigation, scripts, and other non-content elements."""
    for tag_name in ("nav", "script", "style"):
        for el in element.find_all(tag_name):
            el.decompose()

    for el in element.find_all(
        class_=lambda c: c and any(n in c for n in _NOISE_CLASSES),
    ):
        el.decompose()


def extract_article_body(raw_html: str) -> str:
    """Extract the main article content from an ACSC advisory page."""
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
    _resolve_relative_links(matched, "https://www.cyber.gov.au")
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


# -- Advisory scraping ---------------------------------------------------------


def _write_html_cache(data_dir: Path, advisory_id: str, html: str) -> None:
    """Persist raw HTML to the monthly cache directory."""
    try:
        cache_file = html_cache_path(data_dir, "acsc", advisory_id)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(html, encoding="utf-8")
    except OSError:
        logger.warning("Failed to write html_cache for %s", advisory_id)


def scrape_advisory(
    client: httpx.Client, url: str, settings: dict, data_dir: Path,
) -> ScrapeResult:
    """Fetch and extract content from a single ACSC advisory page."""
    advisory_id = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]

    try:
        response = client.get(url)
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.warning("Network error scraping %s: %s", url, exc)
        return ScrapeResult(
            advisory_id=advisory_id, url=url, status="error",
            raw_html=None, article_body=None, http_status=None, cf_ray=None,
            error=str(exc),
        )

    # Akamai uses 403 for blocks, so check before the status code gate
    if detect_akamai_block(response):
        logger.warning("Akamai block for %s", url)
        return ScrapeResult(
            advisory_id=advisory_id, url=url, status="cf_challenged",
            raw_html=None, article_body=None,
            http_status=response.status_code, cf_ray=None,
            response_size=len(response.content),
        )

    if response.status_code != 200:
        return ScrapeResult(
            advisory_id=advisory_id, url=url, status="http_error",
            raw_html=None, article_body=None,
            http_status=response.status_code, cf_ray=None,
        )

    article_body = extract_article_body(response.text)
    _write_html_cache(data_dir, advisory_id, response.text)
    return ScrapeResult(
        advisory_id=advisory_id, url=url, status="ok",
        raw_html=response.text, article_body=article_body,
        http_status=200, cf_ray=None,
    )


# -- Backfill & batch scraping -------------------------------------------------


def seed_backfill(
    conn: sqlite3.Connection,
    entries: list[AcscEntry],
    limit: int | None = None,
) -> int:
    """Insert new ACSC entries into the database as pending advisories."""
    if limit is not None:
        entries = entries[:limit]

    seeded = 0
    now = datetime.now(timezone.utc).isoformat()
    for entry in entries:
        if db.get_advisory(conn, entry.advisory_id) is not None:
            continue
        db.upsert_advisory(conn, {
            "advisory_id": entry.advisory_id,
            "type": entry.advisory_type,
            "source": "acsc",
            "title": entry.title,
            "link": entry.url,
            "pub_date": entry.pub_date,
            "scrape_status": "pending",
            "first_seen": now,
        })
        seeded += 1

    logger.info("Seeded %d new advisories from ACSC", seeded)
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
    """Scrape a batch of ACSC advisories with rate-limiting delays."""
    batch_data_dir = data_dir or Path(settings.get("data_dir", "data"))
    counts = {"scraped": 0, "cf_challenged": 0, "failed": 0, "errors": 0}
    for i, adv in enumerate(advisories):
        result = scrape_advisory(client, adv["link"], settings, batch_data_dir)
        if result.status == "ok":
            db.update_scrape_result(
                conn, adv["advisory_id"], "scraped", result.raw_html, result.article_body,
            )
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
            # Conservative delay to respect ACSC rate limits
            time.sleep(delay)

    return counts


# -- Poll orchestrator ---------------------------------------------------------


def acsc_poll(
    conn: sqlite3.Connection,
    client: httpx.Client,
    settings: dict,
    data_dir: Path | None = None,
) -> dict:
    """Run a full ACSC RSS poll and scrape cycle."""
    poll_data_dir = data_dir or Path(settings.get("data_dir", "data"))

    entries = fetch_rss_entries(client, settings)
    seeded = seed_backfill(conn, entries)

    pending = db.get_pending_scrape(
        conn, settings["acsc"]["backfill_batch_size"], source="acsc",
    )
    counts = {"scraped": 0, "cf_challenged": 0, "failed": 0, "errors": 0}
    if pending:
        batch_counts = scrape_batch(
            conn, client, settings, pending,
            settings["acsc"]["delay_daily"], 0,
            data_dir=poll_data_dir,
        )
        for key in batch_counts:
            counts[key] += batch_counts[key]

    logger.info(
        "ACSC poll complete: %d RSS entries, %d seeded, %d scraped",
        len(entries), seeded, counts["scraped"],
    )
    return {
        "rss_entries": len(entries),
        "seeded": seeded,
        "scraped": counts["scraped"],
        "cf_challenged": counts["cf_challenged"],
        "errors": counts["errors"],
    }
