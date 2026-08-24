"""JPCERT/CC Eyes blog discovery and scraping."""

from __future__ import annotations

import logging
import random
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from bs4 import BeautifulSoup, Tag

from threat2signal.ingest.http import create_http_client as _make_http_client
from threat2signal.ingest.http import html_cache_path
from threat2signal.ingest.models import JpcertEntry, ScrapeResult, normalize_date
from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

_ATOM_NS = "http://www.w3.org/2005/Atom"

# Blog post URLs follow /en/YYYY/MM/slug.html
_POST_URL_RE = re.compile(r"/en/(\d{4})/(\d{2})/([^/]+)\.html")

_ARTICLE_SELECTORS = (
    ".entry-body",
    ".entry-content",
    "article .content",
    "article",
    "[role='main'], main",
)

_NOISE_TAGS = ("nav", "script", "style")
_NOISE_CLASSES = (
    "sidebar", "footer", "header", "comments",
    "navigation", "social-share", "breadcrumb", "menu",
)


# -- HTTP client ---------------------------------------------------------------


def create_jpcert_client(settings: dict) -> httpx.Client:
    """Create an httpx client for JPCERT blog scraping."""
    return _make_http_client(
        user_agent=settings["jpcert"]["user_agent"],
        connect_timeout=settings["http"]["connect_timeout"],
        read_timeout=settings["http"]["read_timeout"],
        # JPCERT has no anti-bot protection; plain httpx suffices
        use_curl_cffi=False,
    )


# -- Advisory ID derivation ----------------------------------------------------


def _derive_advisory_id(url: str) -> str:
    """Extract advisory ID from a JPCERT blog post URL."""
    match = _POST_URL_RE.search(url)
    if match is None:
        slug = url.rstrip("/").rsplit("/", 1)[-1]
        if slug.endswith(".html"):
            slug = slug[:-5]
        return f"jpcert-{slug}"
    year, month, slug = match.groups()
    return f"jpcert-{year}{month}-{slug}"


# -- Atom feed -----------------------------------------------------------------


def _atom_entry_to_jpcert(
    entry_el: ET.Element, ns: dict[str, str], categories: list[str],
) -> JpcertEntry | None:
    """Convert one Atom <entry> to a JpcertEntry, or None if filtered out."""
    # A post may carry multiple <category> elements; pick the first match
    matched_cat = ""
    for cat_el in entry_el.findall("atom:category", ns):
        term = (cat_el.get("term") or "").lower()
        if term in categories:
            matched_cat = term
            break
    if not matched_cat:
        return None

    title_el = entry_el.find("atom:title", ns)
    link_el = entry_el.find("atom:link", ns)
    pub_el = entry_el.find("atom:published", ns)

    title = title_el.text.strip() if title_el is not None and title_el.text else ""
    url = link_el.get("href", "") if link_el is not None else ""
    raw_date = pub_el.text.strip() if pub_el is not None and pub_el.text else ""
    pub_date = normalize_date(raw_date) or ""

    if not url:
        return None

    return JpcertEntry(
        url=url,
        title=title,
        pub_date=pub_date,
        category=matched_cat,
        advisory_id=_derive_advisory_id(url),
    )


def _parse_atom_feed(xml_bytes: bytes, categories: list[str]) -> list[JpcertEntry]:
    """Parse Atom XML into JpcertEntry items filtered by category."""
    root = ET.fromstring(xml_bytes)
    ns = {"atom": _ATOM_NS}
    entries: list[JpcertEntry] = []

    for entry_el in root.findall("atom:entry", ns):
        entry = _atom_entry_to_jpcert(entry_el, ns, categories)
        if entry is not None:
            entries.append(entry)

    logger.info(
        "Atom feed parsed: %d entries matching categories %s",
        len(entries), categories,
    )
    return entries


def fetch_atom_entries(client: httpx.Client, settings: dict) -> list[JpcertEntry]:
    """Fetch the JPCERT Atom feed and return matching entries."""
    atom_url = settings["jpcert"]["atom_url"]
    categories = settings["jpcert"]["categories"]
    try:
        response = client.get(atom_url)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Atom feed fetch failed: %s returned %s",
            atom_url, exc.response.status_code,
        )
        raise
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.error("Network error fetching Atom feed %s: %s", atom_url, exc)
        raise

    logger.info("Fetched Atom feed from %s (%d bytes)", atom_url, len(response.content))
    return _parse_atom_feed(response.content, categories)


# -- Category listing pages ----------------------------------------------------


def _listing_link_to_entry(
    link: Tag, category: str, base_url: str, seen_urls: set[str],
) -> JpcertEntry | None:
    """Convert a listing page <a> to a JpcertEntry if it matches a post URL."""
    href = str(link.get("href", ""))
    match = _POST_URL_RE.search(href)
    if match is None:
        return None

    # Resolve relative paths against the blog origin
    if not href.startswith("http"):
        origin = base_url.split("/en")[0] if "/en" in base_url else base_url.rstrip("/")
        href = origin + (href if href.startswith("/") else "/" + href)

    title = link.get_text(strip=True)
    if not title:
        return None

    if href in seen_urls:
        return None
    seen_urls.add(href)

    pub_date = normalize_date(f"{match.group(1)}-{match.group(2)}") or ""

    return JpcertEntry(
        url=href,
        title=title,
        pub_date=pub_date,
        category=category,
        advisory_id=_derive_advisory_id(href),
    )


def _parse_listing_page(
    html: str, category: str, base_url: str,
) -> list[JpcertEntry]:
    """Extract blog post entries from a category listing page."""
    soup = BeautifulSoup(html, "lxml")
    entries: list[JpcertEntry] = []
    seen_urls: set[str] = set()

    for link in soup.find_all("a", href=True):
        entry = _listing_link_to_entry(link, category, base_url, seen_urls)
        if entry is not None:
            entries.append(entry)

    return entries


def fetch_category_listing(
    client: httpx.Client, settings: dict, category: str, page: int = 1,
) -> list[JpcertEntry]:
    """Fetch one page of a JPCERT blog category listing."""
    base_url = settings["jpcert"]["blog_base_url"].rstrip("/")
    if page <= 1:
        url = f"{base_url}/{category}/"
    else:
        url = f"{base_url}/{category}/page/{page}/"

    try:
        response = client.get(url)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # 404 signals end of pagination
        if exc.response.status_code == 404:
            logger.debug(
                "Category %s page %d returned 404 — end of listing",
                category, page,
            )
            return []
        logger.warning("Listing fetch failed: %s returned %s", url, exc.response.status_code)
        return []
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.warning("Network error fetching listing %s: %s", url, exc)
        return []

    return _parse_listing_page(response.text, category, base_url)


def _collect_category_pages(
    client: httpx.Client,
    settings: dict,
    category: str,
    delay: float,
    all_entries: list[JpcertEntry],
    seen_urls: set[str],
) -> None:
    """Paginate one category until empty, appending deduplicated entries."""
    page = 1
    while True:
        entries = fetch_category_listing(client, settings, category, page)
        if not entries:
            break
        for entry in entries:
            if entry.url not in seen_urls:
                seen_urls.add(entry.url)
                all_entries.append(entry)
        page += 1
        # Respect rate limits between pagination requests
        time.sleep(delay)


def fetch_all_category_entries(
    client: httpx.Client, settings: dict,
) -> list[JpcertEntry]:
    """Paginate all configured categories and return deduplicated entries."""
    categories = settings["jpcert"]["categories"]
    delay = settings["jpcert"]["delay_daily"]
    all_entries: list[JpcertEntry] = []
    seen_urls: set[str] = set()

    for category in categories:
        _collect_category_pages(
            client, settings, category, delay, all_entries, seen_urls,
        )

    logger.info(
        "Category listings: %d unique entries across %s",
        len(all_entries), categories,
    )
    return all_entries


# -- Article extraction --------------------------------------------------------


def _strip_noise(element: Tag) -> None:
    """Remove navigation, scripts, and other non-content elements."""
    for tag_name in _NOISE_TAGS:
        for el in element.find_all(tag_name):
            el.decompose()

    for el in element.find_all(
        class_=lambda c: c and any(n in c for n in _NOISE_CLASSES),
    ):
        el.decompose()


def extract_article_body(raw_html: str) -> str:
    """Extract the main article content from a JPCERT blog post."""
    soup = BeautifulSoup(raw_html, "lxml")

    matched = None
    for selector in _ARTICLE_SELECTORS:
        candidate = soup.select_one(selector)
        # Blog posts can be shorter than CISA advisories
        if candidate and len(candidate.get_text(strip=True)) >= 300:
            matched = candidate
            break

    if matched is None:
        logger.warning("No article body found, using full body as fallback")
        return str(soup.body) if soup.body else raw_html

    _strip_noise(matched)
    return str(matched)


def extract_page_title(raw_html: str) -> str | None:
    """Extract article title from a JPCERT blog page."""
    soup = BeautifulSoup(raw_html, "lxml")
    for selector in (".entry-title", "h1.title", "article h1"):
        el = soup.select_one(selector)
        if el:
            text = el.get_text(strip=True)
            if text:
                return text
    title_tag = soup.find("title")
    if title_tag:
        text = title_tag.get_text(strip=True)
        if text:
            parts = re.split(r"\s*[-|]\s*", text)
            if parts:
                return parts[0].strip()
    return None


def extract_pub_date(raw_html: str) -> str | None:
    """Extract publication date from a JPCERT blog page."""
    soup = BeautifulSoup(raw_html, "lxml")
    time_el = soup.select_one("article time[datetime], .entry-date, time.published")
    if time_el:
        dt = time_el.get("datetime") or time_el.get_text(strip=True)
        if dt:
            return normalize_date(str(dt)) or None
    return None


# -- Post scraping -------------------------------------------------------------


def _write_html_cache(data_dir: Path, advisory_id: str, html: str) -> None:
    """Persist raw HTML to the monthly cache directory."""
    try:
        cache_file = html_cache_path(data_dir, "jpcert", advisory_id)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(html, encoding="utf-8")
    except OSError:
        logger.warning("Failed to write html_cache for %s", advisory_id)


def scrape_post(
    client: httpx.Client, url: str, settings: dict, data_dir: Path,
) -> ScrapeResult:
    """Fetch and extract content from a single JPCERT blog post."""
    advisory_id = _derive_advisory_id(url)

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
    entries: list[JpcertEntry],
    limit: int | None = None,
) -> int:
    """Insert new JPCERT entries into the advisory table as pending."""
    if limit is not None:
        entries = entries[:limit]

    seeded = 0
    now = datetime.now(timezone.utc).isoformat()
    for entry in entries:
        if db.get_advisory(conn, entry.advisory_id) is not None:
            continue
        db.upsert_advisory(conn, {
            "advisory_id": entry.advisory_id,
            "type": f"jpcert_{entry.category}",
            "source": "jpcert",
            "title": entry.title,
            "link": entry.url,
            "pub_date": entry.pub_date,
            "scrape_status": "pending",
            "first_seen": now,
        })
        seeded += 1

    logger.info("Seeded %d new advisories from JPCERT", seeded)
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
    """Scrape a batch of JPCERT blog posts with rate-limiting delays."""
    batch_data_dir = data_dir or Path(settings.get("data_dir", "data"))
    counts: dict[str, int] = {"scraped": 0, "failed": 0, "errors": 0}

    for i, adv in enumerate(advisories):
        result = scrape_post(client, adv["link"], settings, batch_data_dir)
        _record_scrape_outcome(conn, adv["advisory_id"], result, counts)

        if i < len(advisories) - 1:
            delay = delay_base + random.uniform(0, delay_jitter)
            # Rate limit to avoid overloading JPCERT servers
            time.sleep(delay)

    return counts


def _record_scrape_outcome(
    conn: sqlite3.Connection,
    advisory_id: str,
    result: ScrapeResult,
    counts: dict[str, int],
) -> None:
    """Update the database and counters from a single scrape result."""
    if result.status == "ok":
        db.update_scrape_result(
            conn, advisory_id, "scraped", result.raw_html, result.article_body,
        )
        counts["scraped"] += 1
    elif result.status == "http_error":
        db.update_scrape_result(conn, advisory_id, "failed", None, None)
        counts["failed"] += 1
        logger.warning("HTTP error %s for %s", result.http_status, advisory_id)
    else:
        db.update_scrape_result(conn, advisory_id, "failed", None, None)
        counts["errors"] += 1


# -- Poll orchestrator ---------------------------------------------------------


def jpcert_poll(
    conn: sqlite3.Connection,
    client: httpx.Client,
    settings: dict,
    data_dir: Path | None = None,
) -> dict:
    """Run a JPCERT Atom feed poll and scrape cycle."""
    poll_data_dir = data_dir or Path(settings.get("data_dir", "data"))
    entries = fetch_atom_entries(client, settings)
    seeded = seed_backfill(conn, entries)

    pending = db.get_pending_scrape(
        conn, settings["jpcert"]["backfill_batch_size"], source="jpcert",
    )
    counts: dict[str, int] = {"scraped": 0, "failed": 0, "errors": 0}
    if pending:
        counts = scrape_batch(
            conn, client, settings, pending,
            settings["jpcert"]["delay_daily"], 0,
            data_dir=poll_data_dir,
        )

    logger.info(
        "JPCERT poll: %d atom entries, %d seeded, %d scraped, %d errors",
        len(entries), seeded, counts["scraped"], counts["errors"],
    )
    return {
        "atom_entries": len(entries),
        "seeded": seeded,
        "scraped": counts["scraped"],
        "failed": counts["failed"],
        "errors": counts["errors"],
    }
