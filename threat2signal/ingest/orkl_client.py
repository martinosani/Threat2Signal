"""ORKL CTI library API client -- fetch and cache report entries."""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


# -- HTTP client ---------------------------------------------------------------


def create_orkl_client(settings: dict) -> httpx.Client:
    """Create an httpx client configured for the ORKL API."""
    orkl = settings.get("orkl", {})
    http = settings.get("http", {})
    base_url = orkl.get("api_base_url", "https://orkl.eu/api/v1")
    connect_timeout = http.get("connect_timeout", 30)
    read_timeout = http.get("read_timeout", 60)

    return httpx.Client(
        base_url=base_url,
        headers={"User-Agent": "Threat2Signal/1.0"},
        timeout=httpx.Timeout(connect=connect_timeout, read=read_timeout,
                              write=5.0, pool=5.0),
    )


# -- Single-page fetch ---------------------------------------------------------


def fetch_entry_page(
    client: httpx.Client,
    limit: int = 20,
    offset: int = 0,
    order_by: str = "created_at",
    order: str = "asc",
) -> list[dict]:
    """Fetch one page of ORKL library entries."""
    params = {
        "limit": limit,
        "offset": offset,
        "order_by": order_by,
        "order": order,
    }
    try:
        response = client.get("/library/entries", params=params)
        response.raise_for_status()
    except httpx.HTTPStatusError:
        logger.error(
            "ORKL API returned %s for offset=%d",
            response.status_code, offset,
        )
        raise
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.error("Network error fetching ORKL entries at offset=%d: %s", offset, exc)
        raise

    data = response.json().get("data", [])
    logger.info("ORKL page offset=%d: %d entries returned", offset, len(data))
    return data


# -- Paginated generator -------------------------------------------------------


def fetch_all_entries(client: httpx.Client, settings: dict) -> Iterator[dict]:
    """Yield individual ORKL entries, paginating through the full library."""
    orkl = settings.get("orkl", {})
    batch_size = orkl.get("batch_size", 20)
    delay = orkl.get("delay_between_requests", 1.0)
    language_filter = orkl.get("language_filter", "EN").upper()
    min_quality = orkl.get("min_extraction_quality", 1)

    offset = 0
    page_num = 0

    while True:
        logger.info("ORKL fetch: page %d, offset %d", page_num, offset)
        entries = fetch_entry_page(client, limit=batch_size, offset=offset)

        for entry in entries:
            if entry.get("language", "").upper() != language_filter:
                continue
            if entry.get("extraction_quality", 0) < min_quality:
                continue
            yield entry

        if len(entries) < batch_size:
            break

        offset += batch_size
        page_num += 1
        # Polite delay -- ORKL rate limits are undocumented
        time.sleep(delay)


# -- Cache I/O -----------------------------------------------------------------

_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I,
)


def cache_entry(data_dir: Path, entry: dict) -> Path:
    """Write a single ORKL entry to the JSON cache, return the file path."""
    entry_id = entry["id"]
    if not _UUID_RE.fullmatch(entry_id):
        raise ValueError(f"Invalid ORKL entry ID (expected UUID): {entry_id!r}")

    created_at = entry["created_at"]
    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    year_month = dt.strftime("%Y-%m")

    cache_dir = data_dir / "html_cache" / "orkl" / year_month
    cache_dir.mkdir(parents=True, exist_ok=True)

    out_path = cache_dir / f"{entry_id}.json"
    out_path.write_text(
        json.dumps(entry, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return out_path


def load_cached_entry(path: Path) -> dict:
    """Read and parse a cached ORKL entry JSON file."""
    text = path.read_text(encoding="utf-8")
    return json.loads(text)


# -- Source extraction ----------------------------------------------------------


def extract_original_source(entry: dict) -> str | None:
    """Extract the publisher domain from the first reference URL."""
    refs = entry.get("references", [])
    if not refs:
        return None
    parsed = urlparse(refs[0])
    return parsed.netloc or None
