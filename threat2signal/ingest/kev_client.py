"""CISA Known Exploited Vulnerabilities catalog client."""

import logging
from typing import TYPE_CHECKING

import httpx

from threat2signal.ingest.http import create_http_client
from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def _fetch_kev_json(client: httpx.Client, url: str) -> list[dict]:
    """Download the KEV catalog and return the vulnerabilities list."""
    resp = client.get(url)
    resp.raise_for_status()
    data = resp.json()
    return data.get("vulnerabilities") or []


def _map_kev_entry(entry: dict) -> dict:
    """Map a raw KEV JSON object to the db upsert schema."""
    return {
        "cve_id": entry.get("cveID"),
        "vendor": entry.get("vendorProject"),
        "product": entry.get("product"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "date_added": entry.get("dateAdded"),
        "due_date": entry.get("dueDate"),
        "known_ransomware": entry.get("knownRansomwareCampaignUse"),
        "notes": entry.get("notes"),
    }


def kev_poll(conn: "sqlite3.Connection", settings: dict) -> dict:
    """Fetch the CISA KEV catalog and upsert all entries."""
    user_agent = settings.get("msrc", {}).get("user_agent", "Threat2Signal/1.0")
    client = create_http_client(user_agent, 10, 30, use_curl_cffi=False)
    kev_url = settings.get("cisa", {}).get("kev_url", _KEV_URL)

    try:
        entries = _fetch_kev_json(client, kev_url)
    except (httpx.HTTPStatusError, httpx.TimeoutException):
        logger.exception("Failed to fetch KEV catalog from %s", kev_url)
        client.close()
        return {"total": 0, "upserted": 0}

    upserted = 0
    with conn:
        for entry in entries:
            mapped = _map_kev_entry(entry)
            if not mapped.get("cve_id"):
                continue
            try:
                db.upsert_kev_entry(conn, mapped)
                upserted += 1
            except Exception:
                logger.exception("Error upserting KEV entry %s", mapped.get("cve_id"))

    client.close()
    logger.info("KEV poll: %d total entries, %d upserted", len(entries), upserted)
    return {"total": len(entries), "upserted": upserted}
