"""MSRC API client for CVE discovery and enrichment."""

import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from threat2signal.analysis.msrc_scorer import (
    compute_defense_score,
    compute_vr_score,
    generate_vr_tags,
    is_ignored,
    load_scoring_config,
)
from threat2signal.ingest.http import create_http_client
from threat2signal.ingest.models import KbRecord, MsrcCveRecord
from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# CVSS 3.x short-code to human-readable label mappings
_AV_MAP = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
_AC_MAP = {"L": "Low", "H": "High"}
_PR_MAP = {"N": "None", "L": "Low", "H": "High"}
_UI_MAP = {"N": "None", "R": "Required"}
_SCOPE_MAP = {"U": "Unchanged", "C": "Changed"}


# -- RSS discovery (A.9) ------------------------------------------------------


def fetch_rss(client: httpx.Client, rss_url: str) -> list[str]:
    """Fetch the MSRC RSS feed and return a deduplicated sorted list of CVE IDs."""
    resp = client.get(rss_url)
    resp.raise_for_status()

    root = ET.fromstring(resp.content)
    cve_ids: set[str] = set()
    for title_el in root.iter("title"):
        if title_el.text:
            cve_ids.update(re.findall(r"CVE-\d{4}-\d{4,7}", title_el.text))

    result = sorted(cve_ids)
    logger.info("MSRC RSS: discovered %d unique CVE IDs", len(result))
    return result


# -- HTTP retry helper (A.10) -------------------------------------------------


def _retry_wait(url: str, reason: str, attempt: int, max_retries: int, wait: float) -> None:
    """Log a retry warning and sleep."""
    logger.warning("%s on %s (attempt %d/%d), waiting %.0fs", reason, url, attempt, max_retries, wait)
    time.sleep(wait)


def _request_with_retry(
    client: httpx.Client, url: str, max_retries: int = 3,
) -> httpx.Response | None:
    """GET with retry on 429, 5xx, and timeouts; returns None on failure."""
    for attempt in range(1, max_retries + 1):
        try:
            resp = client.get(url)
        except httpx.TimeoutException:
            _retry_wait(url, "Timeout", attempt, max_retries, 5.0 * attempt)
            continue

        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after else 60.0 * attempt
            except (ValueError, TypeError):
                wait = 60.0 * attempt
            _retry_wait(url, "Rate-limited", attempt, max_retries, wait)
            continue

        if 500 <= resp.status_code < 600:
            _retry_wait(url, f"Server error {resp.status_code}", attempt, max_retries, 5.0 * attempt)
            continue

        if 400 <= resp.status_code < 500:
            logger.error("Client error %d on %s, not retrying", resp.status_code, url)
            return None

        return resp

    logger.error("Exhausted %d retries for %s", max_retries, url)
    return None


# -- CVSS vector parsing (A.10) -----------------------------------------------


def _parse_cvss_vector(vector: str | None) -> dict[str, str]:
    """Parse a CVSS 3.x vector string into labelled metric dict."""
    if not vector:
        return {}
    try:
        parts = vector.split("/")
        metrics = {p.split(":")[0]: p.split(":")[1] for p in parts if ":" in p}
    except (IndexError, ValueError):
        logger.warning("Unparseable CVSS vector: %r", vector)
        return {}
    return {
        k: v
        for k, v in (
            ("av", _AV_MAP.get(metrics.get("AV", ""), "")),
            ("ac", _AC_MAP.get(metrics.get("AC", ""), "")),
            ("pr", _PR_MAP.get(metrics.get("PR", ""), "")),
            ("ui", _UI_MAP.get(metrics.get("UI", ""), "")),
            ("scope", _SCOPE_MAP.get(metrics.get("S", ""), "")),
        )
        if v
    }


# -- Vulnerability sub-parsers (A.11) -----------------------------------------


def _extract_cvss(vuln: dict) -> tuple[float | None, float | None, str | None, dict]:
    """Return (base, temporal, vector_str, parsed_labels) from CVSSScoreSets."""
    score_sets = vuln.get("CVSSScoreSets") or []
    first = score_sets[0] if score_sets else {}
    vector = first.get("Vector")
    return first.get("BaseScore"), first.get("TemporalScore"), vector, _parse_cvss_vector(vector)


def _desc_value(obj: dict | None) -> str | None:
    """Safely extract .Description.Value from a threat/remediation entry."""
    if not obj:
        return None
    desc = obj.get("Description")
    return desc.get("Value") if isinstance(desc, dict) else None


def _extract_threats(
    vuln: dict,
) -> tuple[str | None, str | None, str | None, bool, bool]:
    """Parse Threats array -> (impact, severity, exploit_status, disclosed, exploited)."""
    impact = severity = exploit_status = None
    publicly_disclosed = False
    exploited_wild = False
    for threat in vuln.get("Threats") or []:
        desc = _desc_value(threat)
        if desc is None:
            continue
        t_type = threat.get("Type")
        if t_type == 0:
            impact = desc
        elif t_type == 1:
            exploit_status = desc
            desc_lower = desc.lower()
            exploited_wild = "exploited:yes" in desc_lower
            publicly_disclosed = "disclosed:yes" in desc_lower
        elif t_type == 3:
            severity = desc
    return impact, severity, exploit_status, publicly_disclosed, exploited_wild


def _extract_remediations(
    vuln: dict,
    cve_id: str,
) -> tuple[list[KbRecord], str | None, str | None, str | None]:
    """Parse Remediations -> (kb_records, customer_action, component, released)."""
    kb_records: list[KbRecord] = []
    customer_action = component = released = None
    for rem in vuln.get("Remediations") or []:
        if rem.get("Type") == 2:
            product_name = _desc_value(rem)
            if component is None and product_name:
                component = product_name
            if released is None and rem.get("DateSpecified") and rem.get("Date"):
                released = rem["Date"][:10]
            for kb_num in rem.get("KB") or []:
                kb_records.append(KbRecord(
                    cve_id=cve_id,
                    kb_number=str(kb_num),
                    product_name=product_name,
                    download_url=rem.get("URL"),
                ))
        desc_val = _desc_value(rem)
        if desc_val and not customer_action and "customer action" in desc_val.lower():
            customer_action = desc_val
    return kb_records, customer_action, component, released


_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    return _HTML_TAG_RE.sub("", text).strip()


def _extract_description(vuln: dict) -> str | None:
    """Extract vulnerability description from MSRC Notes array.

    CVRF Note Types: 1=General, 2=Description, 3=Details, 4=FAQ,
    5=Legal, 6=Summary, 7=Other, 8=Vendor.  Type 2 is the primary
    description; fall back to Type 7 only if its value looks like
    prose (>40 chars) rather than a bare component name.
    """
    fallback = None
    for note in vuln.get("Notes") or []:
        if not isinstance(note, dict):
            continue
        note_type = note.get("Type")
        if note_type == 2:
            value = note.get("Value")
            if value:
                clean = _strip_html(str(value))
                if len(clean) > 10:
                    return clean
        if note_type == 7 and fallback is None:
            value = note.get("Value")
            if value:
                clean = _strip_html(str(value))
                if len(clean) > 40:
                    fallback = clean
    return fallback


def _extract_component_from_notes(vuln: dict) -> str | None:
    """Extract component/product name from CVRF Notes Type 7 (Other)."""
    for note in vuln.get("Notes") or []:
        if not isinstance(note, dict):
            continue
        if note.get("Type") == 7:
            value = note.get("Value")
            if value and str(value).strip():
                return str(value).strip()
    return None


def _extract_cwe(vuln: dict) -> tuple[str | None, str | None]:
    """Extract CWE ID and description from Notes array."""
    for note in vuln.get("Notes") or []:
        if not isinstance(note, dict):
            continue
        if str(note.get("Type", "")).lower() != "cwe":
            continue
        value = note.get("Value")
        if not value:
            continue
        match = re.search(r"(CWE-\d+)", str(value))
        return (match.group(1) if match else None), str(value)
    return None, None


def _extract_released_fallback(vuln: dict) -> str | None:
    """Fall back to RevisionHistory for a release date."""
    for rev in vuln.get("RevisionHistory") or []:
        if rev.get("Date"):
            return rev["Date"][:10]
    return None


# -- Shared vulnerability parser (A.11) ---------------------------------------


def _parse_vulnerability(vuln: dict, cve_id: str) -> tuple[MsrcCveRecord, list[KbRecord]]:
    """Extract an MsrcCveRecord and KB entries from a single MSRC vuln dict."""
    title_obj = vuln.get("Title")
    title = title_obj.get("Value") if isinstance(title_obj, dict) else None
    description = _extract_description(vuln)
    cvss_base, cvss_temporal, cvss_vector, parsed_vec = _extract_cvss(vuln)
    impact, severity, exploit_status, disclosed, exploited = _extract_threats(vuln)
    kb_records, customer_action, rem_component, released = _extract_remediations(vuln, cve_id)
    component = _extract_component_from_notes(vuln) or rem_component
    cwe_id, cwe_desc = _extract_cwe(vuln)
    if released is None:
        released = _extract_released_fallback(vuln)

    record = MsrcCveRecord(
        cve_id=cve_id, title=title, description=description, released=released,
        component=component, impact=impact, severity=severity,
        cvss_base=cvss_base, cvss_temporal=cvss_temporal,
        cvss_vector=cvss_vector,
        av=parsed_vec.get("av"), ac=parsed_vec.get("ac"),
        pr=parsed_vec.get("pr"), ui=parsed_vec.get("ui"),
        scope=parsed_vec.get("scope"),
        cwe_id=cwe_id, cwe_description=cwe_desc,
        exploit_status=exploit_status,
        publicly_disclosed=disclosed, exploited_wild=exploited,
        customer_action=customer_action,
        raw_json=json.dumps(vuln, default=str),
    )
    return record, kb_records


# -- CVE API enrichment (A.10) ------------------------------------------------


def enrich_cve(
    client: httpx.Client,
    cve_api_url: str,
    cve_id: str,
) -> tuple[MsrcCveRecord, list[KbRecord]] | None:
    """Fetch and parse a single CVE from the MSRC CVE API."""
    url = f"{cve_api_url}/{cve_id}"
    resp = _request_with_retry(client, url)
    if resp is None:
        logger.error("Failed to fetch CVE data for %s", cve_id)
        return None

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        logger.error("Invalid JSON in response for %s", cve_id)
        return None

    return _parse_vulnerability(data, cve_id)


# -- CVRF bulk import (A.11) ---------------------------------------------------


def fetch_cvrf_month(
    client: httpx.Client,
    cvrf_url: str,
    year_month: str,
) -> tuple[list[MsrcCveRecord], list[KbRecord]]:
    """Fetch a month's CVRF document and return all CVE + KB records."""
    url = f"{cvrf_url}/{year_month}"
    resp = _request_with_retry(client, url)
    if resp is None:
        logger.error("Failed to fetch CVRF for %s", year_month)
        return [], []

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        logger.error("Invalid JSON in CVRF response for %s", year_month)
        return [], []

    all_records: list[MsrcCveRecord] = []
    all_kbs: list[KbRecord] = []
    for vuln in data.get("Vulnerability") or []:
        cve_id = vuln.get("CVE")
        if not cve_id:
            continue
        record, kbs = _parse_vulnerability(vuln, cve_id)
        all_records.append(record)
        all_kbs.extend(kbs)

    logger.info(
        "CVRF %s: parsed %d CVEs, %d KB entries",
        year_month, len(all_records), len(all_kbs),
    )
    return all_records, all_kbs


# -- Orchestrator helpers (A.12) -----------------------------------------------


def _score_and_store(
    conn: "sqlite3.Connection",
    record: MsrcCveRecord,
    kb_records: list[KbRecord],
    kev_ids: set[str],
    config: dict,
) -> None:
    """Score a CVE record, persist it and its KB entries atomically."""
    cve_dict = asdict(record)
    score, priority, breakdown = compute_defense_score(cve_dict, kev_ids, config)
    cve_dict["defense_score"] = score
    cve_dict["priority"] = priority
    matched_component = breakdown.get("component", {}).get("name", "")
    if matched_component and not cve_dict.get("component_category"):
        cve_dict["component_category"] = matched_component
    cve_dict["has_kb_entries"] = len(kb_records) > 0
    vr_score, vr_priority, _ = compute_vr_score(cve_dict, kev_ids, config)
    vr_tags = generate_vr_tags(cve_dict, kev_ids, config)
    cve_dict["vr_score"] = vr_score
    cve_dict["vr_priority"] = vr_priority
    cve_dict["vr_tags"] = json.dumps(vr_tags)
    with conn:
        db.upsert_msrc_cve(conn, cve_dict)
        db.replace_kb_entries(
            conn,
            record.cve_id,
            [(kb.kb_number, kb.product_name, kb.download_url) for kb in kb_records],
        )


def _group_kbs_by_cve(kb_records: list[KbRecord]) -> dict[str, list[KbRecord]]:
    """Index a flat KB list by cve_id for efficient per-CVE lookup."""
    grouped: dict[str, list[KbRecord]] = {}
    for kb in kb_records:
        grouped.setdefault(kb.cve_id, []).append(kb)
    return grouped


def _backfill_month(
    conn: "sqlite3.Connection",
    client: httpx.Client,
    cvrf_url: str,
    month: str,
    kev_ids: set[str],
    config: dict,
) -> tuple[int, int, list[str]]:
    """Process one CVRF month; returns (new_count, error_count, error_ids)."""
    records, kb_records = fetch_cvrf_month(client, cvrf_url, month)
    kb_by_cve = _group_kbs_by_cve(kb_records)

    new_count = 0
    error_count = 0
    error_ids: list[str] = []
    for record in records:
        if is_ignored(record.component, config["ignore_list"]):
            continue
        try:
            _score_and_store(conn, record, kb_by_cve.get(record.cve_id, []), kev_ids, config)
            new_count += 1
        except Exception:
            logger.exception("Error storing CVE %s", record.cve_id)
            error_count += 1
            error_ids.append(record.cve_id)
    return new_count, error_count, error_ids


# -- Orchestrators (A.12) -----------------------------------------------------


def msrc_poll(conn: "sqlite3.Connection", settings: dict) -> dict:
    """Run one MSRC poll cycle: discover new CVEs via RSS, enrich, score, store."""
    client = create_http_client(
        settings["msrc"]["user_agent"], 10, 30, use_curl_cffi=False,
    )
    client.headers["Accept"] = "application/json"
    config = load_scoring_config(PROJECT_ROOT / "config" / "scoring.yaml")
    kev_ids = db.get_kev_cve_ids(conn)
    known = db.get_known_msrc_cve_ids(conn)

    rss_ids = fetch_rss(client, settings["msrc"]["rss_url"])
    new_ids = [cid for cid in rss_ids if cid not in known]
    batch_size = settings["msrc"].get("daily_batch_size")
    if batch_size and len(new_ids) > batch_size:
        logger.info(
            "MSRC poll: %d new CVEs, capping to %d per daily_batch_size",
            len(new_ids), batch_size,
        )
        new_ids = new_ids[:batch_size]
    logger.info("MSRC poll: %d new CVEs out of %d in RSS", len(new_ids), len(rss_ids))

    new_count = 0
    error_count = 0
    errors: list[str] = []
    for cve_id in new_ids:
        result = enrich_cve(client, settings["msrc"]["cve_api_url"], cve_id)
        if result is None:
            error_count += 1
            errors.append(cve_id)
            continue
        record, kb_records = result
        if is_ignored(record.component, config["ignore_list"]):
            logger.debug("Skipping ignored component: %s (%s)", record.component, cve_id)
            continue
        try:
            _score_and_store(conn, record, kb_records, kev_ids, config)
            new_count += 1
        except Exception:
            logger.exception("Error storing CVE %s", cve_id)
            error_count += 1
            errors.append(cve_id)

        time.sleep(1)  # 1s courtesy delay between MSRC API calls

    error_str = ", ".join(errors) if errors else None
    db.insert_msrc_poll(conn, new_count, 0, error_str)
    client.close()
    return {"new_cves": new_count, "updated_cves": 0, "errors": error_count}


def msrc_backfill(
    conn: "sqlite3.Connection",
    settings: dict,
    months: list[str],
    delay: float = 5.0,
) -> dict:
    """Backfill historical Patch Tuesday data for the given months."""
    client = create_http_client(
        settings["msrc"]["user_agent"], 10, 30, use_curl_cffi=False,
    )
    client.headers["Accept"] = "application/json"
    config = load_scoring_config(PROJECT_ROOT / "config" / "scoring.yaml")
    kev_ids = db.get_kev_cve_ids(conn)

    total_new = 0
    total_errors = 0
    for month in months:
        month_new, month_errors, error_ids = _backfill_month(
            conn, client, settings["msrc"]["cvrf_bulk_url"], month, kev_ids, config,
        )
        error_str = ", ".join(error_ids) if error_ids else None
        db.insert_msrc_poll(conn, month_new, 0, error_str)
        total_new += month_new
        total_errors += month_errors
        logger.info(
            "CVRF backfill %s: %d CVEs stored, %d errors",
            month, month_new, month_errors,
        )
        time.sleep(delay)  # courtesy delay between monthly bulk fetches

    client.close()
    return {"new_cves": total_new, "updated_cves": 0, "errors": total_errors}
