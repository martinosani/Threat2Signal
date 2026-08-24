"""Daily poll orchestrator."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from threat2signal import config
from threat2signal.analysis._deepseek import create_client, InsufficientBalanceError
from threat2signal.analysis.enricher import enrich_article_body
from threat2signal.analysis.extractor import parse_advisory
from threat2signal.analysis.llm_extractor import extract_intel
from threat2signal.ingest import acsc_client, cisa_client, jpcert_client, kev_client, msrc_client, orkl_client
from threat2signal.ingest.asset_downloader import download_pending_assets
from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_ORKL_PUB_DATE_RE = re.compile(r"Published:\s*(\d{4}-\d{2}-\d{2})")


def run_orkl_poll(
    conn: sqlite3.Connection, settings: dict, data_dir: Path,
) -> dict[str, int]:
    """Poll ORKL for new CTI reports, limited by batch_size."""
    batch_size = settings.get("orkl", {}).get("batch_size", 2)
    client = orkl_client.create_orkl_client(settings)
    try:
        now = datetime.now(timezone.utc).isoformat()
        ingested = 0
        skipped = 0
        for entry in orkl_client.fetch_all_entries(client, settings):
            entry_id = entry.get("id", "")
            try:
                if db.is_advisory_cached(conn, entry_id):
                    skipped += 1
                    continue
                orkl_client.cache_entry(data_dir, entry)
                plain_text = entry.get("plain_text", "")
                lines = plain_text.split("\n", 1)
                summary_text = lines[1][:500] if len(lines) > 1 else plain_text[:500]
                title = entry.get("title") or entry.get("llm_title") or ""
                references = entry.get("references", [])
                m = _ORKL_PUB_DATE_RE.search(plain_text[:300])
                pub_date = m.group(1) if m else entry["created_at"][:10]
                db.upsert_advisory(conn, {
                    "advisory_id": entry_id,
                    "type": "cti_report",
                    "source": "orkl",
                    "original_source": orkl_client.extract_original_source(entry),
                    "title": title,
                    "summary": summary_text.strip(),
                    "link": references[0] if references else None,
                    "pub_date": pub_date,
                    "raw_html": json.dumps(entry, ensure_ascii=False),
                    "article_body": plain_text,
                    "scrape_status": "scraped",
                    "first_seen": now,
                })
                for actor in entry.get("threat_actors", []):
                    main_name = actor.get("main_name", "").strip()
                    if main_name:
                        db.link_advisory_actor(conn, entry_id, main_name)
                        for alias in actor.get("aliases", []):
                            if alias.strip():
                                db.upsert_threat_actor_alias(
                                    conn, alias.strip(), main_name,
                                    actor.get("source_name", ""),
                                )
                        for tool in actor.get("tools", []):
                            if tool.strip():
                                db.link_advisory_malware(conn, entry_id, tool.strip())
                ingested += 1
                logger.info("ORKL ingested: %s — %s", entry_id, title[:60])
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("Skipping malformed ORKL entry %s: %s", entry_id, exc)
                continue
            if ingested >= batch_size:
                break
        return {"ingested": ingested, "skipped": skipped}
    finally:
        client.close()


def cross_reference(conn: sqlite3.Connection) -> int:
    """Scan advisory bodies and extracted JSON for CVE IDs and link via advisory_cve."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT advisory_id, article_body, extracted_json "
        "FROM advisory WHERE article_body IS NOT NULL "
        "OR extracted_json IS NOT NULL",
    )
    rows = cursor.fetchall()
    known_cves = db.get_known_msrc_cve_ids(conn)
    before = conn.total_changes
    for advisory_id, article_body, extracted_json in rows:
        cve_ids: set[str] = set()
        if article_body:
            cve_ids.update(_CVE_RE.findall(article_body))
        if extracted_json:
            cve_ids.update(_CVE_RE.findall(extracted_json))
        for cve_id in cve_ids & known_cves:
            db.link_advisory_cve(conn, advisory_id, cve_id)
    created = conn.total_changes - before
    logger.info("cross_reference: scanned %d advisories, %d new links", len(rows), created)
    return created


def run_parse_extraction(conn: sqlite3.Connection) -> dict[str, int]:
    """Run parse-phase extraction on all advisories with pending extraction status."""
    rows = db.get_advisories_for_parsing(conn)
    known_msrc_cves = db.get_msrc_cve_ids(conn)
    counts: dict[str, int] = {"done": 0, "partial": 0, "failed": 0}
    for row in rows:
        advisory_id = row["advisory_id"]
        try:
            result = parse_advisory(
                advisory_id, row["article_body"], row["source"],
            )
            enriched_body = enrich_article_body(
                row["article_body"], row["source"], advisory_id, result,
                row["numeric_id"], known_msrc_cves=known_msrc_cves,
            )
            status = db.save_parse_results(
                conn, advisory_id, result, enriched_body,
            )
            if status == "parse_done":
                counts["done"] += 1
            elif status == "parse_partial":
                counts["partial"] += 1
            else:
                counts["failed"] += 1
        except Exception as exc:
            logger.exception("Parse-phase extraction failed for %s", advisory_id)
            # Isolate the failure: one bad advisory (or a failing failure-log
            # write) must not abort the batch or the later asset-download step.
            try:
                db.mark_parse_failed(conn, advisory_id, str(exc))
            except Exception:
                logger.exception(
                    "Could not record parse_failed for %s", advisory_id,
                )
            counts["failed"] += 1
    logger.info(
        "Parse-phase extraction complete: %d done, %d partial, %d failed",
        counts["done"], counts["partial"], counts["failed"],
    )
    return counts


def run_intel_extraction(
    conn: sqlite3.Connection, settings: dict,
) -> dict[str, int]:
    """Run intel-phase extraction on advisories with parse_done/parse_partial status."""
    if not settings.get("extraction", {}).get("enable_intel_extraction", False):
        logger.info("Intel extraction disabled in settings, skipping")
        return {"disabled": True}

    rows = db.get_advisories_for_intel(conn)
    if not rows:
        logger.info("No advisories pending intel extraction")
        return {"done": 0, "failed": 0}

    client = create_client(settings)
    counts: dict[str, int] = {"done": 0, "failed": 0}

    for row in rows:
        advisory_id = row["advisory_id"]
        try:
            parse_result = {
                "iocs": db.get_iocs(conn, advisory_id),
                "techniques": db.get_advisory_techniques(conn, advisory_id),
                "actors": db.get_advisory_actors(conn, advisory_id),
            }
            extract_intel(
                conn, client, advisory_id,
                row["article_body"], parse_result, settings,
            )
            counts["done"] += 1
        except InsufficientBalanceError:
            logger.error(
                "InsufficientBalanceError at %s — halting intel batch",
                advisory_id,
            )
            counts["halted"] = 1
            break
        except Exception as exc:
            logger.exception("Intel extraction failed for %s", advisory_id)
            try:
                db.mark_intel_failed(conn, advisory_id, str(exc))
            except Exception:
                logger.exception(
                    "Could not record intel failure for %s", advisory_id,
                )
            counts["failed"] += 1

    logger.info(
        "Intel-phase extraction complete: %d done, %d failed",
        counts["done"], counts["failed"],
    )
    return counts


def _source_remaining(conn: sqlite3.Connection, source: str, cap: int) -> int:
    """Return how many more advisories can be scraped for *source* before hitting *cap*."""
    status_counts = db.count_by_scrape_status(conn, source)
    scraped = status_counts.get("scraped", 0)
    return max(0, cap - scraped)


def run_daily_poll() -> None:
    """Execute the daily poll cycle across all sources."""
    import copy

    settings = config.load_settings()
    conn = db.get_connection(settings["database"]["path"])
    db.init_schema(conn)
    cap = settings.get("max_advisories_per_source", 0)
    try:
        # CISA advisory poll
        if cap <= 0 or _source_remaining(conn, "cisa", cap) > 0:
            poll_settings = copy.deepcopy(settings)
            if cap > 0:
                remaining = _source_remaining(conn, "cisa", cap)
                poll_settings["cisa"]["backfill_batch_size"] = min(
                    poll_settings["cisa"]["backfill_batch_size"], remaining,
                )
            client = cisa_client.create_http_client(poll_settings)
            try:
                result = cisa_client.cisa_poll(conn, client, poll_settings)
                logger.info("CISA poll complete: %s", result)
            finally:
                client.close()
        else:
            logger.info("CISA: cap reached (%d), skipping", cap)

        # ACSC advisory poll
        if cap <= 0 or _source_remaining(conn, "acsc", cap) > 0:
            poll_settings = copy.deepcopy(settings)
            if cap > 0:
                remaining = _source_remaining(conn, "acsc", cap)
                poll_settings["acsc"]["backfill_batch_size"] = min(
                    poll_settings["acsc"]["backfill_batch_size"], remaining,
                )
            acsc_http = acsc_client.create_acsc_client(poll_settings)
            try:
                acsc_result = acsc_client.acsc_poll(conn, acsc_http, poll_settings)
                logger.info("ACSC poll complete: %s", acsc_result)
            finally:
                acsc_http.close()
        else:
            logger.info("ACSC: cap reached (%d), skipping", cap)

        # JPCERT blog poll
        if cap <= 0 or _source_remaining(conn, "jpcert", cap) > 0:
            poll_settings = copy.deepcopy(settings)
            if cap > 0:
                remaining = _source_remaining(conn, "jpcert", cap)
                poll_settings["jpcert"]["backfill_batch_size"] = min(
                    poll_settings["jpcert"]["backfill_batch_size"], remaining,
                )
            jpcert_http = jpcert_client.create_jpcert_client(poll_settings)
            try:
                jpcert_result = jpcert_client.jpcert_poll(conn, jpcert_http, poll_settings)
                logger.info("JPCERT poll complete: %s", jpcert_result)
            finally:
                jpcert_http.close()
        else:
            logger.info("JPCERT: cap reached (%d), skipping", cap)

        # ORKL CTI reports
        data_dir = Path(settings.get("data", {}).get("dir", "data"))
        if cap <= 0 or _source_remaining(conn, "orkl", cap) > 0:
            poll_settings = copy.deepcopy(settings)
            if cap > 0:
                remaining = _source_remaining(conn, "orkl", cap)
                poll_settings["orkl"]["batch_size"] = min(
                    poll_settings["orkl"]["batch_size"], remaining,
                )
            try:
                orkl_result = run_orkl_poll(conn, poll_settings, data_dir)
                logger.info("ORKL poll complete: %s", orkl_result)
            except Exception:
                logger.exception("ORKL poll step failed")
        else:
            logger.info("ORKL: cap reached (%d), skipping", cap)

        # KEV catalog (before MSRC -- scoring needs KEV IDs)
        kev_result = kev_client.kev_poll(conn, settings)
        logger.info("KEV poll complete: %s", kev_result)

        # MSRC CVE poll
        msrc_result = msrc_client.msrc_poll(conn, settings)
        logger.info("MSRC poll complete: %s", msrc_result)

        # Cross-reference advisories <-> CVEs
        links = cross_reference(conn)
        logger.info("Cross-reference: %d new links", links)

        # Parse-phase extraction on newly scraped advisories
        extraction = run_parse_extraction(conn)
        logger.info("Parse-phase extraction: %s", extraction)

        # Intel-phase LLM extraction on parsed advisories
        intel = run_intel_extraction(conn, settings)
        logger.info("Intel-phase extraction: %s", intel)

        # Download pending advisory assets (isolated: a download failure must
        # not abort the poll after extraction has already been persisted)
        try:
            download_result = download_pending_assets(conn, data_dir, settings)
            logger.info("Asset download: %s", download_result)
        except Exception:
            logger.exception("Asset download step failed")
    finally:
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_daily_poll()
