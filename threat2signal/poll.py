"""Daily poll orchestrator."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from threat2signal import config
from threat2signal.analysis._deepseek import create_client, InsufficientBalanceError
from threat2signal.analysis.enricher import enrich_article_body
from threat2signal.analysis.extractor import parse_advisory
from threat2signal.analysis.llm_extractor import extract_intel
from threat2signal.ingest import acsc_client, cisa_client, jpcert_client, kev_client, msrc_client
from threat2signal.ingest.asset_downloader import download_pending_assets
from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


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


def run_daily_poll() -> None:
    """Execute the daily poll cycle across all sources."""
    settings = config.load_settings()
    conn = db.get_connection(settings["database"]["path"])
    db.init_schema(conn)
    try:
        # CISA advisory poll
        client = cisa_client.create_http_client(settings)
        try:
            result = cisa_client.cisa_poll(conn, client, settings)
            logger.info("CISA poll complete: %s", result)
        finally:
            client.close()

        # ACSC advisory poll
        acsc_http = acsc_client.create_acsc_client(settings)
        try:
            acsc_result = acsc_client.acsc_poll(conn, acsc_http, settings)
            logger.info("ACSC poll complete: %s", acsc_result)
        finally:
            acsc_http.close()

        # JPCERT blog poll
        jpcert_http = jpcert_client.create_jpcert_client(settings)
        try:
            jpcert_result = jpcert_client.jpcert_poll(conn, jpcert_http, settings)
            logger.info("JPCERT poll complete: %s", jpcert_result)
        finally:
            jpcert_http.close()

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
        data_dir = Path(settings.get("data", {}).get("dir", "data"))
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
