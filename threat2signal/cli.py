"""CLI entry point for manual operations."""

import argparse
import json
import logging
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from threat2signal import config
from threat2signal.analysis.enricher import enrich_article_body
from threat2signal.analysis.analyzer import analyze_advisory_fresh
from threat2signal.analysis.extractor import parse_advisory
from threat2signal.analysis.msrc_scorer import score_all
from threat2signal.ingest import acsc_client, cisa_client, jpcert_client, kev_client, msrc_client, orkl_client
from threat2signal.ingest.asset_downloader import download_pending_assets
from threat2signal.analysis._deepseek import create_client, InsufficientBalanceError
from threat2signal.analysis.llm_extractor import extract_intel
from threat2signal.storage import db

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_STATUS_TABLES = [
    "advisory",
    "ioc",
    "behavior",
    "msrc_cve",
    "kev_entry",
    "detection_rule",
    "yara_rule",
]

_CONFIG_FILES = [
    "settings.yaml",
    "scoring.yaml",
    "ioc_allowlist.yaml",
]


def _resolve_db_path(settings: dict) -> str:
    """Resolve database.path relative to project root."""
    raw = settings["database"]["path"]
    return str(PROJECT_ROOT / raw)


def _count_tables(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    return cursor.fetchone()[0]


def _run_init_db() -> None:
    """Initialize the SQLite database with full schema."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
        count = _count_tables(conn)
        conn.close()
        print(f"Database initialized at {db_path}: {count} tables created")
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)


def _print_config_status() -> None:
    config_dir = PROJECT_ROOT / "config"
    for name in _CONFIG_FILES:
        tag = "[OK]" if (config_dir / name).exists() else "[MISSING]"
        print(f"  {name}: {tag}")


def _print_db_status(settings: dict) -> None:
    db_path = _resolve_db_path(settings)
    if not Path(db_path).exists():
        print("  Database: [NOT INITIALIZED]")
        return
    try:
        conn = db.get_connection(db_path)
        for table in _STATUS_TABLES:
            row = conn.execute(f"SELECT count(*) FROM [{table}]").fetchone()
            print(f"  {table}: {row[0]} rows")
        conn.close()
    except sqlite3.Error as exc:
        print(f"  Database error: {exc}")


def _print_neo4j_status(settings: dict) -> None:
    try:
        import neo4j as neo4j_driver
    except ImportError:
        print("  Neo4j: [UNAVAILABLE] (driver not installed)")
        return
    try:
        uri = settings["neo4j"]["uri"]
        user = settings["neo4j"]["user"]
        password = settings["neo4j"]["password"]
        driver = neo4j_driver.GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        driver.close()
        print("  Neo4j: [OK]")
    except (neo4j_driver.exceptions.ServiceUnavailable,
            neo4j_driver.exceptions.AuthError,
            neo4j_driver.exceptions.ConfigurationError,
            OSError) as exc:
        logger.debug("Neo4j connectivity check failed: %s", exc)
        print("  Neo4j: [UNAVAILABLE]")


def _print_disk_status(settings: dict) -> None:
    data_dir = PROJECT_ROOT / "data"
    usage = shutil.disk_usage(str(data_dir))
    free_gb = usage.free / (1024 ** 3)
    threshold_mb = settings.get("disk", {}).get("min_free_space_mb", 5120)
    threshold_gb = threshold_mb / 1024
    meets = "OK" if free_gb >= threshold_gb else "LOW"
    print(f"  Disk free: {free_gb:.1f} GB (threshold: {threshold_gb:.1f} GB) [{meets}]")


def _run_status() -> None:
    """Print system status report."""
    print("Config files:")
    _print_config_status()

    try:
        settings = config.load_settings()
    except (FileNotFoundError, ValueError):
        print("\nSettings not loaded -- skipping DB, Neo4j, and disk checks.")
        return

    print("\nDatabase:")
    _print_db_status(settings)

    print("\nNeo4j:")
    _print_neo4j_status(settings)

    print("\nDisk:")
    _print_disk_status(settings)


def _run_backfill(args: argparse.Namespace) -> None:
    """Fetch CISA sitemap, seed advisories, and scrape a batch."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
        client = cisa_client.create_http_client(settings)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        # --status: print progress and exit
        if args.status:
            counts = db.count_by_scrape_status(conn)
            total = sum(counts.values())
            scraped = counts.get("scraped", 0)
            pending = counts.get("pending", 0)
            cf = counts.get("cf_challenged", 0)
            blocked = counts.get("cf_blocked", 0)
            failed = counts.get("failed", 0)
            imported = counts.get("imported", 0)
            print(f"Backfill progress: {scraped}/{total} scraped, "
                  f"{pending} pending, {cf} cf_challenged, "
                  f"{blocked} cf_blocked, {failed} failed, "
                  f"{imported} imported")
            return

        # Fetch and parse sitemap
        sitemap_bytes = cisa_client.fetch_sitemap(
            client, settings["cisa"]["sitemap_url"], settings,
        )
        fetch_fn = lambda url: client.get(
            url,
            timeout=httpx.Timeout(
                settings["http"]["sitemap_read_timeout"],
                connect=settings["http"]["connect_timeout"],
            ),
        ).content
        entries = cisa_client.parse_sitemap(sitemap_bytes, fetch_fn)

        # Seed backfill
        seeded = cisa_client.seed_backfill(
            conn, entries, limit_per_type=args.limit_per_type,
        )
        print(f"Seeded {seeded} new advisories from sitemap")

        # Scrape pending
        pending_list = db.get_pending_scrape(conn, args.batch_size)
        if not pending_list:
            print("No pending advisories to scrape")
            return

        delay_base = float(args.delay)
        counts = cisa_client.scrape_batch(
            conn, client, settings, pending_list,
            delay_base=delay_base, delay_jitter=4.0,
        )
        print(f"Scrape complete: {counts}")
    except httpx.HTTPStatusError as exc:
        print(f"HTTP error: {exc}")
        sys.exit(1)
    finally:
        client.close()
        conn.close()


def _run_import_advisory(args: argparse.Namespace) -> None:
    """Import an advisory from a local HTML file."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        # Parse advisory_id from URL
        advisory_id = args.url.rstrip("/").rsplit("/", 1)[-1]

        # Read HTML from file
        html_path = Path(args.html_file)
        if not html_path.exists():
            print(f"Error: file not found: {args.html_file}")
            sys.exit(1)
        raw_html = html_path.read_text(encoding="utf-8")

        # Extract article body
        article_body = cisa_client.extract_article_body(raw_html)

        # Determine type from advisory_id
        if advisory_id.startswith("aa"):
            advisory_type = "cybersecurity_advisory"
        elif advisory_id.startswith("ar"):
            advisory_type = "analysis_report"
        else:
            advisory_type = "unknown"

        # Upsert advisory
        db.upsert_advisory(conn, {
            "advisory_id": advisory_id,
            "type": advisory_type,
            "source": "manual",
            "link": args.url,
            "raw_html": raw_html,
            "article_body": article_body,
            "scrape_status": "imported",
            "first_seen": datetime.now(timezone.utc).isoformat(),
        })
        print(f"Imported advisory {advisory_id} from {args.html_file}")
    finally:
        conn.close()


def _run_backfill_acsc(args: argparse.Namespace) -> None:
    """Fetch ACSC listings, seed advisories, and scrape a batch."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
        client = acsc_client.create_acsc_client(settings)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        if args.status:
            counts = db.count_by_scrape_status(conn, source="acsc")
            total = sum(counts.values())
            scraped = counts.get("scraped", 0)
            pending = counts.get("pending", 0)
            challenged = counts.get("cf_challenged", 0)
            failed = counts.get("failed", 0)
            print(f"ACSC backfill: {scraped}/{total} scraped, "
                  f"{pending} pending, {challenged} waf_challenged, "
                  f"{failed} failed")
            return

        entries = acsc_client.fetch_all_listing_pages(client, settings)
        seeded = acsc_client.seed_backfill(conn, entries, limit=args.limit)
        print(f"Seeded {seeded} new advisories from ACSC listings")

        data_dir = Path(settings.get("data", {}).get("dir", "data"))
        pending_list = db.get_pending_scrape(
            conn, args.batch_size, source="acsc",
        )
        if not pending_list:
            print("No pending ACSC advisories to scrape")
            return

        counts = acsc_client.scrape_batch(
            conn, client, settings, pending_list,
            delay_base=float(args.delay), delay_jitter=4.0,
            data_dir=data_dir,
        )
        print(f"ACSC scrape complete: {counts}")
    except httpx.HTTPStatusError as exc:
        print(f"HTTP error: {exc}")
        sys.exit(1)
    finally:
        client.close()
        conn.close()


def _run_backfill_jpcert(args: argparse.Namespace) -> None:
    """Fetch JPCERT category listings, seed posts, and scrape a batch."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
        client = jpcert_client.create_jpcert_client(settings)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        if args.status:
            counts = db.count_by_scrape_status(conn, source="jpcert")
            total = sum(counts.values())
            scraped = counts.get("scraped", 0)
            pending = counts.get("pending", 0)
            failed = counts.get("failed", 0)
            print(f"JPCERT backfill: {scraped}/{total} scraped, "
                  f"{pending} pending, {failed} failed")
            return

        entries = jpcert_client.fetch_all_category_entries(client, settings)
        seeded = jpcert_client.seed_backfill(conn, entries, limit=args.limit)
        print(f"Seeded {seeded} new posts from JPCERT listings")

        data_dir = Path(settings.get("data", {}).get("dir", "data"))
        pending_list = db.get_pending_scrape(
            conn, args.batch_size, source="jpcert",
        )
        if not pending_list:
            print("No pending JPCERT posts to scrape")
            return

        counts = jpcert_client.scrape_batch(
            conn, client, settings, pending_list,
            delay_base=float(args.delay), delay_jitter=3.0,
            data_dir=data_dir,
        )
        print(f"JPCERT scrape complete: {counts}")
    except httpx.HTTPStatusError as exc:
        print(f"HTTP error: {exc}")
        sys.exit(1)
    finally:
        client.close()
        conn.close()


def _ingest_orkl_threat_actors(
    conn: sqlite3.Connection,
    advisory_id: str,
    threat_actors: list[dict],
) -> None:
    """Deduplicate ORKL threat actors by main_name and persist actors, aliases, and tools."""
    seen: dict[str, str] = {}  # lowercase main_name -> canonical form
    for actor in threat_actors:
        main_name = actor.get("main_name", "").strip()
        if not main_name:
            continue
        key = main_name.lower()
        if key not in seen:
            seen[key] = main_name
            db.link_advisory_actor(conn, advisory_id, main_name)

        canonical = seen[key]
        source_name = actor.get("source_name", "")

        for alias in actor.get("aliases", []):
            alias = alias.strip()
            if alias:
                db.upsert_threat_actor_alias(conn, alias, canonical, source_name)

        for tool in actor.get("tools", []):
            tool = tool.strip()
            if tool:
                db.link_advisory_malware(conn, advisory_id, tool)


_ORKL_PUB_DATE_RE = re.compile(r"Published:\s*(\d{4}-\d{2}-\d{2})")


def _extract_orkl_pub_date(plain_text: str, fallback: str) -> str:
    """Extract the original publication date from ORKL plain_text header.

    ORKL's ``created_at`` is the archival timestamp, not the original
    publication date.  The real date is embedded as "Published: YYYY-MM-DD"
    near the top of the plain_text field.
    """
    m = _ORKL_PUB_DATE_RE.search(plain_text[:300])
    return m.group(1) if m else fallback


def _run_backfill_orkl(args: argparse.Namespace) -> None:
    """Fetch and ingest ORKL CTI reports."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    # Apply CLI overrides to settings before creating client
    if args.batch_size is not None:
        settings.setdefault("orkl", {})["batch_size"] = args.batch_size
    if args.delay is not None:
        settings.setdefault("orkl", {})["delay_between_requests"] = args.delay

    client = orkl_client.create_orkl_client(settings)
    data_dir = Path(settings.get("data", {}).get("dir", "data"))

    try:
        now = datetime.now(timezone.utc).isoformat()
        fetched = 0
        skipped = 0
        ingested = 0

        for entry in orkl_client.fetch_all_entries(client, settings):
            fetched += 1
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

                db.upsert_advisory(conn, {
                    "advisory_id": entry_id,
                    "type": "cti_report",
                    "source": "orkl",
                    "original_source": orkl_client.extract_original_source(entry),
                    "title": title,
                    "summary": summary_text.strip(),
                    "link": references[0] if references else None,
                    "pub_date": _extract_orkl_pub_date(plain_text, entry["created_at"][:10]),
                    "raw_html": json.dumps(entry, ensure_ascii=False),
                    "article_body": plain_text,
                    "scrape_status": "scraped",
                    "first_seen": now,
                })

                _ingest_orkl_threat_actors(
                    conn, entry_id, entry.get("threat_actors", []),
                )

                ingested += 1
                print(f"  {entry_id}: {title[:60]}")
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("Skipping malformed ORKL entry %s: %s", entry_id, exc)
                continue

            if args.limit and ingested >= args.limit:
                break

        print(
            f"\nORKL backfill complete: {fetched} fetched, "
            f"{skipped} skipped (dedup), {ingested} ingested"
        )
    except httpx.HTTPStatusError as exc:
        print(f"HTTP error: {exc}")
        sys.exit(1)
    finally:
        client.close()
        conn.close()


def _run_poll_msrc(args: argparse.Namespace) -> None:
    """Run MSRC CVE poll."""
    settings = config.load_settings()
    conn = db.get_connection(settings["database"]["path"])
    db.init_schema(conn)
    try:
        result = msrc_client.msrc_poll(conn, settings)
        print(f"MSRC poll complete: {result}")
    except Exception as exc:
        print(f"MSRC poll failed: {exc}")
        sys.exit(1)
    finally:
        conn.close()


def _run_backfill_msrc(args: argparse.Namespace) -> None:
    """Backfill MSRC CVEs from CVRF bulk data."""
    settings = config.load_settings()
    conn = db.get_connection(settings["database"]["path"])
    db.init_schema(conn)
    try:
        result = msrc_client.msrc_backfill(
            conn, settings, args.months, delay=args.delay,
        )
        print(f"MSRC backfill complete: {result}")
    except Exception as exc:
        print(f"MSRC backfill failed: {exc}")
        sys.exit(1)
    finally:
        conn.close()


def _run_poll_kev(args: argparse.Namespace) -> None:
    """Fetch and upsert CISA KEV catalog."""
    settings = config.load_settings()
    conn = db.get_connection(settings["database"]["path"])
    db.init_schema(conn)
    try:
        result = kev_client.kev_poll(conn, settings)
        print(f"KEV poll complete: {result}")
    except Exception as exc:
        print(f"KEV poll failed: {exc}")
        sys.exit(1)
    finally:
        conn.close()


def _run_rescore(args: argparse.Namespace) -> None:
    """Recompute defense and VR scores for all MSRC CVEs."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    try:
        config_path = PROJECT_ROOT / "config" / "scoring.yaml"
        count = score_all(conn, config_path)
        print(f"Rescored {count} MSRC CVEs (defense + VR)")
    finally:
        conn.close()


def _extract_one(
    conn: sqlite3.Connection, advisory_id: str,
    article_body: str, source: str, numeric_id: int,
    known_msrc_cves: set[str],
) -> str:
    """Extract and enrich a single advisory, return status string."""
    result = parse_advisory(advisory_id, article_body, source)
    enriched_body = enrich_article_body(
        article_body, source, advisory_id, result, numeric_id,
        known_msrc_cves=known_msrc_cves,
    )
    status = db.save_parse_results(conn, advisory_id, result, enriched_body)

    # ORKL actors come from API metadata, not extraction;
    # _delete_prior_parse wipes advisory_actor so we must re-insert
    if source == "orkl":
        raw_html = db.get_advisory_raw_html(conn, advisory_id)
        if raw_html:
            entry_data = json.loads(raw_html)
            _ingest_orkl_threat_actors(
                conn, advisory_id, entry_data.get("threat_actors", []),
            )

    return status


def _query_extract_targets(
    conn: sqlite3.Connection, args: argparse.Namespace,
) -> list[dict]:
    """Query advisories to extract based on CLI arguments."""
    if args.advisory:
        rows = db.get_advisories_for_parsing(conn, advisory_id=args.advisory)
        if not rows:
            print(f"Error: advisory {args.advisory} not found or has no article_body")
            sys.exit(1)
        return rows
    return db.get_advisories_for_parsing(conn, include_all=True)


def _run_extract(args: argparse.Namespace) -> None:
    """Run parse-phase extraction on advisory(ies)."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        rows = _query_extract_targets(conn, args)
        known_msrc_cves = db.get_msrc_cve_ids(conn)
        counts: dict[str, int] = {"done": 0, "partial": 0, "failed": 0}
        for row in rows:
            advisory_id = row["advisory_id"]
            try:
                status = _extract_one(
                    conn, advisory_id, row["article_body"], row["source"],
                    row["numeric_id"], known_msrc_cves,
                )
                print(f"  {advisory_id}: {status}")
                if status == "parse_done":
                    counts["done"] += 1
                elif status == "parse_partial":
                    counts["partial"] += 1
                else:
                    counts["failed"] += 1
            except Exception as exc:
                logger.exception("Extraction failed for %s", advisory_id)
                # Parity with the poll: a failed re-extraction must be visibly
                # parse_failed, not silently left as a stale parse_done.
                try:
                    db.mark_parse_failed(conn, advisory_id, str(exc))
                except Exception:
                    logger.exception(
                        "Could not record parse_failed for %s", advisory_id,
                    )
                print(f"  {advisory_id}: FAILED ({exc})")
                counts["failed"] += 1
        print(
            f"Extract complete: {counts['done']} done, "
            f"{counts['partial']} partial, {counts['failed']} failed",
        )
        if counts["failed"]:
            sys.exit(1)
    finally:
        conn.close()


def _build_parse_context(
    conn: sqlite3.Connection, advisory_id: str,
) -> dict:
    """Assemble parse-phase results as context for intel extraction."""
    return {
        "iocs": db.get_iocs(conn, advisory_id),
        "techniques": db.get_advisory_techniques(conn, advisory_id),
        "actors": db.get_advisory_actors(conn, advisory_id),
    }


def _run_intel_extract(args: argparse.Namespace) -> None:
    """Run intel-phase LLM extraction on advisory(ies)."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        if args.model:
            settings["deepseek"]["model"] = args.model

        client = create_client(settings)

        if args.advisory:
            rows = db.get_advisories_for_intel(conn, advisory_id=args.advisory)
            if not rows:
                print(f"Error: advisory {args.advisory} not found or has no article_body")
                sys.exit(1)
        else:
            rows = db.get_advisories_for_intel(conn)

        counts: dict[str, int] = {"done": 0, "failed": 0}
        for row in rows:
            advisory_id = row["advisory_id"]
            try:
                parse_result = _build_parse_context(conn, advisory_id)
                result = extract_intel(
                    conn, client, advisory_id,
                    row["article_body"], parse_result, settings,
                )
                print(
                    f"  {advisory_id}: intel_done "
                    f"({len(result.iocs)} IOCs, "
                    f"{len(result.techniques)} techniques)",
                )
                counts["done"] += 1
            except InsufficientBalanceError:
                print(f"  {advisory_id}: HALTED (insufficient DeepSeek balance)")
                logger.error("InsufficientBalanceError — halting intel batch")
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
                print(f"  {advisory_id}: FAILED ({exc})")
                counts["failed"] += 1

        print(
            f"Intel extract complete: {counts['done']} done, "
            f"{counts['failed']} failed"
            + (", HALTED (billing)" if counts.get("halted") else ""),
        )
        if counts["failed"] or counts.get("halted"):
            sys.exit(1)
    finally:
        conn.close()


_ADVISORY_CHILD_TABLES = [
    "ioc", "yara_rule", "advisory_asset", "behavior", "advisory_cve",
    "advisory_actor", "advisory_malware", "advisory_sector",
    "advisory_technique", "detection_rule", "extraction_history",
    "extraction_log", "advisory_analysis",
]

def _extract_orkl_article_body(raw_content: str) -> str:
    """Return plain_text from a cached ORKL JSON entry."""
    entry = json.loads(raw_content)
    return entry.get("plain_text", "")


_ARTICLE_BODY_EXTRACTORS = {
    "cisa": cisa_client.extract_article_body,
    "acsc": acsc_client.extract_article_body,
    "jpcert": jpcert_client.extract_article_body,
    "orkl": _extract_orkl_article_body,
}


def _extract_html_title(raw_html: str) -> str | None:
    """Generic title extraction from <title> or <h1> tag."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(raw_html, "lxml")
    h1 = soup.find("h1")
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


def _infer_advisory_type(advisory_id: str, source: str) -> str:
    """Derive advisory type from ID prefix or source."""
    if source == "cisa":
        if advisory_id.startswith("aa"):
            return "cybersecurity_advisory"
        if advisory_id.startswith("ar"):
            return "analysis_report"
        return "unknown"
    if source == "acsc":
        return "advisory"
    if source == "jpcert":
        return "jpcert_blog"
    if source == "orkl":
        return "cti_report"
    return "unknown"


def _run_reimport_cache(args: argparse.Namespace) -> None:
    """Drop advisory data and re-ingest from HTML cache on disk."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    cache_dir = PROJECT_ROOT / "data" / "html_cache"
    if not cache_dir.exists():
        print(f"Error: cache directory not found: {cache_dir}")
        sys.exit(1)

    try:
        # Delete all advisory-dependent rows, then advisory rows
        with conn:
            for table in _ADVISORY_CHILD_TABLES:
                conn.execute(f"DELETE FROM [{table}]")
            conn.execute("DELETE FROM advisory")
        print("Cleared advisory tables")

        # Walk cache directory: data/html_cache/{source}/{month}/*.html
        now = datetime.now(timezone.utc).isoformat()
        counts: dict[str, int] = {}
        for source_dir in sorted(cache_dir.iterdir()):
            if not source_dir.is_dir():
                continue
            source = source_dir.name
            if source not in _ARTICLE_BODY_EXTRACTORS:
                print(f"  Skipping unknown source: {source}")
                continue

            extract_body = _ARTICLE_BODY_EXTRACTORS[source]

            for month_dir in sorted(source_dir.iterdir()):
                if not month_dir.is_dir():
                    continue
                for html_file in sorted(
                    list(month_dir.glob("*.html")) + list(month_dir.glob("*.json"))
                ):
                    advisory_id = html_file.stem
                    raw_html = html_file.read_text(encoding="utf-8")
                    article_body = extract_body(raw_html)

                    # Title, pub_date, original_source (source-specific)
                    original_source = None
                    if source == "cisa":
                        title = cisa_client.extract_page_title(raw_html)
                        pub_date = cisa_client.extract_pub_date(raw_html)
                    elif source == "jpcert":
                        title = jpcert_client.extract_page_title(raw_html)
                        pub_date = jpcert_client.extract_pub_date(raw_html)
                    elif source == "acsc":
                        title = acsc_client.extract_page_title(raw_html)
                        pub_date = None
                    elif source == "orkl":
                        entry_data = json.loads(raw_html)
                        title = entry_data.get("title") or entry_data.get("llm_title") or None
                        orkl_fallback = entry_data.get("created_at", "")[:10] or None
                        plain = entry_data.get("plain_text", "")
                        pub_date = _extract_orkl_pub_date(plain, orkl_fallback) if plain else orkl_fallback
                        refs = entry_data.get("references", [])
                        if refs:
                            original_source = urlparse(refs[0]).netloc or None
                    else:
                        title = _extract_html_title(raw_html)
                        pub_date = None

                    advisory_type = _infer_advisory_type(advisory_id, source)

                    db.upsert_advisory(conn, {
                        "advisory_id": advisory_id,
                        "type": advisory_type,
                        "source": source,
                        "title": title,
                        "pub_date": pub_date,
                        "original_source": original_source,
                        "first_seen": now,
                        "scrape_status": "pending",
                    })
                    db.update_scrape_result(
                        conn, advisory_id, "scraped",
                        raw_html, article_body,
                    )

                    # ORKL actors/tools live in API metadata, not extraction
                    if source == "orkl":
                        _ingest_orkl_threat_actors(
                            conn, advisory_id,
                            entry_data.get("threat_actors", []),
                        )

                    counts[source] = counts.get(source, 0) + 1
                    print(f"  {advisory_id} ({source})")

        total = sum(counts.values())
        parts = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        print(f"\nReimported {total} advisories from cache ({parts})")
    finally:
        conn.close()


def _run_download_assets(args: argparse.Namespace) -> None:
    """Download pending advisory assets (figures, PDFs, STIX, etc.)."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    data_dir = Path(settings.get("data", {}).get("dir", "data"))
    try:
        counts = download_pending_assets(conn, data_dir, settings)
        print(
            f"Asset download complete: {counts['downloaded']} downloaded, "
            f"{counts['failed']} failed, {counts['skipped']} skipped"
        )
    finally:
        conn.close()


def _run_serve(args: argparse.Namespace) -> None:
    """Start the FastAPI dashboard server."""
    import uvicorn

    print(f"Dashboard available at http://{args.host}:{args.port}")
    uvicorn.run("threat2signal.api:app", host=args.host, port=args.port)


def _run_analyze(args: argparse.Namespace) -> None:
    """Run analysis on a single advisory."""
    try:
        settings = config.load_settings()
        db_path = _resolve_db_path(settings)
        conn = db.get_connection(db_path)
        db.init_schema(conn)
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        result = analyze_advisory_fresh(conn, args.advisory, settings)
        print(json.dumps(result["analysis"], indent=2))
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


def _run_hash_password() -> None:
    """Hash a password for settings.yaml auth config."""
    import getpass
    from threat2signal.auth import hash_password
    plain = getpass.getpass("Password: ")
    if not plain:
        print("Error: empty password")
        sys.exit(1)
    print(hash_password(plain))


def _run_generate_secret() -> None:
    """Generate a random secret key for JWT signing."""
    import secrets
    print(secrets.token_urlsafe(32))


def main() -> None:
    """Parse arguments and dispatch subcommands."""
    parser = argparse.ArgumentParser(
        description="Threat2Signal — CTI pipeline management"
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("init-db", help="Initialize the SQLite database")
    subparsers.add_parser("status", help="Show system status report")
    subparsers.add_parser("hash-password", help="Hash a password for auth config")
    subparsers.add_parser("generate-secret", help="Generate a random JWT secret key")

    bp = subparsers.add_parser("backfill-cisa", help="Seed and scrape CISA advisories")
    bp.add_argument("--batch-size", type=int, default=10,
                    help="Max advisories to scrape this run (default: 10)")
    bp.add_argument("--delay", type=float, default=10.0,
                    help="Seconds between requests (default: 10)")
    bp.add_argument("--limit-per-type", type=int, default=None,
                    help="Cap seeded advisories per type (AA, AR)")
    bp.add_argument("--status", action="store_true",
                    help="Print backfill progress and exit")

    acsc_bp = subparsers.add_parser(
        "backfill-acsc", help="Seed and scrape ACSC advisories",
    )
    acsc_bp.add_argument("--batch-size", type=int, default=10)
    acsc_bp.add_argument("--delay", type=float, default=10.0)
    acsc_bp.add_argument("--limit", type=int, default=None)
    acsc_bp.add_argument("--status", action="store_true",
                         help="Print ACSC backfill progress and exit")

    jpcert_bp = subparsers.add_parser(
        "backfill-jpcert", help="Seed and scrape JPCERT posts",
    )
    jpcert_bp.add_argument("--batch-size", type=int, default=10)
    jpcert_bp.add_argument("--delay", type=float, default=5.0)
    jpcert_bp.add_argument("--limit", type=int, default=None)
    jpcert_bp.add_argument("--status", action="store_true",
                           help="Print JPCERT backfill progress and exit")

    orkl_bp = subparsers.add_parser(
        "backfill-orkl", help="Fetch and ingest ORKL CTI reports",
    )
    orkl_bp.add_argument("--limit", type=int, default=None,
                         help="Max entries to ingest (default: unlimited)")
    orkl_bp.add_argument("--batch-size", type=int, default=None,
                         help="Override batch_size from settings")
    orkl_bp.add_argument("--delay", type=float, default=None,
                         help="Override delay between requests")

    ip = subparsers.add_parser("import-advisory",
                               help="Import advisory from local HTML file")
    ip.add_argument("--url", required=True, help="Advisory URL")
    ip.add_argument("--html-file", required=True, help="Path to HTML file")

    subparsers.add_parser("poll-msrc", help="Poll MSRC RSS for new CVEs")

    msrc_bp = subparsers.add_parser(
        "backfill-msrc", help="Backfill MSRC CVEs from CVRF bulk data",
    )
    msrc_bp.add_argument(
        "months", nargs="+", help="Month strings (e.g., 2024-Jul 2024-Aug)",
    )
    msrc_bp.add_argument(
        "--delay", type=float, default=5.0,
        help="Seconds between monthly fetches (default: 5)",
    )

    subparsers.add_parser("poll-kev", help="Fetch and upsert CISA KEV catalog")
    subparsers.add_parser("rescore", help="Recompute defense + VR scores for all MSRC CVEs")

    subparsers.add_parser(
        "reimport-cache",
        help="Drop advisory data and re-ingest from HTML cache on disk",
    )
    subparsers.add_parser(
        "download-assets",
        help="Download pending advisory assets (figures, PDFs, STIX files)",
    )

    extract_p = subparsers.add_parser("extract", help="Run extraction pipeline")
    extract_grp = extract_p.add_mutually_exclusive_group(required=True)
    extract_grp.add_argument("--advisory", type=str, help="Extract specific advisory ID")
    extract_grp.add_argument("--all", action="store_true", help="Re-extract all advisories")
    extract_p.add_argument(
        "--phase", choices=["parse", "intel", "all"], default="parse",
        help="Extraction phase to run (default: parse)",
    )
    extract_p.add_argument(
        "--model", type=str, default=None,
        help="Override DeepSeek model for intel extraction",
    )

    analyze_p = subparsers.add_parser("analyze", help="Run analysis on a single advisory")
    analyze_p.add_argument("--advisory", required=True, help="Advisory ID to analyze")

    sp = subparsers.add_parser("serve", help="Start the dashboard web server")
    sp.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default: 127.0.0.1)")
    sp.add_argument("--port", type=int, default=8000,
                    help="Port number (default: 8000)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if args.command == "init-db":
        _run_init_db()
    elif args.command == "status":
        _run_status()
    elif args.command == "hash-password":
        _run_hash_password()
    elif args.command == "generate-secret":
        _run_generate_secret()
    elif args.command == "backfill-cisa":
        _run_backfill(args)
    elif args.command == "backfill-acsc":
        _run_backfill_acsc(args)
    elif args.command == "backfill-jpcert":
        _run_backfill_jpcert(args)
    elif args.command == "backfill-orkl":
        _run_backfill_orkl(args)
    elif args.command == "import-advisory":
        _run_import_advisory(args)
    elif args.command == "poll-msrc":
        _run_poll_msrc(args)
    elif args.command == "backfill-msrc":
        _run_backfill_msrc(args)
    elif args.command == "poll-kev":
        _run_poll_kev(args)
    elif args.command == "rescore":
        _run_rescore(args)
    elif args.command == "reimport-cache":
        _run_reimport_cache(args)
    elif args.command == "download-assets":
        _run_download_assets(args)
    elif args.command == "extract":
        phase = args.phase
        if phase in ("parse", "all"):
            try:
                _run_extract(args)
            except SystemExit:
                if phase != "all":
                    raise
                logger.warning("Parse phase had failures; continuing to intel phase")
        if phase in ("intel", "all"):
            _run_intel_extract(args)
    elif args.command == "analyze":
        _run_analyze(args)
    elif args.command == "serve":
        _run_serve(args)


if __name__ == "__main__":
    main()
