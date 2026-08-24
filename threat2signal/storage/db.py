"""SQLite schema management and data access."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat2signal.analysis.extractor import (
        ActorAlias,
        AssetRecord,
        CveRecord,
        ExtractionLogEntry,
        IocRecord,
        ParseResult,
        RuleRecord,
        TechniqueRecord,
    )


logger = logging.getLogger(__name__)

# Version stamped on parse-phase extraction_history rows so a later re-extraction
# can be attributed to the code that produced it.  Bump when parse output semantics
# change. The extractor module has no single version constant today; if one is
# added there, callers should pass it into save_parse_results instead.
_PARSE_EXTRACTOR_VERSION = "parse/v1"


_TABLE_DDL = (
    """CREATE TABLE IF NOT EXISTS advisory (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id       TEXT NOT NULL UNIQUE,
    type              TEXT NOT NULL,
    source            TEXT NOT NULL,
    title             TEXT,
    summary           TEXT,
    link              TEXT,
    pub_date          TEXT,
    raw_html          TEXT,
    article_body      TEXT,
    enriched_body     TEXT,
    extracted_json    TEXT,
    extraction_status TEXT DEFAULT 'pending',
    extraction_model  TEXT,
    extraction_error  TEXT,
    retry_count       INTEGER DEFAULT 0,
    extracted_at      TEXT,
    input_tokens      INTEGER,
    output_tokens     INTEGER,
    llm_latency_ms    INTEGER,
    llm_cost_usd      REAL,
    scrape_status     TEXT DEFAULT 'pending',
    scrape_retry_count INTEGER DEFAULT 0,
    sitemap_lastmod   TEXT,
    first_seen        TEXT,
    last_updated      TEXT
)""",
    """CREATE TABLE IF NOT EXISTS ioc (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id       TEXT NOT NULL REFERENCES advisory(advisory_id),
    type              TEXT NOT NULL,
    value             TEXT NOT NULL,
    context           TEXT,
    validation_status TEXT DEFAULT 'pending',
    source_verified   INTEGER DEFAULT 0,
    needs_review      INTEGER DEFAULT 1,
    extraction_source TEXT NOT NULL DEFAULT 'parse',
    UNIQUE(advisory_id, type, value)
)""",
    """CREATE TABLE IF NOT EXISTS yara_rule (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id       TEXT NOT NULL REFERENCES advisory(advisory_id),
    rule_name         TEXT,
    rule_text         TEXT NOT NULL,
    raw_extracted     TEXT,
    source            TEXT DEFAULT 'html_parsed',
    validation_status TEXT,
    UNIQUE(advisory_id, rule_name)
)""",
    """CREATE TABLE IF NOT EXISTS advisory_asset (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    asset_type      TEXT NOT NULL,
    original_url    TEXT NOT NULL,
    local_path      TEXT,
    file_name       TEXT,
    file_size       INTEGER,
    alt_text        TEXT,
    caption         TEXT,
    download_status TEXT DEFAULT 'pending',
    download_error  TEXT,
    downloaded_at   TEXT,
    UNIQUE(advisory_id, original_url)
)""",
    """CREATE TABLE IF NOT EXISTS behavior (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    description     TEXT NOT NULL,
    mitre_technique TEXT,
    mitre_tactic    TEXT,
    confidence      TEXT DEFAULT 'llm_extracted',
    UNIQUE(advisory_id, description)
)""",
    """CREATE TABLE IF NOT EXISTS advisory_cve (
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    cve_id          TEXT NOT NULL,
    link_url        TEXT,
    link_source     TEXT,
    PRIMARY KEY (advisory_id, cve_id)
)""",
    """CREATE TABLE IF NOT EXISTS advisory_actor (
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    actor_name      TEXT NOT NULL,
    PRIMARY KEY (advisory_id, actor_name)
)""",
    """CREATE TABLE IF NOT EXISTS threat_actor_alias (
    alias           TEXT PRIMARY KEY,
    canonical_name  TEXT NOT NULL,
    source          TEXT,
    added_at        TEXT
)""",
    """CREATE TABLE IF NOT EXISTS advisory_malware (
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    malware_name    TEXT NOT NULL,
    PRIMARY KEY (advisory_id, malware_name)
)""",
    """CREATE TABLE IF NOT EXISTS advisory_sector (
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    sector          TEXT NOT NULL,
    PRIMARY KEY (advisory_id, sector)
)""",
    """CREATE TABLE IF NOT EXISTS mitre_technique (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT,
    tactic          TEXT,
    description     TEXT,
    platforms       TEXT,
    data_sources    TEXT,
    detection_hint  TEXT,
    stix_json       TEXT
)""",
    """CREATE TABLE IF NOT EXISTS advisory_technique (
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    technique_id    TEXT NOT NULL REFERENCES mitre_technique(technique_id),
    confidence      TEXT DEFAULT 'advisory_stated',
    framework       TEXT NOT NULL DEFAULT 'attack',
    PRIMARY KEY (advisory_id, technique_id)
)""",
    """CREATE TABLE IF NOT EXISTS detection_rule (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id       TEXT REFERENCES advisory(advisory_id),
    technique_id      TEXT REFERENCES mitre_technique(technique_id),
    rule_name         TEXT,
    rule_format       TEXT NOT NULL,
    rule_text         TEXT NOT NULL,
    raw_extracted     TEXT,
    confidence        TEXT,
    source            TEXT,
    validation_status TEXT,
    validation_error  TEXT,
    log_source        TEXT,
    generic_baseline  INTEGER DEFAULT 0,
    needs_review      INTEGER DEFAULT 1
)""",
    """CREATE TABLE IF NOT EXISTS extraction_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    phase           TEXT,
    extracted_json  TEXT NOT NULL,
    extracted_at    TEXT NOT NULL,
    extraction_model TEXT,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    superseded_at   TEXT
)""",
    """CREATE TABLE IF NOT EXISTS extraction_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    phase           TEXT NOT NULL,
    extractor       TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK(severity IN ('warning', 'error')),
    message         TEXT NOT NULL,
    context         TEXT,
    logged_at       TEXT NOT NULL DEFAULT (datetime('now'))
)""",
    """CREATE TABLE IF NOT EXISTS msrc_cve (
    cve_id              TEXT PRIMARY KEY,
    title               TEXT,
    description         TEXT,
    released            TEXT,
    component           TEXT,
    component_category  TEXT,
    impact              TEXT,
    severity            TEXT,
    cvss_base           REAL,
    cvss_temporal       REAL,
    cvss_vector         TEXT,
    av                  TEXT,
    ac                  TEXT,
    pr                  TEXT,
    ui                  TEXT,
    scope               TEXT,
    cwe_id              TEXT,
    cwe_description     TEXT,
    exploit_status      TEXT,
    publicly_disclosed  INTEGER DEFAULT 0,
    exploited_wild      INTEGER DEFAULT 0,
    customer_action     TEXT,
    defense_score       REAL DEFAULT 0,
    priority            TEXT DEFAULT 'NOISE',
    first_seen          TEXT,
    last_updated        TEXT,
    raw_json            TEXT,
    vr_score            REAL DEFAULT 0,
    vr_priority         TEXT DEFAULT 'NOISE',
    vr_tags             TEXT DEFAULT '[]'
)""",
    """CREATE TABLE IF NOT EXISTS msrc_kb (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL REFERENCES msrc_cve(cve_id),
    kb_number       TEXT,
    product_name    TEXT,
    download_url    TEXT
)""",
    """CREATE TABLE IF NOT EXISTS msrc_poll_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    polled_at       TEXT NOT NULL,
    new_cves        INTEGER DEFAULT 0,
    updated_cves    INTEGER DEFAULT 0,
    errors          TEXT
)""",
    """CREATE TABLE IF NOT EXISTS cisa_poll_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    polled_at       TEXT NOT NULL,
    source          TEXT DEFAULT 'sitemap',
    aa_total        INTEGER,
    ar_total        INTEGER,
    new_advisories  INTEGER DEFAULT 0,
    updated         INTEGER DEFAULT 0,
    errors          TEXT
)""",
    """CREATE TABLE IF NOT EXISTS kev_entry (
    cve_id              TEXT PRIMARY KEY,
    vendor              TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    date_added          TEXT,
    due_date            TEXT,
    known_ransomware    TEXT,
    notes               TEXT,
    last_fetched        TEXT
)""",
    """CREATE TABLE IF NOT EXISTS advisory_analysis (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     TEXT NOT NULL REFERENCES advisory(advisory_id),
    analysis_type   TEXT NOT NULL DEFAULT 'purple_team',
    analysis_json   TEXT NOT NULL,
    model           TEXT,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    latency_ms      INTEGER,
    cost_usd        REAL,
    user_context    TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE(advisory_id, analysis_type)
)""",
    """CREATE TABLE IF NOT EXISTS llm_call_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id      TEXT    NOT NULL REFERENCES advisory(advisory_id),
    phase            TEXT    NOT NULL,
    model            TEXT    NOT NULL,
    input_tokens     INTEGER NOT NULL DEFAULT 0,
    output_tokens    INTEGER NOT NULL DEFAULT 0,
    cached_tokens    INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms       INTEGER NOT NULL DEFAULT 0,
    cost_usd         REAL    NOT NULL DEFAULT 0.0,
    prompt_version   TEXT,
    called_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(advisory_id, phase)
)""",
)

_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_advisory_type ON advisory(type)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_pub_date ON advisory(pub_date DESC)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_status ON advisory(extraction_status)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_scrape_status ON advisory(scrape_status)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_source ON advisory(source)",
    "CREATE INDEX IF NOT EXISTS idx_asset_advisory ON advisory_asset(advisory_id)",
    "CREATE INDEX IF NOT EXISTS idx_asset_type ON advisory_asset(asset_type)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc(type, value)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_advisory ON ioc(advisory_id)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_validation ON ioc(validation_status)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc(value COLLATE NOCASE)",
    "CREATE INDEX IF NOT EXISTS idx_behavior_technique ON behavior(mitre_technique)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_cve_cve ON advisory_cve(cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_actor ON advisory_actor(actor_name)",
    "CREATE INDEX IF NOT EXISTS idx_actor_alias_canonical ON threat_actor_alias(canonical_name)",
    "CREATE INDEX IF NOT EXISTS idx_extraction_history_advisory ON extraction_history(advisory_id)",
    "CREATE INDEX IF NOT EXISTS idx_extraction_log_advisory ON extraction_log(advisory_id, severity)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_technique_tech ON advisory_technique(technique_id)",
    "CREATE INDEX IF NOT EXISTS idx_detection_rule_advisory ON detection_rule(advisory_id)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_cve_component ON msrc_cve(component)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_cve_priority ON msrc_cve(priority)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_cve_score ON msrc_cve(defense_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_cve_released ON msrc_cve(released DESC)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_cve_exploited ON msrc_cve(exploited_wild)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_cve_vr_score ON msrc_cve(vr_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_cve_vr_priority ON msrc_cve(vr_priority)",
    "CREATE INDEX IF NOT EXISTS idx_msrc_kb_cve ON msrc_kb(cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_entry(date_added DESC)",
    "CREATE INDEX IF NOT EXISTS idx_analysis_advisory ON advisory_analysis(advisory_id)",
)


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open a configured SQLite connection, creating parent directories as needed."""
    try:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.error("Cannot create parent directory for %s", db_path)
        raise
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.OperationalError:
        logger.error("Cannot open database at %s", db_path)
        raise
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    logger.debug("Connected to SQLite database at %s", db_path)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create all tables and indexes if they do not exist."""
    cursor = conn.cursor()
    try:
        for ddl in _TABLE_DDL:
            cursor.execute(ddl)
        for ddl in _INDEX_DDL:
            cursor.execute(ddl)
        conn.commit()
    except sqlite3.OperationalError:
        logger.error("Schema initialization failed")
        raise
    logger.info(
        "Schema initialized: %d tables, %d indexes",
        len(_TABLE_DDL),
        len(_INDEX_DDL),
    )
    _migrate_schema(conn)


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add columns that were introduced after the original CREATE TABLE statements."""
    cursor = conn.execute("PRAGMA table_info(advisory)")
    columns = {row[1] for row in cursor.fetchall()}
    if "triage_status" not in columns:
        conn.execute(
            "ALTER TABLE advisory ADD COLUMN triage_status TEXT DEFAULT 'unread'"
        )
        conn.commit()
        logger.info("Added triage_status column to advisory table")
    # triage_status is a migration-added column, so its index cannot live in
    # _INDEX_DDL (that runs before the ALTER on a fresh DB). Create it here.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_advisory_triage ON advisory(triage_status)"
    )
    conn.commit()

    cursor = conn.execute("PRAGMA table_info(msrc_cve)")
    msrc_cols = {row[1] for row in cursor.fetchall()}
    if "description" not in msrc_cols:
        conn.execute("ALTER TABLE msrc_cve ADD COLUMN description TEXT")
        conn.commit()
        logger.info("Added description column to msrc_cve table")

    # WS-7: detection_rule schema evolution. Per-column guards so a DB that was
    # only partially migrated (e.g. crashed mid-run) gets every missing column.
    cursor = conn.execute("PRAGMA table_info(detection_rule)")
    dr_cols = {row[1] for row in cursor.fetchall()}
    for dr_col, dr_ddl in (
        ("rule_name", "ALTER TABLE detection_rule ADD COLUMN rule_name TEXT"),
        ("raw_extracted", "ALTER TABLE detection_rule ADD COLUMN raw_extracted TEXT"),
        ("validation_status", "ALTER TABLE detection_rule ADD COLUMN validation_status TEXT"),
        ("validation_error", "ALTER TABLE detection_rule ADD COLUMN validation_error TEXT"),
    ):
        if dr_col not in dr_cols:
            conn.execute(dr_ddl)
            conn.commit()
            logger.info("Added %s column to detection_rule table", dr_col)
    if "rule_format" not in dr_cols and "format" in dr_cols:
        conn.execute("ALTER TABLE detection_rule RENAME COLUMN format TO rule_format")
        conn.commit()
        logger.info("Renamed detection_rule.format to rule_format")

    # WS-7 finding 2: detection_rule had no natural key, so INSERT OR REPLACE
    # never deduped and repeat extraction produced duplicate rows. Enforce a
    # unique key via index (ALTER TABLE cannot add a table constraint, and this
    # keeps fresh + migrated DBs identical). COALESCE folds NULL rule_name so
    # unnamed rules for the same advisory+format also dedupe on re-extraction.
    idx_exists = conn.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'index' AND name = 'idx_detection_rule_uniq'"
    ).fetchone()
    if not idx_exists:
        conn.execute(
            "DELETE FROM detection_rule WHERE id NOT IN ("
            "SELECT MAX(id) FROM detection_rule "
            "GROUP BY advisory_id, COALESCE(rule_name, ''), rule_format)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX idx_detection_rule_uniq "
            "ON detection_rule(advisory_id, COALESCE(rule_name, ''), rule_format)"
        )
        conn.commit()
        logger.info("Enforced detection_rule natural-key unique index")

    # WS-7: advisory_technique framework column
    cursor = conn.execute("PRAGMA table_info(advisory_technique)")
    at_cols = {row[1] for row in cursor.fetchall()}
    if "framework" not in at_cols:
        conn.execute(
            "ALTER TABLE advisory_technique ADD COLUMN framework TEXT NOT NULL DEFAULT 'attack'"
        )
        conn.commit()
        logger.info("Added framework column to advisory_technique table")

    # WS-7: advisory enriched_body column
    cursor = conn.execute("PRAGMA table_info(advisory)")
    adv_cols = {row[1] for row in cursor.fetchall()}
    if "enriched_body" not in adv_cols:
        conn.execute("ALTER TABLE advisory ADD COLUMN enriched_body TEXT")
        conn.commit()
        logger.info("Added enriched_body column to advisory table")

    if "original_source" not in adv_cols:
        conn.execute("ALTER TABLE advisory ADD COLUMN original_source TEXT")
        conn.commit()
        logger.info("Added original_source column to advisory table")

    # WS-7: extraction_history phase column
    cursor = conn.execute("PRAGMA table_info(extraction_history)")
    eh_cols = {row[1] for row in cursor.fetchall()}
    if "phase" not in eh_cols:
        conn.execute("ALTER TABLE extraction_history ADD COLUMN phase TEXT")
        conn.commit()
        logger.info("Added phase column to extraction_history table")

    # WS-7 E.3: advisory_technique use_description column
    cursor = conn.execute("PRAGMA table_info(advisory_technique)")
    at_cols2 = {row[1] for row in cursor.fetchall()}
    if "use_description" not in at_cols2:
        conn.execute(
            "ALTER TABLE advisory_technique ADD COLUMN use_description TEXT",
        )
        conn.commit()
        logger.info("Added use_description column to advisory_technique table")

    # WS-7 C4: advisory_cve records where a CVE link was found and how it was
    # classified (msrc / nvd / other), for MSRC-vs-NVD routing on the dashboard.
    cursor = conn.execute("PRAGMA table_info(advisory_cve)")
    ac_cols = {row[1] for row in cursor.fetchall()}
    for ac_col in ("link_url", "link_source"):
        if ac_col not in ac_cols:
            conn.execute(f"ALTER TABLE advisory_cve ADD COLUMN {ac_col} TEXT")
            conn.commit()
            logger.info("Added %s column to advisory_cve table", ac_col)

    # WS-11: ioc extraction_source column for phase-scoped deletion
    cursor = conn.execute("PRAGMA table_info(ioc)")
    ioc_cols = {row[1] for row in cursor.fetchall()}
    if "extraction_source" not in ioc_cols:
        conn.execute(
            "ALTER TABLE ioc ADD COLUMN extraction_source TEXT NOT NULL DEFAULT 'parse'"
        )
        conn.commit()
        logger.info("Added extraction_source column to ioc table")

    # WS-12: prompt_version column for analysis versioning
    cursor = conn.execute("PRAGMA table_info(advisory_analysis)")
    aa_cols = {row[1] for row in cursor.fetchall()}
    if "prompt_version" not in aa_cols:
        conn.execute(
            "ALTER TABLE advisory_analysis ADD COLUMN prompt_version INTEGER"
        )
        conn.commit()
        logger.info("Added prompt_version column to advisory_analysis table")

    # _backfill_from_raw_json is a one-time repair of legacy msrc_cve rows and a
    # full table scan; api.py/poll.py/cli.py all call init_schema on every boot,
    # so gate it on schema version to run exactly once.
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version < 1:
        _backfill_from_raw_json(conn)
        conn.execute("PRAGMA user_version = 1")
        conn.commit()

    if version < 2:
        _migrate_phase_names(conn)
        conn.execute("PRAGMA user_version = 2")
        conn.commit()


def _backfill_from_raw_json(conn: sqlite3.Connection) -> None:
    """Re-extract description and component from raw_json for rows that need it.

    Runs once: fixes rows where component is a KB number or description is NULL.
    """
    rows = conn.execute(
        "SELECT cve_id, raw_json, component, description FROM msrc_cve "
        "WHERE raw_json IS NOT NULL AND raw_json != '{}'"
    ).fetchall()
    updated = 0
    for cve_id, raw, old_comp, old_desc in rows:
        try:
            vuln = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        notes = vuln.get("Notes") or []
        new_desc = new_comp = None
        for note in notes:
            if not isinstance(note, dict):
                continue
            ntype = note.get("Type")
            val = note.get("Value")
            if ntype == 2 and val and new_desc is None:
                clean = re.sub(r"<[^>]+>", "", str(val)).strip()
                if len(clean) > 10:
                    new_desc = clean
            if ntype == 7 and val and str(val).strip() and new_comp is None:
                new_comp = str(val).strip()
        need_desc = new_desc and not old_desc
        need_comp = new_comp and (
            not old_comp
            or re.fullmatch(r"\d+", old_comp)
            or old_comp in ("Release Notes", "Click to Run")
        )
        if need_desc or need_comp:
            sets, params = [], []
            if need_desc:
                sets.append("description = ?")
                params.append(new_desc)
            if need_comp:
                sets.append("component = ?")
                params.append(new_comp)
            params.append(cve_id)
            conn.execute(
                f"UPDATE msrc_cve SET {', '.join(sets)} WHERE cve_id = ?",
                params,
            )
            updated += 1
    if updated:
        conn.commit()
        logger.info("Backfilled description/component for %d CVEs from raw_json", updated)


def _migrate_phase_names(conn: sqlite3.Connection) -> None:
    """Rename phase_a_* status values and phase tags to parse-based names."""
    conn.execute(
        "UPDATE advisory SET extraction_status = 'parse_done' "
        "WHERE extraction_status = 'phase_a_done'",
    )
    conn.execute(
        "UPDATE advisory SET extraction_status = 'parse_partial' "
        "WHERE extraction_status = 'phase_a_partial'",
    )
    conn.execute(
        "UPDATE advisory SET extraction_status = 'parse_failed' "
        "WHERE extraction_status = 'phase_a_failed'",
    )
    conn.execute(
        "UPDATE extraction_log SET phase = 'parse' "
        "WHERE phase = 'phase_a'",
    )
    conn.execute(
        "UPDATE extraction_history SET phase = 'parse' "
        "WHERE phase = 'phase_a'",
    )
    conn.execute(
        "UPDATE extraction_history "
        "SET extraction_model = REPLACE(extraction_model, 'phase_a/', 'parse/') "
        "WHERE extraction_model LIKE 'phase_a/%'",
    )
    conn.execute(
        "UPDATE threat_actor_alias SET source = 'parse' "
        "WHERE source = 'phase_a'",
    )
    conn.commit()
    logger.info("Migrated phase_a_* names to parse-based naming")


# -- Advisory CRUD ------------------------------------------------------------

# enriched_body is deliberately excluded: it is owned by the parse-phase
# writer (save_parse_results) and cleared by update_scrape_result on re-scrape. The
# ingest/scrape path uses upsert_advisory, which must never resurrect a stale
# enriched body from an incoming dict.
_ADVISORY_COLUMNS = frozenset({
    "advisory_id", "type", "source", "title", "summary", "link", "pub_date",
    "raw_html", "article_body", "extracted_json", "extraction_status",
    "extraction_model", "extraction_error", "retry_count", "extracted_at",
    "input_tokens", "output_tokens", "llm_latency_ms", "llm_cost_usd",
    "scrape_status", "scrape_retry_count", "sitemap_lastmod",
    "first_seen", "last_updated", "triage_status",
    "original_source",
})


def get_advisory(conn: sqlite3.Connection, advisory_id: str) -> dict | None:
    """Return a single advisory as a dict, or None if not found."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute("SELECT * FROM advisory WHERE advisory_id = ?", (advisory_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


def get_advisory_by_numeric_id(conn: sqlite3.Connection, numeric_id: int) -> dict | None:
    """Return a single advisory by numeric primary key."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute("SELECT * FROM advisory WHERE id = ?", (numeric_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


def is_advisory_cached(conn: sqlite3.Connection, advisory_id: str) -> bool:
    """Check whether an advisory with this ID already exists."""
    row = conn.execute(
        "SELECT 1 FROM advisory WHERE advisory_id = ? LIMIT 1",
        (advisory_id,),
    ).fetchone()
    return row is not None


def get_advisory_raw_html(conn: sqlite3.Connection, advisory_id: str) -> str | None:
    """Return the raw_html column for a specific advisory."""
    row = conn.execute(
        "SELECT raw_html FROM advisory WHERE advisory_id = ?",
        (advisory_id,),
    ).fetchone()
    return row[0] if row else None


def upsert_advisory(conn: sqlite3.Connection, data: dict) -> None:
    """Insert or update an advisory row from a dict of column values.

    Only columns present in *data* are written; missing optional columns
    keep their existing value on conflict rather than being overwritten
    with NULL.
    """
    # Whitelist prevents injection -- column names come from a fixed set
    columns = [k for k in data if k in _ADVISORY_COLUMNS]
    if not columns:
        logger.warning("upsert_advisory called with no valid columns")
        return
    placeholders = ", ".join("?" for _ in columns)
    col_list = ", ".join(columns)
    update_cols = [c for c in columns if c != "advisory_id"]
    update_clause = ", ".join(f"{c} = excluded.{c}" for c in update_cols)

    sql = (
        f"INSERT INTO advisory ({col_list}) VALUES ({placeholders}) "
        f"ON CONFLICT(advisory_id) DO UPDATE SET {update_clause}"
    )
    values = [data[c] for c in columns]
    with conn:
        conn.execute(sql, values)
    logger.debug("Upserted advisory %s", data.get("advisory_id"))


# -- Scrape queue --------------------------------------------------------------

def get_pending_scrape(
    conn: sqlite3.Connection, batch_size: int, source: str | None = None,
) -> list[dict]:
    """Return advisories awaiting first scrape, newest sitemap entries first."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    if source is not None:
        cursor.execute(
            "SELECT advisory_id, link, sitemap_lastmod FROM advisory "
            "WHERE scrape_status = 'pending' AND source = ? "
            "ORDER BY sitemap_lastmod DESC LIMIT ?",
            (source, batch_size),
        )
    else:
        cursor.execute(
            "SELECT advisory_id, link, sitemap_lastmod FROM advisory "
            "WHERE scrape_status = 'pending' ORDER BY sitemap_lastmod DESC LIMIT ?",
            (batch_size,),
        )
    return [dict(row) for row in cursor.fetchall()]


def get_cf_challenged(conn: sqlite3.Connection) -> list[dict]:
    """Return advisories that can still be retried after a Cloudflare challenge.

    Advisories with 3+ retries are promoted to 'cf_blocked' first, so only
    retryable rows are returned.
    """
    with conn:
        conn.execute(
            "UPDATE advisory SET scrape_status = 'cf_blocked' "
            "WHERE scrape_status = 'cf_challenged' AND scrape_retry_count >= 3"
        )
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT advisory_id, link, sitemap_lastmod, scrape_retry_count FROM advisory "
        "WHERE scrape_status = 'cf_challenged'"
    )
    return [dict(row) for row in cursor.fetchall()]


def update_scrape_result(
    conn: sqlite3.Connection,
    advisory_id: str,
    scrape_status: str,
    raw_html: str | None,
    article_body: str | None,
) -> None:
    """Record the outcome of a scrape attempt."""
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        if scrape_status == "scraped":
            # A fresh body invalidates any prior extraction: re-queue parse phase
            # (extraction_status='pending') and drop the stale enriched body so
            # the dashboard never serves enrichment built from the old article.
            conn.execute(
                "UPDATE advisory SET scrape_status = ?, raw_html = ?, "
                "article_body = ?, last_updated = ?, scrape_retry_count = 0, "
                "extraction_status = 'pending', enriched_body = NULL "
                "WHERE advisory_id = ?",
                (scrape_status, raw_html, article_body, now, advisory_id),
            )
        elif scrape_status == "cf_challenged":
            conn.execute(
                "UPDATE advisory SET scrape_status = ?, raw_html = ?, "
                "article_body = ?, last_updated = ?, "
                "scrape_retry_count = scrape_retry_count + 1 "
                "WHERE advisory_id = ?",
                (scrape_status, raw_html, article_body, now, advisory_id),
            )
        else:
            conn.execute(
                "UPDATE advisory SET scrape_status = ?, raw_html = ?, "
                "article_body = ?, last_updated = ? WHERE advisory_id = ?",
                (scrape_status, raw_html, article_body, now, advisory_id),
            )
    logger.debug(
        "Scrape result for %s: %s", advisory_id, scrape_status,
    )


# -- Counts --------------------------------------------------------------------

def count_advisories(conn: sqlite3.Connection, source: str | None = None) -> int:
    """Return total advisory count, optionally filtered by source."""
    if source is None:
        row = conn.execute("SELECT COUNT(*) FROM advisory").fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) FROM advisory WHERE source = ?", (source,),
        ).fetchone()
    return row[0]


def count_by_scrape_status(
    conn: sqlite3.Connection, source: str | None = None,
) -> dict[str, int]:
    """Return {status: count} breakdown for advisories, optionally filtered by *source*."""
    if source is not None:
        cursor = conn.execute(
            "SELECT scrape_status, COUNT(*) FROM advisory "
            "WHERE source = ? GROUP BY scrape_status",
            (source,),
        )
    else:
        cursor = conn.execute(
            "SELECT scrape_status, COUNT(*) FROM advisory "
            "GROUP BY scrape_status",
        )
    return {row[0]: row[1] for row in cursor.fetchall()}


# -- Poll history --------------------------------------------------------------

def record_cisa_poll(
    conn: sqlite3.Connection,
    polled_at: str,
    source: str,
    aa_total: int,
    ar_total: int,
    new_advisories: int,
    updated: int,
    errors: str | None,
) -> None:
    """Write one row to cisa_poll_history."""
    with conn:
        conn.execute(
            "INSERT INTO cisa_poll_history "
            "(polled_at, source, aa_total, ar_total, "
            "new_advisories, updated, errors) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (polled_at, source, aa_total, ar_total,
             new_advisories, updated, errors),
        )
    logger.debug(
        "Recorded CISA poll: source=%s, new=%d, updated=%d",
        source, new_advisories, updated,
    )


# -- Advisory listing (dashboard) ---------------------------------------------

def _apply_multi_value_filter(
    col: str, val: str, clauses: list[str], params: list,
) -> None:
    """Append = or IN clause for a column; frontend sends multi-select as CSV."""
    parts = [v.strip() for v in val.split(",")]
    if len(parts) == 1:
        clauses.append(f"{col} = ?")
        params.append(parts[0])
    else:
        placeholders = ", ".join("?" for _ in parts)
        clauses.append(f"{col} IN ({placeholders})")
        params.extend(parts)


def _build_advisory_filters(
    source: str | None,
    advisory_type: str | None,
    extraction_status: str | None,
    triage_status: str | None,
    date_from: str | None,
    date_to: str | None,
    search: str | None,
    scrape_status: str | None = "scraped",
) -> tuple[str, list]:
    """Build WHERE clause and parameter list from non-None filters."""
    clauses: list[str] = []
    params: list = []
    if scrape_status is not None:
        clauses.append("scrape_status = ?")
        params.append(scrape_status)
    for col, val in [
        ("source", source), ("type", advisory_type),
        ("extraction_status", extraction_status),
        ("triage_status", triage_status),
    ]:
        if val is not None:
            _apply_multi_value_filter(col, val, clauses, params)
    if date_from is not None:
        clauses.append("pub_date >= ?")
        params.append(date_from)
    if date_to is not None:
        clauses.append("pub_date <= ?")
        params.append(date_to)
    if search is not None:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("(title LIKE ? ESCAPE '\\' OR advisory_id LIKE ? ESCAPE '\\')")
        params.extend([f"%{escaped}%", f"%{escaped}%"])
    where = " AND ".join(clauses) if clauses else "1=1"
    return where, params


_ADVISORY_SORT_COLUMNS = frozenset({
    "pub_date", "title", "source", "type", "extraction_status",
    "triage_status", "first_seen",
})


def get_advisories_page(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
    source: str | None = None,
    advisory_type: str | None = None,
    extraction_status: str | None = None,
    triage_status: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
    scrape_status: str | None = "scraped",
    sort: str = "pub_date",
    sort_dir: str = "desc",
) -> dict:
    """Return paginated advisory listing excluding large text columns."""
    where, params = _build_advisory_filters(
        source, advisory_type, extraction_status, triage_status,
        date_from, date_to, search, scrape_status=scrape_status,
    )
    if sort not in _ADVISORY_SORT_COLUMNS:
        sort = "pub_date"
    direction = "ASC" if sort_dir.lower() == "asc" else "DESC"

    count_row = conn.execute(
        f"SELECT COUNT(*) FROM advisory WHERE {where}", params,
    ).fetchone()
    total = count_row[0]

    offset = (page - 1) * per_page
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        f"SELECT id, advisory_id, type, source, title, pub_date, "
        f"extraction_status, triage_status, first_seen "
        f"FROM advisory WHERE {where} "
        f"ORDER BY {sort} {direction} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    )
    items = [dict(row) for row in cursor.fetchall()]
    return {"items": items, "total": total, "page": page, "per_page": per_page}


# -- Stats (dashboard) --------------------------------------------------------

def _count_grouped(
    cursor: sqlite3.Cursor, column: str, table: str,
    where: str = "1=1",
) -> dict[str, int]:
    """Return {value: count} for a column grouped by value."""
    rows = cursor.execute(
        f"SELECT {column}, COUNT(*) FROM {table} "
        f"WHERE {where} GROUP BY {column}",
    ).fetchall()
    return {row[0]: row[1] for row in rows}


def get_stats(conn: sqlite3.Connection) -> dict:
    """Return dashboard summary statistics."""
    cursor = conn.cursor()
    scraped = "scrape_status = 'scraped'"
    by_source = _count_grouped(cursor, "source", "advisory", scraped)
    by_extraction = _count_grouped(
        cursor, "extraction_status", "advisory", scraped,
    )
    by_triage = _count_grouped(
        cursor, "triage_status", "advisory", scraped,
    )
    polls: dict[str, str | None] = {}
    for row in cursor.execute(
        "SELECT source, MAX(polled_at) FROM cisa_poll_history GROUP BY source",
    ).fetchall():
        polls[row[0]] = row[1]
    ioc_count = cursor.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
    rule_count = cursor.execute(
        "SELECT COUNT(*) FROM detection_rule",
    ).fetchone()[0]
    return {
        "advisories": {
            "total": sum(by_source.values()),
            "by_source": by_source,
            "by_extraction": by_extraction,
            "by_triage": by_triage,
        },
        "polls": polls,
        "iocs": {"total": ioc_count},
        "rules": {"total": rule_count},
    }


# -- Advisory analysis (analysis phase) ----------------------------------------

def get_analysis(
    conn: sqlite3.Connection,
    advisory_id: str,
    analysis_type: str = "purple_team",
) -> dict | None:
    """Return cached analysis for an advisory, or None if not found."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT * FROM advisory_analysis "
        "WHERE advisory_id = ? AND analysis_type = ?",
        (advisory_id, analysis_type),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def upsert_analysis(
    conn: sqlite3.Connection,
    advisory_id: str,
    analysis_type: str,
    analysis_json: str,
    model: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    latency_ms: int | None = None,
    cost_usd: float | None = None,
    prompt_version: int | None = None,
    user_context: str | None = None,
) -> None:
    """Insert or replace an analysis result for an advisory."""
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            "INSERT INTO advisory_analysis "
            "(advisory_id, analysis_type, analysis_json, model, "
            "input_tokens, output_tokens, latency_ms, cost_usd, "
            "prompt_version, user_context, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(advisory_id, analysis_type) DO UPDATE SET "
            "analysis_json = excluded.analysis_json, "
            "model = excluded.model, "
            "input_tokens = excluded.input_tokens, "
            "output_tokens = excluded.output_tokens, "
            "latency_ms = excluded.latency_ms, "
            "cost_usd = excluded.cost_usd, "
            "prompt_version = excluded.prompt_version, "
            "user_context = excluded.user_context, "
            "created_at = excluded.created_at",
            (advisory_id, analysis_type, analysis_json, model,
             input_tokens, output_tokens, latency_ms, cost_usd,
             prompt_version, user_context, now),
        )
    logger.debug("Upserted analysis for %s (%s)", advisory_id, analysis_type)


# -- Triage --------------------------------------------------------------------

def update_triage_status(
    conn: sqlite3.Connection, advisory_id: str, status: str,
) -> bool:
    """Set triage_status on an advisory. Returns True if row was updated."""
    with conn:
        cursor = conn.execute(
            "UPDATE advisory SET triage_status = ? WHERE advisory_id = ?",
            (status, advisory_id),
        )
    return cursor.rowcount > 0


# -- MSRC CVEs ----------------------------------------------------------------

_MSRC_CVE_DATA_COLUMNS = (
    "cve_id", "title", "description", "released",
    "component", "component_category",
    "impact", "severity", "cvss_base", "cvss_temporal", "cvss_vector",
    "av", "ac", "pr", "ui", "scope", "cwe_id", "cwe_description",
    "exploit_status", "publicly_disclosed", "exploited_wild",
    "customer_action", "defense_score", "priority",
    "vr_score", "vr_priority", "vr_tags", "raw_json",
)

_MSRC_SORT_COLUMNS = frozenset({"defense_score", "vr_score", "cvss_base", "released", "priority", "vr_priority", "severity"})


def upsert_msrc_cve(conn: sqlite3.Connection, data: dict) -> None:
    """Insert or update an MSRC CVE row from a dict of column values."""
    now = datetime.now(timezone.utc).isoformat()
    cols = list(_MSRC_CVE_DATA_COLUMNS) + ["first_seen", "last_updated"]
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    update_cols = [c for c in cols if c not in ("cve_id", "first_seen")]
    update_clause = ", ".join(f"{c} = excluded.{c}" for c in update_cols)
    values = [data.get(c) for c in _MSRC_CVE_DATA_COLUMNS] + [now, now]
    with conn:
        conn.execute(
            f"INSERT INTO msrc_cve ({col_list}) VALUES ({placeholders}) "
            f"ON CONFLICT(cve_id) DO UPDATE SET {update_clause}",
            values,
        )
    logger.debug("Upserted MSRC CVE %s", data.get("cve_id"))


def get_msrc_cve(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    """Return a single MSRC CVE as a dict, or None if not found."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute("SELECT * FROM msrc_cve WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_known_msrc_cve_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of all CVE IDs currently stored in msrc_cve."""
    rows = conn.execute("SELECT cve_id FROM msrc_cve").fetchall()
    return {row[0] for row in rows}


def get_all_msrc_cves(conn: sqlite3.Connection) -> list[dict]:
    """Return every row in msrc_cve as a list of dicts."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute("SELECT * FROM msrc_cve")
    return [dict(row) for row in cursor.fetchall()]


def update_msrc_cve_scores(
    conn: sqlite3.Connection, scores: list[tuple[str, float, str]],
) -> None:
    """Batch-update defense_score and priority for MSRC CVEs.

    Each tuple is (cve_id, defense_score, priority).
    """
    with conn:
        conn.executemany(
            "UPDATE msrc_cve SET defense_score = ?, priority = ? "
            "WHERE cve_id = ?",
            [(score, priority, cve_id) for cve_id, score, priority in scores],
        )
    logger.debug("Updated scores for %d MSRC CVEs", len(scores))


def update_msrc_cve_vr_scores(
    conn: sqlite3.Connection,
    scores: list[tuple[str, float, str, float, str, str]],
) -> None:
    """Batch-update both defense and VR scores for MSRC CVEs.

    Each tuple is (cve_id, defense_score, priority, vr_score, vr_priority, vr_tags).
    """
    with conn:
        conn.executemany(
            "UPDATE msrc_cve SET defense_score = ?, priority = ?, "
            "vr_score = ?, vr_priority = ?, vr_tags = ? "
            "WHERE cve_id = ?",
            [
                (defense_score, priority, vr_score, vr_priority, vr_tags, cve_id)
                for cve_id, defense_score, priority, vr_score, vr_priority, vr_tags in scores
            ],
        )
    logger.debug("Updated defense + VR scores for %d MSRC CVEs", len(scores))


def get_related_cves(
    conn: sqlite3.Connection,
    cve_id: str,
    component: str | None,
    limit: int = 10,
) -> list[dict]:
    """Return CVEs sharing the same component, excluding the given cve_id."""
    if not component:
        return []
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT cve_id, title, impact, severity, cwe_id, released, "
        "defense_score, priority, vr_score, vr_priority, "
        "exploited_wild, publicly_disclosed "
        "FROM msrc_cve WHERE component = ? AND cve_id != ? "
        "ORDER BY released DESC LIMIT ?",
        (component, cve_id, limit),
    )
    return [dict(row) for row in cursor.fetchall()]


def get_cve_ids_with_kb(conn: sqlite3.Connection) -> set[str]:
    """Return CVE IDs that have at least one KB entry."""
    rows = conn.execute("SELECT DISTINCT cve_id FROM msrc_kb").fetchall()
    return {row[0] for row in rows}


def _build_msrc_filters(
    priority: str | None = None,
    impact: str | None = None,
    severity: str | None = None,
    exploit_status: str | None = None,
    component_category: str | None = None,
    cwe_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    has_advisory: bool | None = None,
    customer_action: str | None = None,
    search: str | None = None,
    vr_priority: str | None = None,
) -> tuple[str, list]:
    """Build WHERE clause and parameter list for MSRC CVE filters."""
    clauses: list[str] = []
    params: list = []
    for col, val in [
        ("priority", priority), ("impact", impact),
        ("severity", severity), ("vr_priority", vr_priority),
    ]:
        if val is not None:
            values = [v.strip() for v in val.split(",") if v.strip()]
            if len(values) == 1:
                clauses.append(f"{col} = ?")
                params.append(values[0])
            elif values:
                ph = ", ".join("?" for _ in values)
                clauses.append(f"{col} IN ({ph})")
                params.extend(values)
    for col, val in [
        ("component_category", component_category),
        ("cwe_id", cwe_id),
    ]:
        if val is not None:
            clauses.append(f"{col} = ?")
            params.append(val)
    if customer_action is not None:
        clauses.append("customer_action IS NOT NULL")
    if exploit_status is not None:
        for flag in exploit_status.split(","):
            flag = flag.strip()
            if flag == "kev":
                clauses.append(
                    "EXISTS (SELECT 1 FROM kev_entry "
                    "WHERE kev_entry.cve_id = msrc_cve.cve_id)"
                )
            elif flag == "exploited_wild":
                clauses.append("exploited_wild = 1")
            elif flag == "publicly_disclosed":
                clauses.append("publicly_disclosed = 1")
    if date_from is not None:
        clauses.append("released >= ?")
        params.append(date_from)
    if date_to is not None:
        clauses.append("released <= ?")
        params.append(date_to)
    if has_advisory is True:
        clauses.append(
            "EXISTS (SELECT 1 FROM advisory_cve "
            "WHERE advisory_cve.cve_id = msrc_cve.cve_id)"
        )
    elif has_advisory is False:
        clauses.append(
            "NOT EXISTS (SELECT 1 FROM advisory_cve "
            "WHERE advisory_cve.cve_id = msrc_cve.cve_id)"
        )
    if search is not None:
        escaped = (
            search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        clauses.append(
            "(msrc_cve.cve_id LIKE ? ESCAPE '\\' "
            "OR title LIKE ? ESCAPE '\\')"
        )
        term = f"%{escaped}%"
        params.extend([term, term])
    where = " AND ".join(clauses) if clauses else "1=1"
    return where, params


def _attach_advisory_ids(conn: sqlite3.Connection, items: list[dict]) -> None:
    """Attach an advisory_ids list to each item dict in-place."""
    cve_ids = [item["cve_id"] for item in items]
    adv_map: dict[str, list[dict]] = {}
    if cve_ids:
        ph = ", ".join("?" for _ in cve_ids)
        for row in conn.execute(
            f"SELECT ac.advisory_id, ac.cve_id, a.id "
            f"FROM advisory_cve ac "
            f"INNER JOIN advisory a ON a.advisory_id = ac.advisory_id "
            f"WHERE ac.cve_id IN ({ph})", cve_ids,
        ).fetchall():
            adv_map.setdefault(row[1], []).append(
                {"id": row[2], "advisory_id": row[0]},
            )
    for item in items:
        item["advisory_ids"] = adv_map.get(item["cve_id"], [])


def get_msrc_cves_page(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
    sort: str = "defense_score",
    sort_dir: str = "desc",
    **filter_kwargs,
) -> dict:
    """Return paginated MSRC CVE listing with KEV and advisory enrichment."""
    where, params = _build_msrc_filters(**filter_kwargs)
    sort_col = sort if sort in _MSRC_SORT_COLUMNS else "defense_score"
    direction = "ASC" if sort_dir.upper() == "ASC" else "DESC"

    _PRIORITY_ORDER = (
        "CASE {col} "
        "WHEN 'PRIME' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 "
        "WHEN 'LOW' THEN 4 WHEN 'NOISE' THEN 5 ELSE 6 END"
    )
    _SEVERITY_ORDER = (
        "CASE severity "
        "WHEN 'Critical' THEN 1 WHEN 'Important' THEN 2 WHEN 'Moderate' THEN 3 "
        "WHEN 'Low' THEN 4 ELSE 5 END"
    )
    if sort_col in ("priority", "vr_priority"):
        order_expr = _PRIORITY_ORDER.format(col=sort_col)
    elif sort_col == "severity":
        order_expr = _SEVERITY_ORDER
    else:
        order_expr = sort_col

    total = conn.execute(
        f"SELECT COUNT(*) FROM msrc_cve WHERE {where}", params,
    ).fetchone()[0]

    offset = (page - 1) * per_page
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        f"SELECT msrc_cve.*, "
        f"CASE WHEN kev_entry.cve_id IS NOT NULL THEN 1 ELSE 0 END "
        f"AS kev_listed "
        f"FROM msrc_cve "
        f"LEFT JOIN kev_entry ON kev_entry.cve_id = msrc_cve.cve_id "
        f"WHERE {where} "
        f"ORDER BY {order_expr} {direction} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    )
    items = [dict(row) for row in cursor.fetchall()]
    for item in items:
        item["kev_listed"] = bool(item["kev_listed"])
    _attach_advisory_ids(conn, items)
    return {"items": items, "total": total, "page": page, "per_page": per_page}


# -- MSRC KB entries ----------------------------------------------------------


def replace_kb_entries(
    conn: sqlite3.Connection,
    cve_id: str,
    entries: list[tuple[str, str | None, str | None]],
) -> None:
    """Replace all KB entries for a CVE (delete then batch insert).

    Each tuple is (kb_number, product_name, download_url).
    """
    with conn:
        conn.execute("DELETE FROM msrc_kb WHERE cve_id = ?", (cve_id,))
        conn.executemany(
            "INSERT INTO msrc_kb (cve_id, kb_number, product_name, download_url) "
            "VALUES (?, ?, ?, ?)",
            [(cve_id, kb, prod, url) for kb, prod, url in entries],
        )
    logger.debug("Replaced %d KB entries for %s", len(entries), cve_id)


def get_kb_entries(conn: sqlite3.Connection, cve_id: str) -> list[dict]:
    """Return KB entries for a CVE as a list of dicts."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute("SELECT * FROM msrc_kb WHERE cve_id = ?", (cve_id,))
    return [dict(row) for row in cursor.fetchall()]


# -- KEV entries --------------------------------------------------------------


def upsert_kev_entry(conn: sqlite3.Connection, data: dict) -> None:
    """Insert or update a CISA KEV entry."""
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            "INSERT INTO kev_entry "
            "(cve_id, vendor, product, vulnerability_name, "
            "date_added, due_date, known_ransomware, notes, last_fetched) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cve_id) DO UPDATE SET "
            "vendor = excluded.vendor, product = excluded.product, "
            "vulnerability_name = excluded.vulnerability_name, "
            "date_added = excluded.date_added, "
            "due_date = excluded.due_date, "
            "known_ransomware = excluded.known_ransomware, "
            "notes = excluded.notes, "
            "last_fetched = excluded.last_fetched",
            (data.get("cve_id"), data.get("vendor"), data.get("product"),
             data.get("vulnerability_name"), data.get("date_added"),
             data.get("due_date"), data.get("known_ransomware"),
             data.get("notes"), now),
        )
    logger.debug("Upserted KEV entry %s", data.get("cve_id"))


def get_kev_entry(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    """Return a single KEV entry as a dict, or None if not found."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute("SELECT * FROM kev_entry WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_kev_cve_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of all CVE IDs in the KEV catalog."""
    rows = conn.execute("SELECT cve_id FROM kev_entry").fetchall()
    return {row[0] for row in rows}


# -- MSRC poll history --------------------------------------------------------


def insert_msrc_poll(
    conn: sqlite3.Connection,
    new_cves: int,
    updated_cves: int,
    errors: str | None,
) -> None:
    """Record one MSRC polling run."""
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            "INSERT INTO msrc_poll_history "
            "(polled_at, new_cves, updated_cves, errors) "
            "VALUES (?, ?, ?, ?)",
            (now, new_cves, updated_cves, errors),
        )
    logger.debug("Recorded MSRC poll: new=%d, updated=%d", new_cves, updated_cves)


# -- Advisory-CVE junction ----------------------------------------------------


def link_advisory_cve(
    conn: sqlite3.Connection, advisory_id: str, cve_id: str,
) -> None:
    """Link an advisory to a CVE (idempotent)."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO advisory_cve (advisory_id, cve_id) "
            "VALUES (?, ?)",
            (advisory_id, cve_id),
        )


def get_advisory_cves(conn: sqlite3.Connection, advisory_id: str) -> list[dict]:
    """Return all CVEs linked to an advisory, with MSRC enrichment when known.

    LEFT JOIN (not INNER) so CVEs that were extracted from the advisory but are
    not in msrc_cve (e.g. NVD-only CVEs) are still returned. ``is_msrc`` flags
    whether the CVE row exists in msrc_cve; ``link_source`` carries how the CVE
    link was classified during extraction, for MSRC-vs-NVD routing.
    """
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT ac.cve_id, ac.link_source, "
        "m.title, m.severity, m.cvss_base, "
        "m.defense_score, m.priority, m.exploited_wild, "
        "m.component, m.impact, "
        "CASE WHEN m.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_msrc, "
        "CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS kev_listed "
        "FROM advisory_cve ac "
        "LEFT JOIN msrc_cve m ON m.cve_id = ac.cve_id "
        "LEFT JOIN kev_entry k ON k.cve_id = ac.cve_id "
        "WHERE ac.advisory_id = ?",
        (advisory_id,),
    )
    items = [dict(row) for row in cursor.fetchall()]
    for item in items:
        item["kev_listed"] = bool(item["kev_listed"])
        item["is_msrc"] = bool(item["is_msrc"])
        item["exploited_wild"] = bool(item["exploited_wild"])
    return items


def count_advisory_cves(conn: sqlite3.Connection, advisory_id: str) -> int:
    """Return the number of CVEs linked to an advisory (all rows, not msrc-only)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM advisory_cve WHERE advisory_id = ?",
        (advisory_id,),
    ).fetchone()
    return row[0]


def get_msrc_cve_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of CVE IDs present in msrc_cve, for enricher MSRC-vs-NVD link routing."""
    rows = conn.execute("SELECT cve_id FROM msrc_cve").fetchall()
    return {r[0] for r in rows}


def count_iocs(conn: sqlite3.Connection, advisory_id: str) -> int:
    """Return the number of IOCs linked to an advisory."""
    return conn.execute(
        "SELECT COUNT(*) FROM ioc WHERE advisory_id = ?", (advisory_id,),
    ).fetchone()[0]


def count_detection_rules(conn: sqlite3.Connection, advisory_id: str) -> int:
    """Return the number of detection rules linked to an advisory."""
    return conn.execute(
        "SELECT COUNT(*) FROM detection_rule WHERE advisory_id = ?", (advisory_id,),
    ).fetchone()[0]


def count_advisory_techniques(
    conn: sqlite3.Connection, advisory_id: str, framework: str | None = None,
) -> int:
    """Return the number of techniques linked to an advisory, optionally by framework."""
    if framework is None:
        return conn.execute(
            "SELECT COUNT(*) FROM advisory_technique WHERE advisory_id = ?",
            (advisory_id,),
        ).fetchone()[0]
    return conn.execute(
        "SELECT COUNT(*) FROM advisory_technique WHERE advisory_id = ? AND framework = ?",
        (advisory_id, framework),
    ).fetchone()[0]


def count_advisory_assets(conn: sqlite3.Connection, advisory_id: str) -> int:
    """Return the number of assets linked to an advisory."""
    return conn.execute(
        "SELECT COUNT(*) FROM advisory_asset WHERE advisory_id = ?", (advisory_id,),
    ).fetchone()[0]


def get_extraction_log_severity_counts(
    conn: sqlite3.Connection, advisory_id: str,
) -> dict[str, int]:
    """Return {'warning': n, 'error': m} for an advisory's extraction log (missing keys -> 0)."""
    rows = conn.execute(
        "SELECT severity, COUNT(*) FROM extraction_log WHERE advisory_id = ? GROUP BY severity",
        (advisory_id,),
    ).fetchall()
    counts = {"warning": 0, "error": 0}
    for severity, n in rows:
        counts[severity] = n
    return counts


def bulk_ioc_cross_refs(
    conn: sqlite3.Connection, advisory_id: str,
) -> dict[tuple[str, str], int]:
    """Map (type, value) -> count of OTHER advisories containing the same IOC, in one query.

    Replaces a per-IOC N+1 (count_ioc_cross_refs called in a loop). IOCs with no cross-refs
    are absent from the map; callers should default to 0.
    """
    rows = conn.execute(
        "SELECT i.type, i.value, COUNT(DISTINCT o.advisory_id) "
        "FROM ioc i JOIN ioc o "
        "  ON o.type = i.type AND o.value = i.value AND o.advisory_id != i.advisory_id "
        "WHERE i.advisory_id = ? "
        "GROUP BY i.type, i.value",
        (advisory_id,),
    ).fetchall()
    return {(r[0], r[1]): r[2] for r in rows}


def get_cve_advisories(conn: sqlite3.Connection, cve_id: str) -> list[dict]:
    """Return advisories linked to a CVE."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT a.id, a.advisory_id, a.title, a.source, a.pub_date "
        "FROM advisory_cve ac "
        "INNER JOIN advisory a ON a.advisory_id = ac.advisory_id "
        "WHERE ac.cve_id = ?",
        (cve_id,),
    )
    return [dict(row) for row in cursor.fetchall()]


# -- MSRC stats ---------------------------------------------------------------


def get_msrc_stats(conn: sqlite3.Connection) -> dict:
    """Return MSRC dashboard summary statistics."""
    cursor = conn.cursor()
    total = cursor.execute("SELECT COUNT(*) FROM msrc_cve").fetchone()[0]

    by_priority: dict[str, int] = {}
    for row in cursor.execute(
        "SELECT priority, COUNT(*) FROM msrc_cve GROUP BY priority"
    ).fetchall():
        by_priority[row[0]] = row[1]

    by_vr_priority: dict[str, int] = {}
    for row in cursor.execute(
        "SELECT COALESCE(vr_priority, 'NOISE'), COUNT(*) FROM msrc_cve GROUP BY 1"
    ).fetchall():
        by_vr_priority[row[0]] = row[1]

    by_impact: dict[str, int] = {}
    for row in cursor.execute(
        "SELECT impact, COUNT(*) FROM msrc_cve GROUP BY impact"
    ).fetchall():
        by_impact[row[0]] = row[1]

    by_severity: dict[str, int] = {}
    for row in cursor.execute(
        "SELECT severity, COUNT(*) FROM msrc_cve GROUP BY severity"
    ).fetchall():
        by_severity[row[0]] = row[1]

    kev_count = cursor.execute("SELECT COUNT(*) FROM kev_entry").fetchone()[0]
    exploited = cursor.execute(
        "SELECT COUNT(*) FROM msrc_cve WHERE exploited_wild = 1"
    ).fetchone()[0]
    last_poll_row = cursor.execute(
        "SELECT MAX(polled_at) FROM msrc_poll_history"
    ).fetchone()
    last_poll = last_poll_row[0] if last_poll_row else None

    return {
        "total_cves": total,
        "by_priority": by_priority,
        "by_vr_priority": by_vr_priority,
        "by_impact": by_impact,
        "by_severity": by_severity,
        "kev_count": kev_count,
        "exploited_count": exploited,
        "last_poll": last_poll,
    }


# -- Detection Rules -----------------------------------------------------------


def upsert_detection_rule(
    conn: sqlite3.Connection,
    advisory_id: str,
    rule_name: str | None,
    rule_text: str,
    raw_extracted: str | None,
    source: str | None,
    validation_status: str | None,
    validation_error: str | None,
    rule_format: str,
) -> None:
    """Insert or replace a detection rule for an advisory.

    Idempotent on the natural key (advisory_id, rule_name, rule_format) enforced
    by idx_detection_rule_uniq; INSERT OR REPLACE overwrites the prior row rather
    than duplicating it. Rules that failed validation are kept (their
    validation_status/validation_error are stored, not dropped).
    """
    if rule_format not in ("yara", "sigma", "snort"):
        raise ValueError(
            f"rule_format must be yara, sigma, or snort, got {rule_format!r}"
        )
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO detection_rule "
            "(advisory_id, rule_name, rule_text, raw_extracted, "
            "source, validation_status, validation_error, rule_format) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (advisory_id, rule_name, rule_text, raw_extracted,
             source, validation_status, validation_error, rule_format),
        )


def get_detection_rules(
    conn: sqlite3.Connection,
    advisory_id: str,
    format_filter: str | None = None,
) -> list[dict]:
    """Return detection rules for an advisory."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    if format_filter is not None:
        cursor.execute(
            "SELECT * FROM detection_rule "
            "WHERE advisory_id = ? AND rule_format = ?",
            (advisory_id, format_filter),
        )
    else:
        cursor.execute(
            "SELECT * FROM detection_rule WHERE advisory_id = ?",
            (advisory_id,),
        )
    return [dict(row) for row in cursor.fetchall()]


def validate_technique_ids(
    conn: sqlite3.Connection,
    technique_ids: list[str],
) -> set[str]:
    """Return the subset of technique_ids that exist in mitre_technique table."""
    if not technique_ids:
        return set()
    placeholders = ",".join("?" for _ in technique_ids)
    cursor = conn.execute(
        f"SELECT technique_id FROM mitre_technique "
        f"WHERE technique_id IN ({placeholders})",
        technique_ids,
    )
    return {row[0] for row in cursor.fetchall()}


def delete_detection_rules(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Delete all detection rules for an advisory."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM detection_rule WHERE advisory_id = ?",
            (advisory_id,),
        )
    return cursor.rowcount


# -- IOCs ----------------------------------------------------------------------


def bulk_insert_iocs(
    conn: sqlite3.Connection,
    advisory_id: str,
    iocs: list[dict],
) -> None:
    """Batch-insert IOCs for an advisory, ignoring duplicates."""
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO ioc "
            "(advisory_id, type, value, context, "
            "validation_status, source_verified, needs_review) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (advisory_id, ioc["type"], ioc["value"], ioc.get("context"),
                 ioc.get("validation_status", "pending"),
                 ioc.get("source_verified", 0), ioc.get("needs_review", 1))
                for ioc in iocs
            ],
        )


def get_iocs(
    conn: sqlite3.Connection,
    advisory_id: str,
    type_filter: str | None = None,
) -> list[dict]:
    """Return IOCs for an advisory."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    if type_filter is not None:
        cursor.execute(
            "SELECT * FROM ioc WHERE advisory_id = ? AND type = ?",
            (advisory_id, type_filter),
        )
    else:
        cursor.execute(
            "SELECT * FROM ioc WHERE advisory_id = ?",
            (advisory_id,),
        )
    return [dict(row) for row in cursor.fetchall()]


def delete_iocs(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Delete all IOCs for an advisory."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM ioc WHERE advisory_id = ?",
            (advisory_id,),
        )
    return cursor.rowcount


def get_ioc_by_value(
    conn: sqlite3.Connection, ioc_type: str, value: str,
) -> dict | None:
    """Return a single IOC by type and value, or None."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT * FROM ioc WHERE type = ? AND value = ?",
        (ioc_type, value),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def count_ioc_cross_refs(
    conn: sqlite3.Connection, ioc_type: str, value: str,
    exclude_advisory_id: str,
) -> int:
    """Return how many other advisories contain the same IOC."""
    row = conn.execute(
        "SELECT COUNT(DISTINCT advisory_id) FROM ioc "
        "WHERE type = ? AND value = ? AND advisory_id != ?",
        (ioc_type, value, exclude_advisory_id),
    ).fetchone()
    return row[0] if row else 0


# -- Cross-advisory IOC search (WS-10) ----------------------------------------


_IOC_SORT_COLUMNS = frozenset({
    "type", "value", "validation_status", "first_seen", "cross_ref_count",
})


def _build_ioc_filters(
    ioc_type: str | None,
    validation_status: str | None,
    source: str | None,
    q: str | None,
) -> tuple[list[str], list]:
    """Build WHERE clauses and params for cross-advisory IOC queries."""
    clauses: list[str] = []
    params: list = []
    if q is not None:
        clauses.append("i.value = ? COLLATE NOCASE")
        params.append(q)
    if ioc_type is not None:
        parts = [v.strip() for v in ioc_type.split(",")]
        if len(parts) == 1:
            clauses.append("i.type = ?")
            params.append(parts[0])
        else:
            ph = ", ".join("?" for _ in parts)
            clauses.append(f"i.type IN ({ph})")
            params.extend(parts)
    if validation_status is not None:
        parts = [v.strip() for v in validation_status.split(",")]
        if len(parts) == 1:
            clauses.append("i.validation_status = ?")
            params.append(parts[0])
        else:
            ph = ", ".join("?" for _ in parts)
            clauses.append(f"i.validation_status IN ({ph})")
            params.extend(parts)
    if source is not None:
        parts = [v.strip() for v in source.split(",")]
        if len(parts) == 1:
            clauses.append("a.source = ?")
            params.append(parts[0])
        else:
            ph = ", ".join("?" for _ in parts)
            clauses.append(f"a.source IN ({ph})")
            params.extend(parts)
    return clauses, params


def get_iocs_page(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
    ioc_type: str | None = None,
    validation_status: str | None = None,
    source: str | None = None,
    q: str | None = None,
    sort: str = "cross_ref_count",
    sort_dir: str = "desc",
) -> dict:
    """Return paginated cross-advisory IOC listing grouped by (type, value)."""
    clauses, params = _build_ioc_filters(ioc_type, validation_status, source, q)
    where = " AND ".join(clauses) if clauses else "1=1"
    sort_col = sort if sort in _IOC_SORT_COLUMNS else "cross_ref_count"
    direction = "ASC" if sort_dir.upper() == "ASC" else "DESC"

    count_row = conn.execute(
        f"SELECT COUNT(*) FROM ("
        f"SELECT 1 FROM ioc i JOIN advisory a ON a.advisory_id = i.advisory_id "
        f"WHERE {where} GROUP BY i.type, i.value)",
        params,
    ).fetchone()
    total = count_row[0]

    offset = (page - 1) * per_page
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        f"SELECT i.type, i.value, "
        f"MAX(i.validation_status) AS validation_status, "
        f"MAX(i.source_verified) AS source_verified, "
        f"MIN(a.pub_date) AS first_seen, "
        f"MAX(a.pub_date) AS last_seen, "
        f"COUNT(DISTINCT i.advisory_id) AS cross_ref_count, "
        f"GROUP_CONCAT(DISTINCT i.advisory_id) AS advisory_id_list, "
        f"GROUP_CONCAT(DISTINCT CAST(a.id AS TEXT)) AS advisory_numeric_ids "
        f"FROM ioc i JOIN advisory a ON a.advisory_id = i.advisory_id "
        f"WHERE {where} "
        f"GROUP BY i.type, i.value "
        f"ORDER BY {sort_col} {direction} "
        f"LIMIT ? OFFSET ?",
        params + [per_page, offset],
    )
    items = [dict(row) for row in cursor.fetchall()]
    return {"items": items, "total": total, "page": page, "per_page": per_page}


def get_ioc_stats(conn: sqlite3.Connection) -> dict:
    """Return aggregate IOC statistics for the search landing page."""
    total = conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
    by_type: dict[str, int] = {}
    for row in conn.execute(
        "SELECT type, COUNT(*) FROM ioc GROUP BY type"
    ).fetchall():
        by_type[row[0]] = row[1]
    advisories_with_iocs = conn.execute(
        "SELECT COUNT(DISTINCT advisory_id) FROM ioc"
    ).fetchone()[0]
    cross_referenced = conn.execute(
        "SELECT COUNT(*) FROM ("
        "SELECT type, value FROM ioc "
        "GROUP BY type, value HAVING COUNT(DISTINCT advisory_id) >= 2)"
    ).fetchone()[0]
    return {
        "total_iocs": total,
        "by_type": by_type,
        "advisories_with_iocs": advisories_with_iocs,
        "cross_referenced": cross_referenced,
    }


def get_ioc_advisory_details(
    conn: sqlite3.Connection,
    ioc_type: str,
    value: str,
) -> list[dict]:
    """Return advisory details for all advisories containing a specific IOC."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT a.id, a.advisory_id, a.title, a.source, a.pub_date, "
        "i.context, i.validation_status, i.source_verified, i.needs_review "
        "FROM ioc i "
        "JOIN advisory a ON a.advisory_id = i.advisory_id "
        "WHERE i.type = ? AND i.value = ? COLLATE NOCASE "
        "ORDER BY a.pub_date ASC",
        (ioc_type, value),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    for row in rows:
        aid = row["advisory_id"]
        row["actors"] = [
            r[0] for r in conn.execute(
                "SELECT actor_name FROM advisory_actor WHERE advisory_id = ?",
                (aid,),
            ).fetchall()
        ]
        row["malware"] = [
            r[0] for r in conn.execute(
                "SELECT malware_name FROM advisory_malware WHERE advisory_id = ?",
                (aid,),
            ).fetchall()
        ]
    return rows


# -- Advisory Techniques -------------------------------------------------------


def link_advisory_technique(
    conn: sqlite3.Connection,
    advisory_id: str,
    technique_id: str,
    confidence: str,
    framework: str = "attack",
) -> None:
    """Link an advisory to a MITRE technique (idempotent)."""
    with conn:
        # advisory_technique.technique_id FKs mitre_technique. Seed a stub row so
        # the link is usable standalone (mirrors the parse phase save path) instead of
        # failing when the technique catalogue has not been populated yet.
        conn.execute(
            "INSERT OR IGNORE INTO mitre_technique (technique_id) VALUES (?)",
            (technique_id,),
        )
        conn.execute(
            "INSERT OR REPLACE INTO advisory_technique "
            "(advisory_id, technique_id, confidence, framework) "
            "VALUES (?, ?, ?, ?)",
            (advisory_id, technique_id, confidence, framework),
        )


def get_advisory_techniques(
    conn: sqlite3.Connection,
    advisory_id: str,
    framework: str | None = None,
) -> list[dict]:
    """Return techniques linked to an advisory, enriched with name/tactic."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    base = (
        "SELECT at.*, mt.name, mt.tactic "
        "FROM advisory_technique at "
        "LEFT JOIN mitre_technique mt ON mt.technique_id = at.technique_id "
        "WHERE at.advisory_id = ?"
    )
    if framework is not None:
        cursor.execute(base + " AND at.framework = ?", (advisory_id, framework))
    else:
        cursor.execute(base, (advisory_id,))
    return [dict(row) for row in cursor.fetchall()]


def delete_advisory_techniques(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Delete all technique links for an advisory."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM advisory_technique WHERE advisory_id = ?",
            (advisory_id,),
        )
    return cursor.rowcount


# -- Advisory Sectors ----------------------------------------------------------


def link_advisory_sector(
    conn: sqlite3.Connection, advisory_id: str, sector: str,
) -> None:
    """Link an advisory to a sector (idempotent)."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO advisory_sector "
            "(advisory_id, sector) VALUES (?, ?)",
            (advisory_id, sector),
        )


def get_advisory_sectors(
    conn: sqlite3.Connection, advisory_id: str,
) -> list[str]:
    """Return sectors linked to an advisory."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT sector FROM advisory_sector WHERE advisory_id = ?",
        (advisory_id,),
    )
    return [row[0] for row in cursor.fetchall()]


def delete_advisory_sectors(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Delete all sector links for an advisory."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM advisory_sector WHERE advisory_id = ?",
            (advisory_id,),
        )
    return cursor.rowcount


# -- Advisory Assets -----------------------------------------------------------


def upsert_advisory_asset(
    conn: sqlite3.Connection,
    advisory_id: str,
    asset_type: str,
    original_url: str,
    local_path: str | None,
    caption: str | None,
    alt_text: str | None,
    download_status: str,
) -> None:
    """Insert or update an advisory asset."""
    with conn:
        conn.execute(
            "INSERT INTO advisory_asset "
            "(advisory_id, asset_type, original_url, local_path, "
            "caption, alt_text, download_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(advisory_id, original_url) DO UPDATE SET "
            "local_path = excluded.local_path, "
            "caption = excluded.caption, "
            "alt_text = excluded.alt_text, "
            "download_status = excluded.download_status",
            (advisory_id, asset_type, original_url, local_path,
             caption, alt_text, download_status),
        )


def get_advisory_assets(
    conn: sqlite3.Connection,
    advisory_id: str,
    type_filter: str | None = None,
) -> list[dict]:
    """Return assets for an advisory."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    if type_filter is not None:
        cursor.execute(
            "SELECT * FROM advisory_asset "
            "WHERE advisory_id = ? AND asset_type = ?",
            (advisory_id, type_filter),
        )
    else:
        cursor.execute(
            "SELECT * FROM advisory_asset WHERE advisory_id = ?",
            (advisory_id,),
        )
    return [dict(row) for row in cursor.fetchall()]


def delete_advisory_assets(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Delete all assets for an advisory."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM advisory_asset WHERE advisory_id = ?",
            (advisory_id,),
        )
    return cursor.rowcount


def get_pending_assets(
    conn: sqlite3.Connection,
) -> list[tuple[str, str, str]]:
    """Query all assets awaiting download."""
    cursor = conn.execute(
        "SELECT advisory_id, asset_type, original_url "
        "FROM advisory_asset WHERE download_status = 'pending'",
    )
    return cursor.fetchall()


def mark_asset_downloaded(
    conn: sqlite3.Connection, advisory_id: str, original_url: str,
    local_path: str, file_size: int, downloaded_at: str,
) -> None:
    """Record a successful asset download."""
    with conn:
        conn.execute(
            "UPDATE advisory_asset SET download_status = 'completed', "
            "local_path = ?, file_size = ?, downloaded_at = ? "
            "WHERE advisory_id = ? AND original_url = ?",
            (local_path, file_size, downloaded_at, advisory_id, original_url),
        )


def mark_asset_failed(
    conn: sqlite3.Connection, advisory_id: str, original_url: str,
    error: str,
) -> None:
    """Record a failed asset download."""
    with conn:
        conn.execute(
            "UPDATE advisory_asset SET download_status = 'failed', "
            "download_error = ? "
            "WHERE advisory_id = ? AND original_url = ?",
            (error, advisory_id, original_url),
        )


# -- Extraction History --------------------------------------------------------


def record_extraction(
    conn: sqlite3.Connection,
    advisory_id: str,
    phase: str,
    extractor_version: str,
    items_extracted: dict,
) -> None:
    """Record an extraction run for an advisory."""
    with conn:
        conn.execute(
            "INSERT INTO extraction_history "
            "(advisory_id, phase, extracted_json, extracted_at, extraction_model) "
            "VALUES (?, ?, ?, ?, ?)",
            (advisory_id, phase, json.dumps(items_extracted),
             datetime.now(timezone.utc).isoformat(), extractor_version),
        )


def get_extraction_history(
    conn: sqlite3.Connection, advisory_id: str,
) -> list[dict]:
    """Return extraction history for an advisory, newest first."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT * FROM extraction_history "
        "WHERE advisory_id = ? ORDER BY extracted_at DESC",
        (advisory_id,),
    )
    rows = []
    for row in cursor.fetchall():
        d = dict(row)
        if d.get("extracted_json"):
            d["extracted_json"] = json.loads(d["extracted_json"])
        rows.append(d)
    return rows


# -- Extraction Log ------------------------------------------------------------


def insert_extraction_log(
    conn: sqlite3.Connection,
    advisory_id: str,
    phase: str,
    extractor: str,
    severity: str,
    message: str,
    context: str | None = None,
) -> None:
    """Record an extraction log entry."""
    with conn:
        conn.execute(
            "INSERT INTO extraction_log "
            "(advisory_id, phase, extractor, severity, message, context) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (advisory_id, phase, extractor, severity, message, context),
        )


def get_extraction_logs(
    conn: sqlite3.Connection,
    advisory_id: str,
    severity: str | None = None,
) -> list[dict]:
    """Return extraction logs for an advisory."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    if severity is not None:
        cursor.execute(
            "SELECT * FROM extraction_log "
            "WHERE advisory_id = ? AND severity = ? "
            "ORDER BY logged_at, id",
            (advisory_id, severity),
        )
    else:
        cursor.execute(
            "SELECT * FROM extraction_log "
            "WHERE advisory_id = ? ORDER BY logged_at, id",
            (advisory_id,),
        )
    return [dict(row) for row in cursor.fetchall()]


def delete_extraction_logs(
    conn: sqlite3.Connection,
    advisory_id: str,
    phase: str | None = None,
) -> int:
    """Delete extraction logs for an advisory."""
    with conn:
        if phase is not None:
            cursor = conn.execute(
                "DELETE FROM extraction_log "
                "WHERE advisory_id = ? AND phase = ?",
                (advisory_id, phase),
            )
        else:
            cursor = conn.execute(
                "DELETE FROM extraction_log WHERE advisory_id = ?",
                (advisory_id,),
            )
    return cursor.rowcount


def get_advisories_with_extraction_issues(
    conn: sqlite3.Connection,
) -> list[dict]:
    """Return advisories that have extraction warnings or errors."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT DISTINCT advisory_id, "
        "COUNT(*) as issue_count, "
        "SUM(CASE WHEN severity = 'error' THEN 1 ELSE 0 END) as error_count, "
        "SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) as warning_count "
        "FROM extraction_log GROUP BY advisory_id "
        "ORDER BY error_count DESC, warning_count DESC",
    )
    return [dict(row) for row in cursor.fetchall()]


# -- Advisory Actors -----------------------------------------------------------


def link_advisory_actor(
    conn: sqlite3.Connection, advisory_id: str, actor_name: str,
) -> None:
    """Link an advisory to a threat actor (idempotent)."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO advisory_actor "
            "(advisory_id, actor_name) VALUES (?, ?)",
            (advisory_id, actor_name),
        )


def get_advisory_actors(
    conn: sqlite3.Connection, advisory_id: str,
) -> list[str]:
    """Return actor names linked to an advisory."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT actor_name FROM advisory_actor WHERE advisory_id = ?",
        (advisory_id,),
    )
    return [row[0] for row in cursor.fetchall()]


def get_advisory_malware(
    conn: sqlite3.Connection, advisory_id: str,
) -> list[str]:
    """Return malware names linked to an advisory."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT malware_name FROM advisory_malware WHERE advisory_id = ?",
        (advisory_id,),
    )
    return [row[0] for row in cursor.fetchall()]


def get_advisory_behaviors(
    conn: sqlite3.Connection, advisory_id: str,
) -> list[dict]:
    """Return behaviors extracted for an advisory."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT id, advisory_id, description, mitre_technique, "
        "mitre_tactic, confidence FROM behavior WHERE advisory_id = ?",
        (advisory_id,),
    )
    return [dict(row) for row in cursor.fetchall()]


def count_behaviors(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Count behaviors for an advisory."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM behavior WHERE advisory_id = ?",
        (advisory_id,),
    )
    return cursor.fetchone()[0]


def delete_advisory_actors(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Delete all actor links for an advisory."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM advisory_actor WHERE advisory_id = ?",
            (advisory_id,),
        )
    return cursor.rowcount


# -- Threat Actor Aliases ------------------------------------------------------


def upsert_threat_actor_alias(
    conn: sqlite3.Connection,
    alias: str,
    canonical_name: str,
    source: str | None = None,
) -> None:
    """Insert or update a threat actor alias mapping."""
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO threat_actor_alias "
            "(alias, canonical_name, source, added_at) "
            "VALUES (?, ?, ?, ?)",
            (alias, canonical_name, source,
             datetime.now(timezone.utc).isoformat()),
        )


def get_actor_aliases(
    conn: sqlite3.Connection, canonical_name: str,
) -> list[dict]:
    """Return all aliases for a canonical actor name."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    cursor.execute(
        "SELECT * FROM threat_actor_alias WHERE canonical_name = ?",
        (canonical_name,),
    )
    return [dict(row) for row in cursor.fetchall()]


# -- Advisory Malware ----------------------------------------------------------


def link_advisory_malware(
    conn: sqlite3.Connection, advisory_id: str, malware_name: str,
) -> None:
    """Link an advisory to a malware/tool name (idempotent)."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO advisory_malware "
            "(advisory_id, malware_name) VALUES (?, ?)",
            (advisory_id, malware_name),
        )


# -- Advisory CVE (delete) -----------------------------------------------------


def delete_advisory_cves(
    conn: sqlite3.Connection, advisory_id: str,
) -> int:
    """Delete all CVE links for an advisory."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM advisory_cve WHERE advisory_id = ?",
            (advisory_id,),
        )
    return cursor.rowcount


# -- Parse-phase orchestration queue (C2) --------------------------------------


def get_advisories_for_parsing(
    conn: sqlite3.Connection,
    advisory_id: str | None = None,
    include_all: bool = False,
) -> list[dict]:
    """Return advisories ready for parse-phase extraction.

    Rows carry keys: numeric_id (int), advisory_id (str), article_body (str),
    source (str). All variants require a scraped body (article_body IS NOT NULL).

    - advisory_id given: just that advisory, regardless of status (re-extract).
    - advisory_id=None, include_all=False: the poll queue -- extraction_status='pending'.
    - advisory_id=None, include_all=True: cli --all -- every advisory with a body.
    """
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    base = (
        "SELECT id AS numeric_id, advisory_id, article_body, source "
        "FROM advisory WHERE article_body IS NOT NULL"
    )
    if advisory_id is not None:
        cursor.execute(base + " AND advisory_id = ?", (advisory_id,))
    elif include_all:
        cursor.execute(base + " ORDER BY id")
    else:
        cursor.execute(
            base + " AND extraction_status = 'pending' ORDER BY id",
        )
    return [dict(row) for row in cursor.fetchall()]


def mark_parse_failed(
    conn: sqlite3.Connection, advisory_id: str, error: str,
) -> None:
    """Record a parse-phase orchestration failure (crash before save) in one transaction."""
    with conn:
        conn.execute(
            "DELETE FROM extraction_log WHERE advisory_id = ? AND phase = 'parse'",
            (advisory_id,),
        )
        conn.execute(
            "INSERT INTO extraction_log "
            "(advisory_id, phase, extractor, severity, message) "
            "VALUES (?, 'parse', 'orchestrator', 'error', ?)",
            (advisory_id, error),
        )
        conn.execute(
            "UPDATE advisory SET extraction_status = 'parse_failed' "
            "WHERE advisory_id = ?",
            (advisory_id,),
        )
    logger.error("Parse phase failed for %s: %s", advisory_id, error)


# -- Parse-phase Transaction (C.3) ---------------------------------------------


def _delete_prior_parse(conn: sqlite3.Connection, advisory_id: str) -> None:
    """Remove prior parse-phase extracted records for idempotent re-extraction.

    IOC deletion is scoped to extraction_source='parse' so intel-phase IOCs
    survive a parse re-run. Junction tables (advisory_technique, advisory_sector,
    advisory_cve, advisory_actor) are blanket-wiped because the parse phase owns
    all rows and the intel phase re-adds via INSERT OR IGNORE (additive).

    advisory_asset is deliberately NOT deleted here: _insert_parse_assets
    upserts by original_url and preserves download_status/local_path, so an
    already-downloaded figure survives re-extraction instead of being re-fetched.
    Assets whose URL disappears from a changed extraction are left as harmless
    orphans rather than forcing a full re-download of everything.
    """
    conn.execute("DELETE FROM detection_rule WHERE advisory_id = ?", (advisory_id,))
    conn.execute(
        "DELETE FROM ioc WHERE advisory_id = ? AND extraction_source = 'parse'",
        (advisory_id,),
    )
    conn.execute("DELETE FROM advisory_technique WHERE advisory_id = ?", (advisory_id,))
    conn.execute("DELETE FROM advisory_sector WHERE advisory_id = ?", (advisory_id,))
    conn.execute("DELETE FROM advisory_cve WHERE advisory_id = ?", (advisory_id,))
    conn.execute("DELETE FROM advisory_actor WHERE advisory_id = ?", (advisory_id,))


def _delete_prior_intel(conn: sqlite3.Connection, advisory_id: str) -> None:
    """Remove prior intel-phase extracted records for idempotent re-extraction."""
    conn.execute(
        "DELETE FROM ioc WHERE advisory_id = ? AND extraction_source = 'intel'",
        (advisory_id,),
    )
    conn.execute("DELETE FROM behavior WHERE advisory_id = ?", (advisory_id,))


def _insert_parse_rules(
    conn: sqlite3.Connection, advisory_id: str, rules: list[RuleRecord],
) -> None:
    """Insert detection rules within an open transaction."""
    conn.executemany(
        "INSERT OR REPLACE INTO detection_rule "
        "(advisory_id, rule_name, rule_text, raw_extracted, "
        "source, validation_status, validation_error, rule_format) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(advisory_id, r.rule_name, r.rule_text, r.raw_extracted,
          r.source, r.validation_status, r.validation_error, r.rule_format)
         for r in rules],
    )


def _insert_parse_iocs(
    conn: sqlite3.Connection, advisory_id: str, iocs: list[IocRecord],
) -> None:
    """Batch-insert IOCs within an open transaction."""
    conn.executemany(
        "INSERT OR IGNORE INTO ioc "
        "(advisory_id, type, value, context, "
        "validation_status, source_verified, needs_review) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(advisory_id, ioc.type, ioc.value, ioc.context,
          ioc.validation_status, int(ioc.source_verified),
          int(ioc.needs_review))
         for ioc in iocs],
    )


def _insert_parse_techniques(
    conn: sqlite3.Connection,
    advisory_id: str,
    techniques: list[TechniqueRecord],
) -> None:
    """Insert ATT&CK and D3FEND technique links within an open transaction."""
    conn.executemany(
        "INSERT OR IGNORE INTO mitre_technique (technique_id, name, tactic) "
        "VALUES (?, ?, ?)",
        [(t.technique_id, t.name, t.tactic) for t in techniques],
    )
    conn.executemany(
        "INSERT OR REPLACE INTO advisory_technique "
        "(advisory_id, technique_id, confidence, framework, use_description) "
        "VALUES (?, ?, ?, ?, ?)",
        [(advisory_id, t.technique_id, t.confidence, t.framework,
          t.use_description)
         for t in techniques],
    )


def _insert_parse_sectors(
    conn: sqlite3.Connection, advisory_id: str, sectors: list[str],
) -> None:
    """Insert sector links within an open transaction."""
    conn.executemany(
        "INSERT OR IGNORE INTO advisory_sector (advisory_id, sector) "
        "VALUES (?, ?)",
        [(advisory_id, s) for s in sectors],
    )


def _insert_parse_assets(
    conn: sqlite3.Connection, advisory_id: str, assets: list[AssetRecord],
) -> None:
    """Upsert advisory assets within an open transaction.

    ON CONFLICT refreshes only caption/alt_text and leaves download_status and
    local_path untouched, so a figure already downloaded on a prior run keeps its
    'completed' state across re-extraction (see _delete_prior_parse).
    """
    conn.executemany(
        "INSERT INTO advisory_asset "
        "(advisory_id, asset_type, original_url, caption, alt_text, "
        "download_status) VALUES (?, ?, ?, ?, ?, 'pending') "
        "ON CONFLICT(advisory_id, original_url) DO UPDATE SET "
        "caption = excluded.caption, alt_text = excluded.alt_text",
        [(advisory_id, a.asset_type, a.original_url, a.caption, a.alt_text)
         for a in assets],
    )


def _insert_parse_cves(
    conn: sqlite3.Connection, advisory_id: str, cves: list[CveRecord],
) -> None:
    """Link advisory to CVEs within an open transaction, preserving link metadata."""
    conn.executemany(
        "INSERT OR IGNORE INTO advisory_cve "
        "(advisory_id, cve_id, link_url, link_source) VALUES (?, ?, ?, ?)",
        [(advisory_id, cve.cve_id, cve.link_url, cve.link_source) for cve in cves],
    )


def _insert_parse_actors(
    conn: sqlite3.Connection, advisory_id: str, aliases: list[ActorAlias],
) -> None:
    """Link advisory to actors and record alias mappings.

    The parse phase does not resolve canonical names (that is the intel phase,
    per DESIGN.md), so each tracking name is linked once as its own actor.
    INSERT OR IGNORE on the alias table (never OR REPLACE) so an authoritative
    MITRE-seeded mapping (source='mitre_attack') is never clobbered by a parse
    guess; the source is a fixed 'parse' discriminator so a later reseed can
    tell provisional rows apart.
    """
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT OR IGNORE INTO advisory_actor (advisory_id, actor_name) "
        "VALUES (?, ?)",
        [(advisory_id, a.tracking_name) for a in aliases],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO threat_actor_alias "
        "(alias, canonical_name, source, added_at) VALUES (?, ?, 'parse', ?)",
        [(a.tracking_name, a.tracking_name, now) for a in aliases],
    )


def _insert_parse_logs(
    conn: sqlite3.Connection,
    advisory_id: str,
    logs: list[ExtractionLogEntry],
) -> None:
    """Clear and re-insert parse-phase extraction logs."""
    conn.execute(
        "DELETE FROM extraction_log WHERE advisory_id = ? AND phase = ?",
        (advisory_id, "parse"),
    )
    conn.executemany(
        "INSERT INTO extraction_log "
        "(advisory_id, phase, extractor, severity, message, context) "
        "VALUES (?, 'parse', ?, ?, ?, ?)",
        [(advisory_id, l.extractor, l.severity, l.message, l.context)
         for l in logs],
    )


def _compute_extraction_status(logs: list[ExtractionLogEntry]) -> str:
    """Determine extraction status from log entry severities."""
    errors = sum(1 for l in logs if l.severity == "error")
    if errors > 0:
        return "parse_failed"
    warnings = sum(1 for l in logs if l.severity == "warning")
    if warnings > 0:
        return "parse_partial"
    return "parse_done"


def _record_parse_history(
    conn: sqlite3.Connection,
    advisory_id: str,
    result: ParseResult,
    extractor_version: str,
) -> None:
    """Record parse-phase extraction summary in history table."""
    items = {
        "detection_rules": len(result.detection_rules),
        "iocs": len(result.iocs),
        "techniques": len(result.techniques) + len(result.d3fend),
        "sectors": len(result.sectors),
        "assets": len(result.figures) + len(result.assets),
        "cves": len(result.cves),
        "actors": len(result.actor_aliases),
    }
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE extraction_history SET superseded_at = ? "
        "WHERE advisory_id = ? AND phase = ? AND superseded_at IS NULL",
        (now, advisory_id, "parse"),
    )
    conn.execute(
        "INSERT INTO extraction_history "
        "(advisory_id, phase, extracted_json, extracted_at, extraction_model) "
        "VALUES (?, ?, ?, ?, ?)",
        (advisory_id, "parse", json.dumps(items), now, extractor_version),
    )


def save_parse_results(
    conn: sqlite3.Connection,
    advisory_id: str,
    result: ParseResult,
    enriched_body: str,
    extractor_version: str = _PARSE_EXTRACTOR_VERSION,
) -> str:
    """Persist parse-phase extraction and enrichment in a single transaction.

    Only owns the transaction it starts: if the caller already has one open, it
    commits/rolls back nothing and lets the caller decide -- so a wrapping
    transaction is not silently ended here.
    """
    started = not conn.in_transaction
    if started:
        conn.execute("BEGIN")
    try:
        _delete_prior_parse(conn, advisory_id)
        _insert_parse_rules(conn, advisory_id, result.detection_rules)
        _insert_parse_iocs(conn, advisory_id, result.iocs)
        _insert_parse_techniques(
            conn, advisory_id, result.techniques + result.d3fend,
        )
        _insert_parse_sectors(conn, advisory_id, result.sectors)
        _insert_parse_assets(
            conn, advisory_id, result.figures + result.assets,
        )
        _insert_parse_cves(conn, advisory_id, result.cves)
        _insert_parse_actors(conn, advisory_id, result.actor_aliases)
        _insert_parse_logs(conn, advisory_id, result.logs)
        status = _compute_extraction_status(result.logs)
        conn.execute(
            "UPDATE advisory SET enriched_body = ?, extraction_status = ? "
            "WHERE advisory_id = ?",
            (enriched_body, status, advisory_id),
        )
        _record_parse_history(conn, advisory_id, result, extractor_version)
        if started:
            conn.commit()
    except Exception:
        if started:
            conn.rollback()
        logger.error("Parse-phase save failed for %s, rolling back", advisory_id)
        raise
    return status


# -- Intel-phase Transaction ---------------------------------------------------


def _insert_intel_iocs(
    conn: sqlite3.Connection, advisory_id: str, iocs: list[dict],
) -> None:
    """Insert intel-phase IOCs, yielding to parse-phase rows on collision."""
    conn.executemany(
        "INSERT OR IGNORE INTO ioc "
        "(advisory_id, type, value, context, validation_status, "
        "source_verified, needs_review, extraction_source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'intel')",
        [(advisory_id, ioc["type"], ioc["value"], ioc.get("context"),
          ioc.get("validation_status", "pending"),
          int(ioc.get("source_verified", False)),
          int(ioc.get("needs_review", True)))
         for ioc in iocs],
    )


def _insert_intel_behaviors(
    conn: sqlite3.Connection, advisory_id: str, behaviors: list[dict],
) -> None:
    """Insert behaviors within an open transaction."""
    conn.executemany(
        "INSERT OR REPLACE INTO behavior "
        "(advisory_id, description, mitre_technique, mitre_tactic, confidence) "
        "VALUES (?, ?, ?, ?, ?)",
        [(advisory_id, b["description"], b.get("mitre_technique"),
          b.get("mitre_tactic"), b.get("confidence", "llm_extracted"))
         for b in behaviors],
    )


def _insert_intel_techniques(
    conn: sqlite3.Connection,
    advisory_id: str,
    techniques: list[TechniqueRecord],
) -> None:
    """Insert technique links, preserving higher-confidence parse-phase rows."""
    conn.executemany(
        "INSERT OR IGNORE INTO mitre_technique (technique_id, name, tactic) "
        "VALUES (?, ?, ?)",
        [(t.technique_id, t.name, t.tactic) for t in techniques],
    )
    # INSERT OR IGNORE so parse-phase advisory_stated confidence is never
    # downgraded to llm_extracted
    conn.executemany(
        "INSERT OR IGNORE INTO advisory_technique "
        "(advisory_id, technique_id, confidence, framework, use_description) "
        "VALUES (?, ?, ?, ?, ?)",
        [(advisory_id, t.technique_id, t.confidence, t.framework,
          t.use_description)
         for t in techniques],
    )


def _update_advisory_intel(
    conn: sqlite3.Connection, advisory_id: str, extracted_json: str, now: str,
) -> None:
    """Update advisory status and aggregated LLM telemetry from llm_call_log."""
    conn.execute(
        "UPDATE advisory SET "
        "extraction_status = 'completed', "
        "extracted_json = ?, "
        "extracted_at = ?, "
        "input_tokens = (SELECT SUM(input_tokens) FROM llm_call_log "
        "WHERE advisory_id = ? AND phase IN ('intel', 'rulegen')), "
        "output_tokens = (SELECT SUM(output_tokens) FROM llm_call_log "
        "WHERE advisory_id = ? AND phase IN ('intel', 'rulegen')), "
        "llm_cost_usd = (SELECT SUM(cost_usd) FROM llm_call_log "
        "WHERE advisory_id = ? AND phase IN ('intel', 'rulegen')), "
        "llm_latency_ms = (SELECT MAX(latency_ms) FROM llm_call_log "
        "WHERE advisory_id = ? AND phase IN ('intel', 'rulegen')), "
        "extraction_model = (SELECT model FROM llm_call_log "
        "WHERE advisory_id = ? AND phase IN ('intel', 'rulegen') "
        "ORDER BY called_at DESC LIMIT 1) "
        "WHERE advisory_id = ?",
        (extracted_json, now,
         advisory_id, advisory_id, advisory_id, advisory_id, advisory_id,
         advisory_id),
    )


def _record_intel_history(
    conn: sqlite3.Connection, advisory_id: str, extracted_json: str,
    now: str, model: str,
) -> None:
    """Archive intel-phase extraction to history table."""
    conn.execute(
        "UPDATE extraction_history SET superseded_at = ? "
        "WHERE advisory_id = ? AND phase = 'intel' AND superseded_at IS NULL",
        (now, advisory_id),
    )
    conn.execute(
        "INSERT INTO extraction_history "
        "(advisory_id, phase, extracted_json, extracted_at, extraction_model) "
        "VALUES (?, 'intel', ?, ?, ?)",
        (advisory_id, extracted_json, now, model),
    )


def save_intel_results(
    conn: sqlite3.Connection,
    advisory_id: str,
    iocs: list[dict],
    behaviors: list[dict],
    techniques: list[TechniqueRecord],
    actors: list[str],
    malware: list[str],
    sectors: list[str],
    cves: list[str],
    extracted_json: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int,
    reasoning_tokens: int,
    latency_ms: int,
    cost_usd: float,
    prompt_version: str | None = None,
) -> None:
    """Persist intel-phase extraction in a single transaction."""
    now = datetime.now(timezone.utc).isoformat()
    started = not conn.in_transaction
    if started:
        conn.execute("BEGIN")
    try:
        _delete_prior_intel(conn, advisory_id)
        _insert_intel_iocs(conn, advisory_id, iocs)
        _insert_intel_behaviors(conn, advisory_id, behaviors)
        _insert_intel_techniques(conn, advisory_id, techniques)
        conn.executemany(
            "INSERT OR IGNORE INTO advisory_actor "
            "(advisory_id, actor_name) VALUES (?, ?)",
            [(advisory_id, a) for a in actors],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO advisory_malware "
            "(advisory_id, malware_name) VALUES (?, ?)",
            [(advisory_id, m) for m in malware],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO advisory_sector "
            "(advisory_id, sector) VALUES (?, ?)",
            [(advisory_id, s) for s in sectors],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO advisory_cve "
            "(advisory_id, cve_id) VALUES (?, ?)",
            [(advisory_id, c) for c in cves],
        )
        record_llm_call(
            conn, advisory_id, "intel", model, input_tokens, output_tokens,
            cached_tokens, reasoning_tokens, latency_ms, cost_usd,
            prompt_version,
        )
        _update_advisory_intel(conn, advisory_id, extracted_json, now)
        _record_intel_history(conn, advisory_id, extracted_json, now, model)
        if started:
            conn.commit()
    except Exception:
        if started:
            conn.rollback()
        logger.error("Intel-phase save failed for %s, rolling back", advisory_id)
        raise


# -- LLM Telemetry ------------------------------------------------------------


def record_llm_call(
    conn: sqlite3.Connection,
    advisory_id: str,
    phase: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int,
    reasoning_tokens: int,
    latency_ms: int,
    cost_usd: float,
    prompt_version: str | None = None,
) -> None:
    """Record or overwrite an LLM call in the per-phase telemetry log."""
    conn.execute(
        "INSERT OR REPLACE INTO llm_call_log "
        "(advisory_id, phase, model, input_tokens, output_tokens, "
        "cached_tokens, reasoning_tokens, latency_ms, cost_usd, prompt_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (advisory_id, phase, model, input_tokens, output_tokens,
         cached_tokens, reasoning_tokens, latency_ms, cost_usd, prompt_version),
    )


def resolve_actor_alias(conn: sqlite3.Connection, alias: str) -> str:
    """Return the canonical name for a threat actor alias, or the alias itself."""
    row = conn.execute(
        "SELECT canonical_name FROM threat_actor_alias WHERE alias = ?",
        (alias,),
    ).fetchone()
    return row[0] if row else alias


def get_llm_stats(conn: sqlite3.Connection) -> dict:
    """Aggregate LLM telemetry for dashboard stats."""
    row = conn.execute(
        "SELECT COUNT(*) as call_count, "
        "COALESCE(SUM(cost_usd), 0) as total_cost, "
        "COALESCE(SUM(input_tokens), 0) as total_input_tokens, "
        "COALESCE(SUM(output_tokens), 0) as total_output_tokens "
        "FROM llm_call_log"
    ).fetchone()
    advisory_count = conn.execute(
        "SELECT COUNT(DISTINCT advisory_id) FROM llm_call_log"
    ).fetchone()[0]
    phase_rows = conn.execute(
        "SELECT phase, COUNT(*) FROM llm_call_log GROUP BY phase"
    ).fetchall()
    return {
        "call_count": row[0],
        "total_cost": round(row[1], 6),
        "total_input_tokens": row[2],
        "total_output_tokens": row[3],
        "avg_cost_per_advisory": round(row[1] / advisory_count, 6) if advisory_count else 0.0,
        "calls_by_phase": {r[0]: r[1] for r in phase_rows},
    }


# -- Intel-phase helpers -------------------------------------------------------


def get_advisories_for_intel(
    conn: sqlite3.Connection,
    advisory_id: str | None = None,
) -> list[dict]:
    """Return advisories ready for intel-phase extraction.

    Returns rows with: advisory_id, article_body, source, extraction_status.
    - advisory_id given: just that advisory (for re-extraction).
    - advisory_id=None: poll queue -- extraction_status IN ('parse_done',
      'parse_partial') AND retry_count < 3.
    """
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    base = (
        "SELECT advisory_id, article_body, source, extraction_status "
        "FROM advisory WHERE article_body IS NOT NULL"
    )
    if advisory_id is not None:
        cursor.execute(base + " AND advisory_id = ?", (advisory_id,))
    else:
        cursor.execute(
            base + " AND extraction_status IN ('parse_done', 'parse_partial') "
            "AND retry_count < 3 ORDER BY id",
        )
    return [dict(row) for row in cursor.fetchall()]


def mark_intel_failed(
    conn: sqlite3.Connection, advisory_id: str, error: str,
) -> None:
    """Record intel-phase failure without changing extraction_status."""
    with conn:
        conn.execute(
            "DELETE FROM extraction_log WHERE advisory_id = ? AND phase = 'intel'",
            (advisory_id,),
        )
        conn.execute(
            "INSERT INTO extraction_log "
            "(advisory_id, phase, extractor, severity, message) "
            "VALUES (?, 'intel', 'orchestrator', 'error', ?)",
            (advisory_id, error),
        )
        conn.execute(
            "UPDATE advisory SET retry_count = retry_count + 1, "
            "extraction_error = ? WHERE advisory_id = ?",
            (error, advisory_id),
        )
    logger.warning("Intel phase failed for %s: %s", advisory_id, error)
