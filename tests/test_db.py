"""Tests for threat2signal.db schema initialization."""

import os
import sqlite3
import tempfile

import pytest

from threat2signal.storage.db import (
    get_connection, init_schema,
    upsert_advisory, get_pending_scrape, record_cisa_poll, count_by_scrape_status,
)

EXPECTED_TABLES = frozenset({
    "advisory",
    "advisory_analysis",
    "ioc",
    "yara_rule",
    "advisory_asset",
    "behavior",
    "advisory_cve",
    "advisory_actor",
    "threat_actor_alias",
    "advisory_malware",
    "advisory_sector",
    "mitre_technique",
    "advisory_technique",
    "detection_rule",
    "extraction_history",
    "msrc_cve",
    "msrc_kb",
    "msrc_poll_history",
    "cisa_poll_history",
    "kev_entry",
    "extraction_log",
    "llm_call_log",
})

EXPECTED_INDEXES = frozenset({
    "idx_advisory_type",
    "idx_advisory_pub_date",
    "idx_advisory_status",
    "idx_advisory_scrape_status",
    "idx_advisory_source",
    "idx_asset_advisory",
    "idx_asset_type",
    "idx_ioc_type_value",
    "idx_ioc_advisory",
    "idx_ioc_validation",
    "idx_ioc_value",
    "idx_behavior_technique",
    "idx_advisory_cve_cve",
    "idx_advisory_actor",
    "idx_actor_alias_canonical",
    "idx_extraction_history_advisory",
    "idx_advisory_technique_tech",
    "idx_analysis_advisory",
    "idx_msrc_cve_component",
    "idx_msrc_cve_priority",
    "idx_msrc_cve_score",
    "idx_msrc_cve_released",
    "idx_msrc_cve_exploited",
    "idx_msrc_cve_vr_priority",
    "idx_msrc_cve_vr_score",
    "idx_msrc_kb_cve",
    "idx_kev_date_added",
    "idx_extraction_log_advisory",
    "idx_detection_rule_advisory",
    "idx_advisory_triage",
    "idx_detection_rule_uniq",
})


@pytest.mark.unit
def test_init_schema_creates_all_tables(db_conn):
    rows = db_conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    table_names = {row[0] for row in rows}

    assert len(table_names) == 22
    assert table_names == EXPECTED_TABLES


@pytest.mark.unit
def test_init_schema_creates_all_indexes(db_conn):
    rows = db_conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
    ).fetchall()
    index_names = {row[0] for row in rows}

    assert len(index_names) == 31
    assert index_names == EXPECTED_INDEXES


@pytest.mark.unit
def test_init_schema_idempotent(db_conn):
    init_schema(db_conn)

    rows = db_conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    assert len(rows) == 22


@pytest.mark.unit
def test_foreign_keys_enforced(db_conn):
    fk_status = db_conn.execute("PRAGMA foreign_keys").fetchone()[0]
    assert fk_status == 1

    with pytest.raises(sqlite3.IntegrityError):
        db_conn.execute(
            "INSERT INTO ioc (advisory_id, type, value) VALUES (?, ?, ?)",
            ("nonexistent-advisory-id", "domain", "evil.example.com"),
        )


@pytest.mark.unit
def test_wal_mode(tmp_path):
    db_file = str(tmp_path / "test_wal.db")
    conn = get_connection(db_file)
    try:
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert journal_mode == "wal"
    finally:
        conn.close()
        for suffix in ("", "-wal", "-shm"):
            path = db_file + suffix
            if os.path.exists(path):
                os.remove(path)


@pytest.mark.unit
def test_unique_constraints(db_conn):
    db_conn.execute(
        "INSERT INTO advisory (advisory_id, type, source) VALUES (?, ?, ?)",
        ("aa25-001a", "cybersecurity_advisory", "cisa"),
    )
    db_conn.execute(
        "INSERT INTO ioc (advisory_id, type, value) VALUES (?, ?, ?)",
        ("aa25-001a", "domain", "malware.example.com"),
    )

    with pytest.raises(sqlite3.IntegrityError):
        db_conn.execute(
            "INSERT INTO ioc (advisory_id, type, value) VALUES (?, ?, ?)",
            ("aa25-001a", "domain", "malware.example.com"),
        )


# -- WS-2 data-access function tests ------------------------------------------


@pytest.mark.unit
def test_upsert_advisory_insert(db_conn):
    upsert_advisory(db_conn, {
        "advisory_id": "aa25-001a",
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "link": "https://example.com/aa25-001a",
        "scrape_status": "pending",
        "first_seen": "2026-01-01T00:00:00+00:00",
    })

    row = db_conn.execute(
        "SELECT advisory_id, type, source, link, scrape_status, first_seen "
        "FROM advisory WHERE advisory_id = ?",
        ("aa25-001a",),
    ).fetchone()

    assert row is not None
    assert row[0] == "aa25-001a"
    assert row[1] == "cybersecurity_advisory"
    assert row[2] == "cisa"
    assert row[3] == "https://example.com/aa25-001a"
    assert row[4] == "pending"
    assert row[5] == "2026-01-01T00:00:00+00:00"


@pytest.mark.unit
def test_upsert_advisory_update(db_conn):
    upsert_advisory(db_conn, {
        "advisory_id": "aa25-001a",
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "link": "https://example.com/aa25-001a",
        "scrape_status": "pending",
    })

    upsert_advisory(db_conn, {
        "advisory_id": "aa25-001a",
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "scrape_status": "scraped",
        "raw_html": "<html>test</html>",
    })

    row = db_conn.execute(
        "SELECT scrape_status, raw_html, link FROM advisory WHERE advisory_id = ?",
        ("aa25-001a",),
    ).fetchone()

    assert row is not None
    assert row[0] == "scraped"
    assert row[1] == "<html>test</html>"
    assert row[2] == "https://example.com/aa25-001a"


@pytest.mark.unit
def test_get_pending_scrape(db_conn):
    advisories = [
        ("aa26-001a", "2026-01-01T00:00:00"),
        ("aa26-050a", "2026-02-19T00:00:00"),
        ("aa26-100a", "2026-04-10T00:00:00"),
        ("aa26-150a", "2026-05-30T00:00:00"),
        ("aa26-200a", "2026-07-19T00:00:00"),
    ]
    for aid, lastmod in advisories:
        upsert_advisory(db_conn, {
            "advisory_id": aid,
            "type": "cybersecurity_advisory",
            "source": "cisa",
            "scrape_status": "pending",
            "sitemap_lastmod": lastmod,
        })

    results = get_pending_scrape(db_conn, batch_size=3)

    assert len(results) == 3
    assert results[0]["advisory_id"] == "aa26-200a"
    assert results[1]["advisory_id"] == "aa26-150a"
    assert results[2]["advisory_id"] == "aa26-100a"


@pytest.mark.unit
def test_record_cisa_poll(db_conn):
    record_cisa_poll(
        db_conn,
        polled_at="2026-08-20T06:00:00+00:00",
        source="sitemap",
        aa_total=176,
        ar_total=134,
        new_advisories=3,
        updated=1,
        errors=None,
    )

    row = db_conn.execute(
        "SELECT polled_at, source, aa_total, ar_total, "
        "new_advisories, updated, errors FROM cisa_poll_history"
    ).fetchone()

    assert row is not None
    assert row[0] == "2026-08-20T06:00:00+00:00"
    assert row[1] == "sitemap"
    assert row[2] == 176
    assert row[3] == 134
    assert row[4] == 3
    assert row[5] == 1
    assert row[6] is None


@pytest.mark.unit
def test_count_by_scrape_status(db_conn):
    # 3 pending from cisa
    for i in range(3):
        upsert_advisory(db_conn, {
            "advisory_id": f"pending-cisa-{i}",
            "type": "cybersecurity_advisory",
            "source": "cisa",
            "scrape_status": "pending",
        })
    # 2 scraped from cisa
    for i in range(2):
        upsert_advisory(db_conn, {
            "advisory_id": f"scraped-cisa-{i}",
            "type": "cybersecurity_advisory",
            "source": "cisa",
            "scrape_status": "scraped",
        })
    # 1 cf_challenged from cisa
    upsert_advisory(db_conn, {
        "advisory_id": "cf-challenged-cisa-0",
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "scrape_status": "cf_challenged",
    })
    # 1 pending from manual -- should be excluded
    upsert_advisory(db_conn, {
        "advisory_id": "pending-manual-0",
        "type": "cybersecurity_advisory",
        "source": "manual",
        "scrape_status": "pending",
    })

    counts = count_by_scrape_status(db_conn, source="cisa")

    assert counts == {"pending": 3, "scraped": 2, "cf_challenged": 1}
    # Verify manual-source advisory is not counted
    total = sum(counts.values())
    assert total == 6
