"""Tests for API filter infrastructure and new WS-7 endpoints (smoke-level)."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from threat2signal.analysis.extractor import (
    CveRecord,
    ExtractionLogEntry,
    IocRecord,
    ParseResult,
    RuleRecord,
    TechniqueRecord,
)
from threat2signal.api import (
    _expand_filter_aliases,
    _EXTRACTION_GROUPS,
    _stix_pattern_for_ioc,
    app,
)
from threat2signal.storage.db import (
    _apply_multi_value_filter,
    _build_advisory_filters,
    get_advisories_page,
    init_schema,
    save_parse_results,
    upsert_advisory,
)


# -- _expand_filter_aliases ----------------------------------------------------


# Canonical group vocabulary (CONTRACTS C5 / DESIGN F.13):
#   ready      -> completed
#   processing -> pending, parse_done
#   issues     -> parse_partial, parse_failed, failed
#   skipped    -> skipped


@pytest.mark.unit
def test_expand_filter_aliases_issues_group():
    result = _expand_filter_aliases("issues", _EXTRACTION_GROUPS)
    assert result == "parse_partial,parse_failed,failed"


@pytest.mark.unit
def test_expand_filter_aliases_ready_group():
    result = _expand_filter_aliases("ready", _EXTRACTION_GROUPS)
    assert result == "completed"


@pytest.mark.unit
def test_expand_filter_aliases_processing_group():
    result = _expand_filter_aliases("processing", _EXTRACTION_GROUPS)
    assert result == "pending,parse_done"


@pytest.mark.unit
def test_expand_filter_aliases_skipped_group():
    result = _expand_filter_aliases("skipped", _EXTRACTION_GROUPS)
    assert result == "skipped"


@pytest.mark.unit
def test_expand_filter_aliases_raw_value_passes_through():
    result = _expand_filter_aliases("pending", _EXTRACTION_GROUPS)
    assert result == "pending"


@pytest.mark.unit
def test_expand_filter_aliases_mixed_group_and_raw():
    result = _expand_filter_aliases("issues,pending", _EXTRACTION_GROUPS)
    assert result == "parse_partial,parse_failed,failed,pending"


@pytest.mark.unit
def test_expand_filter_aliases_unknown_group_passes_through():
    # Unknown group names are passed through as literals; they match zero rows
    # rather than raising an error.
    result = _expand_filter_aliases("nonexistent_status", _EXTRACTION_GROUPS)
    assert result == "nonexistent_status"


@pytest.mark.unit
def test_expand_filter_aliases_none_returns_none():
    result = _expand_filter_aliases(None, _EXTRACTION_GROUPS)
    assert result is None


@pytest.mark.unit
def test_expand_filter_aliases_empty_string():
    result = _expand_filter_aliases("", _EXTRACTION_GROUPS)
    assert result == ""


@pytest.mark.unit
def test_expand_filter_aliases_multiple_groups():
    result = _expand_filter_aliases(
        "issues,ready", _EXTRACTION_GROUPS,
    )
    assert result == "parse_partial,parse_failed,failed,completed"


# -- _apply_multi_value_filter -------------------------------------------------


@pytest.mark.unit
def test_apply_multi_value_single():
    clauses: list[str] = []
    params: list = []
    _apply_multi_value_filter("source", "cisa", clauses, params)
    assert clauses == ["source = ?"]
    assert params == ["cisa"]


@pytest.mark.unit
def test_apply_multi_value_csv():
    clauses: list[str] = []
    params: list = []
    _apply_multi_value_filter("source", "cisa,acsc", clauses, params)
    assert clauses == ["source IN (?, ?)"]
    assert params == ["cisa", "acsc"]


@pytest.mark.unit
def test_apply_multi_value_three_values():
    clauses: list[str] = []
    params: list = []
    _apply_multi_value_filter(
        "extraction_status", "pending,failed,completed", clauses, params,
    )
    assert clauses == ["extraction_status IN (?, ?, ?)"]
    assert params == ["pending", "failed", "completed"]


@pytest.mark.unit
def test_apply_multi_value_strips_whitespace():
    clauses: list[str] = []
    params: list = []
    _apply_multi_value_filter("source", " cisa , acsc ", clauses, params)
    assert params == ["cisa", "acsc"]


@pytest.mark.unit
def test_apply_multi_value_appends_to_existing():
    clauses = ["scrape_status = ?"]
    params = ["scraped"]
    _apply_multi_value_filter("source", "cisa", clauses, params)
    assert len(clauses) == 2
    assert params == ["scraped", "cisa"]


# -- _build_advisory_filters ---------------------------------------------------


@pytest.mark.unit
def test_build_filters_single_source():
    where, params = _build_advisory_filters(
        source="cisa", advisory_type=None, extraction_status=None,
        triage_status=None, date_from=None, date_to=None,
        search=None, scrape_status=None,
    )
    assert "source = ?" in where
    assert params == ["cisa"]


@pytest.mark.unit
def test_build_filters_multi_value_source():
    where, params = _build_advisory_filters(
        source="cisa,acsc", advisory_type=None, extraction_status=None,
        triage_status=None, date_from=None, date_to=None,
        search=None, scrape_status=None,
    )
    assert "source IN (?, ?)" in where
    assert "cisa" in params
    assert "acsc" in params


@pytest.mark.unit
def test_build_filters_none_values_produce_no_clause():
    where, params = _build_advisory_filters(
        source=None, advisory_type=None, extraction_status=None,
        triage_status=None, date_from=None, date_to=None,
        search=None, scrape_status=None,
    )
    assert where == "1=1"
    assert params == []


@pytest.mark.unit
def test_build_filters_default_scrape_status():
    where, params = _build_advisory_filters(
        source=None, advisory_type=None, extraction_status=None,
        triage_status=None, date_from=None, date_to=None,
        search=None,
    )
    assert "scrape_status = ?" in where
    assert "scraped" in params


@pytest.mark.unit
def test_build_filters_all_columns():
    where, params = _build_advisory_filters(
        source="cisa", advisory_type="cybersecurity_advisory",
        extraction_status="pending", triage_status="unread",
        date_from=None, date_to=None, search=None, scrape_status=None,
    )
    assert "source = ?" in where
    assert "type = ?" in where
    assert "extraction_status = ?" in where
    assert "triage_status = ?" in where
    assert params == ["cisa", "cybersecurity_advisory", "pending", "unread"]


@pytest.mark.unit
def test_build_filters_combined_with_dates():
    where, params = _build_advisory_filters(
        source="cisa", advisory_type=None, extraction_status=None,
        triage_status=None, date_from="2026-01-01", date_to="2026-12-31",
        search=None, scrape_status=None,
    )
    assert "source = ?" in where
    assert "pub_date >= ?" in where
    assert "pub_date <= ?" in where
    assert params == ["cisa", "2026-01-01", "2026-12-31"]


@pytest.mark.unit
def test_build_filters_search():
    where, params = _build_advisory_filters(
        source=None, advisory_type=None, extraction_status=None,
        triage_status=None, date_from=None, date_to=None,
        search="apt28", scrape_status=None,
    )
    assert "title LIKE ?" in where
    assert "advisory_id LIKE ?" in where
    assert params == ["%apt28%", "%apt28%"]


@pytest.mark.unit
def test_build_filters_multi_value_extraction_status():
    where, params = _build_advisory_filters(
        source=None, advisory_type=None,
        extraction_status="parse_partial,parse_failed,failed",
        triage_status=None, date_from=None, date_to=None,
        search=None, scrape_status=None,
    )
    assert "extraction_status IN (?, ?, ?)" in where
    assert params == ["parse_partial", "parse_failed", "failed"]


# -- Integration: real DB queries ----------------------------------------------


def _seed_advisories(conn: sqlite3.Connection) -> None:
    """Insert a set of test advisories with varied statuses."""
    rows = [
        ("adv-cisa-1", "cybersecurity_advisory", "cisa",
         "pending", "scraped", "unread", "2026-03-01"),
        ("adv-cisa-2", "alert", "cisa",
         "parse_done", "scraped", "reviewed", "2026-04-01"),
        ("adv-cisa-3", "cybersecurity_advisory", "cisa",
         "parse_partial", "scraped", "unread", "2026-05-01"),
        ("adv-acsc-1", "cybersecurity_advisory", "acsc",
         "pending", "scraped", "unread", "2026-03-15"),
        ("adv-acsc-2", "alert", "acsc",
         "completed", "scraped", "flagged", "2026-06-01"),
        ("adv-jpcert-1", "cybersecurity_advisory", "jpcert",
         "failed", "scraped", "unread", "2026-07-01"),
        ("adv-pending-scrape", "cybersecurity_advisory", "cisa",
         "pending", "pending", "unread", "2026-08-01"),
    ]
    for (aid, atype, source, ext_status, scrape, triage, pub) in rows:
        upsert_advisory(conn, {
            "advisory_id": aid,
            "type": atype,
            "source": source,
            "extraction_status": ext_status,
            "scrape_status": scrape,
            "triage_status": triage,
            "pub_date": pub,
        })


@pytest.mark.unit
def test_get_advisories_page_filter_by_source(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn, source="cisa")
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-cisa-1", "adv-cisa-2", "adv-cisa-3"}


@pytest.mark.unit
def test_get_advisories_page_multi_source(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn, source="cisa,acsc")
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-cisa-1", "adv-cisa-2", "adv-cisa-3",
                   "adv-acsc-1", "adv-acsc-2"}


@pytest.mark.unit
def test_get_advisories_page_filter_by_extraction_status(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn, extraction_status="pending")
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-cisa-1", "adv-acsc-1"}


@pytest.mark.unit
def test_get_advisories_page_multi_extraction_status(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(
        db_conn, extraction_status="parse_partial,failed",
    )
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-cisa-3", "adv-jpcert-1"}


@pytest.mark.unit
def test_get_advisories_page_filter_by_triage(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn, triage_status="flagged")
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-acsc-2"}


@pytest.mark.unit
def test_get_advisories_page_filter_by_type(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn, advisory_type="alert")
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-cisa-2", "adv-acsc-2"}


@pytest.mark.unit
def test_get_advisories_page_combined_filters(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(
        db_conn, source="cisa", extraction_status="pending",
    )
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-cisa-1"}


@pytest.mark.unit
def test_get_advisories_page_default_excludes_unscraped(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn)
    ids = {item["advisory_id"] for item in result["items"]}
    assert "adv-pending-scrape" not in ids


@pytest.mark.unit
def test_get_advisories_page_no_scrape_filter_includes_all(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn, scrape_status=None)
    ids = {item["advisory_id"] for item in result["items"]}
    assert "adv-pending-scrape" in ids
    assert len(ids) == 7


@pytest.mark.unit
def test_get_advisories_page_total_reflects_filters(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(db_conn, source="acsc")
    assert result["total"] == 2
    assert len(result["items"]) == 2


@pytest.mark.unit
def test_get_advisories_page_pagination(db_conn):
    _seed_advisories(db_conn)
    page1 = get_advisories_page(db_conn, per_page=2, page=1)
    page2 = get_advisories_page(db_conn, per_page=2, page=2)
    assert len(page1["items"]) == 2
    assert len(page2["items"]) == 2
    ids1 = {item["advisory_id"] for item in page1["items"]}
    ids2 = {item["advisory_id"] for item in page2["items"]}
    assert ids1.isdisjoint(ids2)


@pytest.mark.unit
def test_expanded_issues_alias_real_db(db_conn):
    """End-to-end: expand 'issues' alias, then query the DB with it."""
    _seed_advisories(db_conn)
    expanded = _expand_filter_aliases("issues", _EXTRACTION_GROUPS)
    result = get_advisories_page(db_conn, extraction_status=expanded)
    ids = {item["advisory_id"] for item in result["items"]}
    # parse_partial (adv-cisa-3) + failed (adv-jpcert-1)
    assert ids == {"adv-cisa-3", "adv-jpcert-1"}


@pytest.mark.unit
def test_expanded_ready_alias_real_db(db_conn):
    _seed_advisories(db_conn)
    expanded = _expand_filter_aliases("ready", _EXTRACTION_GROUPS)
    result = get_advisories_page(db_conn, extraction_status=expanded)
    ids = {item["advisory_id"] for item in result["items"]}
    # ready -> completed (adv-acsc-2 only)
    assert ids == {"adv-acsc-2"}


@pytest.mark.unit
def test_expanded_processing_alias_real_db(db_conn):
    _seed_advisories(db_conn)
    expanded = _expand_filter_aliases("processing", _EXTRACTION_GROUPS)
    result = get_advisories_page(db_conn, extraction_status=expanded)
    ids = {item["advisory_id"] for item in result["items"]}
    # processing -> pending (adv-cisa-1, adv-acsc-1; adv-pending-scrape excluded
    # by default scraped filter) + parse_done (adv-cisa-2)
    assert ids == {"adv-cisa-1", "adv-acsc-1", "adv-cisa-2"}


@pytest.mark.unit
def test_unknown_group_matches_zero_rows_real_db(db_conn):
    """An unknown group name is a literal that matches no rows, not an error."""
    _seed_advisories(db_conn)
    expanded = _expand_filter_aliases("bogus_group", _EXTRACTION_GROUPS)
    result = get_advisories_page(db_conn, extraction_status=expanded)
    assert result["total"] == 0
    assert result["items"] == []


@pytest.mark.unit
def test_parameterized_query_prevents_injection(db_conn):
    """IN-clause parameters must not allow SQL injection."""
    _seed_advisories(db_conn)
    malicious = "cisa' OR '1'='1"
    result = get_advisories_page(db_conn, source=malicious)
    assert result["total"] == 0
    assert result["items"] == []


@pytest.mark.unit
def test_date_range_filter_real_db(db_conn):
    _seed_advisories(db_conn)
    result = get_advisories_page(
        db_conn, date_from="2026-05-01", date_to="2026-07-01",
    )
    ids = {item["advisory_id"] for item in result["items"]}
    assert ids == {"adv-cisa-3", "adv-acsc-2", "adv-jpcert-1"}


# -- FastAPI endpoint smoke tests (TestClient) ---------------------------------
#
# The TestClient is used WITHOUT its context manager so the app lifespan (which
# opens the production DB and an httpx proxy client) never runs; app.state is
# wired to an in-memory connection instead.


@pytest.fixture
def api_client():
    """TestClient backed by an in-memory DB seeded with one enriched advisory.

    A dedicated connection with check_same_thread=False is used because the
    TestClient dispatches the async endpoints on an anyio worker thread, while
    seeding happens on the test's main thread -- the same connection object must
    be usable from both.
    """
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)

    upsert_advisory(conn, {
        "advisory_id": "aa25-smoke",
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "scrape_status": "scraped",
        "title": "Smoke Test Advisory",
        "pub_date": "2026-08-01",
    })
    numeric_id = conn.execute(
        "SELECT id FROM advisory WHERE advisory_id = ?", ("aa25-smoke",),
    ).fetchone()[0]

    result = ParseResult(
        iocs=[
            IocRecord(
                type="sha256",
                value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                context="Dropper",
                validation_status="verified",
                source_verified=True,
                needs_review=True,
            ),
            IocRecord(
                type="domain", value="evil.example.com", context="C2",
                validation_status="verified", source_verified=True,
                needs_review=False,
            ),
        ],
        detection_rules=[
            RuleRecord(
                rule_name="smoke_rule",
                rule_text="rule smoke_rule { condition: true }",
                raw_extracted=None, source="html_parsed", rule_format="yara",
                validation_status="valid", validation_error=None,
            ),
        ],
        techniques=[
            TechniqueRecord(
                technique_id="T1566", tactic="Initial Access", name="Phishing",
                use_description="Spearphishing", confidence="advisory_stated",
                framework="attack", version=None,
            ),
        ],
        cves=[
            CveRecord(cve_id="CVE-2025-1234", link_url=None, link_source="none"),
        ],
        logs=[
            ExtractionLogEntry("iocs", "warning", "unmapped table", "table_2"),
        ],
    )
    save_parse_results(conn, "aa25-smoke", result, "<p>enriched</p>")

    app.state.db_conn = conn
    client = TestClient(app)
    try:
        yield client, numeric_id
    finally:
        conn.close()


@pytest.mark.integration
def test_endpoint_iocs_smoke(api_client):
    client, num = api_client
    resp = client.get(f"/api/advisories/{num}/iocs")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 2
    ioc = body[0]
    for key in ("type", "value", "validation_status", "cross_ref_count"):
        assert key in ioc


@pytest.mark.integration
def test_endpoint_iocs_type_filter(api_client):
    client, num = api_client
    resp = client.get(f"/api/advisories/{num}/iocs", params={"type": "domain"})
    assert resp.status_code == 200
    body = resp.json()
    assert {i["type"] for i in body} == {"domain"}


@pytest.mark.integration
def test_endpoint_detection_rules_smoke(api_client):
    client, num = api_client
    resp = client.get(f"/api/advisories/{num}/detection-rules")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["rule_name"] == "smoke_rule"
    assert body[0]["rule_format"] == "yara"


@pytest.mark.integration
def test_endpoint_detection_rules_unknown_format_empty(api_client):
    client, num = api_client
    # Open-ended filter vocabulary: unknown format is an empty list, not a 422.
    resp = client.get(
        f"/api/advisories/{num}/detection-rules", params={"format": "kql"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.integration
def test_endpoint_techniques_smoke(api_client):
    client, num = api_client
    resp = client.get(f"/api/advisories/{num}/techniques")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["technique_id"] == "T1566"


@pytest.mark.integration
def test_endpoint_extraction_logs_smoke(api_client):
    client, num = api_client
    resp = client.get(f"/api/advisories/{num}/extraction-logs")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["severity"] == "warning"
    assert body[0]["extractor"] == "iocs"


@pytest.mark.integration
def test_endpoint_extraction_logs_severity_filter(api_client):
    client, num = api_client
    resp = client.get(
        f"/api/advisories/{num}/extraction-logs", params={"severity": "error"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.integration
def test_endpoint_advisory_detail_smoke(api_client):
    """Advisory detail surfaces enriched_body and per-type counts."""
    client, num = api_client
    resp = client.get(f"/api/advisories/{num}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["advisory_id"] == "aa25-smoke"
    # enriched_body surfaced for the article reader
    assert body.get("enriched_body") == "<p>enriched</p>"
    # raw_html is never leaked in the detail response
    assert "raw_html" not in body
    assert body["ioc_count"] == 2
    assert body["cve_count"] == 1
    assert body["extraction_issues"]["warning_count"] == 1


@pytest.mark.integration
def test_endpoint_cves_routing_shape(api_client):
    """The /cves endpoint returns link_source + is_msrc for MSRC-vs-NVD routing (F.12)."""
    client, num = api_client
    resp = client.get(f"/api/advisories/{num}/cves")
    assert resp.status_code == 200
    cves = resp.json()
    assert any(c["cve_id"] == "CVE-2025-1234" for c in cves)
    cve = next(c for c in cves if c["cve_id"] == "CVE-2025-1234")
    # LEFT JOIN: not in msrc_cve, so is_msrc is False -> frontend routes to NVD
    assert cve["is_msrc"] is False
    assert "link_source" in cve


@pytest.mark.integration
def test_endpoint_unknown_advisory_404(api_client):
    client, _ = api_client
    resp = client.get("/api/advisories/999999/iocs")
    assert resp.status_code == 404


# -- _stix_pattern_for_ioc (WS-8 B.3: filepath + mutex SCO mappings) -----------


@pytest.mark.unit
def test_stix_pattern_for_ioc_filepath():
    result = _stix_pattern_for_ioc("filepath", "/lib/libdsupgrade.so")
    assert result == "[file:name = '/lib/libdsupgrade.so']"


@pytest.mark.unit
def test_stix_pattern_for_ioc_filepath_escapes_backslashes():
    result = _stix_pattern_for_ioc("filepath", "C:\\Windows\\System32\\cmd.exe")
    assert result == "[file:name = 'C:\\\\Windows\\\\System32\\\\cmd.exe']"


@pytest.mark.unit
def test_stix_pattern_for_ioc_mutex():
    result = _stix_pattern_for_ioc("mutex", "K31610KIO9834PG79A90B")
    assert result == "[mutex:name = 'K31610KIO9834PG79A90B']"


@pytest.mark.unit
def test_stix_pattern_for_ioc_domain_still_works():
    result = _stix_pattern_for_ioc("domain", "evil.com")
    assert result == "[domain-name:value = 'evil.com']"
