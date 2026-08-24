"""Tests for threat2signal.ingest.acsc_client module."""

import logging
from pathlib import Path

import pytest
import httpx

from threat2signal.ingest.acsc_client import (
    _parse_rss_feed,
    _parse_severity,
    extract_article_body,
    detect_akamai_block,
    seed_backfill,
    scrape_advisory,
)
from threat2signal.ingest.models import AcscEntry
from threat2signal.storage import db


# -- Helpers -----------------------------------------------------------------


def _mock_request(url="https://www.cyber.gov.au/test"):
    """Minimal httpx.Request to satisfy mock Response construction."""
    return httpx.Request("GET", url)


def _long_text(min_chars=600):
    """Realistic advisory paragraph that exceeds extraction thresholds."""
    sentence = (
        "This advisory provides guidance on threat activity observed "
        "targeting Australian critical infrastructure organisations. "
        "Entities are encouraged to review indicators and apply "
        "recommended mitigations to reduce exposure to compromise. "
    )
    return (sentence * ((min_chars // len(sentence)) + 2))[: min_chars + 50]


def _rss_xml(items):
    """Build RSS 2.0 XML from a list of (title, link, pubDate, guid) tuples."""
    item_elems = ""
    for title, link, pub_date, guid in items:
        item_elems += (
            f"<item>"
            f"<title>{title}</title>"
            f"<link>{link}</link>"
            f"<pubDate>{pub_date}</pubDate>"
            f"<guid>{guid}</guid>"
            f"</item>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<rss version=\"2.0\"><channel>"
        f"<title>ACSC Alerts</title>{item_elems}"
        f"</channel></rss>"
    ).encode()


def _acsc_entry(advisory_id, advisory_type="acsc_alert", title="Test",
                severity=None, pub_date="2026-06-01"):
    """Build an AcscEntry for backfill tests."""
    return AcscEntry(
        url=f"https://www.cyber.gov.au/about-us/advisories/{advisory_id}",
        title=title,
        pub_date=pub_date,
        advisory_type=advisory_type,
        severity=severity,
        advisory_id=advisory_id,
    )


# ---------------------------------------------------------------------------
# RSS feed parsing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_rss_feed_basic():
    xml = _rss_xml([
        (
            "CRITICAL ALERT: Remote code execution in Example Product",
            "https://www.cyber.gov.au/about-us/advisories/critical-rce-example",
            "Mon, 15 Jul 2026 10:00:00 +1000",
            "critical-rce-example",
        ),
        (
            "New ransomware campaign targeting healthcare",
            "https://www.cyber.gov.au/about-us/advisories/ransomware-healthcare-2026",
            "Tue, 16 Jul 2026 09:00:00 +1000",
            "ransomware-healthcare-2026",
        ),
    ])

    entries = _parse_rss_feed(xml, "acsc_alert")

    assert len(entries) == 2
    assert entries[0].advisory_id == "critical-rce-example"
    assert entries[0].advisory_type == "acsc_alert"
    # CRITICAL ALERT prefix is stripped by _parse_severity
    assert entries[0].title == "Remote code execution in Example Product"
    assert entries[0].severity == "critical"

    assert entries[1].advisory_id == "ransomware-healthcare-2026"
    assert entries[1].severity is None
    assert entries[1].title == "New ransomware campaign targeting healthcare"


@pytest.mark.unit
def test_parse_rss_feed_empty():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0"><channel><title>ACSC</title></channel></rss>'
    ).encode()

    entries = _parse_rss_feed(xml, "acsc_advisory")
    assert entries == []


@pytest.mark.unit
def test_parse_rss_feed_skips_missing_link():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0"><channel>'
        '<item><title>No link item</title></item>'
        '<item><title>Has link</title>'
        '<link>https://www.cyber.gov.au/about-us/advisories/has-link</link>'
        '</item>'
        '</channel></rss>'
    ).encode()

    entries = _parse_rss_feed(xml, "acsc_alert")
    assert len(entries) == 1
    assert entries[0].advisory_id == "has-link"


@pytest.mark.unit
def test_parse_rss_feed_advisory_id_from_url():
    xml = _rss_xml([
        (
            "Some advisory title",
            "https://www.cyber.gov.au/about-us/advisories/2026-07-slug-name?utm_source=rss",
            "Wed, 17 Jul 2026 08:00:00 +1000",
            "2026-07-slug-name",
        ),
    ])

    entries = _parse_rss_feed(xml, "acsc_advisory")
    # advisory_id is derived from URL path, query params stripped
    assert entries[0].advisory_id == "2026-07-slug-name"


# ---------------------------------------------------------------------------
# Severity parsing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_severity_critical():
    title, severity = _parse_severity("CRITICAL ALERT: Something bad happened")
    assert title == "Something bad happened"
    assert severity == "critical"


@pytest.mark.unit
def test_parse_severity_high():
    title, severity = _parse_severity("HIGH ALERT: Elevated threat activity")
    assert title == "Elevated threat activity"
    assert severity == "high"


@pytest.mark.unit
def test_parse_severity_medium():
    title, severity = _parse_severity("MEDIUM ALERT: Moderate risk advisory")
    assert title == "Moderate risk advisory"
    assert severity == "medium"


@pytest.mark.unit
def test_parse_severity_low():
    title, severity = _parse_severity("LOW ALERT: Informational notice")
    assert title == "Informational notice"
    assert severity == "low"


@pytest.mark.unit
def test_parse_severity_no_prefix():
    title, severity = _parse_severity("Normal advisory title with no severity")
    assert title == "Normal advisory title with no severity"
    assert severity is None


@pytest.mark.unit
def test_parse_severity_case_insensitive():
    # The function upper-cases for comparison, so mixed-case prefixes work
    title, severity = _parse_severity("Critical Alert: Mixed case")
    assert title == "Mixed case"
    assert severity == "critical"


# ---------------------------------------------------------------------------
# Article body extraction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_extract_article_body_drupal_govcms():
    content = _long_text(600)
    html = (
        "<html><body>"
        "<article>"
        '<div class="field--name-body">'
        f"<p>{content}</p>"
        "</div>"
        "</article>"
        "</body></html>"
    )

    result = extract_article_body(html)
    assert content[:80] in result


@pytest.mark.unit
def test_extract_article_body_fallback(caplog):
    content = _long_text(600)
    # No article, no main, no .node__content -- forces fallback
    html = (
        "<html><body>"
        f'<div class="random-wrapper"><p>{content}</p></div>'
        "</body></html>"
    )

    with caplog.at_level(logging.WARNING, logger="threat2signal.ingest.acsc_client"):
        result = extract_article_body(html)

    assert content[:80] in result
    assert "fallback" in caplog.text.lower()


@pytest.mark.unit
def test_extract_article_body_strips_noise():
    content = _long_text(600)
    html = (
        "<html><body>"
        "<article>"
        "<nav><a href='/'>Home</a></nav>"
        "<script>var tracking = 1;</script>"
        "<style>.hidden { display: none; }</style>"
        f'<div class="field--name-body"><p>{content}</p></div>'
        '<div class="breadcrumb">You are here</div>'
        '<div class="sidebar">Related links</div>'
        "</article>"
        "</body></html>"
    )

    result = extract_article_body(html)

    assert content[:80] in result
    assert "<script>" not in result
    assert "<style>" not in result
    assert "<nav>" not in result
    assert "You are here" not in result
    assert "Related links" not in result


@pytest.mark.unit
def test_extract_article_body_short_content_falls_back():
    body_text = _long_text(600)
    html = (
        "<html><body>"
        '<article><div class="field--name-body"><p>Short.</p></div></article>'
        f"<p>{body_text}</p>"
        "</body></html>"
    )

    result = extract_article_body(html)
    # Matched selector < 500 chars, falls back to full <body>
    assert body_text[:80] in result


# ---------------------------------------------------------------------------
# Akamai block detection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_detect_akamai_block_403_reference():
    body = "<html><body>Access Denied. Reference #12345</body></html>"
    resp = httpx.Response(
        403,
        content=body.encode(),
        headers={"content-type": "text/html"},
        request=_mock_request(),
    )

    assert detect_akamai_block(resp) is True


@pytest.mark.unit
def test_detect_akamai_block_403_access_denied():
    body = "<html><body><p>Access Denied</p></body></html>"
    resp = httpx.Response(
        403,
        content=body.encode(),
        headers={"content-type": "text/html"},
        request=_mock_request(),
    )

    assert detect_akamai_block(resp) is True


@pytest.mark.unit
def test_detect_akamai_block_small_response():
    # Under 2KB with no article structure
    body = "<html><body><p>Please wait.</p></body></html>"
    resp = httpx.Response(
        200,
        content=body.encode(),
        headers={"content-type": "text/html"},
        request=_mock_request(),
    )

    assert len(resp.content) < 2048
    assert detect_akamai_block(resp) is True


@pytest.mark.unit
def test_detect_akamai_block_normal_response():
    # Normal 200 with real article content
    content = _long_text(3000)
    body = (
        "<html><body>"
        f'<article><div class="field--name-body"><p>{content}</p></div></article>'
        "</body></html>"
    )
    resp = httpx.Response(
        200,
        content=body.encode(),
        headers={"content-type": "text/html"},
        request=_mock_request(),
    )

    assert detect_akamai_block(resp) is False


@pytest.mark.unit
def test_detect_akamai_block_known_markers():
    body = "<html><body>AkamaiGHost error page content here</body></html>"
    resp = httpx.Response(
        200,
        # Pad to >2KB to avoid the small-response check
        content=(body + " " * 3000).encode(),
        headers={"content-type": "text/html"},
        request=_mock_request(),
    )

    assert detect_akamai_block(resp) is True


# ---------------------------------------------------------------------------
# seed_backfill
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_seed_backfill_inserts_new_entries(db_conn):
    entries = [
        _acsc_entry("adv-001", advisory_type="acsc_alert"),
        _acsc_entry("adv-002", advisory_type="acsc_advisory"),
    ]

    seeded = seed_backfill(db_conn, entries)

    assert seeded == 2
    assert db.get_advisory(db_conn, "adv-001") is not None
    assert db.get_advisory(db_conn, "adv-002") is not None

    row = db.get_advisory(db_conn, "adv-001")
    assert row["source"] == "acsc"
    assert row["scrape_status"] == "pending"


@pytest.mark.unit
def test_seed_backfill_idempotent(db_conn):
    entries = [
        _acsc_entry("adv-dup-001"),
        _acsc_entry("adv-dup-002"),
    ]

    first = seed_backfill(db_conn, entries)
    assert first == 2

    second = seed_backfill(db_conn, entries)
    assert second == 0

    assert db.count_advisories(db_conn) == 2


@pytest.mark.unit
def test_seed_backfill_respects_limit(db_conn):
    entries = [
        _acsc_entry("adv-lim-001"),
        _acsc_entry("adv-lim-002"),
        _acsc_entry("adv-lim-003"),
        _acsc_entry("adv-lim-004"),
        _acsc_entry("adv-lim-005"),
    ]

    seeded = seed_backfill(db_conn, entries, limit=3)

    assert seeded == 3
    assert db.count_advisories(db_conn) == 3
    # Only the first 3 should be seeded
    assert db.get_advisory(db_conn, "adv-lim-001") is not None
    assert db.get_advisory(db_conn, "adv-lim-002") is not None
    assert db.get_advisory(db_conn, "adv-lim-003") is not None
    assert db.get_advisory(db_conn, "adv-lim-004") is None
    assert db.get_advisory(db_conn, "adv-lim-005") is None


@pytest.mark.unit
def test_advisory_id_derived_from_url_slug():
    """Verify advisory_id derivation from URL path slugs in RSS parsing."""
    xml = _rss_xml([
        (
            "Test Advisory",
            "https://www.cyber.gov.au/about-us/advisories/my-advisory-slug",
            "Mon, 01 Jul 2026 00:00:00 +1000",
            "my-advisory-slug",
        ),
        (
            "Another Advisory",
            "https://www.cyber.gov.au/about-us/advisories/another-slug/",
            "Tue, 02 Jul 2026 00:00:00 +1000",
            "another-slug",
        ),
    ])

    entries = _parse_rss_feed(xml, "acsc_alert")

    assert entries[0].advisory_id == "my-advisory-slug"
    # Trailing slash is stripped before taking the last segment
    assert entries[1].advisory_id == "another-slug"


# ---------------------------------------------------------------------------
# scrape_advisory with MockTransport
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_scrape_advisory_success(tmp_path):
    content = _long_text(800)
    mock_html = (
        "<html><body>"
        "<article>"
        '<div class="field--name-body">'
        f"<p>{content}</p>"
        "</div>"
        "</article>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=mock_html.encode(),
            headers={"content-type": "text/html; charset=utf-8"},
            request=request,
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = scrape_advisory(
            client,
            "https://www.cyber.gov.au/about-us/advisories/test-advisory",
            {},
            tmp_path,
        )
    finally:
        client.close()

    assert result.status == "ok"
    assert result.advisory_id == "test-advisory"
    assert result.raw_html is not None
    assert result.article_body is not None
    assert result.http_status == 200
    assert content[:80] in result.article_body


@pytest.mark.integration
def test_scrape_advisory_network_error(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = scrape_advisory(
            client,
            "https://www.cyber.gov.au/about-us/advisories/unreachable",
            {},
            tmp_path,
        )
    finally:
        client.close()

    assert result.status == "error"
    assert result.advisory_id == "unreachable"
    assert result.raw_html is None
    assert result.article_body is None
    assert result.http_status is None
    assert result.error is not None


@pytest.mark.integration
def test_scrape_advisory_http_error(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        # Body must be >2KB with article markers to avoid triggering Akamai detection
        body = (
            b'<html><body><article role="main">'
            + b"Server error content. " * 200
            + b"</article></body></html>"
        )
        return httpx.Response(
            500,
            content=body,
            headers={"content-type": "text/html"},
            request=request,
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = scrape_advisory(
            client,
            "https://www.cyber.gov.au/about-us/advisories/server-error",
            {},
            tmp_path,
        )
    finally:
        client.close()

    assert result.status == "http_error"
    assert result.http_status == 500


@pytest.mark.integration
def test_scrape_advisory_akamai_blocked(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            content=b"<html><body>Access Denied. Reference #abc123</body></html>",
            headers={"content-type": "text/html"},
            request=request,
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = scrape_advisory(
            client,
            "https://www.cyber.gov.au/about-us/advisories/blocked-page",
            {},
            tmp_path,
        )
    finally:
        client.close()

    assert result.status == "cf_challenged"
    assert result.advisory_id == "blocked-page"
