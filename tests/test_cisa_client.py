"""Tests for threat2signal.ingest.cisa_client module."""

import logging

import pytest
import httpx

from threat2signal.ingest.cisa_client import (
    parse_sitemap,
    diff_sitemap,
    validate_sitemap_result,
    detect_cloudflare_challenge,
    extract_article_body,
    seed_backfill,
    scrape_batch,
    create_http_client,
)
from threat2signal.ingest.models import SitemapEntry
from threat2signal.storage import db


# -- Helpers -----------------------------------------------------------------

_SITEMAP_NS_ATTR = 'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"'


def _urlset_xml(url_entries):
    """Build a <urlset> XML document from (loc, lastmod) pairs."""
    urls = "".join(
        f"<url><loc>{loc}</loc><lastmod>{lastmod}</lastmod></url>"
        for loc, lastmod in url_entries
    )
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f"<urlset {_SITEMAP_NS_ATTR}>{urls}</urlset>"
    ).encode()


def _entry(advisory_id, lastmod):
    """Build a SitemapEntry with conventional CISA URL and inferred type."""
    if advisory_id.startswith("aa"):
        return SitemapEntry(
            url=f"https://www.cisa.gov/news-events/cybersecurity-advisories/{advisory_id}",
            lastmod=lastmod,
            advisory_id=advisory_id,
            advisory_type="cybersecurity_advisory",
        )
    return SitemapEntry(
        url=f"https://www.cisa.gov/news-events/analysis-reports/{advisory_id}",
        lastmod=lastmod,
        advisory_id=advisory_id,
        advisory_type="analysis_report",
    )


def _mock_request():
    """Minimal httpx.Request to satisfy mock Response construction."""
    return httpx.Request("GET", "https://www.cisa.gov/test")


def _long_text(min_chars=600):
    """Realistic advisory paragraph that exceeds the 500-char extraction threshold."""
    sentence = (
        "This advisory provides details on threat actor activity targeting "
        "critical infrastructure sectors including energy and healthcare. "
        "Organizations should review network logs for indicators of compromise "
        "and implement recommended mitigations to reduce exposure. "
    )
    return (sentence * ((min_chars // len(sentence)) + 2))[: min_chars + 50]


# ---------------------------------------------------------------------------
# Sitemap parsing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_sitemap_urlset():
    xml = _urlset_xml([
        ("https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-001a", "2026-01-15T00:00:00Z"),
        ("https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-045b", "2026-03-10T00:00:00Z"),
        ("https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-100a", "2026-02-20T00:00:00Z"),
        ("https://www.cisa.gov/news-events/analysis-reports/ar25-338a", "2026-04-01T00:00:00Z"),
        ("https://www.cisa.gov/news-events/analysis-reports/ar25-100a", "2025-12-01T00:00:00Z"),
    ])

    entries = parse_sitemap(xml, fetch_fn=lambda url: b"")

    assert len(entries) == 5

    ids = {e.advisory_id for e in entries}
    assert ids == {"aa26-001a", "aa26-045b", "aa26-100a", "ar25-338a", "ar25-100a"}

    assert sum(1 for e in entries if e.advisory_type == "cybersecurity_advisory") == 3
    assert sum(1 for e in entries if e.advisory_type == "analysis_report") == 2

    # Sorted by lastmod descending (newest first)
    lastmods = [e.lastmod for e in entries]
    assert lastmods == sorted(lastmods, reverse=True)


@pytest.mark.unit
def test_parse_sitemap_sitemapindex():
    sub1 = _urlset_xml([
        ("https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-010a", "2026-05-01T00:00:00Z"),
        ("https://www.cisa.gov/news-events/analysis-reports/ar25-200a", "2026-04-15T00:00:00Z"),
    ])
    sub2 = _urlset_xml([
        ("https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-020a", "2026-06-01T00:00:00Z"),
    ])

    index_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<sitemapindex {_SITEMAP_NS_ATTR}>"
        "<sitemap><loc>https://www.cisa.gov/sitemap-1.xml</loc></sitemap>"
        "<sitemap><loc>https://www.cisa.gov/sitemap-2.xml</loc></sitemap>"
        "</sitemapindex>"
    ).encode()

    subs = {
        "https://www.cisa.gov/sitemap-1.xml": sub1,
        "https://www.cisa.gov/sitemap-2.xml": sub2,
    }

    entries = parse_sitemap(index_xml, fetch_fn=lambda url: subs[url])

    assert len(entries) == 3
    assert {e.advisory_id for e in entries} == {"aa26-010a", "ar25-200a", "aa26-020a"}


@pytest.mark.unit
def test_parse_sitemap_filters_non_aa_ar():
    xml = _urlset_xml([
        ("https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-050a", "2026-01-01T00:00:00Z"),
        ("https://www.cisa.gov/news-events/analysis-reports/ar25-050a", "2026-01-02T00:00:00Z"),
        ("https://www.cisa.gov/news-events/alerts/al26-001a", "2026-01-03T00:00:00Z"),
        ("https://www.cisa.gov/news-events/ics-advisories/icsa-26-001", "2026-01-04T00:00:00Z"),
        ("https://www.cisa.gov/news-events/alerts/al26-002a", "2026-01-05T00:00:00Z"),
    ])

    entries = parse_sitemap(xml, fetch_fn=lambda url: b"")

    assert len(entries) == 2
    assert {e.advisory_id for e in entries} == {"aa26-050a", "ar25-050a"}


@pytest.mark.unit
def test_parse_sitemap_empty():
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f"<urlset {_SITEMAP_NS_ATTR}></urlset>"
    ).encode()

    entries = parse_sitemap(xml, fetch_fn=lambda url: b"")

    assert entries == []


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_diff_sitemap_new_entries(db_conn):
    entries = [
        _entry("aa26-100a", "2026-06-01T00:00:00Z"),
        _entry("ar25-200a", "2026-05-15T00:00:00Z"),
    ]

    new, updated, unchanged = diff_sitemap(entries, db_conn)

    assert len(new) == 2
    assert len(updated) == 0
    assert unchanged == 0


@pytest.mark.unit
def test_diff_sitemap_updated_entries(db_conn):
    db.upsert_advisory(db_conn, {
        "advisory_id": "aa26-100a",
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "sitemap_lastmod": "2026-01-01T00:00:00Z",
    })

    entries = [_entry("aa26-100a", "2026-08-01T00:00:00Z")]

    new, updated, unchanged = diff_sitemap(entries, db_conn)

    assert len(new) == 0
    assert len(updated) == 1
    assert updated[0].advisory_id == "aa26-100a"
    assert unchanged == 0


@pytest.mark.unit
def test_diff_sitemap_unchanged(db_conn):
    db.upsert_advisory(db_conn, {
        "advisory_id": "aa26-100a",
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "sitemap_lastmod": "2026-05-01T00:00:00Z",
    })

    entries = [_entry("aa26-100a", "2026-05-01T00:00:00Z")]

    new, updated, unchanged = diff_sitemap(entries, db_conn)

    assert len(new) == 0
    assert len(updated) == 0
    assert unchanged == 1


# ---------------------------------------------------------------------------
# Validate sitemap result
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_sitemap_zero_entries_with_existing(db_conn):
    for i in range(105):
        db.upsert_advisory(db_conn, {
            "advisory_id": f"aa26-{i:03d}a",
            "type": "cybersecurity_advisory",
            "source": "cisa",
        })

    assert validate_sitemap_result([], db_conn) is False


@pytest.mark.unit
def test_validate_sitemap_zero_entries_empty_db(db_conn):
    assert validate_sitemap_result([], db_conn) is True


# ---------------------------------------------------------------------------
# Cloudflare detection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_detect_cf_challenge_header():
    # Large body with CISA content markers -- the cf-mitigated header fires first
    body = (
        '<html><body><article><div class="field--name-body">'
        + "x" * 20000
        + "</div></article></body></html>"
    ).encode()
    resp = httpx.Response(
        200,
        content=body,
        headers={"cf-mitigated": "challenge", "content-type": "text/html"},
        request=_mock_request(),
    )

    assert detect_cloudflare_challenge(resp) is True


@pytest.mark.unit
def test_detect_cf_challenge_content():
    # Body under 5000 bytes to skip size-band check; "Just a moment..." triggers
    # the content-marker check (check 3) specifically
    body = (
        "<html><head><title>Just a moment...</title></head>"
        "<body><p>Please wait while we verify your browser.</p></body></html>"
    ).encode()
    resp = httpx.Response(
        200,
        content=body,
        headers={"content-type": "text/html"},
        request=_mock_request(),
    )

    assert len(resp.content) < 5000
    assert detect_cloudflare_challenge(resp) is True


@pytest.mark.unit
def test_detect_cf_normal_response():
    # 150000+ bytes with genuine CISA content structure -- not a challenge
    filler = "Advisory content paragraph. " * 6000
    body = (
        '<html><body><article><div class="field--name-body">'
        f"<p>{filler}</p>"
        "</div></article></body></html>"
    ).encode()
    resp = httpx.Response(
        200,
        content=body,
        headers={"content-type": "text/html"},
        request=_mock_request(),
    )

    assert len(resp.content) >= 150000
    assert detect_cloudflare_challenge(resp) is False


# ---------------------------------------------------------------------------
# Article body extraction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_extract_article_body_drupal():
    content = _long_text(600)
    html = (
        "<html><body>"
        "<article>"
        '<div class="field--name-body">'
        "<nav><a href='/'>Home</a></nav>"
        f"<p>{content}</p>"
        "<script>var t = 1;</script>"
        "<style>.x { display: none; }</style>"
        "</div>"
        "</article>"
        "</body></html>"
    )

    result = extract_article_body(html)

    assert content[:80] in result
    assert "<script>" not in result
    assert "<style>" not in result
    assert "<nav>" not in result


@pytest.mark.unit
def test_extract_article_body_fallback(caplog):
    content = _long_text(600)
    # No article, no main, no role="main", no .node__content, no #main-content
    html = (
        "<html><body>"
        f'<div class="content"><p>{content}</p></div>'
        "</body></html>"
    )

    with caplog.at_level(logging.WARNING, logger="threat2signal.ingest.cisa_client"):
        result = extract_article_body(html)

    assert content[:80] in result
    assert "fallback" in caplog.text.lower()


@pytest.mark.unit
def test_extract_article_body_removes_noise():
    content = _long_text(600)
    html = (
        "<html><body>"
        "<article>"
        '<div class="breadcrumb">Breadcrumb path to advisory</div>'
        f"<p>{content}</p>"
        '<div class="sidebar">Related security resources</div>'
        '<div class="footer">Page footer and disclaimers</div>'
        "</article>"
        "</body></html>"
    )

    result = extract_article_body(html)

    assert content[:80] in result
    assert "Breadcrumb path to advisory" not in result
    assert "Related security resources" not in result
    assert "Page footer and disclaimers" not in result


@pytest.mark.unit
def test_extract_article_body_short_content():
    body_text = _long_text(600)
    html = (
        "<html><body>"
        '<article><div class="field--name-body"><p>Short.</p></div></article>'
        f"<p>{body_text}</p>"
        "</body></html>"
    )

    result = extract_article_body(html)

    # Matched selector content < 500 chars, falls back to full <body>
    assert body_text[:80] in result


# ---------------------------------------------------------------------------
# Seed / backfill with limit
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_seed_backfill_limit_per_type(db_conn):
    entries = []
    # 10 AA entries, newest first
    for i in range(10, 0, -1):
        entries.append(
            _entry(f"aa26-{i:03d}a", f"2026-01-{i:02d}T00:00:00Z")
        )
    # 8 AR entries, newest first
    for i in range(8, 0, -1):
        entries.append(
            _entry(f"ar25-{i:03d}a", f"2025-12-{i:02d}T00:00:00Z")
        )

    count = seed_backfill(db_conn, entries, limit_per_type=2)

    assert count == 4
    assert db.count_advisories(db_conn) == 4

    # Newest 2 of each type are seeded
    assert db.get_advisory(db_conn, "aa26-010a") is not None
    assert db.get_advisory(db_conn, "aa26-009a") is not None
    assert db.get_advisory(db_conn, "ar25-008a") is not None
    assert db.get_advisory(db_conn, "ar25-007a") is not None

    # Older entries are not seeded
    assert db.get_advisory(db_conn, "aa26-001a") is None
    assert db.get_advisory(db_conn, "ar25-001a") is None


@pytest.mark.unit
def test_seed_backfill_no_limit(db_conn):
    entries = [
        _entry("aa26-101a", "2026-04-01T00:00:00Z"),
        _entry("aa26-102a", "2026-04-02T00:00:00Z"),
        _entry("ar25-301a", "2026-03-01T00:00:00Z"),
        _entry("ar25-302a", "2026-03-02T00:00:00Z"),
        _entry("ar25-303a", "2026-03-03T00:00:00Z"),
    ]

    count = seed_backfill(db_conn, entries)

    assert count == 5
    assert db.count_advisories(db_conn) == 5


@pytest.mark.unit
def test_seed_backfill_idempotent(db_conn):
    entries = [
        _entry("aa26-201a", "2026-07-01T00:00:00Z"),
        _entry("ar25-401a", "2026-06-15T00:00:00Z"),
    ]

    first = seed_backfill(db_conn, entries)
    assert first == 2

    second = seed_backfill(db_conn, entries)
    assert second == 0

    assert db.count_advisories(db_conn) == 2


# ---------------------------------------------------------------------------
# Integration: full backfill + scrape flow
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_backfill_flow(db_conn):
    body_text = _long_text(800)
    mock_html = (
        "<html><body>"
        "<article>"
        '<div class="field--name-body">'
        f"<p>{body_text}</p>"
        "</div>"
        "</article>"
        "</body></html>"
    )
    html_bytes = mock_html.encode()

    def transport_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=html_bytes,
            headers={"content-type": "text/html; charset=utf-8"},
            request=request,
        )

    entries = [
        _entry("aa26-301a", "2026-08-10T00:00:00Z"),
        _entry("aa26-302a", "2026-08-09T00:00:00Z"),
        _entry("aa26-303a", "2026-08-08T00:00:00Z"),
        _entry("ar25-501a", "2026-08-07T00:00:00Z"),
        _entry("ar25-502a", "2026-08-06T00:00:00Z"),
    ]

    seeded = seed_backfill(db_conn, entries, limit_per_type=2)
    assert seeded == 4

    pending = db.get_pending_scrape(db_conn, batch_size=10)
    assert len(pending) == 4

    client = httpx.Client(transport=httpx.MockTransport(transport_handler))
    try:
        counts = scrape_batch(
            db_conn, client, {}, pending,
            delay_base=0.1, delay_jitter=0.0,
        )
    finally:
        client.close()

    assert counts["scraped"] == 4

    for adv_id in ("aa26-301a", "aa26-302a", "ar25-501a", "ar25-502a"):
        row = db.get_advisory(db_conn, adv_id)
        assert row is not None
        assert row["raw_html"] is not None
        assert row["article_body"] is not None
        assert row["scrape_status"] == "scraped"

    # Entry beyond the limit_per_type cap was never seeded
    assert db.get_advisory(db_conn, "aa26-303a") is None
