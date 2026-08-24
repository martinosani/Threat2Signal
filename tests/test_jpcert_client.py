"""Tests for threat2signal.ingest.jpcert_client module."""

import logging
from pathlib import Path

import pytest
import httpx

from threat2signal.ingest.jpcert_client import (
    _parse_atom_feed,
    _derive_advisory_id,
    extract_article_body,
    seed_backfill,
    fetch_category_listing,
    scrape_post,
)
from threat2signal.ingest.models import JpcertEntry
from threat2signal.storage import db


# -- Helpers -----------------------------------------------------------------


def _mock_request(url="https://blogs.jpcert.or.jp/en/test"):
    """Minimal httpx.Request to satisfy mock Response construction."""
    return httpx.Request("GET", url)


def _long_text(min_chars=400):
    """Realistic blog paragraph that exceeds the 300-char extraction threshold."""
    sentence = (
        "JPCERT/CC has confirmed attack activity exploiting a vulnerability "
        "in the targeted software. Organisations should apply the latest "
        "patches and review logs for indicators of compromise. "
    )
    return (sentence * ((min_chars // len(sentence)) + 2))[: min_chars + 50]


def _atom_xml(entries):
    """Build Atom XML from a list of (title, href, published, categories) tuples.

    categories is a list of category term strings.
    """
    entry_elems = ""
    for title, href, published, categories in entries:
        cat_elems = "".join(
            f'<category term="{cat}"/>' for cat in categories
        )
        entry_elems += (
            f"<entry>"
            f"<title>{title}</title>"
            f'<link href="{href}"/>'
            f"<published>{published}</published>"
            f"{cat_elems}"
            f"</entry>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<feed xmlns="http://www.w3.org/2005/Atom">'
        f"<title>JPCERT/CC Eyes</title>"
        f"{entry_elems}"
        f"</feed>"
    ).encode()


def _jpcert_entry(advisory_id, category="malware", title="Test Post",
                  pub_date="2026-07-01"):
    """Build a JpcertEntry for backfill tests."""
    return JpcertEntry(
        url=f"https://blogs.jpcert.or.jp/en/2026/07/{advisory_id}.html",
        title=title,
        pub_date=pub_date,
        category=category,
        advisory_id=f"jpcert-202607-{advisory_id}",
    )


# ---------------------------------------------------------------------------
# Atom feed parsing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_atom_feed_basic():
    xml = _atom_xml([
        (
            "Analysis of APT-C-60 Malware",
            "https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html",
            "2026-07-15T09:00:00+09:00",
            ["malware"],
        ),
        (
            "Incident Response Report Q2 2026",
            "https://blogs.jpcert.or.jp/en/2026/07/ir-q2-2026.html",
            "2026-07-10T09:00:00+09:00",
            ["incident"],
        ),
    ])

    entries = _parse_atom_feed(xml, ["malware", "incident"])

    assert len(entries) == 2
    assert entries[0].title == "Analysis of APT-C-60 Malware"
    assert entries[0].category == "malware"
    assert entries[0].advisory_id == "jpcert-202607-apt-c-60_2026"
    assert entries[1].category == "incident"


@pytest.mark.unit
def test_parse_atom_feed_filters_non_matching_categories():
    xml = _atom_xml([
        (
            "Matching Post",
            "https://blogs.jpcert.or.jp/en/2026/07/matching.html",
            "2026-07-15T09:00:00+09:00",
            ["malware"],
        ),
        (
            "Non-matching Post",
            "https://blogs.jpcert.or.jp/en/2026/07/nomatch.html",
            "2026-07-14T09:00:00+09:00",
            ["vulnerability"],
        ),
        (
            "Another non-match",
            "https://blogs.jpcert.or.jp/en/2026/07/other.html",
            "2026-07-13T09:00:00+09:00",
            ["update"],
        ),
    ])

    entries = _parse_atom_feed(xml, ["malware", "incident"])

    assert len(entries) == 1
    assert entries[0].advisory_id == "jpcert-202607-matching"


@pytest.mark.unit
def test_parse_atom_feed_empty():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<feed xmlns="http://www.w3.org/2005/Atom">'
        '<title>JPCERT/CC Eyes</title>'
        '</feed>'
    ).encode()

    entries = _parse_atom_feed(xml, ["malware", "incident"])
    assert entries == []


@pytest.mark.unit
def test_parse_atom_feed_multi_category_entry():
    """An entry with multiple categories picks the first matching one."""
    xml = _atom_xml([
        (
            "Multi-category Post",
            "https://blogs.jpcert.or.jp/en/2026/07/multi-cat.html",
            "2026-07-15T09:00:00+09:00",
            ["vulnerability", "malware", "incident"],
        ),
    ])

    entries = _parse_atom_feed(xml, ["malware", "incident"])

    assert len(entries) == 1
    # malware comes first in the configured categories list
    assert entries[0].category == "malware"


@pytest.mark.unit
def test_parse_atom_feed_skips_entry_without_link():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<feed xmlns="http://www.w3.org/2005/Atom">'
        '<entry>'
        '<title>No link entry</title>'
        '<category term="malware"/>'
        '<published>2026-07-15T09:00:00+09:00</published>'
        '</entry>'
        '</feed>'
    ).encode()

    entries = _parse_atom_feed(xml, ["malware"])
    assert entries == []


# ---------------------------------------------------------------------------
# Advisory ID derivation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_derive_advisory_id_standard_url():
    url = "https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html"
    assert _derive_advisory_id(url) == "jpcert-202607-apt-c-60_2026"


@pytest.mark.unit
def test_derive_advisory_id_different_date():
    url = "https://blogs.jpcert.or.jp/en/2024/01/some-post.html"
    assert _derive_advisory_id(url) == "jpcert-202401-some-post"


@pytest.mark.unit
def test_derive_advisory_id_path_only():
    url = "/en/2026/07/apt-c-60_2026.html"
    assert _derive_advisory_id(url) == "jpcert-202607-apt-c-60_2026"


@pytest.mark.unit
def test_derive_advisory_id_no_match_fallback():
    # URL that does not match the /en/YYYY/MM/slug.html pattern
    url = "https://blogs.jpcert.or.jp/some/other/path.html"
    result = _derive_advisory_id(url)
    assert result == "jpcert-path"


@pytest.mark.unit
def test_derive_advisory_id_no_match_no_extension():
    url = "https://blogs.jpcert.or.jp/misc/page"
    result = _derive_advisory_id(url)
    assert result == "jpcert-page"


# ---------------------------------------------------------------------------
# Article body extraction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_extract_article_body_entry_body():
    content = _long_text(400)
    html = (
        "<html><body>"
        f'<div class="entry-body"><p>{content}</p></div>'
        "</body></html>"
    )

    result = extract_article_body(html)
    assert content[:80] in result


@pytest.mark.unit
def test_extract_article_body_fallback(caplog):
    content = _long_text(400)
    # No matching selectors -- forces fallback to body
    html = (
        "<html><body>"
        f'<div class="random-div"><p>{content}</p></div>'
        "</body></html>"
    )

    with caplog.at_level(logging.WARNING, logger="threat2signal.ingest.jpcert_client"):
        result = extract_article_body(html)

    assert content[:80] in result
    assert "fallback" in caplog.text.lower()


@pytest.mark.unit
def test_extract_article_body_300_char_threshold():
    """JPCERT uses a 300-char minimum, lower than CISA's 500."""
    # Content between 300 and 500 chars should match, not fall back
    content = _long_text(350)
    html = (
        "<html><body>"
        f'<div class="entry-body"><p>{content}</p></div>'
        "<p>Other body text outside selector</p>"
        "</body></html>"
    )

    result = extract_article_body(html)
    assert "entry-body" in result
    assert content[:80] in result


@pytest.mark.unit
def test_extract_article_body_strips_noise():
    content = _long_text(400)
    html = (
        "<html><body>"
        f'<div class="entry-body">'
        "<nav>Navigation links</nav>"
        "<script>var tracking = 1;</script>"
        "<style>.hidden { display: none; }</style>"
        f"<p>{content}</p>"
        '<div class="sidebar">Sidebar content</div>'
        '<div class="breadcrumb">Breadcrumb path</div>'
        "</div>"
        "</body></html>"
    )

    result = extract_article_body(html)

    assert content[:80] in result
    assert "<script>" not in result
    assert "<style>" not in result
    assert "<nav>" not in result
    assert "Sidebar content" not in result
    assert "Breadcrumb path" not in result


# ---------------------------------------------------------------------------
# seed_backfill
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_seed_backfill_inserts_with_correct_source(db_conn):
    entries = [
        _jpcert_entry("post-001", category="malware"),
        _jpcert_entry("post-002", category="incident"),
    ]

    seeded = seed_backfill(db_conn, entries)

    assert seeded == 2
    row1 = db.get_advisory(db_conn, "jpcert-202607-post-001")
    assert row1 is not None
    assert row1["source"] == "jpcert"
    assert row1["type"] == "jpcert_malware"
    assert row1["scrape_status"] == "pending"

    row2 = db.get_advisory(db_conn, "jpcert-202607-post-002")
    assert row2["type"] == "jpcert_incident"


@pytest.mark.unit
def test_seed_backfill_idempotent(db_conn):
    entries = [
        _jpcert_entry("dup-001"),
        _jpcert_entry("dup-002"),
    ]

    first = seed_backfill(db_conn, entries)
    assert first == 2

    second = seed_backfill(db_conn, entries)
    assert second == 0

    assert db.count_advisories(db_conn) == 2


@pytest.mark.unit
def test_seed_backfill_respects_limit(db_conn):
    entries = [
        _jpcert_entry("lim-001"),
        _jpcert_entry("lim-002"),
        _jpcert_entry("lim-003"),
        _jpcert_entry("lim-004"),
    ]

    seeded = seed_backfill(db_conn, entries, limit=2)

    assert seeded == 2
    assert db.count_advisories(db_conn) == 2
    assert db.get_advisory(db_conn, "jpcert-202607-lim-001") is not None
    assert db.get_advisory(db_conn, "jpcert-202607-lim-002") is not None
    assert db.get_advisory(db_conn, "jpcert-202607-lim-003") is None


# ---------------------------------------------------------------------------
# fetch_category_listing returns empty on 404
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_fetch_category_listing_returns_empty_on_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            content=b"Not Found",
            headers={"content-type": "text/html"},
            request=request,
        )

    settings = {
        "jpcert": {
            "blog_base_url": "https://blogs.jpcert.or.jp/en",
        },
    }

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = fetch_category_listing(client, settings, "malware", page=99)
    finally:
        client.close()

    assert result == []


# ---------------------------------------------------------------------------
# scrape_post with MockTransport
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_scrape_post_success(tmp_path):
    content = _long_text(500)
    mock_html = (
        "<html><body>"
        f'<div class="entry-body"><p>{content}</p></div>'
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
        result = scrape_post(
            client,
            "https://blogs.jpcert.or.jp/en/2026/07/test-post.html",
            {},
            tmp_path,
        )
    finally:
        client.close()

    assert result.status == "ok"
    assert result.advisory_id == "jpcert-202607-test-post"
    assert result.raw_html is not None
    assert result.article_body is not None
    assert result.http_status == 200
    assert content[:80] in result.article_body


@pytest.mark.integration
def test_scrape_post_network_error(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = scrape_post(
            client,
            "https://blogs.jpcert.or.jp/en/2026/07/unreachable.html",
            {},
            tmp_path,
        )
    finally:
        client.close()

    assert result.status == "error"
    assert result.advisory_id == "jpcert-202607-unreachable"
    assert result.raw_html is None
    assert result.article_body is None
    assert result.http_status is None
    assert result.error is not None


@pytest.mark.integration
def test_scrape_post_http_error(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            content=b"Internal Server Error",
            headers={"content-type": "text/html"},
            request=request,
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = scrape_post(
            client,
            "https://blogs.jpcert.or.jp/en/2026/07/server-err.html",
            {},
            tmp_path,
        )
    finally:
        client.close()

    assert result.status == "http_error"
    assert result.http_status == 500
    assert result.advisory_id == "jpcert-202607-server-err"
