"""Tests for threat2signal.ingest.http shared transport module."""

from pathlib import Path

import pytest
import httpx

from threat2signal.ingest.http import (
    html_cache_path,
    asset_dir,
    create_http_client,
    CurlCffiTransport,
)


# ---------------------------------------------------------------------------
# html_cache_path
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_html_cache_path_structure(tmp_path):
    result = html_cache_path(tmp_path, "cisa", "aa26-100a")

    # Structure: data_dir / html_cache / {source} / {YYYY-MM} / {id}.html
    parts = result.relative_to(tmp_path).parts
    assert parts[0] == "html_cache"
    assert parts[1] == "cisa"
    # Month directory matches YYYY-MM format
    assert len(parts[2]) == 7 and parts[2][4] == "-"
    assert parts[3] == "aa26-100a.html"


@pytest.mark.unit
def test_html_cache_path_different_sources(tmp_path):
    cisa_path = html_cache_path(tmp_path, "cisa", "aa26-001a")
    acsc_path = html_cache_path(tmp_path, "acsc", "some-advisory")
    jpcert_path = html_cache_path(tmp_path, "jpcert", "jpcert-202607-post")

    assert cisa_path.parent.parent.name == "cisa"
    assert acsc_path.parent.parent.name == "acsc"
    assert jpcert_path.parent.parent.name == "jpcert"


@pytest.mark.unit
def test_html_cache_path_returns_path_object(tmp_path):
    result = html_cache_path(tmp_path, "acsc", "test-id")
    assert isinstance(result, Path)
    assert result.suffix == ".html"


# ---------------------------------------------------------------------------
# asset_dir
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_asset_dir_structure(tmp_path):
    result = asset_dir(tmp_path, "cisa", "2026-08", 500)

    parts = result.relative_to(tmp_path).parts
    assert parts == ("assets", "cisa", "2026-08", "500")


@pytest.mark.unit
def test_asset_dir_different_sources(tmp_path):
    cisa = asset_dir(tmp_path, "cisa", "2026-08", 1)
    acsc = asset_dir(tmp_path, "acsc", "2026-07", 2)
    jpcert = asset_dir(tmp_path, "jpcert", "2026-07", 3)

    assert "cisa" in cisa.parts
    assert "acsc" in acsc.parts
    assert "jpcert" in jpcert.parts


@pytest.mark.unit
def test_asset_dir_returns_path_object(tmp_path):
    result = asset_dir(tmp_path, "acsc", "2026-08", 42)
    assert isinstance(result, Path)


# ---------------------------------------------------------------------------
# create_http_client
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_create_http_client_plain():
    client = create_http_client(
        user_agent="TestAgent/1.0",
        connect_timeout=10,
        read_timeout=30,
        use_curl_cffi=False,
    )
    try:
        assert isinstance(client, httpx.Client)
        # Plain client uses httpx default transport, not CurlCffiTransport
        assert not isinstance(client._transport, CurlCffiTransport)
        assert client.headers["User-Agent"] == "TestAgent/1.0"
    finally:
        client.close()


@pytest.mark.unit
def test_create_http_client_curl_cffi():
    client = create_http_client(
        user_agent="BrowserAgent/1.0",
        connect_timeout=15,
        read_timeout=45,
        use_curl_cffi=True,
    )
    try:
        assert isinstance(client, httpx.Client)
        assert isinstance(client._transport, CurlCffiTransport)
        assert client.headers["User-Agent"] == "BrowserAgent/1.0"
    finally:
        client.close()


@pytest.mark.unit
def test_create_http_client_follows_redirects():
    client = create_http_client(
        user_agent="Test/1.0",
        connect_timeout=10,
        read_timeout=30,
        use_curl_cffi=False,
    )
    try:
        assert client.follow_redirects is True
    finally:
        client.close()
