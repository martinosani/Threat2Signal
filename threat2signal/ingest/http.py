"""Shared HTTP transport with browser TLS fingerprinting."""

from __future__ import annotations

import ipaddress
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from curl_cffi.requests import Session as CffiSession

logger = logging.getLogger(__name__)

# curl_cffi decompresses internally but leaves these headers on the response,
# causing httpx to attempt double-decompression
STRIP_HEADERS = frozenset({"content-encoding", "transfer-encoding"})

# Hosts we are willing to fetch scraped-advisory assets from. URLs in
# advisory_asset originate from attacker-influenced pages, so both the sync
# downloader (asset_downloader.py) and the async proxy (api.py) MUST restrict
# outbound fetches to this set to prevent SSRF into internal services.
ASSET_HOST_ALLOWLIST: frozenset[str] = frozenset({
    "www.cisa.gov",
    "www.cyber.gov.au",
    "blogs.jpcert.or.jp",
    "media.defense.gov",
    "orkl.eu",
    "archive.orkl.eu",
})


class CurlCffiTransport(httpx.BaseTransport):
    """httpx transport backed by curl_cffi for browser-grade TLS fingerprints."""

    def __init__(self, impersonate: str = "chrome") -> None:
        self._session = CffiSession(impersonate=impersonate)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        timeout_ext = request.extensions.get("timeout", {})
        read_timeout = timeout_ext.get("read")
        connect_timeout = timeout_ext.get("connect")
        if read_timeout and connect_timeout:
            timeout = connect_timeout + read_timeout
        elif read_timeout:
            timeout = read_timeout
        else:
            timeout = 60

        resp = self._session.request(
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
            content=request.read() if request.method in ("POST", "PUT", "PATCH") else None,
            allow_redirects=False,
            timeout=timeout,
        )

        headers = [
            (k, v) for k, v in resp.headers.items()
            if k.lower() not in STRIP_HEADERS
        ]

        return httpx.Response(
            status_code=resp.status_code,
            headers=headers,
            content=resp.content,
            request=request,
        )

    def close(self) -> None:
        self._session.close()


def is_allowed_asset_host(host: str) -> bool:
    """Return True if *host* is on the asset download/proxy allowlist."""
    return host.lower() in ASSET_HOST_ALLOWLIST


def _ip_is_public(ip_text: str) -> bool:
    """Return True only for globally-routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    # Reject loopback/link-local/private/ULA/reserved/multicast ranges that an
    # attacker-supplied host could resolve to (169.254.169.254, 127.0.0.1, RFC1918).
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def host_resolves_to_public_ip(host: str) -> bool:
    """Return True only if every resolved address for *host* is public."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    return all(_ip_is_public(addr) for addr in addresses)


def validate_asset_url(url: str) -> None:
    """Raise ValueError if *url* is unsafe to fetch as an advisory asset.

    Shared SSRF guard for the sync downloader and the async asset proxy:
    rejects non-http(s) schemes, hosts not on ASSET_HOST_ALLOWLIST, and hosts
    that resolve to any non-public IP. Callers that follow redirects MUST
    re-validate every hop's URL with this function, not just the first one.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")
    if not is_allowed_asset_host(host):
        raise ValueError(f"host not on asset allowlist: {host}")
    if not host_resolves_to_public_ip(host):
        raise ValueError(f"host resolves to a non-public address: {host}")


def create_http_client(
    user_agent: str,
    connect_timeout: float,
    read_timeout: float,
    use_curl_cffi: bool = True,
    follow_redirects: bool = True,
) -> httpx.Client:
    """Create an httpx client, optionally with browser TLS fingerprinting.

    *follow_redirects* is exposed so the asset client can disable httpx-level
    redirect following and validate each hop itself; the CurlCffiTransport
    already refuses to follow redirects internally, so the two layers agree.
    """
    timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
    transport = CurlCffiTransport(impersonate="chrome") if use_curl_cffi else None
    return httpx.Client(
        transport=transport,
        headers={"User-Agent": user_agent},
        timeout=timeout,
        follow_redirects=follow_redirects,
    )


def html_cache_path(data_dir: Path, source: str, advisory_id: str) -> Path:
    """Return the monthly cache file path for a scraped advisory page."""
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    return data_dir / "html_cache" / source / month / f"{advisory_id}.html"


def asset_dir(data_dir: Path, source: str, month: str, numeric_id: int) -> Path:
    """Return the directory for downloaded assets of a specific advisory."""
    return data_dir / "assets" / source / month / str(numeric_id)
