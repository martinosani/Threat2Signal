"""Advisory asset download and storage."""

from __future__ import annotations

import logging
import re
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx

from threat2signal.ingest.http import create_http_client as _make_http_client
from threat2signal.ingest.http import validate_asset_url
from threat2signal.storage import db

logger = logging.getLogger(__name__)

_CONTENT_TYPES: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
    ".json": "application/json",
    ".xml": "application/xml",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".csv": "text/csv",
}

_MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"%PDF", "application/pdf"),
)

_IMAGE_MAGIC_TYPES: frozenset[str] = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml",
})

_MAX_RETRIES = 2
_RETRY_DELAYS = (1.0, 2.0)
_MAX_REDIRECTS = 3
_CHUNK_SIZE = 64 * 1024

# Cap on a single downloaded asset. URLs are attacker-influenced, so an
# unbounded body would OOM the process; 25 MB comfortably covers the largest
# real figures/PDFs in the corpus. Overridable via settings key
# `assets.max_asset_bytes`; kept as a module constant so the downloader works
# even when that key is absent from settings.yaml.
_DEFAULT_MAX_ASSET_BYTES = 25 * 1024 * 1024

# Characters that are unsafe in a Windows/POSIX filename or could nest paths.
_UNSAFE_FILENAME_CHARS = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')
_MAX_FILENAME_LEN = 200


def _check_disk_space(data_dir: Path, min_mb: int = 100) -> bool:
    """Verify sufficient disk space before downloading."""
    usage = shutil.disk_usage(str(data_dir))
    return usage.free > min_mb * 1024 * 1024


def detect_content_type(filepath: Path) -> str:
    """Detect content type from file extension, with magic byte fallback."""
    ext = filepath.suffix.lower()
    if ext in _CONTENT_TYPES:
        return _CONTENT_TYPES[ext]
    return _detect_by_magic(filepath)


def _detect_by_magic(filepath: Path) -> str:
    """Fall back to magic byte detection for unknown extensions."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(512)
    except OSError:
        return "application/octet-stream"
    return _magic_content_type(header)


def _magic_content_type(header: bytes) -> str:
    """Classify content from its leading bytes, ignoring any filename/extension."""
    if not header:
        return "application/octet-stream"
    for signature, content_type in _MAGIC_SIGNATURES:
        if header.startswith(signature):
            return content_type
    # WEBP: RIFF at offset 0, WEBP at offset 8
    if header[:4] == b"RIFF" and len(header) >= 12 and header[8:12] == b"WEBP":
        return "image/webp"
    if b"<svg" in header:
        return "image/svg+xml"
    # Detect HTML error pages served in place of the requested asset.
    lowered = header.lstrip()[:64].lower()
    if lowered.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return "text/html"
    return "application/octet-stream"


def _validate_asset_bytes(filepath: Path, asset_type: str) -> None:
    """Reject a download whose magic bytes don't match the expected class.

    Prevents storing an HTML error page (or other decoy) as an image. The
    stored extension is untrusted, so classification here is by content only.
    """
    try:
        with open(filepath, "rb") as fh:
            header = fh.read(512)
    except OSError as exc:
        raise ValueError(f"cannot read downloaded asset: {exc}") from exc
    detected = _magic_content_type(header)
    if asset_type == "figure" and detected not in _IMAGE_MAGIC_TYPES:
        raise ValueError(
            f"expected image for figure, got {detected} from magic bytes",
        )
    if asset_type != "figure" and detected == "text/html":
        raise ValueError("expected file asset, got an HTML page")


def _fetch_pending_assets(
    conn: sqlite3.Connection,
) -> list[tuple[str, str, str]]:
    """Query all assets awaiting download."""
    return db.get_pending_assets(conn)


def _get_advisory_row(
    conn: sqlite3.Connection, advisory_id: str,
) -> dict | None:
    """Look up advisory row by advisory_id."""
    return db.get_advisory(conn, advisory_id)


def _month_from_date(pub_date: str | None) -> str:
    """Extract YYYY-MM from a date string, falling back to current month."""
    if pub_date and len(pub_date) >= 7:
        return pub_date[:7]
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _sanitize_filename(original_url: str) -> str:
    """Reduce a URL to a safe bare filename for local storage.

    URLs come from scraped, attacker-influenced advisory HTML. unquote()
    decodes %2e%2e%2f into ../ , so decode first, then keep only the final
    path component and strip anything that could escape the assets directory.
    """
    raw = unquote(Path(urlparse(original_url).path).name)
    # Post-decode separators (e.g. from %2f) can reintroduce nesting; keep the
    # last component only.
    raw = raw.replace("\\", "/").split("/")[-1]
    raw = _UNSAFE_FILENAME_CHARS.sub("_", raw)
    raw = raw.strip(". ")  # drop leading/trailing dots/spaces ('.', '..', hidden)
    if not raw:
        return "unnamed"
    return raw[:_MAX_FILENAME_LEN]


def _build_local_path(
    data_dir: Path, source: str, pub_date: str | None,
    numeric_id: int, asset_type: str, original_url: str,
) -> Path:
    """Determine local storage path for an asset, contained within assets root."""
    filename = _sanitize_filename(original_url)
    subdir = "figures" if asset_type == "figure" else "files"
    month = _month_from_date(pub_date)
    local_path = (
        data_dir / "assets" / source / month / str(numeric_id) / subdir / filename
    )
    assets_root = (data_dir / "assets").resolve()
    # Defense in depth: mirror the serve endpoint's guard so a crafted filename
    # (or source/month token) can never write outside the assets tree.
    if not local_path.resolve().is_relative_to(assets_root):
        raise ValueError(f"asset path escapes assets root: {local_path}")
    return local_path


def _download_with_retries(
    client: httpx.Client, url: str, dest: Path, max_bytes: int,
) -> int:
    """Download a URL to disk with retry on server/network errors."""
    last_error: httpx.HTTPError | None = None
    for attempt in range(_MAX_RETRIES + 1):
        if attempt > 0:
            # Exponential backoff: 1s then 2s
            time.sleep(_RETRY_DELAYS[attempt - 1])
            logger.debug("Retry %d/%d for %s", attempt, _MAX_RETRIES, url)
        try:
            return _stream_download(client, url, dest, max_bytes)
        except httpx.HTTPStatusError as exc:
            if 400 <= exc.response.status_code < 500:
                raise
            last_error = exc
        except httpx.HTTPError as exc:
            last_error = exc
    raise last_error  # type: ignore[misc]


def _stream_download(
    client: httpx.Client, url: str, dest: Path, max_bytes: int,
) -> int:
    """Stream a URL to disk, following only validated allowlisted redirects.

    The asset client has httpx-level redirect following disabled, so each 3xx
    is handled here and its Location re-validated against the SSRF allowlist
    before the next hop is fetched.
    """
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        validate_asset_url(current)
        with client.stream("GET", current) as response:
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("redirect response missing Location header")
                current = str(response.url.join(location))
                continue
            response.raise_for_status()
            return _write_capped(response, dest, max_bytes)
    raise ValueError(f"too many redirects for {url}")


def _write_capped(response: httpx.Response, dest: Path, max_bytes: int) -> int:
    """Write a streamed response to *dest*, aborting if it exceeds *max_bytes*."""
    content_length = response.headers.get("content-length")
    if content_length is not None and content_length.isdigit():
        if int(content_length) > max_bytes:
            raise ValueError(
                f"asset Content-Length {content_length} exceeds cap {max_bytes}",
            )
    written = 0
    try:
        with open(dest, "wb") as fh:
            for chunk in response.iter_bytes(_CHUNK_SIZE):
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError(f"asset exceeds cap of {max_bytes} bytes")
                fh.write(chunk)
    except (ValueError, OSError, httpx.HTTPError):
        dest.unlink(missing_ok=True)
        raise
    return written


def _mark_downloaded(
    conn: sqlite3.Connection, advisory_id: str, original_url: str,
    local_path: str, file_size: int,
) -> None:
    """Record a successful asset download."""
    db.mark_asset_downloaded(
        conn, advisory_id, original_url, local_path, file_size,
        datetime.now(timezone.utc).isoformat(),
    )


def _mark_failed(
    conn: sqlite3.Connection, advisory_id: str, original_url: str,
    error: str,
) -> None:
    """Record a failed asset download."""
    db.mark_asset_failed(conn, advisory_id, original_url, error)


def _record_failure(
    conn: sqlite3.Connection, advisory_id: str, url: str, error: str,
    counts: dict[str, int],
) -> None:
    """Mark an asset failed and count it, tolerating a DB write failure."""
    try:
        _mark_failed(conn, advisory_id, url, error)
    except sqlite3.Error:
        logger.exception("Failed to record download failure for %s", url)
    counts["failed"] += 1


def _skip_existing(
    conn: sqlite3.Connection, advisory_id: str, url: str, local_path: Path,
    counts: dict[str, int],
) -> None:
    """Mark an already-present asset completed without re-fetching it."""
    size = local_path.stat().st_size
    try:
        _mark_downloaded(conn, advisory_id, url, str(local_path), size)
    except sqlite3.Error:
        logger.exception("Failed to mark existing asset completed for %s", url)
        counts["failed"] += 1
        return
    counts["skipped"] += 1
    logger.debug("Asset already present, skipping fetch: %s", local_path)


def _download_one_asset(
    conn: sqlite3.Connection, client: httpx.Client,
    advisory_id: str, asset_type: str, url: str, local_path: Path,
    max_asset_bytes: int, counts: dict[str, int],
) -> None:
    """Download a single asset, updating DB status on completion."""
    try:
        validate_asset_url(url)
    except ValueError as exc:
        _record_failure(conn, advisory_id, url, str(exc), counts)
        logger.error("Rejected asset URL %s: %s", url, exc)
        return
    # Re-runs of `extract --all` re-queue the same assets; skip files already
    # on disk so we don't re-download the whole corpus every time.
    if local_path.exists() and local_path.stat().st_size > 0:
        _skip_existing(conn, advisory_id, url, local_path, counts)
        return
    local_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        file_size = _download_with_retries(
            client, url, local_path, max_asset_bytes,
        )
        _validate_asset_bytes(local_path, asset_type)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        local_path.unlink(missing_ok=True)
        _record_failure(conn, advisory_id, url, str(exc), counts)
        logger.error("Failed to download %s: %s", url, exc)
        return
    try:
        _mark_downloaded(conn, advisory_id, url, str(local_path), file_size)
    except sqlite3.Error:
        logger.exception("Downloaded %s but failed to update DB", url)
        counts["failed"] += 1
        return
    counts["downloaded"] += 1
    logger.debug("Downloaded %s -> %s (%d bytes)", url, local_path, file_size)


def _download_advisory_assets(
    conn: sqlite3.Connection, client: httpx.Client, data_dir: Path,
    advisory_id: str, assets: list[tuple[str, str]],
    max_asset_bytes: int, counts: dict[str, int],
) -> None:
    """Download all pending assets for one advisory."""
    row = _get_advisory_row(conn, advisory_id)
    if row is None:
        logger.warning(
            "Advisory %s not found, skipping %d assets",
            advisory_id, len(assets),
        )
        counts["skipped"] += len(assets)
        return
    source = row["source"]
    pub_date = row.get("pub_date")
    numeric_id = row["id"]
    for asset_type, url in assets:
        try:
            local_path = _build_local_path(
                data_dir, source, pub_date, numeric_id, asset_type, url,
            )
        except ValueError as exc:
            # One malformed URL must never abort the batch.
            _record_failure(conn, advisory_id, url, str(exc), counts)
            logger.error("Rejected asset path for %s: %s", url, exc)
            continue
        _download_one_asset(
            conn, client, advisory_id, asset_type, url, local_path,
            max_asset_bytes, counts,
        )


def download_pending_assets(
    conn: sqlite3.Connection, data_dir: Path,
    settings: dict | None = None,
) -> dict[str, int]:
    """Download pending advisory assets (figures + files) to local storage."""
    if not _check_disk_space(data_dir):
        logger.warning(
            "Insufficient disk space in %s, skipping downloads", data_dir,
        )
        return {"downloaded": 0, "failed": 0, "skipped": 0}
    pending = _fetch_pending_assets(conn)
    if not pending:
        return {"downloaded": 0, "failed": 0, "skipped": 0}
    by_advisory: dict[str, list[tuple[str, str]]] = {}
    for advisory_id, asset_type, url in pending:
        by_advisory.setdefault(advisory_id, []).append((asset_type, url))
    logger.info(
        "Downloading assets for %d advisories (%d files)",
        len(by_advisory), len(pending),
    )
    counts = {"downloaded": 0, "failed": 0, "skipped": 0}
    if settings:
        user_agent = settings.get("cisa", {}).get(
            "user_agent", "Mozilla/5.0 (compatible; Threat2Signal/1.0)",
        )
        connect_timeout = settings.get("http", {}).get("connect_timeout", 30)
        read_timeout = settings.get("http", {}).get("read_timeout", 60)
        max_asset_bytes = settings.get("assets", {}).get(
            "max_asset_bytes", _DEFAULT_MAX_ASSET_BYTES,
        )
    else:
        user_agent = "Mozilla/5.0 (compatible; Threat2Signal/1.0)"
        connect_timeout = 30
        read_timeout = 60
        max_asset_bytes = _DEFAULT_MAX_ASSET_BYTES
    # Redirects are followed manually in _stream_download so each hop's host is
    # re-checked against the SSRF allowlist; disable httpx-level following here.
    client = _make_http_client(
        user_agent=user_agent,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        use_curl_cffi=True,
        follow_redirects=False,
    )
    with client:
        for advisory_id, assets in by_advisory.items():
            _download_advisory_assets(
                conn, client, data_dir, advisory_id, assets,
                max_asset_bytes, counts,
            )
    logger.info(
        "Download complete: %d downloaded, %d failed, %d skipped",
        counts["downloaded"], counts["failed"], counts["skipped"],
    )
    return counts
