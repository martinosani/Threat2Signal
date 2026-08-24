"""FastAPI dashboard backend for advisory browsing and analysis."""

import asyncio
import csv
import io
import json
import logging
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx as httpx_lib
import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from threat2signal import config
from threat2signal.auth import (
    create_token,
    find_user,
    hash_password,
    validate_token,
    verify_password,
)
from threat2signal.config import validate_auth_config
from threat2signal.ingest import http as asset_http
from threat2signal.ingest.asset_downloader import detect_content_type
from threat2signal.analysis.analyzer import analyze_advisory_fresh, _PROMPT_VERSION
from threat2signal.analysis.msrc_scorer import (
    compute_defense_score,
    compute_vr_score,
    load_scoring_config,
)
from threat2signal.storage import db
from threat2signal.analysis.ioc_validator import detect_ioc_type, refang_value

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Guards against duplicate analysis: advisory IDs currently being analyzed
_analysis_in_progress: set[str] = set()
_analysis_lock = asyncio.Lock()

_VALID_TRIAGE_STATUSES = frozenset({"unread", "reviewed", "flagged"})

_IOC_STIX_PATTERNS: dict[str, str] = {
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "sha512": "[file:hashes.'SHA-512' = '{value}']",
    "ssdeep": "[file:hashes.SSDEEP = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "filename": "[file:name = '{value}']",
    "filepath": "[file:name = '{value}']",
    "mutex": "[mutex:name = '{value}']",
}

_CONFIDENCE_COLORS: dict[str, str] = {
    "advisory_stated": "#4caf50",
    "llm_extracted": "#ffeb3b",
    "llm_inferred": "#ff9800",
}
_DEFAULT_CONFIDENCE_COLOR = "#66b2ff"

_CSV_INJECTION_CHARS = frozenset("=+-@\t\r")


class TriageUpdate(BaseModel):
    """Request body for triage status updates."""

    status: str


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Initialize database connection on startup, close on shutdown."""
    settings = config.load_settings()
    raw = settings["database"]["path"]
    db_path = str(PROJECT_ROOT / raw)
    conn = db.get_connection(db_path)
    db.init_schema(conn)
    app.state.db_conn = conn
    app.state.db_path = db_path
    app.state.settings = settings
    validate_auth_config(settings)
    app.state.scoring_config = load_scoring_config(
        str(PROJECT_ROOT / "config" / "scoring.yaml"),
    )
    # follow_redirects=False: the asset proxy fetches attacker-influenced URLs, so
    # a redirect must not silently escape the SSRF host allowlist (WS-7 C10).
    proxy_client = httpx_lib.AsyncClient(
        follow_redirects=False,
        timeout=30.0,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Threat2Signal/1.0)"},
    )
    app.state.proxy_client = proxy_client
    logger.info("Dashboard database ready at %s", db_path)
    yield
    await proxy_client.aclose()
    conn.close()
    logger.info("Dashboard database connection closed")


_PUBLIC_PATHS = frozenset({"/api/auth/login"})
# Pre-computed hash so login always runs bcrypt even for unknown usernames
_DUMMY_HASH = hash_password("dummy-timing-equalizer")


def _extract_bearer_token(request: Request) -> str:
    """Extract token from Authorization: Bearer header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return auth_header[7:]


async def require_auth(request: Request) -> None:
    """Reject unauthenticated requests. Only /api/auth/login is exempt."""
    if request.url.path in _PUBLIC_PATHS:
        return
    auth_cfg = request.app.state.settings["auth"]
    token = _extract_bearer_token(request)
    try:
        validate_token(token, auth_cfg["secret_key"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


app = FastAPI(
    title="Threat2Signal Dashboard",
    lifespan=_lifespan,
    dependencies=[Depends(require_auth)],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -- Authentication --------------------------------------------------------


class LoginRequest(BaseModel):
    """Credentials for authentication."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Successful authentication result."""
    token: str
    user: dict


@app.post("/api/auth/login")
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    """Authenticate user and return JWT."""
    auth_cfg = request.app.state.settings["auth"]
    user = find_user(body.username, auth_cfg["users"])
    # Always run bcrypt to prevent timing side-channel username enumeration
    target_hash = user["password_hash"] if user else _DUMMY_HASH
    password_ok = verify_password(body.password, target_hash)
    if user is None or not password_ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(
        user["username"],
        user["role"],
        auth_cfg["secret_key"],
        auth_cfg.get("token_expiry_hours", 24),
    )
    return LoginResponse(
        token=token,
        user={"username": user["username"], "role": user["role"]},
    )


# -- Advisory lookup helper ---------------------------------------------------


def _get_advisory_or_404(
    conn: sqlite3.Connection, numeric_id: int,
) -> dict:
    """Look up advisory by numeric id; raise 404 if missing."""
    row = db.get_advisory_by_numeric_id(conn, numeric_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return row


# -- Advisory endpoints --------------------------------------------------------

# Canonical extraction-status filter group keys (WS-7 C5). The frontend SENDS
# these group keys; expansion to raw statuses happens server-side. Unknown
# values still pass through as literal statuses via _expand_filter_aliases.
_EXTRACTION_GROUPS: dict[str, str] = {
    "ready": "completed",
    "processing": "pending,parse_done",
    "issues": "parse_partial,parse_failed,failed",
    "skipped": "skipped",
}


def _expand_filter_aliases(
    value: str | None, groups: dict[str, str],
) -> str | None:
    """Expand group aliases in a potentially comma-separated filter value."""
    if value is None:
        return None
    parts = [v.strip() for v in value.split(",") if v.strip()]
    expanded = [groups.get(p, p) for p in parts]
    return ",".join(expanded)


@app.get("/api/advisories")
async def list_advisories(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    source: str | None = None,
    type: str | None = None,
    extraction_status: str | None = None,
    triage_status: str | None = None,
    scrape_status: str | None = "scraped",
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
):
    """Return paginated advisory listing with optional filters."""
    resolved_extraction = _expand_filter_aliases(
        extraction_status, _EXTRACTION_GROUPS,
    )
    return db.get_advisories_page(
        request.app.state.db_conn,
        page=page, per_page=per_page, source=source,
        advisory_type=type, extraction_status=resolved_extraction,
        triage_status=triage_status, date_from=date_from,
        date_to=date_to, search=search, scrape_status=scrape_status,
    )


@app.get("/api/advisories/{id}")
async def get_advisory_detail(id: int, request: Request):
    """Return full advisory detail with enrichment data."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    advisory_id = row["advisory_id"]
    row.pop("raw_html", None)
    row.update(_build_item_counts(conn, advisory_id))
    row["sectors"] = db.get_advisory_sectors(conn, advisory_id)
    row["actors"] = db.get_advisory_actors(conn, advisory_id)
    row["malware"] = db.get_advisory_malware(conn, advisory_id)
    row["extraction_issues"] = _build_extraction_summary(conn, advisory_id)
    return row


@app.get("/api/advisories/{id}/cves")
async def get_advisory_cves(id: int, request: Request):
    """Return CVEs linked to an advisory."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    return db.get_advisory_cves(conn, row["advisory_id"])


@app.get("/api/advisories/{id}/behaviors")
async def get_advisory_behaviors(id: int, request: Request):
    """Return behaviors extracted for an advisory."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    return db.get_advisory_behaviors(conn, row["advisory_id"])


# -- Analysis endpoints --------------------------------------------------------

@app.get("/api/advisories/{id}/analysis")
async def get_advisory_analysis(
    id: int,
    request: Request,
    analysis_type: str = Query("purple_team"),
):
    """Return cached analysis-phase result for an advisory."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    advisory_id = row["advisory_id"]
    result = db.get_analysis(conn, advisory_id, analysis_type)
    if result is None:
        raise HTTPException(
            status_code=404, detail="No analysis found for this advisory",
        )
    try:
        result["analysis"] = json.loads(result.pop("analysis_json"))
    except (json.JSONDecodeError, TypeError):
        result["analysis"] = result.pop("analysis_json", None)
    # Strip internal fields not needed by the frontend
    result.pop("user_context", None)
    result.pop("id", None)
    stale = False
    stale_reason = None
    stored_version = result.get("prompt_version")
    # Pre-WS-12 analyses have NULL prompt_version; treat them as v1
    effective_version = stored_version if stored_version is not None else 1
    if effective_version < _PROMPT_VERSION:
        stale = True
        stale_reason = f"Analysis was generated with prompt v{effective_version}, current is v{_PROMPT_VERSION}"
    result["stale"] = stale
    result["stale_reason"] = stale_reason
    return result


@app.post("/api/advisories/{id}/analysis")
async def trigger_analysis(
    id: int,
    request: Request,
    force: bool = Query(False),
):
    """Trigger analysis-phase processing via the analyzer module."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    advisory_id = row["advisory_id"]
    settings = request.app.state.settings
    db_path = request.app.state.db_path

    _guard_redundant_analysis(conn, advisory_id, force)
    await _guard_concurrent_analysis(advisory_id)

    logger.info("Analysis started for %s (force=%s)", advisory_id, force)
    try:
        result = await _execute_analysis(db_path, advisory_id, settings)
        logger.info("Analysis completed for %s", advisory_id)
        result["prompt_version"] = _PROMPT_VERSION
        result["stale"] = False
        result["stale_reason"] = None
        return result
    except ValueError as exc:
        logger.warning("Analysis validation error for %s: %s", advisory_id, exc)
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Analysis failed for %s", advisory_id)
        raise HTTPException(status_code=500, detail="Analysis failed")
    finally:
        _analysis_in_progress.discard(advisory_id)
        logger.info("Analysis lock released for %s", advisory_id)


def _guard_redundant_analysis(
    conn: sqlite3.Connection, advisory_id: str, force: bool,
) -> None:
    """Reject if a current-version analysis already exists (unless forced)."""
    if force:
        return
    existing = db.get_analysis(conn, advisory_id, "purple_team")
    if existing is None:
        return
    stored_version = existing.get("prompt_version")
    effective = stored_version if stored_version is not None else 1
    if effective >= _PROMPT_VERSION:
        raise HTTPException(
            status_code=409,
            detail="Analysis is already up-to-date. Use force=true to re-analyze.",
        )


async def _guard_concurrent_analysis(advisory_id: str) -> None:
    """Reject if this advisory is already being analyzed."""
    async with _analysis_lock:
        if advisory_id in _analysis_in_progress:
            logger.warning("Concurrent analysis rejected for %s", advisory_id)
            raise HTTPException(
                status_code=409,
                detail="Analysis is already in progress for this advisory.",
            )
        _analysis_in_progress.add(advisory_id)
        logger.info("Analysis lock acquired for %s", advisory_id)


async def _execute_analysis(
    db_path: str, advisory_id: str, settings: dict,
) -> dict:
    """Run the blocking LLM analysis in a threadpool worker."""
    def _run() -> dict:
        worker_conn = db.get_connection(db_path)
        try:
            return analyze_advisory_fresh(worker_conn, advisory_id, settings)
        finally:
            worker_conn.close()
    return await run_in_threadpool(_run)


# -- Triage endpoint -----------------------------------------------------------

@app.patch("/api/advisories/{id}/triage")
async def update_triage(
    id: int, body: TriageUpdate, request: Request,
):
    """Update triage status for an advisory."""
    if body.status not in _VALID_TRIAGE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Must be one of: "
                   f"{', '.join(sorted(_VALID_TRIAGE_STATUSES))}",
        )
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    advisory_id = row["advisory_id"]
    updated = db.update_triage_status(conn, advisory_id, body.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return {"id": id, "advisory_id": advisory_id, "triage_status": body.status}


# -- MSRC CVE endpoints -------------------------------------------------------

@app.get("/api/msrc/cves")
async def list_msrc_cves(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    sort: str = Query("defense_score"),
    sort_dir: str = Query("desc"),
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
):
    """Return paginated MSRC CVE listing with optional filters."""
    result = db.get_msrc_cves_page(
        request.app.state.db_conn,
        page=page, per_page=per_page,
        sort=sort, sort_dir=sort_dir,
        priority=priority, impact=impact, severity=severity,
        exploit_status=exploit_status,
        component_category=component_category,
        cwe_id=cwe_id,
        date_from=date_from, date_to=date_to,
        has_advisory=has_advisory, customer_action=customer_action,
        search=search, vr_priority=vr_priority,
    )
    for item in result["items"]:
        if isinstance(item.get("vr_tags"), str):
            try:
                item["vr_tags"] = json.loads(item["vr_tags"])
            except (json.JSONDecodeError, TypeError):
                item["vr_tags"] = []
    return result


@app.get("/api/msrc/cves/{cve_id}")
async def get_msrc_cve_detail(cve_id: str, request: Request):
    """Return full CVE detail with KB entries, KEV status, advisories, and score breakdown."""
    conn = request.app.state.db_conn
    cve = db.get_msrc_cve(conn, cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail="CVE not found")

    # Enrich with related data
    cve["kb_entries"] = db.get_kb_entries(conn, cve_id)
    cve["kev"] = db.get_kev_entry(conn, cve_id)
    cve["kev_listed"] = cve["kev"] is not None
    cve["advisories"] = db.get_cve_advisories(conn, cve_id)

    # Compute score breakdowns from stored data
    kev_ids = db.get_kev_cve_ids(conn)
    scoring_config = request.app.state.scoring_config
    _, _, breakdown = compute_defense_score(cve, kev_ids, scoring_config)
    cve["score_breakdown"] = breakdown
    cve["has_kb_entries"] = len(cve.get("kb_entries", [])) > 0
    _, _, vr_breakdown = compute_vr_score(cve, kev_ids, scoring_config)
    cve["vr_score_breakdown"] = vr_breakdown
    if isinstance(cve.get("vr_tags"), str):
        try:
            cve["vr_tags"] = json.loads(cve["vr_tags"])
        except (json.JSONDecodeError, TypeError):
            cve["vr_tags"] = []

    cve["related_cves"] = db.get_related_cves(
        conn, cve_id, cve.get("component"),
    )
    cve.pop("raw_json", None)

    return cve


@app.get("/api/msrc/stats")
async def get_msrc_stats(request: Request):
    """Return MSRC-specific statistics."""
    return db.get_msrc_stats(request.app.state.db_conn)


# -- Stats endpoint ------------------------------------------------------------

@app.get("/api/stats")
async def get_stats(request: Request):
    """Return system-wide statistics."""
    stats = db.get_stats(request.app.state.db_conn)
    stats["msrc"] = db.get_msrc_stats(request.app.state.db_conn)
    return stats


@app.get("/api/stats/llm")
async def get_llm_stats_endpoint(request: Request):
    """Return aggregate LLM telemetry for the dashboard stats card."""
    try:
        return db.get_llm_stats(request.app.state.db_conn)
    except sqlite3.OperationalError:
        return {
            "call_count": 0, "total_cost": 0.0,
            "total_input_tokens": 0, "total_output_tokens": 0,
            "avg_cost_per_advisory": 0.0, "calls_by_phase": {},
        }


# -- Extraction & enrichment helpers -------------------------------------------


def _build_item_counts(
    conn: sqlite3.Connection, advisory_id: str,
) -> dict[str, int]:
    """Count extracted items across tables for an advisory."""
    return {
        "ioc_count": db.count_iocs(conn, advisory_id),
        "detection_rule_count": db.count_detection_rules(conn, advisory_id),
        "technique_count": db.count_advisory_techniques(
            conn, advisory_id, framework="attack",
        ),
        "d3fend_count": db.count_advisory_techniques(
            conn, advisory_id, framework="d3fend",
        ),
        "asset_count": db.count_advisory_assets(conn, advisory_id),
        # Count ALL linked CVEs (advisory_cve), not just msrc-enriched ones.
        "cve_count": db.count_advisory_cves(conn, advisory_id),
        "behavior_count": db.count_behaviors(conn, advisory_id),
    }


def _build_extraction_summary(
    conn: sqlite3.Connection, advisory_id: str,
) -> dict[str, int]:
    """Summarize extraction log warnings and errors for an advisory."""
    counts = db.get_extraction_log_severity_counts(conn, advisory_id)
    return {"warning_count": counts["warning"], "error_count": counts["error"]}


def _sanitize_csv_value(val: str) -> str:
    """Prefix formula-injection characters to neutralize spreadsheet execution."""
    if val and val[0] in _CSV_INJECTION_CHARS:
        return f"'{val}"
    return val


def _build_ioc_csv(iocs: list[dict]) -> str:
    """Serialize IOC list to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["type", "value", "context", "validation_status", "source_verified"],
    )
    for ioc in iocs:
        writer.writerow([
            _sanitize_csv_value(str(ioc.get("type", ""))),
            _sanitize_csv_value(str(ioc.get("value", ""))),
            _sanitize_csv_value(str(ioc.get("context", ""))),
            _sanitize_csv_value(str(ioc.get("validation_status", ""))),
            str(ioc.get("source_verified", "")),
        ])
    return output.getvalue()


def _stix_pattern_for_ioc(ioc_type: str, value: str) -> str:
    """Return STIX 2.1 pattern string for a given IOC type and value."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    if ioc_type == "ip":
        # STIX distinguishes ipv4-addr from ipv6-addr; a ':' in the value marks IPv6.
        addr_type = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{addr_type}:value = '{escaped}']"
    template = _IOC_STIX_PATTERNS.get(ioc_type)
    if template is None:
        return f"[artifact:payload_bin = '{escaped}']"
    return template.format(value=escaped)


def _build_ioc_stix_bundle(iocs: list[dict]) -> dict:
    """Build a STIX 2.1 bundle from IOC list."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []
    for ioc in iocs:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"{ioc.get('type', 'unknown')}: {ioc.get('value', '')}",
            "pattern": _stix_pattern_for_ioc(
                ioc.get("type", ""), ioc.get("value", ""),
            ),
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _normalize_navigator_tactic(tactic: str | None) -> str | None:
    """Normalize a tactic label to ATT&CK shorthand, or None if unusable.

    Navigator matches on tactic shorthand ("defense-evasion"), not the display
    name ("Defense Evasion"); an un-normalized tactic silently fails to bind.
    """
    if not tactic:
        return None
    return tactic.strip().lower().replace(" ", "-")


def _build_navigator_layer(
    techniques: list[dict], advisory_id: str,
) -> dict:
    """Build ATT&CK Navigator JSON layer from enterprise technique list.

    ICS techniques (T0xxx) belong to the ics-attack domain and never render in
    an enterprise-attack layer, so they are filtered out here.
    """
    tech_entries = []
    for tech in techniques:
        technique_id = tech["technique_id"]
        if technique_id.upper().startswith("T0"):
            continue
        confidence = tech.get("confidence", "")
        color = _CONFIDENCE_COLORS.get(confidence, _DEFAULT_CONFIDENCE_COLOR)
        entry = {
            "techniqueID": technique_id,
            "color": color,
            "comment": tech.get("use_description", ""),
            "enabled": True,
        }
        # Omit tactic entirely rather than emit an unmatched raw display name.
        tactic = _normalize_navigator_tactic(tech.get("tactic"))
        if tactic:
            entry["tactic"] = tactic
        tech_entries.append(entry)
    # Navigator tolerates an absent versions block and infers a current default;
    # omit it rather than pin a stale ATT&CK version that mismatches technique refs.
    return {
        "name": f"{advisory_id} - ATT&CK Coverage",
        "versions": {"navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques from advisory {advisory_id}",
        "techniques": tech_entries,
    }


# -- Group E endpoints --------------------------------------------------------


@app.get("/api/advisories/{id}/iocs")
async def get_advisory_iocs(
    id: int, request: Request, type: str | None = None,
):
    """Return IOCs for an advisory with cross-reference counts."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    advisory_id = row["advisory_id"]
    iocs = db.get_iocs(conn, advisory_id, type_filter=type)
    cross_refs = db.bulk_ioc_cross_refs(conn, advisory_id)
    for ioc in iocs:
        ioc["cross_ref_count"] = cross_refs.get((ioc["type"], ioc["value"]), 0)
    return iocs


@app.get("/api/advisories/{id}/iocs/export")
async def export_iocs(
    id: int,
    request: Request,
    format: str = Query("csv"),
    type: str | None = None,
    validation_status: str | None = None,
):
    """Export IOCs in CSV or STIX 2.1 format."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    advisory_id = row["advisory_id"]
    iocs = db.get_iocs(conn, advisory_id, type_filter=type)
    if validation_status is not None:
        iocs = [i for i in iocs if i.get("validation_status") == validation_status]
    if format == "stix2":
        return Response(
            content=json.dumps(_build_ioc_stix_bundle(iocs)),
            media_type="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{advisory_id}-iocs.stix.json"',
            },
        )
    if format == "csv":
        return Response(
            content=_build_ioc_csv(iocs),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{advisory_id}-iocs.csv"',
            },
        )
    raise HTTPException(status_code=422, detail="Format must be 'csv' or 'stix2'")


# -- WS-10: Cross-advisory IOC search -----------------------------------------


@app.get("/api/iocs")
async def list_iocs(
    request: Request,
    q: str | None = None,
    type: str | None = None,
    validation_status: str | None = None,
    source: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    sort: str = "cross_ref_count",
    sort_dir: str = "desc",
):
    """List or search IOCs across all advisories."""
    conn = request.app.state.db_conn
    normalized_q = None
    detected_type = None
    if q is not None:
        normalized_q = refang_value(q)
        detected_type = detect_ioc_type(normalized_q)
    result = db.get_iocs_page(
        conn, page=page, per_page=per_page,
        ioc_type=type, validation_status=validation_status,
        source=source, q=normalized_q, sort=sort, sort_dir=sort_dir,
    )
    if q is not None:
        result["query"] = {
            "original": q,
            "normalized": normalized_q,
            "detected_type": detected_type,
        }
    return result


@app.get("/api/iocs/stats")
async def get_ioc_stats_endpoint(request: Request):
    """Return aggregate IOC statistics."""
    conn = request.app.state.db_conn
    return db.get_ioc_stats(conn)


@app.get("/api/iocs/export")
async def export_iocs_global(
    request: Request,
    format: str = Query("csv"),
    q: str | None = None,
    type: str | None = None,
    validation_status: str | None = None,
    source: str | None = None,
):
    """Export filtered IOC results as CSV or STIX 2.1."""
    conn = request.app.state.db_conn
    normalized_q = refang_value(q) if q else None
    result = db.get_iocs_page(
        conn, page=1, per_page=10000,
        ioc_type=type, validation_status=validation_status,
        source=source, q=normalized_q,
    )
    iocs = result["items"]
    if format == "stix2":
        return Response(
            content=json.dumps(_build_ioc_stix_bundle(iocs)),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="iocs-search.stix.json"'},
        )
    if format == "csv":
        return Response(
            content=_build_ioc_csv(iocs),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="iocs-search.csv"'},
        )
    raise HTTPException(status_code=422, detail="Format must be 'csv' or 'stix2'")


@app.get("/api/iocs/{ioc_type}/{value:path}/advisories")
async def get_ioc_advisories(
    ioc_type: str, value: str, request: Request,
):
    """Return advisory details for a specific IOC."""
    conn = request.app.state.db_conn
    results = db.get_ioc_advisory_details(conn, ioc_type, value)
    if not results:
        raise HTTPException(status_code=404, detail="IOC not found")
    return results


@app.get("/api/advisories/{id}/detection-rules")
async def get_advisory_detection_rules(
    id: int, request: Request, format: str | None = None,
):
    """Return detection rules for an advisory with optional format filter.

    An unrecognized ``format`` is not a 422; it simply matches no rows and
    returns an empty list (the filter vocabulary is open-ended: sigma, yara, ...).
    """
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    return db.get_detection_rules(conn, row["advisory_id"], format_filter=format)


@app.get("/api/advisories/{id}/techniques")
async def get_advisory_techniques(
    id: int, request: Request, framework: str | None = None,
):
    """Return ATT&CK/D3FEND technique mappings for an advisory."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    return db.get_advisory_techniques(conn, row["advisory_id"], framework=framework)


@app.get("/api/advisories/{id}/techniques/navigator")
async def export_navigator_layer(id: int, request: Request):
    """Export ATT&CK Navigator JSON layer for an advisory."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    advisory_id = row["advisory_id"]
    techniques = db.get_advisory_techniques(
        conn, advisory_id, framework="attack",
    )
    return _build_navigator_layer(techniques, advisory_id)


@app.get("/api/advisories/{id}/assets")
async def get_advisory_asset_metadata(
    id: int, request: Request, type: str | None = None,
):
    """Return asset metadata for an advisory with optional type filter."""
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    assets = db.get_advisory_assets(conn, row["advisory_id"], type_filter=type)
    for asset in assets:
        if asset.get("download_status") == "completed" and asset.get("local_path"):
            subdir = "figures" if asset["asset_type"] == "figure" else "files"
            fname = Path(asset["local_path"]).name
            asset["url"] = f"/api/assets/{id}/{subdir}/{fname}"
    return assets


@app.get("/api/advisories/{id}/extraction-logs")
async def get_extraction_logs(
    id: int, request: Request, severity: str | None = None,
):
    """Return extraction log entries for an advisory.

    An unrecognized ``severity`` is not a 422; it matches no rows and returns an
    empty list (consistent with the other open-ended list-filter endpoints).
    """
    conn = request.app.state.db_conn
    row = _get_advisory_or_404(conn, id)
    return db.get_extraction_logs(conn, row["advisory_id"], severity=severity)


# -- Asset-serving endpoints ---------------------------------------------------

_SAFE_INLINE_TYPES = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/webp",
})

# Proxy-side safety cap. The downloader enforces its own cap at write time
# (settings); this bounds an unbounded upstream stream when we proxy live.
_MAX_PROXY_ASSET_BYTES = 25 * 1024 * 1024

# Windows treats these device names as reserved regardless of extension; a path
# segment matching one can address a device rather than a file.
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

# Served on any proxy failure so the reader shows a stable placeholder instead of
# a broken-image icon; no-cache so the browser refetches once the real asset lands.
_ASSET_PLACEHOLDER_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180" '
    'viewBox="0 0 320 180" role="img" aria-label="Image not yet available">'
    '<rect width="320" height="180" fill="#2b2b2b"/>'
    '<text x="160" y="95" fill="#bbbbbb" font-family="sans-serif" '
    'font-size="14" text-anchor="middle">Image not yet available</text></svg>'
)


def _asset_placeholder_response() -> Response:
    """Return an inline SVG placeholder for an asset that cannot be served."""
    return Response(
        content=_ASSET_PLACEHOLDER_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


def _validate_path_segments(*segments: str) -> None:
    """Reject path segments that could escape the assets directory."""
    for segment in segments:
        if (
            not segment
            or ".." in segment
            or "/" in segment
            or "\\" in segment
            or ":" in segment  # drive-relative (C:) and NTFS ADS (name::$DATA)
        ):
            raise HTTPException(status_code=400, detail="Invalid path segment")
        stem = segment.split(".", 1)[0].lower()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise HTTPException(status_code=400, detail="Invalid path segment")


def _find_asset_url(assets: list[dict], filename: str) -> str | None:
    """Match an asset record by the last path segment of its original URL."""
    for asset in assets:
        url = asset.get("original_url", "")
        url_filename = url.split("?")[0].split("#")[0].rsplit("/", 1)[-1]
        if url_filename == filename:
            return url
    return None


def _sanitize_content_type(raw: str) -> str:
    """Restrict proxied content types to a known-safe set."""
    base = raw.split(";")[0].strip().lower()
    if base in _SAFE_INLINE_TYPES:
        return base
    return "application/octet-stream"


async def _proxy_asset(
    client: httpx_lib.AsyncClient, original_url: str,
) -> Response | StreamingResponse:
    """Stream an asset from its allowlisted original URL, or a placeholder.

    original_url comes from scraped (attacker-influenced) advisory HTML, so it is
    revalidated against the SSRF allowlist here even though the downloader also
    checks it. The client follows no redirects (lifespan config), so we never
    silently escape the allowlist to an internal host.
    """
    try:
        asset_http.validate_asset_url(original_url)
    except ValueError:
        logger.warning("Refusing to proxy disallowed asset URL: %s", original_url)
        return _asset_placeholder_response()

    try:
        req = client.build_request("GET", original_url)
        resp = await client.send(req, stream=True)
        resp.raise_for_status()
    except httpx_lib.HTTPError:
        logger.warning("Upstream asset fetch failed: %s", original_url)
        return _asset_placeholder_response()

    async def stream_body():
        streamed = 0
        try:
            async for chunk in resp.aiter_bytes(chunk_size=65536):
                streamed += len(chunk)
                if streamed > _MAX_PROXY_ASSET_BYTES:
                    logger.warning(
                        "Proxied asset exceeded %d bytes, truncating: %s",
                        _MAX_PROXY_ASSET_BYTES, original_url,
                    )
                    break
                yield chunk
        finally:
            await resp.aclose()

    # Abort before streaming when the upstream declares an oversized body.
    declared = resp.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > _MAX_PROXY_ASSET_BYTES:
        await resp.aclose()
        logger.warning("Upstream asset too large (%s bytes): %s", declared, original_url)
        return _asset_placeholder_response()

    content_type = _sanitize_content_type(
        resp.headers.get("content-type", "application/octet-stream"),
    )
    return StreamingResponse(content=stream_body(), media_type=content_type)


def _asset_month(pub_date: str | None) -> str:
    """Extract YYYY-MM from a date string, falling back to current month."""
    if pub_date and len(pub_date) >= 7:
        return pub_date[:7]
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _resolve_asset(
    db_path: str, numeric_id: int, asset_subdir: str, filename: str,
) -> tuple[str, ...]:
    """Resolve an asset request to a local file or a proxy URL (blocking work).

    Runs in a threadpool: opens its own SQLite connection (the lifespan
    connection is bound to the event-loop thread) and performs the file-system
    checks. Returns ('local', path, content_type, disposition) or ('proxy', url).
    """
    conn = db.get_connection(db_path)
    try:
        row = db.get_advisory_by_numeric_id(conn, numeric_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        assets_root = (PROJECT_ROOT / "data" / "assets").resolve()
        month = _asset_month(row.get("pub_date"))
        local_path = (
            assets_root / row["source"] / month / str(numeric_id)
            / asset_subdir / filename
        )
        if local_path.resolve().is_relative_to(assets_root) and local_path.exists():
            content_type = detect_content_type(local_path)
            disposition = ""
            if content_type not in _SAFE_INLINE_TYPES:
                disposition = f'attachment; filename="{filename}"'
            return ("local", str(local_path), content_type, disposition)
        assets = db.get_advisory_assets(conn, row["advisory_id"])
        original_url = _find_asset_url(assets, filename)
        if original_url is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return ("proxy", original_url)
    finally:
        conn.close()


async def _serve_asset(
    request: Request, numeric_id: int,
    asset_subdir: str, filename: str,
) -> FileResponse | StreamingResponse | Response:
    """Serve local asset or proxy from original URL."""
    _validate_path_segments(str(numeric_id), filename)
    resolved = await run_in_threadpool(
        _resolve_asset, request.app.state.db_path,
        numeric_id, asset_subdir, filename,
    )
    if resolved[0] == "local":
        _, path, content_type, disposition = resolved
        headers = {"Content-Disposition": disposition} if disposition else {}
        return FileResponse(path, media_type=content_type, headers=headers)
    original_url = resolved[1]
    return await _proxy_asset(request.app.state.proxy_client, original_url)


@app.get("/api/assets/{id}/figures/{filename}", response_model=None)
async def serve_figure(
    id: int, filename: str, request: Request,
) -> FileResponse | StreamingResponse | Response:
    """Serve a figure image, proxying from source if not yet downloaded."""
    return await _serve_asset(request, id, "figures", filename)


@app.get("/api/assets/{id}/files/{filename}", response_model=None)
async def serve_file(
    id: int, filename: str, request: Request,
) -> FileResponse | StreamingResponse | Response:
    """Serve a downloadable file, proxying from source if not yet downloaded."""
    return await _serve_asset(request, id, "files", filename)


# -- SPA fallback --------------------------------------------------------------
# Serve built frontend when available; Vite dev proxy handles this during dev
_dist_dir = PROJECT_ROOT / "frontend" / "dist"
if _dist_dir.exists():
    app.mount("/", StaticFiles(directory=str(_dist_dir), html=True), name="spa")
