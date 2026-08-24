# Threat2Signal

CTI pipeline that ingests threat advisories from national/international sources plus Microsoft's MSRC vulnerability feed, extracts structured intelligence (IOCs, behaviors, detection rules, MITRE mappings), and serves everything through a web dashboard.

SQLite is the single source of truth. The dashboard is read-only against it. A Neo4j graph projection is planned but not yet implemented.

## Data Sources

| Source | What It Pulls | Discovery Method |
|---|---|---|
| CISA | AA (joint agency reports) and AR (malware analysis reports) advisories | Sitemap XML diffing against `<lastmod>` |
| ACSC | Australian Cyber Security Centre alerts and advisories | RSS feeds + listing page scraping |
| JPCERT/CC | JPCERT Eyes blog posts (malware and incident categories) | Atom feed + category pages |
| ORKL | Threat reports from the ORKL CTI library | Paginated REST API |
| MSRC | Microsoft CVEs with full CVRF enrichment | RSS feed + CVRF v2/v3 APIs |
| CISA KEV | Known Exploited Vulnerabilities catalog | JSON feed (used for MSRC scoring) |

## Extraction Pipeline

Each advisory goes through two extraction phases, run via the `extract` CLI command:

**Parse phase** (deterministic, no LLM): Scrapes the advisory HTML for detection rules (YARA with compile-time validation, Sigma, Snort), ATT&CK and D3FEND technique IDs, CVE references, and IOCs across 17+ formats (hashes, IPs, domains, URLs, email addresses, file paths, mutexes, registry keys, etc.). Extracts from tables, code blocks, bullet lists, and inline text. Produces an `enriched_body` with highlighted IOCs, linked technique IDs, and rewritten image URLs.

**Intel phase** (LLM via DeepSeek): Sends the advisory text to DeepSeek with a structured JSON schema prompt. Extracts behaviors with MITRE technique mappings and confidence levels, additional threat actors and malware families, targeted sectors, and IOCs that the deterministic parser missed. All LLM-extracted IOCs pass through a four-stage validation pipeline: format check, allowlist filtering, source-presence verification, and classification. Results are deduplicated against parse-phase findings.

Raw LLM responses are saved to `data/llm_responses/` for auditability. LLM telemetry (tokens, cost, latency) is tracked per call.

## MSRC Scoring

Every MSRC CVE gets two independent scores computed from a YAML-driven config (`config/scoring.yaml`):

**Defense Score** -- Prioritizes CVEs by defensive urgency. Weights component criticality (kernel, Hyper-V, LDAP, RDP rank highest), CWE severity class, impact type (RCE > EoP > SFB > InfoDisc > DoS), CVSS attack vector and privilege requirements, and bonuses for active exploitation, KEV listing, or customer-action-required flags.

**VR (Vulnerability Research) Score** -- Prioritizes CVEs by research tractability. Weights components by fuzzer-friendliness and diffability (Win32k, CLFS, parser components rank highest), memory-corruption CWE classes, and applies bonuses for unproven exploits (novel targets) while penalizing already-exploited CVEs. Tags CVEs with research-relevant labels: `mem_corrupt`, `kernel`, `remote_preauth`, `scope_change`, `novel`, `patchable`, `high_impact`, `info_leak`.

Both scores map to priority tiers (HIGH/MEDIUM/LOW/NOISE for defense; PRIME/HIGH/MEDIUM/LOW for VR). An ignore list filters out non-Windows components (Azure Linux, Chromium, Android, etc.).

## Web Dashboard

React 19 + TypeScript frontend served by FastAPI. JWT authentication.

### Feed (Home)

Paginated advisory list with filters for source, type, extraction status, and triage status (unread/reviewed/flagged). Stats header shows advisory counts by source, extraction progress, last poll time, and cumulative LLM cost. New advisories are highlighted since last visit.

### Advisory Detail

Two-column layout with tabbed content:

- **Overview**: Metadata, threat actors, malware families, targeted sectors, and the full enriched article body. IOC values and MITRE technique IDs in the article text have hover popovers showing validation status and cross-reference counts. Linked CVEs table at the bottom.
- **Behaviors**: Behaviors grouped by ATT&CK tactic in kill-chain order, filterable by confidence level (Stated/Extracted/Inferred).
- **IOCs**: Searchable table with type, value, context, source, validation status, and cross-advisory reference count. Bulk export to CSV or STIX 2.1.
- **Detection Rules**: Collapsible cards grouped by format (YARA/Sigma/Snort) with syntax highlighting, validation status, and copy buttons.
- **Analysis**: On-demand LLM analysis results (see the Analyze button section below).
- **Source HTML**: Raw article body and extracted JSON for debugging.

Sidebar shows extraction telemetry, ATT&CK techniques grouped by tactic (with Navigator JSON export), linked CVEs, and downloadable assets.

Triage status (unread/reviewed/flagged) is editable from the header dropdown.

### MSRC View

Two view modes toggled at the top: **Defense** and **Research**. Each mode shows its own scoring, priority tiers, and sort order.

Filterable by priority, severity, impact type (RCE/EoP/InfoDisc/DoS/SFB/Spoofing/Tampering), and exploit status (KEV/Exploited/Disclosed). Text search with debounce. All columns are sortable.

Stats header shows total CVEs, by-priority breakdown (adapts to the active view mode), KEV-listed count, exploited-in-wild count, and last poll time.

Clicking a CVE row opens a slide-out detail panel showing: defense and VR score breakdowns as stacked bar charts, CVSS vector decomposition, exploit status flags, KEV details, KB patch list, linked advisories, and customer action text.

Full CVE detail page (`/msrc/:cveId`) adds related CVEs (same component), external links (MSRC, NVD, MITRE, CWE), and data freshness timestamps.

### The Analyze Button

The Analyze button appears in the advisory detail page header. It triggers an on-demand LLM analysis that produces tactical and strategic intelligence from the advisory content. This is separate from the extraction pipeline -- extraction pulls out raw data (IOCs, rules, techniques); analysis interprets that data for defensive operations.

What happens when you click it:

1. The button sends `POST /api/advisories/{id}/analysis` to the backend.
2. The backend converts the advisory HTML to markdown, strips redundant sections (IOC tables, MITRE tables, boilerplate), and sends it to DeepSeek with a structured prompt requesting purple-team analysis.
3. DeepSeek returns a JSON response containing five sections of analysis.
4. The backend validates the response: checks MITRE technique IDs against the local database, verifies gap-quote strings against the actual advisory text, and validates detection-rule references against extracted rule names.
5. Results are cached in the `advisory_analysis` table. Subsequent visits load from cache instantly.

The analysis result has five tabs in the UI:

- **Red Team**: Adversary activity cards with MITRE technique tags, execution references (Atomic Red Team tests, Sigma rules, tools), and priority badges.
- **Blue Team**: Detection gap quotes pulled from the advisory text, with verification indicators showing whether the quote actually appears in the source. Detection rule cross-references.
- **Purple Team**: Exercise table ordered by kill chain, with tiered success criteria per exercise.
- **Findings**: Incident lessons and capability gap assessments.
- **Security Posture**: Recommendations grouped by category, with maturity level ratings (foundational/intermediate/advanced) and key-insight callouts.

Re-analysis is possible (warns about ~$0.02 cost). A stale-analysis banner appears when the prompt version has changed since the last run.

### IOC Search

Cross-advisory IOC search. Accepts hashes, IPs, domains, URLs, and email addresses. Auto-detects the IOC type from input and handles defanged notation (`hxxps://`, `[dot]`, `[.]`). Results show every advisory containing that IOC, with context quotes, actors, and malware tags. Bulk export to CSV or STIX 2.1.

### Placeholder Pages

Technique Matrix, Graph Explorer, Detection Rules (cross-advisory), and Actors & Malware views exist as placeholder pages. Per-advisory detection rules are already viewable in the advisory detail tabs.

## CLI Commands

Run with `python -m threat2signal <command>`.

| Command | What It Does |
|---|---|
| `init-db` | Create SQLite schema and run migrations |
| `status` | Print advisory counts and extraction stats |
| `backfill-cisa` | Backfill CISA advisories from sitemap (batched, rate-limited) |
| `backfill-acsc` | Backfill ACSC advisories |
| `backfill-jpcert` | Backfill JPCERT/CC blog posts |
| `backfill-orkl` | Backfill ORKL threat reports |
| `poll-msrc` | Poll MSRC RSS for new CVEs |
| `backfill-msrc` | Backfill MSRC CVEs from CVRF bulk data for a specific month |
| `poll-kev` | Poll CISA KEV catalog |
| `import-advisory` | Import an advisory from a local HTML file |
| `extract` | Run extraction (`--phase parse`, `--phase intel`, or `--phase all`) on `--advisory ID` or `--all` |
| `analyze` | Run on-demand LLM analysis for an advisory |
| `download-assets` | Download pending advisory assets (figures, PDFs, STIX, Sigma) |
| `rescore` | Recompute defense and VR scores for all MSRC CVEs |
| `reimport-cache` | Drop and re-ingest all advisories from HTML cache on disk |
| `serve` | Start the FastAPI dashboard (default `localhost:8001`) |
| `hash-password` | Generate bcrypt hash for auth config |
| `generate-secret` | Generate a random JWT secret key |

## Setup

Requires Python 3.12+.

1. Copy `config/settings.yaml.example` to `config/settings.yaml` and fill in:
   - `deepseek.api_key` -- for LLM extraction and analysis
   - `auth.secret_key` -- run `python -m threat2signal generate-secret`
   - `auth.users[0].password_hash` -- run `python -m threat2signal hash-password`
   - Default credentials: `admin` / `admin`

2. Initialize the database:
   ```bash
   python -m threat2signal init-db
   ```

3. Run an initial backfill (CISA example, 10 advisories at a time):
   ```bash
   python -m threat2signal backfill-cisa --batch-size 10 --delay 10
   ```

4. Run extraction on ingested advisories:
   ```bash
   python -m threat2signal extract --phase all --all
   ```

5. Start the dashboard:
   ```bash
   python -m threat2signal serve
   ```

The frontend dev server (Vite) runs separately from `frontend/` and proxies API calls to the backend on port 8001.

## Dependencies

Python: httpx, curl_cffi, FastAPI, uvicorn, beautifulsoup4, lxml, openai (for DeepSeek API), yara-python, pyyaml, pyjwt, bcrypt, passlib.

Frontend: React 19, TypeScript, Vite, @tanstack/react-query, react-router-dom v7, dompurify.

