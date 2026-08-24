# Feed View

The Feed is the main page. It lists all ingested advisories from CISA, ACSC, JPCERT, and ORKL in a single table. Navigate to it from the sidebar under Intelligence > Feed.

## Advisory table

50 advisories per page. Columns: triage status, ID, source, type, title, date, extraction status.

Click a row to open its detail page. New advisories (since your last visit) get a blue left border.

## Filters

Everything stacks (AND logic). All filters are in the URL, so you can bookmark or share a filtered view.

**Triage** -- toggle chips: Unread, Flagged, Reviewed.

**Source** -- multi-select dropdown: CISA, ACSC, JPCERT, ORKL.

**Type** -- multi-select dropdown: Cybersecurity Advisory, Analysis Report, Advisory, CTI Report, JPCERT Blog.

**Extraction status** -- toggle chips: Ready (green), Processing (blue), Issues (amber), Skipped (gray).

"Clear filters" resets everything.

## Stats header

Collapsible bar at the top. Shows total advisories, count per source, extraction progress (done/processing/issues), last poll time, and LLM cost breakdown when available.

---

# Advisory detail

Two-column layout: tabbed content on the left, sidebar on the right. The sidebar hides when the Analysis tab is active to give it full width.

## Header actions

**Triage dropdown** -- mark the advisory as Unread, Reviewed, or Flagged. Persists immediately.

**Analyze button** -- sends the advisory to DeepSeek for tactical/strategic analysis. Shows a cost confirmation (~$0.02, 5-15s). If analysis already exists, becomes "Re-analyze" with a warning dialog.

**Extraction alert** -- amber or red banner when extraction had warnings or errors. Click "Show details" to see the log.

## Sidebar

**Extraction telemetry** -- status, IOC count, rules count, techniques count, model used, token counts, latency, cost.

**MITRE ATT&CK** -- techniques grouped by tactic in kill-chain order. Each technique shows ID, name, and confidence (Stated/Extracted/Inferred). "Export Navigator" button downloads a Navigator JSON layer file.

**Linked CVEs** -- CVE IDs found in the advisory. MSRC CVEs link to the MSRC detail page with defense score. Others link to NVD.

**Assets** -- downloadable files (figures, PDFs, STIX bundles).

## Tabs

Switch with clicks or keyboard shortcuts 1-6. Tabs only appear when they have data.

### Overview (1)

Top section: title, date, summary, threat actors, malware/tools, sectors.

Below that: the full article body with inline annotations. Hover an IOC to see its type, value, validation status, and a copy button. Hover a MITRE technique reference to see ID, name, tactic, and a link to the MITRE page.

Bottom: table of CVEs referenced in the advisory.

### Behaviors (2)

Extracted threat behaviors mapped to MITRE techniques. Filter by confidence: Stated, Extracted, Inferred. Grouped by tactic in kill-chain order. Each card shows the behavior description, technique ID, and tactic.

### IOCs (3)

All IOCs extracted from the advisory.

**Search** -- free text, matches value or context.

**Type filter chips** -- All, Hashes, Network, File Artifacts, Allowlisted, Needs Review.

**Bulk actions** -- Copy All, Export CSV, Export STIX 2.1.

Table columns: type, value (monospace + copy button), context, source (Stated/Extracted/Parsed/Allowlisted), validation (valid/invalid/suspicious), cross-reference count.

### Detection (4)

Detection rules grouped by format: YARA, Sigma, Snort. Each rule is expandable -- click to see the syntax-highlighted rule text. Validation status shown per rule (valid/invalid). Copy per rule or copy all rules of a format at once.

### Analysis (5)

LLM-generated tactical and strategic analysis. Has its own sub-tabs:

**Red Team** -- attack scenarios with MITRE mappings, priority levels, execution references (Atomic Red Team, Sigma, tools).

**Blue Team** -- defensive gaps found in the advisory. Each card shows the gap, interpretation, MITRE techniques, validation method, and detection rule references.

**Purple Team** -- exercise table mapping red actions to blue countermeasures along the kill chain. Columns: phase, exercise, red action, blue measures, techniques, success criteria.

**Findings** -- incident lessons or capability gaps with impact and recommendations.

**Security Posture** -- strategic assessment cards grouped by category. Each shows priority, maturity level (Foundational/Intermediate/Advanced), key insight, gap analysis, and framework references.

Each sub-tab has its own filters (priority, maturity, detection coverage).

Shows metadata at the bottom: model, timestamp, tokens, latency, cost. Stale analysis banner appears when the advisory was re-extracted after the analysis was generated.

### Source HTML (6)

Raw view. Three sections: the original article HTML, the extracted JSON output, and LLM telemetry.

---

# Other Intelligence pages

## Technique Matrix

Sidebar: Intelligence > Technique Matrix. Placeholder for now -- will show an ATT&CK matrix view once extraction populates technique data.

## Actors & Malware

Sidebar: Intelligence > Actors & Malware. Placeholder -- will list extracted threat actors and malware families across all advisories.
