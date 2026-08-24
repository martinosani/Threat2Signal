# Feed View

The Feed is the main page. It lists all ingested advisories from CISA, ACSC, JPCERT, and ORKL in a single table. Navigate to it from the sidebar under Intelligence > Feed.

![Feed View](images/Feed%20View.png)

## Stats header

Collapsible bar at the top. Shows total advisories, count per source, extraction progress (done/processing/issues), last poll time, and LLM cost breakdown when available.

In the screenshot above you can see 21 total advisories split across ACSC (6), CISA (6), JPCERT (4), and ORKL (5). The extraction column on the right shows all 21 are Done. Last poll was about 1 hour ago. Cost and token stats are in the top-right corner.

## Advisory table

50 advisories per page. Columns: triage status, ID, source, type, title, date, extraction status. All column headers are sortable -- click to sort, click again to reverse. The current sort column gets a ▼ or ▲ indicator.

Click a row to open its detail page. New advisories (since your last visit) get a blue left border.

## Filters

Everything stacks (AND logic). All filters are in the URL, so you can bookmark or share a filtered view.

**Triage** -- toggle chips: Unread, Flagged, Reviewed.

**Source** -- multi-select dropdown: CISA, ACSC, JPCERT, ORKL.

**Type** -- multi-select dropdown: Cybersecurity Advisory, Analysis Report, Advisory, CTI Report, JPCERT Blog.

**Extraction status** -- toggle chips: Ready (green), Processing (blue), Issues (amber), Skipped (gray).

"Clear filters" resets everything.

---

# Advisory Detail

Two-column layout: tabbed content on the left, sidebar on the right. The sidebar hides when the Analysis tab is active to give it full width.

![Advisory Detail View](images/Advisory%20Detail%20View.png)

The header shows the advisory title, source badge, type, publication date, a link to the original, and the extraction status. On the right: triage dropdown and the Analyze/Re-analyze button.

## Sidebar

**Extraction telemetry** -- status, IOC count, rules count, techniques count, D3FEND count, extraction timestamp, model used, token counts (in/out), latency, cost.

**MITRE ATT&CK** -- techniques grouped by tactic in kill-chain order. Each technique shows ID, name, and count. "Export Navigator" button downloads a Navigator JSON layer file you can load in the ATT&CK Navigator.

**Linked CVEs** -- CVE IDs found in the advisory. MSRC CVEs link to the MSRC detail page with defense score. Others link to NVD.

**Assets** -- downloadable files (figures, PDFs, STIX bundles).

## Tabs

Switch with clicks or keyboard shortcuts 1-6. Tabs show a count badge when they have data.

### Overview (1)

Top section: metadata cards for advisory information (title, date), threat actors, malware/tools, and targeted sectors.

Below that: the full article body with inline annotations. Hover an IOC to see its type, value, validation status, and a copy button. Hover a MITRE technique reference to see ID, name, tactic, and a link to the MITRE page. The "Enriched" badge at the top of the article means IOC/technique annotations are active.

Bottom: table of CVEs referenced in the advisory.

### Behaviors (2)

![Behaviors tab](images/Advisory%20Detail%20View%20-%20Behaviors.png)

Extracted threat behaviors mapped to MITRE techniques. Grouped by tactic in kill-chain order (Credential Access, Command and Control, Privilege Escalation, etc.).

Filter by confidence at the top: All, Stated, Extracted, Inferred. Each card shows the behavior description, the MITRE technique ID badge (e.g. T1003.003), tactic name, and an "Extracted" label showing how it was identified.

### IOCs (3)

![IOCs tab](images/Advisory%20Detail%20View%20-%20IOCs.png)

All IOCs extracted from the advisory. The example above shows 159 IOCs from the BRICKSTORM advisory.

**Search** -- free text, matches value or context.

**Type filter chips** -- All, Hashes, Network, File Artifacts, Allowlisted, Needs Review (with count badge).

**Bulk actions** -- Copy All, Export CSV, Export STIX 2.1.

Table columns: type (MD5, SHA1, SHA256, SHA512, SSDEEP, etc.), value (monospace + copy button), context, source (Stated/Extracted/Parsed), validation (Verified/Suspicious/Invalid), cross-reference count.

### Detection (4)

Detection rules grouped by format: YARA, Sigma, Snort. Each rule is expandable -- click to see the syntax-highlighted rule text. Validation status shown per rule (valid/invalid). Copy per rule or copy all rules of a format at once.

### Analysis (5)

LLM-generated tactical and strategic analysis. See the separate [analysis howto](analysis.md) for details.

### Source HTML (6)

Raw view. Three sections: the original article HTML, the extracted JSON output, and LLM telemetry.

---

# Other Intelligence Pages

## Technique Matrix

Sidebar: Intelligence > Technique Matrix. Placeholder -- will show an ATT&CK matrix heatmap.

## Actors & Malware

Sidebar: Intelligence > Actors & Malware. Placeholder -- will list extracted threat actors and malware families across all advisories.
