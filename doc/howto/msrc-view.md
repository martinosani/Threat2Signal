# MSRC View

The MSRC View tracks Microsoft Security Response Center CVEs. It pulls data from MSRC's RSS feed and CVRF bulk API, scores each CVE, and shows everything in a sortable, filterable table.

## Data ingestion

Poll the RSS feed for new CVEs:

```
python -m threat2signal.cli poll-msrc
```

Backfill older Patch Tuesday months (format: `YYYY-Mon`):

```
python -m threat2signal.cli backfill-msrc 2026-Jun 2026-Jul
```

The daily poll (`python -m threat2signal.cli poll`) also runs MSRC automatically.

## Two views: Defense and Research

Toggle between them with the buttons above the table.

**Defense view** is for blue teams. Each CVE gets a defense score based on:
- Component criticality (kernel, Exchange, etc.)
- Impact type (RCE scores highest, spoofing lowest)
- Attack vector and complexity (network + no auth = bad)
- CWE weight (use-after-free, heap overflow score high)
- Bonuses for KEV listing, active exploitation, customer action required

Priority tiers from the defense score: HIGH (80+), MEDIUM (45-79), LOW (15-44), NOISE (<15).

**Research view** is for VR/offensive. Scores weight things differently:
- Fuzzer-friendly components (Win32k, CLFS, Print Spooler, TCP/IP)
- Bug class attractiveness (memory corruption > logic bugs)
- Exploit complexity signals from CVSS vector
- Tags like `memory-corruption`, `no-auth`, `kernel-mode`, `diffable`

Research priority adds a PRIME tier above HIGH for the most interesting targets.

## Sorting

Click any column header to sort. Click again to reverse. Sortable columns: Priority, CVE ID, Severity, CVSS, Score, Released.

Priority sorts by severity order (HIGH > MEDIUM > LOW > NOISE), not alphabetically. Same for Severity (Critical > Important > Moderate > Low).

## Filters

All filters are in the bar above the table. They stack (AND logic).

- **Priority** -- HIGH, MEDIUM, LOW, NOISE (or PRIME in Research view). Multi-select.
- **Severity** -- Critical, Important, Moderate, Low. Multi-select.
- **Impact** -- RCE, EoP, Info Disclosure, DoS, SFB, Spoofing, Tampering. Multi-select.
- **Exploit Status** -- KEV Listed, Exploited in Wild, Publicly Disclosed. Multi-select.
- **Search** -- free text, matches CVE ID or title. Debounced 300ms.

"Clear filters" resets everything.

## CVE detail

Click a row to open the slide-out panel on the right. It shows:
- Both score breakdowns (defense + research) with per-factor contributions
- Severity, impact, CVSS base/temporal, full CVSS vector
- Exploit flags (KEV, exploited, disclosed)
- Component and CWE
- Description

Click the CVE ID link to open the full detail page. From there you also get:
- Research tags with explanations
- KB article list (patches)
- Links to MSRC, NVD, and MITRE pages
- Advisory cross-references (if the CVE appears in a CISA/ACSC/JPCERT advisory)

## Rescoring

If you edit `config/scoring.yaml` (thresholds, component weights, ignore list), recompute all scores:

```
python -m threat2signal.cli rescore
```

## Ignored components

Some components are filtered out during ingestion (not scored, not stored). Defined in `config/scoring.yaml` under `ignore_list`. Currently: Azure Linux, Chromium, Android, iOS, Linux Kernel, Mariner.

## Stats bar

The collapsible header at the top shows: total CVEs, breakdown by priority tier, KEV count, exploited-in-wild count, and time since last poll.
