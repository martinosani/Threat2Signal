# MSRC View

The MSRC View tracks Microsoft Security Response Center CVEs. It pulls data from MSRC's RSS feed and CVRF bulk API, scores each CVE, and shows everything in a sortable, filterable table. Navigate to it from the sidebar under Intelligence > MSRC View.

## Two views: Defense and Research

Toggle between them with the buttons above the filter bar.

### Defense

![Defense view](images/MSRC%20View%20-%20Defense.png)

For blue teams and patch prioritization. Each CVE gets a defense score based on component criticality (kernel, Exchange, etc.), impact type (RCE highest, spoofing lowest), attack vector/complexity, CWE weight, and bonuses for KEV listing, active exploitation, or customer-action-required flags.

Priority tiers: HIGH (80+), MEDIUM (45-79), LOW (15-44), NOISE (<15).

The table shows: Priority, CVE ID, Title, Component, Impact, Severity, CVSS, Score, Released date, Exploited status (KEV/Exploited badges), Advisory links, and Action column.

### Research

![Research view](images/MSRC%20View%20-%20Research.png)

For vulnerability research and offensive security. Scores weight fuzzer-friendly components (Win32k, CLFS, TCP/IP, GDI+), memory-corruption CWE classes, and exploit complexity signals. Bonuses for unproven exploits (novel targets), penalties for already-exploited CVEs.

Research priority adds a **PRIME** tier above HIGH for the most attractive targets. Notice the tags column on the right: HIGH_IMPACT, KERNEL, NOVEL, SCOPE_CHANGE. These flag research-relevant properties at a glance.

## Stats bar

Collapsible header at the top. Shows total CVEs, breakdown by priority tier (adapts to the active view -- defense tiers or VR tiers), KEV-listed count, exploited-in-wild count, and time since last poll.

## Filters

All in the bar above the table. They stack (AND logic).

- **Priority** -- HIGH, MEDIUM, LOW, NOISE (plus PRIME in Research view). Multi-select.
- **Severity** -- Critical, Important, Moderate, Low. Multi-select.
- **Impact** -- RCE, EoP, Info Disclosure, DoS, SFB, Spoofing, Tampering. Multi-select.
- **Exploit Status** -- KEV Listed, Exploited in Wild, Publicly Disclosed. Multi-select.
- **Search** -- free text, matches CVE ID or title. Debounced 300ms.

## Sorting

Click any column header to sort. Click again to reverse. Priority sorts by severity order (HIGH > MEDIUM > LOW > NOISE), not alphabetically.

## CVE detail page

![CVE Detail](images/MSRC%20View%20-%20CVE%20Detail.png)

Click a CVE ID to open the full detail page. The header shows the CVE ID, defense and VR priority badges, title, severity, impact type, release date, and exploit disclosure status.

**Score breakdowns** -- two side-by-side panels showing defense score and research score. Each breaks down the score by factor (Component, CWE, Impact, Attack Vector, Privileges, User Interaction) with a stacked bar chart. The research score also shows bonus factors like exploit_unproven, critical_severity, and scope_changed.

**References sidebar** -- links to the MSRC Security Update page, NVD entry, and MITRE CVE Record.

**Data freshness** -- first seen, last updated, and released dates.

**Research tags** -- at the bottom, colored badges with explanations: HIGH_IMPACT (RCE or EoP), NOVEL (no public exploit), SCOPE_CHANGE (sandbox/VM escape).

The slide-out panel (click a row without clicking the CVE ID link) shows the same score breakdowns in a narrower format.

## Data ingestion

Poll the RSS feed for new CVEs:

```
python -m threat2signal poll-msrc
```

Backfill older Patch Tuesday months (format: `YYYY-Mon`):

```
python -m threat2signal backfill-msrc 2026-Jun 2026-Jul
```

The background poll loop also runs MSRC automatically every cycle.

## Rescoring

If you edit `config/scoring.yaml` (thresholds, component weights, ignore list), recompute all scores:

```
python -m threat2signal rescore
```

## Ignored components

Some components are filtered out during ingestion (not scored, not stored). Defined in `config/scoring.yaml` under `ignore_list`. Currently: Azure Linux, Chromium, Android, iOS, Linux Kernel, Mariner.
