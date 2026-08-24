# Running Analysis

Analysis is a separate step from extraction. Extraction pulls raw data (IOCs, rules, techniques) automatically during ingestion. Analysis interprets that data through an LLM to produce tactical and strategic intelligence. You trigger it manually per advisory.

## How to run it

Open any advisory detail page. Click the **Analyze** button in the top-right corner (green button, next to the triage dropdown). If the advisory was already analyzed, the button says **Re-analyze** instead.

A confirmation dialog shows the expected cost (~$0.02) and time (15-30 seconds). Click to confirm.

![Generating analysis](images/Generating%20analyses%20with%20DeepSeek.png)

While analysis is running, the button changes to "Analyzing..." with a spinner, and the Analysis tab shows a loading indicator with the message "Generating analysis with DeepSeek... This typically takes 15-30 seconds."

When it finishes, the Analysis tab populates with five sub-tabs.

## Red Team

![Red Team tab](images/Advisory%20Detail%20View%20-%20Analysis%20-%20Red%20Team.png)

Attack simulation scenarios derived from the advisory content. Each card has:

- A title describing the attack action (e.g. "Deploy Web Shell on DMZ Web Server")
- Priority badge: critical, high, or medium
- MITRE technique IDs (e.g. T1505.003, T1078)
- Tactic label (Persistence, Lateral Movement, etc.)
- A description of what to validate
- Execution references: Atomic Red Team test names (red badges), tools (gray badges like "Burp Suite", "secretsdump.py")
- "Show details" link for the full exercise breakdown

Filter by priority at the top: All, Critical, High, Medium.

## Purple Team

![Purple Team tab](images/Advisory%20Detail%20View%20-%20Analysis%20-%20Purple%20Team.png)

A structured exercise table that maps red team actions to blue team detection measures. Ordered by kill chain phase.

Columns:
- **Exercise** -- numbered, with a descriptive name
- **Red Action** -- what the attacker does
- **Blue Measures** -- what defenders should detect or alert on
- **MITRE Techniques** -- technique ID badges, plus detection rule references when available
- **Success Criteria** -- tiered: Basic (manual detection within 24h), Intermediate (automated detection within 4h)

Filter at the top: All, Has Rules, Gaps Only. The summary bar shows coverage (e.g. "9/13 techniques covered by detection rules -- 4 gaps"). "Sort by kill chain" button reorders by attack phase.

## Security Posture

![Security Posture tab](images/Advisory%20Detail%20View%20-%20Analysis%20-%20Security%20Posture.png)

Strategic recommendations grouped by category (Patch Management, Network Architecture, etc.). Each card has:

- Title and description of the recommendation
- Priority badge (critical/high/medium) and maturity level (foundational/intermediate/advanced)
- **Key Insight** block -- a highlighted takeaway explaining why this matters in context of the advisory
- Gap analysis quote pulled from the original advisory text (shown in a blockquote with a checkmark if verified against the source)
- Framework reference (e.g. NIST CSF PR.IP-12)

Filter by priority (All/Critical/High/Medium) and maturity (All/Foundational/Intermediate/Advanced).

## Blue Team and Findings

Two more sub-tabs not shown in screenshots:

**Blue Team** -- detection gap analysis. Shows quotes from the advisory that reveal defensive blind spots, with verification indicators and detection rule cross-references.

**Findings** -- incident lessons and capability gap assessments extracted from the advisory.

## Re-analysis

If you click Re-analyze on an advisory that already has results, a warning dialog explains it will overwrite the existing analysis and shows the cost. The old analysis is replaced entirely.

A "stale analysis" banner appears when the extraction prompt version has changed since the analysis was last run, suggesting you re-analyze to pick up improvements.

## Cost and telemetry

Analysis metadata shows at the top of the tab: model used (e.g. deepseek-v4-flash), how long ago it was generated, and a "Details" link. The details include token counts (in/out), latency, and cost.
