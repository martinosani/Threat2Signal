/** Full-page CVE detail view for vulnerability researchers. */

import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { fetchMsrcCve } from '../lib/api';
import type { MsrcCveDetail } from '../lib/types';
import { Badge } from '../components/Badge';
import { ScoreBreakdown } from '../components/msrc/ScoreBreakdown';
import { VR_TAG_DESCRIPTIONS } from '../lib/vr-constants';
import styles from './CveDetail.module.css';

const fmtDate = (d: string | null) => (d ? d.slice(0, 10) : '--');

const fmtRelative = (d: string | null): string => {
  if (!d) return '--';
  const ms = Date.now() - new Date(d).getTime();
  const days = Math.floor(ms / 86_400_000);
  if (days < 1) return 'today';
  if (days === 1) return '1 day ago';
  if (days < 30) return `${days} days ago`;
  return fmtDate(d);
};

const msrcUrl = (id: string) =>
  `https://msrc.microsoft.com/update-guide/vulnerability/${id}`;
const nvdUrl = (id: string) =>
  `https://nvd.nist.gov/vuln/detail/${id}`;
const mitreUrl = (id: string) =>
  `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${id}`;

const KB_COLLAPSE_THRESHOLD = 5;

export default function CveDetail() {
  const { cveId } = useParams<{ cveId: string }>();
  const [descExpanded, setDescExpanded] = useState(false);
  const [kbExpanded, setKbExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const {
    data: cve,
    isLoading,
    error,
  } = useQuery<MsrcCveDetail>({
    queryKey: ['msrc-cve', cveId],
    queryFn: () => fetchMsrcCve(cveId ?? ''),
    enabled: !!cveId,
    staleTime: 5 * 60 * 1000,
  });

  const copyId = () => {
    if (!cve) return;
    navigator.clipboard.writeText(cve.cve_id);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  if (isLoading) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>Loading CVE...</div>
      </div>
    );
  }

  if (error || !cve) {
    const is404 =
      error instanceof Error &&
      'status' in error &&
      (error as { status: number }).status === 404;

    return (
      <div className={styles.container}>
        <div className={styles.errorState}>
          <h2 className={styles.errorTitle}>
            {is404 ? 'CVE not found' : 'Error loading CVE'}
          </h2>
          <p className={styles.errorMessage}>
            {is404
              ? `No CVE found with ID "${cveId}".`
              : `Something went wrong: ${error?.message ?? 'Unknown error'}`}
          </p>
          <Link to="/msrc" className={styles.backLink}>
            Back to MSRC CVEs
          </Link>
        </div>
      </div>
    );
  }

  const kbVisible = kbExpanded
    ? cve.kb_entries
    : cve.kb_entries.slice(0, KB_COLLAPSE_THRESHOLD);
  const kbHidden = cve.kb_entries.length - KB_COLLAPSE_THRESHOLD;

  return (
    <div className={styles.container}>
      {/* -------- Header -------- */}
      <header className={styles.header}>
        <Link to="/msrc" className={styles.backLink}>
          <span className={styles.backArrow}>&larr;</span> MSRC CVEs
        </Link>

        <div className={styles.headerRow}>
          <h1 className={styles.cveId}>
            {cve.cve_id}
            {' '}
            <Badge variant="priority" value={cve.priority} label="DEF" />
            {cve.vr_priority && (
              <>
                {' '}
                <Badge variant="priority" value={cve.vr_priority} label="VR" />
              </>
            )}
          </h1>
          <div className={styles.headerActions}>
            <button
              className={styles.copyBtn}
              onClick={copyId}
              title="Copy CVE ID"
            >
              {copied ? 'Copied' : 'Copy ID'}
            </button>
            <a
              href={msrcUrl(cve.cve_id)}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.extLink}
              title="View on MSRC"
            >
              MSRC &#8599;
            </a>
          </div>
        </div>

        {cve.title && <p className={styles.title}>{cve.title}</p>}

        <div className={styles.metaRow}>
          {cve.severity && <Badge variant="severity" value={cve.severity} />}
          {cve.impact && (
            <>
              <span className={styles.metaDot}>&middot;</span>
              <span>{cve.impact}</span>
            </>
          )}
          <span className={styles.metaDot}>&middot;</span>
          <span className={styles.metaDate}>{fmtDate(cve.released)}</span>
          {cve.exploit_status && (
            <>
              <span className={styles.metaDot}>&middot;</span>
              <span>{cve.exploit_status}</span>
            </>
          )}
          <span className={styles.metaDot}>&middot;</span>
          <div className={styles.flagRow}>
            <span className={styles.flagItem}>
              <span
                className={`${styles.flagDot} ${cve.kev_listed ? styles.flagActive : styles.flagInactive}`}
              />
              KEV
            </span>
            <span className={styles.flagItem}>
              <span
                className={`${styles.flagDot} ${cve.exploited_wild ? styles.flagActive : styles.flagInactive}`}
              />
              Exploited
            </span>
            <span className={styles.flagItem}>
              <span
                className={`${styles.flagDot} ${cve.publicly_disclosed ? styles.flagActive : styles.flagInactive}`}
              />
              Disclosed
            </span>
          </div>
        </div>
      </header>

      {/* -------- Two-column body -------- */}
      <div className={styles.body}>
        {/* ======= Left / primary column ======= */}
        <div className={styles.primaryCol}>
          {/* Description */}
          {cve.description && (
            <div className={styles.section}>
              <h2 className={styles.sectionTitle}>Description</h2>
              <div
                className={`${styles.descBlock} ${descExpanded ? '' : styles.descClamped}`}
              >
                {cve.description}
              </div>
              {cve.description.length > 280 && (
                <button
                  className={styles.expandBtn}
                  onClick={() => setDescExpanded((v) => !v)}
                >
                  {descExpanded ? 'Show less' : 'Show more'}
                </button>
              )}
            </div>
          )}

          {/* Score Cards */}
          <div className={styles.section}>
            <div className={styles.scoreCardsGrid}>
              <div className={styles.scoreCard}>
                <h2 className={styles.scoreCardTitle}>Defense Score</h2>
                <ScoreBreakdown breakdown={cve.score_breakdown} />
              </div>
              <div className={styles.scoreCard}>
                <h2 className={styles.scoreCardTitle}>Research Score</h2>
                <ScoreBreakdown breakdown={cve.vr_score_breakdown} variant="vr" />
              </div>
            </div>
          </div>

          {/* Research Tags */}
          {cve.vr_tags && cve.vr_tags.length > 0 && (
            <div className={styles.section}>
              <h2 className={styles.sectionTitle}>Research Tags</h2>
              <div className={styles.vrTagList}>
                {cve.vr_tags.map((tag) => (
                  <div key={tag} className={styles.vrTagItem}>
                    <span className={styles.vrTag} data-tag={tag}>
                      {tag}
                    </span>
                    <span className={styles.vrTagDesc}>
                      {VR_TAG_DESCRIPTIONS[tag] || tag}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attack Surface */}
          <div className={styles.section}>
            <h2 className={styles.sectionTitle}>Attack Surface</h2>
            <div className={styles.attackGrid}>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Component</span>
                <span className={styles.infoValue}>{cve.component ?? '--'}</span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Category</span>
                <span className={styles.infoValue}>
                  {cve.component_category ?? '--'}
                </span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>CWE</span>
                <span className={styles.infoValueMono}>
                  {cve.cwe_id
                    ? `${cve.cwe_id}${cve.cwe_description ? `: ${cve.cwe_description}` : ''}`
                    : '--'}
                </span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>CVSS</span>
                <span className={styles.infoValueMono}>
                  {cve.cvss_base != null ? cve.cvss_base.toFixed(1) : '--'}
                  {cve.cvss_temporal != null && (
                    <span className={styles.cvssTemp}>
                      {' '}/ {cve.cvss_temporal.toFixed(1)} temporal
                    </span>
                  )}
                </span>
              </div>
            </div>
            {/* Compact CVSS vector */}
            {cve.cvss_vector && (
              <div className={styles.vectorRow}>
                <span className={styles.vectorPill}>AV:{cve.av?.[0] ?? '?'}</span>
                <span className={styles.vectorPill}>AC:{cve.ac?.[0] ?? '?'}</span>
                <span className={styles.vectorPill}>PR:{cve.pr?.[0] ?? '?'}</span>
                <span className={styles.vectorPill}>UI:{cve.ui?.[0] ?? '?'}</span>
                <span className={styles.vectorPill}>S:{cve.scope?.[0] ?? '?'}</span>
                <span className={styles.vectorFull} title={cve.cvss_vector}>
                  {cve.cvss_vector}
                </span>
              </div>
            )}
          </div>

          {/* Customer Action */}
          {cve.customer_action && (
            <div className={styles.section}>
              <h2 className={styles.sectionTitle}>Customer Action</h2>
              <div className={styles.callout}>{cve.customer_action}</div>
            </div>
          )}

          {/* Related CVEs */}
          {cve.related_cves && cve.related_cves.length > 0 && (
            <div className={styles.section}>
              <h2 className={styles.sectionTitle}>
                Related CVEs &mdash; {cve.component} ({cve.related_cves.length})
              </h2>
              <div className={styles.kbTableWrap}>
                <table className={styles.kbTable}>
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Impact</th>
                      <th>CWE</th>
                      <th>DEF</th>
                      <th>VR</th>
                      <th>Released</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cve.related_cves.map((r) => (
                      <tr key={r.cve_id}>
                        <td>
                          <Link to={`/msrc/${r.cve_id}`} className={styles.relCveLink}>
                            {r.cve_id}
                          </Link>
                        </td>
                        <td>{r.impact ?? '--'}</td>
                        <td className={styles.kbMono}>{r.cwe_id ?? '--'}</td>
                        <td><Badge variant="priority" value={r.priority} /></td>
                        <td><Badge variant="priority" value={r.vr_priority} /></td>
                        <td className={styles.kbMono}>{fmtDate(r.released)}</td>
                        <td>
                          {r.exploited_wild ? (
                            <span className={styles.statusExploited}>Exploited</span>
                          ) : r.publicly_disclosed ? (
                            <span className={styles.statusDisclosed}>Disclosed</span>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* ======= Right / sidebar column ======= */}
        <aside className={styles.sidebarCol}>
          {/* References */}
          <div className={styles.sideCard}>
            <h2 className={styles.sideCardTitle}>References</h2>
            <div className={styles.refList}>
              <a
                href={msrcUrl(cve.cve_id)}
                target="_blank"
                rel="noopener noreferrer"
                className={styles.refLink}
              >
                MSRC Security Update &#8599;
              </a>
              <a
                href={nvdUrl(cve.cve_id)}
                target="_blank"
                rel="noopener noreferrer"
                className={styles.refLink}
              >
                NVD Entry &#8599;
              </a>
              <a
                href={mitreUrl(cve.cve_id)}
                target="_blank"
                rel="noopener noreferrer"
                className={styles.refLink}
              >
                MITRE CVE Record &#8599;
              </a>
              {cve.cwe_id && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${cve.cwe_id.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.refLink}
                >
                  {cve.cwe_id} Detail &#8599;
                </a>
              )}
            </div>
          </div>

          {/* Data Freshness */}
          <div className={styles.sideCard}>
            <h2 className={styles.sideCardTitle}>Data Freshness</h2>
            <div className={styles.freshGrid}>
              <span className={styles.infoLabel}>First seen</span>
              <span
                className={styles.infoValue}
                title={cve.first_seen ?? undefined}
              >
                {fmtRelative(cve.first_seen)}
              </span>
              <span className={styles.infoLabel}>Last updated</span>
              <span
                className={styles.infoValue}
                title={cve.last_updated ?? undefined}
              >
                {fmtRelative(cve.last_updated)}
              </span>
              <span className={styles.infoLabel}>Released</span>
              <span className={styles.infoValueMono}>
                {fmtDate(cve.released)}
              </span>
            </div>
          </div>

          {/* KB Patches */}
          {cve.kb_entries.length > 0 && (
            <div className={styles.sideCard}>
              <h2 className={styles.sideCardTitle}>
                KB Patches ({cve.kb_entries.length})
              </h2>
              <div className={styles.kbList}>
                {kbVisible.map((kb, i) => (
                  <div key={i} className={styles.kbItem}>
                    <span className={styles.kbMono}>{kb.kb_number}</span>
                    <span className={styles.kbProduct}>
                      {kb.product_name ?? ''}
                    </span>
                    {kb.download_url && (
                      <a
                        href={kb.download_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={styles.kbDl}
                      >
                        &#8599;
                      </a>
                    )}
                  </div>
                ))}
              </div>
              {kbHidden > 0 && (
                <button
                  className={styles.expandBtn}
                  onClick={() => setKbExpanded((v) => !v)}
                >
                  {kbExpanded
                    ? 'Show fewer'
                    : `Show ${kbHidden} more`}
                </button>
              )}
            </div>
          )}

          {/* KEV Details */}
          {cve.kev && (
            <div className={styles.sideCard}>
              <h2 className={styles.sideCardTitle}>KEV Details</h2>
              <div className={styles.freshGrid}>
                <span className={styles.infoLabel}>Vendor</span>
                <span className={styles.infoValue}>{cve.kev.vendor ?? '--'}</span>
                <span className={styles.infoLabel}>Product</span>
                <span className={styles.infoValue}>{cve.kev.product ?? '--'}</span>
                <span className={styles.infoLabel}>Date Added</span>
                <span className={styles.infoValueMono}>
                  {fmtDate(cve.kev.date_added)}
                </span>
                <span className={styles.infoLabel}>Due Date</span>
                <span className={styles.infoValueMono}>
                  {fmtDate(cve.kev.due_date)}
                </span>
                <span className={styles.infoLabel}>Ransomware</span>
                <span className={styles.infoValue}>
                  {cve.kev.known_ransomware ?? '--'}
                </span>
              </div>
              {cve.kev.notes && (
                <div className={styles.callout} style={{ marginTop: 10 }}>
                  {cve.kev.notes}
                </div>
              )}
            </div>
          )}

          {/* Linked Advisories */}
          {cve.advisories.length > 0 && (
            <div className={styles.sideCard}>
              <h2 className={styles.sideCardTitle}>
                Advisories ({cve.advisories.length})
              </h2>
              <div className={styles.advSideList}>
                {cve.advisories.map((adv) => (
                  <div key={adv.id} className={styles.advSideItem}>
                    <Link
                      to={`/advisory/${adv.id}`}
                      className={styles.advisoryItemId}
                    >
                      {adv.id}
                    </Link>
                    <Badge variant="source" value={adv.source} />
                    <span className={styles.advSideTitle}>
                      {adv.title ?? '--'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
