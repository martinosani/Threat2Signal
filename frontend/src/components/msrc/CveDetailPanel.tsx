/** Slide-out detail panel for a single MSRC CVE. */

import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { fetchMsrcCve } from '../../lib/api';
import { Badge } from '../Badge';
import { Skeleton } from '../Skeleton';
import { VR_TAG_DESCRIPTIONS } from '../../lib/vr-constants';
import { ScoreBreakdown } from './ScoreBreakdown';
import styles from './msrc.module.css';

interface CveDetailPanelProps {
  cveId: string;
  onClose: () => void;
}

export function CveDetailPanel({ cveId, onClose }: CveDetailPanelProps) {
  const {
    data: cve,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['msrc-cve', cveId],
    queryFn: () => fetchMsrcCve(cveId),
    staleTime: 5 * 60 * 1000,
  });

  if (isLoading) {
    return (
      <div>
        <div className={styles.panelHeader}>
          <div className={styles.panelTitleBlock}>
            <Skeleton lines={2} />
          </div>
          <button
            type="button"
            className={styles.panelCloseBtn}
            onClick={onClose}
            aria-label="Close panel"
          >
            &#x2715;
          </button>
        </div>
        <div className={styles.panelBody}>
          <div className={styles.panelSection}>
            <Skeleton lines={6} />
          </div>
        </div>
      </div>
    );
  }

  if (error || !cve) {
    return (
      <div>
        <div className={styles.panelHeader}>
          <div className={styles.panelTitleBlock}>
            <h2 className={styles.panelCveId}>{cveId}</h2>
          </div>
          <button
            type="button"
            className={styles.panelCloseBtn}
            onClick={onClose}
            aria-label="Close panel"
          >
            &#x2715;
          </button>
        </div>
        <div className={styles.panelError}>
          Failed to load CVE details.
          <br />
          <button
            type="button"
            className={styles.retryBtn}
            onClick={() => refetch()}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const formatDate = (d: string | null): string => {
    if (!d) return '--';
    return d.slice(0, 10);
  };

  return (
    <div>
      {/* Header */}
      <div className={styles.panelHeader}>
        <div className={styles.panelTitleBlock}>
          <h2 className={styles.panelCveId}>
            {cve.cve_id}
            {' '}
            <Badge variant="priority" value={cve.priority} label="DEF" />
            {cve.vr_priority && (
              <>
                {' '}
                <Badge variant="priority" value={cve.vr_priority} label="VR" />
              </>
            )}
          </h2>
          {cve.title && <p className={styles.panelTitle}>{cve.title}</p>}
        </div>
        <button
          type="button"
          className={styles.panelCloseBtn}
          onClick={onClose}
          aria-label="Close panel"
        >
          &#x2715;
        </button>
      </div>

      <div className={styles.panelBody}>
        {/* Score Breakdown */}
        <div className={styles.panelSection}>
          <h3 className={styles.panelSectionTitle}>Defense Score</h3>
          <ScoreBreakdown breakdown={cve.score_breakdown} />
        </div>

        {/* VR Score Breakdown */}
        {cve.vr_score_breakdown && (
          <div className={styles.panelSection}>
            <h3 className={styles.panelSectionTitle}>Research Score</h3>
            <ScoreBreakdown breakdown={cve.vr_score_breakdown} variant="vr" />
          </div>
        )}

        {/* VR Tags */}
        {cve.vr_tags && cve.vr_tags.length > 0 && (
          <div className={styles.panelSection}>
            <h3 className={styles.panelSectionTitle}>Research Tags</h3>
            <div className={styles.vrTagList}>
              {cve.vr_tags.map((tag) => (
                <div key={tag} className={styles.vrTagItem}>
                  <span className={styles.vrTag} data-tag={tag}>{tag}</span>
                  <span className={styles.vrTagDesc}>{VR_TAG_DESCRIPTIONS[tag] || tag}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CVE Info Grid */}
        <div className={styles.panelSection}>
          <h3 className={styles.panelSectionTitle}>CVE Information</h3>
          <div className={styles.infoGrid}>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Released</span>
              <span className={styles.infoValueMono}>
                {formatDate(cve.released)}
              </span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Severity</span>
              <span className={styles.infoValue}>
                {cve.severity ? (
                  <Badge variant="severity" value={cve.severity} />
                ) : (
                  '--'
                )}
              </span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>CVSS Base</span>
              <span className={styles.infoValueMono}>
                {cve.cvss_base != null ? cve.cvss_base.toFixed(1) : '--'}
              </span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>CVSS Temporal</span>
              <span className={styles.infoValueMono}>
                {cve.cvss_temporal != null
                  ? cve.cvss_temporal.toFixed(1)
                  : '--'}
              </span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Impact</span>
              <span className={styles.infoValue}>{cve.impact ?? '--'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Component</span>
              <span className={styles.infoValue}>{cve.component ?? '--'}</span>
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
              <span className={styles.infoLabel}>Exploit Status</span>
              <span className={styles.infoValue}>
                {cve.exploit_status ?? '--'}
              </span>
            </div>
          </div>

          {/* CVSS Vector and Decomposition */}
          {cve.cvss_vector && (
            <>
              <div className={styles.infoItem} style={{ marginTop: 10 }}>
                <span className={styles.infoLabel}>CVSS Vector</span>
                <span className={styles.infoValueMono} style={{ fontSize: 11, wordBreak: 'break-all' }}>
                  {cve.cvss_vector}
                </span>
              </div>
              <div className={styles.cvssGrid}>
                <div className={styles.cvssItem}>
                  <span className={styles.cvssLabel}>AV</span>
                  <span className={styles.cvssValue}>{cve.av ?? '--'}</span>
                </div>
                <div className={styles.cvssItem}>
                  <span className={styles.cvssLabel}>AC</span>
                  <span className={styles.cvssValue}>{cve.ac ?? '--'}</span>
                </div>
                <div className={styles.cvssItem}>
                  <span className={styles.cvssLabel}>PR</span>
                  <span className={styles.cvssValue}>{cve.pr ?? '--'}</span>
                </div>
                <div className={styles.cvssItem}>
                  <span className={styles.cvssLabel}>UI</span>
                  <span className={styles.cvssValue}>{cve.ui ?? '--'}</span>
                </div>
                <div className={styles.cvssItem}>
                  <span className={styles.cvssLabel}>Scope</span>
                  <span className={styles.cvssValue}>{cve.scope ?? '--'}</span>
                </div>
              </div>
            </>
          )}

          {/* Exploit flags */}
          <div className={styles.flagRow} style={{ marginTop: 12 }}>
            <span className={styles.flagItem}>
              <span
                className={`${styles.flagDot} ${cve.kev_listed ? styles.flagActive : styles.flagInactive}`}
              />
              KEV Listed
            </span>
            <span className={styles.flagItem}>
              <span
                className={`${styles.flagDot} ${cve.exploited_wild ? styles.flagActive : styles.flagInactive}`}
              />
              Exploited in Wild
            </span>
            <span className={styles.flagItem}>
              <span
                className={`${styles.flagDot} ${cve.publicly_disclosed ? styles.flagActive : styles.flagInactive}`}
              />
              Publicly Disclosed
            </span>
          </div>
        </div>

        {/* KEV Section */}
        {cve.kev && (
          <div className={styles.panelSection}>
            <h3 className={styles.panelSectionTitle}>KEV Details</h3>
            <div className={styles.kevGrid}>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Vendor</span>
                <span className={styles.infoValue}>
                  {cve.kev.vendor ?? '--'}
                </span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Product</span>
                <span className={styles.infoValue}>
                  {cve.kev.product ?? '--'}
                </span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Date Added</span>
                <span className={styles.infoValueMono}>
                  {formatDate(cve.kev.date_added)}
                </span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Due Date</span>
                <span className={styles.infoValueMono}>
                  {formatDate(cve.kev.due_date)}
                </span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Ransomware Use</span>
                <span className={styles.infoValue}>
                  {cve.kev.known_ransomware ?? '--'}
                </span>
              </div>
            </div>
            {cve.kev.notes && (
              <div className={styles.callout} style={{ marginTop: 10 }}>
                {cve.kev.notes}
              </div>
            )}
          </div>
        )}

        {/* KB Patches */}
        {cve.kb_entries.length > 0 && (
          <div className={styles.panelSection}>
            <h3 className={styles.panelSectionTitle}>
              KB Patches ({cve.kb_entries.length})
            </h3>
            <div style={{ overflowX: 'auto' }}>
              <table className={styles.kbTable}>
                <thead>
                  <tr>
                    <th>KB</th>
                    <th>Product</th>
                    <th>Link</th>
                  </tr>
                </thead>
                <tbody>
                  {cve.kb_entries.map((kb, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                        {kb.kb_number}
                      </td>
                      <td>{kb.product_name ?? '--'}</td>
                      <td>
                        {kb.download_url ? (
                          <a
                            href={kb.download_url}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            Download &#8599;
                          </a>
                        ) : (
                          '--'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Linked Advisories */}
        {cve.advisories.length > 0 && (
          <div className={styles.panelSection}>
            <h3 className={styles.panelSectionTitle}>
              Linked Advisories ({cve.advisories.length})
            </h3>
            <div className={styles.advisoryList}>
              {cve.advisories.map((adv) => (
                <div key={adv.id} className={styles.advisoryItem}>
                  <Link
                    to={`/advisory/${adv.id}`}
                    className={styles.advisoryItemId}
                  >
                    {adv.id}
                  </Link>
                  <Badge variant="source" value={adv.source} />
                  <span className={styles.advisoryItemTitle}>
                    {adv.title ?? '--'}
                  </span>
                  <span className={styles.advisoryItemDate}>
                    {formatDate(adv.pub_date)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Customer Action */}
        {cve.customer_action && (
          <div className={styles.panelSection}>
            <h3 className={styles.panelSectionTitle}>Customer Action</h3>
            <div className={styles.callout}>{cve.customer_action}</div>
          </div>
        )}
      </div>
    </div>
  );
}
