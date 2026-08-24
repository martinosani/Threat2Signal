/** Overview tab -- enriched article reader, IOC/MITRE popovers, and linked CVEs. */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router-dom';
import DOMPurify from 'dompurify';
import type { AdvisoryDetail } from '../../lib/types';
import { authHeaders, fetchAdvisoryCves, fetchAdvisoryIocs } from '../../lib/api';
import { Badge } from '../Badge';
import { Skeleton } from '../Skeleton';
import styles from './advisory-tabs.module.css';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface OverviewTabProps {
  advisory: AdvisoryDetail;
  onSwitchToRaw: () => void;
}

interface IocPopoverState {
  x: number;
  y: number;
  type: string;
  /** Normalized value from data-ioc-value (display). */
  value: string;
  /** Visible text of the mark (used for the defensive copy). */
  text: string;
  validationStatus: string;
  crossRefCount: number;
  autoFocus: boolean;
}

interface MitrePopoverState {
  x: number;
  y: number;
  techniqueId: string;
  name: string;
  tactic: string;
  /** Only set when the href host is exactly attack.mitre.org. */
  mitreHref: string | null;
  autoFocus: boolean;
}

type PopoverState =
  | { kind: 'ioc'; data: IocPopoverState }
  | { kind: 'mitre'; data: MitrePopoverState }
  | null;

// ---------------------------------------------------------------------------
// DOMPurify configuration
// ---------------------------------------------------------------------------

const PURIFY_CONFIG = {
  ADD_ATTR: [
    'data-ioc-type',
    'data-ioc-value',
    'data-technique-id',
    'data-tactic',
    'data-cve-id',
    'data-asset-type',
    'data-rule-name',
    'data-cve-known',
    'tabindex',
    'target',
  ],
  ADD_TAGS: ['mark'],
};

/**
 * DOMPurify afterSanitizeAttributes hook: never allow a `target` without a
 * hardened `rel`. The enricher emits target="_blank" on external links; this
 * guarantees rel="noopener noreferrer" is present regardless of source markup.
 */
function forceRelHook(node: Element): void {
  if (node.hasAttribute?.('target')) {
    node.setAttribute('rel', 'noopener noreferrer');
  }
}

/** Return the hostname of an href, or null if it isn't a parseable absolute URL. */
function hrefHost(href: string): string | null {
  try {
    return new URL(href, window.location.origin).hostname;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Popover positioning helper
// ---------------------------------------------------------------------------

function computePopoverPosition(target: HTMLElement): { x: number; y: number } {
  const rect = target.getBoundingClientRect();
  const x = Math.min(rect.left, window.innerWidth - 380);
  const y = rect.bottom + 6;
  // If it would overflow bottom, show above
  if (y + 200 > window.innerHeight) {
    return { x: Math.max(0, x), y: rect.top - 6 };
  }
  return { x: Math.max(0, x), y };
}

// ---------------------------------------------------------------------------
// IocPopover component
// ---------------------------------------------------------------------------

function IocPopover({
  data,
  onClose,
}: {
  data: IocPopoverState;
  onClose: () => void;
}) {
  const popoverRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  // Defensive copy (M1/C8): copy the visible text when it differs from the
  // (attacker-controllable) data-ioc-value attribute.
  const copyValue = data.text && data.text !== data.value ? data.text : data.value;

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(copyValue);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access denied or unavailable
    }
  }, [copyValue]);

  // Only steal focus for keyboard-triggered opens (M3).
  useEffect(() => {
    if (data.autoFocus) popoverRef.current?.focus();
  }, [data.autoFocus]);

  return (
    <div
      ref={popoverRef}
      id="t2s-popover"
      className={styles.popover}
      style={{ left: data.x, top: data.y }}
      role="dialog"
      aria-modal="false"
      aria-label="IOC details"
      tabIndex={-1}
      onKeyDown={(e) => {
        if (e.key === 'Escape') onClose();
      }}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
          onClose();
        }
      }}
    >
      <p className={styles.popoverType}>{data.type}</p>
      <p className={styles.popoverValue}>{data.value}</p>
      <div className={styles.popoverRow}>
        <button
          type="button"
          className={styles.popoverCopyBtn}
          onClick={handleCopy}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
        <span
          className={`${styles.popoverBadge} ${
            data.validationStatus !== 'valid' ? styles.popoverBadgeWarning : ''
          }`}
        >
          {data.validationStatus || 'unknown'}
        </span>
      </div>
      {data.crossRefCount > 0 && (
        <div className={styles.popoverRow}>
          Seen in {data.crossRefCount} other advisor{data.crossRefCount === 1 ? 'y' : 'ies'}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MitrePopover component
// ---------------------------------------------------------------------------

function MitrePopover({
  data,
  onClose,
}: {
  data: MitrePopoverState;
  onClose: () => void;
}) {
  const popoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (data.autoFocus) popoverRef.current?.focus();
  }, [data.autoFocus]);

  return (
    <div
      ref={popoverRef}
      id="t2s-popover"
      className={styles.popover}
      style={{ left: data.x, top: data.y }}
      role="dialog"
      aria-modal="false"
      aria-label="ATT&CK technique details"
      tabIndex={-1}
      onKeyDown={(e) => {
        if (e.key === 'Escape') onClose();
      }}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
          onClose();
        }
      }}
    >
      <p className={styles.popoverType}>{data.techniqueId}</p>
      <p style={{ margin: '0 0 4px', fontWeight: 600 }}>{data.name}</p>
      {data.tactic && (
        <div className={styles.popoverRow}>
          Tactic: {data.tactic}
        </div>
      )}
      {data.mitreHref && (
        <div className={styles.popoverRow}>
          <a
            href={data.mitreHref}
            target="_blank"
            rel="noopener noreferrer"
            className={styles.popoverLink}
          >
            View on MITRE
          </a>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// OverviewTab
// ---------------------------------------------------------------------------

export function OverviewTab({ advisory, onSwitchToRaw }: OverviewTabProps) {
  const articleRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const [popover, setPopover] = useState<PopoverState>(null);
  // Trigger element for a keyboard-opened popover, so focus can return on Escape.
  const triggerElRef = useRef<HTMLElement | null>(null);

  // Sanitize enriched or fallback body. Register the rel-forcing hook only for
  // the duration of this sanitize call (C7/M2).
  const sanitizedHtml = useMemo(() => {
    const source = advisory.enriched_body ?? advisory.article_body;
    if (!source) return null;
    DOMPurify.addHook('afterSanitizeAttributes', forceRelHook);
    try {
      return DOMPurify.sanitize(source, PURIFY_CONFIG) as string;
    } finally {
      DOMPurify.removeHook('afterSanitizeAttributes');
    }
  }, [advisory.enriched_body, advisory.article_body]);

  const isEnriched = advisory.enriched_body != null;

  // Load inline images via authenticated fetch — browser-initiated <img> requests
  // don't carry the JWT Bearer token, so we build a map of src→blobURL and
  // inject them into the HTML before rendering.
  const [imageBlobMap, setImageBlobMap] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!sanitizedHtml) return;
    const parser = new DOMParser();
    const doc = parser.parseFromString(sanitizedHtml, 'text/html');
    const imgs = doc.querySelectorAll<HTMLImageElement>('img[src^="/api/"]');
    if (imgs.length === 0) return;

    const srcs = Array.from(new Set(Array.from(imgs).map((i) => i.getAttribute('src')!)));
    const controller = new AbortController();
    const pending = srcs.map((src) =>
      fetch(src, { headers: authHeaders(), signal: controller.signal })
        .then((r) => {
          if (!r.ok) throw new Error(`${r.status}`);
          return r.blob();
        })
        .then((blob) => [src, URL.createObjectURL(blob)] as const)
        .catch(() => null),
    );

    let cancelled = false;
    Promise.all(pending).then((results) => {
      if (cancelled) return;
      const map: Record<string, string> = {};
      for (const entry of results) {
        if (entry) map[entry[0]] = entry[1];
      }
      if (Object.keys(map).length > 0) setImageBlobMap(map);
    });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [sanitizedHtml]);

  useEffect(() => {
    const urls = Object.values(imageBlobMap);
    return () => {
      for (const url of urls) URL.revokeObjectURL(url);
    };
  }, [imageBlobMap]);

  const renderedHtml = useMemo(() => {
    if (!sanitizedHtml) return null;
    const entries = Object.entries(imageBlobMap);
    if (entries.length === 0) return sanitizedHtml;
    let html = sanitizedHtml;
    for (const [apiSrc, blobUrl] of entries) {
      html = html.replaceAll(apiSrc, blobUrl);
    }
    return html;
  }, [sanitizedHtml, imageBlobMap]);

  // Lazily fetch IOCs when the article renders, to join validation status +
  // cross-ref count into the popover (H10/C6). The enricher only emits
  // data-ioc-type + data-ioc-value on marks, never validation metadata.
  const { data: iocs } = useQuery({
    queryKey: ['advisory-iocs', advisory.id],
    queryFn: () => fetchAdvisoryIocs(advisory.id),
    enabled: !!sanitizedHtml && advisory.ioc_count > 0,
    staleTime: 5 * 60 * 1000,
  });

  const iocMap = useMemo(() => {
    const map = new Map<string, { validationStatus: string; crossRefCount: number }>();
    for (const ioc of iocs ?? []) {
      map.set(ioc.value, {
        validationStatus: ioc.validation_status,
        crossRefCount: ioc.cross_ref_count,
      });
    }
    return map;
  }, [iocs]);

  const closePopover = useCallback(() => setPopover(null), []);

  // Clean up aria-describedby when popover closes
  useEffect(() => {
    if (popover) return;
    articleRef.current
      ?.querySelectorAll('[aria-describedby="t2s-popover"]')
      .forEach((el) => el.removeAttribute('aria-describedby'));
  }, [popover]);

  // Close popover on scroll
  useEffect(() => {
    if (!popover) return;
    const handleScroll = () => setPopover(null);
    window.addEventListener('scroll', handleScroll, true);
    return () => window.removeEventListener('scroll', handleScroll, true);
  }, [popover]);

  // Close popover on Escape at document level (WCAG 1.4.13); return focus to
  // the triggering annotation (M3).
  useEffect(() => {
    if (!popover) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setPopover(null);
        triggerElRef.current?.focus();
        triggerElRef.current = null;
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [popover]);

  // Event delegation for IOC and MITRE hover/focus interactions.
  const handleArticleEvent = useCallback(
    (e: React.FocusEvent | React.MouseEvent) => {
      const target = e.target as HTMLElement;
      const keyboard = e.type === 'focus';

      // IOC element
      const iocEl = target.closest('.t2s-ioc') as HTMLElement | null;
      if (iocEl) {
        iocEl.setAttribute('aria-describedby', 't2s-popover');
        if (keyboard) triggerElRef.current = iocEl;
        const iocValue = iocEl.getAttribute('data-ioc-value') || '';
        const text = iocEl.textContent || '';
        const meta = iocMap.get(iocValue);
        const pos = computePopoverPosition(iocEl);
        setPopover({
          kind: 'ioc',
          data: {
            x: pos.x,
            y: pos.y,
            type: iocEl.getAttribute('data-ioc-type') || 'unknown',
            value: iocValue || text,
            text,
            validationStatus: meta?.validationStatus ?? 'unknown',
            crossRefCount: meta?.crossRefCount ?? 0,
            autoFocus: keyboard,
          },
        });
        return;
      }

      // MITRE technique element
      const mitreEl = target.closest('.t2s-mitre') as HTMLElement | null;
      if (mitreEl) {
        mitreEl.setAttribute('aria-describedby', 't2s-popover');
        if (keyboard) triggerElRef.current = mitreEl;
        const href = mitreEl.getAttribute('href') ?? '';
        // Only expose "View on MITRE" for genuine attack.mitre.org links (M1/C8).
        const mitreHref = hrefHost(href) === 'attack.mitre.org' ? href : null;
        const pos = computePopoverPosition(mitreEl);
        setPopover({
          kind: 'mitre',
          data: {
            x: pos.x,
            y: pos.y,
            techniqueId: mitreEl.getAttribute('data-technique-id') || '',
            name: mitreEl.getAttribute('title') || mitreEl.textContent || '',
            tactic: mitreEl.getAttribute('data-tactic') || '',
            mitreHref,
            autoFocus: keyboard,
          },
        });
        return;
      }
    },
    [iocMap],
  );

  // Intercept internal CVE links so they route client-side instead of doing a
  // full page reload (L9).
  const handleArticleClick = useCallback(
    (e: React.MouseEvent) => {
      const target = e.target as HTMLElement;
      const cveEl = target.closest('.t2s-cve') as HTMLAnchorElement | null;
      if (!cveEl) return;
      const href = cveEl.getAttribute('href') ?? '';
      if (href.startsWith('/')) {
        e.preventDefault();
        navigate(href);
      }
    },
    [navigate],
  );

  const handleArticleMouseLeave = useCallback(() => {
    // Only dismiss if the popover itself doesn't have focus
    setTimeout(() => {
      const active = document.activeElement;
      const popoverEl = document.querySelector(`.${styles.popover}`);
      if (popoverEl && popoverEl.contains(active)) return;
      setPopover(null);
    }, 100);
  }, []);

  // CVEs query
  const {
    data: cves,
    isLoading: cvesLoading,
    error: cvesError,
  } = useQuery({
    queryKey: ['advisory-cves', advisory.id],
    queryFn: () => fetchAdvisoryCves(advisory.id),
    staleTime: 5 * 60 * 1000,
  });

  return (
    <div className={styles.overviewGrid}>
      {/* Basic metadata */}
      <div className={styles.overviewSection}>
        <h3>Advisory Information</h3>
        <div className={styles.metaRow}>
          <span className={styles.metaLabel}>Title</span>
          <span>{advisory.title}</span>
        </div>
        <div className={styles.metaRow}>
          <span className={styles.metaLabel}>Published</span>
          <span>{advisory.pub_date}</span>
        </div>
        {advisory.summary && (
          <div className={styles.metaRow}>
            <span className={styles.metaLabel}>Summary</span>
            <span>{advisory.summary}</span>
          </div>
        )}
      </div>

      {/* Actors & sectors */}
      <div className={styles.overviewSection}>
        <h3>Threat Actors</h3>
        {advisory.actors && advisory.actors.length > 0 ? (
          <div className={styles.tagList}>
            {advisory.actors.map((actor) => (
              <Badge key={actor} variant="priority" value={actor} />
            ))}
          </div>
        ) : (
          <p className={styles.placeholderMessage}>
            {advisory.extraction_status === 'completed'
              ? 'No threat actors identified'
              : 'Available after extraction'}
          </p>
        )}
      </div>

      {/* Malware / Tools */}
      <div className={styles.overviewSection}>
        <h3>Malware / Tools</h3>
        {advisory.malware && advisory.malware.length > 0 ? (
          <div className={styles.tagList}>
            {advisory.malware.map((name) => (
              <Badge key={name} variant="priority" value={name} />
            ))}
          </div>
        ) : (
          <p className={styles.placeholderMessage}>
            {advisory.extraction_status === 'completed'
              ? 'No malware families identified'
              : 'Available after extraction'}
          </p>
        )}
      </div>

      {/* Sectors */}
      <div className={styles.overviewSection}>
        <h3>Sectors</h3>
        {advisory.sectors && advisory.sectors.length > 0 ? (
          <div className={styles.tagList}>
            {advisory.sectors.map((sector) => (
              <Badge key={sector} variant="priority" value={sector} />
            ))}
          </div>
        ) : (
          <p className={styles.placeholderMessage}>
            {advisory.extraction_status === 'completed'
              ? 'No sectors identified'
              : 'Available after extraction'}
          </p>
        )}
      </div>

      {/* Article reader -- full enriched body */}
      {renderedHtml && (
        <div className={styles.articleReader}>
          <div className={styles.articleReaderHeader}>
            <h3 className={styles.articleReaderTitle}>Article</h3>
            {isEnriched ? (
              <span className={styles.articleReaderBadge}>Enriched</span>
            ) : (
              <span className={styles.articleReaderFallback}>Raw HTML</span>
            )}
          </div>
          {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions */}
          <div
            ref={articleRef}
            className={styles.enrichedBody}
            dangerouslySetInnerHTML={{ __html: renderedHtml }}
            onClick={handleArticleClick}
            onFocus={handleArticleEvent}
            onMouseOver={handleArticleEvent}
            onMouseLeave={handleArticleMouseLeave}
          />
        </div>
      )}

      {!renderedHtml && (
        <div className={`${styles.overviewSection} ${styles.articlePreview}`}>
          <h3>Article</h3>
          <p className={styles.placeholderMessage}>
            No article body available for this advisory.
          </p>
          <button
            type="button"
            className={styles.readFullLink}
            onClick={onSwitchToRaw}
          >
            Check Raw tab for details
          </button>
        </div>
      )}

      {/* Popover portal */}
      {popover?.kind === 'ioc' && (
        <IocPopover data={popover.data} onClose={closePopover} />
      )}
      {popover?.kind === 'mitre' && (
        <MitrePopover data={popover.data} onClose={closePopover} />
      )}

      {/* CVEs Referenced -- linked to MSRC detail or NVD */}
      <div className={styles.overviewSection}>
        <h3>CVEs Referenced</h3>
        {cvesLoading && <Skeleton lines={3} />}
        {cvesError && (
          <p className={styles.placeholderMessage}>
            Failed to load linked CVEs.
          </p>
        )}
        {!cvesLoading && !cvesError && cves && cves.length === 0 && (
          <p className={styles.placeholderMessage}>
            No CVEs linked to this advisory
          </p>
        )}
        {!cvesLoading && !cvesError && cves && cves.length > 0 && (
          <div className={styles.exerciseTableWrap}>
            <table className={styles.exerciseTable}>
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Score</th>
                  <th>KEV</th>
                </tr>
              </thead>
              <tbody>
                {cves.map((cve) => (
                  <tr key={cve.cve_id}>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {cve.is_msrc ? (
                        <Link
                          to={`/msrc/${encodeURIComponent(cve.cve_id)}`}
                          style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
                        >
                          {cve.cve_id}
                        </Link>
                      ) : (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
                        >
                          {cve.cve_id}
                        </a>
                      )}
                    </td>
                    <td>{cve.title ?? '--'}</td>
                    <td>
                      {cve.severity ? (
                        <Badge variant="severity" value={cve.severity} />
                      ) : (
                        '--'
                      )}
                    </td>
                    <td
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 600,
                      }}
                    >
                      {cve.is_msrc ? cve.defense_score : '--'}
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      {cve.kev_listed && (
                        <span
                          style={{
                            display: 'inline-block',
                            width: 8,
                            height: 8,
                            borderRadius: '50%',
                            background: 'var(--status-failed)',
                          }}
                        />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
