import { useState, useCallback, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import type { IocSearchItem, IocAdvisoryDetail } from '../lib/types';
import { fetchIocs, fetchIocStats, fetchIocAdvisories, exportIocsGlobal, triggerDownload } from '../lib/api';
import { Badge } from '../components/Badge';
import { Pagination } from '../components/Pagination';
import { Skeleton } from '../components/Skeleton';
import { EmptyState } from '../components/EmptyState';
import { CopyButton } from '../components/CopyButton';
import { useToast } from '../components/Toast';
import styles from './IocSearch.module.css';

const PER_PAGE = 50;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Normalize defanged IOC input back to real form. */
function refangValue(value: string): string {
  let v = value.trim();
  v = v.replace(/\[dot\]/gi, '.');
  v = v.replace(/\[\.\]/g, '.');
  v = v.replace(/\(\.\)/g, '.');
  v = v.replace(/\[@\]/g, '@');
  v = v.replace(/hxxps?:\/\//gi, (m) =>
    m.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://',
  );
  return v;
}

/** Auto-detect IOC type from a normalized value. */
function detectIocType(value: string): string | null {
  const v = value.trim().toLowerCase();
  if (!v) return null;

  // Hash lengths (hex only)
  if (/^[0-9a-f]{128}$/.test(v)) return 'sha512';
  if (/^[0-9a-f]{64}$/.test(v)) return 'sha256';
  if (/^[0-9a-f]{40}$/.test(v)) return 'sha1';
  if (/^[0-9a-f]{32}$/.test(v)) return 'md5';

  // ssdeep
  if (/^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$/.test(value.trim())) return 'ssdeep';

  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v)) return 'ip';

  // URL
  if (/^https?:\/\//.test(v)) return 'url';

  // Email
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email';

  // Domain (has a dot, looks like valid segments)
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(v)) return 'domain';

  return null;
}

/** Type group chip definitions. */
const TYPE_GROUPS: { label: string; types: string[]; activeClass: string }[] = [
  { label: 'Hashes', types: ['md5', 'sha1', 'sha256', 'sha512', 'ssdeep'], activeClass: 'chipBlueActive' },
  { label: 'Network', types: ['ip', 'domain', 'url', 'email'], activeClass: 'chipGreenActive' },
  { label: 'Files', types: ['filepath', 'mutex'], activeClass: 'chipAmberActive' },
];

/** Validation chip definitions. */
const VALIDATION_CHIPS: { key: string; label: string; activeClass: string }[] = [
  { key: 'verified', label: 'Verified', activeClass: 'chipGreenActive' },
  { key: 'format_valid', label: 'Format Valid', activeClass: 'chipBlueActive' },
  { key: 'allowlisted', label: 'Allowlisted', activeClass: 'chipAmberActive' },
  { key: 'invalid', label: 'Invalid', activeClass: 'chipRedActive' },
];

/** Source chip definitions. */
const SOURCE_CHIPS: { key: string; label: string }[] = [
  { key: 'cisa', label: 'CISA' },
  { key: 'acsc', label: 'ACSC' },
  { key: 'jpcert', label: 'JPCERT' },
  { key: 'orkl', label: 'ORKL' },
];

/** Map IOC type to its CSS class suffix. */
function iocTypePillClass(type: string): string {
  const map: Record<string, string> = {
    md5: 'iocTypeMd5',
    sha1: 'iocTypeSha1',
    sha256: 'iocTypeSha256',
    sha512: 'iocTypeSha512',
    ssdeep: 'iocTypeSsdeep',
    ip: 'iocTypeIp',
    domain: 'iocTypeDomain',
    url: 'iocTypeUrl',
    email: 'iocTypeEmail',
    filepath: 'iocTypeFilepath',
    mutex: 'iocTypeMutex',
  };
  return map[type] || '';
}

/** Map validation status to its CSS class suffix. */
function validationPillClass(status: string): string {
  const map: Record<string, string> = {
    verified: 'iocValidationVerified',
    format_valid: 'iocValidationFormat_valid',
    allowlisted: 'iocValidationAllowlisted',
    invalid: 'iocValidationInvalid',
  };
  return map[status] || '';
}

const SORTABLE_COLUMNS: { key: string; label: string }[] = [
  { key: 'type', label: 'Type' },
  { key: 'value', label: 'Value' },
  { key: 'advisory_count', label: 'Advisories' },
  { key: 'validation_status', label: 'Validation' },
  { key: 'first_seen', label: 'First Seen' },
  { key: 'cross_ref_count', label: 'Cross-Ref' },
];

const formatDate = (date: string | null): string => {
  if (!date) return '--';
  return date.slice(0, 10);
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function IocSearch() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [searchInput, setSearchInput] = useState(searchParams.get('q') || '');
  const [expandedRow, setExpandedRow] = useState<{ type: string; value: string } | null>(null);
  const [normHint, setNormHint] = useState('');
  const [detectedType, setDetectedType] = useState<string | null>(null);
  const { addToast } = useToast();

  // Parse URL state
  const q = searchParams.get('q') || '';
  const typeFilter = searchParams.get('type') || '';
  const validationStatus = searchParams.get('validation_status') || '';
  const sourceFilter = searchParams.get('source') || '';
  const page = parseInt(searchParams.get('page') || '1', 10);
  const sort = searchParams.get('sort') || '';
  const sortDir = searchParams.get('sort_dir') || '';

  const hasFilters = !!(q || typeFilter || validationStatus || sourceFilter);

  // --- Helpers to update URL ---

  const updateFilter = useCallback(
    (key: string, value: string) => {
      const next = new URLSearchParams(searchParams);
      if (value) {
        next.set(key, value);
      } else {
        next.delete(key);
      }
      next.set('page', '1');
      setSearchParams(next);
    },
    [searchParams, setSearchParams],
  );

  const setPage = useCallback(
    (p: number) => {
      const next = new URLSearchParams(searchParams);
      next.set('page', String(p));
      setSearchParams(next);
    },
    [searchParams, setSearchParams],
  );

  const toggleSort = useCallback(
    (col: string) => {
      const next = new URLSearchParams(searchParams);
      if (sort === col) {
        next.set('sort_dir', sortDir === 'asc' ? 'desc' : 'asc');
      } else {
        next.set('sort', col);
        next.set('sort_dir', 'desc');
      }
      next.set('page', '1');
      setSearchParams(next);
    },
    [searchParams, setSearchParams, sort, sortDir],
  );

  // --- Search submit ---

  const handleSearch = useCallback(() => {
    const raw = searchInput.trim();
    if (!raw) {
      // Clear search
      const next = new URLSearchParams(searchParams);
      next.delete('q');
      next.set('page', '1');
      setSearchParams(next);
      setNormHint('');
      setDetectedType(null);
      return;
    }

    const normalized = refangValue(raw);
    const wasDefanged = normalized !== raw;
    const detected = detectIocType(normalized);

    setDetectedType(detected);
    setNormHint(wasDefanged ? `Normalized: ${normalized}` : '');

    const next = new URLSearchParams(searchParams);
    next.set('q', normalized);
    next.set('page', '1');
    setSearchParams(next);
  }, [searchInput, searchParams, setSearchParams]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        handleSearch();
      }
    },
    [handleSearch],
  );

  // Escape key closes expanded row
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setExpandedRow(null);
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, []);

  // Sync search input when URL q changes externally
  useEffect(() => {
    setSearchInput(q);
  }, [q]);

  // --- Type group chip toggle ---

  const activeTypes = typeFilter ? typeFilter.split(',') : [];

  const toggleTypeGroup = useCallback(
    (types: string[]) => {
      // If all types in this group are active, remove them; otherwise add them
      const allActive = types.every((t) => activeTypes.includes(t));
      let next: string[];
      if (allActive) {
        next = activeTypes.filter((t) => !types.includes(t));
      } else {
        const merged = new Set([...activeTypes, ...types]);
        next = Array.from(merged);
      }
      updateFilter('type', next.join(','));
    },
    [activeTypes, updateFilter],
  );

  // --- Validation chip toggle ---

  const activeValidations = validationStatus ? validationStatus.split(',') : [];

  const toggleValidation = useCallback(
    (key: string) => {
      const isActive = activeValidations.includes(key);
      const next = isActive
        ? activeValidations.filter((k) => k !== key)
        : [...activeValidations, key];
      updateFilter('validation_status', next.join(','));
    },
    [activeValidations, updateFilter],
  );

  // --- Source chip toggle ---

  const activeSources = sourceFilter ? sourceFilter.split(',') : [];

  const toggleSource = useCallback(
    (key: string) => {
      const isActive = activeSources.includes(key);
      const next = isActive
        ? activeSources.filter((k) => k !== key)
        : [...activeSources, key];
      updateFilter('source', next.join(','));
    },
    [activeSources, updateFilter],
  );

  // --- Build API params ---

  const apiParams: Record<string, string> = {
    page: String(page),
    per_page: String(PER_PAGE),
  };
  if (q) apiParams.q = q;
  if (typeFilter) apiParams.type = typeFilter;
  if (validationStatus) apiParams.validation_status = validationStatus;
  if (sourceFilter) apiParams.source = sourceFilter;
  if (sort) apiParams.sort = sort;
  if (sortDir) apiParams.sort_dir = sortDir;

  // --- Queries ---

  const statsQuery = useQuery({
    queryKey: ['ioc-stats'],
    queryFn: fetchIocStats,
    staleTime: 5 * 60 * 1000,
  });

  const iocsQuery = useQuery({
    queryKey: ['iocs', { q, type: typeFilter, validation_status: validationStatus, source: sourceFilter, page, sort, sort_dir: sortDir }],
    queryFn: () => fetchIocs(apiParams),
    staleTime: 30 * 1000,
  });

  const detailQuery = useQuery({
    queryKey: ['ioc-advisories', expandedRow?.type, expandedRow?.value],
    queryFn: () => fetchIocAdvisories(expandedRow!.type, expandedRow!.value),
    enabled: expandedRow != null,
    staleTime: 60 * 1000,
  });

  const totalPages = iocsQuery.data
    ? Math.ceil(iocsQuery.data.total / iocsQuery.data.per_page)
    : 0;

  // --- Export handlers ---

  const handleExport = useCallback(
    async (format: 'csv' | 'stix2') => {
      try {
        const exportParams: Record<string, string> = {};
        if (q) exportParams.q = q;
        if (typeFilter) exportParams.type = typeFilter;
        if (validationStatus) exportParams.validation_status = validationStatus;
        if (sourceFilter) exportParams.source = sourceFilter;
        const blob = await exportIocsGlobal(format, exportParams);
        const ext = format === 'csv' ? 'csv' : 'json';
        triggerDownload(blob, `iocs_export.${ext}`);
        addToast(`Exported IOCs as ${format.toUpperCase()}`, 'success');
      } catch {
        addToast('Export failed', 'error');
      }
    },
    [q, typeFilter, validationStatus, sourceFilter, addToast],
  );

  const handleCopyAll = useCallback(async () => {
    if (!iocsQuery.data) return;
    const values = iocsQuery.data.items.map((i: IocSearchItem) => i.value).join('\n');
    try {
      await navigator.clipboard.writeText(values);
      addToast('Copied all IOC values', 'success');
    } catch {
      addToast('Failed to copy', 'error');
    }
  }, [iocsQuery.data, addToast]);

  // --- Row expansion ---

  const toggleExpand = useCallback(
    (item: IocSearchItem) => {
      if (expandedRow && expandedRow.type === item.type && expandedRow.value === item.value) {
        setExpandedRow(null);
      } else {
        setExpandedRow({ type: item.type, value: item.value });
      }
    },
    [expandedRow],
  );

  // Determine first advisory ID from comma-separated list
  const firstAdvisoryId = (list: string): string | null => {
    if (!list) return null;
    const parts = list.split(',');
    return parts[0]?.trim() || null;
  };

  // Count advisories from comma-separated list
  const advisoryCount = (list: string): number => {
    if (!list) return 0;
    return list.split(',').filter(Boolean).length;
  };

  // --- Detect type from live input (for the badge) ---
  const liveDetectedType = detectedType ?? (searchInput.trim() ? detectIocType(refangValue(searchInput)) : null);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className={styles.page}>
      {/* Search Header */}
      <div className={styles.searchHeader}>
        <div className={styles.searchBar}>
          <span className={styles.searchIcon}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.3-4.3" />
            </svg>
          </span>
          <input
            className={styles.searchInput}
            type="text"
            placeholder="Search IOCs (hash, IP, domain, URL, email...)"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={handleKeyDown}
            spellCheck={false}
            autoComplete="off"
          />
          {liveDetectedType && (
            <span className={styles.typeBadge}>{liveDetectedType}</span>
          )}
          {searchInput && (
            <button
              className={styles.clearBtn}
              onClick={() => {
                setSearchInput('');
                setDetectedType(null);
                setNormHint('');
                const next = new URLSearchParams(searchParams);
                next.delete('q');
                next.set('page', '1');
                setSearchParams(next);
              }}
              aria-label="Clear search"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6 6 18M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
        {normHint && <div className={styles.normHint}>{normHint}</div>}
      </div>

      {/* Filter Bar */}
      <div className={styles.filterBar}>
        {/* Type groups */}
        {TYPE_GROUPS.map((group) => {
          const allActive = group.types.every((t) => activeTypes.includes(t));
          return (
            <button
              key={group.label}
              className={clsx(styles.chip, allActive && styles[group.activeClass])}
              onClick={() => toggleTypeGroup(group.types)}
              aria-pressed={allActive}
            >
              {group.label}
            </button>
          );
        })}

        <div className={styles.filterSep} />

        {/* Validation chips */}
        <div className={styles.chipGroup}>
          {VALIDATION_CHIPS.map((chip) => {
            const isActive = activeValidations.includes(chip.key);
            return (
              <button
                key={chip.key}
                className={clsx(styles.chip, isActive && styles[chip.activeClass])}
                onClick={() => toggleValidation(chip.key)}
                aria-pressed={isActive}
              >
                {chip.label}
              </button>
            );
          })}
        </div>

        <div className={styles.filterSep} />

        {/* Source chips */}
        <div className={styles.chipGroup}>
          {SOURCE_CHIPS.map((chip) => {
            const isActive = activeSources.includes(chip.key);
            return (
              <button
                key={chip.key}
                className={clsx(styles.chip, isActive && styles.chipActive)}
                onClick={() => toggleSource(chip.key)}
                aria-pressed={isActive}
              >
                {chip.label}
              </button>
            );
          })}
        </div>

        {hasFilters && (
          <button
            className={styles.clearFilters}
            onClick={() => {
              setSearchParams({ page: '1' });
              setSearchInput('');
              setDetectedType(null);
              setNormHint('');
            }}
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Error */}
      {iocsQuery.error && (
        <div className={styles.errorBanner}>
          Failed to load IOCs. Is the API server running?
        </div>
      )}

      {/* Loading */}
      {iocsQuery.isLoading && (
        <div className={styles.tableContainer}>
          <Skeleton lines={8} />
        </div>
      )}

      {/* Initial state: no filters, show landing */}
      {!hasFilters && !iocsQuery.isLoading && !iocsQuery.error && (
        <>
          <EmptyState
            title="Search IOCs"
            description="Search across all extracted indicators of compromise. Enter a hash, IP address, domain, URL, or email to find matching IOCs across advisories."
            icon={
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.3-4.3" />
              </svg>
            }
          />
          {statsQuery.data && <StatsGrid stats={statsQuery.data} />}
        </>
      )}

      {/* Results */}
      {hasFilters && !iocsQuery.isLoading && !iocsQuery.error && iocsQuery.data && (
        <>
          {iocsQuery.data.items.length === 0 ? (
            <EmptyState
              title="No matching IOCs found"
              description="No IOCs match the current search or filters. Try broadening your criteria."
            />
          ) : (
            <>
              {/* Results summary bar */}
              <div className={styles.resultsSummary}>
                <span className={styles.resultCount}>
                  {iocsQuery.data.total.toLocaleString()} IOC{iocsQuery.data.total !== 1 ? 's' : ''} found
                </span>
                <button
                  className={styles.exportBtn}
                  onClick={() => handleExport('csv')}
                >
                  Export CSV
                </button>
                <button
                  className={styles.exportBtn}
                  onClick={() => handleExport('stix2')}
                >
                  Export STIX
                </button>
                <button
                  className={styles.exportBtn}
                  onClick={handleCopyAll}
                >
                  Copy All
                </button>
              </div>

              {/* Table */}
              <div className={styles.tableContainer}>
                <table className={styles.resultsTable}>
                  <thead>
                    <tr>
                      {SORTABLE_COLUMNS.map((col) => (
                        <th
                          key={col.key}
                          className={clsx(
                            styles.sortHeader,
                            sort === col.key && styles.sortActive,
                          )}
                          onClick={() => toggleSort(col.key)}
                        >
                          {col.label}
                          {sort === col.key && (
                            <span className={styles.sortArrow}>
                              {sortDir === 'asc' ? '▴' : '▾'}
                            </span>
                          )}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {iocsQuery.data.items.map((item: IocSearchItem) => {
                      const isExpanded =
                        expandedRow != null &&
                        expandedRow.type === item.type &&
                        expandedRow.value === item.value;
                      const count = advisoryCount(item.advisory_id_list);
                      const firstId = firstAdvisoryId(item.advisory_id_list);
                      const firstNumericId = firstAdvisoryId(item.advisory_numeric_ids);

                      return (
                        <ResultRow
                          key={`${item.type}:${item.value}`}
                          item={item}
                          isExpanded={isExpanded}
                          onToggle={() => toggleExpand(item)}
                          count={count}
                          firstId={firstId}
                          firstNumericId={firstNumericId}
                          detailQuery={isExpanded ? detailQuery : undefined}
                        />
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <Pagination
                page={page}
                totalPages={totalPages}
                onPageChange={setPage}
              />
            </>
          )}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Result Row + Detail Panel
// ---------------------------------------------------------------------------

function ResultRow({
  item,
  isExpanded,
  onToggle,
  count,
  firstId,
  firstNumericId,
  detailQuery,
}: {
  item: IocSearchItem;
  isExpanded: boolean;
  onToggle: () => void;
  count: number;
  firstId: string | null;
  firstNumericId: string | null;
  detailQuery?: { data?: IocAdvisoryDetail[]; isLoading: boolean };
}) {
  return (
    <>
      <tr
        className={clsx(
          styles.row,
          isExpanded && styles.rowExpanded,
          item.cross_ref_count > 1 && styles.crossRefRow,
        )}
        onClick={onToggle}
      >
        <td>
          <span
            className={clsx(
              styles.iocTypePill,
              styles[iocTypePillClass(item.type)],
            )}
          >
            {item.type}
          </span>
        </td>
        <td>
          <span className={styles.iocValueCell}>
            <code className={styles.iocValue}>{item.value}</code>
            <CopyButton text={item.value} label={`Copy ${item.type}`} />
          </span>
        </td>
        <td>
          <span className={styles.advisoryCount}>{count}</span>
          {firstId && firstNumericId && (
            <Link
              to={`/advisory/${firstNumericId}`}
              className={styles.advisoryLink}
              onClick={(e) => e.stopPropagation()}
            >
              {firstId}
            </Link>
          )}
        </td>
        <td>
          <span
            className={clsx(
              styles.iocValidationPill,
              styles[validationPillClass(item.validation_status)],
            )}
          >
            {item.validation_status.replace('_', ' ')}
          </span>
        </td>
        <td className={styles.tdDate}>
          {formatDate(item.first_seen)}
        </td>
        <td>
          <span
            className={clsx(
              styles.crossRefBadge,
              item.cross_ref_count > 1 && styles.crossRefHighlight,
            )}
          >
            {item.cross_ref_count}
          </span>
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={6} className={styles.detailPanel}>
            <DetailPanel
              item={item}
              advisories={detailQuery?.data}
              isLoading={detailQuery?.isLoading ?? true}
            />
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Detail Panel (expanded row)
// ---------------------------------------------------------------------------

function DetailPanel({
  item,
  advisories,
  isLoading,
}: {
  item: IocSearchItem;
  advisories?: IocAdvisoryDetail[];
  isLoading: boolean;
}) {
  if (isLoading) {
    return <div className={styles.detailLoading}>Loading advisory details...</div>;
  }

  return (
    <div className={styles.detailPanelInner}>
      <div className={styles.detailColumns}>
        <div className={styles.detailSection}>
          <h4>Appearances ({advisories?.length ?? 0})</h4>
          {advisories && advisories.length > 0 ? (
            advisories.map((adv) => (
              <div key={adv.id} className={styles.advisoryCard}>
                <div className={styles.advisoryCardHeader}>
                  <Badge variant="source" value={adv.source} />
                  <Link
                    to={`/advisory/${adv.id}`}
                    className={styles.advisoryCardId}
                  >
                    {adv.advisory_id}
                  </Link>
                </div>
                {adv.title && (
                  <div className={styles.advisoryCardTitle} title={adv.title}>
                    {adv.title}
                  </div>
                )}
                {adv.context && (
                  <div className={styles.advisoryCardContext}>
                    &ldquo;{adv.context}&rdquo;
                  </div>
                )}
                <div className={styles.advisoryCardMeta}>
                  {adv.pub_date && <span>{adv.pub_date.slice(0, 10)}</span>}
                  {adv.actors.map((a) => (
                    <span key={a} className={styles.metaTag}>{a}</span>
                  ))}
                  {adv.malware.map((m) => (
                    <span key={m} className={styles.metaTag}>{m}</span>
                  ))}
                </div>
              </div>
            ))
          ) : (
            <div className={styles.detailLoading}>No advisory details available.</div>
          )}
        </div>
        <div className={styles.detailSection}>
          <h4>IOC Details</h4>
          <div className={styles.advisoryCard}>
            <div className={styles.advisoryCardMeta}>
              <span>Type: <strong>{item.type}</strong></span>
            </div>
            <div className={styles.advisoryCardMeta}>
              <span>Validation: <strong>{item.validation_status.replace('_', ' ')}</strong></span>
            </div>
            <div className={styles.advisoryCardMeta}>
              <span>Source verified: <strong>{item.source_verified ? 'Yes' : 'No'}</strong></span>
            </div>
            <div className={styles.advisoryCardMeta}>
              <span>First seen: <strong>{formatDate(item.first_seen)}</strong></span>
            </div>
            <div className={styles.advisoryCardMeta}>
              <span>Last seen: <strong>{formatDate(item.last_seen)}</strong></span>
            </div>
            <div className={styles.advisoryCardMeta}>
              <span>Cross-references: <strong>{item.cross_ref_count}</strong></span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stats Grid (landing page)
// ---------------------------------------------------------------------------

function StatsGrid({ stats }: { stats: { total_iocs: number; by_type: Record<string, number>; advisories_with_iocs: number; cross_referenced: number } }) {
  return (
    <div className={styles.statsGrid}>
      <div className={styles.statCard}>
        <div className={styles.statValue}>{stats.total_iocs.toLocaleString()}</div>
        <div className={styles.statLabel}>Total IOCs</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statBreakdown}>
          {Object.entries(stats.by_type).map(([type, count]) => (
            <div key={type} className={styles.statRow}>
              <span className={styles.statRowLabel}>{type}</span>
              <span className={styles.statRowValue}>{count}</span>
            </div>
          ))}
        </div>
        <div className={styles.statLabel}>By Type</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statValue}>{stats.advisories_with_iocs.toLocaleString()}</div>
        <div className={styles.statLabel}>Advisories with IOCs</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statValue}>{stats.cross_referenced.toLocaleString()}</div>
        <div className={styles.statLabel}>Cross-Referenced</div>
      </div>
    </div>
  );
}
