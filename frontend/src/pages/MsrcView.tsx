/** MSRC CVE listing page — filterable table with sortable columns and slide-out detail panel. */

import { useState, useEffect, useRef, useCallback } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import type { MsrcStatsResponse } from '../lib/types';
import { fetchMsrcCves, fetchMsrcStats } from '../lib/api';
import { Badge } from '../components/Badge';
import { Pagination } from '../components/Pagination';
import { Skeleton } from '../components/Skeleton';
import { EmptyState } from '../components/EmptyState';
import { CveDetailPanel } from '../components/msrc/CveDetailPanel';
import styles from './MsrcView.module.css';

const PER_PAGE = 50;

const PRIORITY_OPTIONS = [
  { value: 'HIGH', label: 'HIGH' },
  { value: 'MEDIUM', label: 'MEDIUM' },
  { value: 'LOW', label: 'LOW' },
  { value: 'NOISE', label: 'NOISE' },
];

const SEVERITY_OPTIONS = [
  { value: 'Critical', label: 'Critical' },
  { value: 'Important', label: 'Important' },
  { value: 'Moderate', label: 'Moderate' },
  { value: 'Low', label: 'Low' },
];

const IMPACT_OPTIONS = [
  { value: 'Remote Code Execution', label: 'Remote Code Execution' },
  { value: 'Elevation of Privilege', label: 'Elevation of Privilege' },
  { value: 'Information Disclosure', label: 'Information Disclosure' },
  { value: 'Denial of Service', label: 'Denial of Service' },
  { value: 'Security Feature Bypass', label: 'Security Feature Bypass' },
  { value: 'Spoofing', label: 'Spoofing' },
  { value: 'Tampering', label: 'Tampering' },
];

const VR_PRIORITY_OPTIONS = [
  { value: 'PRIME', label: 'PRIME' },
  { value: 'HIGH', label: 'HIGH' },
  { value: 'MEDIUM', label: 'MEDIUM' },
  { value: 'LOW', label: 'LOW' },
  { value: 'NOISE', label: 'NOISE' },
];

const EXPLOIT_OPTIONS = [
  { value: 'kev', label: 'KEV Listed' },
  { value: 'exploited_wild', label: 'Exploited in Wild' },
  { value: 'publicly_disclosed', label: 'Publicly Disclosed' },
];

type ViewMode = 'defense' | 'research';

type SortField =
  | 'defense_score'
  | 'vr_score'
  | 'cvss_base'
  | 'cve_id'
  | 'priority'
  | 'vr_priority'
  | 'severity'
  | 'released';

const DEFENSE_COLUMNS: { field: SortField; label: string }[] = [
  { field: 'priority', label: 'Priority' },
  { field: 'cve_id', label: 'CVE ID' },
  { field: 'severity', label: 'Severity' },
  { field: 'cvss_base', label: 'CVSS' },
  { field: 'defense_score', label: 'Score' },
  { field: 'released', label: 'Released' },
];

const RESEARCH_COLUMNS: { field: SortField; label: string }[] = [
  { field: 'vr_priority', label: 'Priority' },
  { field: 'cve_id', label: 'CVE ID' },
  { field: 'severity', label: 'Severity' },
  { field: 'cvss_base', label: 'CVSS' },
  { field: 'vr_score', label: 'Score' },
  { field: 'released', label: 'Released' },
];

export default function MsrcView() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [statsOpen, setStatsOpen] = useState(true);
  const [searchText, setSearchText] = useState(searchParams.get('search') || '');
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Parse URL state
  const viewMode: ViewMode = (searchParams.get('view') as ViewMode) || 'defense';
  const page = parseInt(searchParams.get('page') || '1', 10);
  const priorityFilter = viewMode === 'research'
    ? (searchParams.get('vr_priority') || '')
    : (searchParams.get('priority') || '');
  const severityFilter = searchParams.get('severity') || '';
  const impactFilter = searchParams.get('impact') || '';
  const exploitFilter = searchParams.get('exploit_status') || '';
  const sortField = (searchParams.get('sort') as SortField) || (viewMode === 'research' ? 'vr_score' : 'defense_score');
  const sortDir = searchParams.get('sort_dir') || 'desc';
  const selectedCve = searchParams.get('selected') || '';
  const searchQuery = searchParams.get('search') || '';

  const SORTABLE_COLUMNS = viewMode === 'research' ? RESEARCH_COLUMNS : DEFENSE_COLUMNS;

  // Build API params
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(PER_PAGE),
    sort: sortField,
    sort_dir: sortDir,
  };
  if (priorityFilter) {
    if (viewMode === 'research') {
      params.vr_priority = priorityFilter;
    } else {
      params.priority = priorityFilter;
    }
  }
  if (severityFilter) params.severity = severityFilter;
  if (impactFilter) params.impact = impactFilter;
  if (exploitFilter) params.exploit_status = exploitFilter;
  if (searchQuery) params.search = searchQuery;

  const {
    data: cves,
    isLoading,
    error,
  } = useQuery({
    queryKey: [
      'msrc-cves',
      viewMode,
      page,
      priorityFilter,
      severityFilter,
      impactFilter,
      exploitFilter,
      sortField,
      sortDir,
      searchQuery,
    ],
    queryFn: () => fetchMsrcCves(params),
    staleTime: 5 * 60 * 1000,
  });

  const { data: stats } = useQuery({
    queryKey: ['msrc-stats'],
    queryFn: fetchMsrcStats,
    staleTime: 5 * 60 * 1000,
  });

  // --- Helpers ---

  const setView = useCallback(
    (v: ViewMode) => {
      const next = new URLSearchParams(searchParams);
      next.set('view', v);
      // Switch to appropriate default sort
      next.set('sort', v === 'research' ? 'vr_score' : 'defense_score');
      next.set('sort_dir', 'desc');
      next.set('page', '1');
      // Clear priority filters since they use different tiers
      next.delete('priority');
      next.delete('vr_priority');
      setSearchParams(next);
    },
    [searchParams, setSearchParams],
  );

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
    (field: SortField) => {
      const next = new URLSearchParams(searchParams);
      if (field === sortField) {
        next.set('sort_dir', sortDir === 'desc' ? 'asc' : 'desc');
      } else {
        next.set('sort', field);
        next.set('sort_dir', 'desc');
      }
      next.set('page', '1');
      setSearchParams(next);
    },
    [searchParams, setSearchParams, sortField, sortDir],
  );

  const selectCve = useCallback(
    (cveId: string) => {
      const next = new URLSearchParams(searchParams);
      next.set('selected', cveId);
      setSearchParams(next);
    },
    [searchParams, setSearchParams],
  );

  const closePanel = useCallback(() => {
    const next = new URLSearchParams(searchParams);
    next.delete('selected');
    setSearchParams(next);
  }, [searchParams, setSearchParams]);

  const hasFilters = !!(
    priorityFilter ||
    severityFilter ||
    impactFilter ||
    exploitFilter ||
    searchQuery ||
    (viewMode === 'research' && searchParams.get('vr_priority'))
  );

  const clearAllFilters = useCallback(() => {
    const next = new URLSearchParams();
    next.set('page', '1');
    if (viewMode !== 'defense') next.set('view', viewMode);
    const defaultSort = viewMode === 'research' ? 'vr_score' : 'defense_score';
    if (sortField !== defaultSort) next.set('sort', sortField);
    if (sortDir !== 'desc') next.set('sort_dir', sortDir);
    if (selectedCve) next.set('selected', selectedCve);
    setSearchParams(next);
    setSearchText('');
  }, [selectedCve, sortField, sortDir, viewMode, setSearchParams]);

  // Debounced search
  const handleSearchChange = useCallback(
    (value: string) => {
      setSearchText(value);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        updateFilter('search', value);
      }, 300);
    },
    [updateFilter],
  );

  // Cleanup debounce on unmount
  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  // Sync search text when URL changes via browser navigation
  useEffect(() => {
    const urlSearch = searchParams.get('search') || '';
    if (urlSearch !== searchText) setSearchText(urlSearch);
  }, [searchParams]); // eslint-disable-line react-hooks/exhaustive-deps

  // Close panel on Escape key
  useEffect(() => {
    if (!selectedCve) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closePanel();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [selectedCve, closePanel]);

  const totalPages = cves ? Math.ceil(cves.total / cves.per_page) : 0;

  const formatDate = (date: string | null): string => {
    if (!date) return '--';
    return date.slice(0, 10);
  };

  const truncate = (text: string | null, max: number): string => {
    if (!text) return '--';
    if (text.length <= max) return text;
    return text.slice(0, max) + '...';
  };

  const getSortIndicator = (field: SortField): string => {
    if (field !== sortField) return '';
    return sortDir === 'asc' ? ' ▲' : ' ▼';
  };

  return (
    <div className={styles.page}>
      {/* Stats Header */}
      {stats && (
        <div className={styles.statsHeader}>
          <button
            className={styles.statsToggle}
            onClick={() => setStatsOpen(!statsOpen)}
            aria-expanded={statsOpen}
          >
            <span>MSRC Stats</span>
            <span className={styles.toggleIcon}>
              {statsOpen ? '▴' : '▾'}
            </span>
          </button>
          {statsOpen && <MsrcStatsBar stats={stats} viewMode={viewMode} />}
        </div>
      )}

      {/* Filter Bar */}
      <div className={styles.filterBar}>
        <div className={styles.viewToggle}>
          <button
            className={clsx(styles.viewBtn, viewMode === 'defense' && styles.viewBtnActive)}
            onClick={() => setView('defense')}
          >
            Defense
          </button>
          <button
            className={clsx(styles.viewBtn, viewMode === 'research' && styles.viewBtnActive)}
            onClick={() => setView('research')}
          >
            Research
          </button>
        </div>
        <FilterDropdown
          label="Priority"
          options={viewMode === 'research' ? VR_PRIORITY_OPTIONS : PRIORITY_OPTIONS}
          selected={priorityFilter ? priorityFilter.split(',') : []}
          onChange={(values) => updateFilter(viewMode === 'research' ? 'vr_priority' : 'priority', values.join(','))}
        />
        <FilterDropdown
          label="Severity"
          options={SEVERITY_OPTIONS}
          selected={severityFilter ? severityFilter.split(',') : []}
          onChange={(values) => updateFilter('severity', values.join(','))}
        />
        <FilterDropdown
          label="Impact"
          options={IMPACT_OPTIONS}
          selected={impactFilter ? impactFilter.split(',') : []}
          onChange={(values) => updateFilter('impact', values.join(','))}
        />
        <FilterDropdown
          label="Exploit Status"
          options={EXPLOIT_OPTIONS}
          selected={exploitFilter ? exploitFilter.split(',') : []}
          onChange={(values) => updateFilter('exploit_status', values.join(','))}
        />
        <input
          type="text"
          className={styles.searchInput}
          placeholder="Search CVE ID or title..."
          value={searchText}
          onChange={(e) => handleSearchChange(e.target.value)}
        />
        {hasFilters && (
          <button className={styles.clearFilters} onClick={clearAllFilters}>
            Clear filters
          </button>
        )}
      </div>

      {/* Loading State */}
      {isLoading && (
        <div className={styles.tableContainer}>
          <Skeleton lines={8} />
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className={styles.errorBanner}>
          Failed to load MSRC CVEs. Is the API server running?
        </div>
      )}

      {/* Empty State */}
      {!isLoading && !error && cves && cves.items.length === 0 && (
        <EmptyState
          title={
            hasFilters
              ? 'No matching CVEs'
              : 'No MSRC data yet'
          }
          description={
            hasFilters
              ? 'No CVEs match the current filters. Try broadening your search.'
              : 'Run threat2signal poll-msrc to ingest Microsoft Security Response Center CVEs with defense scoring and KEV enrichment.'
          }
        />
      )}

      {/* CVE Table */}
      {!isLoading && cves && cves.items.length > 0 && (
        <>
          <div className={styles.tableContainer}>
            <table className={styles.table}>
              <thead>
                <tr>
                  {SORTABLE_COLUMNS.slice(0, 2).map((col) => (
                    <th
                      key={col.field}
                      className={styles.thSortable}
                      onClick={() => toggleSort(col.field)}
                    >
                      {col.label}
                      <span className={styles.sortIndicator}>
                        {getSortIndicator(col.field)}
                      </span>
                    </th>
                  ))}
                  <th className={styles.thTitle}>Title</th>
                  <th>Component</th>
                  <th>Impact</th>
                  {SORTABLE_COLUMNS.slice(2).map((col) => (
                    <th
                      key={col.field}
                      className={clsx(
                        styles.thSortable,
                        col.field === 'cvss_base' && styles.thCvss,
                        (col.field === 'defense_score' || col.field === 'vr_score') && styles.thScore,
                      )}
                      onClick={() => toggleSort(col.field)}
                    >
                      {col.label}
                      <span className={styles.sortIndicator}>
                        {getSortIndicator(col.field)}
                      </span>
                    </th>
                  ))}
                  <th>Exploited</th>
                  {viewMode === 'research' && <th>Tags</th>}
                  <th>Advisory</th>
                  <th>Action</th>
                  <th>CWE</th>
                </tr>
              </thead>
              <tbody>
                {cves.items.map((cve) => (
                  <tr
                    key={cve.cve_id}
                    className={clsx(
                      styles.row,
                      selectedCve === cve.cve_id && styles.rowSelected,
                    )}
                    onClick={() => selectCve(cve.cve_id)}
                  >
                    <td>
                      <Badge variant="priority" value={viewMode === 'research' ? cve.vr_priority : cve.priority} />
                    </td>
                    <td className={styles.tdCveId}>
                      <Link
                        to={`/msrc/${cve.cve_id}`}
                        className={styles.cveIdLink}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {cve.cve_id}
                      </Link>
                    </td>
                    <td
                      className={styles.tdTitle}
                      title={cve.title ?? undefined}
                    >
                      {truncate(cve.title, 60)}
                    </td>
                    <td>{cve.component ?? '--'}</td>
                    <td>{cve.impact ?? '--'}</td>
                    <td>
                      {cve.severity ? (
                        <Badge variant="severity" value={cve.severity} />
                      ) : (
                        '--'
                      )}
                    </td>
                    <td className={styles.tdMono}>
                      {cve.cvss_base != null
                        ? cve.cvss_base.toFixed(1)
                        : '--'}
                    </td>
                    <td className={styles.tdMono}>{viewMode === 'research' ? cve.vr_score : cve.defense_score}</td>
                    <td className={styles.tdMono}>
                      {formatDate(cve.released)}
                    </td>
                    <td className={styles.tdExploit}>
                      {cve.kev_listed && <span className={styles.exploitBadge} data-type="kev">KEV</span>}
                      {cve.exploited_wild && <span className={styles.exploitBadge} data-type="exploited">Exploited</span>}
                      {cve.publicly_disclosed && <span className={styles.exploitBadge} data-type="disclosed">Disclosed</span>}
                    </td>
                    {viewMode === 'research' && (
                      <td className={styles.tdTags}>
                        {cve.vr_tags.slice(0, 4).map((tag) => (
                          <span key={tag} className={styles.vrTag} data-tag={tag}>
                            {tag}
                          </span>
                        ))}
                        {cve.vr_tags.length > 4 && (
                          <span className={styles.vrTagOverflow}>+{cve.vr_tags.length - 4}</span>
                        )}
                      </td>
                    )}
                    <td className={styles.tdAdvisory}>
                      {cve.advisory_ids.length > 0
                        ? cve.advisory_ids.map((adv, i) => (
                            <span key={adv.id}>
                              {i > 0 && ', '}
                              <a
                                href={`/advisory/${adv.id}`}
                                onClick={(e) => e.stopPropagation()}
                                className={styles.advisoryLink}
                              >
                                {adv.id}
                              </a>
                            </span>
                          ))
                        : '--'}
                    </td>
                    <td>
                      {cve.customer_action ? (
                        <Badge variant="status" value="Required" />
                      ) : (
                        '--'
                      )}
                    </td>
                    <td className={styles.tdCwe} title={cve.cwe_description ?? undefined}>
                      {cve.cwe_id ?? '--'}
                    </td>
                  </tr>
                ))}
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

      {/* Slide-out Detail Panel */}
      {selectedCve && (
        <>
          <div className={styles.panelOverlay} onClick={closePanel} />
          <div className={styles.slidePanel}>
            <CveDetailPanel cveId={selectedCve} onClose={closePanel} />
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MSRC Stats Bar (collapsible header)
// ---------------------------------------------------------------------------

function MsrcStatsBar({ stats, viewMode }: { stats: MsrcStatsResponse; viewMode: ViewMode }) {
  const formatRelative = (date: string | null): string => {
    if (!date) return 'never';
    try {
      return formatDistanceToNow(new Date(date), { addSuffix: true });
    } catch {
      return 'unknown';
    }
  };

  const priorityData = viewMode === 'research' ? stats.by_vr_priority : stats.by_priority;

  return (
    <div className={styles.statsGrid}>
      <div className={styles.statCard}>
        <div className={styles.statValue}>{stats.total_cves}</div>
        <div className={styles.statLabel}>Total CVEs</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statBreakdown}>
          {priorityData && Object.entries(priorityData).map(([priority, count]) => (
            <div key={priority} className={styles.statRow}>
              <span className={styles.statRowLabel}>{priority}</span>
              <span className={styles.statRowValue}>{count}</span>
            </div>
          ))}
        </div>
        <div className={styles.statLabel}>
          {viewMode === 'research' ? 'By VR Priority' : 'By Priority'}
        </div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statValue}>{stats.kev_count}</div>
        <div className={styles.statLabel}>KEV Listed</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statValue}>{stats.exploited_count}</div>
        <div className={styles.statLabel}>Exploited in Wild</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statValue}>
          {formatRelative(stats.last_poll)}
        </div>
        <div className={styles.statLabel}>Last Poll</div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filter Dropdown (multi-select with checkboxes)
// ---------------------------------------------------------------------------

function FilterDropdown({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: { value: string; label: string }[];
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  const toggle = (value: string) => {
    const next = selected.includes(value)
      ? selected.filter((v) => v !== value)
      : [...selected, value];
    onChange(next);
  };

  return (
    <div className={styles.filterDropdown} ref={ref}>
      <button
        className={clsx(
          styles.filterButton,
          selected.length > 0 && styles.filterActive,
        )}
        onClick={() => setOpen(!open)}
      >
        {label}
        {selected.length > 0 && (
          <span className={styles.filterCount}>{selected.length}</span>
        )}
        <span className={styles.filterChevron}>
          {open ? '▴' : '▾'}
        </span>
      </button>
      {open && (
        <div className={styles.filterMenu}>
          {options.map((opt) => (
            <label key={opt.value} className={styles.filterOption}>
              <input
                type="checkbox"
                checked={selected.includes(opt.value)}
                onChange={() => toggle(opt.value)}
              />
              <span>{opt.label}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
