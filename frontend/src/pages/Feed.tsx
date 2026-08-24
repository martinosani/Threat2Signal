import { useState, useEffect, useRef, useCallback } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import type { LlmStats, StatsResponse } from '../lib/types';
import { fetchAdvisories, fetchStats, fetchLlmStats } from '../lib/api';
import { Badge } from '../components/Badge';
import { Pagination } from '../components/Pagination';
import { Skeleton } from '../components/Skeleton';
import { EmptyState } from '../components/EmptyState';
import styles from './Feed.module.css';

const LAST_SEEN_KEY = 'threat2signal_last_seen';
const PER_PAGE = 50;

const SOURCE_OPTIONS = [
  { value: 'cisa', label: 'CISA' },
  { value: 'acsc', label: 'ACSC' },
  { value: 'jpcert', label: 'JPCERT' },
  { value: 'orkl', label: 'ORKL' },
];

const TYPE_OPTIONS = [
  { value: 'cybersecurity_advisory', label: 'Cybersecurity Advisory' },
  { value: 'analysis_report', label: 'Analysis Report' },
  { value: 'advisory', label: 'Advisory' },
  { value: 'cti_report', label: 'CTI Report' },
  { value: 'jpcert_blog', label: 'JPCERT Blog' },
];

// F.13 / C5: Extraction filter chips SEND their analyst-facing group key
// (ready/processing/issues/skipped) to the API, which expands each to the
// underlying DB statuses server-side. Raw DB statuses never leak into the URL.
const EXTRACTION_CHIPS = [
  { key: 'ready', label: 'Ready', activeClass: 'chipGreenActive' },
  { key: 'processing', label: 'Processing', activeClass: 'chipBlueActive' },
  { key: 'issues', label: 'Issues', activeClass: 'chipAmberActive' },
  { key: 'skipped', label: 'Skipped', activeClass: 'chipGrayActive' },
];

// F.17: Triage filter chip definitions
const TRIAGE_CHIPS = [
  { key: 'unread', label: 'Unread', icon: '●', activeClass: 'chipTriageActive' },
  { key: 'flagged', label: 'Flagged', icon: '★', activeClass: 'chipTriageFlaggedActive' },
  { key: 'reviewed', label: 'Reviewed', icon: '✓', activeClass: 'chipTriageActive' },
];

export default function Feed() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [statsOpen, setStatsOpen] = useState(true);
  const lastSeen = useRef<string | null>(localStorage.getItem(LAST_SEEN_KEY));
  const navigate = useNavigate();

  // Update last seen timestamp on mount
  useEffect(() => {
    localStorage.setItem(LAST_SEEN_KEY, new Date().toISOString());
  }, []);

  // Parse filters from URL
  const page = parseInt(searchParams.get('page') || '1', 10);
  const sourceFilter = searchParams.get('source') || '';
  const typeFilter = searchParams.get('type') || '';
  const extractionFilter = searchParams.get('extraction_status') || '';
  const triageFilter = searchParams.get('triage_status') || '';

  // Derived chip state — extraction filter now carries group keys, not statuses.
  const activeExtractionGroups = extractionFilter ? extractionFilter.split(',') : [];
  const activeTriageStatuses = triageFilter ? triageFilter.split(',') : [];

  // Build API params
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(PER_PAGE),
  };
  if (sourceFilter) params.source = sourceFilter;
  if (typeFilter) params.type = typeFilter;
  if (extractionFilter) params.extraction_status = extractionFilter;
  if (triageFilter) params.triage_status = triageFilter;

  const {
    data: advisories,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['advisories', page, sourceFilter, typeFilter, extractionFilter, triageFilter],
    queryFn: () => fetchAdvisories(params),
    staleTime: 5 * 60 * 1000,
  });

  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    staleTime: 5 * 60 * 1000,
  });

  const { data: llmStats } = useQuery({
    queryKey: ['llm-stats'],
    queryFn: fetchLlmStats,
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });

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

  // F.13 / C5: Toggle an extraction chip — add/remove its group key.
  const toggleExtractionChip = useCallback(
    (key: string) => {
      const isActive = activeExtractionGroups.includes(key);
      const next = isActive
        ? activeExtractionGroups.filter((k) => k !== key)
        : [...activeExtractionGroups, key];
      updateFilter('extraction_status', next.join(','));
    },
    [activeExtractionGroups, updateFilter],
  );

  // F.17: Toggle a triage chip
  const toggleTriageChip = useCallback(
    (key: string) => {
      const isActive = activeTriageStatuses.includes(key);
      let next: string[];
      if (isActive) {
        next = activeTriageStatuses.filter((s) => s !== key);
      } else {
        next = [...activeTriageStatuses, key];
      }
      updateFilter('triage_status', next.join(','));
    },
    [activeTriageStatuses, updateFilter],
  );

  const hasAnyFilter = !!(sourceFilter || typeFilter || extractionFilter || triageFilter);

  const totalPages = advisories
    ? Math.ceil(advisories.total / advisories.per_page)
    : 0;

  const isNew = (firstSeen: string): boolean => {
    if (!lastSeen.current) return false;
    return new Date(firstSeen) > new Date(lastSeen.current);
  };

  const formatDate = (date: string | null): string => {
    if (!date) return '--';
    return date.slice(0, 10); // YYYY-MM-DD
  };

  const formatRelative = (date: string | null): string => {
    if (!date) return '';
    try {
      return formatDistanceToNow(new Date(date), { addSuffix: true });
    } catch {
      return '';
    }
  };

  const truncate = (text: string | null, max: number): string => {
    if (!text) return '--';
    if (text.length <= max) return text;
    return text.slice(0, max) + '...';
  };

  return (
    <div className={styles.feed}>
      {/* Stats Header */}
      {stats && (
        <div className={styles.statsHeader}>
          <button
            className={styles.statsToggle}
            onClick={() => setStatsOpen(!statsOpen)}
            aria-expanded={statsOpen}
          >
            <span>Stats</span>
            <span className={styles.toggleIcon}>
              {statsOpen ? '▴' : '▾'}
            </span>
          </button>
          {statsOpen && <StatsBar stats={stats} llmStats={llmStats} />}
        </div>
      )}

      {/* Filter Bar */}
      <div className={styles.filterBar}>
        {/* F.17: Triage chip toggles */}
        <div className={styles.chipGroup}>
          {TRIAGE_CHIPS.map((chip) => {
            const isActive = activeTriageStatuses.includes(chip.key);
            return (
              <button
                key={chip.key}
                className={clsx(
                  styles.chip,
                  isActive && styles[chip.activeClass],
                )}
                onClick={() => toggleTriageChip(chip.key)}
                aria-pressed={isActive}
              >
                <span className={styles.chipIcon}>{chip.icon}</span>
                {chip.label}
              </button>
            );
          })}
        </div>

        <div className={styles.filterSep} />

        {/* Source / Type dropdowns */}
        <FilterDropdown
          label="Source"
          options={SOURCE_OPTIONS}
          selected={sourceFilter ? sourceFilter.split(',') : []}
          onChange={(values) => updateFilter('source', values.join(','))}
        />
        <FilterDropdown
          label="Type"
          options={TYPE_OPTIONS}
          selected={typeFilter ? typeFilter.split(',') : []}
          onChange={(values) => updateFilter('type', values.join(','))}
        />

        <div className={styles.filterSep} />

        {/* F.13: Extraction chip toggles */}
        <div className={styles.chipGroup}>
          {EXTRACTION_CHIPS.map((chip) => {
            const isActive = activeExtractionGroups.includes(chip.key);
            return (
              <button
                key={chip.key}
                className={clsx(
                  styles.chip,
                  isActive && styles[chip.activeClass],
                )}
                onClick={() => toggleExtractionChip(chip.key)}
                aria-pressed={isActive}
              >
                {chip.label}
              </button>
            );
          })}
        </div>

        {hasAnyFilter && (
          <button
            className={styles.clearFilters}
            onClick={() => {
              setSearchParams({ page: '1' });
            }}
          >
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
          Failed to load advisories. Is the API server running?
        </div>
      )}

      {/* Empty State */}
      {!isLoading && !error && advisories && advisories.items.length === 0 && (
        <EmptyState
          title={
            hasAnyFilter
              ? 'No matching advisories'
              : 'No advisories ingested yet'
          }
          description={
            hasAnyFilter
              ? 'No advisories match the current filters. Try broadening your search.'
              : 'Run threat2signal poll or threat2signal backfill-cisa to get started.'
          }
        />
      )}

      {/* Advisory Table */}
      {!isLoading && advisories && advisories.items.length > 0 && (
        <>
          <div className={styles.tableContainer}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.thTriage}>Triage</th>
                  <th className={styles.thId}>ID</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th className={styles.thTitle}>Title</th>
                  <th>Date</th>
                  <th>Extraction</th>
                </tr>
              </thead>
              <tbody>
                {advisories.items.map((advisory) => (
                  <tr
                    key={advisory.id}
                    className={clsx(
                      styles.row,
                      isNew(advisory.first_seen) && styles.rowNew,
                    )}
                    onClick={() =>
                      navigate(`/advisory/${advisory.id}`)
                    }
                  >
                    <td className={styles.tdTriage}>
                      <TriageDot status={advisory.triage_status} />
                    </td>
                    <td className={styles.tdId}>
                      <Link
                        to={`/advisory/${advisory.id}`}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {advisory.id}
                      </Link>
                    </td>
                    <td>
                      <Badge variant="source" value={advisory.source} />
                      {advisory.original_source && (
                        <span className={styles.originalSource}>
                          {' '}&rarr; {advisory.original_source}
                        </span>
                      )}
                    </td>
                    <td>
                      <Badge variant="type" value={advisory.type} />
                    </td>
                    <td
                      className={styles.tdTitle}
                      title={advisory.title ?? undefined}
                    >
                      {truncate(advisory.title, 80)}
                    </td>
                    <td
                      className={styles.tdDate}
                      title={formatRelative(advisory.pub_date)}
                    >
                      {formatDate(advisory.pub_date)}
                    </td>
                    <td>
                      <Badge
                        variant="status"
                        value={advisory.extraction_status}
                      />
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
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stats Bar (collapsible header)
// ---------------------------------------------------------------------------

function StatsBar({ stats, llmStats }: { stats: StatsResponse; llmStats?: LlmStats }) {
  const { advisories, polls } = stats;

  // F.18: Group extraction counts into 3 categories
  const done = advisories.by_extraction['completed'] ?? 0;
  const processing =
    (advisories.by_extraction['pending'] ?? 0) +
    (advisories.by_extraction['parse_done'] ?? 0);
  const issues =
    (advisories.by_extraction['parse_partial'] ?? 0) +
    (advisories.by_extraction['parse_failed'] ?? 0) +
    (advisories.by_extraction['failed'] ?? 0);

  return (
    <div className={styles.statsGrid}>
      <div className={styles.statCard}>
        <div className={styles.statValue}>{advisories.total}</div>
        <div className={styles.statLabel}>Total Advisories</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statBreakdown}>
          {Object.entries(advisories.by_source).map(([source, count]) => (
            <div key={source} className={styles.statRow}>
              <span className={styles.statRowLabel}>{source.toUpperCase()}</span>
              <span className={styles.statRowValue}>{count}</span>
            </div>
          ))}
        </div>
        <div className={styles.statLabel}>By Source</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statBreakdown}>
          <div className={styles.statRow}>
            <span className={styles.statRowLabel}>Done</span>
            <span className={styles.statRowValue}>{done}</span>
          </div>
          <div className={styles.statRow}>
            <span className={styles.statRowLabel}>Processing</span>
            <span className={styles.statRowValue}>{processing}</span>
          </div>
          <div className={styles.statRow}>
            <span className={styles.statRowLabel}>Issues</span>
            <span
              className={clsx(
                styles.statRowValue,
                issues > 0 && styles.statFailed,
              )}
            >
              {issues}
            </span>
          </div>
        </div>
        <div className={styles.statLabel}>Extraction</div>
      </div>
      <div className={styles.statCard}>
        <div className={styles.statValue}>
          {polls.cisa
            ? formatDistanceToNow(new Date(polls.cisa), {
                addSuffix: true,
              })
            : 'never'}
        </div>
        <div className={styles.statLabel}>Last Poll</div>
      </div>
      {llmStats && llmStats.call_count > 0 && (
        <div className={styles.statCard}>
          <div className={styles.statBreakdown}>
            <div className={styles.statRow}>
              <span className={styles.statRowLabel}>Cost</span>
              <span className={styles.statRowValue}>
                ${llmStats.total_cost.toFixed(4)}
              </span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statRowLabel}>Tokens</span>
              <span className={styles.statRowValue}>
                {(llmStats.total_input_tokens + llmStats.total_output_tokens).toLocaleString()}
              </span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statRowLabel}>Avg/advisory</span>
              <span className={styles.statRowValue}>
                ${llmStats.avg_cost_per_advisory.toFixed(4)}
              </span>
            </div>
            {llmStats.calls_by_phase && Object.keys(llmStats.calls_by_phase).length > 0 && (
              <>
                {Object.entries(llmStats.calls_by_phase).map(([phase, count]) => (
                  <div key={phase} className={styles.statRow}>
                    <span className={styles.statRowLabel}>{phase}</span>
                    <span className={styles.statRowValue}>{count}</span>
                  </div>
                ))}
              </>
            )}
          </div>
          <div className={styles.statLabel}>LLM ({llmStats.call_count} calls)</div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Triage Dot
// ---------------------------------------------------------------------------

function TriageDot({ status }: { status: string }) {
  if (status === 'reviewed') return <span className={styles.triageEmpty} />;
  return (
    <span
      className={clsx(
        styles.triageDot,
        status === 'flagged' ? styles.triageFlagged : styles.triageUnread,
      )}
      title={status}
    >
      {status === 'flagged' ? '★' : '●'}
    </span>
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
