import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import type { Behavior } from '../../lib/types';
import { fetchAdvisoryBehaviors } from '../../lib/api';
import { Skeleton } from '../Skeleton';
import styles from './advisory-tabs.module.css';

interface BehaviorsTabProps {
  advisoryId: number;
  enabled: boolean;
}

type ConfidenceFilter = 'all' | 'advisory_stated' | 'llm_extracted' | 'llm_inferred';

const KILL_CHAIN_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

const CONFIDENCE_OPTIONS: { value: ConfidenceFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'advisory_stated', label: 'Stated' },
  { value: 'llm_extracted', label: 'Extracted' },
  { value: 'llm_inferred', label: 'Inferred' },
];

const CONFIDENCE_COLORS: Record<string, string> = {
  advisory_stated: '#22c55e',
  llm_extracted: '#3b82f6',
  llm_inferred: '#eab308',
};

function confidenceLabel(confidence: string): string {
  switch (confidence) {
    case 'advisory_stated': return 'Stated';
    case 'llm_extracted': return 'Extracted';
    case 'llm_inferred': return 'Inferred';
    default: return confidence;
  }
}

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const color = CONFIDENCE_COLORS[confidence] ?? 'var(--text-muted)';
  return (
    <span
      className={styles.inlineBadge}
      style={{
        background: `color-mix(in srgb, ${color} 15%, transparent)`,
        color,
        borderColor: `color-mix(in srgb, ${color} 30%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 30%, transparent)`,
      }}
    >
      {confidenceLabel(confidence)}
    </span>
  );
}

function FilterButtons<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className={styles.filterGroup}>
      <span className={styles.filterGroupLabel}>{label}</span>
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          className={clsx(styles.filterBtn, value === opt.value && styles.filterBtnActive)}
          onClick={() => onChange(opt.value)}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

function tacticSortKey(tactic: string | null): number {
  if (!tactic) return KILL_CHAIN_ORDER.length;
  const idx = KILL_CHAIN_ORDER.indexOf(tactic);
  return idx >= 0 ? idx : KILL_CHAIN_ORDER.length;
}

function formatTactic(tactic: string): string {
  return tactic
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

export function BehaviorsTab({ advisoryId, enabled }: BehaviorsTabProps) {
  const [confidenceFilter, setConfidenceFilter] = useState<ConfidenceFilter>('all');

  const {
    data: behaviors,
    isLoading,
    error,
  } = useQuery<Behavior[]>({
    queryKey: ['advisory-behaviors', advisoryId],
    queryFn: () => fetchAdvisoryBehaviors(advisoryId),
    enabled,
    staleTime: 5 * 60 * 1000,
  });

  const filtered = useMemo(
    () =>
      (behaviors ?? []).filter(
        (b) => confidenceFilter === 'all' || b.confidence === confidenceFilter,
      ),
    [behaviors, confidenceFilter],
  );

  const groupedByTactic = useMemo(() => {
    const groups: Record<string, Behavior[]> = {};
    for (const b of filtered) {
      const key = b.mitre_tactic ?? 'unknown';
      if (!groups[key]) groups[key] = [];
      groups[key].push(b);
    }

    return Object.entries(groups).sort(
      ([a], [b]) => tacticSortKey(a === 'unknown' ? null : a) - tacticSortKey(b === 'unknown' ? null : b),
    );
  }, [filtered]);

  if (isLoading) return <Skeleton lines={6} />;

  if (error) {
    return (
      <p style={{ color: 'var(--status-failed)', fontSize: 13 }}>
        Failed to load behaviors.
      </p>
    );
  }

  if (!behaviors || behaviors.length === 0) {
    return (
      <p style={{ color: 'var(--text-muted)', fontSize: 13, fontStyle: 'italic' }}>
        No behaviors extracted yet. Run the intel phase to extract behaviors from this advisory.
      </p>
    );
  }

  return (
    <div className={styles.analysisContainer}>
      <div className={styles.filterBar}>
        <FilterButtons
          label="Confidence"
          options={CONFIDENCE_OPTIONS}
          value={confidenceFilter}
          onChange={setConfidenceFilter}
        />
      </div>

      {groupedByTactic.map(([tactic, items]) => (
        <div key={tactic}>
          <h3 className={styles.sectionSubheader}>
            {tactic === 'unknown' ? 'Unknown Tactic' : formatTactic(tactic)}
            <span>{items.length} {items.length === 1 ? 'behavior' : 'behaviors'}</span>
          </h3>
          <div className={styles.cardList}>
            {items.map((b) => (
              <div key={b.id} className={styles.card}>
                <div className={styles.cardHeader}>
                  <div className={styles.cardBody}>{b.description}</div>
                  <div className={styles.cardBadges}>
                    <ConfidenceBadge confidence={b.confidence} />
                  </div>
                </div>
                <div className={styles.cardMeta}>
                  {b.mitre_technique && (
                    <span className={styles.techniqueBadge}>{b.mitre_technique}</span>
                  )}
                  {b.mitre_tactic && (
                    <span className={styles.tacticLabel}>{b.mitre_tactic}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {filtered.length === 0 && (
        <p className={styles.placeholderMessage}>
          No behaviors match the current filter.
        </p>
      )}
    </div>
  );
}
