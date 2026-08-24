/** Analysis-phase display -- tactical exercises and strategic posture recommendations. */

import { useState, useMemo, useCallback } from 'react';
import clsx from 'clsx';
import type {
  AnalysisResult,
  RedTeamActivity,
  BlueTeamActivity,
  SecurityPostureItem,
  ExecutionReference,
  SuccessCriteriaTiered,
  DefensiveFinding,
  LessonLearned,
} from '../../lib/types';
import styles from './advisory-tabs.module.css';

interface AnalysisTabProps {
  analysis: AnalysisResult | null;
  isPending?: boolean;
  error?: string | null;
}

type PriorityFilter = 'all' | 'critical' | 'high' | 'medium';
type MaturityFilter = 'all' | 'foundational' | 'intermediate' | 'advanced';
type DetectionFilter = 'all' | 'has_rules' | 'gaps_only';
type AnalysisSubTab = 'red' | 'blue' | 'purple' | 'findings' | 'posture';

const VERSION_CHANGES: Record<string, string> = {
  '1-2': 'The updated prompt produces tiered success criteria, structured execution references, evidence-based gap analysis, and detection rule cross-referencing.',
};

function snakeCaseToTitle(s: string): string {
  return s
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function formatRelativeTime(isoDate: string): string {
  const ms = Date.now() - new Date(isoDate).getTime();
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function techniqueHref(t: string): string {
  return `https://attack.mitre.org/techniques/${t.replace('.', '/')}/`;
}

function TechniqueBadges({ techniques, max = 2 }: { techniques: string[]; max?: number }) {
  const visible = techniques.slice(0, max);
  const overflow = techniques.length - visible.length;
  return (
    <>
      {visible.map((t) => (
        <a key={t} href={techniqueHref(t)} target="_blank" rel="noopener" className={styles.techniqueBadge}>
          {t}
        </a>
      ))}
      {overflow > 0 && <span className={styles.overflowIndicator}>+{overflow}</span>}
    </>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const cls = clsx(styles.inlineBadge, {
    [styles.priorityCritical]: priority === 'critical',
    [styles.priorityHigh]: priority === 'high',
    [styles.priorityMedium]: priority === 'medium',
  });
  return <span className={cls}>{priority}</span>;
}

function MaturityBadge({ level }: { level: string }) {
  const cls = clsx(styles.inlineBadge, {
    [styles.maturityFoundational]: level === 'foundational',
    [styles.maturityIntermediate]: level === 'intermediate',
    [styles.maturityAdvanced]: level === 'advanced',
  });
  return <span className={cls}>{level}</span>;
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

function TieredCriteria({ criteria }: { criteria: SuccessCriteriaTiered }) {
  return (
    <div className={styles.tieredCriteria}>
      <div className={styles.tieredBasic}><strong className={styles.tieredLabel}>Basic:</strong> <span className={styles.tieredText}>{criteria.basic}</span></div>
      <div className={styles.tieredIntermediate}><strong className={styles.tieredLabel}>Intermediate:</strong> <span className={styles.tieredText}>{criteria.intermediate}</span></div>
      <div className={styles.tieredAdvanced}><strong className={styles.tieredLabel}>Advanced:</strong> <span className={styles.tieredText}>{criteria.advanced}</span></div>
    </div>
  );
}

function RedTeamCard({ activity }: { activity: RedTeamActivity }) {
  const [expanded, setExpanded] = useState(false);

  const techniques = activity.mitre_techniques ?? (activity.mitre_technique ? [activity.mitre_technique] : []);

  const refs: ExecutionReference[] = activity.execution_references
    ?? (activity.tools ?? []).map((t) => ({ type: 'tool' as const, id: null, name: t }));

  const sortedRefs = [...refs].sort((a, b) => {
    const order: Record<string, number> = { atomic_red_team: 0, sigma_rule: 1, tool: 2 };
    return (order[a.type] ?? 2) - (order[b.type] ?? 2);
  });
  const visibleRefs = sortedRefs.length > 4 ? sortedRefs.slice(0, 4) : sortedRefs;
  const overflowCount = sortedRefs.length - visibleRefs.length;

  return (
    <div className={styles.card}>
      <div className={styles.cardHeader}>
        <h4 className={styles.cardTitle}>{activity.title}</h4>
        <div className={styles.cardBadges}>
          <PriorityBadge priority={activity.priority} />
        </div>
      </div>

      <div className={styles.cardMeta}>
        <TechniqueBadges techniques={techniques} />
        {activity.mitre_tactic && (
          <span className={styles.tacticLabel}>{activity.mitre_tactic}</span>
        )}
      </div>

      <div className={styles.cardBody}>{activity.objective}</div>

      {visibleRefs.length > 0 && (
        <div className={styles.toolsList}>
          {visibleRefs.map((ref) => {
            const cls = ref.type === 'atomic_red_team' ? styles.execRefArt
              : ref.type === 'sigma_rule' ? styles.execRefSigma
              : styles.toolPill;
            const label = ref.type === 'atomic_red_team' ? `ART | ${ref.name}`
              : ref.type === 'sigma_rule' ? `Sigma | ${ref.name}`
              : ref.name;
            return <span key={`${ref.type}-${ref.name}`} className={cls}>{label}</span>;
          })}
          {overflowCount > 0 && <span className={styles.overflowIndicator}>+{overflowCount}</span>}
        </div>
      )}

      {activity.description && (
        <>
          <button
            type="button"
            className={styles.expandBtn}
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? 'Collapse' : 'Show details'}
          </button>
          {expanded && <p className={styles.expandedDesc}>{activity.description}</p>}
        </>
      )}
    </div>
  );
}

function BlueTeamCard({ activity }: { activity: BlueTeamActivity }) {
  const gapText = activity.gap_quote ?? activity.gap_from_advisory ?? '';
  const techniques = activity.mitre_techniques ?? [];
  const detectionRefs = activity.detection_rule_refs ?? [];
  const visibleDetection = detectionRefs.slice(0, 3);
  const detectionOverflow = detectionRefs.length - visibleDetection.length;

  return (
    <div className={styles.card}>
      <div className={styles.cardHeader}>
        <h4 className={styles.cardTitle}>{activity.title}</h4>
        <div className={styles.cardBadges}>
          <PriorityBadge priority={activity.priority} />
        </div>
      </div>

      {gapText && (
        <div>
          <blockquote className={styles.gapQuote}>{gapText}</blockquote>
          {activity.gap_quote_verified === true && (
            <span className={styles.gapVerified} title="Quote verified against source">&#10003;</span>
          )}
          {activity.gap_quote_verified === false && (
            <span className={styles.gapVerified} title="Quote not verified">?</span>
          )}
        </div>
      )}

      {activity.gap_quote && activity.gap_interpretation && (
        <div className={styles.cardBody}>{activity.gap_interpretation}</div>
      )}

      <div className={styles.cardMeta}>
        <TechniqueBadges techniques={techniques} />
        <span>Validation: {activity.validation_method}</span>
      </div>

      {visibleDetection.length > 0 && (
        <div className={styles.toolsList}>
          {visibleDetection.map((ref) => (
            <span key={ref} className={styles.detectionRefPill}>{ref}</span>
          ))}
          {detectionOverflow > 0 && <span className={styles.overflowIndicator}>+{detectionOverflow}</span>}
        </div>
      )}
    </div>
  );
}

function LessonCard({ lesson }: { lesson: LessonLearned }) {
  return (
    <div className={styles.card}>
      <p className={styles.findingText}>{lesson.finding}</p>
      <p className={styles.impactText}>{lesson.impact}</p>
      <p className={styles.recommendText}>{lesson.recommendation}</p>
    </div>
  );
}

function DefensiveFindingCard({ finding }: { finding: DefensiveFinding }) {
  const cardCls = clsx(styles.card, {
    [styles.findingCardIncident]: finding.type === 'incident_lessons',
    [styles.findingCardCapability]: finding.type === 'capability_gaps',
  });

  return (
    <div className={cardCls}>
      <div className={styles.cardHeader}>
        <p className={styles.findingText}>{finding.finding}</p>
        <span className={finding.type === 'incident_lessons' ? styles.typeBadgeIncident : styles.typeBadgeCapability}>
          {finding.type === 'incident_lessons' ? 'Incident' : 'Capability Gap'}
        </span>
      </div>
      {finding.type === 'incident_lessons' && (
        <>
          {finding.impact && (
            <p className={styles.impactText}><span className={styles.fieldLabel}>Impact: </span>{finding.impact}</p>
          )}
          {finding.recommendation && (
            <p className={styles.recommendText}><span className={styles.fieldLabel}>Recommendation: </span>{finding.recommendation}</p>
          )}
        </>
      )}
      {finding.type === 'capability_gaps' && (
        <>
          {finding.defensive_control_bypassed && (
            <p className={styles.impactText}>
              <span className={styles.fieldLabel}>Control bypassed: </span>{finding.defensive_control_bypassed}
            </p>
          )}
          {finding.detection_opportunity && (
            <p className={styles.recommendText}>
              <span className={styles.fieldLabel}>Detection opportunity: </span>{finding.detection_opportunity}
            </p>
          )}
        </>
      )}
    </div>
  );
}

function PostureCard({ item }: { item: SecurityPostureItem }) {
  const gapText = item.gap_quote ?? item.gap_from_advisory ?? '';

  return (
    <div className={styles.card}>
      <div className={styles.cardHeader}>
        <h4 className={styles.cardTitle}>{item.title}</h4>
        <div className={styles.cardBadges}>
          <PriorityBadge priority={item.priority} />
          <MaturityBadge level={item.maturity_level} />
        </div>
      </div>

      {item.so_what && (
        <div className={styles.soWhatCallout}>
          <div className={styles.soWhatLabel}>Key insight</div>
          {item.so_what}
        </div>
      )}

      <div className={styles.cardBody}>{item.description}</div>

      {gapText && (
        <div>
          <blockquote className={styles.gapQuote}>{gapText}</blockquote>
          {item.gap_quote_verified === true && (
            <span className={styles.gapVerified} title="Quote verified against source">&#10003;</span>
          )}
          {item.gap_quote_verified === false && (
            <span className={styles.gapVerified} title="Quote not verified">?</span>
          )}
        </div>
      )}

      {item.gap_quote && item.gap_interpretation && (
        <div className={styles.cardBody}>{item.gap_interpretation}</div>
      )}

      {(item.framework_refs ?? []).length > 0 && (
        <div className={styles.citationLine}>
          {(item.framework_refs ?? []).join(' · ')}
        </div>
      )}
    </div>
  );
}

export function AnalysisTab({ analysis, isPending, error }: AnalysisTabProps) {
  const [activeSubTab, setActiveSubTab] = useState<AnalysisSubTab>('red');
  const [priorityFilter, setPriorityFilter] = useState<PriorityFilter>('all');
  const [maturityFilter, setMaturityFilter] = useState<MaturityFilter>('all');
  const [detectionFilter, setDetectionFilter] = useState<DetectionFilter>('all');
  const [killChainSort, setKillChainSort] = useState(false);
  const [staleExpanded, setStaleExpanded] = useState(false);
  const [metaExpanded, setMetaExpanded] = useState(false);

  const matchesPriority = useCallback(
    (priority: string) => priorityFilter === 'all' || priority === priorityFilter,
    [priorityFilter],
  );

  const matchesMaturity = useCallback(
    (level: string) => maturityFilter === 'all' || level === maturityFilter,
    [maturityFilter],
  );

  const filteredRed = useMemo(
    () => analysis?.analysis.tactical.red_team_activities.filter((a) => matchesPriority(a.priority)) ?? [],
    [analysis, matchesPriority],
  );

  const filteredBlue = useMemo(() => {
    const items = analysis?.analysis.tactical.blue_team_activities ?? [];
    return items.filter((a) => {
      if (!matchesPriority(a.priority)) return false;
      if (detectionFilter === 'all') return true;
      const refs = a.detection_rule_refs ?? [];
      if (detectionFilter === 'has_rules') return refs.length > 0;
      return refs.length === 0 && (a.mitre_techniques ?? []).length > 0;
    });
  }, [analysis, matchesPriority, detectionFilter]);

  const findings = useMemo(() => {
    const df = analysis?.analysis.tactical.defensive_findings;
    if (df && df.length > 0) return df;
    return analysis?.analysis.tactical.lessons_learned ?? [];
  }, [analysis]);

  const hasDefensiveFindings = useMemo(
    () => (analysis?.analysis.tactical.defensive_findings ?? []).length > 0,
    [analysis],
  );

  const allPurpleExercises = useMemo(
    () => analysis?.analysis.tactical.purple_team_exercises ?? [],
    [analysis],
  );

  const hasKillChain = useMemo(
    () => allPurpleExercises.some((ex) => ex.kill_chain_phase != null),
    [allPurpleExercises],
  );

  const purpleExercises = useMemo(() => {
    let items = [...allPurpleExercises];
    if (detectionFilter !== 'all') {
      items = items.filter((ex) => {
        const refs = ex.detection_rule_refs ?? [];
        if (detectionFilter === 'has_rules') return refs.length > 0;
        return refs.length === 0 && ex.mitre_techniques.length > 0;
      });
    }
    if (killChainSort && hasKillChain) {
      items.sort((a, b) => (a.kill_chain_phase ?? Infinity) - (b.kill_chain_phase ?? Infinity));
    }
    return items;
  }, [allPurpleExercises, killChainSort, hasKillChain, detectionFilter]);

  const filteredPosture = useMemo(
    () =>
      analysis?.analysis.strategic.security_posture.filter(
        (item) => matchesPriority(item.priority) && matchesMaturity(item.maturity_level),
      ) ?? [],
    [analysis, matchesPriority, matchesMaturity],
  );

  const postureByCategory = useMemo(() => {
    const groups: Record<string, typeof filteredPosture> = {};
    for (const item of filteredPosture) {
      const cat = item.category;
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(item);
    }
    return groups;
  }, [filteredPosture]);

  const hasAnyDetectionRefs = useMemo(() => {
    const blue = analysis?.analysis.tactical.blue_team_activities ?? [];
    const purple = analysis?.analysis.tactical.purple_team_exercises ?? [];
    return blue.some((b) => (b.detection_rule_refs ?? []).length > 0)
      || purple.some((p) => (p.detection_rule_refs ?? []).length > 0);
  }, [analysis]);

  const coverageStats = useMemo(() => {
    if (!hasAnyDetectionRefs || !analysis) return null;
    const red = analysis.analysis.tactical.red_team_activities;
    const blue = analysis.analysis.tactical.blue_team_activities;
    const purple = analysis.analysis.tactical.purple_team_exercises;
    const allTechniques = new Set<string>();
    const coveredTechniques = new Set<string>();

    for (const r of red) {
      for (const t of r.mitre_techniques ?? (r.mitre_technique ? [r.mitre_technique] : [])) {
        allTechniques.add(t);
      }
    }
    for (const b of blue) {
      for (const t of b.mitre_techniques ?? []) {
        allTechniques.add(t);
        if ((b.detection_rule_refs ?? []).length > 0) coveredTechniques.add(t);
      }
    }
    for (const p of purple) {
      for (const t of p.mitre_techniques) {
        allTechniques.add(t);
        if ((p.detection_rule_refs ?? []).length > 0) coveredTechniques.add(t);
      }
    }
    if (allTechniques.size === 0) return null;
    return {
      total: allTechniques.size,
      covered: coveredTechniques.size,
      gaps: allTechniques.size - coveredTechniques.size,
    };
  }, [analysis, hasAnyDetectionRefs]);

  const versionChangeKey = useMemo(() => {
    if (!analysis?.stale_reason) return null;
    const m = analysis.stale_reason.match(/prompt v(\d+).*?v(\d+)/);
    if (m) return `${m[1]}-${m[2]}`;
    return null;
  }, [analysis?.stale_reason]);

  if (!analysis) {
    if (isPending) {
      return (
        <div className={styles.card} style={{ textAlign: 'center', padding: '40px 20px' }}>
          <div className={styles.spinnerLarge} />
          <p style={{ fontSize: '15px', color: 'var(--text-secondary)', margin: '16px 0 0' }}>
            Generating analysis with DeepSeek&hellip; This typically takes 15&ndash;30 seconds.
          </p>
        </div>
      );
    }
    if (error) {
      return (
        <div className={styles.card} style={{ textAlign: 'center', padding: '40px 20px' }}>
          <p style={{ fontSize: '15px', color: '#ef4444', margin: 0 }}>
            Analysis failed: {error}
          </p>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '8px 0 0' }}>
            Click <strong>Analyze</strong> to retry.
          </p>
        </div>
      );
    }
    return (
      <div className={styles.card} style={{ textAlign: 'center', padding: '40px 20px' }}>
        <p style={{ fontSize: '15px', color: 'var(--text-secondary)', margin: 0 }}>
          Click the <strong>Analyze</strong> button to generate tactical exercises
          and strategic security posture recommendations from this advisory.
        </p>
      </div>
    );
  }

  const priorityOptions: { value: PriorityFilter; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
  ];

  const maturityOptions: { value: MaturityFilter; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'foundational', label: 'Foundational' },
    { value: 'intermediate', label: 'Intermediate' },
    { value: 'advanced', label: 'Advanced' },
  ];

  const detectionOptions: { value: DetectionFilter; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'has_rules', label: 'Has Rules' },
    { value: 'gaps_only', label: 'Gaps Only' },
  ];

  return (
    <div className={styles.analysisContainer}>
      {/* Stale analysis banner (D.2) */}
      {analysis.stale && (
        <div className={styles.staleBanner}>
          <div className={styles.staleBannerText}>
            This analysis was generated with an older prompt version. Click &quot;Re-analyze&quot; to regenerate.
          </div>
          {analysis.stale_reason && (
            <div className={styles.staleBannerReason}>{analysis.stale_reason}</div>
          )}
          {versionChangeKey && VERSION_CHANGES[versionChangeKey] && (
            <>
              <button
                type="button"
                className={styles.staleChangesToggle}
                onClick={() => setStaleExpanded(!staleExpanded)}
              >
                {staleExpanded ? 'Hide changes' : 'What changed?'}
              </button>
              {staleExpanded && (
                <div className={styles.staleChangesContent}>
                  {VERSION_CHANGES[versionChangeKey]}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Analysis metadata (10.17) */}
      <div className={styles.analysisMetaLine}>
        <span>
          Generated {formatRelativeTime(analysis.created_at)}
          {analysis.model ? ` with ${analysis.model}` : ''}
        </span>
        <button
          type="button"
          className={styles.analysisMetaToggle}
          onClick={() => setMetaExpanded(!metaExpanded)}
        >
          {metaExpanded ? 'Hide' : 'Details'}
        </button>
      </div>
      {metaExpanded && (
        <div className={styles.analysisMetaExpanded}>
          <span className={styles.analysisMetaKey}>Created</span>
          <span className={styles.analysisMetaValue}>{analysis.created_at}</span>
          {analysis.model && (
            <>
              <span className={styles.analysisMetaKey}>Model</span>
              <span className={styles.analysisMetaValue}>{analysis.model}</span>
            </>
          )}
          {analysis.prompt_version != null && (
            <>
              <span className={styles.analysisMetaKey}>Prompt Version</span>
              <span className={styles.analysisMetaValue}>{analysis.prompt_version}</span>
            </>
          )}
          {analysis.input_tokens != null && (
            <>
              <span className={styles.analysisMetaKey}>Input Tokens</span>
              <span className={styles.analysisMetaValue}>{analysis.input_tokens.toLocaleString()}</span>
            </>
          )}
          {analysis.output_tokens != null && (
            <>
              <span className={styles.analysisMetaKey}>Output Tokens</span>
              <span className={styles.analysisMetaValue}>{analysis.output_tokens.toLocaleString()}</span>
            </>
          )}
          {analysis.latency_ms != null && (
            <>
              <span className={styles.analysisMetaKey}>Latency</span>
              <span className={styles.analysisMetaValue}>{(analysis.latency_ms / 1000).toFixed(1)}s</span>
            </>
          )}
          {analysis.cost_usd != null && (
            <>
              <span className={styles.analysisMetaKey}>Cost</span>
              <span className={styles.analysisMetaValue}>${analysis.cost_usd.toFixed(4)}</span>
            </>
          )}
          {analysis.cached && (
            <>
              <span className={styles.analysisMetaKey}>Cached</span>
              <span className={styles.analysisMetaValue}>Yes</span>
            </>
          )}
        </div>
      )}

      {/* Sub-tab navigation */}
      <nav className={styles.analysisSubTabs} role="tablist">
        <button
          type="button"
          role="tab"
          className={clsx(styles.analysisSubTab, activeSubTab === 'red' && styles.analysisSubTabActive)}
          onClick={() => setActiveSubTab('red')}
        >
          Red Team<span className={styles.analysisSubTabBadge}>{filteredRed.length}</span>
        </button>
        <button
          type="button"
          role="tab"
          className={clsx(styles.analysisSubTab, activeSubTab === 'blue' && styles.analysisSubTabActive)}
          onClick={() => setActiveSubTab('blue')}
        >
          Blue Team<span className={styles.analysisSubTabBadge}>{filteredBlue.length}</span>
        </button>
        <button
          type="button"
          role="tab"
          className={clsx(styles.analysisSubTab, activeSubTab === 'purple' && styles.analysisSubTabActive)}
          onClick={() => setActiveSubTab('purple')}
        >
          Purple Team<span className={styles.analysisSubTabBadge}>{purpleExercises.length}</span>
        </button>
        <button
          type="button"
          role="tab"
          className={clsx(styles.analysisSubTab, activeSubTab === 'findings' && styles.analysisSubTabActive)}
          onClick={() => setActiveSubTab('findings')}
        >
          {hasDefensiveFindings ? 'Findings' : 'Lessons'}<span className={styles.analysisSubTabBadge}>{findings.length}</span>
        </button>
        <button
          type="button"
          role="tab"
          className={clsx(styles.analysisSubTab, activeSubTab === 'posture' && styles.analysisSubTabActive)}
          onClick={() => setActiveSubTab('posture')}
        >
          Security Posture<span className={styles.analysisSubTabBadge}>{filteredPosture.length}</span>
        </button>
      </nav>

      {/* Filters — scoped to active sub-tab */}
      <div className={styles.filterBar}>
        {(activeSubTab === 'red' || activeSubTab === 'blue' || activeSubTab === 'posture') && (
          <FilterButtons
            label="Priority"
            options={priorityOptions}
            value={priorityFilter}
            onChange={setPriorityFilter}
          />
        )}
        {activeSubTab === 'posture' && (
          <FilterButtons
            label="Maturity"
            options={maturityOptions}
            value={maturityFilter}
            onChange={setMaturityFilter}
          />
        )}
        {(activeSubTab === 'blue' || activeSubTab === 'purple') && hasAnyDetectionRefs && (
          <FilterButtons
            label="Detection"
            options={detectionOptions}
            value={detectionFilter}
            onChange={setDetectionFilter}
          />
        )}
      </div>

      {/* Technique coverage summary */}
      {coverageStats && (activeSubTab === 'blue' || activeSubTab === 'purple') && (
        <div className={styles.coverageSummary}>
          <span className={styles.coverageGood}>{coverageStats.covered}</span>/{coverageStats.total} techniques covered by detection rules
          {coverageStats.gaps > 0 && (
            <> &mdash; <span className={styles.coverageGap}>{coverageStats.gaps} gaps</span></>
          )}
        </div>
      )}

      {/* Red Team Activities */}
      {activeSubTab === 'red' && (
        <div role="tabpanel">
          {filteredRed.length > 0 ? (
            <div className={styles.cardList}>
              {filteredRed.map((activity, i) => (
                <RedTeamCard key={`${activity.title}-${i}`} activity={activity} />
              ))}
            </div>
          ) : (
            <p className={styles.placeholderMessage}>No red team activities match the current filters.</p>
          )}
        </div>
      )}

      {/* Blue Team Activities */}
      {activeSubTab === 'blue' && (
        <div role="tabpanel">
          {filteredBlue.length > 0 ? (
            <div className={styles.cardList}>
              {filteredBlue.map((activity, i) => (
                <BlueTeamCard key={`${activity.title}-${i}`} activity={activity} />
              ))}
            </div>
          ) : (
            <p className={styles.placeholderMessage}>No blue team activities match the current filters.</p>
          )}
        </div>
      )}

      {/* Purple Team Exercises */}
      {activeSubTab === 'purple' && (
        <div role="tabpanel">
          {hasKillChain && (
            <button
              type="button"
              className={styles.killChainToggle}
              onClick={() => setKillChainSort(!killChainSort)}
            >
              {killChainSort ? 'Sort by order' : 'Sort by kill chain'}
            </button>
          )}
          {purpleExercises.length > 0 ? (
            <div className={styles.exerciseTableWrap}>
              <table className={styles.exerciseTable}>
                <thead>
                  <tr>
                    {hasKillChain && <th style={{ width: '32px' }} />}
                    <th>Exercise</th>
                    <th>Red Action</th>
                    <th>Blue Measures</th>
                    <th>MITRE Techniques</th>
                    <th>Success Criteria</th>
                  </tr>
                </thead>
                <tbody>
                  {purpleExercises.map((ex, i) => (
                    <tr key={`${ex.title}-${i}`}>
                      {hasKillChain && (
                        <td className={styles.phaseCell}>
                          {ex.kill_chain_phase != null && (
                            <span className={styles.phaseCircle}>{ex.kill_chain_phase}</span>
                          )}
                        </td>
                      )}
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{ex.title}</td>
                      <td>{ex.red_action}</td>
                      <td>
                        {ex.blue_measures.join(', ')}
                        {(ex.detection_rule_refs ?? []).length > 0 && (
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
                            {ex.detection_rule_refs!.map((ref) => (
                              <span key={ref} className={styles.detectionRefPill}>{ref}</span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          <TechniqueBadges techniques={ex.mitre_techniques} />
                        </div>
                      </td>
                      <td>
                        {typeof ex.success_criteria === 'string'
                          ? ex.success_criteria
                          : <TieredCriteria criteria={ex.success_criteria} />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className={styles.placeholderMessage}>No purple team exercises available.</p>
          )}
        </div>
      )}

      {/* Defensive Findings / Lessons Learned */}
      {activeSubTab === 'findings' && (
        <div role="tabpanel">
          {findings.length > 0 ? (
            <div className={styles.cardList}>
              {hasDefensiveFindings
                ? (findings as DefensiveFinding[]).map((finding, i) => (
                    <DefensiveFindingCard key={`${finding.finding}-${i}`} finding={finding} />
                  ))
                : (findings as LessonLearned[]).map((lesson, i) => (
                    <LessonCard key={`${lesson.finding}-${i}`} lesson={lesson} />
                  ))}
            </div>
          ) : (
            <p className={styles.placeholderMessage}>No findings available.</p>
          )}
        </div>
      )}

      {/* Security Posture Recommendations */}
      {activeSubTab === 'posture' && (
        <div role="tabpanel">
          {Object.keys(postureByCategory).length > 0 ? (
            Object.entries(postureByCategory).map(([category, items]) => (
              <div key={category} className={styles.categoryGroup}>
                <h4 className={styles.categoryHeader}>{snakeCaseToTitle(category)}</h4>
                <div className={clsx(styles.cardList, styles.cardListSingleCol)}>
                  {items.map((item) => (
                    <PostureCard key={`${item.category}-${item.title}`} item={item} />
                  ))}
                </div>
              </div>
            ))
          ) : (
            <p className={styles.placeholderMessage}>
              No security posture recommendations match the current filters.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
