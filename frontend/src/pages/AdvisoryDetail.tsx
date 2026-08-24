/** Advisory detail page -- analyst workspace with tabbed content and sidebar. */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  fetchAdvisory,
  fetchAnalysis,
  triggerAnalysis,
  updateTriage,
  fetchAdvisoryTechniques,
  fetchAdvisoryCves,
  fetchAdvisoryAssets,
  fetchExtractionLogs,
  exportNavigatorLayer,
  triggerDownload,
} from '../lib/api';
import type {
  AdvisoryDetail as AdvisoryDetailType,
  AnalysisResult,
  TriageStatus,
  AttackTechnique,
} from '../lib/types';
import { Badge } from '../components/Badge';
import { useToast } from '../components/Toast';
import { Skeleton } from '../components/Skeleton';
import { OverviewTab } from '../components/advisory/OverviewTab';
import { AnalysisTab } from '../components/advisory/AnalysisTab';
import { RawTab } from '../components/advisory/RawTab';
import { IocTab } from '../components/advisory/IocTab';
import { BehaviorsTab } from '../components/advisory/BehaviorsTab';
import { DetectionRulesTab } from '../components/advisory/DetectionRulesTab';
import styles from './AdvisoryDetail.module.css';

// ---------------------------------------------------------------------------
// Types & constants
// ---------------------------------------------------------------------------

type TabId = 'overview' | 'behaviors' | 'iocs' | 'rules' | 'analysis' | 'raw';

/** Fixed shortcut-key to tab mapping (1-5). */
const SHORTCUT_MAP: Record<string, TabId> = {
  '1': 'overview',
  '2': 'behaviors',
  '3': 'iocs',
  '4': 'rules',
  '5': 'analysis',
  '6': 'raw',
};

const TRIAGE_OPTIONS: { value: TriageStatus; label: string; dotClass: string }[] = [
  { value: 'unread', label: 'Unread', dotClass: styles.triageDotUnread },
  { value: 'reviewed', label: 'Reviewed', dotClass: styles.triageDotReviewed },
  { value: 'flagged', label: 'Flagged', dotClass: styles.triageDotFlagged },
];

/** MITRE ATT&CK Enterprise kill-chain order (slug form). */
const KILL_CHAIN_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

const TACTIC_DISPLAY: Record<string, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

function normalizeTactic(tactic: string | null): string {
  if (!tactic) return 'unknown';
  return tactic.toLowerCase().replace(/\s+/g, '-');
}

function getTriageDotClass(status: TriageStatus): string {
  switch (status) {
    case 'unread': return styles.triageDotUnread;
    case 'reviewed': return styles.triageDotReviewed;
    case 'flagged': return styles.triageDotFlagged;
  }
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/**
 * Map a technique confidence value to a styled badge (M8). Handles the backend
 * ATT&CK confidence vocabulary (advisory_stated / llm_extracted / llm_inferred)
 * plus the legacy high/medium/low scale.
 */
function confidenceMeta(confidence: string): { cls: string; label: string } {
  switch (confidence) {
    case 'advisory_stated':
      return { cls: styles.confidenceStated, label: 'Stated' };
    case 'llm_extracted':
      return { cls: styles.confidenceMedium, label: 'Extracted' };
    case 'llm_inferred':
      return { cls: styles.confidenceInferred, label: 'Inferred' };
    case 'high':
      return { cls: styles.confidenceHigh, label: 'High' };
    case 'medium':
      return { cls: styles.confidenceMedium, label: 'Medium' };
    case 'low':
      return { cls: styles.confidenceLow, label: 'Low' };
    default:
      return { cls: styles.confidenceLow, label: confidence || 'unknown' };
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AdvisoryDetail() {
  const { id: idParam } = useParams<{ id: string }>();
  const advisoryId = idParam ? Number(idParam) : undefined;
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const { addToast } = useToast();

  // -- Local UI state --

  const [triageOpen, setTriageOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [alertDismissed, setAlertDismissed] = useState(false);
  const [alertExpanded, setAlertExpanded] = useState(false);
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());
  // Technique id awaiting scroll once the Overview article is mounted (M4).
  const [pendingTechnique, setPendingTechnique] = useState<string | null>(null);
  const triageRef = useRef<HTMLDivElement>(null);
  const visibleTabIdsRef = useRef<Set<TabId>>(new Set(['overview', 'analysis', 'raw']));

  // -- Data fetching --

  const {
    data: advisory,
    isLoading: advisoryLoading,
    error: advisoryError,
  } = useQuery<AdvisoryDetailType>({
    queryKey: ['advisory', advisoryId],
    queryFn: () => fetchAdvisory(advisoryId!),
    enabled: !!advisoryId,
    staleTime: 5 * 60 * 1000,
  });

  const {
    data: analysis,
    isLoading: analysisLoading,
  } = useQuery<AnalysisResult | null>({
    queryKey: ['analysis', advisoryId],
    queryFn: async () => {
      try {
        return await fetchAnalysis(advisoryId!);
      } catch (err: unknown) {
        if (err instanceof Error && 'status' in err && (err as { status: number }).status === 404) {
          return null;
        }
        throw err;
      }
    },
    enabled: !!advisoryId,
    staleTime: 5 * 60 * 1000,
  });

  // Sidebar: ATT&CK techniques
  const showAttackCard = (advisory?.technique_count ?? 0) > 0 || (advisory?.d3fend_count ?? 0) > 0;

  const { data: techniques, isError: techniquesError } = useQuery<AttackTechnique[]>({
    queryKey: ['advisory-techniques', advisoryId],
    queryFn: () => fetchAdvisoryTechniques(advisoryId!),
    enabled: showAttackCard && !!advisoryId,
    staleTime: 5 * 60 * 1000,
  });

  // Sidebar: linked CVEs
  const showCveCard = (advisory?.cve_count ?? 0) > 0;

  const { data: sidebarCves, isError: sidebarCvesError } = useQuery({
    queryKey: ['advisory-cves', advisoryId],
    queryFn: () => fetchAdvisoryCves(advisoryId!),
    enabled: showCveCard && !!advisoryId,
    staleTime: 5 * 60 * 1000,
  });

  // Sidebar: assets
  const showAssetCard = (advisory?.asset_count ?? 0) > 0;

  const { data: assets, isError: assetsError } = useQuery({
    queryKey: ['advisory-assets', advisoryId],
    queryFn: () => fetchAdvisoryAssets(advisoryId!),
    enabled: showAssetCard && !!advisoryId,
    staleTime: 5 * 60 * 1000,
  });

  // Alert banner: extraction logs
  const { data: extractionLogs, isError: extractionLogsError } = useQuery({
    queryKey: ['extraction-logs', advisoryId],
    queryFn: () => fetchExtractionLogs(advisoryId!),
    enabled: alertExpanded && !!advisoryId,
    staleTime: 5 * 60 * 1000,
  });

  // -- Computed: visible tabs --

  const visibleTabs = useMemo((): { id: TabId; label: string; shortcut: string }[] => {
    const tabs: { id: TabId; label: string; shortcut: string }[] = [
      { id: 'overview', label: 'Overview', shortcut: '1' },
    ];
    if (advisory && (advisory.behavior_count ?? 0) > 0) {
      tabs.push({ id: 'behaviors', label: `Behaviors (${advisory.behavior_count})`, shortcut: '2' });
    }
    if (advisory && advisory.ioc_count > 0) {
      tabs.push({ id: 'iocs', label: `IOCs (${advisory.ioc_count})`, shortcut: '3' });
    }
    if (advisory && advisory.detection_rule_count > 0) {
      tabs.push({ id: 'rules', label: `Detection (${advisory.detection_rule_count})`, shortcut: '4' });
    }
    tabs.push({ id: 'analysis', label: 'Analysis', shortcut: '5' });
    tabs.push({ id: 'raw', label: 'Source HTML', shortcut: '6' });
    return tabs;
  }, [advisory]);

  // Derived set of visible tab ids (used during render so deep-links resolve
  // on first paint — H9). A ref mirror is kept only for the keydown handler.
  const visibleTabIds = useMemo(
    () => new Set<TabId>(visibleTabs.map((t) => t.id)),
    [visibleTabs],
  );

  useEffect(() => {
    visibleTabIdsRef.current = visibleTabIds;
  }, [visibleTabIds]);

  // -- Computed: active tab (validated against visible tabs) --

  const tabParam = searchParams.get('tab');
  const activeTab: TabId = (() => {
    if (
      tabParam === 'overview' ||
      tabParam === 'behaviors' ||
      tabParam === 'iocs' ||
      tabParam === 'rules' ||
      tabParam === 'analysis' ||
      tabParam === 'raw'
    ) {
      return visibleTabIds.has(tabParam) ? tabParam : 'overview';
    }
    return 'overview';
  })();

  // -- Computed: ATT&CK technique grouping --

  const attackTechniques = useMemo(
    () => techniques?.filter((t) => t.framework === 'attack') ?? [],
    [techniques],
  );

  const d3fendTechniques = useMemo(
    () => techniques?.filter((t) => t.framework === 'd3fend') ?? [],
    [techniques],
  );

  const tacticGroups = useMemo(() => {
    const groups = new Map<string, AttackTechnique[]>();
    for (const t of attackTechniques) {
      const tactic = normalizeTactic(t.tactic);
      if (!groups.has(tactic)) groups.set(tactic, []);
      groups.get(tactic)!.push(t);
    }
    return [...groups.entries()].sort((a, b) => {
      const ai = KILL_CHAIN_ORDER.indexOf(a[0]);
      const bi = KILL_CHAIN_ORDER.indexOf(b[0]);
      return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
    });
  }, [attackTechniques]);

  const uniqueTacticCount = tacticGroups.length;

  // -- Mutations --

  const analyzeMutation = useMutation({
    mutationFn: (force?: boolean) => triggerAnalysis(advisoryId!, force ?? false),
    onSuccess: (data) => {
      queryClient.setQueryData(['analysis', advisoryId], data);
      setSearchParams({ tab: 'analysis' });
      addToast('Analysis complete', 'success');
    },
    onError: (err: Error) => {
      addToast(`Analysis failed: ${err.message}`, 'error');
    },
  });

  const triageMutation = useMutation({
    mutationFn: (status: TriageStatus) => updateTriage(advisoryId!, status),
    onSuccess: (_data, status) => {
      queryClient.setQueryData<AdvisoryDetailType>(
        ['advisory', advisoryId],
        (old) => old ? { ...old, triage_status: status } : old,
      );
      queryClient.invalidateQueries({ queryKey: ['advisories'] });
      addToast(`Triage set to ${status}`, 'success');
    },
    onError: (err: Error) => {
      addToast(`Failed to update triage: ${err.message}`, 'error');
    },
  });

  // -- Tab switching --

  const setTab = useCallback(
    (tab: TabId) => {
      setSearchParams({ tab });
    },
    [setSearchParams],
  );

  // -- Technique scroll (M4) --

  const scrollToTechnique = useCallback((techniqueId: string): boolean => {
    const el = document.querySelector(
      `.t2s-mitre[data-technique-id="${CSS.escape(techniqueId)}"]`,
    );
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      (el as HTMLElement).focus();
      return true;
    }
    return false;
  }, []);

  const handleTechniqueClick = useCallback(
    (techniqueId: string) => {
      // Off Overview the annotation isn't mounted yet: switch tabs, then scroll
      // in the effect below once the article renders (M4).
      if (activeTab !== 'overview') {
        setPendingTechnique(techniqueId);
        setTab('overview');
        return;
      }
      if (!scrollToTechnique(techniqueId)) {
        window.open(
          `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`,
          '_blank',
          'noopener,noreferrer',
        );
      }
    },
    [activeTab, setTab, scrollToTechnique],
  );

  // Resolve a pending scroll after the Overview article has mounted.
  useEffect(() => {
    if (activeTab !== 'overview' || !pendingTechnique) return;
    const id = pendingTechnique;
    const raf = requestAnimationFrame(() => {
      scrollToTechnique(id);
      setPendingTechnique(null);
    });
    return () => cancelAnimationFrame(raf);
  }, [activeTab, pendingTechnique, scrollToTechnique]);

  // -- Analyze button handler --

  const handleAnalyze = useCallback(() => {
    if (analysis) {
      setConfirmOpen(true);
    } else {
      analyzeMutation.mutate(false);
    }
  }, [analysis, analyzeMutation]);

  const confirmReanalyze = useCallback(() => {
    setConfirmOpen(false);
    analyzeMutation.mutate(true);
  }, [analyzeMutation]);

  // -- Navigator export --

  const handleExportNavigator = useCallback(async () => {
    if (!advisoryId) return;
    try {
      const blob = await exportNavigatorLayer(advisoryId);
      triggerDownload(blob, `${advisory?.advisory_id ?? advisoryId}_navigator.json`);
      addToast('Navigator layer exported', 'success');
    } catch {
      addToast('Failed to export Navigator layer', 'error');
    }
  }, [advisoryId, advisory?.advisory_id, addToast]);

  // -- Tactic toggle --

  const toggleTactic = useCallback((tactic: string) => {
    setExpandedTactics((prev) => {
      const next = new Set(prev);
      if (next.has(tactic)) next.delete(tactic);
      else next.add(tactic);
      return next;
    });
  }, []);

  // -- Keyboard shortcuts: 1-5 for tabs --

  useEffect(() => {
    function handleKeydown(e: KeyboardEvent) {
      // Don't hijack browser/OS chords (Ctrl/Cmd/Alt + digit) (L8).
      if (e.ctrlKey || e.metaKey || e.altKey) return;

      const target = e.target as HTMLElement;
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.tagName === 'SELECT' ||
        target.isContentEditable
      ) {
        return;
      }

      const targetTab = SHORTCUT_MAP[e.key];
      if (targetTab && visibleTabIdsRef.current.has(targetTab)) {
        setTab(targetTab);
      }
    }

    window.addEventListener('keydown', handleKeydown);
    return () => window.removeEventListener('keydown', handleKeydown);
  }, [setTab]);

  // -- Close triage dropdown on outside click --

  useEffect(() => {
    if (!triageOpen) return;

    function handleClick(e: MouseEvent) {
      if (triageRef.current && !triageRef.current.contains(e.target as Node)) {
        setTriageOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [triageOpen]);

  // -- Render states --

  if (advisoryLoading || analysisLoading) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>Loading advisory...</div>
      </div>
    );
  }

  if (advisoryError || !advisory) {
    const is404 =
      advisoryError instanceof Error &&
      'status' in advisoryError &&
      (advisoryError as { status: number }).status === 404;

    return (
      <div className={styles.container}>
        <div className={styles.errorState}>
          <h2 className={styles.errorTitle}>
            {is404 ? 'Advisory not found' : 'Error loading advisory'}
          </h2>
          <p className={styles.errorMessage}>
            {is404
              ? `No advisory found with ID ${advisoryId}.`
              : `Something went wrong: ${advisoryError?.message ?? 'Unknown error'}`}
          </p>
          <Link to="/" className={styles.backLink}>
            Back to Feed
          </Link>
        </div>
      </div>
    );
  }

  // -- Post-guard derived values --

  const triageStatus: TriageStatus =
    advisory.triage_status === 'unread' || advisory.triage_status === 'reviewed' || advisory.triage_status === 'flagged'
      ? advisory.triage_status
      : 'unread';
  const showAlert =
    !alertDismissed &&
    (advisory.extraction_status === 'parse_partial' ||
      advisory.extraction_status === 'parse_failed');
  const alertIsError = advisory.extraction_status === 'parse_failed';

  return (
    <div className={styles.container}>
      {/* -------- Header -------- */}
      <header className={styles.header}>
        <div className={styles.headerTop}>
          <div className={styles.titleBlock}>
            <h1 className={styles.title}>{advisory.title}</h1>

            <div className={styles.headerMeta}>
              <Badge variant="source" value={advisory.source} />
              {advisory.original_source && (
                <>
                  <span className={styles.metaDot}>&rarr;</span>
                  <span className={styles.originalSource}>{advisory.original_source}</span>
                </>
              )}
              <span className={styles.advisoryId}>{advisory.advisory_id}</span>
              {advisory.type && (
                <>
                  <span className={styles.metaDot}>&middot;</span>
                  <Badge variant="type" value={advisory.type} />
                </>
              )}
              <span className={styles.metaDot}>&middot;</span>
              <span>{advisory.pub_date}</span>
              {advisory.link && (
                <>
                  <span className={styles.metaDot}>&middot;</span>
                  <a
                    href={advisory.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={styles.externalLink}
                  >
                    View original &#8599;
                  </a>
                </>
              )}
              <span className={styles.metaDot}>&middot;</span>
              <Badge variant="status" value={advisory.extraction_status} />
            </div>
          </div>

          <div className={styles.headerActions}>
            {/* Triage dropdown */}
            <div className={styles.triageDropdown} ref={triageRef}>
              <button
                type="button"
                className={styles.triageBtn}
                onClick={() => setTriageOpen(!triageOpen)}
                aria-haspopup="listbox"
                aria-expanded={triageOpen}
              >
                <span className={clsx(styles.triageDot, getTriageDotClass(triageStatus))} />
                {triageStatus.charAt(0).toUpperCase() + triageStatus.slice(1)}
                <span style={{ fontSize: '10px', opacity: 0.6 }}>&#9662;</span>
              </button>

              {triageOpen && (
                <div className={styles.triageMenu} role="listbox">
                  {TRIAGE_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      role="option"
                      aria-selected={triageStatus === opt.value}
                      className={clsx(
                        styles.triageOption,
                        triageStatus === opt.value && styles.triageOptionActive,
                      )}
                      onClick={() => {
                        triageMutation.mutate(opt.value);
                        setTriageOpen(false);
                      }}
                    >
                      <span className={clsx(styles.triageDot, opt.dotClass)} />
                      {opt.label}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Analyze button */}
            <button
              type="button"
              className={styles.analyzeBtn}
              onClick={handleAnalyze}
              disabled={analyzeMutation.isPending}
            >
              {analyzeMutation.isPending && <span className={styles.spinner} />}
              {analyzeMutation.isPending
                ? 'Analyzing...'
                : analysis
                  ? 'Re-analyze'
                  : 'Analyze'}
            </button>
          </div>
        </div>
      </header>

      {/* -------- Confirm Dialog -------- */}
      {confirmOpen && (
        <div className={styles.dialogOverlay} onClick={() => setConfirmOpen(false)}>
          <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
            <h3 className={styles.dialogTitle}>Re-analyze advisory?</h3>
            <p className={styles.dialogText}>
              {analysis?.stale
                ? `This analysis is stale: ${analysis.stale_reason}. Re-analyze costs ~$0.02 and takes 5-15 seconds. Continue?`
                : 'Re-analyze costs ~$0.02 and takes 5-15 seconds. This will replace the existing analysis. Continue?'}
            </p>
            <div className={styles.dialogActions}>
              <button
                type="button"
                className={styles.dialogCancel}
                onClick={() => setConfirmOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className={styles.dialogConfirm}
                onClick={confirmReanalyze}
              >
                Continue
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -------- Extraction Alert Banner (F.14) -------- */}
      {showAlert && (
        <div
          className={clsx(
            styles.alertBanner,
            alertIsError ? styles.alertBannerRed : styles.alertBannerAmber,
          )}
        >
          <div className={styles.alertBannerTop}>
            <span className={styles.alertBannerSummary}>
              {alertIsError ? 'Extraction failed' : 'Extraction completed with issues'}
              {advisory.extraction_issues && (
                <>
                  {' -- '}
                  {advisory.extraction_issues.error_count > 0 &&
                    `${advisory.extraction_issues.error_count} error${advisory.extraction_issues.error_count !== 1 ? 's' : ''}`}
                  {advisory.extraction_issues.error_count > 0 && advisory.extraction_issues.warning_count > 0 && ', '}
                  {advisory.extraction_issues.warning_count > 0 &&
                    `${advisory.extraction_issues.warning_count} warning${advisory.extraction_issues.warning_count !== 1 ? 's' : ''}`}
                </>
              )}
            </span>
            <div className={styles.alertBannerActions}>
              <button
                type="button"
                className={styles.alertBannerExpand}
                onClick={() => setAlertExpanded(!alertExpanded)}
              >
                {alertExpanded ? 'Hide details' : 'Show details'}
              </button>
              <button
                type="button"
                className={styles.alertBannerDismiss}
                onClick={() => setAlertDismissed(true)}
                aria-label="Dismiss alert"
              >
                &times;
              </button>
            </div>
          </div>

          {alertExpanded && (
            <div className={styles.alertBannerDetails}>
              {extractionLogsError && (
                <span style={{ fontSize: 12, color: 'var(--status-failed)' }}>
                  Failed to load extraction log.
                </span>
              )}
              {!extractionLogs && !extractionLogsError && <Skeleton lines={3} />}
              {extractionLogs && extractionLogs.length === 0 && (
                <span style={{ fontSize: 12, opacity: 0.7 }}>No detailed log entries.</span>
              )}
              {extractionLogs && extractionLogs.map((log) => (
                <div key={log.id} className={styles.alertLogEntry}>
                  <span
                    className={clsx(
                      styles.alertLogSeverity,
                      log.severity === 'warning'
                        ? styles.alertLogSeverityWarning
                        : styles.alertLogSeverityError,
                    )}
                  >
                    {log.severity}
                  </span>
                  <span className={styles.alertLogMessage}>
                    {log.message}
                    {log.context && (
                      <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>
                        ({log.context})
                      </span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* -------- Page Body (main + sidebar) -------- */}
      <div className={clsx(styles.pageBody, activeTab === 'analysis' && styles.pageBodyFullWidth)}>
        {/* ---- Main Column ---- */}
        <div className={styles.mainColumn}>
          {/* Tab Bar */}
          <nav className={styles.tabBar} role="tablist">
            {visibleTabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                id={`tab-${tab.id}`}
                aria-controls="advisory-tabpanel"
                aria-selected={activeTab === tab.id}
                className={clsx(styles.tab, activeTab === tab.id && styles.tabActive)}
                onClick={() => setTab(tab.id)}
              >
                {tab.label}
                <span className={styles.tabShortcut}>{tab.shortcut}</span>
              </button>
            ))}
          </nav>

          {/* Tab Content */}
          <div
            className={styles.tabContent}
            role="tabpanel"
            id="advisory-tabpanel"
            aria-labelledby={`tab-${activeTab}`}
          >
            {activeTab === 'overview' && (
              <OverviewTab
                advisory={advisory}
                onSwitchToRaw={() => setTab('raw')}
              />
            )}
            {activeTab === 'behaviors' && (
              <BehaviorsTab
                advisoryId={advisory.id}
                enabled={activeTab === 'behaviors'}
              />
            )}
            {activeTab === 'iocs' && (
              <IocTab
                advisoryId={advisory.id}
                enabled={activeTab === 'iocs'}
              />
            )}
            {activeTab === 'rules' && (
              <DetectionRulesTab
                advisoryId={advisory.id}
                enabled={activeTab === 'rules'}
              />
            )}
            {activeTab === 'analysis' && (
              <AnalysisTab
                analysis={analysis ?? null}
                isPending={analyzeMutation.isPending}
                error={analyzeMutation.error?.message ?? null}
              />
            )}
            {activeTab === 'raw' && <RawTab advisory={advisory} />}
          </div>
        </div>

        {/* ---- Sidebar ---- */}
        <aside className={clsx(styles.sidebar, activeTab === 'analysis' && styles.sidebarHidden)}>
          {/* Extraction Telemetry card (F.12) */}
          <div className={styles.sidebarCard}>
            <h3 className={styles.sidebarCardHeader}>Extraction Telemetry</h3>
            <div className={styles.sidebarCardBody}>
              <div className={styles.telemetryMiniGrid}>
                <div className={styles.telemetryMiniStat}>
                  <span className={styles.telemetryMiniLabel}>Status</span>
                  <span className={styles.telemetryMiniValue}>
                    <Badge variant="status" value={advisory.extraction_status} />
                  </span>
                </div>
                <div className={styles.telemetryMiniStat}>
                  <span className={styles.telemetryMiniLabel}>IOCs</span>
                  <span className={styles.telemetryMiniValue}>{advisory.ioc_count ?? 0}</span>
                </div>
                <div className={styles.telemetryMiniStat}>
                  <span className={styles.telemetryMiniLabel}>Rules</span>
                  <span className={styles.telemetryMiniValue}>{advisory.detection_rule_count ?? 0}</span>
                </div>
                <div className={styles.telemetryMiniStat}>
                  <span className={styles.telemetryMiniLabel}>Techniques</span>
                  <span className={styles.telemetryMiniValue}>{advisory.technique_count ?? 0}</span>
                </div>
                <div className={styles.telemetryMiniStat}>
                  <span className={styles.telemetryMiniLabel}>D3FEND</span>
                  <span className={styles.telemetryMiniValue}>{advisory.d3fend_count ?? 0}</span>
                </div>
                {advisory.extracted_at && (
                  <div className={styles.telemetryMiniStat}>
                    <span className={styles.telemetryMiniLabel}>Extracted</span>
                    <span className={styles.telemetryMiniValue} style={{ fontSize: 11 }}>
                      {advisory.extracted_at}
                    </span>
                  </div>
                )}
                {advisory.extraction_model && (
                  <div className={styles.telemetryMiniStat}>
                    <span className={styles.telemetryMiniLabel}>Model</span>
                    <span className={styles.telemetryMiniValue} style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      {advisory.extraction_model}
                    </span>
                  </div>
                )}
                {(advisory.input_tokens != null || advisory.output_tokens != null) && (
                  <div className={styles.telemetryMiniStat}>
                    <span className={styles.telemetryMiniLabel}>Tokens</span>
                    <span className={styles.telemetryMiniValue}>
                      {(advisory.input_tokens ?? 0).toLocaleString()} in / {(advisory.output_tokens ?? 0).toLocaleString()} out
                    </span>
                  </div>
                )}
                {advisory.llm_latency_ms != null && (
                  <div className={styles.telemetryMiniStat}>
                    <span className={styles.telemetryMiniLabel}>Latency</span>
                    <span className={styles.telemetryMiniValue}>
                      {(advisory.llm_latency_ms / 1000).toFixed(1)}s
                    </span>
                  </div>
                )}
                {advisory.llm_cost_usd != null && (
                  <div className={styles.telemetryMiniStat}>
                    <span className={styles.telemetryMiniLabel}>Cost</span>
                    <span className={styles.telemetryMiniValue}>
                      ${advisory.llm_cost_usd.toFixed(4)}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ATT&CK + D3FEND card (F.11) */}
          {showAttackCard && (
            <div className={styles.sidebarCard}>
              <h3 className={styles.sidebarCardHeader}>
                MITRE ATT&CK
                <button
                  type="button"
                  className={styles.navigatorBtn}
                  onClick={handleExportNavigator}
                >
                  Export Navigator
                </button>
              </h3>
              <div className={styles.sidebarCardBody}>
                {techniquesError && (
                  <span style={{ fontSize: 12, color: 'var(--status-failed)' }}>
                    Failed to load techniques.
                  </span>
                )}
                {!techniques && !techniquesError && <Skeleton lines={4} />}
                {techniques && (
                  <>
                    <p className={styles.attackSummary}>
                      {attackTechniques.length} technique{attackTechniques.length !== 1 ? 's' : ''}{' '}
                      across {uniqueTacticCount} tactic{uniqueTacticCount !== 1 ? 's' : ''}
                    </p>

                    {tacticGroups.map(([tactic, techs]) => (
                      <div key={tactic} className={styles.tacticGroup}>
                        <button
                          type="button"
                          className={styles.tacticHeader}
                          onClick={() => toggleTactic(tactic)}
                        >
                          <span className={styles.tacticExpandIcon}>
                            {expandedTactics.has(tactic) ? '▼' : '▶'}
                          </span>
                          <span className={styles.tacticName}>
                            {TACTIC_DISPLAY[tactic] ?? capitalize(tactic.replace(/-/g, ' '))}
                          </span>
                          <span className={styles.tacticCount}>{techs.length}</span>
                        </button>
                        {expandedTactics.has(tactic) && (
                          <div className={styles.techniqueList}>
                            {techs.map((t) => (
                              <div key={t.technique_id} className={styles.techniqueItem}>
                                <button
                                  type="button"
                                  className={styles.techniqueId}
                                  onClick={() => handleTechniqueClick(t.technique_id)}
                                  title="Scroll to annotation (or open MITRE if not in article)"
                                >
                                  {t.technique_id}
                                </button>
                                <span className={styles.techniqueName}>{t.name ?? 'Unknown'}</span>
                                {(() => {
                                  const meta = confidenceMeta(t.confidence);
                                  return (
                                    <span className={clsx(styles.confidenceBadge, meta.cls)}>
                                      {meta.label}
                                    </span>
                                  );
                                })()}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}

                    {/* D3FEND section */}
                    {d3fendTechniques.length > 0 && (
                      <>
                        <h4 className={styles.d3fendHeader}>D3FEND</h4>
                        {d3fendTechniques.map((t) => (
                          <div key={t.technique_id} className={styles.techniqueItem}>
                            <a
                              href={`https://d3fend.mitre.org/technique/${encodeURIComponent(t.technique_id)}/`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={styles.techniqueId}
                            >
                              {t.technique_id}
                            </a>
                            <span className={styles.techniqueName}>{t.name ?? 'Unknown'}</span>
                          </div>
                        ))}
                      </>
                    )}
                  </>
                )}
              </div>
            </div>
          )}

          {/* Linked CVEs card (F.12) */}
          {showCveCard && (
            <div className={styles.sidebarCard}>
              <h3 className={styles.sidebarCardHeader}>
                Linked CVEs
                <span className={styles.tacticCount}>{advisory.cve_count ?? 0}</span>
              </h3>
              <div className={styles.sidebarCardBody}>
                {sidebarCvesError && (
                  <span style={{ fontSize: 12, color: 'var(--status-failed)' }}>
                    Failed to load linked CVEs.
                  </span>
                )}
                {!sidebarCves && !sidebarCvesError && <Skeleton lines={3} />}
                {sidebarCves && sidebarCves.length === 0 && (
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    No linked CVEs found in MSRC.
                  </span>
                )}
                {sidebarCves && sidebarCves.map((cve) => (
                  <div key={cve.cve_id} className={styles.cveLinkItem}>
                    {cve.is_msrc ? (
                      <Link
                        to={`/msrc/${encodeURIComponent(cve.cve_id)}`}
                        className={styles.cveLinkId}
                      >
                        {cve.cve_id}
                      </Link>
                    ) : (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={styles.cveLinkId}
                      >
                        {cve.cve_id}
                      </a>
                    )}
                    {cve.is_msrc && cve.defense_score > 0 && (
                      <span className={styles.defenseScore}>{cve.defense_score}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Downloadable Assets card (F.12) */}
          {showAssetCard && (
            <div className={styles.sidebarCard}>
              <h3 className={styles.sidebarCardHeader}>
                Assets
                <span className={styles.tacticCount}>{advisory.asset_count ?? 0}</span>
              </h3>
              <div className={styles.sidebarCardBody}>
                {assetsError && (
                  <span style={{ fontSize: 12, color: 'var(--status-failed)' }}>
                    Failed to load assets.
                  </span>
                )}
                {!assets && !assetsError && <Skeleton lines={2} />}
                {assets && assets.map((asset) => (
                  <div key={asset.id} className={styles.assetItem}>
                    <span className={styles.assetTypeBadge}>{asset.asset_type}</span>
                    <a
                      href={asset.url ?? asset.original_url}
                      target={asset.url ? undefined : '_blank'}
                      rel="noopener noreferrer"
                      className={styles.assetLink}
                      title={asset.caption ?? asset.original_url}
                    >
                      {asset.caption ?? asset.original_url}
                    </a>
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
