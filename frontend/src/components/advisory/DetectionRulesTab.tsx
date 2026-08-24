/** Detection Rules tab -- collapsible cards grouped by rule format (YARA, Sigma, Snort). */

import { useState, useMemo, useCallback } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import type { DetectionRule } from '../../lib/types';
import { fetchAdvisoryDetectionRules } from '../../lib/api';
import { CopyButton } from '../CopyButton';
import { useToast } from '../Toast';
import { Skeleton } from '../Skeleton';
import styles from '../../pages/AdvisoryDetail.module.css';

const FORMAT_ORDER = ['yara', 'sigma', 'snort'] as const;

// M7: format-specific structural keywords to highlight in rule bodies.
const RULE_KEYWORDS: Record<string, string[]> = {
  yara: ['rule', 'meta', 'strings', 'condition'],
  sigma: ['title', 'logsource', 'detection'],
  snort: ['alert', 'content', 'sid'],
};

/** Wrap format-specific keywords in highlight spans; everything else is plain text. */
function highlightRule(text: string, format: string): ReactNode {
  const keywords = RULE_KEYWORDS[format];
  if (!keywords) return text;
  const re = new RegExp(`\\b(${keywords.join('|')})\\b`, 'g');
  // String.split with a capture group interleaves matches at odd indices.
  return text.split(re).map((part, i) =>
    i % 2 === 1 ? (
      <span key={i} className={styles.ruleKeyword}>
        {part}
      </span>
    ) : (
      <span key={i}>{part}</span>
    ),
  );
}

interface DetectionRulesTabProps {
  advisoryId: number;
  enabled: boolean;
}

export function DetectionRulesTab({ advisoryId, enabled }: DetectionRulesTabProps) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const { addToast } = useToast();

  const {
    data: rules,
    isLoading,
    error,
  } = useQuery<DetectionRule[]>({
    queryKey: ['advisory-rules', advisoryId],
    queryFn: () => fetchAdvisoryDetectionRules(advisoryId),
    enabled,
    staleTime: 5 * 60 * 1000,
  });

  const grouped = useMemo(() => {
    if (!rules) return new Map<string, DetectionRule[]>();
    const map = new Map<string, DetectionRule[]>();
    for (const rule of rules) {
      const key = rule.rule_format;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(rule);
    }
    return map;
  }, [rules]);

  const toggleExpand = (id: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleCopyAllInSection = useCallback(
    async (format: string) => {
      const sectionRules = grouped.get(format);
      if (!sectionRules?.length) return;
      const text = sectionRules.map((r) => r.rule_text).join('\n\n');
      try {
        await navigator.clipboard.writeText(text);
        addToast(`Copied ${sectionRules.length} ${format.toUpperCase()} rule(s)`, 'success');
      } catch {
        addToast('Failed to copy', 'error');
      }
    },
    [grouped, addToast],
  );

  if (isLoading) return <Skeleton lines={6} />;

  if (error) {
    return (
      <p style={{ color: 'var(--status-failed)', fontSize: 13 }}>
        Failed to load detection rules.
      </p>
    );
  }

  if (!rules || rules.length === 0) {
    return (
      <p style={{ color: 'var(--text-muted)', fontSize: 13, fontStyle: 'italic' }}>
        No detection rules found.
      </p>
    );
  }

  return (
    <div className={styles.rulesContainer}>
      {FORMAT_ORDER.filter((f) => grouped.has(f)).map((format) => (
        <div key={format} className={styles.rulesGroup}>
          <h3 className={styles.rulesGroupHeader}>
            <span>
              {format.toUpperCase()}
              <span className={styles.rulesGroupCount}>
                {grouped.get(format)!.length}
              </span>
            </span>
            <button
              type="button"
              className={styles.rulesCopyAllBtn}
              onClick={() => handleCopyAllInSection(format)}
            >
              Copy all
            </button>
          </h3>
          <div className={styles.rulesCards}>
            {grouped.get(format)!.map((rule) => (
              <div key={rule.id} className={styles.ruleCard}>
                <button
                  type="button"
                  className={styles.ruleCardHeader}
                  onClick={() => toggleExpand(rule.id)}
                >
                  <div className={styles.ruleCardTitle}>
                    <span className={styles.ruleExpandIcon}>
                      {expanded.has(rule.id) ? '▼' : '▶'}
                    </span>
                    <span>{rule.rule_name ?? 'Unnamed Rule'}</span>
                  </div>
                  <div className={styles.ruleCardBadges}>
                    <span className={styles.ruleFormatBadge}>
                      {rule.rule_format}
                    </span>
                    {rule.validation_status && (
                      <span
                        className={clsx(
                          styles.ruleValidBadge,
                          rule.validation_status === 'valid' &&
                            styles.ruleValidBadgeValid,
                          rule.validation_status === 'invalid' &&
                            styles.ruleValidBadgeInvalid,
                        )}
                      >
                        {rule.validation_status}
                      </span>
                    )}
                  </div>
                </button>
                {expanded.has(rule.id) && (
                  <div className={styles.ruleCardBody}>
                    {rule.validation_status === 'invalid' && rule.validation_error && (
                      <div className={styles.ruleValidationError}>
                        <span className={styles.ruleValidationErrorLabel}>
                          Validation error
                        </span>
                        <span>{rule.validation_error}</span>
                      </div>
                    )}
                    <div className={styles.ruleCodeWrap}>
                      <div className={styles.ruleCopyCorner}>
                        <CopyButton
                          text={rule.rule_text}
                          label={`Copy ${rule.rule_name ?? 'rule'}`}
                        />
                      </div>
                      <pre className={styles.ruleCode}>
                        <code>{highlightRule(rule.rule_text, rule.rule_format)}</code>
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
