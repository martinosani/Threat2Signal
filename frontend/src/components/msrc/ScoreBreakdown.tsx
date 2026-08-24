/** Visual breakdown of the defense_score into its component dimensions. */

import type { ScoreBreakdown as ScoreBreakdownType, VrScoreBreakdown as VrScoreBreakdownType } from '../../lib/types';
import { Badge } from '../Badge';
import styles from './msrc.module.css';

interface ScoreBreakdownProps {
  breakdown: ScoreBreakdownType | VrScoreBreakdownType;
  variant?: 'defense' | 'vr';
}

const DIMENSION_COLORS: Record<string, string> = {
  component: 'hsl(210, 70%, 50%)',
  cwe: 'hsl(340, 70%, 50%)',
  impact: 'hsl(30, 80%, 50%)',
  attack_vector: 'hsl(160, 60%, 45%)',
  privileges: 'hsl(270, 60%, 55%)',
  user_interaction: 'hsl(190, 60%, 45%)',
  bonuses: 'hsl(140, 60%, 42%)',
};

interface DimensionRow {
  key: string;
  label: string;
  detail: string;
  score: number;
  color: string;
}

export function ScoreBreakdown({ breakdown, variant: _variant = 'defense' }: ScoreBreakdownProps) {
  const bonusTotal = breakdown.bonuses.reduce((s, b) => s + b.score, 0);

  const dimensions: DimensionRow[] = [
    {
      key: 'component',
      label: 'Component',
      detail: breakdown.component.name ?? '--',
      score: breakdown.component.score,
      color: DIMENSION_COLORS.component,
    },
    {
      key: 'cwe',
      label: 'CWE',
      detail: breakdown.cwe.id ?? '--',
      score: breakdown.cwe.score,
      color: DIMENSION_COLORS.cwe,
    },
    {
      key: 'impact',
      label: 'Impact',
      detail: breakdown.impact.type ?? '--',
      score: breakdown.impact.score,
      color: DIMENSION_COLORS.impact,
    },
    {
      key: 'attack_vector',
      label: 'Attack Vector',
      detail: breakdown.attack_vector.value ?? '--',
      score: breakdown.attack_vector.score,
      color: DIMENSION_COLORS.attack_vector,
    },
    {
      key: 'privileges',
      label: 'Privileges',
      detail: breakdown.privileges.value ?? '--',
      score: breakdown.privileges.score,
      color: DIMENSION_COLORS.privileges,
    },
    {
      key: 'user_interaction',
      label: 'User Interaction',
      detail: breakdown.user_interaction.value ?? '--',
      score: breakdown.user_interaction.score,
      color: DIMENSION_COLORS.user_interaction,
    },
  ];

  const penaltyTotal = 'penalties' in breakdown
    ? (breakdown as VrScoreBreakdownType).penalties.reduce((s, p) => s + p.score, 0)
    : 0;
  // Scale bar against positive-only sum so penalties don't cause overflow
  const barDenom = Math.max(breakdown.total - penaltyTotal, 1);

  return (
    <div>
      {/* Total score + priority badge */}
      <div className={styles.scoreHeader}>
        <span className={styles.scoreTotal}>{breakdown.total}</span>
        <Badge variant="priority" value={breakdown.priority} />
      </div>

      {/* Stacked bar */}
      <div className={styles.scoreBar}>
        {dimensions.map((d) =>
          d.score > 0 ? (
            <div
              key={d.key}
              className={styles.scoreSegment}
              style={{
                width: `${(d.score / barDenom) * 100}%`,
                backgroundColor: d.color,
              }}
              title={`${d.label}: ${d.score}`}
            />
          ) : null,
        )}
        {bonusTotal > 0 && (
          <div
            className={styles.scoreSegment}
            style={{
              width: `${(bonusTotal / barDenom) * 100}%`,
              backgroundColor: DIMENSION_COLORS.bonuses,
            }}
            title={`Bonuses: ${bonusTotal}`}
          />
        )}
      </div>

      {/* Dimension list */}
      <div className={styles.scoreDimensions}>
        {dimensions.map((d) => (
          <div key={d.key} className={styles.scoreDimRow}>
            <span className={styles.scoreDimLabel}>
              <span
                className={styles.scoreDimDot}
                style={{ backgroundColor: d.color }}
              />
              <span className={styles.scoreDimName}>{d.label}</span>
              <span className={styles.scoreDimDetail}>{d.detail}</span>
            </span>
            <span className={styles.scoreDimValue}>{d.score}</span>
          </div>
        ))}

        {/* Bonuses */}
        {breakdown.bonuses.length > 0 && (
          <>
            <hr className={styles.bonusDivider} />
            {breakdown.bonuses.map((bonus) => (
              <div key={bonus.name} className={styles.scoreDimRow}>
                <span className={styles.scoreDimLabel}>
                  <span
                    className={styles.scoreDimDot}
                    style={{ backgroundColor: DIMENSION_COLORS.bonuses }}
                  />
                  <span className={styles.scoreDimName}>{bonus.name}</span>
                </span>
                <span className={styles.scoreDimValue}>+{bonus.score}</span>
              </div>
            ))}
          </>
        )}

        {/* Penalties (VR only) */}
        {'penalties' in breakdown && (breakdown as VrScoreBreakdownType).penalties.length > 0 && (
          <>
            <hr className={styles.bonusDivider} />
            {(breakdown as VrScoreBreakdownType).penalties.map((penalty) => (
              <div key={penalty.name} className={styles.scoreDimRow}>
                <span className={styles.scoreDimLabel}>
                  <span className={styles.scoreDimDot} style={{ backgroundColor: 'hsl(0, 70%, 55%)' }} />
                  <span className={styles.scoreDimName}>{penalty.name}</span>
                </span>
                <span className={styles.scoreDimValue} style={{ color: 'var(--status-failed)' }}>
                  {penalty.score}
                </span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
