import clsx from 'clsx';
import { STATUS_DISPLAY_MAP } from '../lib/types';
import styles from './Badge.module.css';

interface BadgeProps {
  variant: 'source' | 'type' | 'status' | 'priority' | 'severity';
  value: string;
  label?: string;
  className?: string;
}

/**
 * Renders a pill/badge with color-coded variant.
 * Always includes text label alongside color (WCAG 1.4.1).
 * Status badges use STATUS_DISPLAY_MAP for human-readable labels.
 */
export function Badge({ variant, value, label, className }: BadgeProps) {
  const normalized = value.toLowerCase().replace(/\s+/g, '_');
  const variantClass = styles[`${variant}_${normalized}`];

  let displayText = label ? `${label}: ${value}` : value;
  let tooltip: string | undefined;

  if (variant === 'status') {
    const mapping = STATUS_DISPLAY_MAP[normalized];
    if (mapping) {
      displayText = label ? `${label}: ${mapping.label}` : mapping.label;
      tooltip = mapping.tooltip;
    }
  }

  return (
    <span className={clsx(styles.badge, variantClass, className)} title={tooltip}>
      {displayText}
    </span>
  );
}
