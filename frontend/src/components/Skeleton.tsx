import styles from './Skeleton.module.css';

interface SkeletonProps {
  lines?: number;
}

/**
 * Pulsing placeholder blocks matching content shape.
 * Used during loading states.
 */
export function Skeleton({ lines = 3 }: SkeletonProps) {
  return (
    <div className={styles.container} aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <div
          key={i}
          className={styles.line}
          style={{
            width: i === lines - 1 ? '60%' : '100%',
          }}
        />
      ))}
    </div>
  );
}
