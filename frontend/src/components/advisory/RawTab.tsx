/** Source HTML tab -- sanitized article HTML, extracted JSON viewer, and LLM telemetry. */

import { useMemo } from 'react';
import DOMPurify from 'dompurify';
import type { AdvisoryDetail } from '../../lib/types';
import styles from './advisory-tabs.module.css';

interface RawTabProps {
  advisory: AdvisoryDetail;
}

function TelemetryPanel({ advisory }: { advisory: AdvisoryDetail }) {
  const hasData =
    advisory.extracted_at ||
    advisory.input_tokens ||
    advisory.output_tokens ||
    advisory.llm_latency_ms ||
    advisory.llm_cost_usd ||
    advisory.extraction_model;

  if (!hasData) return null;

  return (
    <div className={styles.rawSection}>
      <h3 className={styles.rawSectionHeader}>LLM Telemetry</h3>
      <div className={styles.telemetryPanel}>
        {advisory.extraction_model && (
          <div className={styles.telemetryStat}>
            <span className={styles.telemetryLabel}>Model</span>
            <span className={styles.telemetryValue}>{advisory.extraction_model}</span>
          </div>
        )}
        {advisory.extracted_at && (
          <div className={styles.telemetryStat}>
            <span className={styles.telemetryLabel}>Extracted At</span>
            <span className={styles.telemetryValue}>{advisory.extracted_at}</span>
          </div>
        )}
        {advisory.input_tokens != null && (
          <div className={styles.telemetryStat}>
            <span className={styles.telemetryLabel}>Input Tokens</span>
            <span className={styles.telemetryValue}>{advisory.input_tokens.toLocaleString()}</span>
          </div>
        )}
        {advisory.output_tokens != null && (
          <div className={styles.telemetryStat}>
            <span className={styles.telemetryLabel}>Output Tokens</span>
            <span className={styles.telemetryValue}>{advisory.output_tokens.toLocaleString()}</span>
          </div>
        )}
        {advisory.llm_latency_ms != null && (
          <div className={styles.telemetryStat}>
            <span className={styles.telemetryLabel}>Latency</span>
            <span className={styles.telemetryValue}>{(advisory.llm_latency_ms / 1000).toFixed(1)}s</span>
          </div>
        )}
        {advisory.llm_cost_usd != null && (
          <div className={styles.telemetryStat}>
            <span className={styles.telemetryLabel}>Cost</span>
            <span className={styles.telemetryValue}>${advisory.llm_cost_usd.toFixed(4)}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export function RawTab({ advisory }: RawTabProps) {
  const sanitizedHtml = useMemo(
    () => advisory.article_body ? DOMPurify.sanitize(advisory.article_body) : null,
    [advisory.article_body],
  );

  const formattedJson = useMemo(() => {
    if (!advisory.extracted_json) return null;
    try {
      const parsed = JSON.parse(advisory.extracted_json);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return advisory.extracted_json;
    }
  }, [advisory.extracted_json]);

  return (
    <div className={styles.rawContainer}>
      {/* Article body */}
      <div className={styles.rawSection}>
        <h3 className={styles.rawSectionHeader}>Article Body</h3>
        {sanitizedHtml ? (
          <div
            className={styles.articleBody}
            dangerouslySetInnerHTML={{ __html: sanitizedHtml }}
          />
        ) : (
          <p className={styles.noDataMessage}>
            No article body available for this advisory.
          </p>
        )}
      </div>

      {/* Extracted JSON */}
      <div className={styles.rawSection}>
        <h3 className={styles.rawSectionHeader}>Extracted JSON</h3>
        {formattedJson ? (
          <div className={styles.jsonBlock}>
            <pre className={styles.jsonPre}>
              <code>{formattedJson}</code>
            </pre>
          </div>
        ) : (
          <p className={styles.noDataMessage}>
            No extraction data yet -- extraction has not been run on this advisory.
          </p>
        )}
      </div>

      {/* LLM Telemetry */}
      <TelemetryPanel advisory={advisory} />
    </div>
  );
}
