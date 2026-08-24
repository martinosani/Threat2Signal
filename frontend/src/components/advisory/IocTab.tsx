/** IOCs tab -- searchable, filterable table of extracted IOCs with bulk actions. */

import { useState, useMemo, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import type { Ioc } from '../../lib/types';
import { fetchAdvisoryIocs, exportAdvisoryIocs, triggerDownload } from '../../lib/api';
import { CopyButton } from '../CopyButton';
import { useToast } from '../Toast';
import { Skeleton } from '../Skeleton';
import styles from '../../pages/AdvisoryDetail.module.css';

type IocFilter = 'all' | 'hashes' | 'network' | 'files' | 'allowlisted' | 'needs_review';

const HASH_TYPES = new Set([
  'md5', 'sha1', 'sha256', 'sha512', 'hash', 'ssdeep', 'imphash',
]);
const NETWORK_TYPES = new Set([
  'ip', 'ipv4', 'ipv6', 'domain', 'url', 'email', 'uri', 'hostname',
]);
const FILE_TYPES = new Set([
  'filename', 'filepath', 'file', 'mutex', 'registry',
]);

function matchesFilter(ioc: Ioc, filter: IocFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'allowlisted') return ioc.validation_status === 'allowlisted';
  const t = ioc.type.toLowerCase();
  if (filter === 'hashes') return HASH_TYPES.has(t);
  if (filter === 'network') return NETWORK_TYPES.has(t);
  if (filter === 'files') return FILE_TYPES.has(t);
  if (filter === 'needs_review') return ioc.needs_review === 1;
  return true;
}

const FILTER_LABELS: Record<IocFilter, string> = {
  all: 'All',
  hashes: 'Hashes',
  network: 'Network',
  files: 'File Artifacts',
  allowlisted: 'Allowlisted',
  needs_review: 'Needs Review',
};

interface IocTabProps {
  advisoryId: number;
  enabled: boolean;
}

export function IocTab({ advisoryId, enabled }: IocTabProps) {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<IocFilter>('all');
  const { addToast } = useToast();

  const {
    data: iocs,
    isLoading,
    error,
  } = useQuery<Ioc[]>({
    queryKey: ['advisory-iocs', advisoryId],
    queryFn: () => fetchAdvisoryIocs(advisoryId),
    enabled,
    staleTime: 5 * 60 * 1000,
  });

  const filtered = useMemo(() => {
    if (!iocs) return [];
    const q = search.toLowerCase();
    return iocs.filter((ioc) => {
      if (!matchesFilter(ioc, filter)) return false;
      if (
        q &&
        !ioc.value.toLowerCase().includes(q) &&
        !(ioc.context ?? '').toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [iocs, search, filter]);

  const needsReviewCount = useMemo(() => {
    if (!iocs) return 0;
    return iocs.filter((ioc) => ioc.needs_review === 1).length;
  }, [iocs]);

  const handleCopyAll = useCallback(async () => {
    if (!filtered.length) return;
    const text = filtered.map((i) => i.value).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      addToast(`Copied ${filtered.length} IOCs to clipboard`, 'success');
    } catch {
      addToast('Failed to copy', 'error');
    }
  }, [filtered, addToast]);

  const handleExport = useCallback(
    async (format: 'csv' | 'stix2') => {
      try {
        const blob = await exportAdvisoryIocs(advisoryId, format);
        const ext = format === 'csv' ? 'csv' : 'json';
        triggerDownload(blob, `${advisoryId}_iocs.${ext}`);
        addToast(`Export started (${format.toUpperCase()})`, 'success');
      } catch {
        addToast('Export failed', 'error');
      }
    },
    [advisoryId, addToast],
  );

  if (isLoading) return <Skeleton lines={6} />;

  if (error) {
    return (
      <p style={{ color: 'var(--status-failed)', fontSize: 13 }}>
        Failed to load IOCs.
      </p>
    );
  }

  if (!iocs || iocs.length === 0) {
    return (
      <p style={{ color: 'var(--text-muted)', fontSize: 13, fontStyle: 'italic' }}>
        No IOCs found.
      </p>
    );
  }

  return (
    <div className={styles.iocContainer}>
      {/* Search + Filter bar */}
      <div className={styles.iocToolbar}>
        <input
          type="text"
          placeholder="Search IOCs by value or context..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className={styles.iocSearch}
        />
        <div className={styles.iocFilters}>
          {(['all', 'hashes', 'network', 'files', 'allowlisted', 'needs_review'] as IocFilter[]).map((f) => (
            <button
              key={f}
              type="button"
              className={clsx(
                styles.iocFilterChip,
                filter === f && styles.iocFilterChipActive,
              )}
              onClick={() => setFilter(f)}
            >
              {FILTER_LABELS[f]}
              {f === 'needs_review' && needsReviewCount > 0 && (
                <span className={styles.iocCrossRefBadge} style={{ marginLeft: 4 }}>
                  {needsReviewCount}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Bulk actions */}
      <div className={styles.iocBulkActions}>
        <span className={styles.iocResultCount}>
          {filtered.length} IOC{filtered.length !== 1 ? 's' : ''}
        </span>
        <button
          type="button"
          className={styles.iocBulkBtn}
          onClick={handleCopyAll}
        >
          Copy all
        </button>
        <button
          type="button"
          className={styles.iocBulkBtn}
          onClick={() => handleExport('csv')}
        >
          Export CSV
        </button>
        <button
          type="button"
          className={styles.iocBulkBtn}
          onClick={() => handleExport('stix2')}
        >
          Export STIX 2.1
        </button>
      </div>

      {/* Table */}
      <div className={styles.iocTableWrap}>
        <table className={styles.iocTable}>
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Context</th>
              <th>Source</th>
              <th>Validation</th>
              <th>Cross-Ref</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc) => (
              <tr key={ioc.id}>
                <td>
                  <span className={styles.iocTypePill}>{ioc.type}</span>
                </td>
                <td>
                  <div className={styles.iocValueCell}>
                    <code className={styles.iocValue}>{ioc.value}</code>
                    <CopyButton text={ioc.value} />
                  </div>
                </td>
                <td className={styles.iocContext}>{ioc.context ?? '--'}</td>
                <td>
                  <span
                    className={clsx(
                      styles.iocValidationPill,
                      ioc.validation_status === 'allowlisted'
                        ? undefined
                        : ioc.extraction_source === 'parse' && ioc.source_verified
                          ? styles.iocSourceStated
                          : ioc.extraction_source === 'intel'
                            ? styles.iocSourceExtracted
                            : undefined,
                    )}
                  >
                    {ioc.validation_status === 'allowlisted'
                      ? 'Allowlisted'
                      : ioc.extraction_source === 'parse' && ioc.source_verified
                        ? 'Stated'
                        : ioc.extraction_source === 'intel'
                          ? 'Extracted'
                          : 'Parsed'}
                  </span>
                </td>
                <td>
                  <span
                    className={clsx(
                      styles.iocValidationPill,
                      ioc.validation_status === 'valid' &&
                        styles.iocValidationValid,
                      ioc.validation_status === 'invalid' &&
                        styles.iocValidationInvalid,
                      ioc.validation_status === 'suspicious' &&
                        styles.iocValidationSuspicious,
                    )}
                  >
                    {ioc.validation_status}
                  </span>
                </td>
                <td style={{ textAlign: 'center' }}>
                  {ioc.cross_ref_count > 0 && (
                    <span
                      className={styles.iocCrossRefBadge}
                      title={`Seen in ${ioc.cross_ref_count} other ${ioc.cross_ref_count === 1 ? 'advisory' : 'advisories'}`}
                    >
                      {ioc.cross_ref_count}x
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
