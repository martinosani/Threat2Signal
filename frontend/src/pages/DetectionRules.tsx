import { EmptyState } from '../components/EmptyState';

export default function DetectionRules() {
  return (
    <EmptyState
      title="No detection rules generated yet"
      description="Rules are created during advisory extraction (parse and rulegen phases). Run threat2signal extract to generate Sigma, KQL, and YARA detection rules."
    />
  );
}
