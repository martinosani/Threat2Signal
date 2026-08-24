import { EmptyState } from '../components/EmptyState';

export default function TechniqueMatrix() {
  return (
    <EmptyState
      title="No techniques mapped yet"
      description="Techniques appear after advisory extraction runs. Run threat2signal extract to populate the ATT&CK matrix."
    />
  );
}
