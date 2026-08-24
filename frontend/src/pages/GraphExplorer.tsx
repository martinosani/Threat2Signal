import { EmptyState } from '../components/EmptyState';

export default function GraphExplorer() {
  return (
    <EmptyState
      title="Graph Explorer requires Neo4j"
      description="Set up Neo4j and run threat2signal graph-sync to populate the intelligence graph. The explorer lets you visualize relationships between advisories, actors, techniques, and IOCs."
    />
  );
}
