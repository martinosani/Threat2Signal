import { useNavigate } from 'react-router-dom';
import { EmptyState } from '../components/EmptyState';

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <EmptyState
      title="Page not found"
      description="The page you are looking for does not exist or has been moved."
      icon={
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M16 16s-1.5-2-4-2-4 2-4 2" />
          <line x1="9" y1="9" x2="9.01" y2="9" />
          <line x1="15" y1="9" x2="15.01" y2="9" />
        </svg>
      }
      action={{
        label: 'Go to Feed',
        onClick: () => navigate('/'),
      }}
    />
  );
}
