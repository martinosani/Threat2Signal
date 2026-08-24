import { Outlet, NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { fetchStats } from './lib/api';
import { useAuth } from './lib/AuthContext';
import './App.css';

/**
 * Layout shell: grouped sidebar navigation + main content area.
 * Sidebar groups match analyst mental model (WS-4 Navigation spec).
 */
export default function App() {
  // F.19: Fetch stats for unread badge in sidebar
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    staleTime: 5 * 60 * 1000,
  });
  const { user, logout } = useAuth();
  const unreadCount = stats?.advisories?.by_triage?.unread ?? 0;

  return (
    <div className="app-layout">
      <aside className="sidebar">
        {/* Header */}
        <div className="sidebar-header">
          <div className="sidebar-logo">Threat2Signal</div>
          <div className="sidebar-subtitle">CTI Dashboard</div>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav">
          {/* INTELLIGENCE */}
          <div className="nav-group">
            <div className="nav-group-label">Intelligence</div>
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                clsx('nav-link', isActive && 'nav-link-active')
              }
            >
              Feed
              {unreadCount > 0 && (
                <span className="nav-badge">{unreadCount}</span>
              )}
            </NavLink>
            <NavLink
              to="/techniques"
              className={({ isActive }) =>
                clsx('nav-link', isActive && 'nav-link-active')
              }
            >
              Technique Matrix
            </NavLink>
            <NavLink
              to="/actors"
              className={({ isActive }) =>
                clsx('nav-link', isActive && 'nav-link-active')
              }
            >
              Actors &amp; Malware
            </NavLink>
          </div>

          {/* OPERATIONS */}
          <div className="nav-group">
            <div className="nav-group-label">Operations</div>
            <NavLink
              to="/iocs"
              className={({ isActive }) =>
                clsx('nav-link', isActive && 'nav-link-active')
              }
            >
              IOC Search
            </NavLink>
            <NavLink
              to="/rules"
              className={({ isActive }) =>
                clsx('nav-link', isActive && 'nav-link-active')
              }
            >
              Detection Rules
            </NavLink>
            <NavLink
              to="/msrc"
              className={({ isActive }) =>
                clsx('nav-link', isActive && 'nav-link-active')
              }
            >
              MSRC View
            </NavLink>
          </div>

          {/* EXPLORE */}
          <div className="nav-group">
            <div className="nav-group-label">Explore</div>
            <NavLink
              to="/graph"
              className={({ isActive }) =>
                clsx('nav-link', isActive && 'nav-link-active')
              }
            >
              Graph Explorer
            </NavLink>
          </div>
        </nav>

        {/* Footer: user session */}
        <div className="sidebar-footer">
          <span className="status-dot status-dot-connected" />
          <span className="sidebar-user">{user?.username}</span>
          <button className="logout-btn" onClick={logout} type="button">
            Sign out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
