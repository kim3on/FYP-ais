import { NavLink } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useApp }  from '../../hooks/useApp';
import './Sidebar.css';

// Dynamic accessibility person icon (arms outstretched — no emoji)
const AccessibilityIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <circle cx="12" cy="3.5" r="2"/>
    <path d="M18.5 8H5.5a.5.5 0 0 0 0 1H11v3.5l-2.8 5.1a.5.5 0 0 0 .88.48L12 13.2l2.92 4.88a.5.5 0 1 0 .88-.48L13 12.5V9h5.5a.5.5 0 0 0 0-1z"/>
  </svg>
);

const LogoIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" fill="var(--iris, #c4a7e7)" stroke="var(--iris, #c4a7e7)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    <circle cx="12" cy="12" r="5" fill="#fff"/>
    <circle cx="12" cy="12" r="5" stroke="var(--iris, #c4a7e7)" strokeWidth="1.2"/>
    <path d="M12 7V17M7 12H17" stroke="var(--iris, #c4a7e7)" strokeWidth="1"/>
    <path d="M12 7C13.5 8.5 14.5 10 14.5 12C14.5 14 13.5 15.5 12 17C10.5 15.5 9.5 14 9.5 12C9.5 10 10.5 8.5 12 7Z" stroke="var(--iris, #c4a7e7)" strokeWidth="1"/>
  </svg>
);

const NAV = [
  { to: '/',               icon: '⬡',                  label: 'Dashboard'      },
  { to: '/train',          icon: '⚙',                  label: 'Train & Detect' },
  { to: '/alerts',         icon: '◈',                  label: 'Alerts'         },
  { to: '/settings',       icon: '◎',                  label: 'Settings'       },
  { to: '/accessibility',  icon: <AccessibilityIcon />, label: 'Accessibility'  },
];

export default function Sidebar() {
  const { user, logout }        = useAuth();
  const { alerts, theme, setTheme } = useApp();
  const unread = alerts.filter(a => !a.is_false_positive).length;

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <span className="logo-icon"><LogoIcon /></span>
        <div>
          <div className="logo-title">AIS-Detect</div>
          <div className="logo-sub">Immune System IDS</div>
        </div>
      </div>

      {/* Nav links */}
      <nav className="sidebar-nav">
        {NAV.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="nav-icon">{icon}</span>
            <span className="nav-label">{label}</span>
            {label === 'Alerts' && unread > 0 && (
              <span className="nav-badge">{unread > 99 ? '99+' : unread}</span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <NavLink to="/account" className="sidebar-user" style={{ textDecoration: 'none' }}>
          <span className="user-avatar">{user?.[0]?.toUpperCase() ?? 'A'}</span>
          <div>
            <div className="user-name">{user ?? 'Admin'}</div>
            <div className="user-role">Network Admin</div>
          </div>
        </NavLink>
        <button className="btn btn-ghost btn-sm" onClick={toggleTheme} title="Toggle Theme" style={{marginRight: '4px'}}>
          {theme === 'dark' ? '☀' : '☾'}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={logout} title="Logout">
          ⏻
        </button>
      </div>
    </aside>
  );
}
