import { NavLink } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useApp }  from '../../hooks/useApp';
import './Sidebar.css';

const NAV = [
  { to: '/',        icon: '⬡', label: 'Dashboard'     },
  { to: '/train',   icon: '⚙', label: 'Train & Detect'},
  { to: '/alerts',  icon: '◈', label: 'Alerts'        },
  { to: '/settings',icon: '◎', label: 'Settings'      },
];

export default function Sidebar() {
  const { user, logout }        = useAuth();
  const { systemStatus, alerts, theme, setTheme } = useApp();
  const unread = alerts.filter(a => !a.is_false_positive).length;

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <span className="logo-icon">🛡</span>
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
