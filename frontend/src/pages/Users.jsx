import { useCallback, useEffect, useState, useMemo } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';
import { getUsers, createUser, deleteUser } from '../api';

export default function Users() {
  const { currentUser } = useAuth();
  const navigate = useNavigate();

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Creation Form State
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Security Analyst');
  const [creating, setCreating] = useState(false);

  // Deletion State
  const [deleteConfirm, setDeleteConfirm] = useState(null); // stores username to delete
  const [deleting, setDeleting] = useState(false);

  // Strictly enforce Admin check at the UI level
  const isAdmin = useMemo(() => {
    const roleLower = (currentUser?.role || '').toLowerCase();
    return roleLower.includes('administrator') || roleLower === 'admin';
  }, [currentUser]);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await getUsers();
      setUsers(data);
    } catch (err) {
      setError(err.message || 'Failed to retrieve user accounts');
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch users on mount
  useEffect(() => {
    if (isAdmin) {
      const timer = window.setTimeout(() => {
        fetchUsers();
      }, 0);
      return () => window.clearTimeout(timer);
    }
  }, [fetchUsers, isAdmin]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    const cleanUsername = username.trim();
    if (!cleanUsername || !password || !role) {
      setError('Please provide a username, password, and role.');
      return;
    }

    setCreating(true);
    try {
      await createUser(cleanUsername, password, role);
      setSuccess(`Operator @${cleanUsername} registered successfully!`);
      setUsername('');
      setPassword('');
      setRole('Security Analyst');
      await fetchUsers();
    } catch (err) {
      setError(err.message || 'Failed to create user');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteUser = async (userToDelete) => {
    setError('');
    setSuccess('');
    setDeleting(true);
    try {
      await deleteUser(userToDelete);
      setSuccess(`Account @${userToDelete} has been successfully deleted.`);
      setDeleteConfirm(null);
      await fetchUsers();
    } catch (err) {
      setError(err.message || 'Failed to delete user');
    } finally {
      setDeleting(false);
    }
  };

  // Helper to resolve role color theme
  const getRoleBadgeClass = (roleStr = '') => {
    const r = roleStr.toLowerCase();
    if (r.includes('administrator') || r === 'admin') return 'badge critical'; // Pinkish-red accent
    if (r.includes('analyst')) return 'badge medium'; // Primary/Blue-green accent
    return 'badge zero-day'; // Iris/Purple accent
  };

  // Calculate high-level metrics for bento cards
  const stats = useMemo(() => {
    const total = users.length;
    const admins = users.filter(u => {
      const r = (u.role || '').toLowerCase();
      return r.includes('administrator') || r === 'admin';
    }).length;
    return {
      total,
      admins,
      analysts: total - admins
    };
  }, [users]);

  // ── Render Access Denied View ──────────────────────────────────────────
  if (!isAdmin) {
    return (
      <div className="page flex flex-col items-center justify-center fade-in" style={{ minHeight: 'calc(100vh - 120px)', padding: '40px' }}>
        <div className="card text-center" style={{ maxWidth: '480px', width: '100%', padding: '40px', border: '1px solid var(--danger-border)', background: 'rgba(235,111,146,0.03)' }}>
          <div style={{ fontSize: '64px', color: 'var(--danger)', marginBottom: '20px', display: 'flex', justifyContent: 'center' }}>
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
          </div>
          <h1 style={{ fontSize: '24px', margin: '0 0 12px', color: 'var(--text-primary)' }}>Access Denied</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.6', marginBottom: '24px' }}>
            You do not have the required permissions to access this page. This portal is strictly restricted to network administrators.
          </p>
          <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={() => navigate('/')}>
            Return to Dashboard
          </button>
        </div>
      </div>
    );
  }

  // ── Render User Management View ─────────────────────────────────────────
  return (
    <div className="page fade-in" style={{ maxWidth: '1200px', margin: '0 auto', paddingBottom: '40px' }}>
      {/* Header */}
      <div className="page-header" style={{ marginBottom: '24px', display: 'flex', justifyContent: 'between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title" style={{ fontSize: '28px', margin: '0 0 6px' }}>User Management</h1>
          <p className="page-subtitle" style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
            Manage SOC analyst identities, access roles, and monitor active security operators.
          </p>
        </div>
        <button className="btn btn-default" onClick={fetchUsers} disabled={loading} style={{ fontSize: '11px', padding: '6px 12px' }}>
          ↻ Refresh List
        </button>
      </div>

      {/* Alert Messages */}
      {success && <div className="account-message saved" style={{ fontSize: '12px', padding: '10px 14px', borderRadius: 'var(--radius)' }}>✓ {success}</div>}
      {error && <div className="account-message error" style={{ fontSize: '12px', padding: '10px 14px', borderRadius: 'var(--radius)' }}>⚠ {error}</div>}

      {/* Bento Grid Stats */}
      <div className="account-grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '16px', marginBottom: '20px' }}>
        <div className="stat-card active">
          <div className="stat-label">Total Registered Operators</div>
          <div className="stat-value">{loading ? '...' : stats.total}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Administrators</div>
          <div className="stat-value">{loading ? '...' : stats.admins}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">SOC Analysts</div>
          <div className="stat-value">{loading ? '...' : stats.analysts}</div>
        </div>
      </div>

      {/* Core Layout split: Form and Table */}
      <div className="account-grid" style={{ gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
        
        {/* Creation Panel */}
        <section className="card flex flex-col" style={{ gap: '16px', height: 'fit-content' }}>
          <h3 className="account-section-title" style={{ fontSize: '11px', margin: 0 }}>Register New Operator</h3>
          
          <form onSubmit={handleCreateUser} className="flex flex-col" style={{ gap: '14px' }}>
            <div>
              <label htmlFor="reg-username">Username</label>
              <input
                id="reg-username"
                type="text"
                placeholder="e.g. analyst_sarah"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={creating}
                required
              />
            </div>
            
            <div>
              <label htmlFor="reg-password">Password</label>
              <input
                id="reg-password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={creating}
                required
              />
            </div>

            <div>
              <label htmlFor="reg-role">Role Hierarchy</label>
              <select
                id="reg-role"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                disabled={creating}
                style={{ cursor: 'pointer' }}
              >
                <option value="Security Analyst">Security Analyst</option>
                <option value="Network Administrator">Network Administrator</option>
                <option value="Incident Responder">Incident Responder</option>
                <option value="SOC Tier 1 Analyst">SOC Tier 1 Analyst</option>
              </select>
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: '8px' }} disabled={creating}>
              {creating ? 'Registering...' : 'Register Operator'}
            </button>
          </form>
        </section>

        {/* User Table Panel */}
        <section className="card flex flex-col" style={{ gap: '16px', minWidth: 0 }}>
          <h3 className="account-section-title" style={{ fontSize: '11px', margin: 0 }}>Active System Access List</h3>

          {loading ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>
              Loading registered accounts...
            </div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Assigned Role</th>
                    <th>Operational Details</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => {
                    const isSelf = currentUser?.username === user.username;
                    const userInitials = (user.profile?.display_name || user.username || 'A')
                      .split(/\s+/)
                      .filter(Boolean)
                      .slice(0, 2)
                      .map((p) => p[0]?.toUpperCase())
                      .join('') || 'U';

                    return (
                      <tr key={user.username}>
                        <td>
                          <div className="flex items-center gap-12" style={{ minWidth: 0 }}>
                            <div
                              style={{
                                width: '32px',
                                height: '32px',
                                borderRadius: '4px',
                                background: isSelf ? 'var(--accent)' : 'var(--border)',
                                color: '#fff',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                fontSize: '11px',
                                fontWeight: 700,
                                flexShrink: 0
                              }}
                            >
                              {userInitials}
                            </div>
                            <div className="flex flex-col" style={{ minWidth: 0 }}>
                              <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>@{user.username}</span>
                              <span style={{ color: 'var(--text-tertiary)', fontSize: '10px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                                {user.profile?.display_name || 'No Profile Display Name'}
                              </span>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={getRoleBadgeClass(user.role)}>
                            {user.role}
                          </span>
                        </td>
                        <td>
                          <div className="flex flex-col" style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>
                            <span><strong>Team:</strong> {user.profile?.team || 'Unassigned'}</span>
                            <span><strong>Shift:</strong> {user.profile?.shift || 'Unassigned'}</span>
                          </div>
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          {isSelf ? (
                            <span style={{ color: 'var(--text-tertiary)', fontSize: '10px', fontStyle: 'italic', paddingRight: '8px' }}>
                              Current User
                            </span>
                          ) : deleteConfirm === user.username ? (
                            <div className="flex items-center justify-end gap-8 fade-in">
                              <button
                                className="btn btn-danger"
                                style={{ padding: '4px 8px', fontSize: '9px' }}
                                onClick={() => handleDeleteUser(user.username)}
                                disabled={deleting}
                              >
                                {deleting ? 'Deleting...' : 'Confirm'}
                              </button>
                              <button
                                className="btn btn-default"
                                style={{ padding: '4px 8px', fontSize: '9px' }}
                                onClick={() => setDeleteConfirm(null)}
                                disabled={deleting}
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <button
                              className="btn btn-ghost"
                              style={{ padding: '4px 8px', fontSize: '10px', color: 'var(--danger)' }}
                              onClick={() => setDeleteConfirm(user.username)}
                              title="Revoke access"
                            >
                              Revoke Access
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

      </div>
    </div>
  );
}
