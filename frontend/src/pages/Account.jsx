import { useAuth } from '../hooks/useAuth';
import '../components/Layout/Layout.css';

export default function Account() {
  const { user, logout } = useAuth();

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Account</h1>
        <p className="page-subtitle">Manage your profile and session</p>
      </div>

      <div style={{ maxWidth: '600px' }}>
        <div className="card" style={{ marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div style={{
              width: '64px', height: '64px', borderRadius: '50%',
              background: 'var(--accent)', color: 'var(--bg-base)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '24px', fontWeight: '700', fontFamily: 'var(--font-mono)'
            }}>
              {user ? user.charAt(0).toUpperCase() : 'U'}
            </div>
            
            <div style={{ flex: 1 }}>
              <h2 style={{ fontSize: '20px', margin: '0 0 4px 0', color: 'var(--text-primary)' }}>
                {user || 'Unknown User'}
              </h2>
              <div style={{ 
                display: 'inline-block', padding: '2px 8px', borderRadius: '4px',
                background: 'var(--iris-subtle)', color: 'var(--iris)',
                fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: '600'
              }}>
                Network Administrator
              </div>
            </div>
          </div>
        </div>

        <div className="card" style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '16px' }}>
            Session Details
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '12px' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Status</span>
              <span style={{ fontSize: '13px', color: 'var(--success)', fontWeight: '500', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className="status-dot online"></span> Active
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '12px' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Role Permissions</span>
              <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>Full Access (Read/Write)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Authentication Method</span>
              <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>Local JWT</span>
            </div>
          </div>
        </div>

        <button 
          className="btn btn-danger" 
          onClick={logout}
          style={{ width: '100%', justifyContent: 'center', padding: '12px' }}
        >
          ⏻ Sign Out
        </button>
      </div>
    </div>
  );
}
