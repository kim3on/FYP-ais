import { useEffect, useMemo, useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import '../components/Layout/Layout.css';
import './Account.css';

const PROFILE_FIELDS = [
  { key: 'display_name', label: 'Display Name' },
  { key: 'email', label: 'Email' },
  { key: 'phone', label: 'Phone' },
  { key: 'job_title', label: 'Job Title' },
  { key: 'soc_tier', label: 'SOC Tier' },
  { key: 'team', label: 'Team' },
  { key: 'shift', label: 'Shift' },
  { key: 'timezone', label: 'Timezone' },
  { key: 'escalation_contact', label: 'Escalation Contact' },
];

function normalizeProfile(profile = {}) {
  return PROFILE_FIELDS.reduce((next, field) => {
    next[field.key] = profile[field.key] || '';
    return next;
  }, {});
}

function DetailRow({ label, value }) {
  return (
    <div className="account-detail-row">
      <span>{label}</span>
      <strong>{value || 'Not set'}</strong>
    </div>
  );
}

export default function Account() {
  const { currentUser, logout, refreshCurrentUser, updateProfile } = useAuth();
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState(() => normalizeProfile(currentUser?.profile));
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const profile = useMemo(() => normalizeProfile(currentUser?.profile), [currentUser]);
  const displayName = profile.display_name || currentUser?.username || 'Unknown User';
  const initials = displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'U';

  useEffect(() => {
    refreshCurrentUser().catch(() => {});
  }, [refreshCurrentUser]);

  const startEditing = () => {
    setForm(profile);
    setMessage('');
    setError('');
    setEditing(true);
  };

  const cancelEditing = () => {
    setForm(profile);
    setMessage('');
    setError('');
    setEditing(false);
  };

  const handleChange = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError('');
    setMessage('');
    try {
      await updateProfile(form);
      setEditing(false);
      setMessage('Profile updated');
    } catch (err) {
      setError(err.message || 'Failed to update profile');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page account-page">
      <div className="page-header account-header">
        <div>
          <h1 className="page-title">Account</h1>
          <p className="page-subtitle">SOC analyst identity, contact details, and session context</p>
        </div>
        {!editing && (
          <button className="btn btn-default" type="button" onClick={startEditing}>
            Edit Profile
          </button>
        )}
      </div>

      <div className="account-grid">
        <section className="card account-identity-card">
          <div className="account-avatar">{initials}</div>
          <div className="account-identity-main">
            <h2>{displayName}</h2>
            <div className="account-username">@{currentUser?.username || 'unknown'}</div>
            <div className="account-badges">
              <span className="account-badge">{currentUser?.role || 'Unassigned Role'}</span>
              <span className="account-badge subtle">{profile.soc_tier || 'SOC Tier Not Set'}</span>
            </div>
          </div>
        </section>

        <section className="card account-session-card">
          <div className="account-section-title">Session Details</div>
          <DetailRow label="Status" value={currentUser?.session?.status || 'Active'} />
          <DetailRow label="Role Permissions" value={currentUser?.session?.role_permissions || 'Assigned Role Access'} />
          <DetailRow label="Authentication Method" value={currentUser?.session?.authentication_method || 'Local JWT'} />
        </section>
      </div>

      {message && <div className="account-message saved">{message}</div>}
      {error && <div className="account-message error">{error}</div>}

      {editing ? (
        <form className="card account-form" onSubmit={handleSubmit}>
          <div className="account-section-title">Editable Profile</div>
          <div className="account-form-grid">
            {PROFILE_FIELDS.map(({ key, label }) => (
              <div className="account-field" key={key}>
                <label htmlFor={key}>{label}</label>
                <input
                  id={key}
                  type={key === 'email' ? 'email' : 'text'}
                  value={form[key] || ''}
                  onChange={(event) => handleChange(key, event.target.value)}
                />
              </div>
            ))}
          </div>
          <div className="account-actions">
            <button className="btn btn-default" type="button" onClick={cancelEditing} disabled={saving}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={saving}>
              {saving ? 'Saving...' : 'Save Profile'}
            </button>
          </div>
        </form>
      ) : (
        <div className="account-grid">
          <section className="card">
            <div className="account-section-title">Operational Details</div>
            <DetailRow label="Job Title" value={profile.job_title} />
            <DetailRow label="SOC Tier" value={profile.soc_tier} />
            <DetailRow label="Team" value={profile.team} />
            <DetailRow label="Shift" value={profile.shift} />
            <DetailRow label="Timezone" value={profile.timezone} />
          </section>

          <section className="card">
            <div className="account-section-title">Contact Details</div>
            <DetailRow label="Email" value={profile.email} />
            <DetailRow label="Phone" value={profile.phone} />
            <DetailRow label="Escalation Contact" value={profile.escalation_contact} />
          </section>
        </div>
      )}

      <button className="btn btn-danger account-signout" onClick={logout}>
        Sign Out
      </button>
    </div>
  );
}
