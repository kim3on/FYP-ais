import { useState, useEffect } from 'react';
import { getSystemStatus, getModelSummary, updateSettings, clearRawFlows } from '../api';
import { useApp } from '../hooks/useApp';
import { useAuth } from '../hooks/useAuth';
import '../components/Layout/Layout.css';
import './Settings.css';

const MODELS = [
  {
    id: 'nsa',
    name: 'Artificial Immune System (AIS)',
    short: 'AIS',
    desc: 'Bio-inspired detector profile for normal traffic and novelty scoring.',
  },
  {
    id: 'isolation_forest',
    name: 'Isolation Forest',
    short: 'IF',
    desc: 'Statistical baseline for anomaly comparison.',
  },
];

const ZERO_DAY_PRESETS = [
  { label: 'Low', value: 0.45 },
  { label: 'Medium', value: 0.65 },
  { label: 'High', value: 0.85 },
];

const ShieldIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M12 2 5 5v6c0 4.5 2.9 8.7 7 10 4.1-1.3 7-5.5 7-10V5l-7-3Z" />
  </svg>
);

const BellIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" />
    <path d="M13.7 21a2 2 0 0 1-3.4 0" />
  </svg>
);

const DataIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <rect x="4" y="5" width="16" height="3" rx="1" />
    <rect x="4" y="10.5" width="16" height="3" rx="1" />
    <rect x="4" y="16" width="16" height="3" rx="1" />
  </svg>
);

const PulseIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M3 12h4l2-6 4 12 2-6h6" />
  </svg>
);

function SettingSection({ icon, tone = 'accent', title, children, action }) {
  return (
    <section className="settings-section">
      <div className={`settings-section-icon ${tone}`}>{icon}</div>
      <div className="settings-section-body">
        <div className="settings-section-head">
          <h2>{title}</h2>
          {action}
        </div>
        {children}
      </div>
    </section>
  );
}

function FieldBlock({ label, children }) {
  return (
    <div className="settings-field">
      <div className="settings-field-label">{label}</div>
      {children}
    </div>
  );
}

function formatStatus(value) {
  if (value == null || value === '') return 'Unknown';
  return String(value).replace(/_/g, ' ');
}

function isModelUnavailable(modelInfo, modelId) {
  const status = modelInfo?.[modelId]?.status;
  return Boolean(status && status !== 'fitted');
}

export default function Settings() {
  const { activeModel, setActiveModel, refreshStatus } = useApp();
  const { currentUser, refreshCurrentUser } = useAuth();
  const [systemStatus, setSystemStatus] = useState(null);
  const [modelInfo, setModelInfo]   = useState(null);
  const [saving, setSaving]         = useState(false);
  const [zdThreshold, setZdThreshold] = useState(0.65);
  const [saved, setSaved]           = useState(false);
  const [error, setError]           = useState('');
  const [clearingDB, setClearingDB] = useState(false);
  const activeReady = systemStatus?.active_engine_ready ?? systemStatus?.models_ready;
  const role = (currentUser?.role || '').toLowerCase();
  const canOperate = role.includes('administrator') || role === 'admin';

  useEffect(() => {
    getSystemStatus().then(s => {
      setSystemStatus(s);
      if (s.active_detection_engine || s.active_model) setActiveModel(s.active_detection_engine || s.active_model);
      if (s.zero_day_threshold != null) setZdThreshold(Number(s.zero_day_threshold));
    }).catch(err => {
      console.error("Failed to fetch system status:", err);
    });
    getModelSummary().then(setModelInfo).catch(err => {
      console.error("Failed to fetch model summary:", err);
    });
  }, [setActiveModel]);

  useEffect(() => {
    if (!currentUser?.role) {
      refreshCurrentUser().catch(err => {
        console.error("Failed to refresh current user:", err);
      });
    }
  }, [currentUser?.role, refreshCurrentUser]);

  async function handleSave() {
    if (!canOperate) {
      setSaved(false);
      setError('Administrator role required to change system settings.');
      return;
    }
    const model = MODELS.find(m => m.id === activeModel);
    const confirmed = window.confirm(
      `Save detection settings?\n\nActive model: ${model?.name || activeModel}\nZero-day threshold: ${zdThreshold.toFixed(2)}`
    );
    if (!confirmed) return;
    setError(''); setSaved(false);
    setSaving(true);
    try {
      const result = await updateSettings({
        active_model: activeModel,
        zero_day_threshold: zdThreshold,
      });
      if (result.active_model) setActiveModel(result.active_model);
      if (result.zero_day_threshold != null) setZdThreshold(Number(result.zero_day_threshold));
      setSaved(true);
      await refreshStatus();
      getSystemStatus().then(s => {
        setSystemStatus(s);
        if (s.active_detection_engine || s.active_model) setActiveModel(s.active_detection_engine || s.active_model);
        if (s.zero_day_threshold != null) setZdThreshold(Number(s.zero_day_threshold));
      }).catch(err => {
        console.error("Failed to refresh system status:", err);
      });
      setTimeout(() => setSaved(false), 3000);
    } catch(err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  async function handleClearFlows() {
    if (!canOperate) {
      alert('Administrator role required to clear raw flows.');
      return;
    }
    if (!window.confirm('Are you sure you want to clear all raw flows from the persistent database? This action cannot be undone.')) return;
    setClearingDB(true);
    try {
      await clearRawFlows();
      alert('Raw flows cleared from persistent database successfully.');
    } catch (err) {
      alert('Error clearing raw flows: ' + err.message);
    } finally {
      setClearingDB(false);
    }
  }

  return (
    <div className="page settings-page">
      <div className="settings-page-header">
        <div>
          <h1 className="page-title">System Settings</h1>
          <p className="page-subtitle">Runtime detection preferences, model selection, and maintenance controls</p>
        </div>
        <button className="btn btn-primary settings-save" onClick={handleSave} disabled={saving || !canOperate}>
          {!canOperate ? 'Admin Only' : saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
      {!canOperate && (
        <div className="settings-access-note">
          Settings are read-only for this account. Administrator access is required to save changes or clear stored flow data.
        </div>
      )}
      {(error || saved) && (
        <div className={`settings-message ${error ? 'error' : 'saved'}`}>
          {error || 'Settings saved'}
        </div>
      )}
      <div className="settings-stack">
        <SettingSection
          icon={<ShieldIcon />}
          tone="accent"
          title="Detection Settings"
        >
          <div className="settings-grid two">
            <FieldBlock label="Active Model">
              <div className="settings-model-list">
                {MODELS.map(model => {
                  const unavailable = isModelUnavailable(modelInfo, model.id);
                  return (
                  <button
                    key={model.id}
                    type="button"
                    className={`settings-model ${activeModel === model.id ? 'active' : ''}`}
                    onClick={() => setActiveModel(model.id)}
                    disabled={!canOperate || unavailable || saving}
                  >
                    <span>{model.name}</span>
                    <small>{unavailable ? 'Train this model before selecting it.' : model.desc}</small>
                  </button>
                  );
                })}
              </div>
            </FieldBlock>

            <FieldBlock label="Runtime State">
              <div className="settings-status-grid">
                <div>
                  <span>Model Status</span>
                  <strong className={activeReady ? 't-success' : 't-warning'}>
                    {activeReady ? 'Ready' : 'Not Ready'}
                  </strong>
                </div>
                <div>
                  <span>Active Engine</span>
                  <strong>{MODELS.find(m => m.id === activeModel)?.short || activeModel.toUpperCase()}</strong>
                </div>
              </div>
            </FieldBlock>
          </div>
        </SettingSection>

        <SettingSection icon={<BellIcon />} tone="success" title="Alert Configurations">
          <div className="settings-grid two">
            <FieldBlock label="Zero-Day Candidate Threshold">
              <div className="settings-preset-row">
                {ZERO_DAY_PRESETS.map(preset => (
                  <button
                    key={preset.label}
                    type="button"
                    className={`settings-preset ${Math.abs(zdThreshold - preset.value) < 0.01 ? 'active' : ''}`}
                    onClick={() => setZdThreshold(preset.value)}
                    disabled={!canOperate || saving}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
              <div className="settings-range-card">
                <div>
                  <span>Novelty Score</span>
                  <strong>{zdThreshold.toFixed(2)}</strong>
                </div>
                <input
                  type="range"
                  min="0.3"
                  max="0.95"
                  step="0.05"
                  value={zdThreshold}
                  disabled={!canOperate || saving}
                  onChange={e => setZdThreshold(+parseFloat(e.target.value).toFixed(2))}
                />
              </div>
            </FieldBlock>
          </div>
        </SettingSection>

        <SettingSection icon={<DataIcon />} tone="accent" title="Data Management">
          <div className="settings-grid two">
            <FieldBlock label="Raw Flow Retention">
              <div className="settings-data-card">
                <strong>Persistent capture database</strong>
                <span>Raw network flows from live sniffer sessions are stored for system testing and can grow over time.</span>
              </div>
            </FieldBlock>

            <FieldBlock label="Maintenance Action">
              <button
                className="btn btn-default settings-danger-action"
                onClick={handleClearFlows}
                disabled={clearingDB || !canOperate}
              >
                {clearingDB ? <span className="spinner" /> : 'Clear'} Raw Flows Database
              </button>
            </FieldBlock>
          </div>
        </SettingSection>

        <SettingSection icon={<PulseIcon />} tone="success" title="System Informations">
          <div className="settings-grid two">
            <div className="settings-info-list">
              <div><span>Version</span><strong>v4.0.0</strong></div>
              <div><span>System Status</span><strong>{formatStatus(systemStatus?.status)}</strong></div>
              <div><span>Last Update</span><strong>{systemStatus?.server_time ? new Date(systemStatus.server_time).toLocaleString() : 'Unknown'}</strong></div>
            </div>

            <div className="settings-info-list">
              <div><span>Database Status</span><strong className="t-success">Connected</strong></div>
              <div><span>API Status</span><strong className={systemStatus ? 't-success' : 't-warning'}>{systemStatus ? 'Connected' : 'Unknown'}</strong></div>
              <div>
                <span>{systemStatus?.active_model_stat_label || 'Active Model Count'}</span>
                <strong>{(systemStatus?.active_model_stat_value ?? 0).toLocaleString()}</strong>
              </div>
            </div>

            {modelInfo && modelInfo[activeModel] && (
              <div className="settings-model-info">
                {Object.entries(modelInfo[activeModel]).slice(0, 6).map(([key, value]) => (
                  <div key={key}>
                    <span>{key}</span>
                    <strong>{String(value)}</strong>
                  </div>
                ))}
              </div>
            )}
          </div>
        </SettingSection>

        <div className="settings-note">
          Changing the active model only takes effect for new detections. Already-stored alerts are not re-evaluated.
        </div>
      </div>
    </div>
  );
}
