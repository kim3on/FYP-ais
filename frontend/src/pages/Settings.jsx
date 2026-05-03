import { useState, useEffect } from 'react';
import { getSystemStatus, getModelSummary, updateSettings, clearRawFlows } from '../api';
import { useApp } from '../hooks/useApp';
import '../components/Layout/Layout.css';

export default function Settings() {
  const { activeModel, setActiveModel, refreshStatus } = useApp();
  const [modelInfo, setModelInfo]   = useState(null);
  const [threshold, setThreshold]   = useState(0.5);
  const [zdThreshold, setZdThreshold] = useState(0.65);
  const [saved, setSaved]           = useState(false);
  const [error, setError]           = useState('');
  const [clearingDB, setClearingDB] = useState(false);

  useEffect(() => {
    getSystemStatus().then(s => {
      if (s.active_model) setActiveModel(s.active_model);
      if (s.threshold)    setThreshold(s.threshold);
    }).catch(err => {
      console.error("Failed to fetch system status:", err);
    });
    getModelSummary().then(setModelInfo).catch(err => {
      console.error("Failed to fetch model summary:", err);
    });
  }, [setActiveModel]);

  async function handleSave() {
    setError(''); setSaved(false);
    try {
      await updateSettings({
        active_model: activeModel,
        threshold,
        zero_day_threshold: zdThreshold,
      });
      setSaved(true);
      refreshStatus();
      setTimeout(() => setSaved(false), 3000);
    } catch(err) { setError(err.message); }
  }

  async function handleClearFlows() {
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
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Settings</h1>
        <p className="page-subtitle">Configure detection model and threshold parameters</p>
      </div>

      <div className="two-col">
        {/* Left — model selector */}
        <div style={{display:'flex',flexDirection:'column',gap:'14px'}}>
          <div className="card">
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'16px'}}>
              Active Detection Model
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:'10px'}}>
              {[
                {
                  id:'nsa',
                  name:'Negative Selection Algorithm',
                  desc:'Bio-inspired AIS model. Learns a "Self" profile of normal traffic and flags deviations. Supports zero-day detection through novelty scoring.',
                  badge:'Recommended',
                  badgeColor:'var(--success)',
                },
                {
                  id:'isolation_forest',
                  name:'Isolation Forest',
                  desc:'Statistical baseline using random tree isolation. Faster but less interpretable. Used for performance comparison against the NSA.',
                  badge:'Baseline',
                  badgeColor:'var(--rp-muted)',
                },
              ].map(m => (
                <div
                  key={m.id}
                  onClick={()=>setActiveModel(m.id)}
                  style={{
                    background: activeModel===m.id ? 'var(--accent-subtle)' : 'var(--bg-overlay)',
                    border: `1px solid ${activeModel===m.id ? 'var(--accent)' : 'var(--border)'}`,
                    borderRadius:'var(--radius)',padding:'14px',cursor:'pointer',
                    transition:'all var(--transition)',
                  }}
                >
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'6px'}}>
                    <span style={{fontFamily:'var(--font-mono)',fontWeight:600,fontSize:'13px',color:activeModel===m.id?'var(--accent)':'var(--text-primary)'}}>
                      {m.name}
                    </span>
                    <span style={{fontSize:'9px',fontFamily:'var(--font-mono)',fontWeight:700,textTransform:'uppercase',color:m.badgeColor,letterSpacing:'0.06em'}}>
                      {m.badge}
                    </span>
                  </div>
                  <p style={{fontSize:'11px',color:'var(--text-tertiary)',lineHeight:'1.5'}}>{m.desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Model info */}
          {modelInfo && (
            <div className="card">
              <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'12px'}}>
                Loaded Model Info
              </div>
              <div style={{display:'flex',flexDirection:'column',gap:'8px'}}>
                {Object.entries(modelInfo).map(([k,v])=>(
                  <div key={k} style={{display:'flex',justifyContent:'space-between',fontSize:'12px',fontFamily:'var(--font-mono)'}}>
                    <span style={{color:'var(--text-tertiary)'}}>{k}</span>
                    <span style={{color:'var(--text-primary)',fontWeight:500}}>{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Database Management */}
          <div className="card">
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'12px'}}>
              Database Management
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:'8px'}}>
              <p style={{fontSize:'11px',color:'var(--text-tertiary)',lineHeight:'1.5'}}>
                Raw network flows captured during live sniffer sessions are saved to the SQLite database for system testing purposes. They can grow very large over time.
              </p>
              <button 
                className="btn btn-default" 
                style={{color:'var(--danger)',borderColor:'var(--danger-border)',justifyContent:'center',marginTop:'8px'}}
                onClick={handleClearFlows}
                disabled={clearingDB}
              >
                {clearingDB ? <span className="spinner"/> : '🗑'} Clear Raw Flows Database
              </button>
            </div>
          </div>
        </div>

        {/* Right — thresholds */}
        <div style={{display:'flex',flexDirection:'column',gap:'14px'}}>
          <div className="card">
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'16px'}}>
              Detection Thresholds
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:'20px'}}>
              <div>
                <label>Anomaly Threshold — <span style={{color:'var(--accent)'}}>{threshold}</span></label>
                <p style={{fontSize:'10px',color:'var(--text-tertiary)',fontFamily:'var(--font-mono)',marginBottom:'8px'}}>
                  Confidence score above which a flow is flagged as anomalous
                </p>
                <input type="range" min="0.1" max="0.9" step="0.05" value={threshold}
                  onChange={e=>setThreshold(+parseFloat(e.target.value).toFixed(2))}
                  style={{padding:0,cursor:'pointer',accentColor:'var(--accent)'}} />
              </div>
              <div>
                <label>Zero-Day Candidate Threshold — <span style={{color:'var(--iris)'}}>{zdThreshold}</span></label>
                <p style={{fontSize:'10px',color:'var(--text-tertiary)',fontFamily:'var(--font-mono)',marginBottom:'8px'}}>
                  Novelty score above which an anomaly is labelled "Zero-Day Candidate"
                </p>
                <input type="range" min="0.3" max="0.95" step="0.05" value={zdThreshold}
                  onChange={e=>setZdThreshold(+parseFloat(e.target.value).toFixed(2))}
                  style={{padding:0,cursor:'pointer',accentColor:'var(--iris)'}} />
              </div>
            </div>
          </div>

          <div className="card" style={{background:'var(--bg-overlay)',borderStyle:'dashed'}}>
            <div style={{fontSize:'11px',fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',lineHeight:'1.7'}}>
              <span style={{color:'var(--warning)',fontWeight:600}}>⚠ Note:</span> Changing the active model only takes effect for new detections.
              Already-stored alerts are not re-evaluated. Re-train after switching models
              to ensure the Self profile matches the selected algorithm.
            </div>
          </div>

          {error && <div style={{background:'var(--danger-subtle)',border:'1px solid var(--danger-border)',color:'var(--danger)',padding:'10px 14px',borderRadius:'var(--radius)',fontSize:'12px',fontFamily:'var(--font-mono)'}}>⚠ {error}</div>}
          {saved  && <div style={{background:'var(--success-subtle)',border:'1px solid var(--success-border)',color:'var(--success)',padding:'10px 14px',borderRadius:'var(--radius)',fontSize:'12px',fontFamily:'var(--font-mono)'}}>✓ Settings saved</div>}

          <button className="btn btn-primary" onClick={handleSave} style={{width:'100%',justifyContent:'center',padding:'10px'}}>
            Save Settings
          </button>
        </div>
      </div>
    </div>
  );
}
