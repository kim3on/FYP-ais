import { useState, useEffect, useCallback } from 'react';
import { getInterfaces, getCaptureStatus, startCapture, stopCapture } from '../api';
import { useApp } from '../hooks/useApp';
import { useWebSocket } from '../hooks/useWebSocket';
import AlertTable from '../components/AlertTable';
import '../components/Layout/Layout.css';

export default function Capture() {
  const [interfaces, setInterfaces]   = useState([]);
  const [selectedIf, setSelectedIf]   = useState('');
  const [status, setStatus]           = useState(null);
  const [error, setError]             = useState('');
  
  const { 
    captureRunning, setCaptureRunning, pushAlert,
    liveAlerts, clearLiveSession
  } = useApp();

  // Load interfaces
  useEffect(() => {
    getInterfaces().then(d => {
      const ifaces = d.interfaces || d || [];
      setInterfaces(ifaces);
      if (ifaces.length > 0) setSelectedIf(ifaces[0].name || ifaces[0]);
    }).catch(err => {
      console.error("Failed to fetch interfaces:", err);
    });
  }, []);

  // Poll capture status
  useEffect(() => {
    const id = setInterval(async () => {
      try {
        const s = await getCaptureStatus();
        setStatus(s);
        setCaptureRunning(s.active || false);
      } catch(err) {
        console.error("Failed to fetch capture status:", err);
      }
    }, 3000);
    return () => clearInterval(id);
  }, [setCaptureRunning]);

  // WebSocket for live alerts
  useWebSocket('/ws/live', useCallback((msg) => {
    const type = msg?.type;
    const data = msg?.data ?? msg;

    if (type === 'flow') {
        const flowAlerts = data.alerts || [];
        flowAlerts.forEach(a => pushAlert(a));
        return;
    }

    if (type === 'alert' || data?.attack_type || data?.severity) {
      pushAlert(data);
    }
  }, [pushAlert]), captureRunning);

  async function handleStart() {
    setError('');
    try {
      await startCapture(selectedIf);
      setCaptureRunning(true);
    } catch(err) { setError(err.message); }
  }

  async function handleStop() {
    try {
      await stopCapture();
      setCaptureRunning(false);
    } catch(err) { setError(err.message); }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Live Capture</h1>
        <p className="page-subtitle">Real-time packet capture with flow-based anomaly detection</p>
      </div>

      {/* Controls card */}
      <div className="card" style={{marginBottom:'16px'}}>
        <div style={{display:'flex',alignItems:'flex-end',gap:'12px',flexWrap:'wrap'}}>
          <div style={{flex:1,minWidth:'180px'}}>
            <label>Network Interface</label>
            <select value={selectedIf} onChange={e=>setSelectedIf(e.target.value)} disabled={captureRunning}>
              {interfaces.length === 0
                ? <option value="">Loading interfaces…</option>
                : interfaces.map(i => {
                    const name = typeof i==='string'?i:(i.name||i.id||'');
                    const desc = typeof i==='string'?'':(i.description||i.desc||'');
                    return <option key={name} value={name}>{name}{desc?` — ${desc}`:''}</option>;
                  })
              }
            </select>
          </div>

          <div style={{display:'flex',gap:'8px'}}>
            <button className="btn btn-primary" onClick={handleStart} disabled={captureRunning||!selectedIf}>
              ▶ Start Capture
            </button>
            <button className="btn btn-danger" onClick={handleStop} disabled={!captureRunning}>
              ■ Stop
            </button>
          </div>

          {/* Live status indicator */}
          <div style={{display:'flex',alignItems:'center',gap:'8px',fontFamily:'var(--font-mono)',fontSize:'12px',color:'var(--text-secondary)'}}>
            <span className={`status-dot ${captureRunning?'online':'offline'}`} />
            {captureRunning ? 'Capturing…' : 'Stopped'}
            {status && (
              <span style={{color:'var(--text-tertiary)'}}>
                · {status.packets_captured||0} pkts · {status.flows_completed||0} flows
              </span>
            )}
          </div>
        </div>

        {error && (
          <div style={{marginTop:'12px',background:'var(--danger-subtle)',border:'1px solid var(--danger-border)',color:'var(--danger)',padding:'8px 12px',borderRadius:'var(--radius)',fontSize:'12px',fontFamily:'var(--font-mono)'}}>
            ⚠ {error}
          </div>
        )}
      </div>

      {/* Info box */}
      {!captureRunning && liveAlerts.length===0 && (
        <div className="card" style={{textAlign:'center',padding:'48px 24px',borderStyle:'dashed'}}>
          <div style={{fontSize:'32px',marginBottom:'12px'}}>◉</div>
          <p style={{fontFamily:'var(--font-mono)',fontSize:'13px',color:'var(--text-secondary)',marginBottom:'6px'}}>
            Select an interface and click <strong style={{color:'var(--accent)'}}>Start Capture</strong>
          </p>
          <p style={{fontFamily:'var(--font-mono)',fontSize:'11px',color:'var(--text-tertiary)'}}>
            Packets are aggregated into flows · requires admin/root privileges
          </p>
        </div>
      )}

      {/* Live alerts */}
      {liveAlerts.length > 0 && (
        <div className="card">
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'12px'}}>
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em'}}>
              Live Alerts — {liveAlerts.length}
            </div>
            <button className="btn btn-ghost" style={{fontSize:'11px',padding:'3px 8px'}}
              onClick={clearLiveSession}>
              Clear
            </button>
          </div>
          <AlertTable alerts={liveAlerts} />
        </div>
      )}
    </div>
  );
}
