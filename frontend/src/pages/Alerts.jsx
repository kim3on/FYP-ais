import { useEffect, useCallback, useState } from 'react';
import { getAlerts, markFalsePositive, blockIP, unblockIP, getBlockedIPs } from '../api';
import { useApp } from '../hooks/useApp';
import AlertTable from '../components/AlertTable';
import '../components/Layout/Layout.css';

export default function Alerts() {
  const { alerts, setAlerts } = useApp();
  const [loading, setLoading] = useState(false);
  const [filter, setFilter]   = useState('all');
  const [tab, setTab]         = useState('alerts'); // 'alerts' | 'blocked'
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [blockError, setBlockError] = useState('');

  // ── Fetch alerts ─────────────────────────────────────────────
  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getAlerts(500);
      setAlerts(data.alerts || data || []);
    } catch(err) {
      console.error("Failed to fetch alerts:", err);
    } finally {
      setLoading(false);
    }
  }, [setAlerts]);

  // ── Fetch blocked IPs ────────────────────────────────────────
  const refreshBlocked = useCallback(async () => {
    try {
      const data = await getBlockedIPs();
      setBlockedIPs(data.blocked || []);
    } catch(err) {
      console.error("Failed to fetch blocked IPs:", err);
    }
  }, []);

  useEffect(() => {
    let isMounted = true;
    if (isMounted) {
      setTimeout(() => {
        refresh();
        refreshBlocked();
      }, 0);
    }
    return () => { isMounted = false; };
  }, [refresh, refreshBlocked]);

  async function handleMarkFP(id) {
    try {
      await markFalsePositive(id);
      setAlerts(prev => prev.map(a => a.alert_id===id ? {...a,is_false_positive:true} : a));
    } catch(err) {
      console.error("Failed to mark FP:", err);
    }
  }

  async function handleBlockIP(ip, reason) {
    setBlockError('');
    try {
      await blockIP(ip, reason || 'Blocked by AIS-Detect');
      await refreshBlocked();
    } catch(e) {
      setBlockError(e.message || 'Failed to block IP. Is the backend running as Administrator?');
    }
  }

  async function handleUnblock(ip) {
    setBlockError('');
    try {
      await unblockIP(ip);
      await refreshBlocked();
    } catch(e) {
      setBlockError(e.message || 'Failed to unblock IP.');
    }
  }

  const blockedIPList = blockedIPs.map(b => b.ip);

  const filtered = alerts.filter(a => {
    if (filter==='critical')  return (a.severity||'').toLowerCase()==='critical';
    if (filter==='high')      return (a.severity||'').toLowerCase()==='high';
    if (filter==='zero-day')  return a.is_zero_day||a.attack_type==='Zero-Day Candidate';
    return true;
  });

  const counts = {
    total:   alerts.length,
    critical: alerts.filter(a=>(a.severity||'').toLowerCase()==='critical').length,
    high:    alerts.filter(a=>(a.severity||'').toLowerCase()==='high').length,
    zeroDay: alerts.filter(a=>a.is_zero_day||a.attack_type==='Zero-Day Candidate').length,
  };

  function exportAlertsCSV() {
    if (filtered.length === 0) return;
    const header = ['Timestamp', 'Attack Type', 'Severity', 'Confidence', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'False Positive'];
    const csv = [
      header.join(','),
      ...filtered.map(a => [
        a.timestamp || new Date().toISOString(),
        a.attack_type,
        a.severity,
        a.confidence != null ? `${Math.round(a.confidence*100)}%` : '',
        a.src_ip || 'N/A',
        a.dst_ip || 'N/A',
        a.dst_port || 'N/A',
        a.protocol || 'N/A',
        a.is_false_positive ? 'Yes' : 'No'
      ].map(v => `"${(v || '').toString().replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alerts_export_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="page">
      <div className="page-header flex justify-between items-center">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">All detected anomalies with forensic metadata</p>
        </div>
        <button className="btn btn-default" onClick={() => { refresh(); refreshBlocked(); }} disabled={loading}>
          {loading ? <span className="spinner"/> : '↻'} Refresh
        </button>
      </div>

      {/* Stat row */}
      <div className="stat-grid" style={{marginBottom:'16px'}}>
        <div className="stat-card"><div className="stat-label">Total</div><div className="stat-value">{counts.total}</div></div>
        <div className="stat-card" style={{borderColor:counts.critical>0?'var(--danger-border)':'var(--border)'}}>
          <div className="stat-label" style={{color:'var(--danger)'}}>Critical</div>
          <div className="stat-value" style={{color:counts.critical>0?'var(--danger)':'var(--text-primary)'}}>{counts.critical}</div>
        </div>
        <div className="stat-card" style={{borderColor:counts.high>0?'var(--warning-border)':'var(--border)'}}>
          <div className="stat-label" style={{color:'var(--warning)'}}>High</div>
          <div className="stat-value" style={{color:counts.high>0?'var(--warning)':'var(--text-primary)'}}>{counts.high}</div>
        </div>
        <div className="stat-card" style={{borderColor:counts.zeroDay>0?'var(--iris-border)':'var(--border)'}}>
          <div className="stat-label" style={{color:'var(--iris)'}}>Zero-Day</div>
          <div className="stat-value" style={{color:counts.zeroDay>0?'var(--iris)':'var(--text-primary)'}}>{counts.zeroDay}</div>
        </div>
        <div className="stat-card" style={{borderColor:blockedIPs.length>0?'var(--danger-border)':'var(--border)'}}>
          <div className="stat-label" style={{color:'var(--danger)'}}>Blocked IPs</div>
          <div className="stat-value" style={{color:blockedIPs.length>0?'var(--danger)':'var(--text-primary)'}}>{blockedIPs.length}</div>
        </div>
      </div>

      {/* Error banner */}
      {blockError && (
        <div style={{marginBottom:'14px',background:'var(--danger-subtle)',border:'1px solid var(--danger-border)',color:'var(--danger)',padding:'8px 12px',borderRadius:'var(--radius)',fontSize:'11px',fontFamily:'var(--font-mono)',display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <span>⚠ {blockError}</span>
          <button className="btn btn-ghost" style={{fontSize:'10px',padding:'2px 6px'}} onClick={() => setBlockError('')}>✕</button>
        </div>
      )}

      {/* Tab switcher */}
      <div style={{display:'flex',gap:'0',marginBottom:'14px',borderBottom:'1px solid var(--border)'}}>
        <button
          onClick={() => setTab('alerts')}
          style={{
            padding:'8px 20px',fontSize:'12px',fontFamily:'var(--font-mono)',fontWeight:600,
            background:'none',border:'none',cursor:'pointer',
            color: tab==='alerts' ? 'var(--accent)' : 'var(--text-tertiary)',
            borderBottom: tab==='alerts' ? '2px solid var(--accent)' : '2px solid transparent',
          }}
        >
          Recent Alerts
        </button>
        <button
          onClick={() => setTab('blocked')}
          style={{
            padding:'8px 20px',fontSize:'12px',fontFamily:'var(--font-mono)',fontWeight:600,
            background:'none',border:'none',cursor:'pointer',
            color: tab==='blocked' ? 'var(--danger)' : 'var(--text-tertiary)',
            borderBottom: tab==='blocked' ? '2px solid var(--danger)' : '2px solid transparent',
          }}
        >
          Blocked IPs {blockedIPs.length > 0 && <span style={{marginLeft:'6px',background:'var(--danger)',color:'#fff',padding:'1px 6px',borderRadius:'8px',fontSize:'10px'}}>{blockedIPs.length}</span>}
        </button>
      </div>

      {/* ── Alerts Tab ──────────────────────────────────────────── */}
      {tab === 'alerts' && (
        <>
          {/* Filter tabs + export */}
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'14px'}}>
            <div style={{display:'flex',gap:'6px'}}>
              {[['all','All'],['critical','Critical'],['high','High'],['zero-day','Zero-Day']].map(([val,label])=>(
                <button key={val}
                  className={`btn ${filter===val?'btn-primary':'btn-default'}`}
                  style={{fontSize:'11px',padding:'5px 12px'}}
                  onClick={()=>setFilter(val)}>
                  {label}
                </button>
              ))}
            </div>
            <button className="btn btn-primary" style={{fontSize:'11px',padding:'5px 12px'}} onClick={exportAlertsCSV} disabled={filtered.length===0}>
              ↓ Export CSV
            </button>
          </div>

          <div className="card">
            <AlertTable
              alerts={filtered}
              onMarkFP={handleMarkFP}
              onBlockIP={handleBlockIP}
              blockedIPs={blockedIPList}
              showActions
            />
          </div>
        </>
      )}

      {/* ── Blocked IPs Tab ─────────────────────────────────────── */}
      {tab === 'blocked' && (
        <div className="card">
          {blockedIPs.length === 0 ? (
            <div style={{textAlign:'center',padding:'32px 16px',color:'var(--text-tertiary)',fontFamily:'var(--font-mono)',fontSize:'12px'}}>
              No IPs currently blocked
            </div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Blocked At</th>
                    <th>Reason</th>
                    <th>Firewall Rule</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {blockedIPs.map((b, i) => (
                    <tr key={b.ip || i}>
                      <td style={{fontFamily:'var(--font-mono)',fontWeight:600,color:'var(--danger)'}}>
                        {b.ip}
                      </td>
                      <td style={{color:'var(--text-tertiary)',whiteSpace:'nowrap',fontSize:'12px'}}>
                        {b.blocked_at ? new Date(b.blocked_at).toLocaleString() : '—'}
                      </td>
                      <td style={{fontSize:'12px'}}>{b.reason || '—'}</td>
                      <td style={{fontSize:'11px',fontFamily:'var(--font-mono)',color:'var(--text-tertiary)'}}>
                        {b.rule_name || '—'}
                      </td>
                      <td>
                        <button
                          className="btn btn-default"
                          style={{fontSize:'11px',padding:'3px 10px',color:'var(--success)'}}
                          onClick={() => handleUnblock(b.ip)}
                        >
                          ✓ Unblock
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
