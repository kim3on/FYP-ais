import { useEffect, useCallback, useState } from 'react';
import { useApp } from '../hooks/useApp';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  getAlerts,
  getInterfaces, startCapture, stopCapture, getCaptureStatus,
} from '../api';
import AlertTable from '../components/AlertTable';
import '../components/Layout/Layout.css';
import './Dashboard.css';
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, BarElement, ArcElement, Tooltip, Legend, Filler,
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, Tooltip, Legend, Filler);

const LINE_OPTS = {
  responsive: true, maintainAspectRatio: false, animation: false,
  plugins: { legend: { display: false } },
  scales: {
    x: { grid: { color: '#403d52' }, ticks: { color: '#908caa', font: { family: 'JetBrains Mono', size: 10 } } },
    y: { grid: { color: '#403d52' }, ticks: { color: '#908caa', font: { family: 'JetBrains Mono', size: 10 } } },
  },
};

const DONUT_OPTS = {
  responsive: true, maintainAspectRatio: false, animation: false,
  plugins: { legend: { display: false } },
};

export default function Dashboard() {
  const {
    alerts, setAlerts,
    systemStatus, dashStats,
    refreshStatus, refreshDashStats,
    captureRunning, setCaptureRunning,
    pushAlert,
    // Live session state from context
    CHART_LEN,
    liveNormal, setLiveNormal,
    liveAnomaly, setLiveAnomaly,
    livePktCount, setLivePktCount,
    liveAnomalyCount, setLiveAnomalyCount,
    liveFlowCount, setLiveFlowCount,
    liveRawFlows, setLiveRawFlows,
    liveAlerts,
    clearLiveSession,
  } = useApp();

  // Live capture UI state
  const [interfaces, setInterfaces]   = useState([]);
  const [selectedIf, setSelectedIf]   = useState('');
  const [captureStatus, setCaptureStatus] = useState(null);
  const [captureError, setCaptureError]   = useState('');

  // WebSocket — active whenever captureRunning is true
  useWebSocket('/ws/live', useCallback((msg) => {
    const type = msg?.type;
    const data = msg?.data ?? msg;

    if (type === 'snapshot') {
      if (Array.isArray(data.chart_normal))  setLiveNormal(data.chart_normal.slice(-CHART_LEN));
      if (Array.isArray(data.chart_anomaly)) setLiveAnomaly(data.chart_anomaly.slice(-CHART_LEN));
      if (data.packet_count    != null) setLivePktCount(data.packet_count);
      if (data.anomaly_count   != null) setLiveAnomalyCount(data.anomaly_count);
      if (data.flows_completed != null) setLiveFlowCount(data.flows_completed);
      if (Array.isArray(data.recent_alerts)) {
        data.recent_alerts.forEach(a => pushAlert(a));
      }
      return;
    }

    if (type === 'flow') {
      setLiveNormal(prev  => [...prev.slice(1), data.chart_normal  ?? 0]);
      setLiveAnomaly(prev => [...prev.slice(1), data.chart_anomaly ?? 0]);
      if (data.packet_count    != null) setLivePktCount(data.packet_count);
      if (data.anomaly_count   != null) setLiveAnomalyCount(data.anomaly_count);
      if (data.flows_completed != null) setLiveFlowCount(data.flows_completed);

      const newFlow = {
        timestamp: new Date().toISOString(),
        src_ip: data.src_ip,
        dst_ip: data.dst_ip,
        dst_port: data.dst_port,
        protocol: data.protocol === 6 ? 'TCP' : data.protocol === 17 ? 'UDP' : data.protocol === 1 ? 'ICMP' : String(data.protocol),
        flow_bytes_s: data.flow_bytes_s
      };
      setLiveRawFlows(prev => [newFlow, ...prev].slice(0, 1000));

      const flowAlerts = data.alerts || [];
      if (flowAlerts.length > 0) {
        flowAlerts.forEach(a => pushAlert(a));
      }
      return;
    }

    if (data?.attack_type || data?.severity) {
      pushAlert(data);
    }
  }, [pushAlert, CHART_LEN, setLiveNormal, setLiveAnomaly, setLivePktCount, setLiveAnomalyCount, setLiveFlowCount, setLiveRawFlows]), captureRunning);

  // Load interfaces once
  useEffect(() => {
    let isMounted = true;
    getInterfaces().then(d => {
      if (!isMounted) return;
      const ifaces = d.interfaces || d || [];
      setInterfaces(ifaces);
      if (ifaces.length > 0) setSelectedIf(typeof ifaces[0]==='string' ? ifaces[0] : ifaces[0].name||ifaces[0].id||'');
    }).catch(err => {
      console.error("Failed to fetch interfaces:", err);
    });
    return () => { isMounted = false; };
  }, []);

  // Slow background refresh for stored data (8 s) — also updates capture status
  const refresh = useCallback(async () => {
    refreshStatus();
    refreshDashStats();
    try { 
      const d = await getAlerts(50); 
      setAlerts(d.alerts||d||[]); 
    } catch(err) {
      console.error("Failed to refresh alerts:", err);
    }
    try { 
      const s = await getCaptureStatus(); 
      setCaptureStatus(s); 
      setCaptureRunning(s.active||false); 
    } catch(err) {
      console.error("Failed to refresh capture status:", err);
    }
  }, [refreshStatus, refreshDashStats, setAlerts, setCaptureRunning]);

  useEffect(() => {
    let isMounted = true;
    if (isMounted) {
      setTimeout(() => {
        refresh();
      }, 0);
    }
    const id = setInterval(refresh, 8000);
    return () => {
      isMounted = false;
      clearInterval(id);
    };
  }, [refresh]);

  // Fast poll for packet/flow counters while capturing (2 s fallback if WS drops)
  useEffect(() => {
    if (!captureRunning) return;
    const id = setInterval(async () => {
      try {
        const s = await getCaptureStatus();
        setCaptureStatus(s);
        setLivePktCount(s.packets_captured ?? 0);
      } catch(err) {
        console.error("Failed to poll capture status:", err);
      }
    }, 2000);
    return () => clearInterval(id);
  }, [captureRunning, setLivePktCount]);

  async function handleStartCapture() {
    setCaptureError('');
    try { await startCapture(selectedIf); setCaptureRunning(true); } catch(e) { setCaptureError(e.message); }
  }
  async function handleStopCapture() {
    try { await stopCapture(); setCaptureRunning(false); } catch(e) { setCaptureError(e.message); }
  }

  function downloadRawCapture() {
    if (liveRawFlows.length === 0) return;
    const header = ['Timestamp', 'Source IP', 'Destination IP', 'Port', 'Protocol', 'Bytes/s'];
    const csv = [
      header.join(','),
      ...liveRawFlows.map(f => [f.timestamp, f.src_ip, f.dst_ip, f.dst_port, f.protocol, Math.round(f.flow_bytes_s)].join(','))
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `raw_capture_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Derived stats
  const totalAlerts   = alerts.length;
  const criticalCount = alerts.filter(a=>(a.severity||'').toLowerCase()==='critical').length;
  const zeroDayCount  = alerts.filter(a=>a.is_zero_day||a.attack_type==='Zero-Day Candidate').length;
  const highCount     = alerts.filter(a=>(a.severity||'').toLowerCase()==='high').length;

  // Traffic chart — live ring-buffer while capturing, fallback to dashStats
  const chartLabels = captureRunning
    ? Array.from({length: CHART_LEN}, (_, i) => i % 10 === 0 ? `-${CHART_LEN - i}s` : '')
    : (dashStats?.chart_labels || Array.from({length:20},(_,i)=>`T-${20-i}`));
  const trafficData = {
    labels: chartLabels,
    datasets: [
      { label:'Normal',  data: captureRunning ? liveNormal  : (dashStats?.chart_normal  || new Array(20).fill(0)), borderColor:'#9ccfd8', backgroundColor:'rgba(156,207,216,0.08)', fill:true, tension:0.35, pointRadius:0 },
      { label:'Anomaly', data: captureRunning ? liveAnomaly : (dashStats?.chart_anomaly || new Array(20).fill(0)), borderColor:'#eb6f92', backgroundColor:'rgba(235,111,146,0.08)', fill:true, tension:0.35, pointRadius:0 },
    ],
  };

  // Severity doughnut
  const sevCounts = { critical:0, high:0, medium:0, low:0 };
  alerts.forEach(a => { const s=(a.severity||'low').toLowerCase(); if(sevCounts[s]!==undefined) sevCounts[s]++; });
  const doughnutData = {
    labels:['Critical','High','Medium','Low'],
    datasets:[{ data:Object.values(sevCounts), backgroundColor:['#eb6f92','#f6c177','#31748f','#9ccfd8'], borderColor:'#26233a', borderWidth:2 }],
  };

  // Which alerts to show in table — live if capturing, else recent stored
  const tableAlerts = captureRunning ? liveAlerts : alerts.slice(0, 15);
  const tableTitle  = captureRunning
    ? `Live Alerts — ${liveAlerts.length} captured this session`
    : `Recent Alerts — latest ${Math.min(alerts.length,15)} of ${totalAlerts}`;

  // Packet/flow counts — live WS values while capturing, else API counters
  const displayPkts  = captureRunning ? livePktCount     : (captureStatus?.packets_captured ?? null);
  const displayFlows = captureRunning ? liveFlowCount    : (captureStatus?.flows_completed  ?? null);

  return (
    <div className="page">
      <div className="page-header flex justify-between items-center">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">System overview · live capture · threat monitoring</p>
        </div>
      </div>

      {/* ── Stat Cards ─────────────────────────────────────────── */}
      <div className="stat-grid" style={{marginBottom:'16px'}}>
        <div className="stat-card">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value">{totalAlerts}</div>
        </div>
        <div className="stat-card" style={{borderColor:criticalCount>0?'var(--danger-border)':'var(--border)'}}>
          <div className="stat-label" style={{color:'var(--danger)'}}>Critical</div>
          <div className="stat-value" style={{color:criticalCount>0?'var(--danger)':'var(--text-primary)'}}>{criticalCount}</div>
        </div>
        <div className="stat-card" style={{borderColor:highCount>0?'var(--warning-border)':'var(--border)'}}>
          <div className="stat-label" style={{color:'var(--warning)'}}>High</div>
          <div className="stat-value" style={{color:highCount>0?'var(--warning)':'var(--text-primary)'}}>{highCount}</div>
        </div>
        <div className="stat-card" style={{borderColor:zeroDayCount>0?'var(--iris-border)':'var(--border)'}}>
          <div className="stat-label" style={{color:'var(--iris)'}}>Zero-Day</div>
          <div className="stat-value" style={{color:zeroDayCount>0?'var(--iris)':'var(--text-primary)'}}>{zeroDayCount}</div>
        </div>
        <div className="stat-card" style={{borderColor: captureRunning ? 'var(--accent-border, var(--border))' : 'var(--border)'}}>
          <div className="stat-label">Packets (session)</div>
          <div className="stat-value" style={{fontSize:'20px',color: captureRunning ? 'var(--accent)' : 'var(--text-primary)'}}>
            {displayPkts != null ? displayPkts.toLocaleString() : '—'}
          </div>
        </div>
        <div className="stat-card" style={{borderColor: captureRunning && liveAnomalyCount > 0 ? 'var(--danger-border)' : 'var(--border)'}}>
          <div className="stat-label">Anomalies (session)</div>
          <div className="stat-value" style={{fontSize:'20px',color: captureRunning && liveAnomalyCount > 0 ? 'var(--danger)' : 'var(--text-primary)'}}>
            {captureRunning ? liveAnomalyCount.toLocaleString() : '—'}
          </div>
        </div>
        <div className="stat-card" style={{borderColor: captureRunning ? 'var(--success-border, var(--border))' : 'var(--border)'}}>
          <div className="stat-label">Flows (session)</div>
          <div className="stat-value" style={{fontSize:'20px',color: captureRunning ? 'var(--success)' : 'var(--text-primary)'}}>
            {captureRunning ? displayFlows.toLocaleString() : '—'}
          </div>
        </div>
      </div>

      {/* ── Charts Row ─────────────────────────────────────────── */}
      <div className="two-col" style={{marginBottom:'16px'}}>
        <div className="card">
          <div className="section-label">Traffic — Normal vs Anomaly</div>
          <div className="dash-legend">
            <div className="dash-legend-item"><span className="dash-legend-dot" style={{background:'#9ccfd8'}}/>Normal</div>
            <div className="dash-legend-item"><span className="dash-legend-dot" style={{background:'#eb6f92'}}/>Anomaly</div>
          </div>
          <div style={{height:'150px',marginTop:'10px'}}>
            <Line data={trafficData} options={LINE_OPTS} />
          </div>
        </div>
        <div className="card">
          <div className="section-label">Severity Distribution</div>
          <div style={{display:'flex',gap:'16px',alignItems:'center',marginTop:'10px'}}>
            <div style={{height:'130px',width:'130px',flexShrink:0}}>
              <Doughnut data={doughnutData} options={DONUT_OPTS} />
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:'8px',flex:1}}>
              {[['Critical','var(--danger)',sevCounts.critical],['High','var(--warning)',sevCounts.high],['Medium','var(--accent)',sevCounts.medium],['Low','var(--success)',sevCounts.low]].map(([label,color,count])=>(
                <div key={label} style={{display:'flex',justifyContent:'space-between',fontSize:'11px',fontFamily:'var(--font-mono)'}}>
                  <span style={{color:'var(--text-tertiary)'}}>{label}</span>
                  <span style={{color,fontWeight:600}}>{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Live Capture Controls ───────────────────────────────── */}
      <div className="card" style={{marginBottom:'16px'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexWrap:'wrap',gap:'12px'}}>
          <div className="section-label" style={{margin:0}}>Live Packet Capture</div>
          <div style={{display:'flex',alignItems:'center',gap:'10px',flexWrap:'wrap'}}>
            <select
              value={selectedIf}
              onChange={e=>setSelectedIf(e.target.value)}
              disabled={captureRunning}
              style={{width:'auto',minWidth:'200px',padding:'6px 10px'}}
            >
              {interfaces.length===0
                ? <option>No interfaces found</option>
                : interfaces.map(i=>{
                    const name=typeof i==='string'?i:(i.name||i.id||'');
                    const desc=typeof i==='string'?'':(i.description||i.desc||'');
                    return <option key={name} value={name}>{name}{desc?` — ${desc}`:''}</option>;
                  })
              }
            </select>
            <button className="btn btn-primary" onClick={handleStartCapture} disabled={captureRunning||!selectedIf}>
              ▶ Start
            </button>
            <button className="btn btn-danger" onClick={handleStopCapture} disabled={!captureRunning}>
              ■ Stop
            </button>
            <div style={{display:'flex',alignItems:'center',gap:'6px',fontFamily:'var(--font-mono)',fontSize:'11px',color:'var(--text-secondary)'}}>
              <span className={`status-dot ${captureRunning?'online':'offline'}`}/>
              {captureRunning ? 'Capturing…' : 'Idle'}
            </div>
          </div>
        </div>
        {captureError && (
          <div style={{marginTop:'10px',background:'var(--danger-subtle)',border:'1px solid var(--danger-border)',color:'var(--danger)',padding:'8px 12px',borderRadius:'var(--radius)',fontSize:'11px',fontFamily:'var(--font-mono)'}}>
            ⚠ {captureError}
          </div>
        )}
      </div>

      {/* ── Alerts Table ───────────────────────────────────────── */}
      <div className="card">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'12px'}}>
          <div className="section-label" style={{margin:0}}>{tableTitle}</div>
          {liveAlerts.length>0 && (
            <button className="btn btn-ghost" style={{fontSize:'11px',padding:'3px 8px'}} onClick={clearLiveSession}>Clear</button>
          )}
        </div>
        <AlertTable alerts={tableAlerts} />
      </div>

      {/* ── Raw Packet Capture ───────────────────────────────────────── */}
      <div className="card" style={{marginTop: '16px'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'12px'}}>
          <div className="section-label" style={{margin:0}}>Raw Flow Capture — {liveRawFlows.length} flows</div>
          <div style={{display:'flex', gap:'8px'}}>
            <button className="btn btn-ghost" style={{fontSize:'11px',padding:'4px 10px'}} onClick={clearLiveSession} disabled={liveRawFlows.length === 0}>
              Clear
            </button>
            <button className="btn btn-primary" style={{fontSize:'11px',padding:'4px 10px'}} onClick={downloadRawCapture} disabled={liveRawFlows.length === 0}>
              ↓ Export CSV
            </button>
          </div>
        </div>
        <div className="table-responsive" style={{maxHeight: '300px', overflowY: 'auto'}}>
          <table className="table" style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse'}}>
            <thead style={{position: 'sticky', top: 0, background: 'var(--bg-overlay)'}}>
              <tr>
                <th style={{padding: '8px', borderBottom: '1px solid var(--border)'}}>Timestamp</th>
                <th style={{padding: '8px', borderBottom: '1px solid var(--border)'}}>Source IP</th>
                <th style={{padding: '8px', borderBottom: '1px solid var(--border)'}}>Dest IP</th>
                <th style={{padding: '8px', borderBottom: '1px solid var(--border)'}}>Port</th>
                <th style={{padding: '8px', borderBottom: '1px solid var(--border)'}}>Protocol</th>
              </tr>
            </thead>
            <tbody>
              {liveRawFlows.length === 0 ? (
                <tr><td colSpan="5" style={{padding: '16px', textAlign: 'center', color: 'var(--text-tertiary)'}}>No flows captured yet...</td></tr>
              ) : (
                liveRawFlows.slice(0, 100).map((f, i) => (
                  <tr key={i} style={{borderBottom: '1px solid var(--border-subtle)'}}>
                    <td style={{padding: '6px 8px', fontSize: '12px'}}>{new Date(f.timestamp).toLocaleTimeString()}</td>
                    <td style={{padding: '6px 8px', fontSize: '12px', fontFamily: 'var(--font-mono)'}}>{f.src_ip}</td>
                    <td style={{padding: '6px 8px', fontSize: '12px', fontFamily: 'var(--font-mono)'}}>{f.dst_ip}</td>
                    <td style={{padding: '6px 8px', fontSize: '12px', fontFamily: 'var(--font-mono)'}}>{f.dst_port}</td>
                    <td style={{padding: '6px 8px', fontSize: '12px'}}>{f.protocol}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
