import { useEffect, useCallback, useState } from 'react';
import { useApp } from '../hooks/useApp';
import { useAuth } from '../hooks/useAuth';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  getAlerts,
  getInterfaces, startCapture, stopCapture, getCaptureStatus,
  submitFlowFile,
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
  interaction: { intersect: false, mode: 'index' },
  plugins: {
    legend: { display: false },
    tooltip: {
      callbacks: {
        label: context => {
          return `${context.dataset.label}: ${context.parsed.y} flows`;
        },
      },
    },
  },
  scales: {
    x: {
      title: { display: true, text: 'Time', color: '#908caa', font: { family: 'JetBrains Mono', size: 10 } },
      grid: { display: false, drawBorder: false },
      ticks: { color: '#908caa', font: { family: 'JetBrains Mono', size: 10 }, maxRotation: 0 },
      border: { display: false },
    },
    y: {
      title: { display: true, text: 'Flows', color: '#908caa', font: { family: 'JetBrains Mono', size: 10 } },
      grid: { display: false, drawBorder: false },
      ticks: { color: '#908caa', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 },
      border: { display: false },
      beginAtZero: true,
    },
  },
};

const TRAFFIC_NORMAL_COLOR = '#2f80ff';
const TRAFFIC_ANOMALY_COLOR = '#ff2b2b';

const DONUT_OPTS = {
  responsive: true, maintainAspectRatio: false, animation: false,
  plugins: { legend: { display: false } },
};

function csvEscape(value) {
  if (value == null) return '';
  const text = String(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function timestampForFilename(date = new Date()) {
  const pad = value => String(value).padStart(2, '0');
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
    '_',
    pad(date.getHours()),
    pad(date.getMinutes()),
    pad(date.getSeconds()),
  ].join('');
}

function featureValueForExport(value) {
  if (value == null) return '';
  if (typeof value === 'number') return Number.isFinite(value) ? value : '';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'object') return JSON.stringify(value);
  return value;
}

function exportColumnKeys(flows) {
  const keys = [];
  const seen = new Set();
  flows.forEach(flow => {
    Object.keys(flow.flow_features || {}).forEach(key => {
      if (!seen.has(key)) {
        seen.add(key);
        keys.push(key);
      }
    });
  });
  return keys;
}

// ── SVG icons for metric cards ──────────────────────────────────────────────
const IcoList    = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>;
const IcoTrend   = () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/></svg>;
const IcoWarn    = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
const IcoShield  = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const IcoCheck   = () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="9 12 11 14 15 10"/></svg>;
const IcoBio     = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="11.5" r="2.5"/><path d="M12 2a4.5 4.5 0 0 1 4.5 4.5c0 1.33-.58 2.52-1.5 3.35"/><path d="M12 2a4.5 4.5 0 0 0-4.5 4.5c0 1.33.58 2.52 1.5 3.35"/><path d="M8.5 14.5A4.5 4.5 0 0 0 12 21a4.5 4.5 0 0 0 3.5-6.5"/><path d="M5.5 13A4.5 4.5 0 0 0 9 21"/><path d="M18.5 13A4.5 4.5 0 0 1 15 21"/></svg>;
const IcoZap     = () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>;

// ── Severity badge colours (matching reference image) ────────────────────────
const SEVERITY_BADGE = {
  LOW:      { label: 'LOW',      bg: '#3b82f6', color: '#fff' },
  MEDIUM:   { label: 'MEDIUM',   bg: '#eab308', color: '#1a1a1a' },
  HIGH:     { label: 'HIGH',     bg: '#f97316', color: '#fff' },
  CRITICAL: { label: 'CRITICAL', bg: '#ef4444', color: '#fff' },
};

function getSeverityLevel(alerts) {
  const hasCritical = alerts.some(a => (a.severity||'').toLowerCase() === 'critical');
  if (hasCritical) return 'CRITICAL';
  const hasHigh = alerts.some(a => (a.severity||'').toLowerCase() === 'high');
  if (hasHigh) return 'HIGH';
  const hasMedium = alerts.some(a => (a.severity||'').toLowerCase() === 'medium');
  if (hasMedium) return 'MEDIUM';
  return 'LOW';
}

// ── Metric Card ───────────────────────────────────────────────────────────────
function StatCard({ icon, iconColor, topRight, label, value, sub, subColor }) {
  return (
    <div style={{
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '18px 20px',
      display: 'flex', flexDirection: 'column', gap: '10px',
    }}>
      {/* Top row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <span style={{ color: iconColor || 'var(--accent)' }}>{icon}</span>
        {topRight}
      </div>
      {/* Label + Value */}
      <div>
        <div style={{ fontSize: '11px', fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-tertiary)', marginBottom: '4px' }}>
          {label}
        </div>
        <div style={{ fontSize: '28px', fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1 }}>
          {value}
        </div>
      </div>
      {/* Subtitle */}
      {sub && (
        <div style={{ fontSize: '11px', fontFamily: "'JetBrains Mono', monospace", color: subColor || 'var(--text-tertiary)' }}>
          {sub}
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const {
    alerts, setAlerts,
    systemStatus,
    dashStats,
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
  const { currentUser, refreshCurrentUser } = useAuth();

  // Live capture UI state
  const [interfaces, setInterfaces]   = useState([]);
  const [selectedIf, setSelectedIf]   = useState('');
  const [captureStatus, setCaptureStatus] = useState(null);
  const [captureError, setCaptureError]   = useState('');
  const [flowFile, setFlowFile] = useState(null);
  const [flowSubmitting, setFlowSubmitting] = useState(false);
  const [flowSubmitMessage, setFlowSubmitMessage] = useState('');
  const [flowSubmitError, setFlowSubmitError] = useState('');
  const role = (currentUser?.role || '').toLowerCase();
  const canControlCapture = role.includes('administrator') || role === 'admin';

  useEffect(() => {
    if (!currentUser?.role) {
      refreshCurrentUser().catch(err => {
        console.error("Failed to refresh current user:", err);
      });
    }
  }, [currentUser?.role, refreshCurrentUser]);

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
        flow_bytes_s: data.flow_bytes_s,
        flow_features: data.flow_features || {},
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
      setCaptureError(s.sniffer_error || '');
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
        setCaptureRunning(s.active || false);
        setLivePktCount(s.packets_captured ?? 0);
        setLiveFlowCount(s.flows_completed ?? 0);
        setCaptureError(s.sniffer_error || '');
      } catch(err) {
        console.error("Failed to poll capture status:", err);
      }
    }, 2000);
    return () => clearInterval(id);
  }, [captureRunning, setCaptureRunning, setLiveFlowCount, setLivePktCount]);

  async function handleStartCapture() {
    if (!canControlCapture) {
      setCaptureError('Administrator role required to start live capture.');
      return;
    }
    setCaptureError('');
    try {
      await startCapture(selectedIf);
      const s = await getCaptureStatus();
      setCaptureStatus(s);
      setCaptureRunning(s.active || false);
      setCaptureError(s.sniffer_error || '');
    } catch(e) { setCaptureError(e.message); }
  }
  async function handleStopCapture() {
    if (!canControlCapture) {
      setCaptureError('Administrator role required to stop live capture.');
      return;
    }
    try {
      await stopCapture();
      const s = await getCaptureStatus();
      setCaptureStatus(s);
      setCaptureRunning(s.active || false);
      setCaptureError(s.remote_sensor_stop_requested ? 'Remote sensor stop requested. Waiting for laptop agent to exit.' : '');
    } catch(e) { setCaptureError(e.message); }
  }

  async function handleSubmitFlow() {
    if (!flowFile) return;
    setFlowSubmitting(true);
    setFlowSubmitMessage('');
    setFlowSubmitError('');
    try {
      const response = await submitFlowFile(flowFile, 1000);
      const result = response.result || {};
      const submittedAlerts = result.alerts || [];
      submittedAlerts.forEach(a => pushAlert(a));
      if (Array.isArray(response.flow_preview) && response.flow_preview.length > 0) {
        setLiveRawFlows(prev => [...response.flow_preview, ...prev].slice(0, 1000));
      }
      await refreshDashStats();
      setFlowSubmitMessage(
        response.converted
          ? `Converted ${response.converted_flow_count || 0} flows · ${result.anomalies_found || 0} anomalies`
          : `Analysed ${result.total_checked || 0} flows · ${result.anomalies_found || 0} anomalies`
      );
    } catch (err) {
      setFlowSubmitError(err.message || 'Failed to submit flow file');
    } finally {
      setFlowSubmitting(false);
    }
  }

  function downloadRawCapture() {
    if (liveRawFlows.length === 0) return;
    const featureKeys = exportColumnKeys(liveRawFlows);
    const compactHeader = ['Timestamp', 'Source IP', 'Destination IP', 'Port', 'Protocol', 'Bytes/s'];
    const header = [...compactHeader, ...featureKeys];
    const csv = [
      header.map(csvEscape).join(','),
      ...liveRawFlows.map(f => [
        f.timestamp,
        f.src_ip,
        f.dst_ip,
        f.dst_port,
        f.protocol,
        Number.isFinite(Number(f.flow_bytes_s)) ? Math.round(Number(f.flow_bytes_s)) : '',
        ...featureKeys.map(key => featureValueForExport(f.flow_features?.[key])),
      ].map(csvEscape).join(','))
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `live_cicflow_features_${timestampForFilename()}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Derived stats
  const totalAlerts   = alerts.length;
  const zeroDayCount  = alerts.filter(a=>a.is_zero_day||a.attack_type==='Zero-Day Candidate').length;

  const safeLiveNormal = Array.isArray(liveNormal) ? liveNormal : [];
  const safeLiveAnomaly = Array.isArray(liveAnomaly) ? liveAnomaly : [];
  const hasLiveSession =
    captureRunning ||
    livePktCount > 0 ||
    liveFlowCount > 0 ||
    safeLiveNormal.some(v => (v ?? 0) > 0) ||
    safeLiveAnomaly.some(v => (v ?? 0) > 0);
  const normalSource = hasLiveSession ? safeLiveNormal : dashStats?.chart_normal;
  const anomalySource = hasLiveSession ? safeLiveAnomaly : dashStats?.chart_anomaly;
  const normalSeries  = Array.isArray(normalSource) ? normalSource : new Array(20).fill(0);
  const anomalySeries = Array.isArray(anomalySource) ? anomalySource : new Array(20).fill(0);
  const seriesLen = Math.max(normalSeries.length, anomalySeries.length) || 20;

  // Traffic chart — live ring-buffer while capturing, fallback to dashStats
  const chartLabels = Array.from({ length: seriesLen }, (_, i) => {
    const secondsAgo = seriesLen - i - 1;
    if (secondsAgo === 0) return 'Now';
    return secondsAgo % 10 === 0 ? `${secondsAgo}s ago` : '';
  });
  const combinedTraffic = Array.from({ length: seriesLen }, (_, i) => {
    return (normalSeries[i] ?? 0) + (anomalySeries[i] ?? 0);
  });
  const anomalyMask = Array.from({ length: seriesLen }, (_, i) => (anomalySeries[i] ?? 0) > 0);
  const trafficData = {
    labels: chartLabels,
    datasets: [
      {
        label: 'Network Flows',
        data: combinedTraffic,
        borderColor: TRAFFIC_NORMAL_COLOR,
        backgroundColor: 'transparent',
        fill: false,
        tension: 0.35,
        pointRadius: context => anomalyMask[context.dataIndex] ? 3 : 0,
        pointHoverRadius: context => anomalyMask[context.dataIndex] ? 4 : 0,
        pointBackgroundColor: context => anomalyMask[context.dataIndex] ? TRAFFIC_ANOMALY_COLOR : TRAFFIC_NORMAL_COLOR,
        pointBorderColor: context => anomalyMask[context.dataIndex] ? TRAFFIC_ANOMALY_COLOR : TRAFFIC_NORMAL_COLOR,
        borderWidth: 2,
        segment: {
          borderColor: context => {
            const fromAnomaly = anomalyMask[context.p0DataIndex];
            const toAnomaly = anomalyMask[context.p1DataIndex];
            return fromAnomaly || toAnomaly ? TRAFFIC_ANOMALY_COLOR : TRAFFIC_NORMAL_COLOR;
          },
        },
      },
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

  // Flow count mirrors completed CICFlowMeter rows; packet count is a lower-level sniffer metric.
  const displayFlows = captureRunning
    ? (liveFlowCount || liveRawFlows.length)
    : (captureStatus?.flows_completed || liveFlowCount || liveRawFlows.length || 0);
  const captureStatusLabel = captureStatus?.remote_sensor_active
    ? 'Remote sensor'
    : (captureRunning ? 'Capturing…' : 'Idle');

  // Count anomalies in the last 5 minutes from the relevant alert source
  const alertsSource = captureRunning ? liveAlerts : alerts;
  const recentAnomalyCount = alertsSource.filter(a => {
    const ts = a.timestamp ? new Date(a.timestamp).getTime() : 0;
    const now = new Date().getTime(); // Still impure, but let's see if this format is preferred or if we should use useMemo
    return ts >= (now - 5 * 60 * 1000);
  }).length;

  const sevLevel = getSeverityLevel(alerts);
  const badge = SEVERITY_BADGE[sevLevel];
  const activeModelStatLabel = dashStats?.active_model_stat_label || systemStatus?.active_model_stat_label || 'Active Antibodies';
  const activeModelStatValue = dashStats?.active_model_stat_value ?? systemStatus?.active_model_stat_value ?? dashStats?.active_antibodies ?? 0;
  const activeModelStatSubtitle = dashStats?.active_model_stat_subtitle || systemStatus?.active_model_stat_subtitle || 'Generated via Negative Selection';

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-subtitle">System overview · live capture · threat monitoring</p>
      </div>

      {/* ── Metric Cards ─────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '16px' }}>
        <StatCard
          icon={<IcoList />} iconColor="#3b82f6"
          topRight={<span style={{ color: 'var(--success)' }}><IcoTrend /></span>}
          label="Completed Flows"
          value={displayFlows.toLocaleString()}
          sub={livePktCount ? `${livePktCount.toLocaleString()} packets observed` : 'From live capture session'}
          subColor="var(--success)"
        />
        <StatCard
          icon={<IcoWarn />} iconColor="var(--danger)"
          topRight={(
            <span style={{
              background: badge.bg, color: badge.color,
              fontSize: '9px', fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 800, letterSpacing: '0.07em', textTransform: 'uppercase',
              padding: '3px 8px', borderRadius: '4px',
            }}>{badge.label}</span>
          )}
          label="Anomalies Detected"
          value={captureRunning ? liveAnomalyCount.toLocaleString() : totalAlerts.toLocaleString()}
          sub={`${recentAnomalyCount} in last 5 minutes`}
          subColor="var(--success)"
        />
        <StatCard
          icon={<IcoShield />} iconColor="#3b82f6"
          topRight={<span style={{ color: 'var(--success)' }}><IcoCheck /></span>}
          label={activeModelStatLabel}
          value={Number(activeModelStatValue || 0).toLocaleString()}
          sub={activeModelStatSubtitle}
          subColor="var(--accent)"
        />
        <StatCard 
          icon={<IcoBio />} iconColor="var(--iris, #9ccfd8)"
          topRight={<span style={{ color: 'var(--iris, #9ccfd8)' }}><IcoZap /></span>}
          label="Zero-Day Candidates"
          value={zeroDayCount.toLocaleString()}
          sub="Threats with no detector match"
          subColor="var(--iris, #9ccfd8)"
        />
      </div>


      {/* ── Charts Row ─────────────────────────────────────────── */}
      <div className="two-col" style={{marginBottom:'16px'}}>
        <div className="card">
          <div className="section-label">Live Network Traffic</div>
          <div className="dash-legend">
            <div className="dash-legend-item"><span className="dash-legend-dot" style={{background:TRAFFIC_NORMAL_COLOR}}/>Normal Flows</div>
            <div className="dash-legend-item"><span className="dash-legend-dot" style={{background:TRAFFIC_ANOMALY_COLOR}}/>Anomalies</div>
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
          <div style={{display:'flex',alignItems:'center',gap:'8px'}}>
            <div className="section-label" style={{margin:0}}>Live Capture</div>
            {!canControlCapture && <span className="dashboard-admin-badge">Admin only</span>}
          </div>
          <div className="capture-control-grid">
            <select
              value={selectedIf}
              onChange={e=>setSelectedIf(e.target.value)}
              disabled={captureRunning || !canControlCapture}
              style={{width:'100%',padding:'6px 10px'}}
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
            <div className="capture-action-pair">
              <button className="btn btn-primary" onClick={handleStartCapture} disabled={captureRunning||!selectedIf||!canControlCapture} style={{width:'100%',justifyContent:'center'}}>
                {canControlCapture ? '▶ Start' : 'Admin Only'}
              </button>
              <button className="btn btn-danger" onClick={handleStopCapture} disabled={!captureRunning||!canControlCapture} style={{width:'100%',justifyContent:'center'}}>
                ■ Stop
              </button>
            </div>
            <div className="capture-control-status">
              <span className={`status-dot ${captureRunning?'online':'offline'}`}/>
              {captureStatusLabel}
            </div>
          </div>
        </div>
        {captureError && (
          <div style={{marginTop:'10px',background:'var(--danger-subtle)',border:'1px solid var(--danger-border)',color:'var(--danger)',padding:'8px 12px',borderRadius:'var(--radius)',fontSize:'11px',fontFamily:'var(--font-mono)'}}>
            ⚠ {captureError}
          </div>
        )}
      </div>

      {/* ── Manual Flow Submission ─────────────────────────────── */}
      <div className="card" style={{marginBottom:'16px'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexWrap:'wrap',gap:'12px'}}>
          <div>
            <div className="section-label" style={{marginBottom:'4px'}}>Submit Network Flow</div>
            <div style={{fontFamily:'var(--font-mono)',fontSize:'10px',color:'var(--text-tertiary)'}}>
              Upload CIC flow CSV/Parquet or PCAP/PCAPNG. Packet captures are converted to flow features before analysis.
            </div>
          </div>
          <div className="capture-control-grid">
            <input
              id="manual-flow-file"
              type="file"
              accept=".csv,.parquet,.pq,.pcap,.pcapng"
              style={{display:'none'}}
              onChange={e => {
                setFlowFile(e.target.files?.[0] || null);
                setFlowSubmitMessage('');
                setFlowSubmitError('');
              }}
            />
            <button
              className="btn btn-default"
              type="button"
              onClick={() => document.getElementById('manual-flow-file')?.click()}
              disabled={flowSubmitting}
              style={{width:'100%',justifyContent:'center'}}
            >
              Choose File
            </button>
            <button
              className="btn btn-primary"
              type="button"
              onClick={handleSubmitFlow}
              disabled={!flowFile || flowSubmitting}
              style={{width:'100%',justifyContent:'center'}}
            >
              {flowSubmitting ? <><span className="spinner" /> Analysing…</> : 'Submit'}
            </button>
            <div className="capture-control-status">
              {flowFile ? flowFile.name : 'No file selected'}
            </div>
          </div>
        </div>
        {(flowSubmitMessage || flowSubmitError) && (
          <div style={{
            marginTop:'10px',
            background: flowSubmitError ? 'var(--danger-subtle)' : 'var(--success-subtle)',
            border: `1px solid ${flowSubmitError ? 'var(--danger-border)' : 'var(--success-border)'}`,
            color: flowSubmitError ? 'var(--danger)' : 'var(--success)',
            padding:'8px 12px',
            borderRadius:'var(--radius)',
            fontSize:'11px',
            fontFamily:'var(--font-mono)'
          }}>
            {flowSubmitError ? `⚠ ${flowSubmitError}` : `✓ ${flowSubmitMessage}`}
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
              ↓ Export Full Features
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
