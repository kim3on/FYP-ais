import { useState, useCallback, useEffect } from 'react';
import { getAlerts, getSystemStatus, getDashboardStats } from '../api';
import { AppContext } from './AppContext.js';

export function AppProvider({ children }) {
  const [alerts, setAlerts]           = useState([]);
  const [systemStatus, setSystemStatus] = useState(null);
  const [dashStats, setDashStats]     = useState(null);
  const [activeModel, setActiveModel] = useState('nsa');
  const [captureRunning, setCaptureRunning] = useState(false);
  const [theme, setTheme] = useState('dark');

  // Sync theme to DOM
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  // Train/Detect persistence
  const [trainFile, setTrainFile]       = useState(null);
  const [nDetectors, setND]             = useState(500);
  const [rRadius, setR]                 = useState(0.30);
  const [rsRadius, setRS]               = useState(0.03);
  const [trainLogs, setTrainLogs]       = useState([]);
  const [trainResult, setTrainResult]   = useState(null);

  const [detectFile, setDetectFile]     = useState(null);
  const [detectLimit, setDetectLimit]   = useState(1000);
  const [detectLogs, setDetectLogs]     = useState([]);
  const [detectResult, setDetectResult] = useState(null);

  // Live session state (persists across tab changes)
  const CHART_LEN = 60;
  const [liveNormal,       setLiveNormal]       = useState(() => new Array(CHART_LEN).fill(0));
  const [liveAnomaly,      setLiveAnomaly]      = useState(() => new Array(CHART_LEN).fill(0));
  const [livePktCount,     setLivePktCount]     = useState(0);
  const [liveAnomalyCount, setLiveAnomalyCount] = useState(0);
  const [liveFlowCount,    setLiveFlowCount]    = useState(0);
  const [liveRawFlows,     setLiveRawFlows]     = useState([]);
  const [liveAlerts,       setLiveAlerts]       = useState([]);

  // Clear session data manually
  const clearLiveSession = useCallback(() => {
    setLiveNormal(new Array(CHART_LEN).fill(0));
    setLiveAnomaly(new Array(CHART_LEN).fill(0));
    setLivePktCount(0);
    setLiveAnomalyCount(0);
    setLiveFlowCount(0);
    setLiveRawFlows([]);
    setLiveAlerts([]);
  }, [CHART_LEN]);

  // Push a live alert (called from WebSocket handler)
  const pushAlert = useCallback((alert) => {
    setAlerts(prev => [alert, ...prev].slice(0, 500)); // Historical
    setLiveAlerts(prev => [alert, ...prev].slice(0, 200)); // Session
  }, []);

  // Refresh system status
  const refreshStatus = useCallback(async () => {
    try {
      const status = await getSystemStatus();
      setSystemStatus(status);
      if (status.active_model) setActiveModel(status.active_model);
    } catch (err) {
      console.error("Failed to refresh status:", err);
    }
  }, []);

  // Refresh dashboard stats
  const refreshDashStats = useCallback(async () => {
    try {
      const stats = await getDashboardStats();
      setDashStats(stats);
    } catch (err) {
      console.error("Failed to refresh dash stats:", err);
    }
  }, []);

  // Refresh alerts from backend
  const refreshAlerts = useCallback(async () => {
    try {
      const data = await getAlerts(200);
      setAlerts(data.alerts || data || []);
    } catch (err) {
      console.error("Failed to refresh alerts:", err);
    }
  }, []);

  return (
    <AppContext.Provider value={{
      alerts, setAlerts, pushAlert, refreshAlerts,
      systemStatus, refreshStatus,
      dashStats, refreshDashStats,
      activeModel, setActiveModel,
      captureRunning, setCaptureRunning,
      theme, setTheme,
      trainFile, setTrainFile, nDetectors, setND, rRadius, setR, rsRadius, setRS,
      trainLogs, setTrainLogs, trainResult, setTrainResult,
      detectFile, setDetectFile, detectLimit, setDetectLimit,
      detectLogs, setDetectLogs, detectResult, setDetectResult,
      // Live session state
      CHART_LEN,
      liveNormal, setLiveNormal,
      liveAnomaly, setLiveAnomaly,
      livePktCount, setLivePktCount,
      liveAnomalyCount, setLiveAnomalyCount,
      liveFlowCount, setLiveFlowCount,
      liveRawFlows, setLiveRawFlows,
      liveAlerts, setLiveAlerts,
      clearLiveSession,
    }}>
      {children}
    </AppContext.Provider>
  );
}
