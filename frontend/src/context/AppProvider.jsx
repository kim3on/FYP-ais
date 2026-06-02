import { useState, useCallback, useEffect } from 'react';
import { getAlerts, getSystemStatus, getDashboardStats } from '../api';
import { AppContext } from './AppContext.js';

function loadStoredJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function storeJson(key, value) {
  try {
    if (value == null) {
      localStorage.removeItem(key);
    } else {
      localStorage.setItem(key, JSON.stringify(value));
    }
  } catch {
    // Ignore storage quota/private-mode failures; runtime state still works.
  }
}

function loadInitialDevMode() {
  const stored = Boolean(loadStoredJson('ais_dev_mode', false));
  try {
    const devParam = new URLSearchParams(window.location.search).get('dev');
    if (devParam === '1') return true;
    if (devParam === '0') return false;
  } catch {
    // Ignore URL parsing failures and keep the stored mode.
  }
  return stored;
}

function alertKey(alert) {
  return alert?.alert_id || alert?.id || null;
}

function prependUniqueAlert(prev, alert, limit) {
  if (!alert) return prev;
  const normalized = alert.received_at ? alert : { ...alert, received_at: new Date().toISOString() };
  const key = alertKey(normalized);
  if (key && prev.some(existing => alertKey(existing) === key)) {
    return prev.map(existing => (
      alertKey(existing) === key && !existing.received_at
        ? { ...existing, received_at: normalized.received_at }
        : existing
    ));
  }
  return [normalized, ...prev].slice(0, limit);
}

export function AppProvider({ children }) {
  const [alerts, setAlerts]           = useState([]);
  const [systemStatus, setSystemStatus] = useState(null);
  const [dashStats, setDashStats]     = useState(null);
  const [activeModel, setActiveModel] = useState('nsa');
  const [datasetType, setDatasetType] = useState('cicids2017');
  const [captureRunning, setCaptureRunning] = useState(false);
  const [theme, setTheme] = useState('light');

  // Sync theme to DOM
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  // Train/Detect persistence
  const [trainFile, setTrainFile]       = useState(null);
  const [nDetectors, setND]             = useState(3000);
  const [benignRowLimit, setBenignRowLimit] = useState(20000);
  const [trainTargetFpr, setTrainTargetFpr] = useState(() => loadStoredJson('ais_train_target_fpr', 0.10));
  const [devMode, setDevMode] = useState(() => loadInitialDevMode());
  const [trainRepresentation, setTrainRepresentation] = useState(() => {
    return loadInitialDevMode() ? loadStoredJson('ais_train_representation', 'pca') : 'pca';
  });
  const [daeLatentDim, setDaeLatentDim] = useState(() => loadStoredJson('ais_dae_latent_dim', 8));
  const [daeNoiseStd, setDaeNoiseStd] = useState(() => loadStoredJson('ais_dae_noise_std', 0.05));
  const [isoContamination, setIsoContamination] = useState(() => loadStoredJson('ais_iso_contamination', 0.05));
  const [isoEstimators, setIsoEstimators] = useState(() => loadStoredJson('ais_iso_estimators', 100));
  const [trainLogs, setTrainLogs]       = useState([]);
  const [trainResult, setTrainResult]   = useState(null);

  const [detectFile, setDetectFile]     = useState(null);
  const [detectLimit, setDetectLimit]   = useState(() => loadStoredJson('ais_detect_limit', 1000));
  const [detectOffset, setDetectOffset] = useState(() => loadStoredJson('ais_detect_offset', 0));
  const [detectLogs, setDetectLogs]     = useState(() => loadStoredJson('ais_detect_logs', []));
  const [detectResult, setDetectResult] = useState(null);

  useEffect(() => {
    storeJson('ais_dev_mode', Boolean(devMode));
  }, [devMode]);

  useEffect(() => {
    storeJson('ais_train_target_fpr', trainTargetFpr);
  }, [trainTargetFpr]);

  useEffect(() => {
    storeJson('ais_train_representation', trainRepresentation === 'dae' ? 'dae' : 'pca');
  }, [trainRepresentation]);

  useEffect(() => {
    storeJson('ais_dae_latent_dim', daeLatentDim);
  }, [daeLatentDim]);

  useEffect(() => {
    storeJson('ais_dae_noise_std', daeNoiseStd);
  }, [daeNoiseStd]);

  useEffect(() => {
    storeJson('ais_iso_contamination', isoContamination);
  }, [isoContamination]);

  useEffect(() => {
    storeJson('ais_iso_estimators', isoEstimators);
  }, [isoEstimators]);

  useEffect(() => {
    storeJson('ais_detect_limit', detectLimit);
  }, [detectLimit]);

  useEffect(() => {
    storeJson('ais_detect_offset', detectOffset);
  }, [detectOffset]);

  useEffect(() => {
    storeJson('ais_detect_logs', detectLogs);
  }, [detectLogs]);

  useEffect(() => {
    try {
      localStorage.removeItem('ais_detect_result');
    } catch {
      // Ignore storage failures; this only clears old oversized cached results.
    }
  }, []);

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
    setAlerts(prev => prependUniqueAlert(prev, alert, 500)); // Historical
    setLiveAlerts(prev => prependUniqueAlert(prev, alert, 200)); // Session
  }, []);

  // Refresh system status
  const refreshStatus = useCallback(async () => {
    try {
      const status = await getSystemStatus();
      setSystemStatus(status);
      if (status.active_detection_engine || status.active_model) {
        setActiveModel(status.active_detection_engine || status.active_model);
      }
      if (status.active_dataset_type) setDatasetType(status.active_dataset_type);
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

  // Auto-boot: load all data immediately on mount
  useEffect(() => {
    const init = async () => {
      await refreshStatus();
      await refreshDashStats();
      await refreshAlerts();
    };
    init();
  }, [refreshStatus, refreshDashStats, refreshAlerts]);

  return (
    <AppContext.Provider value={{
      alerts, setAlerts, pushAlert, refreshAlerts,
      systemStatus, refreshStatus,
      dashStats, refreshDashStats,
      activeModel, setActiveModel,
      datasetType, setDatasetType,
      captureRunning, setCaptureRunning,
      theme, setTheme,
      trainFile, setTrainFile, nDetectors, setND, benignRowLimit, setBenignRowLimit,
      trainTargetFpr, setTrainTargetFpr,
      devMode, setDevMode,
      trainRepresentation, setTrainRepresentation,
      daeLatentDim, setDaeLatentDim,
      daeNoiseStd, setDaeNoiseStd,
      isoContamination, setIsoContamination, isoEstimators, setIsoEstimators,
      trainLogs, setTrainLogs, trainResult, setTrainResult,
      detectFile, setDetectFile, detectLimit, setDetectLimit, detectOffset, setDetectOffset,
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
