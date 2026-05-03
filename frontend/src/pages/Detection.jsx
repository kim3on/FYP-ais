import { useState, useRef, useCallback, useEffect } from 'react';
import { detectFromFile, getDetectionLogs, getDetectionResult } from '../api';
import AlertTable from '../components/AlertTable';
import '../components/Layout/Layout.css';

export default function Detection() {
  const [file, setFile]         = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [logs, setLogs]         = useState([]);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState('');
  const [limit, setLimit]       = useState(1000);
  const logRef  = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const pollLogs = useCallback(async () => {
    try {
      const data = await getDetectionLogs();
      setLogs(data.logs || data || []);
    } catch (err) {
      console.error("Failed to poll detection logs:", err);
    }
  }, []);

  async function handleDetect() {
    if (!file) { setError('Please select a file.'); return; }
    setError(''); setLoading(true); setResult(null); setLogs([]);
    try {
      pollRef.current = setInterval(pollLogs, 1500);
      await detectFromFile(file, limit);
      const r = await getDetectionResult();
      setResult(r);
    } catch (err) {
      setError(err.message);
    } finally {
      clearInterval(pollRef.current);
      const final = await getDetectionLogs().catch(()=>({logs:[]}));
      setLogs(final.logs || []);
      setLoading(false);
    }
  }

  const alerts    = result?.alerts || [];
  const zdCount   = alerts.filter(a=>a.is_zero_day||a.attack_type==='Zero-Day Candidate').length;
  const anomCount = alerts.filter(a=>!a.is_false_positive).length;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Batch Detection</h1>
        <p className="page-subtitle">Upload a network traffic log to run anomaly detection</p>
      </div>

      <div className="two-col" style={{marginBottom:'16px'}}>
        {/* Upload + config */}
        <div style={{display:'flex',flexDirection:'column',gap:'14px'}}>
          <div className="card">
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'12px'}}>
              Traffic Log Upload
            </div>
            <div
              className={`drop-zone ${dragging?'drag-over':''}`}
              onDragOver={e=>{e.preventDefault();setDragging(true)}}
              onDragLeave={()=>setDragging(false)}
              onDrop={e=>{e.preventDefault();setDragging(false);const f=e.dataTransfer.files[0];if(f)setFile(f);}}
              onClick={()=>document.getElementById('det-file').click()}
            >
              <div className="drop-icon">🔍</div>
              {file
                ? <p><span>{file.name}</span><br/><small style={{color:'var(--text-tertiary)'}}>{(file.size/1024/1024).toFixed(2)} MB</small></p>
                : <p>Drop a <span>.csv</span> or <span>.parquet</span> file<br/><small style={{color:'var(--text-tertiary)'}}>or click to browse</small></p>
              }
            </div>
            <input id="det-file" type="file" accept=".csv,.parquet,.pq" style={{display:'none'}}
              onChange={e=>setFile(e.target.files[0])} />
          </div>

          <div className="card">
            <label>Row Limit — <span style={{color:'var(--accent)'}}>{limit.toLocaleString()}</span></label>
            <input type="range" min="100" max="10000" step="100" value={limit}
              onChange={e=>setLimit(+e.target.value)}
              style={{padding:0,cursor:'pointer',accentColor:'var(--accent)',marginTop:'8px'}} />
          </div>

          {error && <div style={{background:'var(--danger-subtle)',border:'1px solid var(--danger-border)',color:'var(--danger)',padding:'10px 14px',borderRadius:'var(--radius)',fontSize:'12px',fontFamily:'var(--font-mono)'}}>⚠ {error}</div>}

          <button className="btn btn-primary" onClick={handleDetect} disabled={loading||!file}
            style={{width:'100%',justifyContent:'center',padding:'10px'}}>
            {loading ? <><span className="spinner"/> Detecting…</> : '⬢ Run Detection'}
          </button>

          {/* Detection log */}
          <div className="card">
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'10px'}}>Detection Log</div>
            <div className="log-box" ref={logRef} style={{height:'160px'}}>
              {logs.length===0
                ? <span style={{color:'var(--text-tertiary)'}}>No detection run yet…</span>
                : logs.map((l,i)=>{
                    const cls=l.startsWith('[OK]')||l.includes('✓')?'log-ok':l.startsWith('[ERR]')||l.includes('✗')?'log-err':l.startsWith('[WARN]')?'log-warn':'log-info';
                    return <div key={i} className={cls}>{l}</div>;
                  })
              }
            </div>
          </div>
        </div>

        {/* Result stats */}
        {result && (
          <div style={{display:'flex',flexDirection:'column',gap:'14px'}}>
            <div className="stat-grid" style={{gridTemplateColumns:'1fr 1fr'}}>
              <div className="stat-card">
                <div className="stat-label">Total Flows</div>
                <div className="stat-value">{result.total_flows ?? alerts.length}</div>
              </div>
              <div className="stat-card" style={{borderColor:anomCount>0?'var(--danger-border)':'var(--border)'}}>
                <div className="stat-label" style={{color:'var(--danger)'}}>Anomalies</div>
                <div className="stat-value" style={{color:anomCount>0?'var(--danger)':'var(--text-primary)'}}>{anomCount}</div>
              </div>
              {zdCount > 0 && (
                <div className="stat-card" style={{borderColor:'var(--iris-border)',gridColumn:'span 2'}}>
                  <div className="stat-label" style={{color:'var(--iris)'}}>⚠ Zero-Day Candidates</div>
                  <div className="stat-value" style={{color:'var(--iris)'}}>{zdCount}</div>
                </div>
              )}
            </div>

            {/* Metrics if available */}
            {result.accuracy != null && (
              <div className="card">
                <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'12px'}}>Model Metrics</div>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'10px'}}>
                  {[['Accuracy',result.accuracy],['Precision',result.precision],['Recall',result.recall],['F1',result.f1]].map(([k,v])=>(
                    <div key={k} style={{background:'var(--bg-overlay)',borderRadius:'var(--radius)',padding:'10px 12px'}}>
                      <div style={{fontSize:'10px',fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',marginBottom:'4px'}}>{k}</div>
                      <div style={{fontSize:'20px',fontWeight:700,fontFamily:'var(--font-mono)',color:'var(--success)'}}>{v!=null?`${(v*100).toFixed(1)}%`:'—'}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Results table */}
      {alerts.length > 0 && (
        <div className="card">
          <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'12px'}}>
            Detection Results — {alerts.length} alerts
          </div>
          <AlertTable alerts={alerts} />
        </div>
      )}
    </div>
  );
}
