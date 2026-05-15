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
  const [offset, setOffset]     = useState(0);
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
      await detectFromFile(file, limit, offset);
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

  // Metric assessment badge helper
  const gradeBadge = (assessment) => {
    if (!assessment) return null;
    const colors = {
      target_met: { bg: 'var(--success-subtle)', border: 'var(--success-border)', color: 'var(--success)', label: 'TARGET MET' },
      prototype_acceptable: { bg: 'var(--warning-subtle)', border: 'var(--warning-border)', color: 'var(--warning)', label: 'ACCEPTABLE' },
      needs_improvement: { bg: 'var(--danger-subtle)', border: 'var(--danger-border)', color: 'var(--danger)', label: 'NEEDS WORK' },
      not_applicable: { bg: 'var(--bg-overlay)', border: 'var(--border)', color: 'var(--text-tertiary)', label: 'N/A' },
    };
    const s = colors[assessment.grade] || colors.not_applicable;
    return (
      <span style={{fontSize:'8px',fontWeight:700,fontFamily:'var(--font-mono)',background:s.bg,border:`1px solid ${s.border}`,color:s.color,padding:'2px 6px',borderRadius:'4px',marginLeft:'6px',letterSpacing:'0.05em'}}>
        {s.label}
      </span>
    );
  };

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
            <label>Start Row — <span style={{color:'var(--accent)'}}>{offset.toLocaleString()}</span></label>
            <input type="number" min="0" step="1000" value={offset}
              onChange={e=>setOffset(Math.max(0, Number(e.target.value)||0))}
              style={{marginTop:'8px',marginBottom:'12px'}} />
            <label>Rows to Analyse — <span style={{color:'var(--accent)'}}>{limit.toLocaleString()}</span></label>
            <input type="range" min="100" max="50000" step="100" value={limit}
              onChange={e=>setLimit(+e.target.value)}
              style={{padding:0,cursor:'pointer',accentColor:'var(--accent)',marginTop:'8px'}} />
            <p style={{fontSize:'10px',color:'var(--text-tertiary)',fontFamily:'var(--font-mono)',marginTop:'8px'}}>
              Analysing rows {offset.toLocaleString()}–{(offset+limit).toLocaleString()}.
            </p>
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
                <div className="stat-value">{result.total_checked ?? alerts.length}</div>
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

            {/* Post-run verification metrics */}
            {result.accuracy != null && (
              <div className="card">
                <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'4px'}}>Post-Run Verification Metrics</div>
                {result.verification_mode && (
                  <div style={{fontSize:'9px',fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',marginBottom:'12px',lineHeight:1.4}}>
                    Labels used only after detection · Layer 2 attribution is heuristic-only
                  </div>
                )}
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'10px'}}>
                  {[['Recall',result.recall,'recall'],['FNR',result.false_negative_rate,'false_negative_rate'],['Precision',result.precision,'precision'],['F1',result.f1,'f1'],['FPR',result.false_positive_rate,'false_positive_rate'],['Accuracy',result.accuracy,null]].map(([k,v,assessKey])=>(
                    <div key={k} style={{background:'var(--bg-overlay)',borderRadius:'var(--radius)',padding:'10px 12px'}}>
                      <div style={{fontSize:'10px',fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',marginBottom:'4px'}}>
                        {k}
                        {assessKey && result.metric_assessment && gradeBadge(result.metric_assessment[assessKey])}
                      </div>
                      <div style={{fontSize:'20px',fontWeight:700,fontFamily:'var(--font-mono)',color:v!=null?'var(--success)':'var(--text-tertiary)'}}>{v!=null?`${(v*100).toFixed(1)}%`:'N/A'}</div>
                    </div>
                  ))}
                </div>
                {(result.tp != null || result.fn != null) && (
                  <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr 1fr',gap:'8px',marginTop:'10px'}}>
                    {[['TP',result.tp,'var(--success)'],['TN',result.tn,'var(--text-secondary)'],['FP',result.fp,'var(--warning)'],['FN',result.fn,'var(--danger)']].map(([k,v,c])=>(
                      <div key={k} style={{textAlign:'center',background:'var(--bg-overlay)',borderRadius:'var(--radius)',padding:'6px'}}>
                        <div style={{fontSize:'9px',fontFamily:'var(--font-mono)',color:'var(--text-tertiary)'}}>{k}</div>
                        <div style={{fontSize:'16px',fontWeight:700,fontFamily:'var(--font-mono)',color:c}}>{v != null ? v.toLocaleString() : '—'}</div>
                      </div>
                    ))}
                  </div>
                )}
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
