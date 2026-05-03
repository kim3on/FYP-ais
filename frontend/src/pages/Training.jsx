import { useState, useRef, useCallback, useEffect } from 'react';
import { startTraining, getTrainingLogs, getTrainingResult } from '../api';
import { useApp } from '../hooks/useApp';
import '../components/Layout/Layout.css';

export default function Training() {
  const [file, setFile]         = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState('');
  const [nDetectors, setNDetectors] = useState(500);
  const [rRadius, setRRadius]   = useState(0.30);
  const [rsRadius, setRSRadius] = useState(0.03);
  const { trainingLog, pushLog, clearTrainingLog, refreshStatus } = useApp();
  const logRef  = useRef(null);
  const pollRef = useRef(null);

  // Auto-scroll log box
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [trainingLog]);

  const pollLogs = useCallback(async () => {
    try {
      const data = await getTrainingLogs();
      const lines = data.logs || data || [];
      lines.forEach(l => pushLog(l));
    } catch (err) {
      console.error("Failed to poll training logs:", err);
    }
  }, [pushLog]);

  async function handleTrain() {
    if (!file) { setError('Please select a dataset file first.'); return; }
    setError(''); setLoading(true); setResult(null); clearTrainingLog();
    pushLog('[INFO] Starting training pipeline…');

    try {
      // Start polling logs every 2s
      pollRef.current = setInterval(pollLogs, 2000);
      const data = await startTraining(file, { n_detectors: nDetectors, r: rRadius });
      pushLog(`[OK] Training complete — ${data.message || 'Success'}`);
      // Fetch final result
      try {
        const r = await getTrainingResult();
        setResult(r);
      } catch(err) {
        console.error("Failed to fetch training result:", err);
      }
      refreshStatus();
    } catch (err) {
      pushLog(`[ERR] ${err.message}`);
      setError(err.message);
    } finally {
      clearInterval(pollRef.current);
      setLoading(false);
    }
  }

  function handleDrop(e) {
    e.preventDefault(); setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">AIS Training</h1>
        <p className="page-subtitle">Upload a clean network traffic dataset to train the NSA Self profile</p>
      </div>

      <div className="two-col">
        {/* Left — config */}
        <div style={{display:'flex',flexDirection:'column',gap:'16px'}}>
          {/* File drop zone */}
          <div className="card">
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'12px'}}>
              Dataset Upload
            </div>
            <div
              className={`drop-zone ${dragging?'drag-over':''}`}
              onDragOver={e=>{e.preventDefault();setDragging(true)}}
              onDragLeave={()=>setDragging(false)}
              onDrop={handleDrop}
              onClick={()=>document.getElementById('train-file-input').click()}
            >
              <div className="drop-icon">📂</div>
              {file ? (
                <p><span>{file.name}</span><br/><small style={{color:'var(--text-tertiary)'}}>{(file.size/1024/1024).toFixed(2)} MB</small></p>
              ) : (
                <p>Drop a <span>.csv</span> or <span>.parquet</span> file here<br/><small style={{color:'var(--text-tertiary)'}}>or click to browse</small></p>
              )}
            </div>
            <input id="train-file-input" type="file" accept=".csv,.parquet,.pq" style={{display:'none'}}
              onChange={e=>setFile(e.target.files[0])} />
          </div>

          {/* Parameters */}
          <div className="card">
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'14px'}}>
              NSA Parameters
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:'12px'}}>
              <div>
                <label>Number of Detectors — <span style={{color:'var(--accent)'}}>{nDetectors}</span></label>
                <input type="range" min="100" max="2000" step="100" value={nDetectors}
                  onChange={e=>setNDetectors(+e.target.value)}
                  style={{padding:0,cursor:'pointer',accentColor:'var(--accent)',width:'100%'}} />
              </div>
              <div>
                <label>Self Gap Radius (r) — <span style={{color:'var(--accent)'}}>{rRadius}</span></label>
                <input type="range" min="0.05" max="1.0" step="0.01" value={rRadius}
                  onChange={e=>setRRadius(+parseFloat(e.target.value).toFixed(2))}
                  style={{padding:0,cursor:'pointer',accentColor:'var(--accent)',width:'100%'}} />
              </div>
              <div>
                <label>Detector Tolerance (r_s) — <span style={{color:'var(--accent)'}}>{rsRadius}</span></label>
                <input type="range" min="0.01" max="0.2" step="0.01" value={rsRadius}
                  onChange={e=>setRSRadius(+parseFloat(e.target.value).toFixed(2))}
                  style={{padding:0,cursor:'pointer',accentColor:'var(--accent)',width:'100%'}} />
              </div>
            </div>
          </div>

          {error && (
            <div style={{background:'var(--danger-subtle)',border:'1px solid var(--danger-border)',color:'var(--danger)',padding:'10px 14px',borderRadius:'var(--radius)',fontSize:'12px',fontFamily:'var(--font-mono)'}}>
              ⚠ {error}
            </div>
          )}

          <button className="btn btn-primary" onClick={handleTrain} disabled={loading || !file}
            style={{width:'100%',justifyContent:'center',padding:'10px'}}>
            {loading ? <><span className="spinner"/> Training…</> : '⚙ Start Training'}
          </button>
        </div>

        {/* Right — logs + result */}
        <div style={{display:'flex',flexDirection:'column',gap:'16px'}}>
          <div className="card" style={{flex:1}}>
            <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'12px'}}>
              Training Log
            </div>
            <div className="log-box" ref={logRef} style={{height:'260px'}}>
              {trainingLog.length === 0
                ? <span style={{color:'var(--text-tertiary)'}}>Waiting for training to start…</span>
                : trainingLog.map((l,i)=>{
                    const cls = l.startsWith('[OK]')||l.startsWith('[✓]') ? 'log-ok'
                      : l.startsWith('[ERR]')||l.startsWith('[✗]') ? 'log-err'
                      : l.startsWith('[WARN]') ? 'log-warn' : 'log-info';
                    return <div key={i} className={cls}>{l}</div>;
                  })
              }
            </div>
          </div>

          {result && (
            <div className="card">
              <div style={{fontSize:'11px',fontWeight:600,fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:'14px'}}>
                Training Result
              </div>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'10px'}}>
                {[
                  ['Detectors', result.n_detectors ?? '—'],
                  ['Self Samples', result.n_self ?? '—'],
                  ['Accuracy', result.accuracy != null ? `${(result.accuracy*100).toFixed(1)}%` : '—'],
                  ['Precision', result.precision != null ? `${(result.precision*100).toFixed(1)}%` : '—'],
                  ['Recall', result.recall != null ? `${(result.recall*100).toFixed(1)}%` : '—'],
                  ['F1 Score', result.f1 != null ? `${(result.f1*100).toFixed(1)}%` : '—'],
                ].map(([label,val])=>(
                  <div key={label} style={{background:'var(--bg-overlay)',borderRadius:'var(--radius)',padding:'10px 12px'}}>
                    <div style={{fontSize:'10px',fontFamily:'var(--font-mono)',color:'var(--text-tertiary)',textTransform:'uppercase',marginBottom:'4px'}}>{label}</div>
                    <div style={{fontSize:'18px',fontWeight:700,fontFamily:'var(--font-mono)',color:'var(--accent)'}}>{val}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
