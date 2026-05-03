/**
 * AlertTable — reusable alert table used on Dashboard, Alerts, and Detection pages.
 * Handles zero-day highlighting, severity badges, false-positive marking, and IP blocking.
 */
const cap = (s) => s ? s.charAt(0).toUpperCase() + s.slice(1) : '';

export default function AlertTable({ alerts = [], onMarkFP, onBlockIP, blockedIPs = [], showActions = false }) {
  if (!alerts.length) {
    return (
      <div style={{ 
        textAlign: 'center', 
        padding: '48px 24px', 
        color: 'var(--text-tertiary)', 
        fontFamily: 'var(--font-mono)', 
        fontSize: '12px',
        border: '1px dashed var(--border)',
        borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-overlay)'
      }}>
        <div style={{ fontSize: '24px', marginBottom: '8px', opacity: 0.5 }}>⬡</div>
        No alerts detected in this session
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Detection Profile</th>
            <th>Source Address</th>
            <th>Target Address</th>
            <th>Port</th>
            <th>Proto</th>
            <th>Severity</th>
            <th>Confidence</th>
            {showActions && <th style={{ textAlign: 'right' }}>Forensics</th>}
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => {
            const zd  = a.is_zero_day || a.attack_type === 'Zero-Day Candidate';
            const sev = (a.severity || '').toLowerCase();
            const srcBlocked = blockedIPs.includes(a.src_ip);
            
            // Format timestamp for better readability
            const ts = a.timestamp ? (a.timestamp.includes('T') ? a.timestamp.split('T')[1].split('.')[0] : a.timestamp) : '—';
            
            return (
              <tr key={a.alert_id || i} className={zd ? 'zero-day-row' : ''} style={{
                background: zd ? 'var(--iris-subtle)' : 'transparent'
              }}>
                <td style={{ color: 'var(--text-tertiary)', fontWeight: 500 }}>
                  {ts}
                </td>
                <td>
                  {zd ? (
                    <span className="badge zero-day" title="Novel pattern — no known attack signature matched">
                      ⚠ {a.attack_type}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                      {a.attack_type || '—'}
                    </span>
                  )}
                </td>
                <td style={{ color: 'var(--rp-pine)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                  {a.src_ip || 'N/A'}
                  {srcBlocked && (
                    <span style={{ 
                      marginLeft: '8px', 
                      fontSize: '8px', 
                      background: 'var(--danger)', 
                      color: '#fff', 
                      padding: '1px 4px', 
                      borderRadius: '2px', 
                      verticalAlign: 'middle'
                    }}>
                      LOCKED
                    </span>
                  )}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{a.dst_ip || 'N/A'}</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{a.dst_port || '—'}</td>
                <td style={{ color: 'var(--text-tertiary)', fontWeight: 600 }}>
                  {(a.protocol || 'N/A').toUpperCase()}
                </td>
                <td>
                  <span className={`badge ${sev}`}>{cap(sev)}</span>
                </td>
                <td style={{ 
                  fontWeight: 700, 
                  fontFamily: 'var(--font-mono)',
                  color: sev === 'critical' ? 'var(--danger)' : 'var(--text-primary)' 
                }}>
                  {a.confidence_pct || `${Math.round((a.confidence || 0) * 100)}%`}
                </td>
                {showActions && (
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'flex', gap: '6px', justifyContent: 'flex-end' }}>
                      {!a.is_false_positive ? (
                        <button
                          className="btn btn-ghost"
                          style={{ fontSize: '10px', padding: '4px 8px' }}
                          onClick={() => onMarkFP && onMarkFP(a.alert_id)}
                        >
                          Mark FP
                        </button>
                      ) : (
                        <span className="badge normal" style={{ opacity: 0.7 }}>RESOLVED</span>
                      )}
                      {a.src_ip && a.src_ip !== 'N/A' && !srcBlocked && (
                        <button
                          className="btn btn-danger"
                          style={{ fontSize: '10px', padding: '4px 8px' }}
                          onClick={() => onBlockIP && onBlockIP(a.src_ip, a.attack_type)}
                          title={`Block ${a.src_ip}`}
                        >
                          LOCKED DOWN
                        </button>
                      )}
                    </div>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
