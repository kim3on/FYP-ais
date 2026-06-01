/**
 * AlertTable — reusable alert table used on Dashboard, Alerts, and Detection pages.
 * Handles zero-day highlighting, severity badges, false-positive marking, and IP blocking.
 * Paginated to avoid DOM thrashing with large result sets.
 */
import { useState, useMemo } from 'react';

const cap = (s) => s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
const hasValue = (v) => Boolean(v && v !== 'N/A' && v !== '?');
const PAGE_SIZE = 50;

export default function AlertTable({ alerts = [], onMarkFP, onBlockIP, blockedIPs = [], showActions = false }) {
  const [page, setPage] = useState(0);

  const totalPages = Math.max(1, Math.ceil(alerts.length / PAGE_SIZE));
  // Reset page when alerts change (e.g. new detection run)
  const pageAlerts = useMemo(() => {
    const safeP = Math.min(page, totalPages - 1);
    return alerts.slice(safeP * PAGE_SIZE, (safeP + 1) * PAGE_SIZE);
  }, [alerts, page, totalPages]);

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

  const safePage = Math.min(page, totalPages - 1);

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Detection Profile</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Direction</th>
            <th>Port</th>
            <th>Proto</th>
            <th>Severity</th>
            <th>Confidence</th>
            {showActions && <th style={{ textAlign: 'right' }}>Tool</th>}
          </tr>
        </thead>
        <tbody>
          {pageAlerts.map((a, i) => {
            const zd  = a.is_zero_day || a.attack_type === 'Zero-Day Candidate';
            const sev = (a.severity || '').toLowerCase();
            const targetIp = a.dst_ip;
            const remoteIp = hasValue(a.remote_ip) ? a.remote_ip : '';
            const targetBlocked = remoteIp && blockedIPs.includes(remoteIp);
            const direction = a.traffic_direction || 'unknown';
            
            // Format timestamp for better readability
            const ts = a.timestamp ? (a.timestamp.includes('T') ? a.timestamp.split('T')[1].split('.')[0] : a.timestamp) : '—';
            
            return (
              <tr key={a.alert_id || (safePage * PAGE_SIZE + i)} className={zd ? 'zero-day-row' : ''} style={{
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
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  {targetIp || 'N/A'}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', minWidth: '86px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 700 }}>
                    {direction.toUpperCase()}
                  </span>
                </td>
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
                      {remoteIp && !targetBlocked && (
                        <button
                          className="btn btn-danger"
                          style={{ fontSize: '10px', padding: '4px 8px' }}
                          onClick={() => onBlockIP && onBlockIP(remoteIp, a.attack_type)}
                          title={`Block remote endpoint ${remoteIp}`}
                        >
                          BLOCK
                        </button>
                      )}
                      {remoteIp && targetBlocked && (
                        <span className="badge critical" style={{ opacity: 0.8 }}>LOCKED</span>
                      )}
                      {!remoteIp && (
                        <button
                          className="btn btn-ghost"
                          style={{ fontSize: '10px', padding: '4px 8px', opacity: 0.65 }}
                          disabled
                          title={a.endpoint_role_reason || 'No remote endpoint available'}
                        >
                          No remote IP
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

      {/* Pagination controls */}
      {totalPages > 1 && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 4px 2px',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          color: 'var(--text-tertiary)',
        }}>
          <span>
            Showing {safePage * PAGE_SIZE + 1}–{Math.min((safePage + 1) * PAGE_SIZE, alerts.length)} of {alerts.length.toLocaleString()}
          </span>
          <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
            <button
              className="btn btn-ghost"
              style={{ fontSize: '10px', padding: '4px 10px' }}
              disabled={safePage === 0}
              onClick={() => setPage(0)}
            >
              ⟪
            </button>
            <button
              className="btn btn-ghost"
              style={{ fontSize: '10px', padding: '4px 10px' }}
              disabled={safePage === 0}
              onClick={() => setPage(p => Math.max(0, p - 1))}
            >
              ◂ Prev
            </button>
            <span style={{ padding: '0 6px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              {safePage + 1} / {totalPages}
            </span>
            <button
              className="btn btn-ghost"
              style={{ fontSize: '10px', padding: '4px 10px' }}
              disabled={safePage >= totalPages - 1}
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            >
              Next ▸
            </button>
            <button
              className="btn btn-ghost"
              style={{ fontSize: '10px', padding: '4px 10px' }}
              disabled={safePage >= totalPages - 1}
              onClick={() => setPage(totalPages - 1)}
            >
              ⟫
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
