import React, { useState, useEffect } from 'react';
import { Search, Filter, RefreshCw, X, ShieldAlert, Clock, ArrowRight } from 'lucide-react';
import AlertBadge from '../components/AlertBadge';
import ThreatMeter from '../components/ThreatMeter';
import { getAlerts, updateAlert } from '../services/api';

export default function Alerts({ selectedAlert, onClearSelectedAlert }) {
  const [alerts, setAlerts] = useState([]);
  const [activeAlert, setActiveAlert] = useState(selectedAlert || null);

  const [severityFilter, setSeverityFilter] = useState('');
  const [attackFilter, setAttackFilter] = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (selectedAlert) setActiveAlert(selectedAlert);
  }, [selectedAlert]);

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const data = await getAlerts({
        severity: severityFilter || undefined,
        attack_type: attackFilter || undefined,
        src_ip: ipFilter || undefined,
        limit: 100,
      });
      setAlerts(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [severityFilter, attackFilter, ipFilter]);

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      const updated = await updateAlert(alertId, { status: newStatus });
      setAlerts(alerts.map(a => a.id === alertId ? updated : a));
      if (activeAlert?.id === alertId) setActiveAlert(updated);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Filters Bar */}
      <div className="glass-card" style={{ padding: 16, display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="input"
            style={{ paddingLeft: 30 }}
            placeholder="Filter by Source IP..."
            value={ipFilter}
            onChange={e => setIpFilter(e.target.value)}
          />
        </div>

        <select
          className="input"
          style={{ width: 140 }}
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
        >
          <option value="">ALL SEVERITIES</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>

        <select
          className="input"
          style={{ width: 160 }}
          value={attackFilter}
          onChange={e => setAttackFilter(e.target.value)}
        >
          <option value="">ALL ATTACK TYPES</option>
          <option value="PORT_SCAN">PORT SCAN</option>
          <option value="BRUTE_FORCE">BRUTE FORCE</option>
          <option value="SYN_FLOOD">SYN FLOOD</option>
          <option value="ICMP_FLOOD">ICMP FLOOD</option>
          <option value="TRAFFIC_SPIKE">TRAFFIC SPIKE</option>
          <option value="DOS_PATTERN">DOS PATTERN</option>
        </select>

        <button className="btn btn-ghost" onClick={loadAlerts}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Alerts Table */}
      <div className="glass-card" style={{ padding: 20 }}>
        <div className="section-header">
          <div className="section-title">SECURITY ALERTS DATABASE</div>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            {alerts.length} records found
          </span>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>SEVERITY</th>
                <th>ATTACK TYPE</th>
                <th>SOURCE IP</th>
                <th>DESTINATION IP</th>
                <th>PORT</th>
                <th>PROTOCOL</th>
                <th>STATUS</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                    No matching security alerts.
                  </td>
                </tr>
              ) : (
                alerts.map(a => (
                  <tr key={a.id}>
                    <td>{new Date(a.timestamp).toLocaleTimeString()}</td>
                    <td><AlertBadge severity={a.severity} /></td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {a.attack_type.replace('_', ' ')}
                    </td>
                    <td style={{ color: 'var(--accent-cyan)' }}>{a.src_ip}</td>
                    <td>{a.dst_ip || '--'}</td>
                    <td>{a.dst_port || '--'}</td>
                    <td>{a.protocol || 'TCP'}</td>
                    <td>
                      <span className={`badge ${a.status === 'RESOLVED' ? 'badge-safe' : 'badge-info'}`}>
                        {a.status}
                      </span>
                      <span className="badge" style={{ marginLeft: 4, background: a.is_simulation ? 'rgba(255, 165, 0, 0.1)' : 'rgba(0, 212, 255, 0.1)', color: a.is_simulation ? 'orange' : 'var(--accent-cyan)' }}>
                        {a.is_simulation ? 'SIMULATION' : 'LIVE'}
                      </span>
                    </td>
                    <td>
                      <button className="btn btn-ghost btn-sm" onClick={() => setActiveAlert(a)}>
                        INVESTIGATE
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Investigation Modal */}
      {activeAlert && (
        <div
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 999, padding: 20, backdropFilter: 'blur(8px)',
          }}
        >
          <div
            className="glass-card"
            style={{
              width: 600, maxWidth: '100%', maxHeight: '90vh', overflowY: 'auto',
              padding: 24, border: '1px solid var(--border-bright)', boxShadow: '0 0 40px rgba(0,0,0,0.8)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                  <AlertBadge severity={activeAlert.severity} />
                  <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    ALERT #{activeAlert.id}
                  </span>
                </div>
                <h2 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>
                  {activeAlert.attack_type.replace('_', ' ')}
                </h2>
              </div>
              <button
                onClick={() => { setActiveAlert(null); onClearSelectedAlert && onClearSelectedAlert(); }}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20, background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, fontSize: 12, fontFamily: 'var(--font-mono)' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Source IP:</span> <strong style={{ color: 'var(--accent-cyan)' }}>{activeAlert.src_ip}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Destination IP:</span> <strong>{activeAlert.dst_ip || '192.168.1.10'}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Source Port:</span> {activeAlert.src_port || '--'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>Destination Port:</span> {activeAlert.dst_port || '--'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>Protocol:</span> {activeAlert.protocol || 'TCP'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>Timestamp:</span> {new Date(activeAlert.timestamp).toLocaleString()}</div>
            </div>

            <div style={{ marginBottom: 20 }}>
              <ThreatMeter score={activeAlert.threat_score} />
            </div>

            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6 }}>DETECTION RULE</div>
              <div style={{ fontSize: 12, background: 'rgba(0,212,255,0.05)', border: '1px solid var(--border)', padding: 10, borderRadius: 6, color: 'var(--text-primary)' }}>
                {activeAlert.detection_rule || 'Rule-based anomaly match'}
              </div>
            </div>

            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--threat-high)', marginBottom: 6 }}>RECOMMENDED ACTION</div>
              <div style={{ fontSize: 12, background: 'rgba(255,136,0,0.08)', border: '1px solid rgba(255,136,0,0.3)', padding: 10, borderRadius: 6, color: 'var(--text-primary)' }}>
                {activeAlert.recommended_action || 'Block source IP, review firewall rules, monitor targeted service.'}
              </div>
            </div>

            {/* Timeline */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10 }}>ATTACK TIMELINE</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, borderLeft: '2px solid var(--border)', paddingLeft: 12, fontSize: 11 }}>
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>T-0s</span> - Packet flow anomaly detected from {activeAlert.src_ip}
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>T+0.5s</span> - Rule threshold breached ({activeAlert.attack_type})
                </div>
                <div>
                  <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>T+1.0s</span> - Alert recorded with Threat Score {activeAlert.threat_score}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', paddingTop: 16, borderTop: '1px solid var(--border)' }}>
              <button className="btn btn-ghost" onClick={() => handleStatusChange(activeAlert.id, 'INVESTIGATING')}>
                MARK INVESTIGATING
              </button>
              <button className="btn btn-success" onClick={() => handleStatusChange(activeAlert.id, 'RESOLVED')}>
                RESOLVE ALERT
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
