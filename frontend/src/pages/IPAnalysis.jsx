import React, { useState, useEffect } from 'react';
import { Search, Shield, Globe, Activity, Clock, Terminal } from 'lucide-react';
import ThreatMeter from '../components/ThreatMeter';
import AlertBadge from '../components/AlertBadge';
import { getIPAnalysis } from '../services/api';

export default function IPAnalysis({ initialIP }) {
  const [ip, setIp] = useState(initialIP || '192.168.1.25');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyze = async (targetIP) => {
    if (!targetIP) return;
    setLoading(true);
    try {
      const res = await getIPAnalysis(targetIP);
      setData(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialIP) {
      setIp(initialIP);
      analyze(initialIP);
    } else {
      analyze(ip);
    }
  }, [initialIP]);

  const handleSubmit = (e) => {
    e.preventDefault();
    analyze(ip);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Search Input */}
      <div className="glass-card" style={{ padding: 20 }}>
        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={16} style={{ position: 'absolute', left: 12, top: 12, color: 'var(--text-muted)' }} />
            <input
              type="text"
              className="input"
              style={{ paddingLeft: 36, fontSize: 14 }}
              placeholder="Enter IP Address (e.g., 192.168.1.25 or 45.33.32.156)..."
              value={ip}
              onChange={e => setIp(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-primary" style={{ padding: '10px 20px' }}>
            ANALYZE IP
          </button>
        </form>
      </div>

      {loading ? (
        <div className="empty-state">
          <div className="loading-pulse">
            <div className="loading-dot" />
            <div className="loading-dot" />
            <div className="loading-dot" />
          </div>
          <div>Analyzing IP forensics database...</div>
        </div>
      ) : data ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Header Card with Threat Meter */}
          <div className="glass-card" style={{ padding: 24, display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                <h2 style={{ fontSize: 24, fontWeight: 900, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                  {data.ip}
                </h2>
                <span className={`badge badge-${(data.threat_level || 'LOW').toLowerCase()}`}>
                  {data.threat_level}
                </span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
                First Seen: {data.stats?.first_seen ? new Date(data.stats.first_seen).toLocaleString() : 'N/A'} |
                Last Seen: {data.stats?.last_seen ? new Date(data.stats.last_seen).toLocaleString() : 'N/A'}
              </div>

              {/* Stat Pill Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 10, borderRadius: 6, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                  <div style={{ color: 'var(--text-muted)' }}>PACKETS</div>
                  <strong style={{ fontSize: 14, color: 'var(--text-primary)' }}>{data.stats?.packet_count?.toLocaleString() || 0}</strong>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 10, borderRadius: 6, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                  <div style={{ color: 'var(--text-muted)' }}>ALERTS</div>
                  <strong style={{ fontSize: 14, color: 'var(--threat-high)' }}>{data.stats?.alert_count || 0}</strong>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 10, borderRadius: 6, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                  <div style={{ color: 'var(--text-muted)' }}>UNIQUE PORTS</div>
                  <strong style={{ fontSize: 14, color: 'var(--accent-blue)' }}>{data.stats?.unique_ports_accessed || 0}</strong>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <ThreatMeter score={data.threat_score} />
            </div>
          </div>

          {/* External Intelligence Note */}
          <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'rgba(0,212,255,0.04)', border: '1px solid var(--border)', padding: 10, borderRadius: 6 }}>
            💡 <strong>Note on Threat Intelligence:</strong> All threat scores and connection metrics above are derived from locally captured network traffic and real-time detection rules.
          </div>

          {/* Protocol Distribution & Target Ports */}
          <div className="grid-2">
            <div className="glass-card" style={{ padding: 20 }}>
              <div className="section-header">
                <div className="section-title">TOP DESTINATION PORTS PROBED</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {data.top_destination_ports?.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No targeted ports recorded.</div>
                ) : (
                  data.top_destination_ports?.map(p => (
                    <div key={p.port} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, fontFamily: 'var(--font-mono)', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                      <span style={{ color: 'var(--accent-cyan)' }}>Port {p.port}</span>
                      <span>{p.count} attempts</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="glass-card" style={{ padding: 20 }}>
              <div className="section-header">
                <div className="section-title">PROTOCOL BREAKDOWN</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(data.protocol_distribution || {}).map(([proto, count]) => (
                  <div key={proto} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, fontFamily: 'var(--font-mono)', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                    <span>{proto}</span>
                    <span style={{ color: 'var(--accent-green)' }}>{count} packets</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Attack History */}
          <div className="glass-card" style={{ padding: 20 }}>
            <div className="section-header">
              <div className="section-title">ATTACK HISTORY FOR {data.ip}</div>
            </div>
            <div className="table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>TIME</th>
                    <th>ATTACK TYPE</th>
                    <th>SEVERITY</th>
                    <th>PROTOCOL</th>
                    <th>THREAT SCORE</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_alerts?.length === 0 ? (
                    <tr>
                      <td colSpan="5" style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)' }}>
                        No attack history for this IP address.
                      </td>
                    </tr>
                  ) : (
                    data.recent_alerts?.map(a => (
                      <tr key={a.id}>
                        <td>{new Date(a.timestamp).toLocaleString()}</td>
                        <td style={{ fontWeight: 600 }}>{a.attack_type.replace('_', ' ')}</td>
                        <td><AlertBadge severity={a.severity} /></td>
                        <td>{a.protocol || 'TCP'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{a.threat_score}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
