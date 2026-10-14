import React, { useState, useEffect } from 'react';
import { Shield, Eye, AlertTriangle } from 'lucide-react';
import ThreatMeter from '../components/ThreatMeter';
import { getSuspiciousIPs } from '../services/api';

export default function ThreatIntelligence({ onSelectIP }) {
  const [ips, setIps] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSuspiciousIPs(20)
      .then(setIps)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="section-header">
        <div className="section-title">ACTIVE THREAT INTELLIGENCE & SUSPICIOUS IPS</div>
      </div>

      <div className="table-wrapper glass-card" style={{ padding: 20 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>THREAT SCORE</th>
              <th>IP ADDRESS</th>
              <th>THREAT LEVEL</th>
              <th>TOTAL ALERTS</th>
              <th>PACKETS</th>
              <th>LAST SEEN</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {ips.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                  No high-threat IPs identified yet. Run Demo Mode to simulate threat intelligence feeds.
                </td>
              </tr>
            ) : (
              ips.map(item => (
                <tr key={item.ip}>
                  <td style={{ width: 140 }}>
                    <div style={{ fontWeight: 800, fontFamily: 'var(--font-mono)', color: item.threat_score > 60 ? 'var(--threat-critical)' : 'var(--threat-high)' }}>
                      {item.threat_score} / 100
                    </div>
                  </td>
                  <td style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{item.ip}</td>
                  <td>
                    <span className={`badge badge-${(item.threat_level || 'HIGH').toLowerCase()}`}>
                      {item.threat_level}
                    </span>
                  </td>
                  <td>{item.alert_count}</td>
                  <td>{item.packet_count}</td>
                  <td>{item.last_seen ? new Date(item.last_seen).toLocaleTimeString() : 'Just now'}</td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => onSelectIP && onSelectIP(item.ip)}
                    >
                      <Eye size={12} /> INVESTIGATE IP
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
