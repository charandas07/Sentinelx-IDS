import React, { useState, useEffect } from 'react';
import { Download, Printer, Shield, FileText } from 'lucide-react';
import { getReport, exportReportJSON, exportReportCSV } from '../services/api';

export default function Reports() {
  const [report, setReport] = useState(null);
  const [days, setDays] = useState(7);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getReport(days)
      .then(setReport)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [days]);

  const handlePrintPDF = () => {
    window.print();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Export Bar */}
      <div className="glass-card" style={{ padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>PERIOD:</span>
          <select
            className="input"
            style={{ width: 140 }}
            value={days}
            onChange={e => setDays(Number(e.target.value))}
          >
            <option value={1}>Last 24 Hours</option>
            <option value={7}>Last 7 Days</option>
            <option value={30}>Last 30 Days</option>
          </select>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-ghost" onClick={handlePrintPDF}>
            <Printer size={14} /> EXPORT PDF / PRINT
          </button>
          <a href={exportReportCSV(days)} target="_blank" className="btn btn-primary" style={{ textDecoration: 'none' }}>
            <Download size={14} /> EXPORT CSV
          </a>
          <a href={exportReportJSON(days)} target="_blank" className="btn btn-success" style={{ textDecoration: 'none' }}>
            <Download size={14} /> EXPORT JSON
          </a>
        </div>
      </div>

      {/* Security Report Preview Document */}
      {loading ? (
        <div className="empty-state">Loading Security Report...</div>
      ) : report ? (
        <div
          className="glass-card printable-report"
          style={{ padding: 32, display: 'flex', flexDirection: 'column', gap: 24 }}
        >
          {/* Header */}
          <div style={{ borderBottom: '2px solid var(--border-bright)', paddingBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 900, letterSpacing: 2, color: 'var(--accent-cyan)' }}>
                SENTINELX IDS SECURITY REPORT
              </h1>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                Generated: {new Date(report.generated_at).toLocaleString()}
              </div>
            </div>
            <div style={{ textAlign: 'right', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              <div>Period Start: {new Date(report.period_start).toLocaleDateString()}</div>
              <div>Period End: {new Date(report.period_end).toLocaleDateString()}</div>
            </div>
          </div>

          {/* Key Metrics Grid */}
          <div>
            <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: 1, color: 'var(--text-muted)', marginBottom: 12 }}>
              1. EXECUTIVE SUMMARY & TRAFFIC STATS
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: 12, borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)' }}>TOTAL PACKETS</div>
                <div style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                  {report.total_packets.toLocaleString()}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.3)', padding: 12, borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)' }}>CONNECTIONS</div>
                <div style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>
                  {report.total_connections.toLocaleString()}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.3)', padding: 12, borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)' }}>THREATS DETECTED</div>
                <div style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--threat-high)' }}>
                  {report.threats_detected}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.3)', padding: 12, borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)' }}>CRITICAL ALERTS</div>
                <div style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--threat-critical)' }}>
                  {report.critical_alerts}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.3)', padding: 12, borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)' }}>SUSPICIOUS IPS</div>
                <div style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--threat-medium)' }}>
                  {report.suspicious_ips}
                </div>
              </div>
            </div>
          </div>

          {/* Top Vectors */}
          <div className="grid-2">
            <div>
              <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: 1, color: 'var(--text-muted)', marginBottom: 8 }}>
                2. TOP ATTACK TYPES
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                {report.top_attacks.map(att => (
                  <div key={att.attack_type} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                    <span>{att.attack_type.replace('_', ' ')}</span>
                    <strong style={{ color: 'var(--threat-high)' }}>{att.count} occurrences</strong>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: 1, color: 'var(--text-muted)', marginBottom: 8 }}>
                3. TOP OFFENDING SOURCE IPS
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                {report.top_source_ips.map(item => (
                  <div key={item.ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                    <span style={{ color: 'var(--accent-cyan)' }}>{item.ip}</span>
                    <strong>{item.count} alerts</strong>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Recommendations */}
          <div>
            <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: 1, color: 'var(--accent-green)', marginBottom: 8 }}>
              4. SECURITY RECOMMENDATIONS
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {report.recommendations.map((rec, i) => (
                <div key={i} style={{ fontSize: 12, display: 'flex', gap: 8, alignItems: 'flex-start', background: 'rgba(0,255,136,0.04)', padding: 8, borderRadius: 6, border: '1px solid rgba(0,255,136,0.15)' }}>
                  <span>🛡️</span>
                  <div>{rec}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
