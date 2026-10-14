import React, { useState } from 'react';
import { Upload, FileSearch, ShieldAlert, CheckCircle, AlertTriangle } from 'lucide-react';
import AlertBadge from '../components/AlertBadge';
import ThreatMeter from '../components/ThreatMeter';
import { uploadPCAP } from '../services/api';

export default function PCAPAnalyzer() {
  const [file, setFile] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleRunAnalysis = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      const res = await uploadPCAP(file);
      setReport(res);
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed. Please check file format.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* File Upload Header */}
      <div className="glass-card" style={{ padding: 24 }}>
        <div className="section-header" style={{ marginBottom: 16 }}>
          <div className="section-title">PCAP / PCAPNG OFF-LINE TRAFFIC ANALYZER</div>
        </div>

        <div
          style={{
            border: '2px dashed var(--border-bright)',
            borderRadius: 12,
            padding: 30,
            textAlign: 'center',
            background: 'rgba(0,0,0,0.2)',
            cursor: 'pointer',
          }}
          onClick={() => document.getElementById('pcap-input').click()}
        >
          <Upload size={36} color="var(--accent-cyan)" style={{ marginBottom: 12 }} />
          <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>
            {file ? file.name : 'Select or Drop PCAP File Here'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Supports .pcap and .pcapng network capture files up to 50 MB
          </div>
          <input
            id="pcap-input"
            type="file"
            accept=".pcap,.pcapng"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
        </div>

        {error && (
          <div style={{ marginTop: 12, color: 'var(--threat-critical)', fontSize: 12 }}>
            ⚠️ {error}
          </div>
        )}

        <div style={{ marginTop: 16, display: 'flex', justifyContent: 'flex-end' }}>
          <button
            className="btn btn-primary"
            disabled={!file || loading}
            onClick={handleRunAnalysis}
            style={{ padding: '10px 24px' }}
          >
            <FileSearch size={16} />
            {loading ? 'ANALYZING PCAP PACKETS...' : 'RUN IDS ANALYSIS'}
          </button>
        </div>
      </div>

      {/* Analysis Results Report */}
      {loading ? (
        <div className="empty-state">
          <div className="loading-pulse">
            <div className="loading-dot" />
            <div className="loading-dot" />
            <div className="loading-dot" />
          </div>
          <div>Parsing packet buffers and running detection rules engine...</div>
        </div>
      ) : report ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Summary Banner */}
          <div className="glass-card" style={{ padding: 24, display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>PACKETS ANALYZED</div>
              <div style={{ fontSize: 24, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                {report.packets_analyzed.toLocaleString()}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>POTENTIAL ATTACKS</div>
              <div style={{ fontSize: 24, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--threat-high)' }}>
                {report.potential_attacks.length}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>ALERTS GENERATED</div>
              <div style={{ fontSize: 24, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--threat-critical)' }}>
                {report.alerts_generated}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>ANALYSIS TIME</div>
              <div style={{ fontSize: 24, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-green)' }}>
                {report.analysis_time_seconds}s
              </div>
            </div>
          </div>

          <div className="grid-2">
            {/* Threat Meter */}
            <div className="glass-card" style={{ padding: 20 }}>
              <div className="section-header">
                <div className="section-title">OVERALL PCAP THREAT SCORE</div>
              </div>
              <ThreatMeter score={report.overall_threat_score} />
            </div>

            {/* Identified Potential Attacks */}
            <div className="glass-card" style={{ padding: 20 }}>
              <div className="section-header">
                <div className="section-title">IDENTIFIED ATTACK PATTERNS</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {report.potential_attacks.length === 0 ? (
                  <div style={{ color: 'var(--accent-green)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <CheckCircle size={14} /> No malicious attack vectors identified in capture file.
                  </div>
                ) : (
                  report.potential_attacks.map((att, idx) => (
                    <div key={idx} style={{ background: 'rgba(255,34,68,0.1)', border: '1px solid rgba(255,34,68,0.3)', padding: 10, borderRadius: 6, fontSize: 12, color: 'var(--threat-critical)', fontFamily: 'var(--font-mono)' }}>
                      🚨 {att}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Top Source IPs & Target Ports */}
          <div className="grid-2">
            <div className="glass-card" style={{ padding: 20 }}>
              <div className="section-header">
                <div className="section-title">TOP SOURCE IPS IN CAPTURE</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {report.top_src_ips.map(item => (
                  <div key={item.key} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, fontFamily: 'var(--font-mono)', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                    <span style={{ color: 'var(--accent-cyan)' }}>{item.key}</span>
                    <span>{item.count} pkts</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-card" style={{ padding: 20 }}>
              <div className="section-header">
                <div className="section-title">TOP TARGETED PORTS</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {report.top_ports.map(item => (
                  <div key={item.key} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, fontFamily: 'var(--font-mono)', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                    <span style={{ color: 'var(--accent-blue)' }}>Port {item.key}</span>
                    <span>{item.count} pkts</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
