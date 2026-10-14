import React, { useState } from 'react';
import { Shield, Server, Laptop, Router, Globe, AlertTriangle } from 'lucide-react';

export default function NetworkMap({ suspiciousNodes = [] }) {
  const [selectedNode, setSelectedNode] = useState(null);

  const nodes = [
    { id: 'internet', label: 'INTERNET', type: 'cloud', ip: '0.0.0.0/0', x: 250, y: 40, icon: Globe },
    { id: 'router', label: 'ROUTER', type: 'router', ip: '192.168.1.1', x: 250, y: 120, icon: Router },
    { id: 'pc01', label: 'PC-01', type: 'workstation', ip: '192.168.1.10', x: 100, y: 220, icon: Laptop, packets: 1420, conns: 28, threatScore: 12 },
    { id: 'pc02', label: 'PC-02', type: 'workstation', ip: '192.168.1.15', x: 250, y: 220, icon: Laptop, packets: 890, conns: 14, threatScore: 5 },
    { id: 'server', label: 'SRV-MAIN', type: 'server', ip: '192.168.1.50', x: 400, y: 220, icon: Server, packets: 15420, conns: 310, threatScore: 25 },
    {
      id: 'attacker',
      label: 'SUSPICIOUS IP',
      type: 'threat',
      ip: suspiciousNodes[0]?.ip || '45.33.32.156',
      x: 100, y: 310,
      icon: AlertTriangle,
      isThreat: true,
      threatScore: suspiciousNodes[0]?.threat_score || 82,
      packets: 4210,
      conns: 145,
      attacks: ['Port Scan', 'SYN Flood']
    }
  ];

  const connections = [
    { from: 'internet', to: 'router', isAlert: false },
    { from: 'router', to: 'pc01', isAlert: false },
    { from: 'router', to: 'pc02', isAlert: false },
    { from: 'router', to: 'server', isAlert: false },
    { from: 'pc01', to: 'attacker', isAlert: true }
  ];

  const getNode = (id) => nodes.find(n => n.id === id);

  return (
    <div className="glass-card" style={{ padding: 20, position: 'relative' }}>
      <div className="section-header" style={{ marginBottom: 12 }}>
        <div className="section-title">LIVE NETWORK TOPOLOGY MAP</div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Click node to inspect
        </span>
      </div>

      <div style={{ width: '100%', height: 360, position: 'relative', background: 'rgba(5, 8, 16, 0.6)', borderRadius: 12, overflow: 'hidden', border: '1px solid var(--border)' }}>
        <svg style={{ width: '100%', height: '100%', position: 'absolute', inset: 0 }}>
          <defs>
            <linearGradient id="alertLine" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--threat-critical)" />
              <stop offset="100%" stopColor="var(--threat-high)" />
            </linearGradient>
            <linearGradient id="normalLine" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity="0.4" />
              <stop offset="100%" stopColor="var(--accent-blue)" stopOpacity="0.4" />
            </linearGradient>
          </defs>

          {connections.map((c, i) => {
            const n1 = getNode(c.from);
            const n2 = getNode(c.to);
            if (!n1 || !n2) return null;
            return (
              <g key={i}>
                <line
                  x1={n1.x}
                  y1={n1.y}
                  x2={n2.x}
                  y2={n2.y}
                  stroke={c.isAlert ? 'url(#alertLine)' : 'url(#normalLine)'}
                  strokeWidth={c.isAlert ? 2.5 : 1.5}
                  strokeDasharray={c.isAlert ? '4 4' : 'none'}
                />
                {c.isAlert && (
                  <circle r="4" fill="var(--threat-critical)">
                    <animateMotion
                      path={`M${n1.x},${n1.y} L${n2.x},${n2.y}`}
                      dur="2s"
                      repeatCount="indefinite"
                    />
                  </circle>
                )}
              </g>
            );
          })}
        </svg>

        {nodes.map(n => {
          const Icon = n.icon;
          const isSelected = selectedNode?.id === n.id;
          return (
            <div
              key={n.id}
              onClick={() => setSelectedNode(n)}
              style={{
                position: 'absolute',
                left: n.x - 28,
                top: n.y - 28,
                width: 56,
                height: 56,
                borderRadius: '50%',
                background: n.isThreat
                  ? 'rgba(255, 34, 68, 0.15)'
                  : 'rgba(13, 19, 33, 0.9)',
                border: `2px solid ${
                  isSelected
                    ? 'var(--accent-cyan)'
                    : n.isThreat
                    ? 'var(--threat-critical)'
                    : 'var(--border-bright)'
                }`,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                boxShadow: n.isThreat ? '0 0 15px rgba(255, 34, 68, 0.4)' : '0 4px 12px rgba(0,0,0,0.5)',
                transition: 'all 0.2s ease',
                zIndex: 2,
              }}
            >
              <Icon
                size={20}
                color={n.isThreat ? 'var(--threat-critical)' : 'var(--accent-cyan)'}
              />
              <span style={{ fontSize: 9, fontWeight: 700, marginTop: 2, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                {n.label}
              </span>
            </div>
          );
        })}

        {/* Selected Node Details Drawer/Card */}
        {selectedNode && (
          <div
            style={{
              position: 'absolute',
              right: 12,
              top: 12,
              width: 220,
              background: 'rgba(10, 15, 28, 0.95)',
              border: '1px solid var(--border-bright)',
              borderRadius: 8,
              padding: 12,
              fontSize: 11,
              zIndex: 10,
              boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
              backdropFilter: 'blur(10px)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ fontWeight: 800, color: 'var(--accent-cyan)' }}>{selectedNode.label}</span>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 12 }}
              >
                ✕
              </button>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginBottom: 4 }}>
              IP: {selectedNode.ip}
            </div>
            {selectedNode.packets !== undefined && (
              <div style={{ color: 'var(--text-secondary)' }}>Packets: {selectedNode.packets.toLocaleString()}</div>
            )}
            {selectedNode.conns !== undefined && (
              <div style={{ color: 'var(--text-secondary)' }}>Connections: {selectedNode.conns}</div>
            )}
            {selectedNode.threatScore !== undefined && (
              <div style={{ color: selectedNode.threatScore > 50 ? 'var(--threat-critical)' : 'var(--accent-green)', fontWeight: 700, marginTop: 4 }}>
                Threat Score: {selectedNode.threatScore} / 100
              </div>
            )}
            {selectedNode.attacks && (
              <div style={{ marginTop: 6, color: 'var(--threat-high)', fontSize: 10 }}>
                Attacks: {selectedNode.attacks.join(', ')}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
