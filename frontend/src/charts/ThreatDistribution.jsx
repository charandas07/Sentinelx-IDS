import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';

const COLORS = [
  '#00d4ff', // Cyan - Port Scan
  '#ff8800', // Orange - Brute Force
  '#ff2244', // Red - DoS / SYN
  '#ffcc00', // Yellow - ICMP Flood
  '#8844ff', // Purple - Suspicious TCP
  '#00ff88', // Green - Other
];

export default function ThreatDistribution({ data = [] }) {
  const chartData = data.length > 0 ? data.map(d => ({
    name: (d.attack_type || d.name || 'Other').replace('_', ' '),
    value: d.count || d.value || 1,
  })) : [
    { name: 'Port Scan', value: 35 },
    { name: 'Brute Force', value: 25 },
    { name: 'DoS / SYN', value: 15 },
    { name: 'ICMP Flood', value: 10 },
    { name: 'Suspicious TCP', value: 10 },
    { name: 'Other', value: 5 },
  ];

  return (
    <div className="glass-card" style={{ padding: 20, height: '100%' }}>
      <div className="section-header">
        <div className="section-title">THREAT DISTRIBUTION</div>
      </div>
      <div style={{ width: '100%', height: 240 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={85}
              paddingAngle={4}
              dataKey="value"
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} stroke="rgba(0,0,0,0.5)" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(10, 15, 28, 0.95)',
                border: '1px solid var(--border-bright)',
                borderRadius: '8px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
              }}
            />
            <Legend
              layout="horizontal"
              verticalAlign="bottom"
              align="center"
              iconSize={8}
              wrapperStyle={{ fontSize: '11px', color: 'var(--text-secondary)' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
