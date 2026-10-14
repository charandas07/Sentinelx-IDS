import React from 'react';

export function ThreatMeter({ score = 0, showLevel = true }) {
  const val = Math.min(Math.max(Number(score) || 0, 0), 100);

  let color = 'var(--threat-safe)';
  let level = 'SAFE';

  if (val > 80) {
    color = 'var(--threat-critical)';
    level = 'CRITICAL';
  } else if (val > 60) {
    color = 'var(--threat-high)';
    level = 'HIGH';
  } else if (val > 40) {
    color = 'var(--threat-medium)';
    level = 'MEDIUM';
  } else if (val > 20) {
    color = 'var(--threat-low)';
    level = 'LOW';
  }

  // Calculate filled bars for ASCII/block meter representation
  const totalBlocks = 20;
  const filledBlocks = Math.round((val / 100) * totalBlocks);
  const blocksStr = '█'.repeat(filledBlocks) + '░'.repeat(totalBlocks - filledBlocks);

  return (
    <div className="threat-meter" style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '1px', color: 'var(--text-muted)' }}>THREAT SCORE</span>
        <span style={{ fontSize: 14, fontWeight: 800, fontFamily: 'var(--font-mono)', color }}>
          {val.toFixed(1)} / 100
        </span>
      </div>

      <div className="threat-bar-track" style={{ marginBottom: 6 }}>
        <div className="threat-bar-fill" style={{ width: `${val}%`, backgroundColor: color }} />
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', letterSpacing: 1 }}>
          {blocksStr}
        </div>
        {showLevel && (
          <span style={{ fontSize: 11, fontWeight: 800, color, fontFamily: 'var(--font-mono)' }}>
            {level}
          </span>
        )}
      </div>
    </div>
  );
}

export default ThreatMeter;
