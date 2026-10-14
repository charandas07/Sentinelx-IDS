import { useEffect, useRef } from 'react';

export default function StatCard({ label, value, sub, accentColor, icon: Icon }) {
  const numRef = useRef(null);
  const prevRef = useRef(0);

  useEffect(() => {
    const target = typeof value === 'number' ? value : parseFloat(String(value).replace(/[^0-9.]/g, '')) || 0;
    const start = prevRef.current;
    prevRef.current = target;

    if (start === target) return;
    const duration = 600;
    const startTime = performance.now();

    const step = (now) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(start + (target - start) * eased);
      if (numRef.current) {
        numRef.current.textContent = current.toLocaleString();
      }
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value]);

  return (
    <div
      className="glass-card stat-card"
      style={{ '--card-accent': `linear-gradient(90deg, ${accentColor || 'var(--accent-cyan)'}, transparent)` }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div className="stat-card-label">{label}</div>
        {Icon && (
          <div style={{ color: accentColor || 'var(--accent-cyan)', opacity: 0.6 }}>
            <Icon size={16} />
          </div>
        )}
      </div>
      <div className="stat-card-value">
        <span ref={numRef}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
      </div>
      {sub && <div className="stat-card-sub">{sub}</div>}
    </div>
  );
}
