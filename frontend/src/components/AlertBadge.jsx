export function AlertBadge({ severity }) {
  const sev = (severity || 'INFO').toUpperCase();
  const clsMap = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
    INFO: 'badge-info',
    SAFE: 'badge-safe',
    SIMULATION: 'badge-sim',
  };
  return <span className={`badge ${clsMap[sev] || 'badge-info'}`}>{sev}</span>;
}

export default AlertBadge;
