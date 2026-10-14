import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Wifi, WifiOff, Play, Square, Loader2 } from 'lucide-react';
import { startDemo, stopDemo, getDemoStatus } from '../services/api';
import toast from 'react-hot-toast';

export default function TopBar({ title, wsConnected, stats }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [time, setTime] = useState(new Date());
  const [simulationActive, setSimulationActive] = useState(stats?.demo_mode || false);
  const [simulationLoading, setSimulationLoading] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // Sync demo mode state from WebSocket stats
  useEffect(() => {
    if (stats?.demo_mode !== undefined) {
      setSimulationActive(stats.demo_mode);
    }
  }, [stats?.demo_mode]);

  const toggleSimulation = useCallback(async () => {
    setSimulationLoading(true);
    try {
      if (simulationActive) {
        await stopDemo();
        setSimulationActive(false);
        toast.success('Simulation stopped');
      } else {
        await startDemo('guided');
        setSimulationActive(true);
        if (location.pathname !== '/dashboard') {
          navigate('/dashboard');
        }
        toast.success('Guided demo started — executing realistic attack pipeline');
      }
    } catch (err) {
      toast.error(simulationActive ? 'Failed to stop simulation' : 'Failed to start simulation');
    } finally {
      setSimulationLoading(false);
    }
  }, [simulationActive, location.pathname, navigate]);

  return (
    <header className="topbar">
      <div className="topbar-title">{title}</div>
      <div className="topbar-right">
        <button
          onClick={toggleSimulation}
          disabled={simulationLoading}
          className={`btn ${simulationActive ? 'btn-danger' : 'btn-success'}`}
          style={{ gap: 8, padding: '8px 16px' }}
          title={simulationActive ? 'Stop simulation mode' : 'Start simulation mode'}
        >
          {simulationLoading ? (
            <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
          ) : simulationActive ? (
            <Square size={14} />
          ) : (
            <Play size={14} />
          )}
          <span style={{ fontWeight: 600, letterSpacing: '0.5px' }}>
            {simulationLoading ? 'Working…' : simulationActive ? 'Stop Simulation' : 'Start Simulation'}
          </span>
        </button>

        {stats?.demo_mode ? (
            <div className="status-badge sim-active" style={{ background: 'rgba(136, 68, 255, 0.12)', color: '#aa88ff', border: '1px solid rgba(136, 68, 255, 0.3)' }}>
                <div className="status-dot" style={{ background: '#aa88ff', boxShadow: '0 0 8px #aa88ff' }} />
                SIMULATION ACTIVE
            </div>
        ) : (
            <div className="status-badge" style={{ background: 'rgba(0, 212, 255, 0.1)', color: 'var(--accent-cyan)', border: '1px solid var(--accent-cyan)' }}>
                <div className="status-dot" style={{ background: 'var(--accent-cyan)' }} />
                LIVE
            </div>
        )}
        
        {stats?.active_iface && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                IFACE: {stats.active_iface}
            </div>
        )}

        {stats?.capture_error && (
            <div style={{ fontSize: 11, color: 'var(--threat-high)' }} title={stats.capture_error}>
                ⚠️ CAPTURE ERROR
            </div>
        )}

        <div className="status-badge">
          <div className="status-dot" />
          SYSTEM ONLINE
        </div>
        {wsConnected !== undefined && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: wsConnected ? 'var(--accent-green)' : 'var(--threat-high)' }}>
            {wsConnected ? <Wifi size={12} /> : <WifiOff size={12} />}
            {wsConnected ? 'CONNECTED' : 'RECONNECTING'}
          </div>
        )}
        <div className="topbar-time">
          {time.toLocaleTimeString('en-US', { hour12: false })}
        </div>
      </div>
    </header>
  );
}
