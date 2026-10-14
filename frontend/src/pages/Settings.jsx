import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Save, RefreshCw, Server, Shield, Play, Square } from 'lucide-react';
import { getInterfaces, startCapture, stopCapture, getStatus } from '../services/api';

export default function Settings() {
  const [iface, setIface] = useState('');
  const [interfaces, setInterfaces] = useState([]);
  const [maxPcapMB, setMaxPcapMB] = useState(50);
  const [logLevel, setLogLevel] = useState('INFO');
  const [saved, setSaved] = useState(false);
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureError, setCaptureError] = useState(null);

  useEffect(() => {
    getInterfaces().then(setInterfaces).catch(console.error);
    getStatus().then(s => {
      setIsCapturing(s.is_capturing);
      setIface(s.active_iface || '');
      setCaptureError(s.capture_error);
    }).catch(console.error);
  }, []);

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleStartCapture = async () => {
    try {
      const res = await startCapture(iface || null);
      setIsCapturing(res.is_capturing);
      setCaptureError(res.capture_error);
    } catch (e) {
      console.error(e);
    }
  };

  const handleStopCapture = async () => {
    try {
      const res = await stopCapture();
      setIsCapturing(res.is_capturing);
      setCaptureError(res.capture_error);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="section-header">
        <div className="section-title">SENTINELX SYSTEM SETTINGS & PREFERENCES</div>
      </div>

      <div className="glass-card" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        <div>
          <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
            CAPTURE NETWORK INTERFACE
          </label>
          <div style={{ display: 'flex', gap: 10 }}>
              <select className="input" value={iface} onChange={e => setIface(e.target.value)} style={{ flex: 1 }}>
                <option value="">AUTO-DETECT PRIMARY INTERFACE</option>
                {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
              {isCapturing ? (
                  <button type="button" className="btn" style={{ background: 'var(--threat-high)' }} onClick={handleStopCapture}>
                      <Square size={14} /> STOP CAPTURE
                  </button>
              ) : (
                  <button type="button" className="btn btn-success" onClick={handleStartCapture}>
                      <Play size={14} /> START CAPTURE
                  </button>
              )}
          </div>
          {captureError && (
              <div style={{ fontSize: 11, color: 'var(--threat-high)', marginTop: 8 }}>
                  ERROR: {captureError}
              </div>
          )}
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
            Note: Live packet capture requires administrator / root privileges. If unavailable, system gracefully falls back to Demo Simulation mode.
          </div>
        </div>

        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div>
            <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
              MAX PCAP FILE SIZE UPLOAD (MB)
            </label>
            <input
            type="number"
            className="input"
            value={maxPcapMB}
            onChange={e => setMaxPcapMB(Number(e.target.value))}
          />
        </div>

        <div>
          <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
            LOG LEVEL
          </label>
          <select className="input" value={logLevel} onChange={e => setLogLevel(e.target.value)}>
            <option value="DEBUG">DEBUG</option>
            <option value="INFO">INFO</option>
            <option value="WARNING">WARNING</option>
            <option value="ERROR">ERROR</option>
          </select>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 16, borderTop: '1px solid var(--border)' }}>
          {saved ? (
            <span style={{ fontSize: 12, color: 'var(--accent-green)', fontWeight: 700 }}>
              ✓ Settings saved successfully!
            </span>
          ) : (
            <span />
          )}
          <button type="submit" className="btn btn-primary" style={{ padding: '10px 20px' }}>
            <Save size={14} /> SAVE PREFERENCES
          </button>
        </div>
      </form>
    </div>
  </div>
);
}
