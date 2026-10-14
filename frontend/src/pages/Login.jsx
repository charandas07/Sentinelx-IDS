import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Terminal, Activity } from 'lucide-react';
import api from '../services/api';

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await api.post('/api/login', { username, password });
      if (res.data?.token) {
        localStorage.setItem('token', res.data.token);
        navigate('/dashboard');
      } else {
        setError('Authentication failed: No token returned');
      }
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'Invalid username or password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        height: '100vh',
        width: '100vw',
        background: 'radial-gradient(circle at center, #0f172a 0%, #050810 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}
    >
      <div
        className="glass-card"
        style={{
          width: 420,
          padding: 40,
          borderRadius: 20,
          border: '1px solid var(--border-bright)',
          boxShadow: '0 0 40px rgba(0, 212, 255, 0.15)',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 30 }}>
          <div
            style={{
              width: 64,
              height: 64,
              borderRadius: '50%',
              background: 'rgba(0, 212, 255, 0.1)',
              border: '1px solid var(--accent-cyan)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 16px',
            }}
          >
            <Shield size={32} color="var(--accent-cyan)" />
          </div>
          <h1
            style={{
              fontSize: 24,
              fontWeight: 900,
              letterSpacing: 3,
              background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-green))',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            SENTINELX
          </h1>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: 2, marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            NETWORK INTRUSION DETECTION SYSTEM
          </div>
        </div>

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1, color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
              OPERATOR ID
            </label>
            <input
              type="text"
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              required
            />
          </div>

          <div>
            <label style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1, color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
              ACCESS CODE
            </label>
            <input
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
            />
          </div>

          {error && (
            <div
              style={{
                padding: '10px 12px',
                borderRadius: 8,
                background: 'rgba(255, 68, 68, 0.15)',
                border: '1px solid #ff4444',
                color: '#ff6b6b',
                fontSize: 12,
                fontFamily: 'var(--font-mono)',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <span>⚠</span>
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{ width: '100%', justifyContent: 'center', padding: 12, marginTop: 10, opacity: loading ? 0.7 : 1 }}
          >
            {loading ? '[ AUTHENTICATING... ]' : '[ ENTER SOC ]'}
          </button>
        </form>

        <div style={{ marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-secondary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <Activity size={12} color="var(--accent-green)" /> Monitoring Engine Ready
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <Terminal size={12} color="var(--accent-cyan)" /> Detection Engine Active
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Lock size={12} color="var(--accent-blue)" /> Threat Intelligence Sync
          </div>
        </div>
      </div>
    </div>
  );
}
