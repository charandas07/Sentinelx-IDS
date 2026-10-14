import React, { useState, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import toast, { Toaster } from 'react-hot-toast';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import LiveTraffic from './pages/LiveTraffic';
import Alerts from './pages/Alerts';
import ThreatIntelligence from './pages/ThreatIntelligence';
import IPAnalysis from './pages/IPAnalysis';
import PCAPAnalyzer from './pages/PCAPAnalyzer';
import DetectionRules from './pages/DetectionRules';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import { useWebSocket } from './hooks/useWebSocket';

export default function App() {
  const [wsData, setWsData] = useState({});
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedIP, setSelectedIP] = useState('');

  const onStats = useCallback((data) => {
    setWsData(prev => ({ ...prev, stats: data }));
  }, []);

  const onAlert = useCallback((data) => {
    setWsData(prev => ({ ...prev, alert: data }));
  }, []);

  const onTraffic = useCallback((data) => {
    setWsData(prev => ({ ...prev, traffic: data }));
  }, []);

  const onNotification = useCallback((data) => {
    toast((t) => (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <strong style={{ color: 'var(--threat-critical)' }}>{data.title || '🚨 SECURITY ALERT'}</strong>
        <div style={{ fontSize: 11 }}>{data.message}</div>
        <div style={{ fontSize: 10, opacity: 0.8, fontFamily: 'var(--font-mono)' }}>
          IP: {data.src_ip} | Threat Score: {data.threat_score}
        </div>
      </div>
    ), {
      duration: 5000,
      style: {
        background: 'rgba(10, 15, 28, 0.95)',
        color: '#fff',
        border: '1px solid var(--threat-critical)',
        boxShadow: '0 0 20px rgba(255,34,68,0.3)',
      },
    });
  }, []);

  const onDemoStarted = useCallback((data) => {
    setWsData(prev => ({ ...prev, demoStarted: data }));
  }, []);

  const onDemoStage = useCallback((data) => {
    setWsData(prev => ({ ...prev, demoStage: data }));
  }, []);

  const onDemoStageResult = useCallback((data) => {
    setWsData(prev => ({ ...prev, demoStageResult: data }));
  }, []);

  const onDemoFinished = useCallback((data) => {
    setWsData(prev => ({ ...prev, demoFinished: data }));
  }, []);

  const { connected } = useWebSocket({
    onStats,
    onAlert,
    onTraffic,
    onNotification,
    onDemoStarted,
    onDemoStage,
    onDemoStageResult,
    onDemoFinished,
  });

  return (
    <BrowserRouter>
      <Toaster position="top-right" />
      <Routes>
        <Route path="/" element={<Login />} />
        <Route element={<Layout wsConnected={connected} wsData={wsData} />}>
          <Route
            path="/dashboard"
            element={
              <Dashboard
                wsData={wsData}
                onSelectAlert={(a) => { setSelectedAlert(a); }}
                onSelectIP={(ip) => { setSelectedIP(ip); }}
              />
            }
          />
          <Route path="/traffic" element={<LiveTraffic wsData={wsData} />} />
          <Route
            path="/alerts"
            element={
              <Alerts
                selectedAlert={selectedAlert}
                onClearSelectedAlert={() => setSelectedAlert(null)}
              />
            }
          />
          <Route
            path="/threats"
            element={
              <ThreatIntelligence
                onSelectIP={(ip) => setSelectedIP(ip)}
              />
            }
          />
          <Route path="/ip" element={<IPAnalysis initialIP={selectedIP} />} />
          <Route path="/pcap" element={<PCAPAnalyzer />} />
          <Route path="/rules" element={<DetectionRules />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
