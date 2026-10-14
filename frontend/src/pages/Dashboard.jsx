import React, { useState, useEffect } from 'react';
import {
  Activity, Shield, AlertOctagon, Eye, Play, Square, RefreshCw, Zap, Crosshair, Lock, Flame, Radio
} from 'lucide-react';
import toast from 'react-hot-toast';
import StatCard from '../components/StatCard';
import AlertBadge from '../components/AlertBadge';
import ThreatMeter from '../components/ThreatMeter';
import NetworkMap from '../components/NetworkMap';
import DemoPanel from '../components/DemoPanel';
import TrafficChart from '../charts/TrafficChart';
import ThreatDistribution from '../charts/ThreatDistribution';
import { getStats, getAlerts, getSuspiciousIPs, startDemo, stopDemo, getDemoStatus, simulateAttack } from '../services/api';

const DEFAULT_STAGES = [
  { key: 'NORMAL_TRAFFIC', title: 'Normal Baseline Traffic', description: 'Learning what normal looks like.', detection_rule_text: 'Observes benign HTTP/HTTPS/DNS traffic to calibrate baseline.' },
  { key: 'PORT_SCAN', title: 'TCP SYN Port Scan', description: 'Reconnaissance attack scanning multiple ports.', detection_rule_text: 'SYN-only packets to >= 20 distinct ports within 10s.' },
  { key: 'BRUTE_FORCE', title: 'SSH Authentication Brute Force', description: 'Repeated connection attempts to crack SSH authentication.', detection_rule_text: '>= 10 SYN attempts to auth port 22:SSH within 30s.' },
  { key: 'SYN_FLOOD', title: 'TCP SYN Flood DoS', description: 'High-volume half-open TCP connection flood.', detection_rule_text: '>= 100 SYN packets from a single source within 5s.' },
  { key: 'ICMP_FLOOD', title: 'ICMP Ping Flood DoS', description: 'Volumetric ICMP echo request flood.', detection_rule_text: '>= 50 ICMP packets from a single source within 5s.' },
  { key: 'TRAFFIC_SPIKE', title: 'Volumetric DDoS Spike', description: 'Multi-source volumetric DDoS spike.', detection_rule_text: 'Global inbound PPS exceeds baseline x 3.0 x 2.' },
  { key: 'SUMMARY', title: 'Scenario Complete', description: 'Demo scenario completed successfully.', detection_rule_text: 'All detection algorithms evaluated against real-time pipeline.' },
];

export default function Dashboard({ wsData, onSelectAlert, onSelectIP }) {
  const [stats, setStats] = useState({
    packets_analyzed: 0,
    threats_detected: 0,
    critical_alerts: 0,
    suspicious_ips: 0,
    traffic_bytes: 0,
    is_capturing: false,
    demo_mode: false,
  });

  const [alerts, setAlerts] = useState([]);
  const [suspiciousIPs, setSuspiciousIPs] = useState([]);
  const [demoActive, setDemoActive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [injecting, setInjecting] = useState(null);

  const [demoState, setDemoState] = useState({
    active: false,
    finished: false,
    runId: null,
    currentStep: 0,
    totalSteps: DEFAULT_STAGES.length,
    currentStageKey: null,
    progressPct: 0,
    stages: DEFAULT_STAGES,
    stageResults: {},
    summary: null,
  });

  // Sync WS data
  useEffect(() => {
    if (wsData?.stats) {
      setStats(prev => ({ ...prev, ...wsData.stats }));
      if (wsData.stats.demo_mode) {
        setDemoState(prev => ({ ...prev, active: true }));
      }
    }
    if (wsData?.alert) {
      setAlerts(prev => [wsData.alert, ...prev.slice(0, 19)]);
    }
    if (wsData?.demoStarted) {
      const d = wsData.demoStarted;
      setDemoState({
        active: true,
        finished: false,
        runId: d.run_id,
        currentStep: 0,
        totalSteps: d.total_steps || DEFAULT_STAGES.length,
        currentStageKey: 'NORMAL_TRAFFIC',
        progressPct: 0,
        stages: d.stages || DEFAULT_STAGES,
        stageResults: {},
        summary: null,
      });
    }
    if (wsData?.demoStage) {
      const s = wsData.demoStage;
      setDemoState(prev => ({
        ...prev,
        active: true,
        currentStep: s.step,
        totalSteps: s.total,
        currentStageKey: s.key,
        progressPct: s.progress_pct,
      }));
    }
    if (wsData?.demoStageResult) {
      const r = wsData.demoStageResult;
      setDemoState(prev => ({
        ...prev,
        stageResults: {
          ...prev.stageResults,
          [r.key]: r,
        },
      }));
    }
    if (wsData?.demoFinished) {
      const f = wsData.demoFinished;
      setDemoState(prev => ({
        ...prev,
        active: false,
        finished: true,
        progressPct: 100,
        currentStageKey: null,
        summary: f,
      }));
      fetchData();
    }
  }, [wsData]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [s, a, ips, demo] = await Promise.all([
        getStats().catch(() => null),
        getAlerts({ limit: 10 }).catch(() => []),
        getSuspiciousIPs(5).catch(() => []),
        getDemoStatus().catch(() => ({ active: false })),
      ]);
      if (s) setStats(s);
      if (a) setAlerts(a);
      if (ips) setSuspiciousIPs(ips);
      if (demo) setDemoActive(demo.active);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const toggleDemo = async () => {
    if (demoActive) {
      await stopDemo();
      setDemoActive(false);
      toast.success('Simulation mode stopped');
    } else {
      await startDemo();
      setDemoActive(true);
      toast.success('Simulation mode active');
    }
    fetchData();
  };

  const handleSimulateAttack = async (type) => {
    try {
      setInjecting(type);
      await simulateAttack(type);
      toast.success(`Injected ${type.replace('_', ' ')} traffic! IDS evaluating real-time rules…`);
      setTimeout(fetchData, 1800);
    } catch (err) {
      toast.error('Failed to inject attack traffic');
    } finally {
      setInjecting(null);
    }
  };

  const highestThreatScore = suspiciousIPs.length > 0 ? suspiciousIPs[0].threat_score : 45;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Guided Simulation Scenario Stepper Panel */}
      <DemoPanel
        demoState={demoState}
        onDismiss={() => setDemoState(prev => ({ ...prev, active: false, finished: false }))}
        onDataCleared={() => fetchData()}
      />

      {/* Real-time Intrusion Attack Trigger Panel */}
      <div className="glass-card" style={{ padding: 18, borderLeft: '4px solid var(--accent-cyan)' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 10, height: 10, borderRadius: '50%', background: 'var(--accent-green)',
              boxShadow: '0 0 10px var(--accent-green)', animation: 'pulse 1.5s infinite'
            }} />
            <div>
              <div style={{ fontWeight: 800, letterSpacing: 1.2, fontSize: 13, color: 'var(--text-primary)' }}>
                REAL-TIME IDS INTRUSION DETECTOR ONLINE
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                Rule Engine evaluating live traffic counters every 1.5s • Trigger attacks below to test real-time detection
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            <button
              onClick={() => handleSimulateAttack('PORT_SCAN')}
              disabled={injecting === 'PORT_SCAN'}
              className="btn btn-ghost btn-sm"
              style={{ border: '1px solid rgba(0, 229, 255, 0.3)', color: 'var(--accent-cyan)' }}
            >
              <Crosshair size={13} /> {injecting === 'PORT_SCAN' ? 'Injecting…' : 'Port Scan'}
            </button>

            <button
              onClick={() => handleSimulateAttack('BRUTE_FORCE')}
              disabled={injecting === 'BRUTE_FORCE'}
              className="btn btn-ghost btn-sm"
              style={{ border: '1px solid rgba(255, 170, 0, 0.3)', color: 'var(--threat-medium)' }}
            >
              <Lock size={13} /> {injecting === 'BRUTE_FORCE' ? 'Injecting…' : 'Brute Force'}
            </button>

            <button
              onClick={() => handleSimulateAttack('SYN_FLOOD')}
              disabled={injecting === 'SYN_FLOOD'}
              className="btn btn-ghost btn-sm"
              style={{ border: '1px solid rgba(255, 34, 68, 0.4)', color: 'var(--threat-critical)' }}
            >
              <Flame size={13} /> {injecting === 'SYN_FLOOD' ? 'Injecting…' : 'SYN Flood'}
            </button>

            <button
              onClick={() => handleSimulateAttack('ICMP_FLOOD')}
              disabled={injecting === 'ICMP_FLOOD'}
              className="btn btn-ghost btn-sm"
              style={{ border: '1px solid rgba(255, 77, 106, 0.3)', color: 'var(--threat-high)' }}
            >
              <Radio size={13} /> {injecting === 'ICMP_FLOOD' ? 'Injecting…' : 'ICMP Flood'}
            </button>

            <button
              onClick={() => handleSimulateAttack('TRAFFIC_SPIKE')}
              disabled={injecting === 'TRAFFIC_SPIKE'}
              className="btn btn-ghost btn-sm"
              style={{ border: '1px solid rgba(179, 136, 255, 0.4)', color: 'var(--accent-blue)' }}
            >
              <Zap size={13} /> {injecting === 'TRAFFIC_SPIKE' ? 'Injecting…' : 'DoS Spike'}
            </button>

            <button
              onClick={toggleDemo}
              className={`btn ${demoActive ? 'btn-danger' : 'btn-success'} btn-sm`}
            >
              {demoActive ? <Square size={12} /> : <Play size={12} />}
              {demoActive ? 'Pause Sim' : 'Auto Sim'}
            </button>
          </div>
        </div>
      </div>

      {/* Top Stat Cards */}
      <div className="stat-grid">
        <StatCard
          label="System Status"
          value={stats.is_capturing ? 'CAPTURING' : demoActive ? 'SIMULATION' : 'ONLINE'}
          sub="IDS Engine active & monitoring"
          accentColor="var(--accent-green)"
          icon={Activity}
        />
        <StatCard
          label="Packets Analyzed"
          value={stats.packets_analyzed || 0}
          sub="Live traffic sliding-window"
          accentColor="var(--accent-cyan)"
          icon={Activity}
        />
        <StatCard
          label="Threats Detected"
          value={stats.threats_detected || 0}
          sub="Total rule alerts triggered"
          accentColor="var(--threat-high)"
          icon={Shield}
        />
        <StatCard
          label="Critical Alerts"
          value={stats.critical_alerts || 0}
          sub="High severity intrusions"
          accentColor="var(--threat-critical)"
          icon={AlertOctagon}
        />
        <StatCard
          label="Suspicious IPs"
          value={stats.suspicious_ips || 0}
          sub="Threat score > 40"
          accentColor="var(--threat-medium)"
          icon={Eye}
        />
        <StatCard
          label="Network Bandwidth"
          value={`${((stats.traffic_bytes || 0) / 1e6).toFixed(1)} MB`}
          sub="Ingested packet size total"
          accentColor="var(--accent-blue)"
        />
      </div>

      {/* Real-Time Traffic Graph & Threat Distribution */}
      <div className="grid-2">
        <TrafficChart data={wsData?.stats?.pps_history || []} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <ThreatDistribution data={stats.top_attack_types} />
          <div className="glass-card" style={{ padding: 20 }}>
            <ThreatMeter score={highestThreatScore} />
          </div>
        </div>
      </div>

      {/* Network Topology Map */}
      <NetworkMap suspiciousNodes={suspiciousIPs} />

      {/* Recent Security Alerts Table */}
      <div className="glass-card" style={{ padding: 20 }}>
        <div className="section-header">
          <div className="section-title">REAL-TIME DETECTED INTRUSIONS</div>
          <button onClick={fetchData} className="btn btn-ghost btn-sm">
            <RefreshCw size={12} /> Refresh
          </button>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>SEVERITY</th>
                <th>ATTACK TYPE</th>
                <th>SOURCE IP</th>
                <th>DESTINATION IP</th>
                <th>PORT</th>
                <th>PROTOCOL</th>
                <th>STATUS</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: 30, color: 'var(--text-muted)' }}>
                    No intrusions detected yet. Trigger an attack simulation above to test real-time detection.
                  </td>
                </tr>
              ) : (
                alerts.map((a, idx) => (
                  <tr key={a.id || idx}>
                    <td>{a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'Just now'}</td>
                    <td><AlertBadge severity={a.severity} /></td>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                      {(a.attack_type || 'PORT_SCAN').replace('_', ' ')}
                    </td>
                    <td
                      style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                      onClick={() => onSelectIP && onSelectIP(a.src_ip)}
                    >
                      {a.src_ip}
                    </td>
                    <td>{a.dst_ip || '192.168.1.10'}</td>
                    <td>{a.dst_port || a.src_port || '22'}</td>
                    <td>{a.protocol || 'TCP'}</td>
                    <td><span className="badge badge-info">{a.status || 'DETECTED'}</span></td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => onSelectAlert && onSelectAlert(a)}
                      >
                        VIEW
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
