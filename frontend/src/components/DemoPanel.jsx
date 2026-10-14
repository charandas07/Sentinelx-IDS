import React from 'react';
import {
  Play,
  Square,
  CheckCircle2,
  XCircle,
  Clock,
  RotateCcw,
  Trash2,
  Loader2,
  ShieldAlert,
  Radio,
  Zap,
  Terminal,
  Activity,
  Layers,
  ChevronRight,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { startDemo, stopDemo, clearDemoData } from '../services/api';

const STAGE_ICONS = {
  NORMAL_TRAFFIC: Activity,
  PORT_SCAN: RadarIcon,
  BRUTE_FORCE: Terminal,
  SYN_FLOOD: Zap,
  ICMP_FLOOD: Radio,
  TRAFFIC_SPIKE: ShieldAlert,
  SUMMARY: CheckCircle2,
};

function RadarIcon(props) {
  return <Activity {...props} />;
}

export default function DemoPanel({
  demoState,
  onDismiss,
  onDataCleared,
}) {
  const {
    active,
    finished,
    runId,
    currentStep,
    totalSteps,
    currentStageKey,
    progressPct,
    stages,
    stageResults,
    summary,
  } = demoState;

  if (!active && !finished) {
    return null;
  }

  const handleStop = async () => {
    try {
      await stopDemo();
      toast.success('Simulation stopped');
    } catch {
      toast.error('Failed to stop simulation');
    }
  };

  const handleRunAgain = async () => {
    try {
      await startDemo('guided');
      toast.success('Restarting guided demo');
    } catch {
      toast.error('Failed to restart simulation');
    }
  };

  const handleClearData = async () => {
    try {
      const res = await clearDemoData();
      toast.success('Simulation data cleared');
      if (onDataCleared) onDataCleared(res);
      if (onDismiss) onDismiss();
    } catch {
      toast.error('Failed to clear simulation data');
    }
  };

  const currentStageInfo = stages.find((s) => s.key === currentStageKey) || stages[currentStep];

  return (
    <div
      className="glass-card"
      style={{
        padding: 24,
        border: '1px solid var(--accent-purple, #aa88ff)',
        borderRadius: 16,
        background: 'linear-gradient(135deg, rgba(30, 20, 50, 0.7) 0%, rgba(15, 20, 35, 0.85) 100%)',
        boxShadow: '0 8px 32px rgba(136, 68, 255, 0.15)',
        display: 'flex',
        flexDirection: 'column',
        gap: 20,
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'rgba(170, 136, 255, 0.15)',
              border: '1px solid rgba(170, 136, 255, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#aa88ff',
            }}
          >
            <Layers size={20} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 16, fontWeight: 800, letterSpacing: '0.5px' }}>
                Guided Demo Pipeline
              </span>
              <span
                className="badge-sim"
                style={{
                  padding: '2px 8px',
                  borderRadius: 6,
                  fontSize: 10,
                  fontWeight: 700,
                  background: 'rgba(255, 136, 0, 0.2)',
                  color: 'var(--accent-orange, #ff8800)',
                  border: '1px solid rgba(255, 136, 0, 0.4)',
                }}
              >
                SIMULATION
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              Deterministic real-time intrusion detection scenario (60–75s)
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {active && (
            <button
              onClick={handleStop}
              className="btn btn-danger"
              style={{ padding: '6px 14px', fontSize: 12, gap: 6 }}
            >
              <Square size={13} />
              Stop
            </button>
          )}
          {finished && onDismiss && (
            <button
              onClick={onDismiss}
              className="btn btn-secondary"
              style={{ padding: '6px 14px', fontSize: 12 }}
            >
              Dismiss
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 6, color: 'var(--text-muted)' }}>
          <span>
            {active ? `Stage ${(currentStep || 0) + 1} of ${totalSteps || stages.length}` : 'Scenario Complete'}
          </span>
          <span style={{ fontFamily: 'var(--font-mono)' }}>{progressPct}%</span>
        </div>
        <div
          style={{
            height: 6,
            background: 'rgba(255, 255, 255, 0.08)',
            borderRadius: 3,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              height: '100%',
              width: `${progressPct}%`,
              background: finished
                ? 'linear-gradient(90deg, #aa88ff, var(--accent-green))'
                : 'linear-gradient(90deg, var(--accent-cyan), #aa88ff)',
              transition: 'width 0.4s ease',
            }}
          />
        </div>
      </div>

      {/* Current Stage Highlight Box (when active) */}
      {active && currentStageInfo && (
        <div
          style={{
            padding: '14px 18px',
            background: 'rgba(170, 136, 255, 0.08)',
            borderLeft: '4px solid #aa88ff',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            gap: 14,
          }}
        >
          <Loader2 size={20} color="#aa88ff" style={{ animation: 'spin 1.5s linear infinite', flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#aa88ff', letterSpacing: 1, textTransform: 'uppercase' }}>
              CURRENT STAGE: {currentStageInfo.title}
            </div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginTop: 2 }}>
              "{currentStageInfo.description}"
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
              Rule: {currentStageInfo.detection_rule_text}
            </div>
          </div>
        </div>
      )}

      {/* Vertical Stepper Rows */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {stages.map((stg, idx) => {
          const isCurrent = active && currentStageKey === stg.key;
          const result = stageResults[stg.key];
          const isPassed = result?.detected;
          const isMissed = result && !result.detected && !result.skipped;
          const isSkipped = result?.skipped;
          const isPending = !isCurrent && !result && (!active || idx > currentStep);

          const IconComp = STAGE_ICONS[stg.key] || ChevronRight;

          let statusBadge = (
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Pending</span>
          );

          if (isCurrent) {
            statusBadge = (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#aa88ff', fontSize: 12, fontWeight: 700 }}>
                <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} />
                Evaluating…
              </span>
            );
          } else if (isPassed) {
            statusBadge = (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent-green)', fontSize: 12, fontWeight: 700 }}>
                <CheckCircle2 size={15} />
                Detected {result.latency_s ? `in ${result.latency_s}s` : ''}
              </span>
            );
          } else if (isMissed) {
            statusBadge = (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--threat-high)', fontSize: 12, fontWeight: 700 }}>
                <XCircle size={15} />
                Missed
              </span>
            );
          } else if (isSkipped) {
            statusBadge = (
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                Skipped (rule disabled)
              </span>
            );
          } else if (stg.key === 'NORMAL_TRAFFIC' && idx < currentStep) {
            statusBadge = (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent-green)', fontSize: 12 }}>
                <CheckCircle2 size={15} />
                Calibrated
              </span>
            );
          }

          return (
            <div
              key={stg.key}
              style={{
                padding: '10px 14px',
                borderRadius: 8,
                background: isCurrent ? 'rgba(170, 136, 255, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                border: isCurrent ? '1px solid rgba(170, 136, 255, 0.3)' : '1px solid transparent',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div
                  style={{
                    width: 28,
                    height: 28,
                    borderRadius: '50%',
                    background: isCurrent
                      ? 'rgba(170, 136, 255, 0.2)'
                      : isPassed
                      ? 'rgba(0, 230, 118, 0.15)'
                      : 'rgba(255, 255, 255, 0.05)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: isCurrent
                      ? '#aa88ff'
                      : isPassed
                      ? 'var(--accent-green)'
                      : 'var(--text-muted)',
                  }}
                >
                  <IconComp size={14} />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>
                    {stg.title}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    {stg.description}
                  </div>
                </div>
              </div>

              <div>{statusBadge}</div>
            </div>
          );
        })}
      </div>

      {/* Summary Card when Finished */}
      {finished && summary && (
        <div
          style={{
            padding: 18,
            borderRadius: 12,
            background: 'rgba(0, 230, 118, 0.08)',
            border: '1px solid rgba(0, 230, 118, 0.3)',
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--accent-green)' }}>
                {summary.cancelled ? 'Demo Cancelled' : 'Scenario Evaluation Complete'}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-primary)', marginTop: 2 }}>
                <strong>{summary.detected_count}/{summary.attack_stages || 5}</strong> attack types detected | Avg detection time: <strong>{summary.avg_latency_s}s</strong> | Total alerts: <strong>{summary.total_alerts}</strong>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <button
                onClick={handleRunAgain}
                className="btn btn-primary"
                style={{ padding: '7px 14px', fontSize: 12, gap: 6 }}
              >
                <RotateCcw size={13} />
                Run again
              </button>
              <button
                onClick={handleClearData}
                className="btn btn-secondary"
                style={{ padding: '7px 14px', fontSize: 12, gap: 6, color: 'var(--threat-high)' }}
              >
                <Trash2 size={13} />
                Clear simulation data
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
