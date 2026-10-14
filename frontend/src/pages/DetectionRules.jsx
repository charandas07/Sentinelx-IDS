import React, { useState, useEffect } from 'react';
import { Save, RotateCcw, Cpu } from 'lucide-react';
import AlertBadge from '../components/AlertBadge';
import { getRules, updateRule, resetRule } from '../services/api';

export default function DetectionRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchRules = async () => {
    try {
      const data = await getRules();
      setRules(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggleRule = async (rule) => {
    try {
      const updated = await updateRule(rule.id, { enabled: !rule.enabled });
      setRules(rules.map(r => r.id === rule.id ? updated : r));
    } catch (e) {
      console.error(e);
    }
  };

  const handleChangeThreshold = async (rule, value) => {
    const val = parseFloat(value);
    if (isNaN(val)) return;
    try {
      const updated = await updateRule(rule.id, { threshold: val });
      setRules(rules.map(r => r.id === rule.id ? updated : r));
    } catch (e) {
      console.error(e);
    }
  };

  const handleChangeSeverity = async (rule, severity) => {
    try {
      const updated = await updateRule(rule.id, { severity });
      setRules(rules.map(r => r.id === rule.id ? updated : r));
    } catch (e) {
      console.error(e);
    }
  };

  const handleResetRule = async (id) => {
    try {
      const res = await resetRule(id);
      setRules(rules.map(r => r.id === id ? res : r));
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="section-header">
        <div className="section-title">IDS DETECTION RULES CONFIGURATION</div>
      </div>

      <div className="glass-card" style={{ padding: 20 }}>
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>STATUS</th>
                <th>RULE NAME</th>
                <th>ATTACK TYPE</th>
                <th>THRESHOLD</th>
                <th>WINDOW (SEC)</th>
                <th>SEVERITY</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(r => (
                <tr key={r.id}>
                  <td>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={r.enabled}
                        onChange={() => handleToggleRule(r)}
                      />
                      <span className="toggle-slider" />
                    </label>
                  </td>
                  <td>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{r.display_name}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{r.description}</div>
                  </td>
                  <td><span className="badge badge-info">{r.attack_type}</span></td>
                  <td style={{ width: 110 }}>
                    <input
                      type="number"
                      className="input"
                      style={{ padding: '4px 8px', fontSize: 11 }}
                      value={r.threshold || ''}
                      onChange={e => handleChangeThreshold(r, e.target.value)}
                    />
                  </td>
                  <td style={{ width: 90, fontFamily: 'var(--font-mono)' }}>
                    {r.time_window || 10}s
                  </td>
                  <td>
                    <select
                      className="input"
                      style={{ padding: '4px 8px', fontSize: 11, width: 110 }}
                      value={r.severity}
                      onChange={e => handleChangeSeverity(r, e.target.value)}
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => handleResetRule(r.id)}
                      title="Reset rule to default"
                    >
                      <RotateCcw size={12} /> Reset
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
