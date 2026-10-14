import React, { useState, useEffect } from 'react';
import { Pause, Play, Download, Search, RefreshCw } from 'lucide-react';
import { getTraffic, exportReportCSV } from '../services/api';

export default function LiveTraffic({ wsData }) {
  const [packets, setPackets] = useState([]);
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');

  useEffect(() => {
    if (!paused && wsData?.traffic?.packets) {
      setPackets(prev => [...wsData.traffic.packets, ...prev].slice(0, 100));
    }
  }, [wsData, paused]);

  const fetchTraffic = async () => {
    try {
      const data = await getTraffic({ limit: 50 });
      setPackets(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchTraffic();
  }, []);

  const filteredPackets = packets.filter(p => {
    const matchesSearch =
      !search ||
      p.src_ip?.includes(search) ||
      p.dst_ip?.includes(search) ||
      String(p.dst_port)?.includes(search);
    const matchesProto = protocolFilter === 'ALL' || p.protocol?.toUpperCase() === protocolFilter;
    return matchesSearch && matchesProto;
  });

  const exportCSV = () => {
    window.open(exportReportCSV(1), '_blank');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Controls Bar */}
      <div className="glass-card" style={{ padding: 16, display: 'flex', flexWrap: 'wrap', gap: 12, justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flex: 1, minWidth: 260 }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-muted)' }} />
            <input
              type="text"
              className="input"
              style={{ paddingLeft: 30 }}
              placeholder="Search IP or Port..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <select
            className="input"
            style={{ width: 130 }}
            value={protocolFilter}
            onChange={e => setProtocolFilter(e.target.value)}
          >
            <option value="ALL">ALL PROTOCOLS</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="DNS">DNS</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
          </select>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className={`btn ${paused ? 'btn-success' : 'btn-ghost'}`}
            onClick={() => setPaused(!paused)}
          >
            {paused ? <Play size={14} /> : <Pause size={14} />}
            {paused ? 'RESUME STREAM' : 'PAUSE STREAM'}
          </button>
          <button className="btn btn-primary" onClick={exportCSV}>
            <Download size={14} /> EXPORT CSV
          </button>
          <button className="btn btn-ghost" onClick={fetchTraffic}>
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Packet Stream Table */}
      <div className="glass-card" style={{ padding: 20 }}>
        <div className="section-header">
          <div className="section-title">REAL-TIME PACKET FLOWS</div>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            Showing {filteredPackets.length} packets
          </span>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>SOURCE</th>
                <th>DESTINATION</th>
                <th>PROTOCOL</th>
                <th>SRC PORT</th>
                <th>DST PORT</th>
                <th>SIZE (BYTES)</th>
                <th>FLAGS</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                    No matching packet flows observed. Enable Demo Mode for live traffic stream.
                  </td>
                </tr>
              ) : (
                filteredPackets.map((p, i) => (
                  <tr key={p.id || i}>
                    <td>{p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '22:12:01'}</td>
                    <td style={{ color: 'var(--accent-cyan)' }}>{p.src_ip}</td>
                    <td>{p.dst_ip}</td>
                    <td><span className="badge badge-info">{p.protocol}</span></td>
                    <td>{p.src_port || '--'}</td>
                    <td>{p.dst_port || '--'}</td>
                    <td>{p.packet_size || 54}</td>
                    <td>{p.flags || '--'}</td>
                    <td>
                      <span className={`badge ${p.status === 'SUSPICIOUS' ? 'badge-high' : 'badge-safe'}`}>
                        {p.status || 'NORMAL'}
                      </span>
                      {p.is_simulation && (
                        <span className="badge" style={{ marginLeft: 4, background: 'rgba(255, 165, 0, 0.1)', color: 'orange' }}>
                          SIMULATION
                        </span>
                      )}
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
