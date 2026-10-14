import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Activity, Bell, Shield, Search,
  FileSearch, Settings, BarChart3, Cpu, Network
} from 'lucide-react';

const NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/traffic',   icon: Activity,        label: 'Live Traffic' },
  { to: '/alerts',    icon: Bell,            label: 'Alerts' },
  { to: '/threats',   icon: Shield,          label: 'Threat Intel' },
  { to: '/ip',        icon: Search,          label: 'IP Analysis' },
  { to: '/pcap',      icon: FileSearch,      label: 'PCAP Analyzer' },
  { to: '/rules',     icon: Cpu,             label: 'Detection Rules' },
  { to: '/reports',   icon: BarChart3,       label: 'Reports' },
  { to: '/settings',  icon: Settings,        label: 'Settings' },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-text">SENTINELX</div>
        <div className="sidebar-logo-sub">INTRUSION DETECTION SYSTEM</div>
      </div>
      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Navigation</div>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon className="nav-icon" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
