import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';

const pageTitles = {
  '/dashboard': 'SOC Dashboard',
  '/traffic': 'Live Network Traffic',
  '/alerts': 'Security Alerts',
  '/threats': 'Threat Intelligence',
  '/ip': 'IP Analysis & Forensics',
  '/pcap': 'PCAP File Analyzer',
  '/rules': 'IDS Detection Rules',
  '/reports': 'Security Reports',
  '/settings': 'System Settings',
};

export default function Layout({ wsConnected, wsData }) {
  const location = useLocation();
  const title = pageTitles[location.pathname] || 'SentinelX SOC';

  return (
    <div className="app-layout scanlines">
      <Sidebar />
      <div className="main-content">
        <TopBar title={title} wsConnected={wsConnected} stats={wsData?.stats} />
        <main className="page-content page-enter">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
