# SentinelX – Intelligent Network Intrusion Detection System

**SentinelX** is a complete, functional Network Intrusion Detection System (IDS) equipped with a modern, Security Operations Center (SOC)-themed interactive cybersecurity dashboard.

Designed for real-time live network monitoring, PCAP file forensics, automated rule-based threat detection, and comprehensive threat intelligence analysis.

---

## 🌟 Key Features

- 🛡️ **Rule-Based IDS Engine**: Detects common network attacks including:
  - **Port Scanning**: Probing multiple destination ports within short windows.
  - **Brute-Force Attempts**: Repeated connections to SSH (22), FTP (21), RDP (3389), VNC (5900), or HTTP auth endpoints.
  - **SYN Flooding**: Excessive TCP SYN-only packets exceeding normal thresholds.
  - **ICMP Flooding**: Excessive ping echo request rates from a single source.
  - **Traffic Spikes & DoS Patterns**: Volume anomalies compared against dynamic baseline traffic.
- ⚡ **Real-Time WebSocket Updates**: Live streaming of traffic metrics, alerts, and system stats straight to the React dashboard without polling.
- 📊 **Interactive SOC Dashboard**:
  - Live packets/sec area chart
  - Threat distribution donut chart
  - Visual 0–100 Threat Meter gauge
  - Dynamic Network Topology Map with interactive nodes
  - Filterable security alerts table & investigation modal
- 📂 **PCAP / PCAPNG File Analyzer**: Upload packet captures to generate full forensic analysis reports with protocol distributions and threat scoring.
- 🔍 **IP Investigation & Forensics**: Query any IP to view threat score breakdown, protocol distribution, top ports probed, and attack history.
- ⚙️ **Configurable Detection Rules**: Adjust detection thresholds, time windows, and severity ratings dynamically, or toggle individual rules.
- 📄 **Security Reports & Export**: Generate comprehensive security reports and export data in **PDF**, **CSV**, or **JSON** formats.
- 🎮 **Demo / Simulation Mode**: Built-in simulator to generate realistic synthetic network traffic and attack scenarios (clearly labeled as `SIMULATION`) for demonstration without needing root packet capture privileges.

---

## 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │     Network         │
                    │      Traffic        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Packet Capture      │
                    │      Engine         │
                    │       Scapy         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Traffic Processing  │
                    │ & Feature Extraction│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Detection Engine    │
                    │ Rule-Based IDS      │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┼─────────────┐
                 ▼             ▼             ▼
          ┌───────────┐ ┌────────────┐ ┌────────────┐
          │ Alerts    │ │ IP / Flow  │ │ Statistics │
          │ Database  │ │ Database   │ │ Engine     │
          └─────┬─────┘ └──────┬─────┘ └──────┬─────┘
                │               │              │
                └───────────────┼──────────────┘
                                ▼
                     ┌────────────────────┐
                     │ FastAPI Backend    │
                     │ REST + WebSocket   │
                     └──────────┬─────────┘
                                │
                                ▼
                     ┌────────────────────┐
                     │ React SOC Dashboard│
                     └────────────────────┘
```

---

## 🛠️ Technology Stack

### Backend
- **Python 3.11+**
- **FastAPI** – High-performance REST API & WebSockets
- **Scapy & DPKT** – Live packet capture & offline PCAP parsing
- **Pandas** – Traffic flow processing & window aggregations
- **SQLAlchemy (Async) & SQLite** – Async database persistence
- **Pydantic v2** – Robust data validation & schemas

### Frontend
- **React 18 & Vite**
- **Vanilla CSS** – Curated Dark SOC aesthetic with glassmorphism & gradients
- **Recharts** – Interactive charts (traffic flow & threat distribution)
- **Lucide React** – Security icons
- **React Hot Toast** – Real-time toast notifications

---

## 🚀 Quick Start & Installation

### Prerequisites
- **Python 3.11+**
- **Node.js 18+ & npm**

---

### 1. Running the Backend

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
```
Backend API will be running at `http://localhost:8000`.  
Swagger Interactive API documentation: `http://localhost:8000/docs`.

---

### 2. Running the Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```
Open `http://localhost:5173` in your web browser.

---

## 🚀 Real-time Mode (Packet Capture)

By default, SentinelX uses a simulation mode if live capture fails. To enable live packet capture:

1. **Permissions**: Live packet capture requires `CAP_NET_RAW` capabilities or root/Administrator privileges.
   * Linux: Run as root (`sudo`) or grant python the capability: `sudo setcap cap_net_raw,cap_net_admin=eip /path/to/venv/bin/python`.
   * Windows: Run your terminal as Administrator.
2. **Interface**: Specify the interface in `.env` (e.g., `CAPTURE_IFACE=eth0`).
3. **Security**: Change `SECRET_KEY` in production and set `DEBUG=False`.

---

## 🎮 Using Demo Simulation Mode

If running on an OS environment without raw socket permissions (administrator/root privileges required for live packet capture), click the **START DEMO MODE** banner button at the top of the dashboard.

Demo Mode will generate:
- Live synthetic normal traffic (HTTP, HTTPS, DNS, TCP, UDP)
- Simulated security attack events (Port Scan, Brute Force, SYN Flood, ICMP Flood)
- Real-time WebSocket notifications & toast alerts

*All simulated events are explicitly marked with `SIMULATION` badges.*

---

## 🔬 PCAP Analyzer Guide

1. Navigate to **PCAP Analyzer** in the sidebar.
2. Select or drag-and-drop a `.pcap` or `.pcapng` file.
3. Click **RUN IDS ANALYSIS**.
4. SentinelX will parse all ethernet/IP packets, run all detection rules, calculate an overall threat score, and produce a detailed forensic breakdown.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Check system & engine online status |
| `/api/stats` | GET | Fetch live aggregate security statistics |
| `/api/alerts` | GET | Query security alerts with severity/type filters |
| `/api/alerts/{id}` | PATCH | Update alert investigation status |
| `/api/traffic` | GET | Retrieve live packet flows & PPS history |
| `/api/ip/{ip}` | GET | Get complete forensic profile for an IP |
| `/api/rules` | GET/PUT | List or modify IDS rule thresholds |
| `/api/pcap/upload` | POST | Upload and analyze PCAP file |
| `/api/demo/start` | POST | Activate synthetic traffic simulator |
| `/api/reports` | GET | Generate aggregated security report |

---

## ⚠️ Legal & Ethical Disclaimer

SentinelX is designed strictly for **educational, security research, and authorized network monitoring purposes**. Only analyze networks and packet captures that you own or have explicit authorization to monitor.
