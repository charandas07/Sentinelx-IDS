"""
SentinelX Configuration
Loads settings from environment variables / .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional
import json
import socket


def _auto_detect_local_ips() -> List[str]:
    """Auto-detect local IPs using socket."""
    ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ":" not in addr:  # skip IPv6
                ips.add(addr)
    except Exception:
        pass
    return list(ips)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/sentinelx.db"

    # Security
    SECRET_KEY: str = "sentinelx-dev-secret-change-in-production"
    ADMIN_USER: str = "admin"
    ADMIN_PASSWORD: str = ""
    DEBUG: bool = False
    MAX_PCAP_SIZE_MB: int = 50

    # CORS
    CORS_ORIGINS: str = '["http://localhost:5173","http://localhost:3000"]'

    # Logging
    LOG_LEVEL: str = "INFO"

    # Detection Thresholds
    PORT_SCAN_THRESHOLD: int = 20
    PORT_SCAN_WINDOW: int = 10          # seconds
    BRUTE_FORCE_THRESHOLD: int = 10
    BRUTE_FORCE_WINDOW: int = 30        # seconds
    SYN_FLOOD_THRESHOLD: int = 100
    SYN_FLOOD_WINDOW: int = 5           # seconds
    ICMP_FLOOD_THRESHOLD: int = 50
    ICMP_FLOOD_WINDOW: int = 5          # seconds
    TRAFFIC_SPIKE_MULTIPLIER: float = 3.0

    # Flow tracking (bidirectional network flows)
    FLOW_IDLE_TIMEOUT: int = 60             # seconds without a packet before a flow is expired
    FLOW_ACTIVE_TIMEOUT: int = 300          # seconds max lifetime of a flow regardless of activity
    FLOW_MAX_TRACKED: int = 20000           # bounded flow table size (LRU eviction)
    FLOW_SCAN_WINDOW: int = 10              # seconds window for distinct-port scan accounting
    FLOW_SCAN_DISTINCT_PORTS: int = 20      # distinct dst ports (flow level) for scan detection

    # Alert correlation (incidents)
    CORRELATION_ENABLED: bool = True
    CORRELATION_WINDOW: int = 300           # seconds; alerts within window from same source correlate
    CORRELATION_MAX_ALERTS_PER_INCIDENT: int = 200   # bounded incident growth

    # Evidence retention
    EVIDENCE_MAX_PACKET_REFS: int = 10      # packet/flow evidence refs stored per alert
    EVIDENCE_RETENTION_HOURS: int = 48      # how long structured evidence JSON is kept

    # Capture / Demo
    ENABLE_DEMO_ON_STARTUP: bool = False
    CAPTURE_IFACE: Optional[str] = None                 # None = scapy default
    CAPTURE_FILTER: str = "ip"                          # BPF filter
    LOCAL_IPS: str = ""                                 # comma-separated; auto-detected if empty
    WHITELIST_IPS: str = ""                             # comma-separated; never alerts
    PROTECTED_NETWORKS: str = ""                        # comma-separated CIDRs
    DEMO_SPEED: float = 1.0                             # Multiplier for demo sleeps (higher = faster)

    # Retention
    RETENTION_HOURS: int = 24

    def get_cors_origins(self) -> List[str]:
        try:
            return json.loads(self.CORS_ORIGINS)
        except Exception:
            # Include real IPs as fallback
            return ["http://localhost:5173", "http://localhost:3000", "http://172.18.206.151:5173", "http://192.168.56.1:5173"]

    def get_local_ips(self) -> List[str]:
        """Return configured or auto-detected local IPs."""
        raw = self.LOCAL_IPS.strip()
        if raw:
            return [ip.strip() for ip in raw.split(",") if ip.strip()]
        ips = _auto_detect_local_ips()
        # Also try scapy if available
        try:
            from scapy.config import conf
            from scapy.layers.inet import get_if_addr
            iface_ip = get_if_addr(conf.iface)
            if iface_ip and iface_ip != "0.0.0.0":
                ips.append(iface_ip)
        except Exception:
            pass
        # Add real IPs
        ips.add("172.18.206.151")
        ips.add("192.168.56.1")
        return list(set(ips))

    def get_whitelist_ips(self) -> List[str]:
        raw = self.WHITELIST_IPS.strip()
        if not raw:
            return []
        return [ip.strip() for ip in raw.split(",") if ip.strip()]

    def get_protected_networks(self) -> List[str]:
        raw = self.PROTECTED_NETWORKS.strip()
        if not raw:
            return []
        return [net.strip() for net in raw.split(",") if net.strip()]


settings = Settings()