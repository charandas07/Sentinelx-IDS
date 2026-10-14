"""Pydantic schemas for all API request/response models."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


# ─────────────────────────── Alert Schemas ────────────────────────────

class AlertBase(BaseModel):
    attack_type: str
    severity: str
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    packet_count: int = 0
    connection_count: int = 0
    threat_score: float = 0.0
    status: str = "DETECTED"
    detection_rule: Optional[str] = None
    recommended_action: Optional[str] = None
    details: Optional[str] = None
    is_simulation: bool = False


class AlertCreate(AlertBase):
    pass


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[str] = None


# ─────────────────────────── Traffic Schemas ──────────────────────────

class TrafficFlowBase(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    packet_size: int = 0
    flags: Optional[str] = None
    status: str = "NORMAL"
    is_simulation: bool = False


class TrafficFlowResponse(TrafficFlowBase):
    id: int
    timestamp: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────── IP Stats Schemas ─────────────────────────

class IPStatsResponse(BaseModel):
    id: int
    ip: str
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    connection_count: int
    threat_score: float
    alert_count: int
    bytes_sent: int
    bytes_received: int
    unique_ports_accessed: int
    top_protocol: Optional[str]
    is_internal: int

    model_config = {"from_attributes": True}


# ─────────────────────────── Rule Schemas ────────────────────────────

class DetectionRuleBase(BaseModel):
    name: str
    display_name: str
    description: Optional[str] = None
    enabled: bool = True
    threshold: Optional[float] = None
    time_window: Optional[int] = None
    severity: str = "HIGH"
    attack_type: str
    recommended_action: Optional[str] = None


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    threshold: Optional[float] = None
    time_window: Optional[int] = None
    severity: Optional[str] = None
    recommended_action: Optional[str] = None


class DetectionRuleResponse(DetectionRuleBase):
    id: int

    model_config = {"from_attributes": True}


# ─────────────────────────── Stats Schemas ───────────────────────────

class SystemStats(BaseModel):
    packets_analyzed: int
    threats_detected: int
    critical_alerts: int
    suspicious_ips: int
    traffic_bytes: int
    uptime_seconds: float
    is_capturing: bool
    capture_error: Optional[str] = None
    active_iface: Optional[str] = None
    demo_mode: bool
    alerts_last_hour: int
    top_attack_types: List[dict] = Field(default_factory=list)


class StatusResponse(BaseModel):
    status: str
    version: str
    demo_mode: bool
    is_capturing: bool
    capture_error: Optional[str] = None
    active_iface: Optional[str] = None
    uptime_seconds: float
    database: str


# ─────────────────────────── PCAP Schemas ────────────────────────────

class PCAPReport(BaseModel):
    filename: str
    packets_analyzed: int
    protocols: dict
    top_src_ips: List[dict]
    top_dst_ips: List[dict]
    top_ports: List[dict]
    potential_attacks: List[str]
    overall_threat_score: float
    alerts_generated: int
    analysis_time_seconds: float


# ─────────────────────────── Flow Schemas (2.0) ───────────────────────

class FlowResponse(BaseModel):
    """A tracked bidirectional flow (live in-memory view)."""
    flow_id: str
    transport: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    fwd_packets: int
    rev_packets: int
    fwd_bytes: int
    rev_bytes: int
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    rev_syn_count: int = 0
    rev_ack_count: int = 0
    rev_fin_count: int = 0
    rev_rst_count: int = 0
    icmp_requests: int = 0
    icmp_responses: int = 0
    connection_attempts: int = 0
    response_seen: bool = False
    is_simulation: bool = False
    provenance: str = "live"
    termination_reason: Optional[str] = None


class FlowDetailResponse(FlowResponse):
    packet_refs: List[list] = Field(default_factory=list)
    alert_ids: List[int] = Field(default_factory=list)
    incident_ids: List[int] = Field(default_factory=list)


class FlowListResponse(BaseModel):
    items: List[FlowResponse]
    total: int
    limit: int
    offset: int
    tracker_stats: dict


class FlowTrackerStats(BaseModel):
    active_flows: int
    evicted: int
    expired: int
    max_flows: int
    idle_timeout: int
    active_timeout: int


# ─────────────────────────── Incident Schemas (2.0) ───────────────────

class IncidentResponse(BaseModel):
    id: int
    title: str
    classification: str
    status: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None
    src_ip: Optional[str] = None
    affected_endpoints_json: Optional[str] = None
    flow_ids_json: Optional[str] = None
    alert_count: int = 0
    correlation_window: int = 300
    explanation: Optional[str] = None
    notes: Optional[str] = None
    is_simulation: bool = False
    provenance: str = "live"

    model_config = {"from_attributes": True}


class IncidentUpdate(BaseModel):
    status: Optional[str] = None     # OPEN/INVESTIGATING/RESOLVED/CLOSED
    notes: Optional[str] = None


class IncidentTimelineEvent(BaseModel):
    """One entry in an incident's chronological timeline."""
    kind: str                        # "alert" | "status_change"
    timestamp: datetime
    alert_id: Optional[int] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[dict] = None


class IncidentDetailResponse(IncidentResponse):
    alerts: List[AlertResponse] = Field(default_factory=list)
    timeline: List[IncidentTimelineEvent] = Field(default_factory=list)
    flow_ids: List[str] = Field(default_factory=list)


class EvidenceResponse(BaseModel):
    """Evidence document for a single alert."""
    alert_id: int
    evidence: Optional[dict] = None
    flow: Optional[dict] = None
    incident_id: Optional[int] = None
    provenance: Optional[str] = None


# ─────────────────────────── Evaluation Schemas (2.0) ─────────────────

class EvaluationMetrics(BaseModel):
    true_positives: Optional[int] = None
    false_positives: Optional[int] = None
    true_negatives: Optional[int] = None
    false_negatives: Optional[int] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    false_positive_rate: Optional[float] = None
    detection_latencies_s: List[float] = Field(default_factory=list)
    mean_detection_latency_s: Optional[float] = None
    throughput_pps: Optional[float] = None
    processing_seconds: Optional[float] = None
    raw_alerts: int = 0
    correlated_incidents: int = 0
    evidence_completeness: Optional[float] = None
    notes: List[str] = Field(default_factory=list)


class EvaluationRunRequest(BaseModel):
    config: str = "C"                 # A | B | C
    pcap_path: Optional[str] = None   # server-local path under data/pcaps
    manifest_path: Optional[str] = None


class EvaluationConfigResult(BaseModel):
    config: str
    label: str
    metrics: EvaluationMetrics
    alerts: List[dict] = Field(default_factory=list)
    incidents: List[dict] = Field(default_factory=list)


class EvaluationRunResponse(BaseModel):
    run_id: str
    dataset: dict
    configs: List[EvaluationConfigResult]
    started_at: datetime
    finished_at: datetime
    software_version: str
    rule_config: dict
    limitations: List[str] = Field(default_factory=list)


# ─────────────────────────── Report Schemas ──────────────────────────

class SecurityReport(BaseModel):
    generated_at: datetime
    period_start: Optional[datetime]
    period_end: Optional[datetime]
    total_packets: int
    total_connections: int
    threats_detected: int
    critical_alerts: int
    suspicious_ips: int
    top_attacks: List[dict]
    top_source_ips: List[dict]
    top_target_ports: List[dict]
    threat_distribution: List[dict]
    recommendations: List[str]


# ─────────────────────────── WebSocket Message Schemas ───────────────

class WSMessage(BaseModel):
    type: str   # stats/traffic/alert/notification
    data: dict
