"""
Data structures for SSH and Nginx parsed events, security alerts, and analysis reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SSHEvent:
    """Represents a single parsed SSH authentication event."""
    timestamp: str
    event_type: str  # 'failed', 'accepted', 'invalid_user'
    username: str
    ip_address: str
    port: int
    raw_line: str


@dataclass
class NginxEvent:
    """Represents a single parsed Nginx HTTP access log entry."""
    remote_ip: str
    timestamp: str
    method: str
    path: str
    status_code: int
    body_bytes: int
    referer: str
    user_agent: str
    raw_line: str


@dataclass
class SecurityAlert:
    """Represents an identified security violation, attack pattern, or scanning activity."""
    category: str
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    source_ip: str
    description: str
    count: int = 1
    evidence: List[str] = field(default_factory=list)


@dataclass
class AnalysisSummary:
    """Consolidated summary of parsed logs and security detections."""
    ssh_events_scanned: int = 0
    ssh_failed_logins: int = 0
    ssh_accepted_logins: int = 0
    ssh_unique_ips: int = 0

    nginx_events_scanned: int = 0
    nginx_unique_ips: int = 0
    nginx_status_distribution: Dict[int, int] = field(default_factory=dict)

    alerts: List[SecurityAlert] = field(default_factory=list)

    @property
    def critical_alerts(self) -> int:
        return sum(1 for a in self.alerts if a.severity.upper() == "CRITICAL")

    @property
    def high_alerts(self) -> int:
        return sum(1 for a in self.alerts if a.severity.upper() == "HIGH")

    @property
    def medium_alerts(self) -> int:
        return sum(1 for a in self.alerts if a.severity.upper() == "MEDIUM")

    @property
    def low_alerts(self) -> int:
        return sum(1 for a in self.alerts if a.severity.upper() == "LOW")
