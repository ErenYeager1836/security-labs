"""
Data models and schemas for hardening auditor rules, results, and compliance metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RuleStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    MANUAL = "MANUAL"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(str, Enum):
    SSH = "SSH Configuration"
    FILE_PERMS = "File & Directory Permissions"
    OPEN_PORTS = "Network Services & Open Ports"
    SUDO = "Sudoers & Privilege Delegation"


@dataclass
class RuleResult:
    """Outcome of an individual security hardening rule check."""
    rule_id: str
    title: str
    category: str
    severity: str
    status: RuleStatus
    current_value: str
    expected_value: str
    remediation: str
    rationale: str


@dataclass
class AuditSummary:
    """Aggregated audit statistics, compliance score, and itemized findings."""
    total_rules: int
    passed_rules: int
    failed_rules: int
    skipped_rules: int
    score_percentage: float
    results: List[RuleResult] = field(default_factory=list)

    @property
    def critical_failures(self) -> int:
        return sum(1 for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.CRITICAL.value)

    @property
    def high_failures(self) -> int:
        return sum(1 for r in self.results if r.status == RuleStatus.FAIL and r.severity == Severity.HIGH.value)
