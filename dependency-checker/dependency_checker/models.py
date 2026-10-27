"""
Data models for dependency-checker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Ecosystem(str, Enum):
    PYPI = "PyPI"
    MAVEN = "Maven"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        ranks = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "UNKNOWN": 1,
        }
        return ranks.get(self.value, 0)

    def __ge__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


@dataclass
class PackageDependency:
    """Represents an extracted package dependency from a manifest file."""
    name: str
    version: str
    ecosystem: Ecosystem
    file_path: str
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


@dataclass
class Vulnerability:
    """Represents a vulnerability record retrieved from OSV.dev."""
    id: str  # GHSA-xxx, PYSEC-xxx, or CVE-xxx
    summary: str
    details: str
    aliases: List[str] = field(default_factory=list)  # e.g., ['CVE-2021-44228']
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    fixed_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    @property
    def display_cve(self) -> str:
        """Returns primary CVE alias if available, else primary advisory ID."""
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "display_cve": self.display_cve,
            "summary": self.summary,
            "aliases": self.aliases,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "fixed_versions": self.fixed_versions,
            "references": self.references,
        }


@dataclass
class DependencyAudit:
    """Audit result for a single package dependency."""
    dependency: PackageDependency
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def highest_severity(self) -> Severity:
        if not self.vulnerabilities:
            return Severity.UNKNOWN
        return max(v.severity for v in self.vulnerabilities)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dependency": self.dependency.to_dict(),
            "is_vulnerable": self.is_vulnerable,
            "highest_severity": self.highest_severity.value if self.is_vulnerable else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


@dataclass
class AuditSummary:
    """Aggregated summary of an audit run."""
    manifest_files: List[str]
    total_packages: int = 0
    vulnerable_packages: int = 0
    total_vulnerabilities: int = 0
    duration_seconds: float = 0.0
    audits: List[DependencyAudit] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.audits for v in a.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for a in self.audits for v in a.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for a in self.audits for v in a.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for a in self.audits for v in a.vulnerabilities if v.severity == Severity.LOW)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_files": self.manifest_files,
            "total_packages": self.total_packages,
            "vulnerable_packages": self.vulnerable_packages,
            "total_vulnerabilities": self.total_vulnerabilities,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "duration_seconds": round(self.duration_seconds, 3),
            "audits": [a.to_dict() for a in self.audits],
        }
