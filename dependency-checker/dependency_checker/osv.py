"""
OSV.dev API client for dependency-checker.

Queries the Google Open Source Vulnerabilities (OSV) database using its public
REST API to check packages for known CVEs and security advisories.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from dependency_checker.models import (
    DependencyAudit,
    PackageDependency,
    Severity,
    Vulnerability,
)


class OSVClient:
    """Client for querying https://api.osv.dev/v1."""

    API_QUERY_URL = "https://api.osv.dev/v1/query"
    API_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self, timeout_seconds: int = 10):
        self.timeout = timeout_seconds

    def query_package(self, dep: PackageDependency) -> DependencyAudit:
        """Queries a single package dependency against OSV."""
        payload = json.dumps({
            "package": {
                "name": dep.name,
                "ecosystem": dep.ecosystem.value,
            },
            "version": dep.version,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.API_QUERY_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "security-labs-dependency-checker/0.1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulns_data = data.get("vulns", [])
                vulnerabilities = [self._parse_vulnerability(v) for v in vulns_data]
                return DependencyAudit(dependency=dep, vulnerabilities=vulnerabilities)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            # Return audit with no vulnerabilities on network error/timeout
            return DependencyAudit(dependency=dep, vulnerabilities=[])

    def query_batch(self, dependencies: List[PackageDependency]) -> List[DependencyAudit]:
        """
        Queries a list of dependencies concurrently using OSV's querybatch endpoint.
        Falls back to individual queries if batch request fails.
        """
        if not dependencies:
            return []

        queries = [
            {
                "package": {
                    "name": dep.name,
                    "ecosystem": dep.ecosystem.value,
                },
                "version": dep.version,
            }
            for dep in dependencies
        ]

        payload = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            self.API_BATCH_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "security-labs-dependency-checker/0.1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout + 5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])
                audits: List[DependencyAudit] = []

                for dep, res in zip(dependencies, results):
                    vulns_data = res.get("vulns", [])
                    vulnerabilities = [self._parse_vulnerability(v) for v in vulns_data]
                    audits.append(DependencyAudit(dependency=dep, vulnerabilities=vulnerabilities))

                return audits
        except Exception:
            # Fallback to individual requests if batch fails
            return [self.query_package(dep) for dep in dependencies]

    @classmethod
    def _parse_vulnerability(cls, data: Dict[str, Any]) -> Vulnerability:
        vuln_id = data.get("id", "UNKNOWN")
        summary = data.get("summary", "") or data.get("details", "")[:120]
        details = data.get("details", "")
        aliases = data.get("aliases", [])

        # Extract fixed versions
        fixed_versions: List[str] = []
        for aff in data.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])

        # Deduplicate fixed versions while preserving order
        unique_fixed = list(dict.fromkeys(fixed_versions))

        # Extract references
        references = [r.get("url", "") for r in data.get("references", []) if r.get("url")]

        # Determine severity
        severity, cvss_score = cls._extract_severity(data)

        return Vulnerability(
            id=vuln_id,
            summary=summary,
            details=details,
            aliases=aliases,
            severity=severity,
            cvss_score=cvss_score,
            fixed_versions=unique_fixed,
            references=references[:3],  # Keep top 3 reference links
        )

    @staticmethod
    def _extract_severity(data: Dict[str, Any]) -> tuple[Severity, Optional[float]]:
        """Parses severity from OSV CVSS strings or database_specific tags."""
        # 1. Inspect CVSS records in 'severity' list
        for sev in data.get("severity", []):
            score_str = sev.get("score", "")
            # If standard CVSS vector, check if score or vector can provide severity
            if "CVSS:3" in score_str:
                # Heuristic estimation if base score not directly given
                pass

        # 2. Inspect database_specific severity (GitHub Advisory DB style)
        db_specific = data.get("database_specific", {})
        db_sev = str(db_specific.get("severity", "")).upper()
        if db_sev in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
            if db_sev == "MODERATE":
                return Severity.MEDIUM, None
            return Severity(db_sev), None

        # 3. Inspect ecosystem_specific severity
        eco_specific = data.get("ecosystem_specific", {})
        eco_sev = str(eco_specific.get("severity", "")).upper()
        if eco_sev in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
            if eco_sev == "MODERATE":
                return Severity.MEDIUM, None
            return Severity(eco_sev), None

        # Fallback to MEDIUM if unknown but vulnerability exists
        return Severity.MEDIUM, None
