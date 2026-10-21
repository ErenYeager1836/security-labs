"""
Detection engine identifying brute force attacks, web scanners, sensitive path probes, and malicious payloads.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import re
from typing import Dict, List, Set
import urllib.parse

from log_analyzer.models import NginxEvent, SSHEvent, SecurityAlert


# Known automated scanners, attack tools, and suspicious User-Agent signatures
SUSPICIOUS_UA_PATTERNS = [
    (re.compile(r"(?i)\b(?:sqlmap|nikto|wpscan|masscan|zgrab|gobuster|dirbuster|nuclei|acunetix)\b"), "Automated Security Scanner"),
    (re.compile(r"(?i)\b(?:nmap\s+scripting\s+engine|nmap)\b"), "Nmap Port/Service Prober"),
    (re.compile(r"(?i)\b(?:python-requests|aiohttp|go-http-client|curl/\d|libwww-perl)\b"), "Automated Scripting HTTP Client"),
]

# Sensitive paths and directory enumeration targets
SENSITIVE_PATH_PATTERNS = [
    (re.compile(r"(?i)\.env(?:ironment)?(?:\.local|\.prod|\.backup)?$"), "Environment Configuration File"),
    (re.compile(r"(?i)/\.(?:git|svn|hg)(?:/|$)"), "Source Code Version Control Repository"),
    (re.compile(r"(?i)/(?:wp-admin|wp-login\.php|xmlrpc\.php)"), "WordPress Administrative Interface"),
    (re.compile(r"(?i)/(?:phpmyadmin|pma|adminer|myadmin)"), "Database Management Interface"),
    (re.compile(r"(?i)/(?:actuator/|debug/pprof|metrics)"), "Exposed Cloud / Application Metrics Endpoint"),
    (re.compile(r"(?i)/(?:etc/passwd|windows/win\.ini|\.aws/credentials)"), "System / Credential File Traversal Target"),
    (re.compile(r"(?i)\.(?:bak|old|backup|sql|tar\.gz|zip)$"), "Backup or Database Dump Archive"),
]

# Exploit payload patterns in URL query parameters and paths
EXPLOIT_PAYLOAD_PATTERNS = [
    (re.compile(r"(?i)(?:union\s+all\s+select|union\s+select|order\s+by\s+\d+|waitfor\s+delay|sleep\(\d+\)|benchmark\()"), "SQL Injection Payload"),
    (re.compile(r"(?:\.\./|\.\.\\){2,}"), "Path Traversal / LFI Sequence"),
    (re.compile(r"(?i)(?:<script|javascript:|onerror\s*=|onload\s*=)"), "Cross-Site Scripting (XSS) Probe"),
]


def analyze_ssh_events(ssh_events: List[SSHEvent], brute_force_threshold: int = 5) -> List[SecurityAlert]:
    """Analyzes SSH authentication events to detect brute-force attacks and credential stuffing."""
    alerts: List[SecurityAlert] = []

    # Map: source_ip -> list of failed events
    failures_by_ip: Dict[str, List[SSHEvent]] = defaultdict(list)
    for ev in ssh_events:
        if ev.event_type in ("failed", "invalid_user"):
            failures_by_ip[ev.ip_address].append(ev)

    for ip, fails in failures_by_ip.items():
        count = len(fails)
        if count >= brute_force_threshold:
            usernames = sorted(set(f.username for f in fails))
            targeted_root = "root" in usernames
            severity = "CRITICAL" if (count >= 20 or targeted_root) else "HIGH"

            evidence = [
                f"Total failed attempts: {count}",
                f"Targeted usernames ({len(usernames)}): {', '.join(usernames[:10])}{' ...' if len(usernames) > 10 else ''}",
                f"First failure: {fails[0].timestamp}",
                f"Latest failure: {fails[-1].timestamp}",
            ]

            alert = SecurityAlert(
                category="SSH Brute-Force Authentication Attack",
                severity=severity,
                source_ip=ip,
                description=(
                    f"Host {ip} triggered {count} failed SSH authentication attempts "
                    f"targeting user accounts: {', '.join(usernames[:5])}."
                ),
                count=count,
                evidence=evidence,
            )
            alerts.append(alert)

    # Sort alerts: CRITICAL first, then by count descending
    sev_weight = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    alerts.sort(key=lambda a: (sev_weight.get(a.severity, 0), a.count), reverse=True)
    return alerts


def analyze_nginx_events(nginx_events: List[NginxEvent]) -> List[SecurityAlert]:
    """Analyzes Nginx access logs to detect scanner user agents, path probing, and exploit strings."""
    alerts: List[SecurityAlert] = []

    # 1. Suspicious User-Agents
    ua_by_ip: Dict[str, Dict[str, int]] = defaultdict(lambda: Counter())
    for ev in nginx_events:
        if not ev.user_agent:
            continue
        for pat, tag in SUSPICIOUS_UA_PATTERNS:
            if pat.search(ev.user_agent):
                ua_by_ip[ev.remote_ip][f"{tag} ({ev.user_agent[:45]})"] += 1

    for ip, counts in ua_by_ip.items():
        total_scanner_reqs = sum(counts.values())
        summary_tools = "; ".join(f"{tool} ({cnt}x)" for tool, cnt in counts.items())
        alerts.append(
            SecurityAlert(
                category="Automated Web Scanner / Suspicious User-Agent",
                severity="HIGH",
                source_ip=ip,
                description=f"Automated tool activity detected from {ip}: {summary_tools}",
                count=total_scanner_reqs,
                evidence=[f"Tool signatures: {summary_tools}"],
            )
        )

    # 2. Sensitive Path Probing & Enumeration
    probes_by_ip: Dict[str, List[NginxEvent]] = defaultdict(list)
    for ev in nginx_events:
        decoded_path = urllib.parse.unquote_plus(ev.path)
        for pat, desc in SENSITIVE_PATH_PATTERNS:
            if pat.search(ev.path) or pat.search(decoded_path):
                probes_by_ip[ev.remote_ip].append(ev)
                break

    for ip, events in probes_by_ip.items():
        count = len(events)
        sample_paths = sorted(set(e.path for e in events))[:8]
        status_codes = Counter(e.status_code for e in events)
        status_summary = ", ".join(f"{code}:{cnt}" for code, cnt in status_codes.items())

        alerts.append(
            SecurityAlert(
                category="Sensitive Path Probing / Directory Enumeration",
                severity="HIGH" if any(p in "".join(sample_paths) for p in [".env", ".git", "passwd"]) else "MEDIUM",
                source_ip=ip,
                description=f"Host {ip} performed targeted enumeration of {count} sensitive administrative/system endpoints.",
                count=count,
                evidence=[
                    f"Sample probed endpoints: {', '.join(sample_paths)}",
                    f"HTTP response distribution: {status_summary}",
                ],
            )
        )

    # 3. Exploit Payload Injection Attempts
    exploits_by_ip: Dict[str, List[NginxEvent]] = defaultdict(list)
    for ev in nginx_events:
        decoded_path = urllib.parse.unquote_plus(ev.path)
        for pat, desc in EXPLOIT_PAYLOAD_PATTERNS:
            if pat.search(ev.path) or pat.search(decoded_path):
                exploits_by_ip[ev.remote_ip].append(ev)
                break

    for ip, events in exploits_by_ip.items():
        count = len(events)
        sample_payloads = [e.path for e in events[:5]]
        alerts.append(
            SecurityAlert(
                category="Web Exploit Payload Attempt",
                severity="CRITICAL",
                source_ip=ip,
                description=f"Identified {count} active exploitation payloads in HTTP request line from {ip}.",
                count=count,
                evidence=[f"Observed payload samples: {', '.join(sample_payloads)}"],
            )
        )

    sev_weight = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    alerts.sort(key=lambda a: (sev_weight.get(a.severity, 0), a.count), reverse=True)
    return alerts
