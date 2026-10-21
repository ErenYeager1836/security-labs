"""
Markdown report generator formatting security findings, attack metrics, and mitigation actions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from log_analyzer.models import AnalysisSummary, SecurityAlert


def generate_markdown_report(summary: AnalysisSummary, title: str = "Security Log Audit Report") -> str:
    """Generates an executive Markdown audit report from an AnalysisSummary."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    md: List[str] = []
    md.append(f"# {title}\n")
    md.append(f"**Generated:** {now_utc}  \n")
    md.append(f"**Scanner:** `log-analyzer v0.1.0`  \n\n")
    md.append("---\n\n")

    # Executive Summary Table
    md.append("## 1. Executive Summary\n\n")
    md.append("| Metric | Count |\n")
    md.append("| :--- | :--- |\n")
    md.append(f"| **SSH Events Scanned** | {summary.ssh_events_scanned} |\n")
    md.append(f"| **Failed SSH Logins** | {summary.ssh_failed_logins} |\n")
    md.append(f"| **Accepted SSH Logins** | {summary.ssh_accepted_logins} |\n")
    md.append(f"| **Unique SSH Source IPs** | {summary.ssh_unique_ips} |\n")
    md.append(f"| **Nginx Access Requests Scanned** | {summary.nginx_events_scanned} |\n")
    md.append(f"| **Unique Nginx Client IPs** | {summary.nginx_unique_ips} |\n")
    md.append(f"| **Total Security Alerts** | {len(summary.alerts)} |\n")
    md.append(f"| **Critical / High Severity Alerts** | {summary.critical_alerts} Critical / {summary.high_alerts} High |\n\n")

    # Severity Breakdown
    md.append("### Alert Severity Distribution\n\n")
    md.append(f"- **CRITICAL**: {summary.critical_alerts}\n")
    md.append(f"- **HIGH**: {summary.high_alerts}\n")
    md.append(f"- **MEDIUM**: {summary.medium_alerts}\n")
    md.append(f"- **LOW**: {summary.low_alerts}\n\n")
    md.append("---\n\n")

    # Detailed Alerts Section
    md.append("## 2. Security Alerts & Anomaly Detections\n\n")
    if not summary.alerts:
        md.append("No security anomalies or attack patterns detected in the analyzed log files.\n\n")
    else:
        for idx, alert in enumerate(summary.alerts, start=1):
            sev_badge = f"`{alert.severity}`"
            md.append(f"### Alert #{idx}: [{alert.severity}] {alert.category}\n\n")
            md.append(f"- **Source IP:** `{alert.source_ip}`\n")
            md.append(f"- **Severity:** {sev_badge}\n")
            md.append(f"- **Activity Count:** {alert.count}\n")
            md.append(f"- **Details:** {alert.description}\n")
            if alert.evidence:
                md.append("- **Supporting Evidence:**\n")
                for ev in alert.evidence:
                    md.append(f"  - `{ev}`\n")
            md.append("\n")

    md.append("---\n\n")

    # Defensive Mitigation Actions
    md.append("## 3. Recommended Defensive Remediation Actions\n\n")
    unique_attacker_ips = sorted(set(a.source_ip for a in summary.alerts if a.severity in ("CRITICAL", "HIGH")))

    if unique_attacker_ips:
        md.append("### Immediate Firewall Blocklist (`iptables` / `nftables`)\n")
        md.append("To immediately drop traffic from hosts executing brute force or exploit probes:\n\n")
        md.append("```bash\n")
        for ip in unique_attacker_ips:
            md.append(f"iptables -A INPUT -s {ip} -j DROP\n")
        md.append("```\n\n")

    md.append("### Hardening Best Practices\n")
    md.append("1. **SSH Hardening**:\n")
    md.append("   - Disable SSH password authentication (`PasswordAuthentication no`) in `/etc/ssh/sshd_config`.\n")
    md.append("   - Enforce public key authentication only (`PubkeyAuthentication yes`).\n")
    md.append("   - Deploy and configure `fail2ban` to automatically jail IPs with repeated login failures.\n")
    md.append("2. **Nginx & Web Application Hardening**:\n")
    md.append("   - Block dotfile requests (`location ~ /\\.(?!well-known).* { deny all; }`).\n")
    md.append("   - Block known scanner User-Agents using an Nginx map or Cloudflare / ModSecurity WAF rules.\n")
    md.append("   - Rate limit dynamic requests using `limit_req_zone`.\n")

    return "".join(md)
