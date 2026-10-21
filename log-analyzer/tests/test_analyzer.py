"""
Unit and integration tests for log-analyzer parsing and detection engines.
"""

from pathlib import Path
import pytest

from log_analyzer.models import AnalysisSummary, NginxEvent, SSHEvent, SecurityAlert
from log_analyzer.nginx_parser import parse_nginx_log_file, parse_nginx_log_line
from log_analyzer.report import generate_markdown_report
from log_analyzer.rules import (
    analyze_nginx_events,
    analyze_ssh_events,
)
from log_analyzer.ssh_parser import parse_ssh_log_file, parse_ssh_log_line


def test_parse_ssh_failed_password():
    line = "Oct 21 04:12:01 web-server sshd[14201]: Failed password for invalid user admin from 198.51.100.44 port 41232 ssh2"
    ev = parse_ssh_log_line(line)
    assert ev is not None
    assert ev.event_type == "failed"
    assert ev.username == "admin"
    assert ev.ip_address == "198.51.100.44"
    assert ev.port == 41232


def test_parse_ssh_invalid_user():
    line = "Oct 21 05:01:12 web-server sshd[15011]: Invalid user support from 203.0.113.89"
    ev = parse_ssh_log_line(line)
    assert ev is not None
    assert ev.event_type == "invalid_user"
    assert ev.username == "support"
    assert ev.ip_address == "203.0.113.89"


def test_parse_ssh_accepted_login():
    line = "Oct 21 06:15:00 web-server sshd[16110]: Accepted publickey for sec_admin from 192.168.1.50 port 55410 ssh2"
    ev = parse_ssh_log_line(line)
    assert ev is not None
    assert ev.event_type == "accepted"
    assert ev.username == "sec_admin"
    assert ev.ip_address == "192.168.1.50"


def test_detect_ssh_brute_force_triggers_above_threshold():
    events = [
        SSHEvent("Oct 21 01:00:00", "failed", "root", "198.51.100.1", 22, ""),
        SSHEvent("Oct 21 01:00:02", "failed", "admin", "198.51.100.1", 22, ""),
        SSHEvent("Oct 21 01:00:04", "failed", "test", "198.51.100.1", 22, ""),
        SSHEvent("Oct 21 01:00:06", "failed", "ubuntu", "198.51.100.1", 22, ""),
        SSHEvent("Oct 21 01:00:08", "failed", "deploy", "198.51.100.1", 22, ""),
    ]
    alerts = analyze_ssh_events(events, brute_force_threshold=5)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "198.51.100.1"
    assert alerts[0].count == 5
    assert alerts[0].severity == "CRITICAL"  # targeted root


def test_detect_ssh_brute_force_ignores_below_threshold():
    events = [
        SSHEvent("Oct 21 01:00:00", "failed", "alice", "198.51.100.2", 22, ""),
        SSHEvent("Oct 21 01:00:02", "failed", "alice", "198.51.100.2", 22, ""),
    ]
    alerts = analyze_ssh_events(events, brute_force_threshold=5)
    assert len(alerts) == 0


def test_parse_nginx_combined_line():
    line = '192.168.1.100 - - [21/Oct/2026:08:14:02 +0000] "GET /api/v1/status HTTP/1.1" 200 120 "http://ref.com" "Mozilla/5.0"'
    ev = parse_nginx_log_line(line)
    assert ev is not None
    assert ev.remote_ip == "192.168.1.100"
    assert ev.method == "GET"
    assert ev.path == "/api/v1/status"
    assert ev.status_code == 200
    assert ev.body_bytes == 120
    assert ev.referer == "http://ref.com"
    assert ev.user_agent == "Mozilla/5.0"


def test_detect_suspicious_user_agent_nikto_and_sqlmap():
    events = [
        NginxEvent("198.51.100.77", "time", "GET", "/page", 200, 100, "", "sqlmap/1.7#stable", ""),
        NginxEvent("203.0.113.12", "time", "GET", "/page", 200, 100, "", "Mozilla/5.0 (Nikto/2.1.6)", ""),
    ]
    alerts = analyze_nginx_events(events)
    scanner_alerts = [a for a in alerts if "Scanner" in a.category or "User-Agent" in a.category]
    assert len(scanner_alerts) == 2
    ips = {a.source_ip for a in scanner_alerts}
    assert "198.51.100.77" in ips
    assert "203.0.113.12" in ips


def test_detect_sensitive_path_probing_env_and_git():
    events = [
        NginxEvent("203.0.113.12", "time", "GET", "/.env", 404, 50, "", "curl/7.88", ""),
        NginxEvent("203.0.113.12", "time", "GET", "/.git/config", 404, 50, "", "curl/7.88", ""),
        NginxEvent("203.0.113.12", "time", "GET", "/backup.sql", 404, 50, "", "curl/7.88", ""),
    ]
    alerts = analyze_nginx_events(events)
    probe_alerts = [a for a in alerts if "Sensitive Path" in a.category]
    assert len(probe_alerts) == 1
    assert probe_alerts[0].count == 3
    assert probe_alerts[0].source_ip == "203.0.113.12"


def test_detect_exploit_payloads_sqli_and_traversal():
    events = [
        NginxEvent("198.51.100.99", "time", "GET", "/search?q=1%20UNION%20SELECT%20null,password", 400, 50, "", "curl", ""),
        NginxEvent("198.51.100.99", "time", "GET", "/view?file=../../../../etc/passwd", 403, 50, "", "curl", ""),
    ]
    alerts = analyze_nginx_events(events)
    exploit_alerts = [a for a in alerts if "Web Exploit" in a.category]
    assert len(exploit_alerts) == 1
    assert exploit_alerts[0].count == 2
    assert exploit_alerts[0].severity == "CRITICAL"


def test_generate_markdown_report_structure(tmp_path: Path):
    summary = AnalysisSummary(
        ssh_events_scanned=10,
        ssh_failed_logins=8,
        ssh_accepted_logins=2,
        ssh_unique_ips=3,
        nginx_events_scanned=25,
        nginx_unique_ips=5,
        alerts=[
            SecurityAlert(
                category="SSH Brute-Force Authentication Attack",
                severity="CRITICAL",
                source_ip="198.51.100.44",
                description="8 failed attempts",
                count=8,
                evidence=["Targeted accounts: root, admin"],
            )
        ],
    )
    md = generate_markdown_report(summary)
    assert "# Security Log Audit Report" in md
    assert "198.51.100.44" in md
    assert "SSH Brute-Force" in md
    assert "CRITICAL" in md
    assert "iptables -A INPUT -s 198.51.100.44 -j DROP" in md


def test_sample_logs_full_execution(tmp_path: Path):
    sample_dir = Path(__file__).parent.parent / "sample_logs"
    auth_file = sample_dir / "auth.log"
    access_file = sample_dir / "access.log"

    assert auth_file.is_file()
    assert access_file.is_file()

    ssh_events = parse_ssh_log_file(auth_file)
    nginx_events = parse_nginx_log_file(access_file)

    assert len(ssh_events) > 10
    assert len(nginx_events) > 10

    ssh_alerts = analyze_ssh_events(ssh_events, brute_force_threshold=5)
    nginx_alerts = analyze_nginx_events(nginx_events)

    assert len(ssh_alerts) >= 1
    assert len(nginx_alerts) >= 1
