"""
Command line interface for log-analyzer.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

# Ensure parent directory is in sys.path when invoked directly as a script
_pkg_root = Path(__file__).resolve().parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from typing import List

from log_analyzer.models import AnalysisSummary, NginxEvent, SSHEvent, SecurityAlert
from log_analyzer.nginx_parser import parse_nginx_log_file
from log_analyzer.report import generate_markdown_report
from log_analyzer.rules import analyze_nginx_events, analyze_ssh_events
from log_analyzer.ssh_parser import parse_ssh_log_file


def parse_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Security log analyzer identifying SSH brute-force attacks, web vulnerability scanners, and anomalous traffic.",
    )
    parser.add_argument(
        "--auth-log",
        type=str,
        default=None,
        help="Path to SSH authentication log file (e.g., /var/log/auth.log)",
    )
    parser.add_argument(
        "--nginx-log",
        type=str,
        default=None,
        help="Path to Nginx HTTP access log file (e.g., /var/log/nginx/access.log)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="security_report.md",
        help="Path to output Markdown report (default: security_report.md)",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=5,
        help="Failed login threshold to trigger SSH brute force alert (default: 5)",
    )
    parser.add_argument(
        "--print-report",
        action="store_true",
        help="Print the generated Markdown report directly to terminal stdout",
    )
    return parser


def main() -> int:
    parser = parse_args()
    args = parser.parse_args()

    if not args.auth_log and not args.nginx_log:
        # Check if default sample_logs exist in relative directory
        sample_dir = Path(__file__).parent.parent / "sample_logs"
        sample_auth = sample_dir / "auth.log"
        sample_nginx = sample_dir / "access.log"
        if sample_auth.is_file() or sample_nginx.is_file():
            print("[*] No log paths specified. Using included sample logs for demonstration...")
            args.auth_log = str(sample_auth) if sample_auth.is_file() else None
            args.nginx_log = str(sample_nginx) if sample_nginx.is_file() else None
        else:
            parser.print_help()
            print("\n[-] Error: You must supply at least one of --auth-log or --nginx-log.")
            return 1

    print("=========================================================")
    print("         security-labs // log-analyzer (Python)          ")
    print("   Defensive SSH & Nginx Security Anomaly Auditor        ")
    print("=========================================================\n")

    summary = AnalysisSummary()
    all_alerts: List[SecurityAlert] = []

    # 1. Parse & Analyze SSH Logs
    if args.auth_log:
        auth_path = Path(args.auth_log)
        if not auth_path.is_file():
            print(f"[-] Error: SSH log file does not exist: {auth_path}", file=sys.stderr)
            return 1

        print(f"[*] Parsing SSH authentication log: {auth_path}")
        ssh_events: List[SSHEvent] = parse_ssh_log_file(auth_path)
        summary.ssh_events_scanned = len(ssh_events)
        summary.ssh_failed_logins = sum(1 for e in ssh_events if e.event_type in ("failed", "invalid_user"))
        summary.ssh_accepted_logins = sum(1 for e in ssh_events if e.event_type == "accepted")
        summary.ssh_unique_ips = len(set(e.ip_address for e in ssh_events))

        ssh_alerts = analyze_ssh_events(ssh_events, brute_force_threshold=args.threshold)
        all_alerts.extend(ssh_alerts)
        print(f"[+] Scanned {len(ssh_events)} SSH events ({summary.ssh_failed_logins} failed, {summary.ssh_accepted_logins} accepted).")

    # 2. Parse & Analyze Nginx Logs
    if args.nginx_log:
        nginx_path = Path(args.nginx_log)
        if not nginx_path.is_file():
            print(f"[-] Error: Nginx log file does not exist: {nginx_path}", file=sys.stderr)
            return 1

        print(f"[*] Parsing Nginx access log: {nginx_path}")
        nginx_events: List[NginxEvent] = parse_nginx_log_file(nginx_path)
        summary.nginx_events_scanned = len(nginx_events)
        summary.nginx_unique_ips = len(set(e.remote_ip for e in nginx_events))

        from collections import Counter
        summary.nginx_status_distribution = dict(Counter(e.status_code for e in nginx_events))

        nginx_alerts = analyze_nginx_events(nginx_events)
        all_alerts.extend(nginx_alerts)
        print(f"[+] Scanned {len(nginx_events)} HTTP access requests across {summary.nginx_unique_ips} client IPs.")

    # Sort consolidated alerts by severity
    sev_weight = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    all_alerts.sort(key=lambda a: (sev_weight.get(a.severity, 0), a.count), reverse=True)
    summary.alerts = all_alerts

    # Print Terminal Overview
    print("\n--- Detection Findings Summary ---")
    if not summary.alerts:
        print("[+] No malicious scanning or brute-force patterns identified.")
    else:
        print(f"[!] Total Alerts Flagged: {len(summary.alerts)}")
        print(f"    - CRITICAL: {summary.critical_alerts}")
        print(f"    - HIGH:     {summary.high_alerts}")
        print(f"    - MEDIUM:   {summary.medium_alerts}")
        print(f"    - LOW:      {summary.low_alerts}\n")

        for idx, a in enumerate(summary.alerts[:8], start=1):
            print(f"  #{idx} [{a.severity}] {a.category} from {a.source_ip} (Count: {a.count})")
        if len(summary.alerts) > 8:
            print(f"  ... and {len(summary.alerts) - 8} more alert(s) in report.")

    # Generate & Export Markdown Report
    report_content = generate_markdown_report(summary)
    output_path = Path(args.output)
    output_path.write_text(report_content, encoding="utf-8")
    print(f"\n[+] Security Audit Report exported to: {output_path.resolve()}")

    if args.print_report:
        print("\n" + report_content)

    return 0


if __name__ == "__main__":
    sys.exit(main())
