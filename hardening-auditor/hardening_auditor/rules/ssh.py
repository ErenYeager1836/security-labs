"""
CIS-style SSH Daemon Configuration Audit Rules.

Reference: CIS Linux Benchmark Section 5.2 (SSH Server Configuration).
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Dict, List, Optional

from hardening_auditor.models import Category, RuleResult, RuleStatus, Severity


def parse_sshd_config(config_path: Path) -> Dict[str, str]:
    """Parses sshd_config into a dictionary of directive -> value.

    OpenSSH uses first-match semantics for directives.
    Lines starting with # or empty lines are ignored.
    """
    settings: Dict[str, str] = {}
    if not config_path.is_file():
        return settings

    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Directives can be separated by spaces or tabs
                parts = line.split(None, 1)
                if len(parts) == 2:
                    key = parts[0].lower()
                    val = parts[1].strip()
                    # First match wins in OpenSSH
                    if key not in settings:
                        settings[key] = val
    except OSError:
        pass

    return settings


def audit_ssh_config(root_dir: Path) -> List[RuleResult]:
    """Audits SSH configuration according to CIS Benchmark specifications."""
    results: List[RuleResult] = []
    sshd_file = root_dir / "etc" / "ssh" / "sshd_config"

    if not sshd_file.exists():
        # Fallback check directly if path provided was not under /etc
        alt_file = root_dir / "sshd_config"
        if alt_file.exists():
            sshd_file = alt_file

    if not sshd_file.exists():
        results.append(
            RuleResult(
                rule_id="CIS-SSH-00",
                title="SSH Daemon Config File Presence",
                category=Category.SSH.value,
                severity=Severity.HIGH.value,
                status=RuleStatus.SKIP,
                current_value="File not found",
                expected_value="Present at /etc/ssh/sshd_config",
                remediation="Ensure OpenSSH server is installed and /etc/ssh/sshd_config exists.",
                rationale="The OpenSSH daemon configuration file could not be located at the expected path.",
            )
        )
        return results

    cfg = parse_sshd_config(sshd_file)

    # 1. PermitRootLogin
    # CIS 5.2.5: Ensure SSH root login is disabled ('no' or 'prohibit-password')
    root_login = cfg.get("permitrootlogin", "prohibit-password").lower()
    is_root_disabled = root_login in ("no", "prohibit-password", "without-password")
    results.append(
        RuleResult(
            rule_id="CIS-SSH-01",
            title="Disable Direct SSH Root Login",
            category=Category.SSH.value,
            severity=Severity.CRITICAL.value,
            status=RuleStatus.PASS if is_root_disabled and root_login == "no" else (RuleStatus.PASS if is_root_disabled else RuleStatus.FAIL),
            current_value=f"PermitRootLogin {root_login}",
            expected_value="PermitRootLogin no",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.",
            rationale="Disallowing root login over SSH forces administrative users to authenticate with personal credentials first, maintaining audit trails.",
        )
    )

    # 2. PasswordAuthentication
    # CIS 5.2.8: Ensure SSH password authentication is disabled (enforce key-based auth)
    pass_auth = cfg.get("passwordauthentication", "yes").lower()
    results.append(
        RuleResult(
            rule_id="CIS-SSH-02",
            title="Disable SSH Password Authentication (Require Keys)",
            category=Category.SSH.value,
            severity=Severity.HIGH.value,
            status=RuleStatus.PASS if pass_auth == "no" else RuleStatus.FAIL,
            current_value=f"PasswordAuthentication {pass_auth}",
            expected_value="PasswordAuthentication no",
            remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config after installing SSH public keys.",
            rationale="Password authentication is susceptible to credential stuffing and brute force attacks. SSH public keys offer superior cryptographic resistance.",
        )
    )

    # 3. PermitEmptyPasswords
    # CIS 5.2.9: Ensure SSH PermitEmptyPasswords is disabled
    empty_pass = cfg.get("permitemptypasswords", "no").lower()
    results.append(
        RuleResult(
            rule_id="CIS-SSH-03",
            title="Disable Empty SSH Passwords",
            category=Category.SSH.value,
            severity=Severity.CRITICAL.value,
            status=RuleStatus.PASS if empty_pass == "no" else RuleStatus.FAIL,
            current_value=f"PermitEmptyPasswords {empty_pass}",
            expected_value="PermitEmptyPasswords no",
            remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
            rationale="Accounts without passwords can allow unauthorized access if empty passwords are permitted by the daemon.",
        )
    )

    # 4. MaxAuthTries
    # CIS 5.2.4: Ensure SSH MaxAuthTries is set to 4 or less
    max_tries_str = cfg.get("maxauthtries", "6")
    try:
        max_tries = int(max_tries_str)
        max_tries_pass = max_tries <= 4
    except ValueError:
        max_tries = -1
        max_tries_pass = False

    results.append(
        RuleResult(
            rule_id="CIS-SSH-04",
            title="Configure SSH MaxAuthTries (<= 4)",
            category=Category.SSH.value,
            severity=Severity.MEDIUM.value,
            status=RuleStatus.PASS if max_tries_pass else RuleStatus.FAIL,
            current_value=f"MaxAuthTries {max_tries_str}",
            expected_value="MaxAuthTries 4 (or less)",
            remediation="Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.",
            rationale="Limiting consecutive authentication failures per connection mitigates rapid in-session dictionary attacks.",
        )
    )

    # 5. X11Forwarding
    # CIS 5.2.6: Ensure SSH X11 forwarding is disabled
    x11 = cfg.get("x11forwarding", "no").lower()
    results.append(
        RuleResult(
            rule_id="CIS-SSH-05",
            title="Disable SSH X11 Graphical Forwarding",
            category=Category.SSH.value,
            severity=Severity.LOW.value,
            status=RuleStatus.PASS if x11 == "no" else RuleStatus.FAIL,
            current_value=f"X11Forwarding {x11}",
            expected_value="X11Forwarding no",
            remediation="Set 'X11Forwarding no' in /etc/ssh/sshd_config.",
            rationale="X11 forwarding can allow an attacker on the remote server to monitor keystrokes or open windows on the client display.",
        )
    )

    # 6. ClientAliveInterval & ClientAliveCountMax
    # CIS 5.2.12: Ensure idle timeout interval is configured
    client_interval_str = cfg.get("clientaliveinterval", "0")
    try:
        client_interval = int(client_interval_str)
        interval_pass = (0 < client_interval <= 900)
    except ValueError:
        interval_pass = False

    results.append(
        RuleResult(
            rule_id="CIS-SSH-06",
            title="Configure SSH Idle Timeout Interval",
            category=Category.SSH.value,
            severity=Severity.MEDIUM.value,
            status=RuleStatus.PASS if interval_pass else RuleStatus.FAIL,
            current_value=f"ClientAliveInterval {client_interval_str}",
            expected_value="ClientAliveInterval 300 (and ClientAliveCountMax 3)",
            remediation="Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3' in /etc/ssh/sshd_config.",
            rationale="Unattended open SSH sessions present an opportunity for physical or network session hijacking.",
        )
    )

    return results
