"""
CIS-style Sudoers & Privilege Delegation Audit Rules.

Reference: CIS Linux Benchmark Section 5.3 (Configure Sudo).
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import List, Set, Tuple

from hardening_auditor.models import Category, RuleResult, RuleStatus, Severity


def read_sudoers_lines(root_dir: Path) -> List[Tuple[str, str]]:
    """Reads all non-comment lines from /etc/sudoers and /etc/sudoers.d/*."""
    lines_with_source: List[Tuple[str, str]] = []
    sudoers_main = root_dir / "etc" / "sudoers"

    files_to_read: List[Path] = []
    if sudoers_main.is_file():
        files_to_read.append(sudoers_main)
    else:
        alt_main = root_dir / "sudoers"
        if alt_main.is_file():
            files_to_read.append(alt_main)

    sudoers_d = root_dir / "etc" / "sudoers.d"
    if sudoers_d.is_dir():
        for dropin in sorted(sudoers_d.iterdir()):
            if dropin.is_file() and not dropin.name.startswith((".", "~")) and not dropin.name.endswith("~"):
                files_to_read.append(dropin)

    for p in files_to_read:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    sline = line.strip()
                    if sline and not sline.startswith("#"):
                        lines_with_source.append((sline, p.name))
        except OSError:
            pass

    return lines_with_source


def audit_sudo_config(root_dir: Path) -> List[RuleResult]:
    """Audits sudoers configuration files for CIS benchmark compliance."""
    results: List[RuleResult] = []
    active_lines = read_sudoers_lines(root_dir)

    if not active_lines:
        results.append(
            RuleResult(
                rule_id="CIS-SUDO-00",
                title="Sudoers Configuration File Presence",
                category=Category.SUDO.value,
                severity=Severity.HIGH.value,
                status=RuleStatus.SKIP,
                current_value="No sudoers files found",
                expected_value="File exists at /etc/sudoers",
                remediation="Install sudo and create /etc/sudoers using visudo.",
                rationale="The sudoers privilege configuration file could not be read or does not exist.",
            )
        )
        return results

    # 1. NOPASSWD: ALL checks
    # Look for entries like: "%admin ALL=(ALL) NOPASSWD: ALL" or "deploy ALL=(ALL:ALL) NOPASSWD: ALL"
    nopasswd_entries: List[str] = []
    for line, src in active_lines:
        if "NOPASSWD" in line.upper():
            # Check if this rule is granting ALL commands without password
            if re.search(r"NOPASSWD:\s*ALL", line, re.IGNORECASE):
                nopasswd_entries.append(f"{line} [{src}]")

    if nopasswd_entries:
        results.append(
            RuleResult(
                rule_id="CIS-SUDO-01",
                title="Restrict Passwordless Sudo (NOPASSWD: ALL)",
                category=Category.SUDO.value,
                severity=Severity.CRITICAL.value,
                status=RuleStatus.FAIL,
                current_value=f"Found {len(nopasswd_entries)} passwordless ALL entry/entries: {', '.join(nopasswd_entries[:2])}",
                expected_value="No unrestricted 'NOPASSWD: ALL' directives",
                remediation="Run 'visudo' and remove or restrict 'NOPASSWD: ALL' to specific audited commands.",
                rationale="Granting unrestricted passwordless root execution enables any compromised local user shell to achieve instant, unauthenticated root takeover.",
            )
        )
    else:
        results.append(
            RuleResult(
                rule_id="CIS-SUDO-01",
                title="Restrict Passwordless Sudo (NOPASSWD: ALL)",
                category=Category.SUDO.value,
                severity=Severity.CRITICAL.value,
                status=RuleStatus.PASS,
                current_value="No unrestricted 'NOPASSWD: ALL' directives found",
                expected_value="No unrestricted 'NOPASSWD: ALL' directives",
                remediation="Maintain password confirmation on all administrative commands.",
                rationale="Requiring password confirmation prevents automated malware or hijacked terminal sessions from elevating to root.",
            )
        )

    # 2. Defaults use_pty
    has_use_pty = any(re.search(r"Defaults\s+([^#]*\buse_pty\b)", line) for line, _ in active_lines)
    results.append(
        RuleResult(
            rule_id="CIS-SUDO-02",
            title="Ensure Sudo Runs Commands in a Dedicated Pseudo-Terminal (use_pty)",
            category=Category.SUDO.value,
            severity=Severity.MEDIUM.value,
            status=RuleStatus.PASS if has_use_pty else RuleStatus.FAIL,
            current_value="Defaults use_pty configured" if has_use_pty else "Defaults use_pty NOT configured",
            expected_value="Defaults use_pty present in /etc/sudoers",
            remediation="Add 'Defaults use_pty' to /etc/sudoers using visudo.",
            rationale="Running sudo in its own pseudo-terminal prevents malicious background processes from eavesdropping on user input or spoofing terminal responses.",
        )
    )

    # 3. Defaults env_reset
    has_env_reset = any(re.search(r"Defaults\s+([^#]*\benv_reset\b)", line) for line, _ in active_lines)
    results.append(
        RuleResult(
            rule_id="CIS-SUDO-03",
            title="Ensure Sudo Environment Variables are Reset (env_reset)",
            category=Category.SUDO.value,
            severity=Severity.HIGH.value,
            status=RuleStatus.PASS if has_env_reset else RuleStatus.FAIL,
            current_value="Defaults env_reset configured" if has_env_reset else "Defaults env_reset NOT configured",
            expected_value="Defaults env_reset present in /etc/sudoers",
            remediation="Add 'Defaults env_reset' to /etc/sudoers using visudo.",
            rationale="Resetting environment variables prevents privilege escalation via manipulated LD_PRELOAD, PYTHONPATH, or PATH values.",
        )
    )

    # 4. Defaults logfile
    has_logfile = any(re.search(r"Defaults\s+([^#]*logfile\s*=)", line) for line, _ in active_lines)
    results.append(
        RuleResult(
            rule_id="CIS-SUDO-04",
            title="Ensure Sudo Execution Logging is Configured (logfile)",
            category=Category.SUDO.value,
            severity=Severity.MEDIUM.value,
            status=RuleStatus.PASS if has_logfile else RuleStatus.FAIL,
            current_value="Defaults logfile configured" if has_logfile else "Defaults logfile NOT configured",
            expected_value='Defaults logfile="/var/log/sudo.log" in /etc/sudoers',
            remediation='Add \'Defaults logfile="/var/log/sudo.log"\' to /etc/sudoers using visudo.',
            rationale="Dedicated sudo logs preserve non-repudiation and forensic visibility when investigating administrative commands.",
        )
    )

    return results
