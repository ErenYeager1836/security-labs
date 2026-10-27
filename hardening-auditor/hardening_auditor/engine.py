"""
Compliance assessment engine aggregating CIS-style rules across SSH, permissions, ports, and sudoers.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from hardening_auditor.models import AuditSummary, RuleResult, RuleStatus
from hardening_auditor.rules.permissions import audit_file_permissions
from hardening_auditor.rules.ports import audit_open_ports
from hardening_auditor.rules.ssh import audit_ssh_config
from hardening_auditor.rules.sudo import audit_sudo_config


def run_system_audit(root_dir: Optional[Path] = None) -> AuditSummary:
    """Executes a full read-only security compliance audit against the specified filesystem root.

    This function is strictly READ-ONLY. It never creates, modifies, deletes, or alters
    any system files, permissions, network configurations, or active services.
    """
    if root_dir is None:
        root_dir = Path("/")

    all_results: List[RuleResult] = []

    # 1. SSH Server Configuration
    all_results.extend(audit_ssh_config(root_dir))

    # 2. Critical File & Directory Permissions
    all_results.extend(audit_file_permissions(root_dir))

    # 3. Network Services & Insecure Listening Ports
    all_results.extend(audit_open_ports(root_dir))

    # 4. Sudoers Configuration & Privilege Delegation
    all_results.extend(audit_sudo_config(root_dir))

    passed = sum(1 for r in all_results if r.status == RuleStatus.PASS)
    failed = sum(1 for r in all_results if r.status == RuleStatus.FAIL)
    skipped = sum(1 for r in all_results if r.status == RuleStatus.SKIP)

    scored_total = passed + failed
    score_pct = (passed / scored_total * 100.0) if scored_total > 0 else 100.0

    return AuditSummary(
        total_rules=len(all_results),
        passed_rules=passed,
        failed_rules=failed,
        skipped_rules=skipped,
        score_percentage=round(score_pct, 1),
        results=all_results,
    )
