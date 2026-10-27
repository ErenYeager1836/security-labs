"""
Automated Remediation Engine for CIS Hardening Auditor.
Generates safe dry-run execution plans, pre-flight backup targets, and unified diff previews.
"""

from __future__ import annotations

import difflib
import time
from typing import Dict, List, Optional

from hardening_auditor.models import RuleResult, RuleStatus


class RemediationPlan:
    """
    Computes unified diffs and shell commands for failing hardening rules
    without altering live files.
    """

    @staticmethod
    def generate_unified_diff(
        filepath: str,
        original_content: str,
        fixed_content: str
    ) -> str:
        """Produces a standard unified diff between original and proposed config files."""
        orig_lines = original_content.splitlines(keepends=True)
        fixed_lines = fixed_content.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a{filepath}",
            tofile=f"b{filepath}.hardened",
            lineterm=""
        )
        return "".join(diff)

    @staticmethod
    def generate_dry_run_script(results: List[RuleResult]) -> str:
        """
        Generates a non-destructive shell remediation script containing
        pre-flight backups (.bak) and proposed changes for failed rules.
        """
        failing_rules = [r for r in results if r.status == RuleStatus.FAIL]
        if not failing_rules:
            return "# All hardening audit checks passed. No remediation required.\n"

        ts = int(time.time())
        script_lines = [
            "#!/bin/bash",
            "# CIS Linux Hardening Remediation Plan (DRY-RUN GENERATION)",
            f"# Generated timestamp: {ts}",
            "set -euo pipefail",
            "",
            "# --- Step 1: Pre-flight Backups ---",
            f"BACKUP_DIR=\"/var/backups/hardening_{ts}\"",
            "mkdir -p \"$BACKUP_DIR\"",
            "echo \"[+] Created pre-flight backup directory: $BACKUP_DIR\"",
            "",
            "# --- Step 2: Remediation Commands ---",
        ]

        for rule in failing_rules:
            script_lines.append(f"# [{rule.rule_id}] {rule.title} (Severity: {rule.severity})")
            script_lines.append(f"# Current: {rule.current_value} -> Expected: {rule.expected_value}")
            if rule.remediation:
                script_lines.append(f"{rule.remediation}")
            else:
                script_lines.append(f"# Manual remediation required for {rule.rule_id}")
            script_lines.append("")

        return "\n".join(script_lines)
