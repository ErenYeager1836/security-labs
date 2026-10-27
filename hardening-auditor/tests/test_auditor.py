"""
Unit test suite for hardening-auditor.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest

from hardening_auditor.engine import run_system_audit
from hardening_auditor.models import RuleStatus, Severity
from hardening_auditor.rules.permissions import audit_file_permissions
from hardening_auditor.rules.ports import audit_open_ports
from hardening_auditor.rules.ssh import audit_ssh_config, parse_sshd_config
from hardening_auditor.rules.sudo import audit_sudo_config, read_sudoers_lines


SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_configs"
UNHARDENED_DIR = SAMPLE_DIR / "unhardened"
HARDENED_DIR = SAMPLE_DIR / "hardened"


def test_ssh_parsing_and_unhardened_audit():
    results = audit_ssh_config(UNHARDENED_DIR)
    rule_map = {r.rule_id: r for r in results}

    assert rule_map["CIS-SSH-01"].status == RuleStatus.FAIL  # PermitRootLogin yes
    assert rule_map["CIS-SSH-02"].status == RuleStatus.FAIL  # PasswordAuthentication yes
    assert rule_map["CIS-SSH-03"].status == RuleStatus.FAIL  # PermitEmptyPasswords yes
    assert rule_map["CIS-SSH-04"].status == RuleStatus.FAIL  # MaxAuthTries 10 (> 4)
    assert rule_map["CIS-SSH-05"].status == RuleStatus.FAIL  # X11Forwarding yes
    assert rule_map["CIS-SSH-06"].status == RuleStatus.FAIL  # ClientAliveInterval 0


def test_ssh_hardened_audit():
    results = audit_ssh_config(HARDENED_DIR)
    for r in results:
        assert r.status == RuleStatus.PASS, f"Expected rule {r.rule_id} ({r.title}) to PASS, got {r.status}"


def test_permissions_unhardened():
    results = audit_file_permissions(UNHARDENED_DIR)
    rule_map = {r.rule_id: r for r in results}

    assert rule_map["CIS-PERM-01"].status == RuleStatus.FAIL  # 0666 on shadow
    assert rule_map["CIS-PERM-02"].status == RuleStatus.FAIL  # 0666 on gshadow
    assert rule_map["CIS-PERM-03"].status == RuleStatus.FAIL  # 0666 on passwd
    assert rule_map["CIS-PERM-04"].status == RuleStatus.FAIL  # 0666 on group
    assert rule_map["CIS-PERM-05"].status == RuleStatus.FAIL  # 0666 on sudoers


def test_permissions_hardened():
    results = audit_file_permissions(HARDENED_DIR)
    for r in results:
        assert r.status == RuleStatus.PASS, f"Expected {r.rule_id} to PASS, got {r.status}"


def test_open_ports_unhardened():
    results = audit_open_ports(UNHARDENED_DIR)
    rule_map = {r.rule_id: r for r in results}

    assert rule_map["CIS-PORT-01"].status == RuleStatus.FAIL  # Port 23 telnet open
    assert rule_map["CIS-PORT-02"].status == RuleStatus.FAIL  # Port 21 ftp open
    assert rule_map["CIS-PORT-03"].status == RuleStatus.FAIL  # Port 514 rsh open


def test_open_ports_hardened():
    results = audit_open_ports(HARDENED_DIR)
    for r in results:
        assert r.status == RuleStatus.PASS, f"Port {r.rule_id} should PASS"


def test_sudo_unhardened():
    results = audit_sudo_config(UNHARDENED_DIR)
    rule_map = {r.rule_id: r for r in results}

    assert rule_map["CIS-SUDO-01"].status == RuleStatus.FAIL  # NOPASSWD: ALL detected
    assert rule_map["CIS-SUDO-02"].status == RuleStatus.FAIL  # use_pty missing
    assert rule_map["CIS-SUDO-03"].status == RuleStatus.FAIL  # env_reset missing
    assert rule_map["CIS-SUDO-04"].status == RuleStatus.FAIL  # logfile missing


def test_sudo_hardened():
    results = audit_sudo_config(HARDENED_DIR)
    for r in results:
        assert r.status == RuleStatus.PASS, f"{r.rule_id} should PASS"


def test_full_system_audit_unhardened_score():
    summary = run_system_audit(UNHARDENED_DIR)
    assert summary.total_rules >= 18
    assert summary.failed_rules >= 14
    assert summary.score_percentage < 30.0
    assert summary.critical_failures >= 5


def test_full_system_audit_hardened_score():
    summary = run_system_audit(HARDENED_DIR)
    assert summary.total_rules >= 18
    assert summary.failed_rules == 0
    assert summary.score_percentage == 100.0


def test_read_only_invariant():
    """Verify that auditing an arbitrary directory never writes or mutates any files."""
    import hashlib

    def compute_tree_checksums(dir_path: Path) -> dict[str, str]:
        hashes = {}
        for p in dir_path.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(dir_path))
                hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        return hashes

    before = compute_tree_checksums(UNHARDENED_DIR)
    # Run audit twice
    run_system_audit(UNHARDENED_DIR)
    run_system_audit(UNHARDENED_DIR)
    after = compute_tree_checksums(UNHARDENED_DIR)

    assert before == after, "Hardening audit violated read-only invariant and modified file(s)!"
