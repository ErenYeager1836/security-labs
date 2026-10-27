"""
Unit tests for Phase 2 defensive security enhancements across security-labs.
"""

import json
try:
    import pytest
except ImportError:
    pytest = None

from log_analyzer.models import NginxEvent, SSHEvent
from log_analyzer.rules import analyze_ssh_events, analyze_nginx_events, stream_inspect_nginx_event
from hardening_auditor.models import RuleResult, RuleStatus, Severity
from hardening_auditor.remediation import RemediationPlan
from dependency_checker.models import Ecosystem, PackageDependency
from dependency_checker.sbom import generate_cyclonedx_sbom, create_purl


# ==============================================================================
# 1. log-analyzer: MITRE ATT&CK Tagging & Streaming Detection
# ==============================================================================

def test_log_analyzer_mitre_attack_tagging():
    """Verify that SSH and Nginx detection rules attach valid MITRE ATT&CK tactics."""
    ssh_events = [
        SSHEvent(
            timestamp="2026-10-27T10:00:00",
            event_type="failed",
            username=f"user_{i}",
            ip_address="192.168.1.100",
            port=55120,
            raw_line="sample raw line"
        )
        for i in range(10)
    ]
    ssh_alerts = analyze_ssh_events(ssh_events, brute_force_threshold=5)
    assert len(ssh_alerts) == 1
    assert ssh_alerts[0].mitre_attack_id == "T1110.001"
    assert ssh_alerts[0].mitre_tactic == "Credential Access"

    nginx_events = [
        NginxEvent(
            remote_ip="10.0.0.50",
            timestamp="2026-10-27T10:00:00",
            method="GET",
            path="/login?user=admin' UNION SELECT 1,2,3--",
            status_code=200,
            body_bytes=512,
            referer="-",
            user_agent="Mozilla/5.0",
            raw_line="sample nginx line"
        )
    ]
    nginx_alerts = analyze_nginx_events(nginx_events)
    assert len(nginx_alerts) == 1
    assert nginx_alerts[0].mitre_attack_id == "T1190"
    assert nginx_alerts[0].mitre_tactic == "Initial Access"


def test_log_analyzer_live_stream_inspection():
    """Verify that stream_inspect_nginx_event detects live exploit injections instantaneously."""
    exploit_event = NginxEvent(
        remote_ip="203.0.113.15",
        timestamp="2026-10-27T10:05:00",
        method="GET",
        path="/api/item?id=1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)",
        status_code=500,
        body_bytes=120,
        referer="-",
        user_agent="sqlmap/1.7.2#stable",
        raw_line="sample log line"
    )
    alerts = stream_inspect_nginx_event(exploit_event)
    assert len(alerts) >= 1
    exploit_alert = next(a for a in alerts if a.mitre_attack_id == "T1190")
    assert exploit_alert.severity == "CRITICAL"
    assert "203.0.113.15" == exploit_alert.source_ip


# ==============================================================================
# 2. hardening-auditor: Automated Remediation Engine (Dry-Run Diffs)
# ==============================================================================

def test_remediation_unified_diff_generation():
    """Verify that RemediationPlan creates valid standard unified diffs."""
    original = "PermitRootLogin yes\nPasswordAuthentication yes\n"
    fixed = "PermitRootLogin no\nPasswordAuthentication yes\n"
    diff = RemediationPlan.generate_unified_diff("/etc/ssh/sshd_config", original, fixed)
    assert "--- a/etc/ssh/sshd_config" in diff
    assert "+++ b/etc/ssh/sshd_config.hardened" in diff
    assert "-PermitRootLogin yes" in diff
    assert "+PermitRootLogin no" in diff


def test_remediation_dry_run_script_generation():
    """Verify that RemediationPlan builds complete non-destructive shell script."""
    failing_results = [
        RuleResult(
            rule_id="SSH-01",
            title="Disable SSH Root Login",
            category="SSH Configuration",
            severity=Severity.HIGH.value,
            status=RuleStatus.FAIL,
            current_value="yes",
            expected_value="no",
            remediation="sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            rationale="Disabling direct root login prevents brute-force targeting of UID 0."
        )
    ]
    script = RemediationPlan.generate_dry_run_script(failing_results)
    assert "#!/bin/bash" in script
    assert "BACKUP_DIR=\"/var/backups/hardening_" in script
    assert "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config" in script


# ==============================================================================
# 3. dependency-checker: CycloneDX 1.5 JSON SBOM Generation
# ==============================================================================

def test_cyclonedx_sbom_generation(tmp_path):
    """Verify that generate_cyclonedx_sbom outputs a valid CycloneDX 1.5 JSON document."""
    deps = [
        PackageDependency(
            name="requests",
            version="2.25.1",
            ecosystem=Ecosystem.PYPI,
            file_path="requirements.txt",
            line_number=1
        ),
        PackageDependency(
            name="org.apache.logging.log4j:log4j-core",
            version="2.14.1",
            ecosystem=Ecosystem.MAVEN,
            file_path="pom.xml",
            line_number=25
        )
    ]

    out_file = str(tmp_path / "bom.json")
    sbom = generate_cyclonedx_sbom(deps, output_path=out_file)

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert "serialNumber" in sbom
    assert len(sbom["components"]) == 2

    comp1 = sbom["components"][0]
    assert comp1["name"] == "requests"
    assert comp1["purl"] == "pkg:pypi/requests@2.25.1"

    comp2 = sbom["components"][1]
    assert comp2["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

    # Verify JSON persisted file
    with open(out_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["bomFormat"] == "CycloneDX"
