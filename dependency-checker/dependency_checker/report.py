"""
Reporting and formatters for dependency-checker.
"""

from __future__ import annotations

import json
import sys
from typing import List

from dependency_checker.models import AuditSummary, Severity


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"

    @classmethod
    def disable(cls) -> None:
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RED = ""
        cls.MAGENTA = ""
        cls.YELLOW = ""
        cls.GREEN = ""
        cls.CYAN = ""


def get_severity_badge(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return f"{Colors.BOLD}{Colors.RED}[CRITICAL]{Colors.RESET}"
    elif severity == Severity.HIGH:
        return f"{Colors.BOLD}{Colors.MAGENTA}[HIGH]{Colors.RESET}"
    elif severity == Severity.MEDIUM:
        return f"{Colors.BOLD}{Colors.YELLOW}[MEDIUM]{Colors.RESET}"
    elif severity == Severity.LOW:
        return f"{Colors.BOLD}{Colors.CYAN}[LOW]{Colors.RESET}"
    return f"{Colors.DIM}[UNKNOWN]{Colors.RESET}"


def format_console_report(summary: AuditSummary, no_color: bool = False) -> str:
    """Renders console output report."""
    if no_color or not sys.stdout.isatty():
        Colors.disable()

    out: List[str] = [
        f"{Colors.BOLD}{Colors.CYAN}=== security-labs // dependency-checker ==={Colors.RESET}",
        f"Manifests Scanned: {', '.join(summary.manifest_files)}",
        f"Total Dependencies: {summary.total_packages}  |  "
        f"Vulnerable: {summary.vulnerable_packages}  |  "
        f"Advisories: {summary.total_vulnerabilities}  |  "
        f"Duration: {summary.duration_seconds:.2f}s",
        "",
    ]

    if summary.total_vulnerabilities == 0:
        out.append(f"{Colors.BOLD}{Colors.GREEN}No known vulnerabilities identified in audited packages!{Colors.RESET}\n")
        return "\n".join(out)

    out.append(f"{Colors.BOLD}{Colors.RED}Identified Security Vulnerabilities:{Colors.RESET}")
    out.append("-" * 75)

    idx = 1
    for audit in summary.audits:
        if not audit.is_vulnerable:
            continue

        dep = audit.dependency
        out.append(
            f"{Colors.BOLD}{idx}. Package: {Colors.CYAN}{dep.name}=={dep.version}{Colors.RESET} "
            f"({dep.ecosystem.value}) in {dep.file_path}"
        )

        for vuln in audit.vulnerabilities:
            badge = get_severity_badge(vuln.severity)
            out.append(f"   {badge} {Colors.BOLD}{vuln.display_cve}{Colors.RESET} ({vuln.id})")
            if vuln.summary:
                out.append(f"   {Colors.DIM}Summary:{Colors.RESET}  {vuln.summary}")
            if vuln.fixed_versions:
                fix_str = ", ".join(vuln.fixed_versions)
                out.append(f"   {Colors.GREEN}{Colors.BOLD}Upgrade to:{Colors.RESET} {fix_str}")
            if vuln.references:
                out.append(f"   {Colors.DIM}Reference:{Colors.RESET} {vuln.references[0]}")
            out.append("")

        idx += 1

    out.append("-" * 75)
    out.append(
        f"Severity Breakdown: "
        f"{Colors.RED}Critical: {summary.critical_count}{Colors.RESET} | "
        f"{Colors.MAGENTA}High: {summary.high_count}{Colors.RESET} | "
        f"{Colors.YELLOW}Medium: {summary.medium_count}{Colors.RESET} | "
        f"{Colors.CYAN}Low: {summary.low_count}{Colors.RESET}"
    )

    return "\n".join(out)


def format_markdown_report(summary: AuditSummary) -> str:
    """Renders detailed Markdown audit report."""
    md: List[str] = [
        "# Software Supply Chain Vulnerability Audit Report",
        "",
        f"**Manifests Audited:** `{', '.join(summary.manifest_files)}`  ",
        f"**Total Packages:** {summary.total_packages}  ",
        f"**Vulnerable Packages:** {summary.vulnerable_packages}  ",
        f"**Total Security Advisories:** {summary.total_vulnerabilities}  ",
        f"**Duration:** {summary.duration_seconds:.2f}s  ",
        "",
        "## Severity Breakdown",
        "",
        f"- **Critical:** {summary.critical_count}",
        f"- **High:** {summary.high_count}",
        f"- **Medium:** {summary.medium_count}",
        f"- **Low:** {summary.low_count}",
        "",
        "---",
        "",
        "## Vulnerability Details",
        "",
        "| Package | Version | Ecosystem | Advisory / CVE | Severity | Recommended Fix | Summary |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for audit in summary.audits:
        if not audit.is_vulnerable:
            continue
        dep = audit.dependency
        for vuln in audit.vulnerabilities:
            fix_str = f"`{', '.join(vuln.fixed_versions)}`" if vuln.fixed_versions else "No fix documented"
            clean_summary = vuln.summary.replace("|", "\\|").replace("\n", " ")[:90]
            md.append(
                f"| `{dep.name}` | `{dep.version}` | {dep.ecosystem.value} | "
                f"**{vuln.display_cve}** | `{vuln.severity.value}` | {fix_str} | {clean_summary} |"
            )

    return "\n".join(md)


def format_json_report(summary: AuditSummary) -> str:
    """Renders structured JSON report."""
    return json.dumps(summary.to_dict(), indent=2)
