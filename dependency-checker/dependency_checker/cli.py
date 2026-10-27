"""
CLI interface for dependency-checker.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

from dependency_checker import __version__
from dependency_checker.models import AuditSummary, PackageDependency, Severity
from dependency_checker.osv import OSVClient
from dependency_checker.parsers import PomParser, RequirementsParser
from dependency_checker.report import (
    format_console_report,
    format_json_report,
    format_markdown_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dependency-checker",
        description="Software Supply Chain Vulnerability Auditor for Python (requirements.txt) & Java (pom.xml).",
    )

    parser.add_argument(
        "manifests",
        nargs="*",
        help="Path(s) to requirements.txt or pom.xml files (defaults to autodetecting in current directory).",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "markdown"],
        default="console",
        help="Output report format (default: console).",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Write report to specified file path instead of stdout.",
    )

    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEVER"],
        default="HIGH",
        help="Exit with code 1 if vulnerabilities meet or exceed this severity (default: HIGH).",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console output.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"dependency-checker v{__version__}",
    )

    return parser


def audit_manifests(manifest_paths: List[Path], client: Optional[OSVClient] = None) -> AuditSummary:
    """Parses manifests and queries OSV database."""
    osv = client or OSVClient()
    start_time = time.perf_counter()

    all_deps: List[PackageDependency] = []
    audited_files: List[str] = []

    for path in manifest_paths:
        resolved = path.resolve()
        audited_files.append(str(resolved))

        if resolved.name == "pom.xml" or resolved.suffix == ".xml":
            all_deps.extend(PomParser.parse(resolved))
        else:
            all_deps.extend(RequirementsParser.parse(resolved))

    # Query OSV using batch endpoint
    audits = osv.query_batch(all_deps)
    duration = time.perf_counter() - start_time

    vulnerable_pkgs = sum(1 for a in audits if a.is_vulnerable)
    total_vulns = sum(len(a.vulnerabilities) for a in audits)

    return AuditSummary(
        manifest_files=audited_files,
        total_packages=len(all_deps),
        vulnerable_packages=vulnerable_pkgs,
        total_vulnerabilities=total_vulns,
        duration_seconds=duration,
        audits=audits,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target_paths: List[Path] = []
    if args.manifests:
        for m in args.manifests:
            p = Path(m)
            if p.exists():
                target_paths.append(p)
            else:
                print(f"[!] Warning: manifest file '{m}' not found.", file=sys.stderr)
    else:
        # Autodetect in current directory
        cwd = Path.cwd()
        for candidate in ["requirements.txt", "pom.xml"]:
            p = cwd / candidate
            if p.exists():
                target_paths.append(p)

    if not target_paths:
        print("[!] No requirements.txt or pom.xml manifest files specified or found.", file=sys.stderr)
        return 1

    summary = audit_manifests(target_paths)

    if args.format == "json":
        report_output = format_json_report(summary)
    elif args.format == "markdown":
        report_output = format_markdown_report(summary)
    else:
        report_output = format_console_report(summary, no_color=args.no_color)

    if args.output:
        Path(args.output).write_text(report_output, encoding="utf-8")
        print(f"[+] Audit report written to: {args.output}")
    else:
        print(report_output)

    if args.fail_on == "NEVER":
        return 0

    fail_severity = Severity(args.fail_on)
    should_fail = any(
        v.severity >= fail_severity
        for a in summary.audits
        for v in a.vulnerabilities
    )

    return 1 if should_fail else 0


if __name__ == "__main__":
    sys.exit(main())
