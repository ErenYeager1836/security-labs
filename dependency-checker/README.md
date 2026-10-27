# dependency-checker

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Database: OSV.dev](https://img.shields.io/badge/Database-Google%20OSV.dev-green.svg)](https://osv.dev/)

> **Software supply chain vulnerability auditor for Python (`requirements.txt`) and Java (`pom.xml`) powered by the Google OSV.dev REST API.**

---

## Overview

Software supply chain security is a critical priority in modern application security. Over 80% of lines of code in modern enterprise software come from third-party open-source dependencies.

`dependency-checker` extracts declared dependencies from Python and Java Maven manifests, queries Google's **Open Source Vulnerabilities (OSV.dev)** database via its high-performance batch query endpoint, and generates actionable vulnerability reports with remediation upgrade recommendations and CI quality gates.

---

## Features

1. **Multi-Ecosystem Manifest Support**:
   - **Python (`requirements.txt`)**: Parses pinned packages (`==`), ranges (`>=`, `~=`), strips inline comments, and handles environment markers.
   - **Java (`pom.xml`)**: Parses Maven XML namespaces, traverses `<dependencies>` and `<dependencyManagement>`, and resolves variable properties (e.g. `${log4j.version}`).
2. **OSV.dev Batch Querying**:
   - Uses `https://api.osv.dev/v1/querybatch` to audit an entire dependency manifest in a single HTTP round-trip (auditing dozens of dependencies in under 1 second).
3. **Actionable Remediation**:
   - Extracts exact upgrade target versions (`fixed_versions`) from vulnerability range events.
4. **CI/CD Quality Gates**:
   - Enforce build breaks on vulnerable dependencies using `--fail-on HIGH` or `--fail-on CRITICAL`.
5. **Flexible Output Formats**:
   - Colorized terminal report with severity badges.
   - Markdown summary table export (`-o report.md`).
   - Raw JSON export (`-f json`).

---

## Installation

```bash
cd dependency-checker
pip install -e .
```

---

## Usage Guide

### 1. Basic Scan
Scan a Python `requirements.txt` and Java `pom.xml`:

```bash
# Scan specific files
python -m dependency_checker.cli requirements.txt pom.xml

# Or autodetect in current working directory
python -m dependency_checker.cli
```

### 2. Export Markdown Security Report
```bash
python -m dependency_checker.cli sample_files/requirements.txt -f markdown -o audit_report.md
```

### 3. CI/CD Quality Gate
Fail build (exit code 1) if vulnerabilities with severity `HIGH` or `CRITICAL` are present:
```bash
python -m dependency_checker.cli requirements.txt --fail-on HIGH
```

---

## Sample Output

```text
=== security-labs // dependency-checker ===
Manifests Scanned: requirements.txt, pom.xml
Total Dependencies: 7  |  Vulnerable: 6  |  Advisories: 54  |  Duration: 0.87s

Identified Security Vulnerabilities:
---------------------------------------------------------------------------
1. Package: org.apache.logging.log4j:log4j-core==2.14.1 (Maven) in pom.xml
   [CRITICAL] CVE-2021-44228 (GHSA-jfh8-c2jp-5v3q)
   Summary:  Remote code execution in Log4j 2.x JNDI lookup feature (Log4Shell)
   Upgrade to: 2.15.0, 2.16.0, 2.17.1
   Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-44228

2. Package: urllib3==1.25.8 (PyPI) in requirements.txt
   [HIGH] CVE-2021-33503 (GHSA-q2q7-5pp4-w6pg)
   Summary:  Catastrophic ReDoS in urllib3 URL authority parser
   Upgrade to: 1.26.5
   Reference: https://github.com/urllib3/urllib3/security/advisories/GHSA-q2q7-5pp4-w6pg
---------------------------------------------------------------------------
Severity Breakdown: Critical: 4 | High: 12 | Medium: 38 | Low: 0
```

---

## Testing

Run automated tests (unit tests for parsers, OSV client mocking, and CLI quality gates):

```bash
python -m pytest tests -v
```

---

## Limitations & Roadmap

- [ ] Transitive dependency tree resolution (currently audits direct manifest declarations).
- [ ] Support for Node.js `package.json` / `package-lock.json` and Go `go.mod`.
- [ ] Automated pull request branch creation for version bumps.

---

## License

MIT &copy; 2026 Nithishvelan M (ErenYeager1836).
