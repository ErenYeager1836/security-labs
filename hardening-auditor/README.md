# hardening-auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Read Only](https://img.shields.io/badge/mode-read--only-brightgreen.svg)](#read-only-safety-guarantee)

> **Read-only security compliance and hardening auditor for Linux systems aligned with CIS Benchmark recommendations.**  
> Audits SSH configurations, system file permissions, dangerous open ports, and sudo privileges against published CIS Linux Benchmark recommendations, calculates a compliance score, and provides actionable remediation commands.

---

## Security & Authorized-Use Policy

> [!IMPORTANT]
> **Authorized Assessment Notice & Read-Only Invariant**: `hardening-auditor` is designed strictly for evaluating the security posture of Linux hosts and containers that you own or are explicitly authorized to audit. It **never** alters configuration files, modifies filesystem permissions, terminates listening services, or executes state-changing actions. All remediation steps are emitted as suggestions for operator review.

---

## Benchmark Item Mapping & Control Counts

The checks in this tool are defensive configuration audits mapped directly to recommendation items from the **CIS Distribution-Independent Linux / Ubuntu Linux Benchmark (v1.1.0/v2.0.0)**. They should not be confused with top-level CIS Critical Security Controls (CIS Controls v8).

| Rule ID | CIS Benchmark Item | Category | Description |
| :--- | :--- | :--- | :--- |
| `CIS-SSH-01` | Section 5.2.10 | SSH | Disable direct SSH root login (`PermitRootLogin no`) |
| `CIS-SSH-02` | Section 5.2.14 | SSH | Require SSH public key authentication (`PasswordAuthentication no`) |
| `CIS-SSH-03` | Section 5.2.11 | SSH | Disable empty SSH passwords (`PermitEmptyPasswords no`) |
| `CIS-SSH-04` | Section 5.2.7 | SSH | Limit SSH maximum authentication attempts (`MaxAuthTries <= 4`) |
| `CIS-SSH-05` | Section 5.2.6 | SSH | Disable SSH X11 graphical forwarding (`X11Forwarding no`) |
| `CIS-SSH-06` | Section 5.2.16 | SSH | Enforce SSH idle timeout interval (`ClientAliveInterval 300`) |
| `CIS-PERM-01` | Section 6.1.3 | File Permissions | Enforce restrictive permissions on `/etc/shadow` (0640 or 0600) |
| `CIS-PERM-02` | Section 6.1.5 | File Permissions | Enforce restrictive permissions on `/etc/gshadow` (0640 or 0600) |
| `CIS-PERM-03` | Section 6.1.2 | File Permissions | Enforce restrictive permissions on `/etc/passwd` (0644, not world-writable) |
| `CIS-PERM-04` | Section 6.1.4 | File Permissions | Enforce restrictive permissions on `/etc/group` (0644, not world-writable) |
| `CIS-PERM-05` | Section 5.3.1 | File Permissions | Enforce restrictive permissions on `/etc/sudoers` (0440 or 0400) |
| `CIS-PORT-01` | Section 2.1.18 | Open Ports | Ensure Telnet server is not listening (TCP 23) |
| `CIS-PORT-02` | Section 2.1.8 | Open Ports | Ensure unencrypted FTP daemon is not listening (TCP 21) |
| `CIS-PORT-03` | Section 2.1.15 | Open Ports | Ensure legacy `rsh`/`rlogin`/`rcp` daemons are not listening (512-514) |
| `CIS-PORT-04` | Section 2.1.19 | Open Ports | Ensure TFTP daemon is not listening (UDP 69) |
| `CIS-SUDO-00` | Section 5.3.1 | Sudoers | Verify `/etc/sudoers` configuration file presence and readability |
| `CIS-SUDO-01` | Section 5.3.4 | Sudoers | Restrict passwordless sudo delegation (`NOPASSWD: ALL`) |
| `CIS-SUDO-02` | Section 5.3.2 | Sudoers | Ensure sudo executes commands in a dedicated pseudo-terminal (`use_pty`) |
| `CIS-SUDO-03` | Section 5.3.3 | Sudoers | Ensure sudo resets environment variables (`env_reset`) |
| `CIS-SUDO-04` | Section 5.3.7 | Sudoers | Ensure sudo command execution logging is configured (`logfile`) |

### Total Controls Audited: 19 vs. 16 Explained
- **19 checks**: When auditing a target filesystem where `/etc/sudoers` is readable (e.g. running against fixture trees like `sample_configs/unhardened` or `sample_configs/hardened`, or when executing with root privileges on the live host): 6 SSH checks + 5 File permission checks + 4 Port checks + 4 Sudoers checks (`CIS-SUDO-01` through `CIS-SUDO-04`).
- **16 checks**: When executing without root/sudo privileges against the live host `/`: `/etc/sudoers` has mode 0440 (readable only by root). Because the unprivileged auditor cannot read `/etc/sudoers`, it records 1 distinct `could not check` result for `CIS-SUDO-00` and does not run the 4 privileged sub-checks, yielding 6 + 5 + 4 + 1 = 16 total controls. A status of `could not check` does **not** count as a pass in the compliance score.

---

## Features

1. **SSH Daemon Configuration (`sshd_config`)**:
   - Disables direct root login (`PermitRootLogin no`)
   - Requires public key authentication (`PasswordAuthentication no`)
   - Prohibits empty passwords (`PermitEmptyPasswords no`)
   - Limits authentication attempts (`MaxAuthTries <= 4`)
   - Disables graphical X11 forwarding (`X11Forwarding no`)
   - Enforces idle connection termination (`ClientAliveInterval 300`)
2. **System File Permissions**:
   - Enforces restrictive mode on sensitive identity files: `/etc/shadow` (0600), `/etc/gshadow` (0600), `/etc/passwd` (0644), `/etc/group` (0644), and `/etc/sudoers` (0440).
3. **Insecure Network Services & Open Ports**:
   - Detects cleartext and legacy listening services: Telnet (23), Insecure FTP (21), legacy `rsh`/`rlogin`/`rcp` (512-514), and TFTP (69).
4. **Sudoers & Privilege Delegation**:
   - Flags unrestricted passwordless execution (`NOPASSWD: ALL`).
   - Ensures commands run in an isolated pseudo-terminal (`Defaults use_pty`).
   - Ensures environment variables are reset (`Defaults env_reset`).
   - Verifies audit logging (`Defaults logfile="/var/log/sudo.log"`).
5. **Flexible Output Formats**:
   - ANSI terminal scorecard with color badges.
   - Comprehensive Markdown report export (`--output report.md`).
   - Machine-readable JSON output (`--json`) for pipeline integration.
6. **Portable Mock Root Support**:
   - Supports `--root <directory>` to audit chroot environments, container images, or test fixtures on Windows/macOS.

---

## Installation

```bash
cd hardening-auditor
pip install -e .
```

---

## Usage Guide

### 1. Audit Live System (Linux / Root)
```bash
python -m hardening_auditor.cli
```

### 2. Audit a Mounted Chroot / Container Image / Test Fixture
```bash
python -m hardening_auditor.cli --root sample_configs/unhardened
```

### 3. Generate a Markdown Compliance Report
```bash
python -m hardening_auditor.cli --root sample_configs/unhardened -o audit_report.md
```

### 4. Output Raw JSON for SIEM / CI Quality Gate
```bash
python -m hardening_auditor.cli --root sample_configs/hardened --json
```

### 5. Display Remediation Fixes Only
```bash
python -m hardening_auditor.cli --fixes-only
```

---

## Sample Terminal Output

```text
================================================================
      security-labs // hardening-auditor (Python)       
      CIS-Style Read-Only Linux Security Auditor        
================================================================
[*] Target Directory Root : /etc
[*] Total Controls Audited: 19
[+] Passed Controls       : 18
[-] Failed Controls       : 1
[~] Skipped Controls      : 0
[*] Compliance Score      : 94.7%
----------------------------------------------------------------

[+] Category: SSH Configuration
  [PASS]   CIS-SSH-01: Disable Direct SSH Root Login (CRITICAL)
  [PASS]   CIS-SSH-02: Disable SSH Password Authentication (HIGH)
  [PASS]   CIS-SSH-03: Disable Empty SSH Passwords (CRITICAL)
  [PASS]   CIS-SSH-04: Configure SSH MaxAuthTries (MEDIUM)
  [PASS]   CIS-SSH-05: Disable SSH X11 Graphical Forwarding (LOW)
  [PASS]   CIS-SSH-06: Configure SSH Idle Timeout Interval (MEDIUM)

[+] Category: File & Directory Permissions
  [PASS]   CIS-PERM-01: Permissions on /etc/shadow (CRITICAL)
  [PASS]   CIS-PERM-02: Permissions on /etc/gshadow (CRITICAL)
  [PASS]   CIS-PERM-03: Permissions on /etc/passwd (CRITICAL)
  [PASS]   CIS-PERM-04: Permissions on /etc/group (HIGH)
  [PASS]   CIS-PERM-05: Permissions on /etc/sudoers (CRITICAL)

[+] Category: Network Services & Open Ports
  [PASS]   CIS-PORT-01: Ensure Telnet Server is Not Listening (Port 23) (CRITICAL)
  [PASS]   CIS-PORT-02: Ensure Insecure FTP Server is Not Listening (Port 21) (HIGH)
  [PASS]   CIS-PORT-03: Ensure Legacy rsh/rlogin/rcp Services are Not Listening (CRITICAL)
  [PASS]   CIS-PORT-04: Ensure TFTP Server is Not Listening (UDP Port 69) (HIGH)

[+] Category: Sudoers & Privilege Delegation
  [PASS]   CIS-SUDO-01: Restrict Passwordless Sudo (CRITICAL)
  [PASS]   CIS-SUDO-02: Ensure Sudo Runs Commands in Pseudo-Terminal (MEDIUM)
  [PASS]   CIS-SUDO-03: Ensure Sudo Environment Variables are Reset (HIGH)
  [FAIL]   CIS-SUDO-04: Ensure Sudo Execution Logging is Configured (MEDIUM)
           Current:  Defaults logfile NOT configured
           Expected: Defaults logfile="/var/log/sudo.log" in /etc/sudoers
           Fix:      Add 'Defaults logfile="/var/log/sudo.log"' to /etc/sudoers using visudo.

================================================================
               RECOMMENDED REMEDIATION COMMANDS                
================================================================
# Execute with root / sudo permissions after reviewing impact:
#1. [CIS-SUDO-04] Ensure Sudo Execution Logging is Configured
Add 'Defaults logfile="/var/log/sudo.log"' to /etc/sudoers using visudo.

[!] NOTE: hardening-auditor is read-only. No system changes were applied.
```

---

## Testing

Run the automated test suite verifying both unhardened and hardened fixture states as well as file read-only invariants:

```bash
python -m pytest tests -v
```

---

## Limitations

1. **Linux Specific**: Designed for Linux operating systems. Audits on Windows use the `--root` flag pointing to mock Unix directory trees.
2. **Standard File Layout**: Assumes standard Linux paths (`/etc/ssh/sshd_config`, `/etc/sudoers`, `/etc/shadow`). Custom daemon locations must be mapped under the target `--root`.
3. **Read-Only Scope**: Does not automatically remediate findings. Remediation must be executed manually by an administrator.

---

## Roadmap

- [ ] Kernel parameter auditing (`/etc/sysctl.conf` / `/proc/sys/net/ipv4/conf/all/rp_filter`, ASLR verification).
- [ ] Automated remediation generator (`--generate-ansible-playbook`).
- [ ] Integration with OpenSCAP XCCDF format.

---

## License

MIT &copy; 2026 Nithishvelan M (ErenYeager1836).
