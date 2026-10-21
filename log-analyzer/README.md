# `log-analyzer`

> Automated defensive security log analysis engine for Linux SSH authentication logs (`auth.log` / `secure`) and Nginx HTTP access logs (`access.log`). Detects credential brute-forcing, directory fuzzing/path traversal, automated vulnerability scanners, and exploit payload injection, generating an actionable Markdown incident response report.

---

## Features

- **Dual-Source Log Parsing**:
  - **SSH (`/var/log/auth.log`, `/var/log/secure`)**: Tracks failed password attempts, invalid user enumerations, and successful logins.
  - **Nginx (`/var/log/nginx/access.log`)**: Parses Combined Log Format and custom formats with URL decoding and status code tracking.
- **Defensive Rule Engine**:
  - **SSH Brute-Force & Credential Stuffing**: Aggregates failed authentication attempts per source IP against a configurable threshold, highlighting targeted usernames and root account targeting.
  - **Automated Web Scanner Detection**: Matches signatures of attack tools such as `sqlmap`, `nikto`, `wpscan`, `nuclei`, `dirbuster`, `gobuster`, `nmap`, and scripting user agents.
  - **Sensitive Path Enumeration**: Flags probes targeting `.env` files, `.git` repositories, WordPress administration endpoints (`wp-admin`), database interfaces (`phpMyAdmin`), and backup dumps.
  - **Exploit Injections & Traversal**: Identifies SQL injection sequences (`UNION SELECT`, `WAITFOR DELAY`), path traversal (`../../`), and reflected XSS probes.
- **Incident Response Report**:
  - Generates a GitHub-flavored Markdown report (`security_report.md`) complete with executive metrics, evidence tables, severity ratings (CRITICAL / HIGH / MEDIUM / LOW), and copy-pasteable firewall remediation commands (`iptables`).
- **Zero Third-Party Dependencies**: Pure Python 3.10+ standard library implementation.

---

## Installation

No external dependencies are required. Simply clone the repository or copy the directory:

```bash
cd log-analyzer
python --version  # Requires Python 3.10+
```

Optional editable install:
```bash
pip install -e .
```

---

## Usage

### Analyze Both SSH and Nginx Logs

```bash
python log_analyzer/cli.py \
  --auth-log sample_logs/auth.log \
  --nginx-log sample_logs/access.log \
  --output report.md \
  --print-report
```

### Command-Line Arguments

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--auth-log` | `FILE` | `None` | Path to SSH authentication log (`/var/log/auth.log` or `sample_logs/auth.log`) |
| `--nginx-log` | `FILE` | `None` | Path to Nginx access log (`/var/log/nginx/access.log` or `sample_logs/access.log`) |
| `-o`, `--output` | `FILE` | `security_report.md`| Output file path for Markdown incident report |
| `--threshold` | `INT` | `5` | Failed SSH attempt threshold required before raising a brute-force alert |
| `--print-report` | `FLAG`| `False` | Also print the full Markdown report to stdout |

---

## Sample Output

```text
=========================================================
         security-labs // log-analyzer (Python)          
   Defensive SSH & Nginx Security Anomaly Auditor        
=========================================================

[*] Parsing SSH authentication log: sample_logs/auth.log
[+] Scanned 22 SSH events (21 failed, 1 accepted).
[*] Parsing Nginx access log: sample_logs/access.log
[+] Scanned 14 HTTP access requests across 4 client IPs.

--- Detection Findings Summary ---
[!] Total Alerts Flagged: 9
    - CRITICAL: 4
    - HIGH:     5
    - MEDIUM:   0
    - LOW:      0

  #1 [CRITICAL] SSH Brute-Force Authentication Attack from 198.51.100.44 (Count: 12)
  #2 [CRITICAL] SSH Brute-Force Authentication Attack from 203.0.113.89 (Count: 9)
  #3 [CRITICAL] Web Exploit Payload Attempt from 198.51.100.77 (Count: 2)
  #4 [CRITICAL] Web Exploit Payload Attempt from 192.0.2.88 (Count: 2)
  #5 [HIGH] Automated Web Scanner / Suspicious User-Agent from 203.0.113.12 (Count: 6)
  ... and 4 more alert(s) in report.

[+] Security Audit Report exported to: security_report.md
```

---

## Sample Incident Report Excerpt

The generated `security_report.md` provides defensive remediation actions:

```markdown
### Immediate Firewall Blocklist (`iptables` / `nftables`)
```bash
iptables -A INPUT -s 192.0.2.88 -j DROP
iptables -A INPUT -s 198.51.100.44 -j DROP
iptables -A INPUT -s 198.51.100.77 -j DROP
iptables -A INPUT -s 203.0.113.12 -j DROP
iptables -A INPUT -s 203.0.113.89 -j DROP
```
```

---

## Testing

Run unit tests with `pytest`:

```bash
pytest -v tests/
```

All 11 unit tests validate:
- SSH event parsing (failed passwords, invalid usernames, accepted public keys).
- Brute-force threshold logic (ignoring low count, alerting on high count/root targeting).
- Nginx Combined format parsing with query parameter extraction.
- Scanner User-Agent pattern recognition.
- Sensitive directory path traversal and configuration exposure detection.
- Active exploit injection payload detection (SQLi, XSS, LFI).
- Report generation schema and markdown rendering.

---

## Limitations & Roadmap

- **Streaming / Real-Time**: Currently operates in batch mode over archived logs. Future versions could tail logs (`tail -F`) or integrate with `systemd-journald`.
- **IP Reputation Lookups**: Future integration with AbuseIPDB or GreyNoise APIs to correlate source IPs with known threat actors.
- **Log Rotation**: Currently analyzes single uncompressed files; support for `.gz` log archives planned.
