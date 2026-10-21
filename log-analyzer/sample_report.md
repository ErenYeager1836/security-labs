# Security Log Audit Report
**Generated:** 2026-10-21 11:40:57 UTC  
**Scanner:** `log-analyzer v0.1.0`  

---

## 1. Executive Summary

| Metric | Count |
| :--- | :--- |
| **SSH Events Scanned** | 22 |
| **Failed SSH Logins** | 21 |
| **Accepted SSH Logins** | 1 |
| **Unique SSH Source IPs** | 3 |
| **Nginx Access Requests Scanned** | 14 |
| **Unique Nginx Client IPs** | 4 |
| **Total Security Alerts** | 9 |
| **Critical / High Severity Alerts** | 4 Critical / 5 High |

### Alert Severity Distribution

- **CRITICAL**: 4
- **HIGH**: 5
- **MEDIUM**: 0
- **LOW**: 0

---

## 2. Security Alerts & Anomaly Detections

### Alert #1: [CRITICAL] SSH Brute-Force Authentication Attack

- **Source IP:** `198.51.100.44`
- **Severity:** `CRITICAL`
- **Activity Count:** 12
- **Details:** Host 198.51.100.44 triggered 12 failed SSH authentication attempts targeting user accounts: admin, deploy, guest, oracle, postgres.
- **Supporting Evidence:**
  - `Total failed attempts: 12`
  - `Targeted usernames (8): admin, deploy, guest, oracle, postgres, root, test, ubuntu`
  - `First failure: Oct 21 04:12:01`
  - `Latest failure: Oct 21 04:12:38`

### Alert #2: [CRITICAL] SSH Brute-Force Authentication Attack

- **Source IP:** `203.0.113.89`
- **Severity:** `CRITICAL`
- **Activity Count:** 9
- **Details:** Host 203.0.113.89 triggered 9 failed SSH authentication attempts targeting user accounts: ansible, dev, git, monitoring, root.
- **Supporting Evidence:**
  - `Total failed attempts: 9`
  - `Targeted usernames (6): ansible, dev, git, monitoring, root, support`
  - `First failure: Oct 21 05:01:12`
  - `Latest failure: Oct 21 05:01:31`

### Alert #3: [CRITICAL] Web Exploit Payload Attempt

- **Source IP:** `198.51.100.77`
- **Severity:** `CRITICAL`
- **Activity Count:** 2
- **Details:** Identified 2 active exploitation payloads in HTTP request line from 198.51.100.77.
- **Supporting Evidence:**
  - `Observed payload samples: /api/v1/products?cat=electronics%27%20UNION%20SELECT%20null,username,password%20FROM%20users--, /api/v1/products?cat=1%27%20WAITFOR%20DELAY%20%270:0:5%27--`

### Alert #4: [CRITICAL] Web Exploit Payload Attempt

- **Source IP:** `192.0.2.88`
- **Severity:** `CRITICAL`
- **Activity Count:** 2
- **Details:** Identified 2 active exploitation payloads in HTTP request line from 192.0.2.88.
- **Supporting Evidence:**
  - `Observed payload samples: /view?doc=../../../../etc/passwd, /search?q=<script>alert(1)</script>`

### Alert #5: [HIGH] Automated Web Scanner / Suspicious User-Agent

- **Source IP:** `203.0.113.12`
- **Severity:** `HIGH`
- **Activity Count:** 6
- **Details:** Automated tool activity detected from 203.0.113.12: Automated Security Scanner (Mozilla/5.0 (Nikto/2.1.6) (Nikto/2.1.6)) (6x)
- **Supporting Evidence:**
  - `Tool signatures: Automated Security Scanner (Mozilla/5.0 (Nikto/2.1.6) (Nikto/2.1.6)) (6x)`

### Alert #6: [HIGH] Sensitive Path Probing / Directory Enumeration

- **Source IP:** `203.0.113.12`
- **Severity:** `HIGH`
- **Activity Count:** 6
- **Details:** Host 203.0.113.12 performed targeted enumeration of 6 sensitive administrative/system endpoints.
- **Supporting Evidence:**
  - `Sample probed endpoints: /.env, /.git/config, /actuator/heapdump, /backup.sql, /phpmyadmin/index.php, /wp-admin/install.php`
  - `HTTP response distribution: 404:6`

### Alert #7: [HIGH] Automated Web Scanner / Suspicious User-Agent

- **Source IP:** `198.51.100.77`
- **Severity:** `HIGH`
- **Activity Count:** 3
- **Details:** Automated tool activity detected from 198.51.100.77: Automated Security Scanner (sqlmap/1.7#stable (https://sqlmap.org)) (3x)
- **Supporting Evidence:**
  - `Tool signatures: Automated Security Scanner (sqlmap/1.7#stable (https://sqlmap.org)) (3x)`

### Alert #8: [HIGH] Automated Web Scanner / Suspicious User-Agent

- **Source IP:** `192.0.2.88`
- **Severity:** `HIGH`
- **Activity Count:** 2
- **Details:** Automated tool activity detected from 192.0.2.88: Automated Scripting HTTP Client (curl/7.88.1) (2x)
- **Supporting Evidence:**
  - `Tool signatures: Automated Scripting HTTP Client (curl/7.88.1) (2x)`

### Alert #9: [HIGH] Sensitive Path Probing / Directory Enumeration

- **Source IP:** `192.0.2.88`
- **Severity:** `HIGH`
- **Activity Count:** 1
- **Details:** Host 192.0.2.88 performed targeted enumeration of 1 sensitive administrative/system endpoints.
- **Supporting Evidence:**
  - `Sample probed endpoints: /view?doc=../../../../etc/passwd`
  - `HTTP response distribution: 403:1`

---

## 3. Recommended Defensive Remediation Actions

### Immediate Firewall Blocklist (`iptables` / `nftables`)
To immediately drop traffic from hosts executing brute force or exploit probes:

```bash
iptables -A INPUT -s 192.0.2.88 -j DROP
iptables -A INPUT -s 198.51.100.44 -j DROP
iptables -A INPUT -s 198.51.100.77 -j DROP
iptables -A INPUT -s 203.0.113.12 -j DROP
iptables -A INPUT -s 203.0.113.89 -j DROP
```

### Hardening Best Practices
1. **SSH Hardening**:
   - Disable SSH password authentication (`PasswordAuthentication no`) in `/etc/ssh/sshd_config`.
   - Enforce public key authentication only (`PubkeyAuthentication yes`).
   - Deploy and configure `fail2ban` to automatically jail IPs with repeated login failures.
2. **Nginx & Web Application Hardening**:
   - Block dotfile requests (`location ~ /\.(?!well-known).* { deny all; }`).
   - Block known scanner User-Agents using an Nginx map or Cloudflare / ModSecurity WAF rules.
   - Rate limit dynamic requests using `limit_req_zone`.
