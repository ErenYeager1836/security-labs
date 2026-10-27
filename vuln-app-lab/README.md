# vuln-app-lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Flask: 3.x](https://img.shields.io/badge/Framework-Flask-black.svg)](https://flask.palletsprojects.com/)
[![Localhost Only](https://img.shields.io/badge/environment-localhost%20only-red.svg)](#safety--authorized-use-notice)

> **Localhost-only educational web application lab demonstrating real OWASP Top 10 vulnerabilities (SQLi, Reflected XSS, IDOR, SSRF) with side-by-side vulnerable and remediated implementations.**

---

## Safety & Authorized Use Notice

> [!CAUTION]
> **DELIBERATE SECURITY VULNERABILITIES**: This application contains intentional, exploitable security vulnerabilities designed strictly for local security training, code auditing, and interview demonstrations.
> 
> - **Localhost Binding Only**: The application refuses to bind to external or non-loopback network interfaces (`0.0.0.0`).
> - **Authorized Use**: Do not deploy this application on public servers, shared hosting, or production environments.

---

## Laboratory Modules

| Lab ID | Vulnerability | CWE | OWASP | Vulnerable Endpoint | Remediated Endpoint | Defense Implemented |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Lab 1** | **SQL Injection (SQLi)** | CWE-89 | A03:2021 | `/api/sqli/vulnerable` | `/api/sqli/fixed` | Parameterized prepared statements (`?` placeholders) |
| **Lab 2** | **Reflected XSS** | CWE-79 | A03:2021 | `/api/xss/vulnerable` | `/api/xss/fixed` | Context-aware HTML entity escaping + CSP header |
| **Lab 3** | **IDOR / BOLA** | CWE-639 | A01:2021 | `/api/idor/vulnerable/notes/<id>` | `/api/idor/fixed/notes/<id>` | Tenant-scoped object-level authorization checks |
| **Lab 4** | **SSRF** | CWE-918 | A10:2021 | `/api/ssrf/vulnerable` | `/api/ssrf/fixed` | Scheme allowlist, DNS IP resolution, private CIDR filtering |

---

## Exploit Walkthrough & Attack Payloads

### 1. SQL Injection (CWE-89)
- **Vulnerable Code**: `cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")`
- **Exploit Payload**: `' OR '1'='1`
- **Mechanism**: The single quote closes the string literal and injects `' OR '1'='1`, evaluating the WHERE clause to `TRUE` for every row, leaking the complete user table.
- **Fixed Code**: `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`
- **Defense**: The database driver separates SQL code structure from untrusted user data. The database parser never executes data operands as code.

### 2. Reflected Cross-Site Scripting (CWE-79)
- **Vulnerable Code**: `return Response(f"<h2>Search Results for: {q}</h2>", mimetype="text/html")`
- **Exploit Payload**: `<script>alert('XSS')</script>` or `<img src=x onerror=alert(1)>`
- **Mechanism**: The browser parses the unescaped `<script>` tag as executable JavaScript inside the document context.
- **Fixed Code**: `html.escape(q, quote=True)` + `Content-Security-Policy: default-src 'self'`
- **Defense**: Converts `<` to `&lt;` and `>` to `&gt;`. The CSP header acts as defense-in-depth, blocking inline script execution even if escaping is bypassed.

### 3. Insecure Direct Object Reference (CWE-639)
- **Vulnerable Code**: `cursor.execute("SELECT * FROM notes WHERE id = ?", (note_id,))`
- **Exploit Scenario**: Authenticated as `Alice` (ID: 2). Alice navigates to Note ID `3` (Bob's private crypto seed phrase) or Note ID `4` (Admin infrastructure key). The server returns the note without verifying ownership.
- **Fixed Code**:
  ```python
  if note['is_private'] and note['owner_id'] != current_user.id:
      abort(403)
  ```
- **Defense**: Enforces object-level authorization verifying that private resources belong strictly to the authenticated identity.

### 4. Server-Side Request Forgery (CWE-918)
- **Vulnerable Code**: `urllib.request.urlopen(url)`
- **Exploit Payload**: `http://127.0.0.1:5000/api/ssrf/internal-admin-status` or `http://169.254.169.254/latest/meta-data/`
- **Mechanism**: The server issues requests on behalf of the attacker, reaching internal microservices or cloud instance metadata credentials.
- **Fixed Code**:
  - Scheme validation: enforces `http` and `https` (blocks `file://`, `gopher://`).
  - DNS resolution check: resolves hostname to IP and verifies `not (ip.is_private or ip.is_loopback or ip.is_link_local)`.
  - Disables HTTP redirect following to prevent DNS rebinding bypasses.

---

## Installation & Running Locally

### 1. Install Dependencies
```bash
cd vuln-app-lab
pip install -e .
```

### 2. Run the Interactive Lab Server
```bash
python app.py
```
Visit **`http://127.0.0.1:5000`** in your browser to interact with the visual dashboard, toggle between vulnerable and fixed endpoints, and test preloaded attack payloads.

---

## Testing

Run the automated test suite verifying exploit execution on `/vulnerable` and complete defense on `/fixed`:

```bash
python -m pytest tests -v
```

---

## Limitations & Roadmap

- [ ] CSRF (Cross-Site Request Forgery) lab with SameSite cookie and anti-CSRF token demonstrations.
- [ ] JWT security lab (none-algorithm attack and secret brute forcing).
- [ ] Command Injection lab (ping / traceroute utility).

---

## License

MIT &copy; 2026 Nithishvelan M (ErenYeager1836).
