"""
Lab 4: Server-Side Request Forgery (SSRF) - CWE-918 / OWASP A10:2021

Demonstrates vulnerable unvalidated backend URL fetching vs. robust IP and scheme validation.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from flask import Blueprint, jsonify, request

ssrf_bp = Blueprint("ssrf", __name__, url_prefix="/api/ssrf")

SSRF_EXPLANATION = {
    "vulnerability": "Server-Side Request Forgery (SSRF) - CWE-918",
    "description": (
        "SSRF vulnerabilities occur when a web application fetches a remote resource (e.g., an avatar image, "
        "webhook, or external API feed) from a user-supplied URL without validating the target destination. "
        "An attacker can supply URLs pointing to internal-only loopback services (127.0.0.1), intranet systems, "
        "or cloud instance metadata endpoints (169.254.169.254) to bypass firewall perimeters and extract credentials."
    ),
    "exploit_payloads": [
        "http://127.0.0.1:5000/api/ssrf/internal-admin-status",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "file:///etc/passwd",
    ],
    "remediation": (
        "1. Restrict URL schemes strictly to 'http' and 'https' (block dangerous schemes like 'file://', 'gopher://'). "
        "2. Resolve the target hostname using DNS and check the IP address against private, loopback, link-local, and reserved CIDR ranges. "
        "3. Disable HTTP redirect following in the HTTP client to prevent redirect-based filter evasion. "
        "4. Where possible, enforce a strict domain allowlist."
    ),
}


@ssrf_bp.route("/explanation", methods=["GET"])
def get_explanation():
    return jsonify(SSRF_EXPLANATION)


@ssrf_bp.route("/internal-admin-status", methods=["GET"])
def internal_admin_status():
    """
    Simulated internal microservice endpoint.
    Supposed to be inaccessible from outside the internal network perimeter.
    """
    return jsonify({
        "service": "Internal Infrastructure Cluster Manager",
        "environment": "Production-Internal",
        "cluster_tokens": {
            "primary": "CLUSTER-SECRET-TOKEN-99881122",
            "db_replica_host": "db-replica-01.internal.local:5432",
        },
        "status": "HEALTHY",
        "message": "CRITICAL: This endpoint is private and should NEVER be directly accessible from the public internet!",
    })


@ssrf_bp.route("/vulnerable", methods=["GET", "POST"])
def vulnerable_fetch():
    """
    VULNERABLE IMPLEMENTATION:
    Fetches the user-supplied URL directly using urllib without scheme or IP validation.
    """
    url = request.args.get("url") or (request.json.get("url") if request.is_json else "")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    try:
        # VULNERABLE: Direct server-side request without destination validation
        req = urllib.request.Request(url, headers={"User-Agent": "vuln-app-lab-fetcher/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            content_type = resp.headers.get_content_type()
            raw_body = resp.read(2048)  # Read up to 2KB
            try:
                body = raw_body.decode("utf-8")
            except UnicodeDecodeError:
                body = f"<binary data: {len(raw_body)} bytes>"

            return jsonify({
                "status": "success",
                "mode": "vulnerable",
                "target_url": url,
                "response_code": resp.status,
                "content_type": content_type,
                "body": body,
            })
    except Exception as e:
        return jsonify({
            "status": "error",
            "mode": "vulnerable",
            "target_url": url,
            "error": str(e),
        }), 500


def is_safe_url(target_url: str) -> tuple[bool, str]:
    """
    Validates URL scheme, resolves IP via DNS, and blocks private/loopback/cloud-metadata IPs.
    """
    try:
        parsed = urllib.parse.urlparse(target_url)
    except Exception:
        return False, "Invalid URL structure"

    # 1. Scheme check: only http and https
    if parsed.scheme not in {"http", "https"}:
        return False, f"Scheme '{parsed.scheme}' prohibited. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL hostname is missing"

    # Explicit hostname blocklist
    blocked_hosts = {"localhost", "127.0.0.1", "::1", "metadata.google.internal", "169.254.169.254"}
    if hostname.lower() in blocked_hosts:
        return False, f"Destination hostname '{hostname}' is blocked."

    # 2. DNS resolution and IP address validation
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"

    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"

        # 3. Check for private, loopback, link-local, or reserved ranges
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, f"Prohibited IP destination: {ip_str} belongs to a private/internal network range."

    return True, "URL destination validated"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom handler that disables following HTTP redirects."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@ssrf_bp.route("/fixed", methods=["GET", "POST"])
def fixed_fetch():
    """
    FIXED IMPLEMENTATION:
    Validates URL scheme, checks DNS IP against private/loopback CIDRs, and blocks redirects.
    """
    url = request.args.get("url") or (request.json.get("url") if request.is_json else "")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    # Validate destination safety
    is_safe, reason = is_safe_url(url)
    if not is_safe:
        return jsonify({
            "error": "Forbidden by SSRF Security Filter",
            "reason": reason,
            "target_url": url,
            "mode": "fixed",
            "blocked": True,
        }), 403

    # Use custom opener with redirects disabled
    opener = urllib.request.build_opener(NoRedirectHandler)
    req = urllib.request.Request(url, headers={"User-Agent": "security-labs-safe-fetcher/1.0"})

    try:
        with opener.open(req, timeout=3) as resp:
            content_type = resp.headers.get_content_type()
            raw_body = resp.read(2048)
            try:
                body = raw_body.decode("utf-8")
            except UnicodeDecodeError:
                body = f"<binary data: {len(raw_body)} bytes>"

            return jsonify({
                "status": "success",
                "mode": "fixed",
                "target_url": url,
                "response_code": resp.status,
                "content_type": content_type,
                "body": body,
            })
    except Exception as e:
        return jsonify({
            "status": "error",
            "mode": "fixed",
            "target_url": url,
            "error": str(e),
        }), 500
