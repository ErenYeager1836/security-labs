"""
Lab 2: Cross-Site Scripting (Reflected XSS) - CWE-79 / OWASP A03:2021

Demonstrates vulnerable unescaped user reflection vs. context-aware HTML encoding and CSP.
"""

from __future__ import annotations

import html
from flask import Blueprint, Response, jsonify, request

xss_bp = Blueprint("xss", __name__, url_prefix="/api/xss")

XSS_EXPLANATION = {
    "vulnerability": "Cross-Site Scripting (Reflected XSS) - CWE-79",
    "description": (
        "Reflected Cross-Site Scripting occurs when an application receives user input in an HTTP request "
        "and echoes it back in an immediate HTML response without adequate escaping or sanitization. "
        "This allows an attacker to inject client-side JavaScript that executes within victim browsers, "
        "enabling session hijacking (cookie theft), credential phishing, or DOM manipulation."
    ),
    "exploit_payload": "<script>alert('XSS-Exploit-Triggered')</script>",
    "alternative_payload": "<img src=x onerror=\"alert('XSS-Via-Image')\">",
    "exploit_mechanism": (
        "In the vulnerable endpoint, the 'q' parameter is embedded directly into the HTML document stream. "
        "When the browser renders '<script>...', the HTML parser switches into script-execution mode, running "
        "the injected JavaScript within the application's origin context."
    ),
    "remediation": (
        "1. Perform context-aware HTML entity encoding (e.g. converting '<' to '&lt;', '>' to '&gt;'). "
        "2. Leverage modern template engines (Jinja2, React) with auto-escaping enabled by default. "
        "3. Enforce a restrictive Content-Security-Policy (CSP) HTTP header (e.g., Content-Security-Policy: default-src 'self') "
        "to block inline script execution as defense-in-depth."
    ),
}


@xss_bp.route("/explanation", methods=["GET"])
def get_explanation():
    return jsonify(XSS_EXPLANATION)


@xss_bp.route("/vulnerable", methods=["GET"])
def vulnerable_search():
    """
    VULNERABLE IMPLEMENTATION:
    Reflects the 'q' query parameter directly into raw HTML without encoding.
    """
    q = request.args.get("q", "")

    # VULNERABLE: Direct string interpolation into HTML output
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results (Vulnerable)</title></head>
    <body style="font-family: sans-serif; padding: 20px;">
        <h2>Search Results for: {q}</h2>
        <p>No records matched your search query.</p>
        <hr>
        <p><small>Mode: <b>Vulnerable (Unescaped Reflection)</b></small></p>
    </body>
    </html>
    """
    return Response(html_content, mimetype="text/html")


@xss_bp.route("/fixed", methods=["GET"])
def fixed_search():
    """
    FIXED IMPLEMENTATION:
    Applies HTML entity escaping and attaches a Content-Security-Policy header.
    """
    q = request.args.get("q", "")

    # FIXED 1: Context-aware HTML entity encoding
    safe_q = html.escape(q, quote=True)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results (Fixed)</title></head>
    <body style="font-family: sans-serif; padding: 20px;">
        <h2>Search Results for: {safe_q}</h2>
        <p>No records matched your search query.</p>
        <hr>
        <p><small>Mode: <b>Fixed (HTML Escaped + CSP Active)</b></small></p>
    </body>
    </html>
    """
    resp = Response(html_content, mimetype="text/html")

    # FIXED 2: Defense-in-depth Content-Security-Policy
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp
