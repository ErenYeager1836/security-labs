"""
vuln-app-lab: Educational OWASP Top 10 Vulnerability Laboratory.

Runs strictly on localhost (127.0.0.1) for educational demonstrations.
Contains deliberate SQLi, XSS, IDOR, and SSRF flaws with side-by-side remediated versions.
"""

from __future__ import annotations

import argparse
import os
import sys
from flask import Flask, jsonify, render_template

from db import get_db
from labs.idor import idor_bp
from labs.sqli import sqli_bp
from labs.ssrf import ssrf_bp
from labs.xss import xss_bp


def create_app() -> Flask:
    """Application factory for vuln-app-lab."""
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    # Initialize SQLite in-memory database
    with app.app_context():
        get_db()

    # Register lab blueprints
    app.register_blueprint(sqli_bp)
    app.register_blueprint(xss_bp)
    app.register_blueprint(idor_bp)
    app.register_blueprint(ssrf_bp)

    @app.route("/", methods=["GET"])
    def index():
        return render_template("index.html")

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "UP",
            "environment": "localhost-sandbox",
            "labs": ["SQL Injection", "Reflected XSS", "IDOR / BOLA", "SSRF"],
        })

    return app


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vuln-app-lab",
        description="Localhost educational vulnerability laboratory (SQLi, XSS, IDOR, SSRF).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--in-docker", action="store_true", help="Allow binding inside containerized Docker environment")
    args = parser.parse_args()

    in_docker = args.in_docker or os.environ.get("DOCKER_CONTAINER", "0") == "1"

    # Safety constraint: enforce localhost binding unless in isolated container
    if not in_docker and args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(f"[!] SAFETY WARNING: vuln-app-lab contains intentional vulnerabilities and must ONLY be run on localhost!")
        print(f"[!] Refusing to bind to external interface: {args.host}")
        return 1

    print("=" * 64)
    print("         security-labs // vuln-app-lab (Flask)          ")
    print("   OWASP Top 10 Vulnerability & Defense Laboratory      ")
    print("=" * 64)
    print(f"[*] Binding to Localhost Interface: http://{args.host}:{args.port}")
    print("[*] Available Labs:")
    print("    - 1. SQL Injection (SQLi)        -> /api/sqli/{vulnerable,fixed}")
    print("    - 2. Reflected XSS               -> /api/xss/{vulnerable,fixed}")
    print("    - 3. IDOR / Object Authorization -> /api/idor/{vulnerable,fixed}")
    print("    - 4. Server-Side Request Forgery -> /api/ssrf/{vulnerable,fixed}")
    print("[!] AUTHORIZED USE ONLY: Designed strictly for local testing.")
    print("=" * 64)

    app = create_app()
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
