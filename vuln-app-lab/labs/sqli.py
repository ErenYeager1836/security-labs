"""
Lab 1: SQL Injection (SQLi) - CWE-89 / OWASP A03:2021

Demonstrates vulnerable dynamic string formatting vs. secure parameterized queries.
"""

from __future__ import annotations

import sqlite3
from flask import Blueprint, jsonify, request
from db import get_db

sqli_bp = Blueprint("sqli", __name__, url_prefix="/api/sqli")

SQLI_EXPLANATION = {
    "vulnerability": "SQL Injection (CWE-89)",
    "description": (
        "SQL injection occurs when untrusted user input is directly concatenated into a dynamic SQL string. "
        "An attacker can inject SQL control characters (e.g., quotes, semicolons, comments) to alter the query's "
        "logical structure, bypass authentication, extract sensitive tables via UNION queries, or tamper with data."
    ),
    "exploit_payload": "' OR '1'='1",
    "exploit_mechanism": (
        "In the vulnerable query: SELECT * FROM users WHERE username = '{username}', passing \"' OR '1'='1\" transforms "
        "the WHERE clause into: WHERE username = '' OR '1'='1', evaluating to TRUE for every row in the database."
    ),
    "remediation": (
        "Always use parameterized queries (prepared statements) provided by database drivers (e.g. cursor.execute('... WHERE username = ?', (username,))). "
        "In parameterized queries, the database engine compiles the SQL command structure first; user arguments are treated strictly as literal data operands."
    ),
}


@sqli_bp.route("/explanation", methods=["GET"])
def get_explanation():
    return jsonify(SQLI_EXPLANATION)


@sqli_bp.route("/vulnerable", methods=["GET", "POST"])
def vulnerable_search():
    """
    VULNERABLE IMPLEMENTATION:
    Interpolates untrusted input directly into SQL statement using an f-string.
    """
    username = request.args.get("username") or (request.json.get("username") if request.is_json else "")
    if not username:
        return jsonify({"error": "Missing 'username' query parameter"}), 400

    conn = get_db()
    cursor = conn.cursor()

    # VULNERABLE: Direct string interpolation
    query = f"SELECT id, username, email, role, bio FROM users WHERE username = '{username}'"

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        users = [dict(row) for row in rows]
        return jsonify({
            "status": "success",
            "executed_query": query,
            "results_count": len(users),
            "users": users,
            "mode": "vulnerable",
        })
    except sqlite3.OperationalError as e:
        return jsonify({"error": f"SQLite error: {e}", "executed_query": query}), 500


@sqli_bp.route("/fixed", methods=["GET", "POST"])
def fixed_search():
    """
    FIXED IMPLEMENTATION:
    Uses parameterized query placeholders ('?') to safely bind input.
    """
    username = request.args.get("username") or (request.json.get("username") if request.is_json else "")
    if not username:
        return jsonify({"error": "Missing 'username' query parameter"}), 400

    conn = get_db()
    cursor = conn.cursor()

    # FIXED: Parameterized prepared statement
    query = "SELECT id, username, email, role, bio FROM users WHERE username = ?"

    cursor.execute(query, (username,))
    rows = cursor.fetchall()
    users = [dict(row) for row in rows]

    return jsonify({
        "status": "success",
        "parameterized_query": query,
        "bound_parameter": username,
        "results_count": len(users),
        "users": users,
        "mode": "fixed",
    })
