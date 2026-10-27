"""
Lab 3: Insecure Direct Object Reference (IDOR) - CWE-639 / OWASP A01:2021

Demonstrates vulnerable un-scoped database queries vs. object-level authorization checks.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from db import get_db

idor_bp = Blueprint("idor", __name__, url_prefix="/api/idor")

IDOR_EXPLANATION = {
    "vulnerability": "Insecure Direct Object Reference (IDOR) / BOLA (CWE-639)",
    "description": (
        "IDOR occurs when an application exposes a reference to an internal database object (such as an ID or filename) "
        "in an API parameter and fails to validate whether the authenticated requester possesses permission to access that specific object. "
        "An attacker simply modifies the ID number in the request (horizontal privilege escalation) to read, update, or delete other users' private data."
    ),
    "exploit_scenario": (
        "Current authenticated session belongs to 'Alice' (User ID: 2). "
        "Alice requests note ID 1 (her own public note) -> 200 OK. "
        "Alice modifies note ID to 3 (Bob's private note) or 4 (Admin's backup key) -> In the vulnerable version, "
        "the server returns Bob's and Admin's confidential data!"
    ),
    "remediation": (
        "1. Never rely solely on object IDs. Enforce tenant-scoped database queries: "
        "'SELECT * FROM notes WHERE id = ? AND owner_id = ?'. "
        "2. If an object does not belong to the requesting user and is private, return HTTP 403 Forbidden (or HTTP 404 to prevent ID enumeration). "
        "3. Consider using indirect references (unguessable UUIDs or encrypted session-scoped tokens) in public URLs."
    ),
}

# Simulated authenticated session context
SIMULATED_USER = {
    "id": 2,
    "username": "alice",
    "role": "user",
}


@idor_bp.route("/explanation", methods=["GET"])
def get_explanation():
    return jsonify(IDOR_EXPLANATION)


@idor_bp.route("/vulnerable/notes/<int:note_id>", methods=["GET"])
def vulnerable_get_note(note_id: int):
    """
    VULNERABLE IMPLEMENTATION:
    Queries note by ID alone without checking whether the authenticated user (Alice) owns it.
    """
    conn = get_db()
    cursor = conn.cursor()

    # VULNERABLE: Direct query by primary key ID without owner scoping
    cursor.execute("SELECT id, owner_id, title, content, is_private FROM notes WHERE id = ?", (note_id,))
    note = cursor.fetchone()

    if not note:
        return jsonify({"error": f"Note with ID {note_id} not found"}), 404

    note_dict = dict(note)
    is_idor_violation = (note_dict["owner_id"] != SIMULATED_USER["id"]) and bool(note_dict["is_private"])

    return jsonify({
        "status": "success",
        "current_user": SIMULATED_USER,
        "note": note_dict,
        "mode": "vulnerable",
        "idor_violation_occurred": is_idor_violation,
        "security_warning": "IDOR Exploitation Successful: Accessed note owned by User ID " f"{note_dict['owner_id']}"
        if is_idor_violation else "Accessed owned note",
    })


@idor_bp.route("/fixed/notes/<int:note_id>", methods=["GET"])
def fixed_get_note(note_id: int):
    """
    FIXED IMPLEMENTATION:
    Enforces object-level ownership check. Only allows access if the note is public
    or owned by the requesting user.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Fetch note
    cursor.execute("SELECT id, owner_id, title, content, is_private FROM notes WHERE id = ?", (note_id,))
    note = cursor.fetchone()

    if not note:
        return jsonify({"error": f"Note with ID {note_id} not found"}), 404

    note_dict = dict(note)

    # FIXED: Authorization check verifying ownership or public visibility
    if note_dict["is_private"] and note_dict["owner_id"] != SIMULATED_USER["id"]:
        return jsonify({
            "error": "Forbidden: You do not have authorization to view this private note.",
            "mode": "fixed",
            "current_user": SIMULATED_USER,
            "attempted_target_owner_id": note_dict["owner_id"],
            "authorization_enforced": True,
        }), 403

    return jsonify({
        "status": "success",
        "current_user": SIMULATED_USER,
        "note": note_dict,
        "mode": "fixed",
        "authorization_enforced": True,
    })
