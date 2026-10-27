"""
Demonstration of cryptographic salting and rainbow table mitigation.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from password_demo.hasher import PasswordHasher


def run_salting_demonstration(password: str = "CorrectHorseBatteryStaple!") -> Dict[str, Any]:
    """
    Demonstrates:
    1. Unsalted hashing: 3 users with the same password have identical hash digests.
    2. Salted hashing: 3 users with the same password have unique, divergent digests.
    """
    users = ["Alice", "Bob", "Charlie"]

    # 1. Unsalted scenario (vulnerable to precomputed rainbow tables)
    unsalted_results: List[Dict[str, str]] = []
    for user in users:
        h, _ = PasswordHasher.hash_md5(password, salt=None)
        unsalted_results.append({
            "user": user,
            "password": password,
            "salt": "None",
            "hash": h,
        })

    # 2. Salted scenario (random 16-byte salt per user)
    salted_results: List[Dict[str, str]] = []
    for user in users:
        salt = os.urandom(16)
        h, _ = PasswordHasher.hash_md5(password, salt=salt)
        salted_results.append({
            "user": user,
            "password": password,
            "salt_hex": salt.hex(),
            "hash": h,
        })

    return {
        "password_tested": password,
        "unsalted": unsalted_results,
        "salted": salted_results,
        "all_unsalted_hashes_identical": len(set(r["hash"] for r in unsalted_results)) == 1,
        "all_salted_hashes_unique": len(set(r["hash"] for r in salted_results)) == len(users),
    }
