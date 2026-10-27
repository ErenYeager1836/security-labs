"""
Password hashing primitives for MD5, bcrypt, and Argon2id.
"""

from __future__ import annotations

import hashlib
import time
from typing import Optional, Tuple

import argon2
import bcrypt


class PasswordHasher:
    """Wrapper implementing hashing and verification across MD5, bcrypt, and Argon2id."""

    @staticmethod
    def hash_md5(password: str, salt: Optional[bytes] = None) -> Tuple[str, float]:
        """
        MD5 (Message Digest 5):
        A 128-bit cryptographic hash designed in 1991 for checksumming and message integrity.
        It is NOT a Key Derivation Function (KDF). It has NO work factor and takes < 1 microsecond.
        """
        start = time.perf_counter()
        data = (salt or b"") + password.encode("utf-8")
        # MD5 is broken for security; usedforsecurity=False explicitly indicates benchmark context
        digest = hashlib.md5(data, usedforsecurity=False).hexdigest()
        elapsed = time.perf_counter() - start
        return digest, elapsed

    @staticmethod
    def verify_md5(password: str, expected_hash: str, salt: Optional[bytes] = None) -> bool:
        computed_hash, _ = PasswordHasher.hash_md5(password, salt=salt)
        return computed_hash.lower() == expected_hash.lower()

    @staticmethod
    def hash_bcrypt(password: str, cost: int = 12) -> Tuple[str, float]:
        """
        bcrypt (Blowfish-based KDF):
        Designed by Provos & Mazières in 1999. Includes an adaptive cost factor (2^cost iterations)
        and an automatic 128-bit salt embedded directly into the resulting string.
        """
        start = time.perf_counter()
        pw_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=cost)
        hashed = bcrypt.hashpw(pw_bytes, salt).decode("utf-8")
        elapsed = time.perf_counter() - start
        return hashed, elapsed

    @staticmethod
    def verify_bcrypt(password: str, hashed_value: str) -> bool:
        pw_bytes = password.encode("utf-8")
        hash_bytes = hashed_value.encode("utf-8")
        return bcrypt.checkpw(pw_bytes, hash_bytes)

    @staticmethod
    def hash_argon2(
        password: str,
        time_cost: int = 3,
        memory_cost_kib: int = 65536,  # 64 MB
        parallelism: int = 4,
    ) -> Tuple[str, float]:
        """
        Argon2id:
        Winner of the Password Hashing Competition (PHC, 2015).
        Combines Argon2d (data-dependent, protects against GPU cracking) and
        Argon2i (data-independent, protects against side-channel cache attacks).
        Memory-hardness prevents high-speed parallel ASIC/FPGA acceleration.
        """
        ph = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID,
        )
        start = time.perf_counter()
        hashed = ph.hash(password)
        elapsed = time.perf_counter() - start
        return hashed, elapsed

    @staticmethod
    def verify_argon2(password: str, hashed_value: str) -> bool:
        ph = argon2.PasswordHasher()
        try:
            return ph.verify(hashed_value, password)
        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHashError):
            return False
