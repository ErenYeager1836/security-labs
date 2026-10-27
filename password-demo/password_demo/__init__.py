"""
password-demo: Educational benchmarking and analysis of password hashing algorithms.

Compares MD5 (broken, fast general-purpose digest) against bcrypt (CPU-bound KDF)
and Argon2id (memory-hard winner of the Password Hashing Competition), demonstrating
why computational latency and cryptographic salting are vital for credential protection.
"""

__version__ = "0.1.0"
