"""
Benchmarking engine measuring hashing speeds, work factors, and cracking resistance.
"""

from __future__ import annotations

import statistics
import time
from typing import Any, Dict, List

from password_demo.hasher import PasswordHasher


def benchmark_algorithm(
    name: str,
    hash_func,
    iterations: int = 5,
    sample_password: str = "CorrectHorseBatteryStaple!",
) -> Dict[str, Any]:
    """Runs N iterations of a hashing function and computes execution statistics."""
    durations: List[float] = []

    for _ in range(iterations):
        _, elapsed = hash_func(sample_password)
        durations.append(elapsed)

    mean_sec = statistics.mean(durations)
    hashes_per_sec = (1.0 / mean_sec) if mean_sec > 0 else 0.0

    return {
        "algorithm": name,
        "iterations": iterations,
        "mean_latency_ms": round(mean_sec * 1000, 3),
        "min_latency_ms": round(min(durations) * 1000, 3),
        "max_latency_ms": round(max(durations) * 1000, 3),
        "hashes_per_second": round(hashes_per_sec, 2),
    }


def run_full_benchmark(iterations: int = 3) -> Dict[str, Any]:
    """
    Executes comparative benchmarks across:
    - MD5 (fast digest)
    - bcrypt (cost 10, 11, 12)
    - Argon2id (t=2, m=19MB; t=3, m=64MB)
    """
    benchmarks: List[Dict[str, Any]] = []

    # 1. MD5 benchmark (many iterations for microsecond measurement)
    md5_bench = benchmark_algorithm(
        "MD5 (broken general-purpose digest)",
        lambda pw: PasswordHasher.hash_md5(pw),
        iterations=max(iterations * 10, 50),
    )
    benchmarks.append(md5_bench)

    # 2. bcrypt cost 10 and 12
    bcrypt_10 = benchmark_algorithm(
        "bcrypt (cost=10, 2^10 = 1,024 iterations)",
        lambda pw: PasswordHasher.hash_bcrypt(pw, cost=10),
        iterations=iterations,
    )
    benchmarks.append(bcrypt_10)

    bcrypt_12 = benchmark_algorithm(
        "bcrypt (cost=12, 2^12 = 4,096 iterations)",
        lambda pw: PasswordHasher.hash_bcrypt(pw, cost=12),
        iterations=iterations,
    )
    benchmarks.append(bcrypt_12)

    # 3. Argon2id (RFC 9106 recommended parameters)
    argon2_std = benchmark_algorithm(
        "Argon2id (t=3, m=64MB, p=4 - RFC 9106 recommended)",
        lambda pw: PasswordHasher.hash_argon2(pw, time_cost=3, memory_cost_kib=65536, parallelism=4),
        iterations=iterations,
    )
    benchmarks.append(argon2_std)

    # Calculate relative slowdown factor compared to MD5
    md5_latency = md5_bench["mean_latency_ms"]
    for b in benchmarks:
        b["slowdown_vs_md5"] = f"{round(b['mean_latency_ms'] / md5_latency, 1)}x slower" if md5_latency > 0 else "N/A"

    return {
        "timestamp": time.time(),
        "benchmarks": benchmarks,
    }
