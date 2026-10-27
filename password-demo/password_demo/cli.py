"""
Command line interface for password-demo.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from password_demo import __version__
from password_demo.benchmark import run_full_benchmark
from password_demo.salting import run_salting_demonstration


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-demo",
        description="Educational comparison of MD5 vs bcrypt vs Argon2 hashing speeds, work factors, and salt security.",
    )

    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run hashing latency and throughput comparison benchmark across MD5, bcrypt, and Argon2id.",
    )

    parser.add_argument(
        "--salting",
        action="store_true",
        help="Demonstrate why cryptographic salting defeats rainbow tables.",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run both the benchmark and the salting demonstration.",
    )

    parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=3,
        help="Number of iterations per algorithm benchmark (default: 3).",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"password-demo v{__version__}",
    )

    return parser


def display_benchmark(benchmark_data: dict) -> None:
    print("\n" + "=" * 80)
    print("      PASSWORD HASHING BENCHMARK: MD5 vs bcrypt vs Argon2id      ")
    print("=" * 80)
    print(f"{'Algorithm':<44} {'Mean Latency':<16} {'Hashes/Sec':<14} {'Slowdown'}")
    print("-" * 80)

    for b in benchmark_data["benchmarks"]:
        latency_str = f"{b['mean_latency_ms']} ms"
        hps_str = f"{b['hashes_per_second']:.1f}/s"
        slowdown = b.get("slowdown_vs_md5", "1.0x")
        print(f"{b['algorithm']:<44} {latency_str:<16} {hps_str:<14} {slowdown}")

    print("-" * 80)
    print("[*] Key Takeaway:")
    print("    MD5 takes <0.001 ms because it was built for fast data verification, not passwords.")
    print("    bcrypt & Argon2id enforce computational work factors and memory-hardness, making")
    print("    offline dictionary and GPU brute-force attacks mathematically infeasible.\n")


def display_salting(salting_data: dict) -> None:
    print("\n" + "=" * 80)
    print("          WHY SALTING MATTERS: RAINBOW TABLE MITIGATION          ")
    print("=" * 80)
    print(f"Password tested across 3 different users: '{salting_data['password_tested']}'\n")

    print("[1] Unsalted Hashing (Vulnerable to Rainbow Tables):")
    print("--------------------------------------------------------------------------------")
    for r in salting_data["unsalted"]:
        print(f"  User: {r['user']:<8} | Salt: None        | Hash: {r['hash']}")
    print("  -> VULNERABILITY: All 3 users have IDENTICAL hashes!")
    print("  -> An attacker with a precomputed rainbow table cracks all 3 accounts instantly.\n")

    print("[2] Salted Hashing (Random 128-bit Salt per User):")
    print("--------------------------------------------------------------------------------")
    for r in salting_data["salted"]:
        print(f"  User: {r['user']:<8} | Salt: {r['salt_hex'][:12]}... | Hash: {r['hash']}")
    print("  -> SECURITY BENEFIT: Every user has a UNIQUE, DIVERGENT hash!")
    print("  -> Rainbow tables are rendered completely useless; attacker must brute-force each account individually.\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Default to --all if no specific mode selected
    run_bench = args.benchmark or args.all or (not args.benchmark and not args.salting)
    run_salt = args.salting or args.all or (not args.benchmark and not args.salting)

    combined_results = {}

    if run_bench:
        bench_data = run_full_benchmark(iterations=args.iterations)
        combined_results["benchmark"] = bench_data
        if not args.json:
            display_benchmark(bench_data)

    if run_salt:
        salt_data = run_salting_demonstration()
        combined_results["salting"] = salt_data
        if not args.json:
            display_salting(salt_data)

    if args.json:
        print(json.dumps(combined_results, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
