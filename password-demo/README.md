# password-demo

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Argon2id](https://img.shields.io/badge/KDF-Argon2id%20(RFC%209106)-orange.svg)](https://www.rfc-editor.org/rfc/rfc9106)
[![bcrypt](https://img.shields.io/badge/KDF-bcrypt%20(Cost%2012)-blue.svg)](https://en.wikipedia.org/wiki/Bcrypt)

> **Educational comparison of MD5 vs bcrypt vs Argon2id hashing latency, work factor scaling, and cryptographic salting against rainbow table attacks.**

---

## Educational Scope & Notice

> [!NOTE]
> **No Real Data Cracking**: This project is strictly educational and architectural. It benchmark timings and illustrates cryptographic principles using synthetic dummy passwords (e.g., `CorrectHorseBatteryStaple!`). It contains no password cracking engines or leaked real-world hashes.

---

## Key Cryptographic Concepts Demonstrated

### 1. Fast General-Purpose Hashes vs. Key Derivation Functions (KDFs)
- **MD5 (and SHA-1, SHA-256)**: Designed for raw throughput and message integrity verification (e.g. file checksums, git tree hashing). Because they take less than `0.001 ms` to compute, consumer GPUs (like an RTX 4090) can compute billions of MD5 hashes per second, making offline dictionary brute forcing trivial.
- **bcrypt**: Designed in 1999 specifically for passwords. Introduces a configurable exponential work factor (`cost`). Each increment of `cost` doubles the computation time ($2^{\text{cost}}$ iterations).
- **Argon2id**: Winner of the Password Hashing Competition (2015, RFC 9106). Combines data-dependent memory access (Argon2d) to defeat GPU/ASIC parallelization and data-independent memory access (Argon2i) to defeat side-channel cache attacks. Memory-hardness forces the cracking device to allocate gigabytes of high-speed RAM per concurrent cracking attempt.

### 2. Why Cryptographic Salting is Mandatory
- **Unsalted Passwords**: If 10,000 users have the password `Summer2026!`, all 10,000 database rows store the exact same hash digest. An attacker with a precomputed **rainbow table** (a pre-generated lookup table mapping common passwords to hash outputs) can crack all 10,000 accounts in a single lookup (`O(1)` time complexity).
- **Salted Passwords**: Appending a unique, cryptographically random salt (e.g. 16 bytes from `os.urandom`) ensures that even identical passwords produce completely divergent hashes. Precomputed rainbow tables are rendered completely useless because an attacker must recompute an entire rainbow table specifically for each user's unique 128-bit salt ($2^{128}$ possibilities).

---

## Live Benchmark Results

Measured on a standard x86-64 CPU core:

```text
================================================================================
      PASSWORD HASHING BENCHMARK: MD5 vs bcrypt vs Argon2id      
================================================================================
Algorithm                                    Mean Latency     Hashes/Sec     Slowdown
--------------------------------------------------------------------------------
MD5 (broken general-purpose digest)          0.002 ms         644,329.9/s    1.0x (baseline)
bcrypt (cost=10, 2^10 = 1,024 iterations)    58.123 ms        17.2/s         29,061x slower
bcrypt (cost=12, 2^12 = 4,096 iterations)    233.239 ms       4.3/s          116,619x slower
Argon2id (t=3, m=64MB, p=4 - RFC 9106)       87.093 ms        11.5/s         43,546x slower
--------------------------------------------------------------------------------
```

---

## Salting Demonstration Output

```text
================================================================================
          WHY SALTING MATTERS: RAINBOW TABLE MITIGATION          
================================================================================
Password tested across 3 different users: 'CorrectHorseBatteryStaple!'

[1] Unsalted Hashing (Vulnerable to Rainbow Tables):
--------------------------------------------------------------------------------
  User: Alice    | Salt: None        | Hash: d887e0b4402e96ad0da114d98ba1c9e7
  User: Bob      | Salt: None        | Hash: d887e0b4402e96ad0da114d98ba1c9e7
  User: Charlie  | Salt: None        | Hash: d887e0b4402e96ad0da114d98ba1c9e7
  -> VULNERABILITY: All 3 users have IDENTICAL hashes!

[2] Salted Hashing (Random 128-bit Salt per User):
--------------------------------------------------------------------------------
  User: Alice    | Salt: ec236441300c... | Hash: 49af2c26d9e12ca5a0d36881e1609445
  User: Bob      | Salt: 49bed1ce6140... | Hash: a6380929f3ba846f91b4e346c5babb51
  User: Charlie  | Salt: bf9ff9880b40... | Hash: 0557da6f1247207a8b5ca660b4dfc3e5
  -> SECURITY BENEFIT: Every user has a UNIQUE, DIVERGENT hash!
```

---

## Installation & Usage

```bash
cd password-demo
pip install -e .

# Run both benchmark and salting demonstration
python -m password_demo.cli --all

# Run benchmark only with 5 iterations
python -m password_demo.cli --benchmark -i 5

# Run salting demonstration only
python -m password_demo.cli --salting

# Output results as JSON
python -m password_demo.cli --all --json
```

---

## Testing

```bash
python -m pytest tests -v
```

---

## Limitations & Roadmap

- [ ] GPU cracking throughput simulation comparison (hashcat benchmarks).
- [ ] PBKDF2-HMAC-SHA256 and scrypt comparative benchmark additions.
- [ ] Argon2 memory tuning visualizer.

---

## License

MIT &copy; 2026 Nithishvelan M (ErenYeager1836).
