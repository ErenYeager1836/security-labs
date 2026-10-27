# port-scanner (C++17)

[![Standard: C++17](https://img.shields.io/badge/c%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Build: CMake](https://img.shields.io/badge/build-CMake-brightgreen.svg)](https://cmake.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)

A high-performance, multithreaded TCP connect scanner and service banner grabber written in modern **C++17**. Designed for network engineers and defensive security auditors to assess local listening services, discover exposed ports, and verify service identification banners.

> **LEGAL & ETHICAL USE DISCLAIMER**:  
> This tool is developed strictly for authorized security auditing, defensive assessment, and educational research on systems you own or have explicit written permission to test. Unauthorized port scanning against third-party networks or systems may violate the **Computer Fraud and Abuse Act (CFAA)**, the **UK Computer Misuse Act (CMA)**, and international cybercrime statutes. The tool automatically alerts the operator when targeted against non-loopback addresses.

---

## Features

1. **Multithreaded Thread-Pool Engine**:
   - Uses an atomic work-stealing counter to partition port ranges across concurrent worker threads without lock contention.
2. **Non-Blocking Connect with Precise Timeout**:
   - Switches sockets to non-blocking mode (`ioctlsocket` / `fcntl`) and performs asynchronous connection polling using `select()`, avoiding unbounded kernel connection delays.
3. **Banner Grabbing & Service Detection**:
   - Probes open ports for identification strings (e.g., SSH version headers, HTTP `Server:` banners, FTP greetings).
4. **Cross-Platform Compatibility**:
   - Native support for both Windows (**Winsock2**) and Linux/macOS (**POSIX Berkeley sockets**) without external third-party dependencies.
5. **Safety Warning on Non-Loopback Destinations**:
   - Emits a prominent terminal warning banner whenever the target host is not a loopback address (`127.0.0.1`, `localhost`, `::1`).

---

## Technical Architecture

```
                       [ CLI Arguments ]
                              │
                    (Loopback verification)
                              ▼
                   ┌───────────────────────┐
                   │   PortScanner Engine  │
                   └──────────┬────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
   [ Worker #1 ]        [ Worker #2 ]        [ Worker #N ]
         │                    │                    │
   (Non-blocking)       (Non-blocking)       (Non-blocking)
   connect() + select   connect() + select   connect() + select
         │                    │                    │
         └────────────────────┼────────────────────┘
                              ▼
                     [ Open Port Found ]
                              │
                    (Optional Banner Grab)
                              │
                              ▼
                  [ Consolidated Results ]
```

---

## Building from Source

### Prerequisites
- C++17 compliant compiler (MSVC 2019+, GCC 9+, or Clang 10+)
- CMake 3.15 or newer
- Ninja or Make

### Windows (MSVC + Ninja)
```bash
# From port-scanner directory:
cmake -B build -G Ninja
cmake --build build
```

### Linux / macOS (GCC / Clang)
```bash
cmake -B build
cmake --build build
```

The build produces two targets:
- `build/port_scanner` (the CLI tool)
- `build/port_scanner_tests` (the automated test suite)

---

## Usage Guide

```text
Usage: port_scanner [options]

Options:
  -h, --host <host>       Target IP or hostname (default: 127.0.0.1)
  -p, --ports <range>      Port range 'start-end' or single port (default: 1-1024)
  -t, --timeout <ms>       Connect timeout in milliseconds (default: 1000)
  -n, --threads <num>      Concurrency / thread pool size (default: 50)
      --no-banner          Disable service banner grabbing
      --help               Display this help dialog
```

### Examples

#### 1. Scan default well-known ports on localhost
```bash
./port_scanner --host 127.0.0.1 --ports 1-1024 --threads 50
```

#### 2. Scan specific range with custom timeout
```bash
./port_scanner --host 127.0.0.1 --ports 8000-8100 --timeout 250 --threads 20
```

#### 3. Scan without banner grabbing for rapid probing
```bash
./port_scanner --host 127.0.0.1 --ports 1-5000 --threads 100 --no-banner
```

---

## Sample Output

```text
=========================================================
       security-labs // port-scanner (C++17)             
  Multithreaded TCP Connect Scanner & Banner Grabber     
=========================================================

[*] Target Host:     127.0.0.1
[*] Port Range:      1 -> 1024
[*] Connect Timeout: 500 ms
[*] Worker Threads:  50
[*] Banner Grab:     Enabled

[*] Starting port scan...
[+] Progress: 1024/1024 ports (100%) 

--- Scan Results ---
PORT        STATE     SERVICE               BANNER
-----------------------------------------------------------------
22/tcp      OPEN      SSH                   SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
80/tcp      OPEN      HTTP                  HTTP/1.1 200 OK (nginx/1.18.0)
443/tcp     OPEN      HTTPS                 -
3306/tcp    OPEN      MySQL                 5.7.42-0ubuntu0.18.04.1

[+] Finished in 1.12s. 4 open port(s) found across 1024 ports scanned.
```

---

## Running the Unit Tests

The test suite runs an in-process local TCP listener on an ephemeral loopback port, validates loopback detection, verifies service dictionary mappings, tests positive connection and banner retrieval, and confirms negative connection handling:

```bash
# Run tests executable
./build/port_scanner_tests

# Or run via CTest
ctest --test-dir build --output-on-failure
```

---

## Design Trade-offs & Limitations

1. **TCP Connect Scan vs. Raw SYN Stealth Scan**:
   - `port-scanner` uses standard operating system socket `connect()` calls. Unlike raw SYN scanners (such as Nmap SYN scan), it does not require root/administrator privileges and leaves full TCP three-way handshakes in server logs.
2. **File Descriptor Limits**:
   - Setting `--threads` higher than the operating system's per-process file descriptor ceiling (e.g. `RLIMIT_NOFILE` on Linux, typically 1024) can cause socket creation exhaustion.
3. **TCP Only**:
   - Does not probe UDP services, which require ICMP port unreachable parsing.

---

## Roadmap & Future Enhancements

- [x] Multithreaded TCP connect scanning engine with configurable timeout and thread pool size.
- [x] SocketGuard RAII socket cleanup abstraction preventing file descriptor leaks.
- [x] Application-layer banner grabbing for HTTP, SSH, FTP, SMTP, and MySQL services.
- [x] Strict safety guard enforcement restricting active scans to `127.0.0.1` and loopback interfaces.
- [ ] **Raw SYN Stealth Scanning**: Implement raw socket TCP SYN scanning (`SOCK_RAW`) on Linux with `CAP_NET_RAW` capability to detect open ports without completing the three-way handshake.
- [ ] **UDP Service Scanning**: Support UDP port probing via ICMP port-unreachable error frame parsing (`SOCK_RAW` / `IPPROTO_ICMP`).
- [ ] **TLS Certificate Inspection**: Automatic TLS negotiation on port 443/8443 to extract certificate Subject Alternative Names (SAN), issuer CA, and expiration dates.
- [ ] **OS Fingerprinting**: Heuristic operating system detection based on initial TCP Window Size, IP TTL defaults, and TCP options order.
- [ ] **Structured Output**: Export results directly to JSON, CSV, and SARIF for automated vulnerability management ingestion.

