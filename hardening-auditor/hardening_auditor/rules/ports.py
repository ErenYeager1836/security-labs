"""
CIS-style Network Services & Insecure Listening Ports Audit Rules.

Reference: CIS Linux Benchmark Section 2.1 (Special Purpose Services).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

from hardening_auditor.models import Category, RuleResult, RuleStatus, Severity


# High-risk / legacy insecure services that should never listen on production endpoints
INSECURE_PORTS = [
    {
        "id": "CIS-PORT-01",
        "port": 23,
        "proto": "tcp",
        "service": "telnet",
        "title": "Ensure Telnet Server is Not Listening (Port 23)",
        "severity": Severity.CRITICAL.value,
        "rationale": "The Telnet protocol transmits all data, including credentials and command payloads, in unencrypted plaintext.",
        "remediation": "systemctl stop telnet.socket telnet && systemctl disable telnet.socket telnet; apt-get purge telnetd / yum remove telnet-server",
    },
    {
        "id": "CIS-PORT-02",
        "port": 21,
        "proto": "tcp",
        "service": "ftp",
        "title": "Ensure Insecure FTP Server is Not Listening (Port 21)",
        "severity": Severity.HIGH.value,
        "rationale": "Standard FTP transmits credentials and session data unencrypted over the wire. Secure alternatives (SFTP, SCP) should be used.",
        "remediation": "systemctl stop vsftpd proftpd pure-ftpd && systemctl disable vsftpd proftpd pure-ftpd",
    },
    {
        "id": "CIS-PORT-03",
        "port": 514,
        "proto": "tcp",
        "service": "rsh/rlogin",
        "title": "Ensure Legacy rsh/rlogin/rcp Services are Not Listening (Ports 512-514)",
        "severity": Severity.CRITICAL.value,
        "rationale": "Legacy r-commands use weak IP-based trust authentication (.rhosts) without encryption and are trivially spoofed.",
        "remediation": "systemctl stop rsh.socket rlogin.socket && systemctl disable rsh.socket rlogin.socket",
    },
    {
        "id": "CIS-PORT-04",
        "port": 69,
        "proto": "udp",
        "service": "tftp",
        "title": "Ensure TFTP Server is Not Listening (UDP Port 69)",
        "severity": Severity.HIGH.value,
        "rationale": "TFTP provides no authentication or authorization controls, allowing arbitrary unauthenticated file reads/writes.",
        "remediation": "systemctl stop tftpd-hpa && systemctl disable tftpd-hpa",
    },
]


def parse_proc_net_tcp(proc_file: Path) -> Set[int]:
    """Parses Linux /proc/net/tcp or /proc/net/tcp6 to extract listening TCP ports (state 0A = TCP_LISTEN)."""
    listening_ports: Set[int] = set()
    if not proc_file.is_file():
        return listening_ports

    try:
        with open(proc_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            # First line is column headers: sl local_address rem_address st ...
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    state = parts[3].upper()
                    # 0A is TCP_LISTEN in Linux kernel socket states
                    if state == "0A" and ":" in local_addr:
                        _, hex_port = local_addr.split(":", 1)
                        try:
                            port = int(hex_port, 16)
                            listening_ports.add(port)
                        except ValueError:
                            pass
    except OSError:
        pass

    return listening_ports


def load_mock_listening_ports(root_dir: Path) -> Set[int]:
    """Checks for mock port files in root_dir: mock_ports.json or proc/net/tcp."""
    ports: Set[int] = set()
    json_file = root_dir / "mock_ports.json"
    if json_file.is_file():
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    ports.update(int(p) for p in data)
                elif isinstance(data, dict) and "open_ports" in data:
                    ports.update(int(p) for p in data["open_ports"])
        except Exception:
            pass

    proc_tcp = root_dir / "proc" / "net" / "tcp"
    if proc_tcp.is_file():
        ports.update(parse_proc_net_tcp(proc_tcp))

    proc_tcp6 = root_dir / "proc" / "net" / "tcp6"
    if proc_tcp6.is_file():
        ports.update(parse_proc_net_tcp(proc_tcp6))

    return ports


def audit_open_ports(root_dir: Path) -> List[RuleResult]:
    """Audits listening ports for insecure legacy services."""
    results: List[RuleResult] = []
    listening_ports = load_mock_listening_ports(root_dir)

    # If root_dir has no mock and is root '/', check system /proc/net/tcp
    if not listening_ports and str(root_dir) in ("/", ""):
        sys_tcp = Path("/proc/net/tcp")
        if sys_tcp.exists():
            listening_ports.update(parse_proc_net_tcp(sys_tcp))
        sys_tcp6 = Path("/proc/net/tcp6")
        if sys_tcp6.exists():
            listening_ports.update(parse_proc_net_tcp(sys_tcp6))

    for spec in INSECURE_PORTS:
        target_port = spec["port"]
        is_open = target_port in listening_ports

        status = RuleStatus.FAIL if is_open else RuleStatus.PASS
        curr_val = f"Port {target_port} is ACTIVE (LISTENING)" if is_open else f"Port {target_port} closed / not listening"

        results.append(
            RuleResult(
                rule_id=spec["id"],
                title=spec["title"],
                category=Category.OPEN_PORTS.value,
                severity=spec["severity"],
                status=status,
                current_value=curr_val,
                expected_value=f"Service disabled, port {target_port} closed",
                remediation=spec["remediation"],
                rationale=spec["rationale"],
            )
        )

    return results
