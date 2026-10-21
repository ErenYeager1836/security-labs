"""
Parser for SSH daemon authentication logs (Debian/Ubuntu auth.log and RHEL secure log formats).
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import List, Optional

from log_analyzer.models import SSHEvent


# Regex patterns matching standard SSH daemon log lines
FAILED_PASSWORD_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?:\S+\s+)?sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+)\s+"
    r"from (?P<ip>[0-9a-fA-F.:]+)\s+port (?P<port>\d+)"
)

INVALID_USER_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?:\S+\s+)?sshd\[\d+\]:\s+Invalid user (?P<user>\S+)\s+"
    r"from (?P<ip>[0-9a-fA-F.:]+)"
)

ACCEPTED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?:\S+\s+)?sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+)\s+"
    r"from (?P<ip>[0-9a-fA-F.:]+)\s+port (?P<port>\d+)"
)


def parse_ssh_log_line(line: str) -> Optional[SSHEvent]:
    """Parses a single line of an SSH auth.log into a structured SSHEvent."""
    line = line.strip()
    if not line:
        return None

    m_fail = FAILED_PASSWORD_RE.search(line)
    if m_fail:
        return SSHEvent(
            timestamp=m_fail.group("timestamp"),
            event_type="failed",
            username=m_fail.group("user"),
            ip_address=m_fail.group("ip"),
            port=int(m_fail.group("port")),
            raw_line=line,
        )

    m_inv = INVALID_USER_RE.search(line)
    if m_inv:
        return SSHEvent(
            timestamp=m_inv.group("timestamp"),
            event_type="invalid_user",
            username=m_inv.group("user"),
            ip_address=m_inv.group("ip"),
            port=22,
            raw_line=line,
        )

    m_acc = ACCEPTED_LOGIN_RE.search(line)
    if m_acc:
        return SSHEvent(
            timestamp=m_acc.group("timestamp"),
            event_type="accepted",
            username=m_acc.group("user"),
            ip_address=m_acc.group("ip"),
            port=int(m_acc.group("port")),
            raw_line=line,
        )

    return None


def parse_ssh_log_file(file_path: str | Path) -> List[SSHEvent]:
    """Reads and parses an entire SSH auth.log file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"SSH log file not found: {file_path}")

    events: List[SSHEvent] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_ssh_log_line(line)
            if ev:
                events.append(ev)
    return events
