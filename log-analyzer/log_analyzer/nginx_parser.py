"""
Parser for Nginx HTTP access logs (Combined Log Format and common custom formats).
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import List, Optional

from log_analyzer.models import NginxEvent


# Standard Nginx combined log format regex
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
NGINX_COMBINED_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F.:]+)\s+-\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)(?:\s+[A-Z0-9./]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
)


def parse_nginx_log_line(line: str) -> Optional[NginxEvent]:
    """Parses a single line of an Nginx access.log into a structured NginxEvent."""
    line = line.strip()
    if not line:
        return None

    m = NGINX_COMBINED_RE.match(line)
    if not m:
        # Fallback for simplified status/request lines
        simple_match = re.search(r'(?P<ip>[0-9a-fA-F.:]+).*"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)".*?\s+(?P<status>\d{3})\s+(?P<bytes>\d+)', line)
        if simple_match:
            return NginxEvent(
                remote_ip=simple_match.group("ip"),
                timestamp="",
                method=simple_match.group("method"),
                path=simple_match.group("path"),
                status_code=int(simple_match.group("status")),
                body_bytes=int(simple_match.group("bytes")),
                referer="",
                user_agent="",
                raw_line=line,
            )
        return None

    return NginxEvent(
        remote_ip=m.group("ip"),
        timestamp=m.group("time"),
        method=m.group("method"),
        path=m.group("path"),
        status_code=int(m.group("status")),
        body_bytes=int(m.group("bytes")),
        referer=m.group("referer") or "",
        user_agent=m.group("ua") or "",
        raw_line=line,
    )


def parse_nginx_log_file(file_path: str | Path) -> List[NginxEvent]:
    """Reads and parses an entire Nginx access.log file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Nginx access log file not found: {file_path}")

    events: List[NginxEvent] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_nginx_log_line(line)
            if ev:
                events.append(ev)
    return events
