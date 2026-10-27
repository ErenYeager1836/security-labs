"""
CIS-style File & Directory Permission Audit Rules.

Reference: CIS Linux Benchmark Section 6.1 (System File Permissions).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Dict, List, Optional, Tuple

from hardening_auditor.models import Category, RuleResult, RuleStatus, Severity


# Specification of critical security files, maximum permissible octal mode, and CIS rule metadata
FILE_PERMISSION_SPECS = [
    {
        "id": "CIS-PERM-01",
        "path": "etc/shadow",
        "display": "/etc/shadow",
        "title": "Permissions on /etc/shadow (0640 or more restrictive)",
        "max_mode": 0o640,
        "recommended_str": "0600 (or 0000 / 0640)",
        "severity": Severity.CRITICAL.value,
        "rationale": "Contains one-way cryptographic hashes of user passwords; world readability permits offline password cracking.",
        "remediation": "chmod 0600 /etc/shadow && chown root:root /etc/shadow",
    },
    {
        "id": "CIS-PERM-02",
        "path": "etc/gshadow",
        "display": "/etc/gshadow",
        "title": "Permissions on /etc/gshadow (0640 or more restrictive)",
        "max_mode": 0o640,
        "recommended_str": "0600 (or 0000 / 0640)",
        "severity": Severity.CRITICAL.value,
        "rationale": "Contains group account shadow password hashes; unauthorized access facilitates privilege escalation.",
        "remediation": "chmod 0600 /etc/gshadow && chown root:root /etc/gshadow",
    },
    {
        "id": "CIS-PERM-03",
        "path": "etc/passwd",
        "display": "/etc/passwd",
        "title": "Permissions on /etc/passwd (0644 or more restrictive, no world-write)",
        "max_mode": 0o644,
        "recommended_str": "0644",
        "severity": Severity.CRITICAL.value,
        "rationale": "Stores user account metadata. Write access allows unprivileged users to create UID 0 accounts or redirect home paths.",
        "remediation": "chmod 0644 /etc/passwd && chown root:root /etc/passwd",
    },
    {
        "id": "CIS-PERM-04",
        "path": "etc/group",
        "display": "/etc/group",
        "title": "Permissions on /etc/group (0644 or more restrictive, no world-write)",
        "max_mode": 0o644,
        "recommended_str": "0644",
        "severity": Severity.HIGH.value,
        "rationale": "Lists user group memberships. Write access enables arbitrary group addition (e.g. adding oneself to sudo or docker group).",
        "remediation": "chmod 0644 /etc/group && chown root:root /etc/group",
    },
    {
        "id": "CIS-PERM-05",
        "path": "etc/sudoers",
        "display": "/etc/sudoers",
        "title": "Permissions on /etc/sudoers (0440 or 0400)",
        "max_mode": 0o440,
        "recommended_str": "0440",
        "severity": Severity.CRITICAL.value,
        "rationale": "Controls sudo execution privileges. World or group writability permits instant local root takeover.",
        "remediation": "chmod 0440 /etc/sudoers && chown root:root /etc/sudoers",
    },
]


def load_mock_permissions(root_dir: Path) -> Dict[str, int]:
    """Loads simulated POSIX permission modes from .permissions.json if present."""
    mock_file = root_dir / ".permissions.json"
    if not mock_file.exists():
        mock_file = root_dir / "permissions.json"

    if mock_file.is_file():
        try:
            with open(mock_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                result: Dict[str, int] = {}
                for k, v in data.items():
                    norm_k = k.lstrip("/").replace("\\", "/")
                    if isinstance(v, str):
                        result[norm_k] = int(v, 8)
                    elif isinstance(v, int):
                        result[norm_k] = v
                return result
        except Exception:
            return {}
    return {}


def get_file_mode(target_file: Path, mock_modes: Dict[str, int], rel_path: str) -> Optional[int]:
    """Retrieves file permission mode, consulting mock data or OS filesystem stat."""
    # Check mock map first
    norm_rel = rel_path.lstrip("/").replace("\\", "/")
    if norm_rel in mock_modes:
        return mock_modes[norm_rel]
    if f"/{norm_rel}" in mock_modes:
        return mock_modes[f"/{norm_rel}"]

    if not target_file.exists():
        return None

    # On POSIX systems, read actual mode
    if os.name != "nt":
        try:
            st = target_file.stat()
            return stat.S_IMODE(st.st_mode)
        except OSError:
            return None

    # On Windows without mock data, simulate safe default if file exists
    return 0o644


def audit_file_permissions(root_dir: Path) -> List[RuleResult]:
    """Audits file permissions on critical system configuration and credential databases."""
    results: List[RuleResult] = []
    mock_modes = load_mock_permissions(root_dir)

    for spec in FILE_PERMISSION_SPECS:
        target_path = root_dir / Path(spec["path"])
        mode = get_file_mode(target_path, mock_modes, spec["path"])

        if mode is None:
            results.append(
                RuleResult(
                    rule_id=spec["id"],
                    title=spec["title"],
                    category=Category.FILE_PERMS.value,
                    severity=spec["severity"],
                    status=RuleStatus.SKIP,
                    current_value="File does not exist",
                    expected_value=f"Permissions <= {spec['recommended_str']}",
                    remediation=spec["remediation"],
                    rationale=spec["rationale"],
                )
            )
            continue

        mode_octal_str = f"0{oct(mode)[2:]}"

        # Evaluation rules:
        # 1. No world-write permission (0o002) for ANY security file
        # 2. No world-read permission (0o004) for shadow, gshadow, sudoers
        # 3. Mode must not exceed max permissible mode bits
        is_world_writable = bool(mode & 0o002)
        is_world_readable = bool(mode & 0o004)

        has_excess_bits = False
        if spec["path"] in ("etc/shadow", "etc/gshadow", "etc/sudoers"):
            if is_world_readable or is_world_writable:
                has_excess_bits = True
        if is_world_writable:
            has_excess_bits = True

        # Check against specific maximum bitmask
        max_mode = spec["max_mode"]
        # Any bits set in mode that are NOT allowed in max_mode
        if (mode & ~max_mode) != 0:
            has_excess_bits = True

        status = RuleStatus.FAIL if has_excess_bits else RuleStatus.PASS

        results.append(
            RuleResult(
                rule_id=spec["id"],
                title=spec["title"],
                category=Category.FILE_PERMS.value,
                severity=spec["severity"],
                status=status,
                current_value=f"Mode {mode_octal_str}",
                expected_value=f"Mode <= {spec['recommended_str']}",
                remediation=spec["remediation"],
                rationale=spec["rationale"],
            )
        )

    return results
