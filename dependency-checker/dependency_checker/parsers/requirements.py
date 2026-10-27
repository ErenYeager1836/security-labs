"""
Parser for Python requirements.txt manifest files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from dependency_checker.models import Ecosystem, PackageDependency


class RequirementsParser:
    """Parses Python requirements.txt files into PackageDependency objects."""

    # Matches package specifiers: name==version, name>=version, name~=version
    PKG_REGEX = re.compile(
        r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|===)\s*([a-zA-Z0-9_\-\.\+]+)",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, file_path: str | Path) -> List[PackageDependency]:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Requirements file not found: {path}")

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        dependencies: List[PackageDependency] = []

        for line_no, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # Ignore empty lines and full line comments
            if not line or line.startswith("#"):
                continue

            # Strip inline comments (e.g., requests==2.25.0 # security update)
            if "#" in line:
                line = line.split("#", 1)[0].strip()

            # Ignore pip option flags (-r, -i, --extra-index-url, etc.)
            if line.startswith("-"):
                continue

            # Remove environment markers (e.g. ; python_version >= '3.8')
            if ";" in line:
                line = line.split(";", 1)[0].strip()

            match = cls.PKG_REGEX.match(line)
            if match:
                pkg_name, pkg_version = match.groups()
                dependencies.append(
                    PackageDependency(
                        name=pkg_name.lower().replace("_", "-"),
                        version=pkg_version.strip(),
                        ecosystem=Ecosystem.PYPI,
                        file_path=str(path),
                        line_number=line_no,
                    )
                )

        return dependencies
