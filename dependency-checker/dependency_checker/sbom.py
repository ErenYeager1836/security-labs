"""
Software Bill of Materials (SBOM) generator in CycloneDX 1.5 JSON format.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid

from dependency_checker.models import Ecosystem, PackageDependency


def create_purl(dep: PackageDependency) -> str:
    """Generates standard Package URL (purl) according to package-url specification."""
    safe_version = dep.version if dep.version and dep.version != "*" else "0.0.0"
    if dep.ecosystem == Ecosystem.PYPI:
        return f"pkg:pypi/{dep.name.lower()}@{safe_version}"
    elif dep.ecosystem == Ecosystem.MAVEN:
        # Handles groupId:artifactId format
        parts = dep.name.split(":", 1)
        if len(parts) == 2:
            return f"pkg:maven/{parts[0]}/{parts[1]}@{safe_version}"
        return f"pkg:maven/{dep.name}@{safe_version}"
    return f"pkg:generic/{dep.name}@{safe_version}"


def generate_cyclonedx_sbom(
    dependencies: List[PackageDependency],
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a compliant CycloneDX 1.5 JSON SBOM structure from parsed dependencies.
    Optionally saves the document directly to disk.
    """
    now = datetime.now(timezone.utc).isoformat()
    serial_uuid = str(uuid.uuid4())

    components = []
    for dep in dependencies:
        purl = create_purl(dep)
        comp = {
            "type": "library",
            "name": dep.name,
            "version": dep.version if dep.version else "unknown",
            "purl": purl,
            "bom-ref": purl,
            "properties": [
                {"name": "ecosystem", "value": dep.ecosystem.value},
                {"name": "manifest_file", "value": dep.file_path},
            ]
        }
        components.append(comp)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_uuid}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "Security Labs",
                    "name": "dependency-checker",
                    "version": "1.1.0"
                }
            ],
            "component": {
                "type": "application",
                "name": "scanned-workspace",
                "version": "1.0.0"
            }
        },
        "components": components
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)

    return sbom
