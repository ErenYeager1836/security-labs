"""
Parser for Maven pom.xml manifest files.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List

from dependency_checker.models import Ecosystem, PackageDependency


class PomParser:
    """Parses Java Maven pom.xml files into PackageDependency objects."""

    @classmethod
    def parse(cls, file_path: str | Path) -> List[PackageDependency]:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"pom.xml file not found: {path}")

        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML in {path}: {e}")

        # Maven namespaces (e.g. {http://maven.apache.org/POM/4.0.0})
        ns = ""
        if root.tag.startswith("{") and "}" in root.tag:
            ns = root.tag.split("}")[0] + "}"

        # 1. Parse properties map for property resolution (e.g. ${log4j.version})
        properties: Dict[str, str] = {}
        props_elem = root.find(f"{ns}properties")
        if props_elem is not None:
            for prop in props_elem:
                prop_name = prop.tag.replace(ns, "")
                if prop.text:
                    properties[f"${{{prop_name}}}"] = prop.text.strip()

        dependencies: List[PackageDependency] = []

        # 2. Extract dependencies from <dependencies> and <dependencyManagement>
        for deps_container in root.findall(f".//{ns}dependencies"):
            for dep in deps_container.findall(f"{ns}dependency"):
                group_elem = dep.find(f"{ns}groupId")
                artifact_elem = dep.find(f"{ns}artifactId")
                version_elem = dep.find(f"{ns}version")

                if group_elem is None or artifact_elem is None:
                    continue

                group_id = (group_elem.text or "").strip()
                artifact_id = (artifact_elem.text or "").strip()
                raw_version = (version_elem.text if version_elem is not None else "").strip()

                if not group_id or not artifact_id or not raw_version:
                    continue

                # Resolve property reference if used
                resolved_version = properties.get(raw_version, raw_version)

                # Form standard OSV package name: "groupId:artifactId"
                package_name = f"{group_id}:{artifact_id}"

                dependencies.append(
                    PackageDependency(
                        name=package_name,
                        version=resolved_version,
                        ecosystem=Ecosystem.MAVEN,
                        file_path=str(path),
                    )
                )

        return dependencies
