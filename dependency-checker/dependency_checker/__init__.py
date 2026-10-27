"""
dependency-checker: Software supply chain and package vulnerability auditor.

Parses requirements.txt and pom.xml manifests and audits dependencies against
the open-source Google OSV.dev vulnerability database.
"""

__version__ = "0.2.0"

from dependency_checker.sbom import generate_cyclonedx_sbom

__all__ = ["generate_cyclonedx_sbom"]
