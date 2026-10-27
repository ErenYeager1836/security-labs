"""
Parsers package for dependency-checker.
"""

from dependency_checker.parsers.pom import PomParser
from dependency_checker.parsers.requirements import RequirementsParser

__all__ = ["RequirementsParser", "PomParser"]
