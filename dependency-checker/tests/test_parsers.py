"""
Unit tests for requirements.txt and pom.xml parsers.
"""

import tempfile
import unittest
from pathlib import Path

from dependency_checker.models import Ecosystem
from dependency_checker.parsers.pom import PomParser
from dependency_checker.parsers.requirements import RequirementsParser


class TestRequirementsParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.req_file = Path(self.temp_dir.name) / "requirements.txt"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_standard_pinned_packages(self):
        content = (
            "# Core dependencies\n"
            "requests==2.25.1\n"
            "urllib3 == 1.26.5 # Inline comment\n"
            "flask>=2.0.0\n"
            "-r other-requirements.txt\n"
            "--index-url https://pypi.org/simple\n"
            "pytest~=7.1.0; python_version >= '3.8'\n"
        )
        self.req_file.write_text(content, encoding="utf-8")

        deps = RequirementsParser.parse(self.req_file)
        self.assertEqual(len(deps), 4)

        dep_map = {d.name: d for d in deps}
        self.assertIn("requests", dep_map)
        self.assertEqual(dep_map["requests"].version, "2.25.1")
        self.assertEqual(dep_map["requests"].ecosystem, Ecosystem.PYPI)

        self.assertIn("urllib3", dep_map)
        self.assertEqual(dep_map["urllib3"].version, "1.26.5")

        self.assertIn("flask", dep_map)
        self.assertEqual(dep_map["flask"].version, "2.0.0")

        self.assertIn("pytest", dep_map)
        self.assertEqual(dep_map["pytest"].version, "7.1.0")


class TestPomParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pom_file = Path(self.temp_dir.name) / "pom.xml"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_maven_dependencies_with_properties(self):
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <properties>
        <log4j.ver>2.14.1</log4j.ver>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>${log4j.ver}</version>
        </dependency>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>30.1-jre</version>
        </dependency>
    </dependencies>
</project>"""
        self.pom_file.write_text(xml_content, encoding="utf-8")

        deps = PomParser.parse(self.pom_file)
        self.assertEqual(len(deps), 2)

        dep_map = {d.name: d for d in deps}
        self.assertIn("org.apache.logging.log4j:log4j-core", dep_map)
        self.assertEqual(dep_map["org.apache.logging.log4j:log4j-core"].version, "2.14.1")
        self.assertEqual(dep_map["org.apache.logging.log4j:log4j-core"].ecosystem, Ecosystem.MAVEN)

        self.assertIn("com.google.guava:guava", dep_map)
        self.assertEqual(dep_map["com.google.guava:guava"].version, "30.1-jre")


if __name__ == "__main__":
    unittest.main()
