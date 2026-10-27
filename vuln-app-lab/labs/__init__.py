"""
Labs package for vuln-app-lab.
"""

from labs.idor import idor_bp
from labs.sqli import sqli_bp
from labs.ssrf import ssrf_bp
from labs.xss import xss_bp

__all__ = ["sqli_bp", "xss_bp", "idor_bp", "ssrf_bp"]
