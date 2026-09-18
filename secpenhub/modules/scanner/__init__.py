"""
Scanner Module - Web Vulnerability Detection
"""

from .owasp_top10 import OWASPScanner
from .sql_injection import SQLInjectionScanner
from .xss import XSSScanner
from .csrf import CSRFScanner

__all__ = ["OWASPScanner", "SQLInjectionScanner", "XSSScanner", "CSRFScanner"]
