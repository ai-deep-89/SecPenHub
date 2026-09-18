"""
XSS Scanner - Cross-Site Scripting Detection
"""

import asyncio
import aiohttp
import re
from typing import List, Optional, Dict
from dataclasses import dataclass

from ...core.logger import Logger


@dataclass
class XSSResult:
    """Result of XSS test."""
    url: str
    parameter: str
    payload: str
    xss_type: str  # reflected, stored, DOM
    is_vulnerable: bool
    context: Optional[str] = None


class XSSScanner:
    """
    Cross-Site Scripting (XSS) scanner with multiple detection techniques.

    Supports:
    - Reflected XSS
    - Stored XSS (basic detection)
    - DOM-based XSS
    """

    # XSS payloads by type
    PAYLOADS = {
        "reflected": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>",
            "javascript:alert('XSS')",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        ],
        "stored": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ],
        "dom": [
            "#<img src=x onerror=alert('XSS')>",
            "#<script>alert('XSS')</script>",
        ]
    }

    def __init__(
        self,
        target_url: str,
        timeout: int = 30
    ):
        """
        Initialize XSS scanner.

        Args:
            target_url: Target URL to test
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.logger = Logger.get_logger("xss_scanner")

    async def scan_parameter(self, param_name: str, param_value: str = "test") -> List[XSSResult]:
        """
        Scan a specific parameter for XSS.

        Args:
            param_name: Parameter name to test
            param_value: Original parameter value

        Returns:
            List of XSS findings
        """
        results = []

        for xss_type, payloads in self.PAYLOADS.items():
            for payload in payloads:
                result = await self._test_xss(param_name, param_value, payload, xss_type)
                if result and result.is_vulnerable:
                    results.append(result)

        return results

    async def _test_xss(
        self,
        param_name: str,
        param_value: str,
        payload: str,
        xss_type: str
    ) -> Optional[XSSResult]:
        """Test a specific payload."""
        try:
            test_params = {param_name: payload}

            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, params=test_params, timeout=self.timeout) as response:
                    content = await response.text()

            # Check if payload is reflected without proper encoding
            if self._check_reflection(payload, content):
                # Additional checks for context
                context = self._determine_context(payload, content)

                return XSSResult(
                    url=self.target_url,
                    parameter=param_name,
                    payload=payload,
                    xss_type=xss_type,
                    is_vulnerable=True,
                    context=context
                )

        except Exception as e:
            self.logger.debug(f"XSS test failed: {e}")

        return None

    def _check_reflection(self, payload: str, content: str) -> bool:
        """Check if payload is reflected in content."""
        # Direct reflection
        if payload in content:
            return True

        # Encoded reflection checks
        encoded_payloads = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace("'", "%27").replace('"', "%22"),
        ]

        for encoded in encoded_payloads:
            if encoded in content:
                # Check if the original characters also appear (could be double-encoded)
                if payload in content:
                    return True

        return False

    def _determine_context(self, payload: str, content: str) -> str:
        """Determine the context where the payload is reflected."""
        # HTML context
        if re.search(r'<[^>]*>' + re.escape(payload), content, re.I):
            return "HTML tag context"

        # Attribute context
        if re.search(r'<[^>]*\s' + re.escape(payload) + r'=', content, re.I):
            return "HTML attribute context"

        # JavaScript context
        if re.search(r'<script[^>]*>.*?' + re.escape(payload), content, re.I | re.S):
            return "JavaScript context"

        # URL context
        if re.search(r'[?&]' + re.escape(payload), content):
            return "URL parameter context"

        return "Unknown context"

    def _is_html_encoded(self, s: str) -> bool:
        """Check if string contains HTML entities."""
        html_entities = ['&lt;', '&gt;', '&amp;', '&quot;', '&#']
        return any(entity in s for entity in html_entities)

    async def scan_form(self, form_data: Dict) -> List[XSSResult]:
        """
        Scan all parameters in a form for XSS.

        Args:
            form_data: Form information with action, method, and inputs

        Returns:
            List of XSS findings
        """
        results = []

        for input_field in form_data.get('inputs', []):
            if input_field.get('type') in ('text', 'search', 'email', 'url', 'hidden'):
                findings = await self.scan_parameter(
                    input_field['name'],
                    input_field.get('value', 'test')
                )
                results.extend(findings)

        return results

    async def scan_post_form(self, form_data: Dict) -> List[XSSResult]:
        """
        Scan a POST form for XSS.

        Args:
            form_data: Form information with action, method, and inputs

        Returns:
            List of XSS findings
        """
        results = []

        for input_field in form_data.get('inputs', []):
            if input_field.get('type') in ('text', 'search', 'email', 'password', 'hidden'):
                for payload in self.PAYLOADS["reflected"]:
                    try:
                        data = {input_field['name']: payload}
                        async with aiohttp.ClientSession() as session:
                            async with session.post(
                                form_data['action'],
                                data=data,
                                timeout=self.timeout
                            ) as response:
                                content = await response.text()

                        if self._check_reflection(payload, content):
                            results.append(XSSResult(
                                url=form_data['action'],
                                parameter=input_field['name'],
                                payload=payload,
                                xss_type="reflected",
                                is_vulnerable=True
                            ))

                    except Exception as e:
                        self.logger.debug(f"POST XSS test failed: {e}")

        return results
