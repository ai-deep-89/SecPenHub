"""
CSRF Scanner - Cross-Site Request Forgery Detection
"""

import aiohttp
import re
from typing import List, Dict, Optional
from dataclasses import dataclass

from ...core.logger import Logger


@dataclass
class CSRFResult:
    """Result of CSRF test."""
    url: str
    form_action: str
    has_token: bool
    token_name: Optional[str]
    is_vulnerable: bool
    severity: str


class CSRFScanner:
    """
    Cross-Site Request Forgery (CSRF) scanner.

    Detects forms missing CSRF token protection.
    """

    # Known CSRF token parameter names
    TOKEN_NAMES = [
        'csrf_token',
        'csrftoken',
        '_csrf',
        '_csrf_token',
        'xsrf_token',
        'x-csrf-token',
        'x-xsrf-token',
        'csrfmiddlewaretoken',
        'authenticity_token',
        'request_verification_token',
    ]

    def __init__(self, timeout: int = 30):
        """
        Initialize CSRF scanner.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.logger = Logger.get_logger("csrf_scanner")

    async def scan_page(self, url: str) -> List[CSRFResult]:
        """
        Scan a page for CSRF vulnerabilities.

        Args:
            url: Target URL to scan

        Returns:
            List of CSRF findings
        """
        results = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    html = await response.text()

                # Find all forms
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, 'html.parser')
                forms = soup.find_all('form')

                for form in forms:
                    result = self._analyze_form(url, form)
                    if result:
                        results.append(result)

        except Exception as e:
            self.logger.warning(f"CSRF scan failed for {url}: {e}")

        return results

    def _analyze_form(self, page_url: str, form) -> Optional[CSRFResult]:
        """Analyze a single form for CSRF protection."""
        form_action = form.get('action', '')
        method = form.get('method', 'get').upper()

        # Only check POST/PUT/PATCH forms (state-changing)
        if method not in ('POST', 'PUT', 'PATCH'):
            return None

        # Find all input fields
        inputs = form.find_all(['input', 'textarea'])
        token_input = None

        for inp in inputs:
            name = inp.get('name', '').lower()
            inp_type = inp.get('type', 'text').lower()

            # Check if this is a CSRF token field
            if inp_type == 'hidden':
                for token_name in self.TOKEN_NAMES:
                    if token_name in name:
                        token_input = inp
                        break

            if token_input:
                break

        has_token = token_input is not None
        token_name = token_input.get('name') if token_input else None

        # Check for SameSite cookie attribute (would need response headers)
        # For now, we flag forms without tokens as vulnerable
        is_vulnerable = not has_token

        if is_vulnerable:
            return CSRFResult(
                url=page_url,
                form_action=form_action,
                has_token=has_token,
                token_name=token_name,
                is_vulnerable=True,
                severity="Medium" if method == "POST" else "Low"
            )

        return None

    async def scan_multiple(self, urls: List[str]) -> List[CSRFResult]:
        """
        Scan multiple pages for CSRF vulnerabilities.

        Args:
            urls: List of URLs to scan

        Returns:
            List of all CSRF findings
        """
        all_results = []

        import asyncio
        tasks = [self.scan_page(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_results.extend(result)

        return all_results
