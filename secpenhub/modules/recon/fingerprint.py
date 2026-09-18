"""
Service Fingerprinting Module

Identifies services and versions through banner grabbing and pattern analysis.
"""

import asyncio
import aiohttp
from typing import Dict, Optional, List
from bs4 import BeautifulSoup
import re

from ...core.logger import Logger


class Fingerprint:
    """
    Service fingerprinting through multiple techniques.
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize fingerprint module.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.logger = Logger.get_logger("fingerprint")

    async def fingerprint_url(self, url: str) -> Dict[str, str]:
        """
        Fingerprint a web service.

        Args:
            url: Target URL

        Returns:
            Dictionary with fingerprint information
        """
        result = {
            "url": url,
            "server": None,
            "tech": [],
            "cms": None,
            "js_libs": []
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    headers = response.headers

                    # Server detection
                    result["server"] = headers.get("Server") or headers.get("X-Powered-By")

                    # Parse HTML for tech detection
                    if response.content_type and "text/html" in response.content_type:
                        html = await response.text()
                        result["tech"] = self._detect_technologies(html)
                        result["cms"] = self._detect_cms(html, headers)
                        result["js_libs"] = self._detect_js_libs(html)

        except Exception as e:
            self.logger.warning(f"Fingerprint failed for {url}: {e}")

        return result

    def _detect_technologies(self, html: str) -> List[str]:
        """Detect technologies from HTML content."""
        technologies = []

        tech_signatures = {
            "jQuery": r"jquery",
            "React": r"react",
            "Vue": r"vue\.js",
            "Angular": r"angular",
            "Bootstrap": r"bootstrap",
            "WordPress": r"wp-content|wordpress",
            "Drupal": r"drupal",
            "Laravel": r"laravel",
            "Django": r"csrfmiddlewaretoken",
            "Rails": r"csrf-token",
            "Express": r"express",
            "Node.js": r"node",
        }

        html_lower = html.lower()
        for tech, pattern in tech_signatures.items():
            if re.search(pattern, html_lower):
                technologies.append(tech)

        return technologies

    def _detect_cms(self, html: str, headers: Dict) -> Optional[str]:
        """Detect CMS from HTML and headers."""
        # Check headers first
        server = headers.get("Server", "").lower()

        if "wordPress" in html.lower() or "wp-content" in html.lower():
            return "WordPress"
        if "drupal" in html.lower():
            return "Drupal"
        if "joomla" in html.lower():
            return "Joomla"
        if "magento" in html.lower():
            return "Magento"
        if "shopify" in html.lower():
            return "Shopify"

        return None

    def _detect_js_libs(self, html: str) -> List[str]:
        """Detect JavaScript libraries from HTML."""
        libs = []

        # Look for script tags with src attributes
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script', src=True)

        lib_signatures = {
            "jQuery": r"jquery[\d.]*\.js",
            "React": r"react[\d.]*\.js|react.production.min.js",
            "Vue": r"vue[\d.]*\.js",
            "Angular": r"angular[\d.]*\.js",
            "Axios": r"axios[\d.]*\.js",
            "Lodash": r"lodash[\d.]*\.js",
            "Moment.js": r"moment[\d.]*\.js",
            "D3.js": r"d3[\d.]*\.js",
            "Three.js": r"three[\d.]*\.js",
        }

        for script in scripts:
            src = script.get('src', '').lower()
            for lib, pattern in lib_signatures.items():
                if re.search(pattern, src) and lib not in libs:
                    libs.append(lib)

        return libs

    async def fingerprint_multiple(self, urls: List[str]) -> List[Dict[str, str]]:
        """
        Fingerprint multiple URLs concurrently.

        Args:
            urls: List of URLs to fingerprint

        Returns:
            List of fingerprint results
        """
        tasks = [self.fingerprint_url(url) for url in urls]
        return await asyncio.gather(*tasks)
