"""
Subdomain Enumeration Module

Discovers subdomains through multiple techniques:
- Certificate Transparency logs (crt.sh)
- DNS zone transfers (where permitted)
- Dictionary-based guessing
- Permutation algorithms
"""

import asyncio
import aiohttp
import socket
from typing import List, Set, Optional, AsyncIterator
from urllib.parse import urlparse
import re

from ...core.logger import Logger


class SubdomainEnumerator:
    """
    Async subdomain enumeration with multiple discovery methods.
    """

    def __init__(
        self,
        domain: str,
        wordlist: Optional[str] = None,
        timeout: int = 30,
        max_concurrent: int = 50
    ):
        """
        Initialize subdomain enumerator.

        Args:
            domain: Target domain (e.g., "example.com")
            wordlist: Path to subdomain wordlist file
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent DNS lookups
        """
        self.domain = domain
        self.wordlist = wordlist
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = Logger.get_logger("subdomain_enum")
        self._found: Set[str] = set()

    async def enumerate(self) -> List[str]:
        """
        Run full subdomain enumeration.

        Returns:
            List of discovered subdomains
        """
        self.logger.info(f"Starting subdomain enumeration for {self.domain}")

        # Method 1: Certificate Transparency
        await self._enumerate_ct()

        # Method 2: DNS brute force with wordlist
        if self.wordlist:
            await self._enumerate_dns_brute()

        # Method 3: Permutation (if we have some subdomains)
        if self._found:
            await self._enumerate_permutation()

        self.logger.info(f"Enumeration complete. Found {len(self._found)} subdomains")
        return list(self._found)

    async def _enumerate_ct(self) -> None:
        """Enumerate via Certificate Transparency logs."""
        self.logger.debug("Enumerating via Certificate Transparency...")

        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            # Split by newlines and clean
                            for subdomain in name.split("\n"):
                                subdomain = subdomain.strip().lower()
                                if subdomain.endswith(f".{self.domain}"):
                                    self._found.add(subdomain)
                        self.logger.debug(f"CT found {len(data)} entries")
        except Exception as e:
            self.logger.warning(f"CT enumeration failed: {e}")

    async def _enumerate_dns_brute(self) -> None:
        """Enumerate via DNS brute force with wordlist."""
        self.logger.debug("Starting DNS brute force...")

        try:
            with open(self.wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.warning(f"Wordlist not found: {self.wordlist}")
            return

        # Use common wordlist if specific one not found
        if not words:
            words = self._get_default_wordlist()

        # Process in batches
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_subdomain(word: str) -> Optional[str]:
            subdomain = f"{word}.{self.domain}"
            if await self._resolve_subdomain(subdomain):
                return subdomain
            return None

        tasks = [check_subdomain(word) for word in words]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result:
                self._found.add(result)

    async def _enumerate_permutation(self) -> None:
        """Enumerate via permutation of known subdomains."""
        self.logger.debug("Starting permutation enumeration...")

        base_subdomains = list(self._found)[:10]  # Limit to first 10 for performance
        permutations = ["www", "mail", "ftp", "admin", "blog", "dev", "test", "staging"]

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_permutation(subdomain: str, perm: str) -> Optional[str]:
            new_subdomain = f"{perm}-{subdomain}"
            if await self._resolve_subdomain(new_subdomain):
                return new_subdomain
            # Also try subdomain as prefix
            parts = subdomain.split(".")
            if len(parts) > 2:
                new_subdomain = f"{parts[0]}-{perm}.{'.'.join(parts[1:])}"
                if await self._resolve_subdomain(new_subdomain):
                    return new_subdomain
            return None

        tasks = [
            check_permutation(sub, perm)
            for sub in base_subdomains
            for perm in permutations
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if result:
                self._found.add(result)

    async def _resolve_subdomain(self, subdomain: str) -> bool:
        """Check if a subdomain resolves (exists)."""
        try:
            # Try DNS resolution
            socket.setdefaulttimeout(self.timeout / 2)
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False

    def _get_default_wordlist(self) -> List[str]:
        """Get default subdomain wordlist."""
        return [
            "www", "mail", "ftp", "localhost", "webmail", "smtp",
            "pop", "ns1", "webdisk", "ns2", "cpanel", "whm",
            "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin",
            "forum", "news", "vpn", "ns3", "mail2", "new",
            "mysql", "old", "lists", "support", "mobile", "mx",
            "static", "docs", "beta", "shop", "sql", "secure"
        ]

    async def enumerate_async(self) -> AsyncIterator[str]:
        """
        Async generator for real-time subdomain discovery.

        Yields:
            Discovered subdomains as they are found
        """
        all_subdomains = await self.enumerate()
        for subdomain in all_subdomains:
            yield subdomain


class SubdomainResult:
    """Result of subdomain enumeration."""

    def __init__(
        self,
        subdomain: str,
        ip_addresses: List[str],
        sources: List[str],
        is_alive: bool = True
    ):
        self.subdomain = subdomain
        self.ip_addresses = ip_addresses
        self.sources = sources
        self.is_alive = is_alive

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ip_addresses": self.ip_addresses,
            "sources": self.sources,
            "is_alive": self.is_alive
        }
