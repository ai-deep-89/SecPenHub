"""
Port Scanning Module

Performs TCP port scanning with service detection.
Supports:
- TCP Connect scan
- Banner grabbing
- Service fingerprinting
"""

import socket
import asyncio
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from ...core.logger import Logger


@dataclass
class PortResult:
    """Result of a port scan."""
    port: int
    state: str  # 'open', 'closed', 'filtered'
    service: str
    banner: str
    version: str


class PortScanner:
    """
    Async port scanner with service detection.
    """

    # Common ports and their default services
    COMMON_PORTS = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        993: "imaps",
        995: "pop3s",
        1723: "pptp",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        27017: "mongodb",
    }

    # Top 100 ports for quick scan
    TOP_PORTS = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
        119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
        515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
        1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
        2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
        5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
        8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
        49153, 49154, 49155, 49156, 49157
    ]

    def __init__(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        max_concurrent: int = 100
    ):
        """
        Initialize port scanner.

        Args:
            host: Target hostname or IP
            ports: List of ports to scan (default: TOP_PORTS)
            timeout: Connection timeout per port
            max_concurrent: Maximum concurrent connections
        """
        self.host = host
        self.ports = ports or self.TOP_PORTS
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = Logger.get_logger("port_scanner")

    async def scan(self) -> List[PortResult]:
        """
        Perform port scan.

        Returns:
            List of PortResult for open ports
        """
        self.logger.info(f"Starting port scan on {self.host} ({len(self.ports)} ports)")

        open_ports = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def scan_port(port: int) -> Optional[PortResult]:
            result = await self._scan_port(port)
            if result and result.state == "open":
                return result
            return None

        tasks = [scan_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, PortResult):
                open_ports.append(result)

        self.logger.info(f"Scan complete. Found {len(open_ports)} open ports")
        return sorted(open_ports, key=lambda x: x.port)

    async def _scan_port(self, port: int) -> Optional[PortResult]:
        """Scan a single port."""
        try:
            # TCP connect scan
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, port),
                timeout=self.timeout
            )

            # Port is open, try to grab banner
            service = self.COMMON_PORTS.get(port, "unknown")
            banner = ""
            version = ""

            try:
                # Send basic probe and read response
                if port == 80 or port == 8080:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443 or port == 8443:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")

                await writer.drain()
                reader.set_close_delimiter('\n')
                banner = await asyncio.wait_for(
                    reader.readline(),
                    timeout=1.0
                )
                banner = banner.decode('utf-8', errors='ignore').strip()
            except:
                pass

            writer.close()
            await writer.wait_closed()

            # Parse version from banner if possible
            version = self._parse_version(service, banner)

            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
                version=version
            )

        except asyncio.TimeoutError:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            return None

    def _parse_version(self, service: str, banner: str) -> str:
        """Parse version information from banner."""
        if not banner:
            return ""

        # Simple pattern matching for common services
        if service == "ssh":
            match = re.search(r"SSH-[\d.]+-(.+?)(?:\n|$)", banner)
            return match.group(1) if match else ""
        elif service in ("http", "https"):
            match = re.search(r"Server: (.+?)(?:\n|$)", banner)
            return match.group(1) if match else ""
        elif service == "mysql":
            match = re.search(r"mysql.*?(\d+\.\d+\.\d+)", banner, re.I)
            return match.group(1) if match else ""

        return banner[:50]  # Return truncated banner as version

    def scan_sync(self) -> List[PortResult]:
        """Synchronous wrapper for port scanning."""
        return asyncio.run(self.scan())

    async def scan_top_ports(self, count: int = 100) -> List[PortResult]:
        """
        Scan only the most common ports.

        Args:
            count: Number of top ports to scan (default: 100)

        Returns:
            List of open ports
        """
        self.ports = self.TOP_PORTS[:count]
        return await self.scan()

    def get_service_name(self, port: int) -> str:
        """Get the default service name for a port."""
        return self.COMMON_PORTS.get(port, "unknown")
