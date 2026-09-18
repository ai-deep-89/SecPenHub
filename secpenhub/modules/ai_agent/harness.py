"""
Harness System - Extensible framework for custom security testing
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ...core.logger import Logger


@dataclass
class HarnessContext:
    """Context passed to harnesses during execution."""
    target: str
    assets: List[Dict]
    findings: List[Dict]
    config: Dict[str, Any]
    metadata: Dict[str, Any]


class HarnessResult:
    """Result from harness execution."""

    def __init__(
        self,
        success: bool,
        findings: Optional[List[Dict]] = None,
        data: Optional[Dict] = None,
        error: Optional[str] = None
    ):
        self.success = success
        self.findings = findings or []
        self.data = data or {}
        self.error = error


class Harness(ABC):
    """
    Base class for all harnesses.

    Harnesses are pluggable modules that extend SecPenHub's capabilities.
    They receive a context and return findings or data.

    Example:
        class MyCustomHarness(Harness):
            name = "custom_scan"
            description = "A custom security scan"

            async def execute(self, context: HarnessContext) -> HarnessResult:
                # Custom scanning logic
                findings = []
                # ... scan logic ...
                return HarnessResult(success=True, findings=findings)
    """

    name: str = "base_harness"
    description: str = "Base harness class"
    version: str = "1.0.0"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize harness.

        Args:
            config: Harness-specific configuration
        """
        self.config = config or {}
        self.logger = Logger.get_logger(f"harness.{self.name}")

    @abstractmethod
    async def execute(self, context: HarnessContext) -> HarnessResult:
        """
        Execute the harness with the given context.

        Args:
            context: Harness context with target info and existing findings

        Returns:
            HarnessResult with findings and/or data
        """
        pass

    def validate(self, result: HarnessResult) -> bool:
        """
        Validate harness execution result.

        Args:
            result: Result to validate

        Returns:
            True if result is valid, False otherwise
        """
        # Default validation - check success flag
        return result.success

    def get_info(self) -> Dict[str, str]:
        """Get harness information."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version
        }


class WebHarness(Harness):
    """
    Harness for web application security testing.
    """

    name = "web_harness"
    description = "Web application security testing harness"

    async def execute(self, context: HarnessContext) -> HarnessResult:
        """Execute web security scan."""
        try:
            from ..scanner.owasp_top10 import OWASPScanner

            scanner = OWASPScanner(context.target)
            vulnerabilities = await scanner.scan()

            findings = [v.to_dict() for v in vulnerabilities]

            return HarnessResult(
                success=True,
                findings=findings,
                data={"target": context.target, "scan_type": "web"}
            )

        except Exception as e:
            self.logger.error(f"Web harness execution failed: {e}")
            return HarnessResult(success=False, error=str(e))


class NetworkHarness(Harness):
    """
    Harness for network reconnaissance and scanning.
    """

    name = "network_harness"
    description = "Network reconnaissance and port scanning harness"

    async def execute(self, context: HarnessContext) -> HarnessResult:
        """Execute network scan."""
        try:
            from urllib.parse import urlparse
            from ..recon.portscan import PortScanner
            from ..recon.fingerprint import Fingerprint

            # Parse target
            parsed = urlparse(context.target)
            host = parsed.netloc or parsed.path

            # Remove port if present
            if ':' in host:
                host = host.split(':')[0]

            # Scan ports
            scanner = PortScanner(host)
            open_ports = await scanner.scan()

            # Fingerprint services
            fingerprint = Fingerprint()
            fingerprints = []

            for port in open_ports[:20]:  # Fingerprint first 20
                url = f"http://{host}:{port.port}"
                try:
                    fp = await fingerprint.fingerprint_url(url)
                    fingerprints.append(fp)
                except:
                    pass

            findings = []
            for port in open_ports:
                findings.append({
                    "type": "network",
                    "port": port.port,
                    "service": port.service,
                    "state": port.state,
                    "banner": port.banner
                })

            return HarnessResult(
                success=True,
                findings=findings,
                data={
                    "host": host,
                    "open_ports": len(open_ports),
                    "fingerprints": fingerprints
                }
            )

        except Exception as e:
            self.logger.error(f"Network harness execution failed: {e}")
            return HarnessResult(success=False, error=str(e))


class AuthHarness(Harness):
    """
    Harness for authentication and authorization testing.
    """

    name = "auth_harness"
    description = "Authentication and authorization testing harness"

    async def execute(self, context: HarnessContext) -> HarnessResult:
        """Execute auth security scan."""
        try:
            from ..scanner.csrf import CSRFScanner

            scanner = CSRFScanner()
            csrf_results = await scanner.scan_page(context.target)

            findings = []
            for result in csrf_results:
                findings.append({
                    "type": "csrf",
                    "url": result.url,
                    "form_action": result.form_action,
                    "has_token": result.has_token,
                    "is_vulnerable": result.is_vulnerable,
                    "severity": result.severity
                })

            return HarnessResult(
                success=True,
                findings=findings,
                data={"target": context.target, "scan_type": "auth"}
            )

        except Exception as e:
            self.logger.error(f"Auth harness execution failed: {e}")
            return HarnessResult(success=False, error=str(e))


class HarnessManager:
    """
    Manager for registering and executing harnesses.
    """

    def __init__(self):
        """Initialize harness manager."""
        self._harnesses: Dict[str, Harness] = {}
        self.logger = Logger.get_logger("harness_manager")

    def register(self, harness: Harness) -> None:
        """
        Register a harness.

        Args:
            harness: Harness instance to register
        """
        self._harnesses[harness.name] = harness
        self.logger.info(f"Registered harness: {harness.name}")

    def unregister(self, name: str) -> bool:
        """
        Unregister a harness.

        Args:
            name: Harness name to unregister

        Returns:
            True if harness was unregistered, False if not found
        """
        if name in self._harnesses:
            del self._harnesses[name]
            self.logger.info(f"Unregistered harness: {name}")
            return True
        return False

    def get_harness(self, name: str) -> Optional[Harness]:
        """
        Get a harness by name.

        Args:
            name: Harness name

        Returns:
            Harness instance or None if not found
        """
        return self._harnesses.get(name)

    def list_harnesses(self) -> List[Dict[str, str]]:
        """
        List all registered harnesses.

        Returns:
            List of harness info dictionaries
        """
        return [h.get_info() for h in self._harnesses.values()]

    async def execute_harness(
        self,
        name: str,
        context: HarnessContext
    ) -> HarnessResult:
        """
        Execute a specific harness.

        Args:
            name: Harness name
            context: Execution context

        Returns:
            HarnessResult from execution
        """
        harness = self._harnesses.get(name)
        if not harness:
            return HarnessResult(success=False, error=f"Harness not found: {name}")

        self.logger.info(f"Executing harness: {name}")
        result = await harness.execute(context)

        if harness.validate(result):
            self.logger.info(f"Harness {name} completed successfully")
        else:
            self.logger.warning(f"Harness {name} result validation failed")

        return result

    async def execute_all(
        self,
        context: HarnessContext
    ) -> List[HarnessResult]:
        """
        Execute all registered harnesses.

        Args:
            context: Execution context

        Returns:
            List of results from all harnesses
        """
        results = []
        for name in self._harnesses:
            result = await self.execute_harness(name, context)
            results.append(result)
        return results


# Register default harnesses
def get_default_harness_manager() -> HarnessManager:
    """Get a harness manager with default harnesses registered."""
    manager = HarnessManager()
    manager.register(WebHarness())
    manager.register(NetworkHarness())
    manager.register(AuthHarness())
    return manager
