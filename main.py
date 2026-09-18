"""
SecPenHub - Main Entry Point

Intelligent Penetration Testing & Security Assessment Platform
"""

import asyncio
import argparse
import sys
from pathlib import Path

from secpenhub.core.config import Config
from secpenhub.core.logger import Logger
from secpenhub.core.database import Database
from secpenhub.modules.recon.subdomain import SubdomainEnumerator
from secpenhub.modules.recon.portscan import PortScanner
from secpenhub.modules.scanner.owasp_top10 import OWASPScanner
from secpenhub.modules.ai_agent.planner import PlannerAgent
from secpenhub.modules.ai_agent.harness import get_default_harness_manager, HarnessContext
from secpenhub.modules.evaluator.risk_score import RiskCalculator
from secpenhub.modules.reporter.generator import ReportGenerator


class SecPenHub:
    """
    Main SecPenHub application class.
    """

    def __init__(self, target: str, config: Config = None):
        """
        Initialize SecPenHub.

        Args:
            target: Target URL or hostname
            config: Optional configuration object
        """
        self.target = target
        self.config = config or Config()
        self.logger = Logger.get_logger("secpenhub")
        self.db = Database(self.config.get("database.path", ".secpenhub.db"))

        # Add target to database
        self.target_id = self.db.add_target(target)

    async def scan(self, mode: str = "full") -> dict:
        """
        Run security scan.

        Args:
            mode: Scan mode (full, recon, owasp, custom)

        Returns:
            Scan results dictionary
        """
        self.logger.info(f"Starting {mode} scan on {self.target}")

        # Create scan record
        scan_id = self.db.create_scan(self.target_id, mode)

        # Initialize AI planner
        planner = PlannerAgent(self.config.all)

        try:
            if mode == "full":
                results = await self._full_scan(scan_id)
            elif mode == "recon":
                results = await self._recon_scan(scan_id)
            elif mode == "owasp":
                results = await self._owasp_scan(scan_id)
            else:
                results = await self._full_scan(scan_id)

            # Calculate security score
            calculator = RiskCalculator()
            security_score = calculator.calculate_security_score(results["findings"])

            # Complete scan in database
            self.db.complete_scan(
                scan_id,
                security_score.overall_score,
                {
                    "total": security_score.total_findings,
                    "critical": security_score.critical_count,
                    "high": security_score.high_count,
                    "medium": security_score.medium_count,
                    "low": security_score.low_count
                }
            )

            self.db.update_target_scan_count(self.target_id)

            results["security_score"] = security_score.to_dict()

            self.logger.info(f"Scan complete. Security Score: {security_score.overall_score}")
            return results

        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise

    async def _full_scan(self, scan_id: int) -> dict:
        """Run full security scan."""
        # Get attack plan from AI
        planner = PlannerAgent()
        plan_response = await planner.call({
            "target": self.target,
            "assets": [],
            "previous_findings": []
        })

        # Run reconnaissance
        recon_results = await self._recon_scan(scan_id)

        # Run OWASP scan
        owasp_results = await self._owasp_scan(scan_id)

        # Combine findings
        all_findings = recon_results["findings"] + owasp_results["findings"]

        return {
            "scan_id": scan_id,
            "target": self.target,
            "assets": recon_results.get("assets", []),
            "findings": all_findings,
            "plan": plan_response.data if plan_response.success else None
        }

    async def _recon_scan(self, scan_id: int) -> dict:
        """Run reconnaissance scan."""
        from urllib.parse import urlparse
        findings = []
        assets = []

        parsed = urlparse(self.target)
        domain = parsed.netloc or parsed.path

        # Subdomain enumeration
        try:
            subdomain_enum = SubdomainEnumerator(domain)
            subdomains = await subdomain_enum.enumerate()
            for subdomain in subdomains:
                self.db.add_asset(scan_id, "subdomain", subdomain)
                assets.append({"type": "subdomain", "value": subdomain})
            self.logger.info(f"Found {len(subdomains)} subdomains")
        except Exception as e:
            self.logger.warning(f"Subdomain enumeration failed: {e}")

        # Port scanning
        try:
            host = domain.split(":")[0]  # Remove port if present
            port_scanner = PortScanner(host)
            open_ports = await port_scanner.scan()
            for port in open_ports:
                self.db.add_asset(scan_id, "port", f"{port.port}/{port.service}")
                assets.append({
                    "type": "port",
                    "value": f"{port.port}",
                    "service": port.service
                })
            self.logger.info(f"Found {len(open_ports)} open ports")
        except Exception as e:
            self.logger.warning(f"Port scanning failed: {e}")

        return {
            "scan_id": scan_id,
            "target": self.target,
            "assets": assets,
            "findings": findings
        }

    async def _owasp_scan(self, scan_id: int) -> dict:
        """Run OWASP Top 10 scan."""
        findings = []

        try:
            scanner = OWASPScanner(self.target)
            vulnerabilities = await scanner.scan()

            for vuln in vulnerabilities:
                # Store in database
                finding_id = self.db.add_finding(
                    scan_id=scan_id,
                    vulnerability_type=vuln.category,
                    severity=vuln.severity,
                    title=vuln.title,
                    cvss_score=vuln.cvss_score,
                    description=vuln.description,
                    url=vuln.url,
                    parameter=vuln.parameter,
                    payload=vuln.payload,
                    poc=vuln.poc,
                    remediation=vuln.remediation,
                    references=",".join(vuln.references) if vuln.references else None
                )
                findings.append(vuln.to_dict())

        except Exception as e:
            self.logger.warning(f"OWASP scan failed: {e}")

        return {
            "scan_id": scan_id,
            "target": self.target,
            "findings": findings
        }

    async def generate_report(self, format: str = "html") -> str:
        """
        Generate security report.

        Args:
            format: Report format (html, json, markdown)

        Returns:
            Path to generated report
        """
        # Get latest scan results
        scan_results = self.db.get_scan_results(
            self.db.get_target(self.target)["last_scan_id"] if False else 1
        )

        generator = ReportGenerator()
        report_path = await generator.generate(
            scan_data={"target": self.target},
            findings=scan_results.get("findings", []),
            format=format
        )

        return report_path


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SecPenHub - Intelligent Penetration Testing Platform"
    )
    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Target URL or hostname"
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["full", "recon", "owasp"],
        default="full",
        help="Scan mode (default: full)"
    )
    parser.add_argument(
        "--report",
        "-r",
        choices=["html", "json", "markdown"],
        default="html",
        help="Report format (default: html)"
    )
    parser.add_argument(
        "--config",
        "-c",
        help="Configuration file path"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Setup logging
    log_level = Logger.LogLevel.DEBUG if args.verbose else Logger.LogLevel.INFO
    Logger.setup(level=log_level)

    # Initialize SecPenHub
    config = Config(args.config) if args.config else Config()
    scanner = SecPenHub(args.target, config)

    # Run scan
    try:
        results = await scanner.scan(mode=args.mode)

        # Print summary
        print("\n" + "=" * 60)
        print("SecPenHub Security Assessment Complete")
        print("=" * 60)
        print(f"\nTarget: {args.target}")
        print(f"Scan Mode: {args.mode}")

        if "security_score" in results:
            score = results["security_score"]
            print(f"\nSecurity Score: {score['overall_score']}/100 ({score['rating']})")
            print(f"Critical: {score['critical_count']} | High: {score['high_count']} | "
                  f"Medium: {score['medium_count']} | Low: {score['low_count']}")

        print(f"\nTotal Findings: {len(results['findings'])}")

        # Generate report
        report_path = await scanner.generate_report(format=args.report)
        print(f"\nReport saved to: {report_path}")

        print("\n" + "=" * 60)

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
