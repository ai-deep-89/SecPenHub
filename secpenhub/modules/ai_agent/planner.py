"""
Planner Agent - AI-powered attack planning
"""

from typing import Dict, List, Any, Optional
from datetime import datetime

from ...core.logger import Logger
from .agent import AIAgent, AgentRole, AgentResponse


class PlannerAgent(AIAgent):
    """
    AI-powered attack planning agent.

    Analyzes target information and generates optimal attack plans.
    """

    def __init__(self, config: Optional[Dict] = None):
        super().__init__("planner", AgentRole.PLANNER, config)
        self.logger = Logger.get_logger("planner_agent")

    async def process(self, input_data: Dict[str, Any]) -> AgentResponse:
        """
        Generate attack plan based on target and reconnaissance data.

        Args:
            input_data: Dictionary containing:
                - target: Target URL or hostname
                - assets: Discovered assets (subdomains, ports, etc.)
                - previous_findings: Any previous scan results
                - constraints: Time limits, scope restrictions

        Returns:
            AgentResponse with attack plan
        """
        try:
            target = input_data.get("target", "")
            assets = input_data.get("assets", [])
            previous_findings = input_data.get("previous_findings", [])
            constraints = input_data.get("constraints", {})

            # Generate attack plan
            plan = self._create_attack_plan(target, assets, previous_findings, constraints)

            return AgentResponse(
                success=True,
                data=plan,
                agent_name=self.name
            )

        except Exception as e:
            self.logger.error(f"Attack planning failed: {e}")
            return AgentResponse(
                success=False,
                data=None,
                error=str(e),
                agent_name=self.name
            )

    def _create_attack_plan(
        self,
        target: str,
        assets: List,
        previous_findings: List,
        constraints: Dict
    ) -> Dict[str, Any]:
        """
        Create attack plan based on available intelligence.

        Args:
            target: Target information
            assets: Discovered assets
            previous_findings: Previous findings
            constraints: Planning constraints

        Returns:
            Attack plan dictionary
        """
        # Determine scan phases based on asset discovery
        phases = []

        # Phase 1: Reconnaissance (always needed unless already done)
        if not assets:
            phases.append({
                "phase": 1,
                "name": "Reconnaissance",
                "description": "Discover attack surface and assets",
                "tasks": [
                    {"task": "subdomain_enumeration", "priority": "high", "tool": "subdomain_enum"},
                    {"task": "port_scanning", "priority": "high", "tool": "portscan"},
                    {"task": "service_fingerprinting", "priority": "medium", "tool": "fingerprint"}
                ],
                "estimated_time": "5-15 minutes"
            })

        # Phase 2: Vulnerability Assessment
        phases.append({
            "phase": len(phases) + 1,
            "name": "Vulnerability Assessment",
            "description": "Scan for security vulnerabilities",
            "tasks": [
                {"task": "owasp_top10_scan", "priority": "high", "tool": "owasp_scanner"},
                {"task": "sql_injection_test", "priority": "high", "tool": "sqli_scanner"},
                {"task": "xss_test", "priority": "high", "tool": "xss_scanner"},
                {"task": "csrf_test", "priority": "medium", "tool": "csrf_scanner"},
                {"task": "ssrf_test", "priority": "medium", "tool": "owasp_scanner"}
            ],
            "estimated_time": "15-30 minutes"
        })

        # Phase 3: Exploitation/Validation
        phases.append({
            "phase": len(phases) + 1,
            "name": "Exploitation & Validation",
            "description": "Validate findings and test exploitability",
            "tasks": [
                {"task": "vulnerability_validation", "priority": "high", "tool": "analyzer"},
                {"task": "poc_development", "priority": "medium", "tool": "reporter"},
                {"task": "risk_assessment", "priority": "high", "tool": "evaluator"}
            ],
            "estimated_time": "10-20 minutes"
        })

        # Phase 4: Reporting
        phases.append({
            "phase": len(phases) + 1,
            "name": "Reporting",
            "description": "Document findings and recommendations",
            "tasks": [
                {"task": "report_generation", "priority": "high", "tool": "reporter"},
                {"task": "remediation_plan", "priority": "high", "tool": "reporter"}
            ],
            "estimated_time": "5-10 minutes"
        })

        # Calculate overall risk level
        risk_level = self._calculate_risk_level(target, assets, previous_findings)

        return {
            "target": target,
            "created_at": datetime.now().isoformat(),
            "phases": phases,
            "total_estimated_time": self._estimate_total_time(phases),
            "risk_level": risk_level,
            "scope": constraints.get("scope", "full"),
            "recommendations": self._generate_recommendations(phases)
        }

    def _estimate_total_time(self, phases: List[Dict]) -> str:
        """Estimate total scan time based on phases."""
        # Parse time estimates and calculate total
        total_minutes = 0
        for phase in phases:
            time_str = phase.get("estimated_time", "0 minutes")
            # Simple parsing
            import re
            match = re.search(r'(\d+)-(\d+)\s*minutes', time_str)
            if match:
                total_minutes += (int(match.group(1)) + int(match.group(2))) // 2
            else:
                match = re.search(r'(\d+)\s*minutes', time_str)
                if match:
                    total_minutes += int(match.group(1))

        if total_minutes < 60:
            return f"{total_minutes}-{total_minutes + 10} minutes"
        else:
            hours = total_minutes // 60
            mins = total_minutes % 60
            return f"{hours}-{hours + 1} hours {mins} minutes"

    def _calculate_risk_level(
        self,
        target: str,
        assets: List,
        previous_findings: List
    ) -> str:
        """Calculate risk level for the target."""
        # Simple heuristic based on asset count and previous findings
        asset_count = len(assets)
        finding_count = len(previous_findings)

        if finding_count > 10 or asset_count > 50:
            return "high"
        elif finding_count > 5 or asset_count > 20:
            return "medium"
        else:
            return "low"

    def _generate_recommendations(self, phases: List[Dict]) -> List[str]:
        """Generate recommendations for the scan."""
        recommendations = []

        for phase in phases:
            phase_name = phase.get("name", "")
            if "Reconnaissance" in phase_name:
                recommendations.append("Start with passive reconnaissance to minimize detection")
            elif "Vulnerability" in phase_name:
                recommendations.append("Use rate limiting to avoid triggering WAF/IPS")
            elif "Exploitation" in phase_name:
                recommendations.append("Focus on high-severity findings first")
            elif "Reporting" in phase_name:
                recommendations.append("Prioritize actionable findings in executive summary")

        return recommendations
