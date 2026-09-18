"""
AI Agent Core - Message-passing agent framework for security automation
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Protocol
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
from enum import Enum

from ...core.logger import Logger


class AgentRole(Enum):
    """Agent role enumeration."""
    PLANNER = "planner"
    EXECUTOR = "executor"
    ANALYZER = "analyzer"
    REPORTER = "reporter"


class Message:
    """Message passed between agents."""

    def __init__(
        self,
        sender: str,
        recipient: str,
        action: str,
        payload: Dict[str, Any],
        timestamp: Optional[datetime] = None
    ):
        self.sender = sender
        self.recipient = recipient
        self.action = action
        self.payload = payload
        self.timestamp = timestamp or datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "action": self.action,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class AgentResponse:
    """Response from an agent."""
    success: bool
    data: Any
    error: Optional[str] = None
    agent_name: str = ""


class AIAgent(ABC):
    """
    Base class for AI agents in SecPenHub.

    Each agent has:
    - A specific role (planner, executor, analyzer, reporter)
    - A message queue for communication
    - The ability to process messages and generate responses
    """

    def __init__(self, name: str, role: AgentRole, config: Optional[Dict] = None):
        """
        Initialize AI agent.

        Args:
            name: Agent name
            role: Agent role
            config: Optional configuration dictionary
        """
        self.name = name
        self.role = role
        self.config = config or {}
        self.logger = Logger.get_logger(f"agent.{name}")
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._handlers: Dict[str, callable] = {}

    async def start(self) -> None:
        """Start the agent."""
        self._running = True
        self.logger.info(f"Agent {self.name} started with role {self.role.value}")
        asyncio.create_task(self._process_messages())

    async def stop(self) -> None:
        """Stop the agent."""
        self._running = False
        self.logger.info(f"Agent {self.name} stopped")

    async def send_message(self, message: Message) -> None:
        """Send a message to this agent's queue."""
        await self._message_queue.put(message)

    async def receive_message(self) -> Message:
        """Receive a message from the queue."""
        return await self._message_queue.get()

    async def _process_messages(self) -> None:
        """Process messages from the queue."""
        while self._running:
            try:
                message = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0
                )
                await self._handle_message(message)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")

    async def _handle_message(self, message: Message) -> None:
        """Handle a received message."""
        handler = self._handlers.get(message.action)
        if handler:
            try:
                await handler(message)
            except Exception as e:
                self.logger.error(f"Error in handler for {message.action}: {e}")
        else:
            self.logger.warning(f"No handler for action: {message.action}")

    def register_handler(self, action: str, handler: callable) -> None:
        """Register a handler for a specific action."""
        self._handlers[action] = handler

    @abstractmethod
    async def process(self, input_data: Dict[str, Any]) -> AgentResponse:
        """
        Process input and generate output.

        This is the main method subclasses should implement.

        Args:
            input_data: Input data for processing

        Returns:
            AgentResponse with results
        """
        pass

    async def call(self, input_data: Dict[str, Any]) -> AgentResponse:
        """
        Synchronous call interface for the agent.

        Args:
            input_data: Input data for processing

        Returns:
            AgentResponse with results
        """
        return await self.process(input_data)


class PlannerAgent(AIAgent):
    """Agent responsible for attack planning and strategy."""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__("planner", AgentRole.PLANNER, config)
        self.register_handler("plan_attack", self._handle_plan_attack)

    async def process(self, input_data: Dict[str, Any]) -> AgentResponse:
        """Generate attack plan based on target information."""
        try:
            target = input_data.get("target", "")
            discovered_assets = input_data.get("assets", [])
            scan_results = input_data.get("previous_findings", [])

            # AI-powered attack planning
            plan = await self._generate_plan(target, discovered_assets, scan_results)

            return AgentResponse(
                success=True,
                data=plan,
                agent_name=self.name
            )
        except Exception as e:
            return AgentResponse(
                success=False,
                data=None,
                error=str(e),
                agent_name=self.name
            )

    async def _generate_plan(
        self,
        target: str,
        assets: List,
        previous_findings: List
    ) -> Dict[str, Any]:
        """Generate attack plan using AI."""
        # Simple rule-based planning (in production, would integrate with LLM)
        plan = {
            "target": target,
            "phases": [
                {
                    "phase": 1,
                    "name": "Reconnaissance",
                    "tasks": ["subdomain_enum", "port_scan", "fingerprint"],
                    "priority": 1
                },
                {
                    "phase": 2,
                    "name": "Vulnerability Scanning",
                    "tasks": ["owasp_scan", "sqli_scan", "xss_scan"],
                    "priority": 2
                },
                {
                    "phase": 3,
                    "name": "Exploitation",
                    "tasks": ["validate_findings", "test_exploits"],
                    "priority": 3
                },
                {
                    "phase": 4,
                    "name": "Reporting",
                    "tasks": ["generate_report", "create_poc"],
                    "priority": 4
                }
            ],
            "estimated_time": "30-60 minutes",
            "risk_level": "medium"
        }

        # If we already have findings, skip to exploitation
        if previous_findings:
            plan["phases"] = plan["phases"][2:]  # Skip recon and scanning

        return plan

    async def _handle_plan_attack(self, message: Message) -> None:
        """Handle incoming attack planning request."""
        response = await self.process(message.payload)
        # Send response back (would go to executor agent in full implementation)


class AnalyzerAgent(AIAgent):
    """Agent responsible for vulnerability analysis and prioritization."""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__("analyzer", AgentRole.ANALYZER, config)
        self.register_handler("analyze_vulns", self._handle_analyze)

    async def process(self, input_data: Dict[str, Any]) -> AgentResponse:
        """Analyze and prioritize vulnerabilities."""
        try:
            findings = input_data.get("findings", [])

            # Sort and prioritize findings
            prioritized = self._prioritize_findings(findings)

            return AgentResponse(
                success=True,
                data=prioritized,
                agent_name=self.name
            )
        except Exception as e:
            return AgentResponse(
                success=False,
                data=None,
                error=str(e),
                agent_name=self.name
            )

    def _prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Prioritize findings based on severity and impact."""
        # Sort by CVSS score (descending)
        sorted_findings = sorted(
            findings,
            key=lambda x: x.get("cvss_score", 0),
            reverse=True
        )

        # Add priority ranking
        for i, finding in enumerate(sorted_findings):
            finding["priority_rank"] = i + 1

        return sorted_findings

    async def _handle_analyze(self, message: Message) -> None:
        """Handle vulnerability analysis request."""
        response = await self.process(message.payload)


class ReporterAgent(AIAgent):
    """Agent responsible for generating security reports."""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__("reporter", AgentRole.REPORTER, config)
        self.register_handler("generate_report", self._handle_generate)

    async def process(self, input_data: Dict[str, Any]) -> AgentResponse:
        """Generate security report from findings."""
        try:
            scan_data = input_data.get("scan_data", {})
            findings = input_data.get("findings", [])
            target = input_data.get("target", "")

            # Generate report structure
            report = self._generate_report_structure(target, scan_data, findings)

            return AgentResponse(
                success=True,
                data=report,
                agent_name=self.name
            )
        except Exception as e:
            return AgentResponse(
                success=False,
                data=None,
                error=str(e),
                agent_name=self.name
            )

    def _generate_report_structure(
        self,
        target: str,
        scan_data: Dict,
        findings: List
    ) -> Dict[str, Any]:
        """Generate report data structure."""
        # Calculate statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "executive_summary": {
                "total_findings": len(findings),
                "severity_distribution": severity_counts,
                "overall_risk": "High" if severity_counts["critical"] > 0 else "Medium"
            },
            "findings": findings,
            "recommendations": self._generate_recommendations(findings)
        }

    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        for finding in findings:
            if finding.get("remediation"):
                recommendations.append(finding["remediation"])

        return list(set(recommendations))  # Remove duplicates

    async def _handle_generate(self, message: Message) -> None:
        """Handle report generation request."""
        response = await self.process(message.payload)
